//! The daemon's shared state and its RPC implementations.
//!
//! One `Daemon` is shared by every connection. It owns the rtnetlink handle
//! (one netlink socket serving all callers), the event bus (one multicast
//! socket feeding all subscribers) and the capture registry.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rtnetlink::Handle;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

use crate::capture::{self, Capture};
use crate::collect::{self, links, neigh, routes, sockets};
use crate::correlate::{self, CorrelationInput};
use crate::diag;
use crate::ipc::session::{Responder, StreamOutcome};
use crate::proto;
use crate::snapshot;
use crate::util;
use crate::watch::{self, EventBus};

/// How often WatchSockets re-dumps when the client does not choose.
const DEFAULT_SOCKET_POLL_MS: u64 = 2000;
/// Floor on the socket poll interval; a full inet_diag dump is not free.
const MIN_SOCKET_POLL_MS: u64 = 250;
/// Ceiling, so a subscription cannot be configured into never reporting.
const MAX_SOCKET_POLL_MS: u64 = 60_000;
/// Captures are allowed to run this long when the client sets no duration.
const DEFAULT_CAPTURE_DURATION_MS: u64 = 60_000;

pub struct Daemon {
    pub handle: Handle,
    pub events: EventBus,
    pub started_unix_ms: i64,
    pub version: String,
    capabilities: proto::DaemonCapabilities,
    warnings: Vec<String>,
    captures: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    next_capture_id: AtomicU64,
}

impl Daemon {
    pub fn new(handle: Handle, events: EventBus) -> Self {
        let (capabilities, warnings) = probe_capabilities();
        Self {
            handle,
            events,
            started_unix_ms: util::now_unix_ms(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities,
            warnings,
            captures: Mutex::new(HashMap::new()),
            next_capture_id: AtomicU64::new(1),
        }
    }

    /// Interface index -> name, rebuilt per call. Cheap (one netlink dump) and
    /// always correct, which matters more here than caching would: a stale
    /// name map on a device mid-handover produces confusing output.
    async fn if_names(&self) -> Result<HashMap<u32, String>, proto::Error> {
        let interfaces = links::get_interfaces(&self.handle, false, false)
            .await
            .map_err(proto::Error::from)?;
        Ok(collect::interface_names(&interfaces))
    }

    /// Non-fatal problems found while probing capabilities at startup.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn hello(&self, request: &proto::HelloRequest) -> proto::HelloResponse {
        let negotiated = request.protocol_version.min(proto::PROTOCOL_VERSION);
        info!(
            "client {} {} connected, protocol {} (negotiated {negotiated})",
            request.client_name, request.client_version, request.protocol_version
        );
        proto::HelloResponse {
            protocol_version: negotiated,
            daemon_version: self.version.clone(),
            kernel_release: util::kernel_release(),
            daemon_uid: unsafe { libc::getuid() },
            daemon_pid: std::process::id(),
            capabilities: Some(self.capabilities),
            warnings: self.warnings.clone(),
            daemon_started_unix_ms: self.started_unix_ms,
        }
    }

    // ---- Unary ------------------------------------------------------------

    pub async fn get_snapshot(
        &self,
        request: proto::GetSnapshotRequest,
    ) -> Result<proto::GetSnapshotResponse, proto::Error> {
        let snapshot = snapshot::collect_snapshot(&self.handle, &request)
            .await
            .map_err(proto::Error::from)?;
        Ok(proto::GetSnapshotResponse {
            snapshot: Some(snapshot),
        })
    }

    pub async fn get_interfaces(
        &self,
        request: proto::GetInterfacesRequest,
    ) -> Result<proto::GetInterfacesResponse, proto::Error> {
        let mut interfaces =
            links::get_interfaces(&self.handle, request.include_stats, request.include_sysctls)
                .await
                .map_err(proto::Error::from)?;

        if !request.names.is_empty() || !request.indexes.is_empty() {
            interfaces
                .retain(|i| request.names.contains(&i.name) || request.indexes.contains(&i.index));
        }

        Ok(proto::GetInterfacesResponse { interfaces })
    }

    pub async fn get_routes(
        &self,
        request: proto::GetRoutesRequest,
    ) -> Result<proto::GetRoutesResponse, proto::Error> {
        let if_names = self.if_names().await?;
        let family = proto::IpFamily::try_from(request.family)
            .map_err(|_| proto::Error::invalid("unknown address family"))?;

        let dump = routes::get_routes(
            &self.handle,
            family,
            request.table,
            request.only_default,
            request.interface_index,
            &if_names,
        )
        .await
        .map_err(proto::Error::from)?;

        Ok(proto::GetRoutesResponse {
            routes: dump.routes,
            table_names: dump.table_names,
        })
    }

    pub async fn get_routing_rules(
        &self,
        request: proto::GetRoutingRulesRequest,
    ) -> Result<proto::GetRoutingRulesResponse, proto::Error> {
        let family = proto::IpFamily::try_from(request.family)
            .map_err(|_| proto::Error::invalid("unknown address family"))?;
        let uid = request.has_uid.then_some(request.uid);

        let rules = routes::get_rules(&self.handle, family, uid)
            .await
            .map_err(proto::Error::from)?;
        Ok(proto::GetRoutingRulesResponse { rules })
    }

    pub async fn get_neighbors(
        &self,
        request: proto::GetNeighborsRequest,
    ) -> Result<proto::GetNeighborsResponse, proto::Error> {
        let if_names = self.if_names().await?;
        let family = proto::IpFamily::try_from(request.family)
            .map_err(|_| proto::Error::invalid("unknown address family"))?;

        let neighbors = neigh::get_neighbors(
            &self.handle,
            family,
            request.interface_index,
            request.only_routers,
            &if_names,
        )
        .await
        .map_err(proto::Error::from)?;

        Ok(proto::GetNeighborsResponse { neighbors })
    }

    pub async fn get_sockets(
        &self,
        request: proto::GetSocketsRequest,
    ) -> Result<proto::GetSocketsResponse, proto::Error> {
        let if_names = self.if_names().await?;
        let filter = request.filter.unwrap_or_default();
        let dump = sockets::get_sockets(&filter, &if_names)
            .await
            .map_err(proto::Error::from)?;

        Ok(proto::GetSocketsResponse {
            sockets: dump.sockets,
            summary: Some(dump.summary),
            truncated: dump.truncated,
        })
    }

    pub async fn get_app_network_state(
        &self,
        request: proto::GetAppNetworkStateRequest,
    ) -> Result<proto::GetAppNetworkStateResponse, proto::Error> {
        let app = request
            .app
            .ok_or_else(|| proto::Error::invalid("the request names no app"))?;
        if app.uid == 0 {
            return Err(proto::Error::invalid(
                "an app uid is required; the app resolves the package name to a uid, the \
                 daemon has no PackageManager",
            ));
        }

        let interfaces = links::get_interfaces(&self.handle, false, false)
            .await
            .map_err(proto::Error::from)?;
        let if_names = collect::interface_names(&interfaces);

        let state = correlate::app_network_state(
            &self.handle,
            &interfaces,
            &if_names,
            CorrelationInput {
                app,
                android_state: request.android_state.as_ref(),
                include_tcp_info: request.include_tcp_info,
                skip_route_lookup: request.skip_route_lookup,
            },
        )
        .await
        .map_err(proto::Error::from)?;

        Ok(proto::GetAppNetworkStateResponse { state: Some(state) })
    }

    pub async fn route_lookup(
        &self,
        request: proto::RouteLookupRequest,
    ) -> Result<proto::RouteLookupResponse, proto::Error> {
        let address = request
            .destination
            .as_ref()
            .filter(|a| a.is_set())
            .ok_or_else(|| proto::Error::invalid("destination must be a 4 or 16 byte address"))?;
        let destination: IpAddr = address
            .to_ip()
            .ok_or_else(|| proto::Error::invalid("destination is not a valid IP address"))?;

        let if_names = self.if_names().await?;
        let lookup = routes::route_lookup(
            &self.handle,
            destination,
            request.source_hint.as_ref().and_then(|a| a.to_ip()),
            request.has_uid.then_some(request.uid),
            request.has_fwmark.then_some(request.fwmark),
            request.out_interface_index,
            &if_names,
        )
        .await;

        Ok(proto::RouteLookupResponse {
            lookup: Some(lookup),
        })
    }

    /// Framework callbacks pushed by the app, merged into the shared timeline.
    pub async fn push_framework_event(
        &self,
        request: proto::PushFrameworkEventRequest,
    ) -> Result<proto::PushFrameworkEventResponse, proto::Error> {
        let mut accepted = 0u64;
        for mut event in request.events {
            // Force the source: a client must not be able to inject events
            // that look like they came from the kernel.
            event.source = proto::EventSource::Framework as i32;
            self.events.publish(event);
            accepted += 1;
        }
        Ok(proto::PushFrameworkEventResponse { accepted })
    }

    // ---- Streaming --------------------------------------------------------

    pub async fn diagnose_stream(
        self: Arc<Self>,
        id: u64,
        request: proto::DiagnoseRequest,
        responder: Responder,
    ) -> StreamOutcome {
        let (tx, mut rx) = mpsc::channel::<proto::Check>(64);

        let forwarder = {
            let responder = responder.clone();
            tokio::spawn(async move {
                let mut sent = 0u64;
                while let Some(check) = rx.recv().await {
                    let frame = proto::server_frame::Body::Diagnose(proto::DiagnoseProgress {
                        payload: Some(proto::diagnose_progress::Payload::Check(check)),
                    });
                    if !responder.reply(id, frame).await {
                        break;
                    }
                    sent += 1;
                }
                sent
            })
        };

        let response = diag::run(&self.handle, request, Some(tx)).await;
        let checks_sent = forwarder.await.unwrap_or(0);

        let findings = response.findings.len();
        let summary = response.summary.clone();
        responder
            .reply(
                id,
                proto::server_frame::Body::Diagnose(proto::DiagnoseProgress {
                    payload: Some(proto::diagnose_progress::Payload::Response(response)),
                }),
            )
            .await;

        info!("diagnosis complete: {summary} ({findings} finding(s))");
        StreamOutcome::done("diagnosis complete", checks_sent + 1)
    }

    pub async fn watch_network(
        self: Arc<Self>,
        id: u64,
        request: proto::WatchNetworkRequest,
        responder: Responder,
    ) -> StreamOutcome {
        let filter = request.filter.unwrap_or_default();
        let mut receiver = self.events.subscribe();
        let mut sent = 0u64;

        if request.replay_initial_state
            && let Err(outcome) = self.replay_state(id, &filter, &responder, &mut sent).await
        {
            return outcome;
        }

        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if !watch::matches_filter(&event, &filter) {
                        continue;
                    }
                    if !responder
                        .reply(id, proto::server_frame::Body::Event(event))
                        .await
                    {
                        return StreamOutcome::done("client disconnected", sent);
                    }
                    sent += 1;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    // Tell the client rather than silently losing events: a
                    // timeline with a hole in it is worse than one that admits
                    // to the hole.
                    warn!("subscriber {id} lagged and missed {missed} event(s)");
                    let notice = proto::NetworkEvent {
                        source: proto::EventSource::Daemon as i32,
                        severity: proto::EventSeverity::Warning as i32,
                        summary: format!(
                            "{missed} event(s) were dropped because this subscription could \
                             not keep up"
                        ),
                        unix_ms: util::now_unix_ms(),
                        monotonic_ns: util::monotonic_ns(),
                        ..Default::default()
                    };
                    if !responder
                        .reply(id, proto::server_frame::Body::Event(notice))
                        .await
                    {
                        return StreamOutcome::done("client disconnected", sent);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return StreamOutcome::done("the event bus closed", sent);
                }
            }
        }
    }

    /// Emit the current state as synthetic "added" events so a freshly opened
    /// timeline is populated instead of blank.
    async fn replay_state(
        &self,
        id: u64,
        filter: &proto::EventFilter,
        responder: &Responder,
        sent: &mut u64,
    ) -> Result<(), StreamOutcome> {
        let interfaces = match links::get_interfaces(&self.handle, false, false).await {
            Ok(interfaces) => interfaces,
            Err(e) => {
                return Err(StreamOutcome::failed(proto::Error::from(e), *sent));
            }
        };

        for interface in interfaces {
            let up = interface.flags.as_ref().map(|f| f.up).unwrap_or(false);
            let event = proto::NetworkEvent {
                source: proto::EventSource::Daemon as i32,
                severity: proto::EventSeverity::Info as i32,
                summary: format!(
                    "{} is {} (initial state)",
                    interface.name,
                    if up { "up" } else { "down" }
                ),
                unix_ms: util::now_unix_ms(),
                monotonic_ns: util::monotonic_ns(),
                payload: Some(proto::network_event::Payload::Link(proto::LinkEvent {
                    added: true,
                    interface: Some(interface),
                    went_up: up,
                    ..Default::default()
                })),
                ..Default::default()
            };
            if !watch::matches_filter(&event, filter) {
                continue;
            }
            if !responder
                .reply(id, proto::server_frame::Body::Event(event))
                .await
            {
                return Err(StreamOutcome::done("client disconnected", *sent));
            }
            *sent += 1;
        }

        Ok(())
    }

    pub async fn watch_routes(
        self: Arc<Self>,
        id: u64,
        request: proto::WatchRoutesRequest,
        responder: Responder,
    ) -> StreamOutcome {
        // Routes and rules come off the same bus; this is WatchNetwork with a
        // preset filter, which keeps one code path for event delivery.
        let filter = proto::EventFilter {
            routes: true,
            rules: request.include_rules,
            ..Default::default()
        };
        let family =
            proto::IpFamily::try_from(request.family).unwrap_or(proto::IpFamily::Unspecified);

        let mut receiver = self.events.subscribe();
        let mut sent = 0u64;

        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if !watch::matches_filter(&event, &filter) {
                        continue;
                    }
                    if !route_event_matches(&event, family, request.table) {
                        continue;
                    }
                    if !responder
                        .reply(id, proto::server_frame::Body::Event(event))
                        .await
                    {
                        return StreamOutcome::done("client disconnected", sent);
                    }
                    sent += 1;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return StreamOutcome::done("the event bus closed", sent);
                }
            }
        }
    }

    /// Sockets have no netlink multicast group for state changes, so this
    /// polls and reports the differences.
    pub async fn watch_sockets(
        self: Arc<Self>,
        id: u64,
        request: proto::WatchSocketsRequest,
        responder: Responder,
    ) -> StreamOutcome {
        let filter = request.filter.unwrap_or_default();
        // 0 means "daemon's choice"; anything else is clamped, because a full
        // inet_diag dump every few milliseconds would cost more than the
        // information is worth.
        let poll_ms = if request.poll_ms == 0 {
            DEFAULT_SOCKET_POLL_MS
        } else {
            (request.poll_ms as u64).clamp(MIN_SOCKET_POLL_MS, MAX_SOCKET_POLL_MS)
        };
        let interval = std::time::Duration::from_millis(poll_ms);

        let mut previous: HashMap<u64, proto::Socket> = HashMap::new();
        let mut first_pass = true;
        let mut sent = 0u64;

        loop {
            let if_names = match self.if_names().await {
                Ok(names) => names,
                Err(e) => return StreamOutcome::failed(e, sent),
            };
            let dump = match sockets::get_sockets(&filter, &if_names).await {
                Ok(dump) => dump,
                Err(e) => return StreamOutcome::failed(proto::Error::from(e), sent),
            };

            let mut current: HashMap<u64, proto::Socket> = HashMap::new();
            for socket in dump.sockets {
                // The cookie is the kernel's own stable identity for a socket;
                // the 4-tuple is not, because ports get reused.
                let key = if socket.socket_cookie != 0 {
                    socket.socket_cookie
                } else {
                    socket.inode
                };
                current.insert(key, socket);
            }

            // The first pass establishes the baseline; reporting every
            // existing socket as "appeared" would bury the real changes.
            if !first_pass {
                for (key, socket) in &current {
                    match previous.get(key) {
                        None => {
                            if !self
                                .emit_socket_event(id, &responder, socket, None, true, false)
                                .await
                            {
                                return StreamOutcome::done("client disconnected", sent);
                            }
                            sent += 1;
                        }
                        Some(old) if old.state != socket.state => {
                            let previous_state = proto::TcpState::try_from(old.state)
                                .unwrap_or(proto::TcpState::Unspecified);
                            if !self
                                .emit_socket_event(
                                    id,
                                    &responder,
                                    socket,
                                    Some(previous_state),
                                    false,
                                    false,
                                )
                                .await
                            {
                                return StreamOutcome::done("client disconnected", sent);
                            }
                            sent += 1;
                        }
                        _ => {}
                    }
                }
                for (key, socket) in &previous {
                    if !current.contains_key(key)
                        && !self
                            .emit_socket_event(id, &responder, socket, None, false, true)
                            .await
                    {
                        return StreamOutcome::done("client disconnected", sent);
                    }
                }
            }

            previous = current;
            first_pass = false;
            tokio::time::sleep(interval).await;
        }
    }

    async fn emit_socket_event(
        &self,
        id: u64,
        responder: &Responder,
        socket: &proto::Socket,
        previous_state: Option<proto::TcpState>,
        appeared: bool,
        disappeared: bool,
    ) -> bool {
        let state = proto::TcpState::try_from(socket.state).unwrap_or(proto::TcpState::Unspecified);
        let local = socket
            .local_address
            .as_ref()
            .map(|a| a.display())
            .unwrap_or_default();
        let remote = socket
            .remote_address
            .as_ref()
            .map(|a| a.display())
            .unwrap_or_default();

        // The mark is what ties this socket to a framework Network, so it
        // belongs in the timeline line rather than only in the payload.
        let mark = if socket.has_mark {
            format!(" mark {}", correlate::describe_mark(socket.mark))
        } else {
            String::new()
        };

        let summary = if disappeared {
            format!(
                "socket closed: {local}:{} -> {remote}:{} (uid {}){mark}",
                socket.local_port, socket.remote_port, socket.uid
            )
        } else if appeared {
            format!(
                "socket {state:?}: {local}:{} -> {remote}:{} (uid {}){mark}",
                socket.local_port, socket.remote_port, socket.uid
            )
        } else {
            format!(
                "socket {:?} -> {state:?}: {local}:{} -> {remote}:{} (uid {}){mark}",
                previous_state.unwrap_or(proto::TcpState::Unspecified),
                socket.local_port,
                socket.remote_port,
                socket.uid
            )
        };

        let event = proto::NetworkEvent {
            source: proto::EventSource::Kernel as i32,
            severity: if state == proto::TcpState::SynSent {
                proto::EventSeverity::Notice as i32
            } else {
                proto::EventSeverity::Debug as i32
            },
            summary,
            unix_ms: util::now_unix_ms(),
            monotonic_ns: util::monotonic_ns(),
            payload: Some(proto::network_event::Payload::Socket(proto::SocketEvent {
                socket: Some(socket.clone()),
                previous_state: previous_state.unwrap_or(proto::TcpState::Unspecified) as i32,
                appeared,
                disappeared,
            })),
            ..Default::default()
        };

        responder
            .reply(id, proto::server_frame::Body::Event(event))
            .await
    }

    pub async fn start_capture(
        self: Arc<Self>,
        id: u64,
        request: proto::StartCaptureRequest,
        responder: Responder,
    ) -> StreamOutcome {
        let capture_id = self.next_capture_id.fetch_add(1, Ordering::Relaxed);

        let mut capture = match Capture::open(&request) {
            Ok(capture) => capture,
            Err(e) => {
                return StreamOutcome::failed(proto::Error::from(e), 0);
            }
        };

        self.captures
            .lock()
            .await
            .insert(capture_id, capture.stop_flag());

        let filter = request.filter.clone().unwrap_or_default();
        let started = proto::CaptureStarted {
            capture_id,
            interface_name: capture.interface_name.clone(),
            link_type: capture.link_type as i32,
            snaplen: capture.snaplen,
            started_unix_ms: util::now_unix_ms(),
            bpf_expression_ignored: !filter.bpf_expression.is_empty(),
            note: if filter.bpf_expression.is_empty() {
                String::new()
            } else {
                "this build filters in userspace and ignores bpf_expression".to_string()
            },
            pcap_file_header: capture::pcap_header(capture.link_type, capture.snaplen).to_vec(),
        };
        if !responder
            .reply(id, proto::server_frame::Body::CaptureStarted(started))
            .await
        {
            self.finish_capture(capture_id).await;
            return StreamOutcome::done("client disconnected", 0);
        }

        let duration = std::time::Duration::from_millis(if request.duration_ms == 0 {
            DEFAULT_CAPTURE_DURATION_MS
        } else {
            request.duration_ms as u64
        });
        let deadline = tokio::time::Instant::now() + duration;

        let mut sent = 0u64;
        let mut bytes = 0u64;
        let reason = loop {
            if request.max_packets != 0 && sent >= request.max_packets as u64 {
                break "max_packets";
            }
            if request.max_bytes != 0 && bytes >= request.max_bytes {
                break "max_bytes";
            }

            let next = tokio::select! {
                result = capture.next_packet(&filter, request.include_payload) => result,
                _ = tokio::time::sleep_until(deadline) => break "duration",
            };

            match next {
                Ok(Some(mut packet)) => {
                    packet.capture_id = capture_id;
                    bytes += packet.original_length as u64;
                    if !responder
                        .reply(id, proto::server_frame::Body::Packet(packet))
                        .await
                    {
                        break "client disconnected";
                    }
                    sent += 1;
                }
                Ok(None) => break "stopped",
                Err(e) => {
                    debug!("capture {capture_id} failed: {e}");
                    self.finish_capture(capture_id).await;
                    return StreamOutcome::failed(proto::Error::from(e), sent);
                }
            }
        };

        let stats = capture.stats(capture_id);
        responder
            .reply(id, proto::server_frame::Body::CaptureStats(stats))
            .await;
        responder
            .reply(
                id,
                proto::server_frame::Body::CaptureFinished(proto::CaptureFinished {
                    capture_id,
                    stats: Some(stats),
                    reason: reason.to_string(),
                    error: None,
                }),
            )
            .await;

        self.finish_capture(capture_id).await;
        StreamOutcome::done(format!("capture finished: {reason}"), sent)
    }

    pub async fn stop_capture(&self, capture_id: u64) -> bool {
        let captures = self.captures.lock().await;
        match captures.get(&capture_id) {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    async fn finish_capture(&self, capture_id: u64) {
        self.captures.lock().await.remove(&capture_id);
    }
}

fn route_event_matches(event: &proto::NetworkEvent, family: proto::IpFamily, table: u32) -> bool {
    use proto::network_event::Payload;
    match &event.payload {
        Some(Payload::Route(e)) => {
            let Some(route) = &e.route else { return true };
            if family != proto::IpFamily::Unspecified && route.family != family as i32 {
                return false;
            }
            table == 0 || route.table == table
        }
        Some(Payload::Rule(e)) => {
            let Some(rule) = &e.rule else { return true };
            if family != proto::IpFamily::Unspecified && rule.family != family as i32 {
                return false;
            }
            table == 0 || rule.table == table
        }
        _ => true,
    }
}

/// Work out at startup what this kernel and policy actually allow, so the
/// client can grey out features instead of failing at them.
fn probe_capabilities() -> (proto::DaemonCapabilities, Vec<String>) {
    use netlink_sys::{Socket, protocols};

    let mut warnings = Vec::new();

    let netlink_route = Socket::new(protocols::NETLINK_ROUTE).is_ok();
    if !netlink_route {
        warnings.push("NETLINK_ROUTE is unavailable; almost nothing will work".to_string());
    }

    let inet_diag = Socket::new(protocols::NETLINK_SOCK_DIAG).is_ok();
    if !inet_diag {
        warnings.push(
            "NETLINK_INET_DIAG is unavailable; per-socket and per-app views will be empty"
                .to_string(),
        );
    }

    // SAFETY: socket(2) with constant arguments; the fd is closed immediately.
    let packet_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    let packet_capture = packet_fd >= 0;
    if packet_capture {
        // SAFETY: `packet_fd` is a valid descriptor we just created.
        unsafe { libc::close(packet_fd) };
    } else {
        warnings.push("AF_PACKET is unavailable; packet capture is disabled".to_string());
    }

    // SAFETY: socket(2) with constant arguments; the fd is closed immediately.
    let icmp_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    let raw_icmp = icmp_fd >= 0;
    if raw_icmp {
        // SAFETY: `icmp_fd` is a valid descriptor we just created.
        unsafe { libc::close(icmp_fd) };
    } else {
        // SAFETY: getgid never fails.
        let gid = unsafe { libc::getgid() };
        if collect::procnet::ping_group_range_allows(gid) {
            warnings.push(
                "raw ICMP sockets are unavailable, but ping_group_range allows datagram ICMP \
                 sockets, so ping probes will still work"
                    .to_string(),
            );
        } else {
            warnings.push(
                "neither raw nor datagram ICMP sockets are available; ping probes will be \
                 skipped"
                    .to_string(),
            );
        }
    }

    let bpf_maps = std::path::Path::new("/sys/fs/bpf").exists();
    let iptables = which("iptables-save");
    let nftables = which("nft");

    (
        proto::DaemonCapabilities {
            netlink_route,
            inet_diag,
            route_lookup: netlink_route,
            packet_capture,
            bpf_maps,
            nftables,
            iptables,
            tc: netlink_route,
            raw_icmp,
            so_mark: true,
        },
        warnings,
    )
}

fn which(program: &str) -> bool {
    [
        "/system/bin",
        "/system/xbin",
        "/vendor/bin",
        "/usr/bin",
        "/bin",
        "/sbin",
    ]
    .iter()
    .any(|dir| std::path::Path::new(dir).join(program).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_events_can_be_narrowed_by_family_and_table() {
        let event = proto::NetworkEvent {
            payload: Some(proto::network_event::Payload::Route(proto::RouteEvent {
                route: Some(proto::Route {
                    family: proto::IpFamily::V6 as i32,
                    table: 101,
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        assert!(route_event_matches(&event, proto::IpFamily::Unspecified, 0));
        assert!(route_event_matches(&event, proto::IpFamily::V6, 101));
        assert!(!route_event_matches(&event, proto::IpFamily::V4, 0));
        assert!(!route_event_matches(&event, proto::IpFamily::V6, 254));
    }

    #[test]
    fn non_route_events_pass_the_route_filter_untouched() {
        let event = proto::NetworkEvent {
            payload: Some(proto::network_event::Payload::Daemon(Default::default())),
            ..Default::default()
        };
        assert!(route_event_matches(&event, proto::IpFamily::V4, 254));
    }

    #[test]
    fn capability_probe_reports_something_sane() {
        let (capabilities, _warnings) = probe_capabilities();
        // Netlink route is available on any Linux the daemon can run on.
        assert!(capabilities.netlink_route);
        assert!(capabilities.so_mark);
    }
}
