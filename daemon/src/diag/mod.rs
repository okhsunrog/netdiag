//! The diagnosis engine.
//!
//! Two layers, deliberately separated:
//!
//! * **Checks** are facts. Each one runs an observation or a probe and reports
//!   pass/fail/warn/skip with the evidence that produced it. A check never
//!   speculates about causes.
//! * **Findings** (in [`rules`]) are interpretations. They read the whole set
//!   of check results and fire when a recognisable pattern is present, e.g.
//!   "IPv6 is configured, DNS returns AAAA, but no IPv6 connection completes".
//!
//! Keeping them apart is what makes the output trustworthy: a user can always
//! see the raw observations behind a conclusion, and a wrong interpretation
//! never corrupts the facts. It also means adding a new heuristic is a change
//! to `rules.rs` alone.
//!
//! The rules are hand-written and will stay that way. A model in this loop
//! would make the tool unable to explain itself, which is the only thing it
//! has to offer.

pub mod rules;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rtnetlink::Handle;
use tokio::sync::mpsc;
use tracing::debug;

use crate::collect::{self, firewall, links, neigh, routes, sockets};
use crate::probe::{ProbeContext, ProbeResult, dns, icmp, mtu, tcp, tls};
use crate::proto;
use crate::util::{self, Stopwatch};

/// Default host for the DNS and TLS checks. Google's connectivity-check host
/// is deliberate: it is what Android itself validates against, so a failure
/// here is directly comparable with the framework's own VALIDATED verdict.
const DEFAULT_HOSTNAME: &str = "connectivitycheck.gstatic.com";

/// Fixed endpoints for the raw TCP checks.
///
/// These are literals on purpose. If the TCP check depended on DNS, a broken
/// resolver would make every transport check fail too, and the report would
/// blame the wrong layer. Cloudflare's anycast resolvers are reachable on both
/// families and answer on 443.
const DEFAULT_V4_ENDPOINT: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const DEFAULT_V6_ENDPOINT: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const DEFAULT_TCP_PORT: u16 = 443;

/// Resolvers used only when the framework told us nothing about DNS servers.
const FALLBACK_DNS_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const FALLBACK_DNS_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

/// Number of sockets in SYN_SENT above which the state is called suspicious.
/// A couple are normal during page load; a dozen means connections are not
/// completing.
const SYN_SENT_THRESHOLD: u32 = 5;
const CLOSE_WAIT_THRESHOLD: u32 = 20;

// ---- Check construction -----------------------------------------------------

pub fn check_key(id: proto::CheckId) -> &'static str {
    use proto::CheckId as C;
    match id {
        C::Unspecified => "unspecified",
        C::AndroidNetworkState => "android.state",
        C::ActiveInterface => "iface.active",
        C::Ipv4Address => "addr.v4",
        C::Ipv6Address => "addr.v6",
        C::Ipv4DefaultRoute => "route.v4.default",
        C::Ipv6DefaultRoute => "route.v6.default",
        C::GatewayReachabilityV4 => "gateway.v4",
        C::GatewayReachabilityV6 => "gateway.v6",
        C::DnsA => "dns.a",
        C::DnsAaaa => "dns.aaaa",
        C::TcpV4 => "tcp.v4",
        C::TcpV6 => "tcp.v6",
        C::TlsHandshake => "tls.handshake",
        C::PrivateDns => "dns.private",
        C::Nat64Dns64 => "nat64.dns64",
        C::VpnRouting => "vpn.routing",
        C::FirewallAnomaly => "firewall.anomaly",
        C::MtuPmtu => "mtu.pmtu",
        C::SuspiciousTcpStates => "sockets.states",
        C::FrameworkKernelAgreement => "framework.kernel",
        C::RoutingRuleCoverage => "rules.coverage",
        C::DnsLatency => "dns.latency",
        C::CaptivePortal => "captive.portal",
        C::RouteLookupV4 => "route.lookup.v4",
        C::RouteLookupV6 => "route.lookup.v6",
    }
}

struct CheckBuilder {
    check: proto::Check,
    clock: Stopwatch,
}

impl CheckBuilder {
    fn new(id: proto::CheckId, title: &str) -> Self {
        Self {
            check: proto::Check {
                id: id as i32,
                key: check_key(id).to_string(),
                title: title.to_string(),
                ..Default::default()
            },
            clock: Stopwatch::start(),
        }
    }

    fn family(mut self, family: proto::IpFamily) -> Self {
        self.check.family = family as i32;
        self
    }

    fn depends_on(mut self, keys: &[&str]) -> Self {
        self.check.depends_on = keys.iter().map(|k| k.to_string()).collect();
        self
    }

    fn ev(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.check.evidence.insert(key.into(), value.into());
        self
    }

    fn finish(mut self, status: proto::CheckStatus, detail: impl Into<String>) -> proto::Check {
        self.check.status = status as i32;
        self.check.detail = detail.into();
        self.check.duration_ms = self.clock.elapsed_ms();
        self.check
    }

    fn pass(self, detail: impl Into<String>) -> proto::Check {
        self.finish(proto::CheckStatus::Pass, detail)
    }
    fn fail(self, detail: impl Into<String>) -> proto::Check {
        self.finish(proto::CheckStatus::Fail, detail)
    }
    fn warn(self, detail: impl Into<String>) -> proto::Check {
        self.finish(proto::CheckStatus::Warn, detail)
    }
    fn skip(self, detail: impl Into<String>) -> proto::Check {
        self.finish(proto::CheckStatus::Skip, detail)
    }
    fn info(self, detail: impl Into<String>) -> proto::Check {
        self.finish(proto::CheckStatus::Info, detail)
    }

    /// Fold a probe result into the check, carrying its evidence, its measured
    /// duration (which is the probe's own timing, not the builder's) and its
    /// error across.
    fn with_probe(mut self, result: ProbeResult) -> proto::Check {
        self.check.error = result.to_error();
        let duration_ms = result.duration_ms;
        for (k, v) in result.evidence {
            self.check.evidence.insert(k, v);
        }
        let mut check = if result.ok {
            self.pass(result.detail)
        } else {
            self.fail(result.detail)
        };
        check.duration_ms = duration_ms;
        check
    }
}

// ---- Engine -----------------------------------------------------------------

/// Everything the checks share, collected once so twenty checks do not each
/// re-dump the routing table.
pub struct DiagState {
    pub interfaces: Vec<proto::Interface>,
    pub rules: Vec<proto::RoutingRule>,
    pub routes: Vec<proto::Route>,
    pub neighbors: Vec<proto::Neighbor>,
    pub sockets: Vec<proto::Socket>,
    pub socket_summary: proto::SocketSummary,
    pub clat: proto::Clat464State,
    /// The Android Network the report is about, if the app supplied state.
    pub network: Option<proto::AndroidNetwork>,
    pub net_id: i32,
    pub probe_ctx_v4: ProbeContext,
    pub probe_ctx_v6: ProbeContext,
    pub lookup_v4: proto::RouteLookup,
    pub lookup_v6: proto::RouteLookup,
    pub egress_v4: Option<proto::Interface>,
    pub egress_v6: Option<proto::Interface>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_from_framework: bool,
    pub hostname: String,
    pub v4_endpoint: SocketAddr,
    pub v6_endpoint: SocketAddr,
    pub timeout_ms: u32,
}

pub async fn run(
    handle: &Handle,
    request: proto::DiagnoseRequest,
    emit: Option<mpsc::Sender<proto::Check>>,
) -> proto::DiagnoseResponse {
    let started_unix_ms = util::now_unix_ms();
    let clock = Stopwatch::start();

    let mut checks: Vec<proto::Check> = Vec::new();
    let push = |check: proto::Check, checks: &mut Vec<proto::Check>| {
        if let Some(tx) = &emit {
            // A full channel means the client stopped reading; the report is
            // still assembled and returned at the end.
            let _ = tx.try_send(check.clone());
        }
        checks.push(check);
    };

    let state = match gather(handle, &request).await {
        Ok(state) => state,
        Err(e) => {
            let check = CheckBuilder::new(proto::CheckId::ActiveInterface, "Collect kernel state")
                .fail(format!("could not read kernel networking state: {e}"));
            push(check, &mut checks);
            return finish(started_unix_ms, clock.elapsed_ms(), checks, Vec::new());
        }
    };

    let wanted = |id: proto::CheckId| -> bool {
        if request.skip.contains(&(id as i32)) {
            return false;
        }
        request.only.is_empty() || request.only.contains(&(id as i32))
    };

    // Structural checks first: they are instant and they decide which probes
    // are even meaningful.
    if wanted(proto::CheckId::AndroidNetworkState) {
        push(check_android_state(&state, &request), &mut checks);
    }
    if wanted(proto::CheckId::ActiveInterface) {
        push(check_active_interface(&state), &mut checks);
    }
    if wanted(proto::CheckId::RouteLookupV4) {
        push(check_route_lookup(&state, proto::IpFamily::V4), &mut checks);
    }
    if wanted(proto::CheckId::RouteLookupV6) {
        push(check_route_lookup(&state, proto::IpFamily::V6), &mut checks);
    }
    if wanted(proto::CheckId::Ipv4Address) {
        push(check_address(&state, proto::IpFamily::V4), &mut checks);
    }
    if wanted(proto::CheckId::Ipv6Address) {
        push(check_address(&state, proto::IpFamily::V6), &mut checks);
    }
    if wanted(proto::CheckId::Ipv4DefaultRoute) {
        push(
            check_default_route(&state, proto::IpFamily::V4),
            &mut checks,
        );
    }
    if wanted(proto::CheckId::Ipv6DefaultRoute) {
        push(
            check_default_route(&state, proto::IpFamily::V6),
            &mut checks,
        );
    }
    if wanted(proto::CheckId::RoutingRuleCoverage) {
        push(check_rule_coverage(&state), &mut checks);
    }
    if wanted(proto::CheckId::VpnRouting) {
        push(check_vpn(&state), &mut checks);
    }
    if wanted(proto::CheckId::FirewallAnomaly) {
        push(check_firewall(&request).await, &mut checks);
    }
    if wanted(proto::CheckId::SuspiciousTcpStates) {
        push(check_socket_states(&state), &mut checks);
    }
    if wanted(proto::CheckId::FrameworkKernelAgreement) {
        push(check_framework_agreement(&state), &mut checks);
    }
    if wanted(proto::CheckId::CaptivePortal) {
        push(check_captive_portal(&state), &mut checks);
    }

    if request.passive_only {
        for id in [
            proto::CheckId::GatewayReachabilityV4,
            proto::CheckId::GatewayReachabilityV6,
            proto::CheckId::DnsA,
            proto::CheckId::DnsAaaa,
            proto::CheckId::TcpV4,
            proto::CheckId::TcpV6,
            proto::CheckId::TlsHandshake,
            proto::CheckId::PrivateDns,
            proto::CheckId::Nat64Dns64,
            proto::CheckId::MtuPmtu,
        ] {
            if wanted(id) {
                push(
                    CheckBuilder::new(id, probe_check_title(id))
                        .skip("skipped: the request asked for passive analysis only"),
                    &mut checks,
                );
            }
        }
    } else {
        // Probes. Gateway reachability first, then DNS, then transport: that
        // order means a failure is reported at the lowest layer that broke.
        if wanted(proto::CheckId::GatewayReachabilityV4) {
            push(
                check_gateway(&state, proto::IpFamily::V4).await,
                &mut checks,
            );
        }
        if wanted(proto::CheckId::GatewayReachabilityV6) {
            push(
                check_gateway(&state, proto::IpFamily::V6).await,
                &mut checks,
            );
        }
        if wanted(proto::CheckId::DnsA) {
            push(check_dns(&state, dns::TYPE_A).await, &mut checks);
        }
        if wanted(proto::CheckId::DnsAaaa) {
            push(check_dns(&state, dns::TYPE_AAAA).await, &mut checks);
        }
        if wanted(proto::CheckId::TcpV4) {
            push(check_tcp(&state, proto::IpFamily::V4).await, &mut checks);
        }
        if wanted(proto::CheckId::TcpV6) {
            push(check_tcp(&state, proto::IpFamily::V6).await, &mut checks);
        }
        if wanted(proto::CheckId::TlsHandshake) {
            push(check_tls(&state, &checks).await, &mut checks);
        }
        if wanted(proto::CheckId::PrivateDns) {
            push(check_private_dns(&state).await, &mut checks);
        }
        if wanted(proto::CheckId::Nat64Dns64) {
            push(check_nat64(&state).await, &mut checks);
        }
        if wanted(proto::CheckId::MtuPmtu) {
            push(check_mtu(&state).await, &mut checks);
        }
    }

    let findings = rules::evaluate(&checks, &state);
    finish(started_unix_ms, clock.elapsed_ms(), checks, findings)
}

fn probe_check_title(id: proto::CheckId) -> &'static str {
    use proto::CheckId as C;
    match id {
        C::GatewayReachabilityV4 => "IPv4 gateway reachable",
        C::GatewayReachabilityV6 => "IPv6 gateway reachable",
        C::DnsA => "DNS A lookup",
        C::DnsAaaa => "DNS AAAA lookup",
        C::TcpV4 => "TCP connection over IPv4",
        C::TcpV6 => "TCP connection over IPv6",
        C::TlsHandshake => "TLS handshake",
        C::PrivateDns => "Private DNS",
        C::Nat64Dns64 => "NAT64 / DNS64",
        C::MtuPmtu => "MTU / path MTU",
        _ => "Check",
    }
}

fn finish(
    started_unix_ms: i64,
    total_duration_ms: u64,
    checks: Vec<proto::Check>,
    findings: Vec<proto::Finding>,
) -> proto::DiagnoseResponse {
    let mut passed = 0;
    let mut failed = 0;
    let mut warned = 0;
    let mut skipped = 0;
    for c in &checks {
        match proto::CheckStatus::try_from(c.status) {
            Ok(proto::CheckStatus::Pass) => passed += 1,
            Ok(proto::CheckStatus::Fail) => failed += 1,
            Ok(proto::CheckStatus::Warn) => warned += 1,
            Ok(proto::CheckStatus::Skip) => skipped += 1,
            _ => {}
        }
    }

    let worst = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(proto::FindingSeverity::Unspecified as i32);

    let summary = match findings.first() {
        Some(finding) => finding.title.clone(),
        None if failed == 0 && warned == 0 => {
            "No problems found; connectivity looks healthy on every layer checked".to_string()
        }
        None if failed == 0 => format!("{warned} warning(s), nothing conclusive"),
        None => format!("{failed} check(s) failed but no known pattern matched"),
    };

    proto::DiagnoseResponse {
        started_unix_ms,
        total_duration_ms,
        checks,
        findings,
        summary,
        worst_severity: worst,
        passed,
        failed,
        warned,
        skipped,
    }
}

// ---- Gathering --------------------------------------------------------------

async fn gather(handle: &Handle, request: &proto::DiagnoseRequest) -> anyhow::Result<DiagState> {
    let target = request.target.clone().unwrap_or_default();

    let interfaces = links::get_interfaces(handle, true, true).await?;
    let if_names = collect::interface_names(&interfaces);
    let route_dump =
        routes::get_routes(handle, proto::IpFamily::Unspecified, 0, false, 0, &if_names).await?;
    let rules = routes::get_rules(handle, proto::IpFamily::Unspecified, None).await?;
    let neighbors =
        neigh::get_neighbors(handle, proto::IpFamily::Unspecified, 0, false, &if_names).await?;

    let socket_filter = proto::SocketFilter {
        include_tcp_info: true,
        ..Default::default()
    };
    let socket_dump = sockets::get_sockets(&socket_filter, &if_names)
        .await
        .unwrap_or_else(|e| {
            debug!("socket dump failed during diagnosis: {e}");
            sockets::SocketDump {
                sockets: Vec::new(),
                summary: Default::default(),
                truncated: false,
            }
        });

    let android_state = request.android_state.clone();
    let net_id = resolve_net_id(&target, android_state.as_ref());
    let network = android_state.as_ref().and_then(|s| {
        s.networks
            .iter()
            .find(|n| n.net_id == net_id)
            .or_else(|| s.networks.iter().find(|n| n.is_default))
            .cloned()
    });

    let timeout_ms = target.timeout_ms;
    let base_ctx = ProbeContext::with_timeout(timeout_ms).pinned_to_net_id(net_id);

    let uid = if target.has_as_uid {
        Some(target.as_uid)
    } else {
        None
    };
    let mark = base_ctx.mark;

    let lookup_v4 = routes::route_lookup(
        handle,
        IpAddr::V4(DEFAULT_V4_ENDPOINT),
        None,
        uid,
        mark,
        0,
        &if_names,
    )
    .await;
    let lookup_v6 = routes::route_lookup(
        handle,
        IpAddr::V6(DEFAULT_V6_ENDPOINT),
        None,
        uid,
        mark,
        0,
        &if_names,
    )
    .await;

    let egress_v4 = egress_interface(&lookup_v4, &interfaces);
    let egress_v6 = egress_interface(&lookup_v6, &interfaces);

    // Bind probes to the interface the kernel says it would use. The mark
    // alone is usually enough, but when the app supplied no netId there is no
    // mark and the device name is all we have.
    let probe_ctx_v4 = match &egress_v4 {
        Some(iface) => base_ctx.clone().on_device(iface.name.clone()),
        None => base_ctx.clone(),
    };
    let probe_ctx_v6 = match &egress_v6 {
        Some(iface) => base_ctx.clone().on_device(iface.name.clone()),
        None => base_ctx.clone(),
    };

    let (dns_servers, dns_from_framework) = resolve_dns_servers(network.as_ref());

    let hostname = if target.hostname.is_empty() {
        DEFAULT_HOSTNAME.to_string()
    } else {
        target.hostname.clone()
    };
    let port = if target.tcp_port == 0 {
        DEFAULT_TCP_PORT
    } else {
        target.tcp_port as u16
    };
    let v4_endpoint = SocketAddr::new(
        target
            .ipv4_endpoint
            .as_ref()
            .and_then(|a| a.to_ip())
            .unwrap_or(IpAddr::V4(DEFAULT_V4_ENDPOINT)),
        port,
    );
    let v6_endpoint = SocketAddr::new(
        target
            .ipv6_endpoint
            .as_ref()
            .and_then(|a| a.to_ip())
            .unwrap_or(IpAddr::V6(DEFAULT_V6_ENDPOINT)),
        port,
    );

    Ok(DiagState {
        clat: crate::collect::procnet::detect_clat(&interfaces),
        interfaces,
        rules,
        routes: route_dump.routes,
        neighbors,
        sockets: socket_dump.sockets,
        socket_summary: socket_dump.summary,
        network,
        net_id,
        probe_ctx_v4,
        probe_ctx_v6,
        lookup_v4,
        lookup_v6,
        egress_v4,
        egress_v6,
        dns_servers,
        dns_from_framework,
        hostname,
        v4_endpoint,
        v6_endpoint,
        timeout_ms,
    })
}

fn resolve_net_id(
    target: &proto::DiagnoseTarget,
    android_state: Option<&proto::AndroidNetworkState>,
) -> i32 {
    if target.net_id != 0 {
        return target.net_id;
    }
    android_state
        .filter(|s| s.has_active_network)
        .map(|s| s.active_net_id)
        .unwrap_or(0)
}

fn egress_interface(
    lookup: &proto::RouteLookup,
    interfaces: &[proto::Interface],
) -> Option<proto::Interface> {
    let route = lookup.route.as_ref()?;
    let hop = route.next_hops.first()?;
    interfaces
        .iter()
        .find(|i| i.index == hop.out_interface_index)
        .cloned()
}

/// DNS servers to test, preferring the ones the framework actually configured.
/// Falling back to a public resolver still exercises the path, but the check
/// says so, because "DNS works against 1.1.1.1" and "DNS works" are different
/// claims when the network's own resolver is the broken thing.
fn resolve_dns_servers(network: Option<&proto::AndroidNetwork>) -> (Vec<IpAddr>, bool) {
    if let Some(network) = network
        && let Some(lp) = &network.link_properties
    {
        let servers: Vec<IpAddr> = lp.dns_servers.iter().filter_map(|a| a.to_ip()).collect();
        if !servers.is_empty() {
            return (servers, true);
        }
    }
    (
        vec![IpAddr::V4(FALLBACK_DNS_V4), IpAddr::V6(FALLBACK_DNS_V6)],
        false,
    )
}

// ---- Individual checks ------------------------------------------------------

fn check_android_state(state: &DiagState, request: &proto::DiagnoseRequest) -> proto::Check {
    let builder = CheckBuilder::new(
        proto::CheckId::AndroidNetworkState,
        "Android framework network state",
    );

    let Some(android) = &request.android_state else {
        return builder.skip(
            "the app did not supply ConnectivityManager state, so framework-level checks \
             cannot run",
        );
    };
    let Some(network) = &state.network else {
        return builder
            .ev("networks", android.networks.len().to_string())
            .fail("ConnectivityManager reports no usable network");
    };

    let caps = network.capabilities.clone().unwrap_or_default();
    let transports: Vec<String> = network
        .transports
        .iter()
        .map(|t| {
            proto::Transport::try_from(*t)
                .map(|t| transport_name(t).to_string())
                .unwrap_or_else(|_| format!("transport {t}"))
        })
        .collect();

    let builder = builder
        .ev("net_id", network.net_id.to_string())
        .ev("net_id_under_test", state.net_id.to_string())
        .ev("probe_timeout_ms", state.timeout_ms.to_string())
        .ev("network_handle", network.network_handle.to_string())
        .ev("transports", transports.join(", "))
        .ev("validated", caps.validated.to_string())
        .ev("internet_capability", caps.internet.to_string())
        .ev("metered", (!caps.not_metered).to_string())
        .ev("captive_portal", caps.captive_portal.to_string())
        .ev("is_default", network.is_default.to_string())
        .ev(
            "interface",
            network
                .link_properties
                .as_ref()
                .map(|lp| lp.interface_name.clone())
                .unwrap_or_default(),
        );

    if !caps.internet {
        return builder.fail(format!(
            "network {} does not claim NET_CAPABILITY_INTERNET",
            network.net_id
        ));
    }
    if caps.captive_portal {
        return builder.warn(format!(
            "network {} is behind a captive portal according to the framework",
            network.net_id
        ));
    }
    if !caps.validated {
        return builder.warn(format!(
            "network {} has INTERNET but not VALIDATED: Android could not confirm \
             end-to-end connectivity",
            network.net_id
        ));
    }
    if caps.partial_connectivity {
        return builder.warn(format!(
            "network {} reports partial connectivity",
            network.net_id
        ));
    }

    builder.pass(format!(
        "network {} is VALIDATED over {}",
        network.net_id,
        transports.join("+")
    ))
}

pub fn transport_name(t: proto::Transport) -> &'static str {
    use proto::Transport as T;
    match t {
        T::Cellular => "cellular",
        T::Wifi => "Wi-Fi",
        T::Bluetooth => "Bluetooth",
        T::Ethernet => "Ethernet",
        T::Vpn => "VPN",
        T::WifiAware => "Wi-Fi Aware",
        T::Lowpan => "LoWPAN",
        T::Usb => "USB",
        T::Thread => "Thread",
        T::Satellite => "satellite",
        T::Unspecified => "unknown",
    }
}

fn check_active_interface(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::ActiveInterface, "Active egress interface");

    let iface = state.egress_v4.as_ref().or(state.egress_v6.as_ref());
    let Some(iface) = iface else {
        return builder.fail(
            "the kernel has no route to the internet for either family; nothing would leave \
             the device",
        );
    };

    let flags = iface.flags.unwrap_or_default();
    let builder = builder
        .ev("interface", iface.name.clone())
        .ev("index", iface.index.to_string())
        .ev("mtu", iface.mtu.to_string())
        .ev(
            "kind",
            format!(
                "{:?}",
                proto::LinkKind::try_from(iface.kind).unwrap_or(proto::LinkKind::Unspecified)
            ),
        )
        .ev(
            "oper_state",
            format!(
                "{:?}",
                proto::OperState::try_from(iface.oper_state)
                    .unwrap_or(proto::OperState::Unspecified)
            ),
        )
        .ev(
            "egress_v4",
            state
                .egress_v4
                .as_ref()
                .map(|i| i.name.clone())
                .unwrap_or_else(|| "none".into()),
        )
        .ev(
            "egress_v6",
            state
                .egress_v6
                .as_ref()
                .map(|i| i.name.clone())
                .unwrap_or_else(|| "none".into()),
        );

    if !flags.up {
        return builder.fail(format!(
            "{} is the egress interface but is not UP",
            iface.name
        ));
    }
    if !flags.running {
        return builder.warn(format!(
            "{} is UP but has no carrier (IFF_RUNNING is clear)",
            iface.name
        ));
    }

    builder.pass(format!(
        "traffic leaves via {} (index {}, MTU {})",
        iface.name, iface.index, iface.mtu
    ))
}

fn check_route_lookup(state: &DiagState, family: proto::IpFamily) -> proto::Check {
    let (id, lookup, target) = match family {
        proto::IpFamily::V6 => (
            proto::CheckId::RouteLookupV6,
            &state.lookup_v6,
            IpAddr::V6(DEFAULT_V6_ENDPOINT),
        ),
        _ => (
            proto::CheckId::RouteLookupV4,
            &state.lookup_v4,
            IpAddr::V4(DEFAULT_V4_ENDPOINT),
        ),
    };

    let builder = CheckBuilder::new(
        id,
        &format!("Kernel route lookup ({})", family_label(family)),
    )
    .family(family)
    .ev("destination", target.to_string())
    .ev("mark", format!("0x{:x}", lookup.fwmark))
    .ev("uid", lookup.uid.to_string());

    if let Some(err) = &lookup.error {
        return builder.fail(format!(
            "the kernel could not route to {target}: {}",
            err.message
        ));
    }

    let Some(route) = &lookup.route else {
        return builder.fail(format!("the kernel returned no route to {target}"));
    };

    let hop = route.next_hops.first().cloned().unwrap_or_default();
    let gateway = hop
        .gateway
        .as_ref()
        .map(|g| g.display())
        .unwrap_or_else(|| "on-link".to_string());

    builder
        .ev("table", format!("{} ({})", route.table, route.table_name))
        .ev("out_interface", hop.out_interface_name.clone())
        .ev("gateway", gateway.clone())
        .ev(
            "source",
            route
                .preferred_source
                .as_ref()
                .map(|s| s.display())
                .unwrap_or_default(),
        )
        .info(format!(
            "packets to {target} take table {} out of {} via {}",
            route.table, hop.out_interface_name, gateway
        ))
}

fn family_label(family: proto::IpFamily) -> &'static str {
    match family {
        proto::IpFamily::V4 => "IPv4",
        proto::IpFamily::V6 => "IPv6",
        proto::IpFamily::Unspecified => "any",
    }
}

fn check_address(state: &DiagState, family: proto::IpFamily) -> proto::Check {
    let (id, egress) = match family {
        proto::IpFamily::V6 => (proto::CheckId::Ipv6Address, &state.egress_v6),
        _ => (proto::CheckId::Ipv4Address, &state.egress_v4),
    };

    let builder = CheckBuilder::new(id, &format!("{} address assigned", family_label(family)))
        .family(family)
        .depends_on(&["iface.active"]);

    // Fall back to the other family's egress interface: a v6-only network has
    // no v4 egress, and we still want to report on its interface.
    let iface = egress
        .as_ref()
        .or(state.egress_v4.as_ref())
        .or(state.egress_v6.as_ref());
    let Some(iface) = iface else {
        return builder.skip("no egress interface was identified");
    };

    let addresses: Vec<String> = iface
        .addresses
        .iter()
        .filter(|a| {
            a.prefix
                .as_ref()
                .and_then(|p| p.ip())
                .map(|ip| match family {
                    proto::IpFamily::V6 => ip.is_ipv6(),
                    _ => ip.is_ipv4(),
                })
                .unwrap_or(false)
        })
        .map(|a| {
            let text = a.prefix.as_ref().map(|p| p.display()).unwrap_or_default();
            let scope =
                proto::AddressScope::try_from(a.scope).unwrap_or(proto::AddressScope::Unspecified);
            format!("{text} ({scope:?})")
        })
        .collect();

    let builder = builder
        .ev("interface", iface.name.clone())
        .ev("addresses", addresses.join(", "));

    let builder = if family == proto::IpFamily::V6 {
        let sysctls = iface.sysctls.unwrap_or_default();
        builder
            .ev("disable_ipv6", sysctls.ipv6_disabled.to_string())
            .ev("accept_ra", sysctls.accept_ra.to_string())
    } else {
        builder
    };

    if links::has_global_address(iface, family) {
        return builder.pass(format!(
            "{} has a global {} address: {}",
            iface.name,
            family_label(family),
            addresses.join(", ")
        ));
    }

    let tentative = iface.addresses.iter().any(|a| {
        a.flags.as_ref().map(|f| f.tentative).unwrap_or(false)
            && a.prefix
                .as_ref()
                .and_then(|p| p.ip())
                .map(|ip| ip.is_ipv6())
                .unwrap_or(false)
    });
    if family == proto::IpFamily::V6 && tentative {
        return builder.warn(format!(
            "{} has only tentative IPv6 addresses; duplicate address detection has not \
             finished",
            iface.name
        ));
    }

    if family == proto::IpFamily::V6
        && iface
            .sysctls
            .as_ref()
            .map(|s| s.ipv6_disabled)
            .unwrap_or(false)
    {
        return builder.fail(format!(
            "IPv6 is disabled on {} by the disable_ipv6 sysctl",
            iface.name
        ));
    }

    builder.fail(format!(
        "{} has no global {} address",
        iface.name,
        family_label(family)
    ))
}

fn check_default_route(state: &DiagState, family: proto::IpFamily) -> proto::Check {
    let (id, lookup) = match family {
        proto::IpFamily::V6 => (proto::CheckId::Ipv6DefaultRoute, &state.lookup_v6),
        _ => (proto::CheckId::Ipv4DefaultRoute, &state.lookup_v4),
    };

    let builder =
        CheckBuilder::new(id, &format!("{} default route", family_label(family))).family(family);

    // The table the kernel actually chose is the only one whose default route
    // matters; a default route in `main` is irrelevant if the uid rules send
    // this traffic to table 101.
    let table = lookup.route.as_ref().map(|r| r.table);

    let defaults: Vec<&proto::Route> = state
        .routes
        .iter()
        .filter(|r| r.is_default && r.family == family as i32)
        .collect();

    let in_table: Vec<&&proto::Route> =
        defaults.iter().filter(|r| Some(r.table) == table).collect();

    let describe = |r: &proto::Route| {
        let hop = r.next_hops.first().cloned().unwrap_or_default();
        format!(
            "table {} via {} dev {} metric {}",
            r.table,
            hop.gateway
                .as_ref()
                .map(|g| g.display())
                .unwrap_or_else(|| "on-link".into()),
            hop.out_interface_name,
            r.priority
        )
    };

    let builder = builder
        .ev(
            "selected_table",
            table
                .map(|t| t.to_string())
                .unwrap_or_else(|| "none".into()),
        )
        .ev("default_routes_total", defaults.len().to_string())
        .ev(
            "all_default_routes",
            defaults
                .iter()
                .map(|r| describe(r))
                .collect::<Vec<_>>()
                .join(" | "),
        );

    if in_table.is_empty() {
        if defaults.is_empty() {
            return builder.fail(format!(
                "there is no {} default route in any table",
                family_label(family)
            ));
        }
        // No table means the lookup itself failed, so there is no "the table
        // this traffic uses" to name. Saying which tables do have a default
        // route is the useful part: it shows the routes exist but are not
        // reachable from the policy this traffic follows.
        let Some(table) = table else {
            let tables: Vec<String> = {
                let mut ids: Vec<u32> = defaults.iter().map(|r| r.table).collect();
                ids.sort_unstable();
                ids.dedup();
                ids.iter().map(|t| t.to_string()).collect()
            };
            return builder.fail(format!(
                "{} default route(s) exist (in table(s) {}) but the kernel's policy lookup \
                 reaches none of them, so this traffic has no {} path at all",
                defaults.len(),
                tables.join(", "),
                family_label(family)
            ));
        };
        return builder.fail(format!(
            "there are {} default route(s) for {} but none in table {table}, which is the \
             table this traffic uses",
            defaults.len(),
            family_label(family),
        ));
    }

    if in_table.len() > 1 {
        return builder.warn(format!(
            "table {} has {} competing {} default routes",
            table.unwrap_or(0),
            in_table.len(),
            family_label(family)
        ));
    }

    builder.pass(format!(
        "{} default route present: {}",
        family_label(family),
        describe(in_table[0])
    ))
}

fn check_rule_coverage(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(
        proto::CheckId::RoutingRuleCoverage,
        "Policy routing rule coverage",
    );

    let uid_rules: Vec<&proto::RoutingRule> =
        state.rules.iter().filter(|r| r.has_uid_range).collect();
    let mark_rules: Vec<&proto::RoutingRule> =
        state.rules.iter().filter(|r| r.has_fwmark).collect();

    let builder = builder
        .ev("total_rules", state.rules.len().to_string())
        .ev("uid_range_rules", uid_rules.len().to_string())
        .ev("fwmark_rules", mark_rules.len().to_string())
        .ev("tables_referenced", {
            let mut tables: Vec<u32> = state.rules.iter().map(|r| r.table).collect();
            tables.sort_unstable();
            tables.dedup();
            tables
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        });

    if state.rules.is_empty() {
        return builder.fail(
            "the kernel reports no policy routing rules at all, which is impossible on a \
             healthy Android device",
        );
    }

    if mark_rules.is_empty() {
        return builder.warn(
            "no fwmark-based rules are installed; Android normally uses them to bind \
             sockets to networks",
        );
    }

    builder.pass(format!(
        "{} rules installed, {} of them selecting on fwmark and {} on uid ranges",
        state.rules.len(),
        mark_rules.len(),
        uid_rules.len()
    ))
}

fn check_vpn(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::VpnRouting, "VPN routing");

    let vpn_ifaces: Vec<&proto::Interface> = state
        .interfaces
        .iter()
        .filter(|i| {
            i.kind == proto::LinkKind::VpnTun as i32
                && i.flags.as_ref().map(|f| f.up).unwrap_or(false)
        })
        .collect();

    let framework_vpn = state
        .network
        .as_ref()
        .map(|n| n.transports.contains(&(proto::Transport::Vpn as i32)))
        .unwrap_or(false);

    let builder = builder
        .ev(
            "vpn_interfaces",
            vpn_ifaces
                .iter()
                .map(|i| i.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
        )
        .ev("framework_reports_vpn", framework_vpn.to_string());

    if vpn_ifaces.is_empty() && !framework_vpn {
        return builder.skip("no VPN is active");
    }

    if vpn_ifaces.is_empty() && framework_vpn {
        return builder.fail(
            "the framework reports a VPN transport but no tun interface is up in the kernel",
        );
    }

    let vpn = vpn_ifaces[0];
    let egress_is_vpn = state
        .egress_v4
        .as_ref()
        .map(|i| i.index == vpn.index)
        .unwrap_or(false)
        || state
            .egress_v6
            .as_ref()
            .map(|i| i.index == vpn.index)
            .unwrap_or(false);

    // A link-local or on-link prefix route on the tun device is not an IPv6
    // path; only a default route through it means IPv6 actually goes into the
    // tunnel. Accepting any route here made a VPN that carries no IPv6 look
    // healthy.
    let vpn_default_v6 = state.routes.iter().any(|r| {
        r.is_default
            && r.family == proto::IpFamily::V6 as i32
            && r.next_hops
                .iter()
                .any(|h| h.out_interface_index == vpn.index)
    });
    let vpn_default_v4 = state.routes.iter().any(|r| {
        r.is_default
            && r.family == proto::IpFamily::V4 as i32
            && r.next_hops
                .iter()
                .any(|h| h.out_interface_index == vpn.index)
    });

    // Android blackholes IPv6 for a v4-only VPN by pointing the tunnel table's
    // IPv6 default route at loopback. Naming that explicitly turns a confusing
    // "IPv6 is broken" into "the VPN is deliberately blocking IPv6", which is
    // working as intended and needs no fixing.
    let vpn_table = state.lookup_v4.route.as_ref().map(|r| r.table);
    let ipv6_blackholed = state.routes.iter().any(|r| {
        r.is_default
            && r.family == proto::IpFamily::V6 as i32
            && Some(r.table) == vpn_table
            && r.next_hops
                .iter()
                .any(|h| h.out_interface_name == "lo" || h.out_interface_index == 1)
    }) || state.routes.iter().any(|r| {
        r.is_default
            && r.family == proto::IpFamily::V6 as i32
            && Some(r.table) == vpn_table
            && (r.r#type == proto::RouteType::Unreachable as i32
                || r.r#type == proto::RouteType::Blackhole as i32
                || r.r#type == proto::RouteType::Prohibit as i32)
    });

    let builder = builder
        .ev("egress_is_vpn", egress_is_vpn.to_string())
        .ev("vpn_has_ipv6_routes", vpn_default_v6.to_string())
        .ev("vpn_default_route_v4", vpn_default_v4.to_string())
        .ev("ipv6_blackholed_in_vpn_table", ipv6_blackholed.to_string())
        .ev(
            "vpn_table",
            vpn_table
                .map(|t| t.to_string())
                .unwrap_or_else(|| "?".into()),
        );

    if !egress_is_vpn {
        return builder.warn(format!(
            "{} is up but this traffic does not go through it; it is being routed around \
             the VPN",
            vpn.name
        ));
    }

    if !vpn_default_v6 {
        if ipv6_blackholed {
            return builder.info(format!(
                "{} carries IPv4 only, and IPv6 is deliberately blackholed inside the VPN's \
                 routing table; applications fall back to IPv4 cleanly and nothing leaks",
                vpn.name
            ));
        }
        return builder.warn(format!(
            "{} carries IPv4 but has no IPv6 default route and IPv6 is not blackholed; IPv6 \
             traffic may leave outside the tunnel",
            vpn.name
        ));
    }

    builder.pass(format!(
        "traffic is routed through {}, for both IPv4 and IPv6",
        vpn.name
    ))
}

async fn check_firewall(request: &proto::DiagnoseRequest) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::FirewallAnomaly, "Firewall interaction");

    let target = request.target.clone().unwrap_or_default();
    let uid = if target.has_as_uid {
        target.as_uid
    } else {
        // With no uid to ask about, report the surface that exists rather than
        // claiming anything about a specific app.
        let fw = firewall::collect(false).await;
        return builder
            .ev("backends", format!("{:?}", fw.backends_detected))
            .ev("bpf_objects", fw.bpf_pinned_objects.len().to_string())
            .ev("note", fw.collection_note.clone())
            .info(fw.collection_note);
    };

    let uid_state = firewall::read_uid_firewall(uid);
    let builder = builder
        .ev("uid", uid.to_string())
        .ev("raw_match", format!("0x{:x}", uid_state.raw_match))
        .ev(
            "matches",
            firewall::decode_match_bits(uid_state.raw_match).join(", "),
        )
        .ev("source_available", uid_state.source_available.to_string());

    if !uid_state.source_available {
        return builder.skip(
            "netd's eBPF uid_owner_map could not be read, so per-app firewall state is not \
             determinable",
        );
    }

    if firewall::is_unambiguously_denied(&uid_state) {
        return builder.fail(format!(
            "uid {uid} is denied by a firewall rule: {}",
            firewall::decode_match_bits(uid_state.raw_match).join(", ")
        ));
    }

    if uid_state.raw_match == 0 {
        return builder.pass(format!("no per-uid firewall rules apply to uid {uid}"));
    }

    builder.info(format!(
        "uid {uid} has firewall bits set: {}",
        firewall::decode_match_bits(uid_state.raw_match).join(", ")
    ))
}

fn check_socket_states(state: &DiagState) -> proto::Check {
    let summary = &state.socket_summary;

    // Which family the stuck connections are on is what turns a generic
    // "connections are not completing" into evidence for a specific finding.
    let syn_sent_v6 = state
        .sockets
        .iter()
        .filter(|s| {
            s.state == proto::TcpState::SynSent as i32 && s.family == proto::IpFamily::V6 as i32
        })
        .count();
    let syn_sent_v4 = summary.syn_sent as usize - syn_sent_v6.min(summary.syn_sent as usize);

    let builder = CheckBuilder::new(proto::CheckId::SuspiciousTcpStates, "TCP socket states")
        .ev("syn_sent_v4", syn_sent_v4.to_string())
        .ev("syn_sent_v6", syn_sent_v6.to_string())
        .ev("total", summary.total.to_string())
        .ev("established", summary.established.to_string())
        .ev("syn_sent", summary.syn_sent.to_string())
        .ev("close_wait", summary.close_wait.to_string())
        .ev("fin_wait", summary.fin_wait.to_string())
        .ev("time_wait", summary.time_wait.to_string())
        .ev("retransmitting", summary.retransmitting.to_string());

    if summary.total == 0 {
        return builder.skip("no sockets were readable");
    }

    if summary.syn_sent >= SYN_SENT_THRESHOLD {
        return builder.fail(format!(
            "{} sockets are stuck in SYN_SENT: SYNs are leaving and nothing is answering",
            summary.syn_sent
        ));
    }
    if summary.close_wait >= CLOSE_WAIT_THRESHOLD {
        return builder.warn(format!(
            "{} sockets are in CLOSE_WAIT, which usually means an app is not closing \
             connections the peer already finished with",
            summary.close_wait
        ));
    }
    if summary.retransmitting > 0 && summary.established > 0 {
        let ratio = summary.retransmitting as f32 / summary.established as f32;
        if ratio > 0.25 {
            return builder.warn(format!(
                "{} of {} established connections are retransmitting",
                summary.retransmitting, summary.established
            ));
        }
    }

    builder.pass(format!(
        "{} sockets, {} established, nothing stuck",
        summary.total, summary.established
    ))
}

fn check_framework_agreement(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(
        proto::CheckId::FrameworkKernelAgreement,
        "Framework and kernel agree",
    );

    let Some(network) = &state.network else {
        return builder.skip("no framework state to compare against");
    };
    let Some(lp) = &network.link_properties else {
        return builder.skip("the framework reported no LinkProperties");
    };

    let mut disagreements: Vec<String> = Vec::new();

    // Interface existence and state.
    let kernel_iface = state
        .interfaces
        .iter()
        .find(|i| i.name == lp.interface_name);
    match kernel_iface {
        None if !lp.interface_name.is_empty() => {
            disagreements.push(format!(
                "the framework names interface {} but the kernel has no such interface",
                lp.interface_name
            ));
        }
        Some(iface) => {
            if !iface.flags.as_ref().map(|f| f.up).unwrap_or(false) {
                disagreements.push(format!(
                    "the framework is using {} but the kernel has it DOWN",
                    iface.name
                ));
            }
            if lp.mtu > 0 && iface.mtu > 0 && lp.mtu as u32 != iface.mtu {
                disagreements.push(format!(
                    "MTU mismatch on {}: framework says {}, kernel says {}",
                    iface.name, lp.mtu, iface.mtu
                ));
            }

            // Addresses.
            let kernel_addrs: Vec<String> = iface
                .addresses
                .iter()
                .filter_map(|a| a.prefix.as_ref().map(|p| p.display()))
                .collect();
            for framework_addr in &lp.link_addresses {
                let text = framework_addr.display();
                if !kernel_addrs.contains(&text) {
                    disagreements.push(format!(
                        "the framework reports address {text} on {} but the kernel does not \
                         have it",
                        iface.name
                    ));
                }
            }
        }
        _ => {}
    }

    // Default routes.
    let framework_default_v4 = lp.routes.iter().any(|r| {
        r.is_default
            && r.destination
                .as_ref()
                .and_then(|d| d.ip())
                .map(|ip| ip.is_ipv4())
                .unwrap_or(false)
    });
    let framework_default_v6 = lp.routes.iter().any(|r| {
        r.is_default
            && r.destination
                .as_ref()
                .and_then(|d| d.ip())
                .map(|ip| ip.is_ipv6())
                .unwrap_or(false)
    });
    let kernel_default_v4 = state.lookup_v4.route.is_some();
    let kernel_default_v6 = state.lookup_v6.route.is_some();

    if framework_default_v6 && !kernel_default_v6 {
        disagreements.push(
            "the framework lists an IPv6 default route but the kernel cannot route IPv6 to \
             the internet"
                .to_string(),
        );
    }
    if framework_default_v4 && !kernel_default_v4 {
        disagreements.push(
            "the framework lists an IPv4 default route but the kernel cannot route IPv4 to \
             the internet"
                .to_string(),
        );
    }

    let builder = builder
        .ev("framework_interface", lp.interface_name.clone())
        .ev("framework_mtu", lp.mtu.to_string())
        .ev(
            "framework_default_routes",
            format!("v4={framework_default_v4} v6={framework_default_v6}"),
        )
        .ev(
            "kernel_default_routes",
            format!("v4={kernel_default_v4} v6={kernel_default_v6}"),
        )
        .ev("disagreements", disagreements.len().to_string());

    if disagreements.is_empty() {
        return builder
            .pass("the framework's view of interfaces, addresses and routes matches the kernel");
    }

    builder.fail(disagreements.join("; "))
}

fn check_captive_portal(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::CaptivePortal, "Captive portal");

    let Some(network) = &state.network else {
        return builder.skip("no framework state; captive portal status comes from Android");
    };
    let caps = network.capabilities.clone().unwrap_or_default();
    let portal_url = network
        .link_properties
        .as_ref()
        .map(|lp| lp.captive_portal_api_url.clone())
        .unwrap_or_default();

    let builder = builder
        .ev("captive_portal_capability", caps.captive_portal.to_string())
        .ev("validated", caps.validated.to_string())
        .ev("captive_portal_api_url", portal_url.clone());

    if caps.captive_portal {
        return builder.fail(
            "Android has detected a captive portal; traffic is being intercepted until the \
             portal is satisfied",
        );
    }
    if !caps.validated && caps.internet {
        return builder.warn(
            "the network is not validated; a captive portal that Android has not classified \
             yet would look exactly like this",
        );
    }
    builder.pass("no captive portal detected")
}

// ---- Probe-backed checks ----------------------------------------------------

async fn check_gateway(state: &DiagState, family: proto::IpFamily) -> proto::Check {
    let (id, lookup, ctx) = match family {
        proto::IpFamily::V6 => (
            proto::CheckId::GatewayReachabilityV6,
            &state.lookup_v6,
            &state.probe_ctx_v6,
        ),
        _ => (
            proto::CheckId::GatewayReachabilityV4,
            &state.lookup_v4,
            &state.probe_ctx_v4,
        ),
    };

    let builder = CheckBuilder::new(id, &format!("{} gateway reachable", family_label(family)))
        .family(family)
        .depends_on(&[if family == proto::IpFamily::V6 {
            "route.v6.default"
        } else {
            "route.v4.default"
        }]);

    let Some(route) = &lookup.route else {
        return builder.skip(format!(
            "no {} route, so there is no gateway to test",
            family_label(family)
        ));
    };
    let hop = route.next_hops.first().cloned().unwrap_or_default();
    let Some(gateway) = hop.gateway.as_ref().and_then(|g| g.to_ip()) else {
        return builder.skip(format!(
            "the {} route is on-link (no gateway to probe)",
            family_label(family)
        ));
    };

    // The neighbour table is the cheap answer, and it distinguishes "we never
    // got an ARP/NDP reply" from "the gateway is there but the path beyond is
    // broken".
    let entry = neigh::find_gateway(&state.neighbors, gateway, hop.out_interface_index);
    let neighbor_state = entry
        .map(|n| {
            proto::NeighborState::try_from(n.state).unwrap_or(proto::NeighborState::Unspecified)
        })
        .unwrap_or(proto::NeighborState::None);

    let builder = builder
        .ev("gateway", gateway.to_string())
        .ev("interface", hop.out_interface_name.clone())
        .ev("neighbor_state", format!("{neighbor_state:?}"))
        .ev(
            "link_address",
            entry
                .map(|n| util::format_mac(&n.link_address))
                .unwrap_or_default(),
        );

    let ping = icmp::ping(gateway, 2, 56, ctx).await;
    let builder = builder
        .ev("icmp", ping.detail.clone())
        .ev("routing", ctx.describe());

    if ping.ok {
        return builder.pass(format!("gateway {gateway} answers ICMP echo"));
    }

    // Many gateways drop ICMP on purpose. A usable neighbour entry is proof
    // enough that the next hop exists, so this is a warning, not a failure.
    if neigh::is_usable(neighbor_state) {
        return builder.warn(format!(
            "gateway {gateway} does not answer ICMP but is present in the neighbour table \
             as {neighbor_state:?}; many gateways filter ICMP, so this is not conclusive"
        ));
    }

    builder.fail(format!(
        "gateway {gateway} is unreachable: neighbour state is {neighbor_state:?} and it does \
         not answer ICMP"
    ))
}

async fn check_dns(state: &DiagState, qtype: u16) -> proto::Check {
    let (id, label) = if qtype == dns::TYPE_A {
        (proto::CheckId::DnsA, "A")
    } else {
        (proto::CheckId::DnsAaaa, "AAAA")
    };

    let mut builder = CheckBuilder::new(id, &format!("DNS {label} lookup"))
        .ev("hostname", state.hostname.clone())
        .ev("from_framework", state.dns_from_framework.to_string())
        .ev(
            "servers",
            state
                .dns_servers
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );

    if state.dns_servers.is_empty() {
        return builder.skip("no DNS servers are configured for this network");
    }

    let mut last: Option<ProbeResult> = None;
    for (index, server) in state.dns_servers.iter().enumerate() {
        let ctx = if server.is_ipv6() {
            &state.probe_ctx_v6
        } else {
            &state.probe_ctx_v4
        };
        let result = dns::probe(SocketAddr::new(*server, 53), &state.hostname, qtype, ctx).await;
        builder = builder.ev(
            format!("server_{index}"),
            format!("{server}: {}", result.detail),
        );
        if result.ok {
            return builder.with_probe(result);
        }
        last = Some(result);
    }

    match last {
        Some(result) => builder.with_probe(result),
        None => builder.skip("no DNS server was tried"),
    }
}

async fn check_tcp(state: &DiagState, family: proto::IpFamily) -> proto::Check {
    let (id, endpoint, ctx, address_check) = match family {
        proto::IpFamily::V6 => (
            proto::CheckId::TcpV6,
            state.v6_endpoint,
            &state.probe_ctx_v6,
            "addr.v6",
        ),
        _ => (
            proto::CheckId::TcpV4,
            state.v4_endpoint,
            &state.probe_ctx_v4,
            "addr.v4",
        ),
    };

    let builder = CheckBuilder::new(id, &format!("TCP connection over {}", family_label(family)))
        .family(family)
        .depends_on(&[address_check]);

    // Without a route the connect would fail instantly with ENETUNREACH,
    // which says nothing new beyond what the route check already reported.
    let has_route = match family {
        proto::IpFamily::V6 => state.lookup_v6.route.is_some(),
        _ => state.lookup_v4.route.is_some(),
    };
    if !has_route {
        return builder.skip(format!(
            "no {} route to the internet, so a TCP test would only repeat that",
            family_label(family)
        ));
    }

    builder.with_probe(tcp::connect(endpoint, ctx).await)
}

async fn check_tls(state: &DiagState, existing: &[proto::Check]) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::TlsHandshake, "TLS handshake")
        .depends_on(&["tcp.v4", "tcp.v6"]);

    let passed = |key: &str| {
        existing
            .iter()
            .any(|c| c.key == key && c.status == proto::CheckStatus::Pass as i32)
    };

    // Run TLS over whichever family actually established TCP, preferring IPv6
    // when both work: that is the family a modern client will try first, so a
    // TLS problem there is the one users will feel.
    let (endpoint, ctx, family) = if passed("tcp.v6") {
        (state.v6_endpoint, &state.probe_ctx_v6, proto::IpFamily::V6)
    } else if passed("tcp.v4") {
        (state.v4_endpoint, &state.probe_ctx_v4, proto::IpFamily::V4)
    } else {
        return builder.skip("no TCP connection succeeded, so there is nothing to handshake over");
    };

    builder
        .family(family)
        .ev("family", family_label(family).to_string())
        .with_probe(tls::probe(endpoint, &state.hostname, ctx).await)
}

async fn check_private_dns(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::PrivateDns, "Private DNS");

    let Some(network) = &state.network else {
        return builder.skip("Private DNS configuration comes from the framework");
    };
    let Some(lp) = &network.link_properties else {
        return builder.skip("no LinkProperties to read Private DNS from");
    };

    let mode = proto::PrivateDnsMode::try_from(lp.private_dns_mode)
        .unwrap_or(proto::PrivateDnsMode::Unspecified);

    let builder = builder
        .ev("mode", format!("{mode:?}"))
        .ev("hostname", lp.private_dns_server_name.clone())
        .ev("active", lp.private_dns_active.to_string())
        .ev(
            "validated_servers",
            lp.validated_private_dns_servers
                .iter()
                .map(|s| s.display())
                .collect::<Vec<_>>()
                .join(", "),
        );

    if mode == proto::PrivateDnsMode::Off || mode == proto::PrivateDnsMode::Unspecified {
        return builder.skip("Private DNS is off");
    }

    // In strict mode a failure to reach port 853 means no DNS at all, because
    // Android will not fall back to cleartext. That is a hard failure, and it
    // is worth proving rather than trusting the framework's own flag.
    let mut reachable = Vec::new();
    let mut unreachable = Vec::new();
    let servers: Vec<IpAddr> = if lp.validated_private_dns_servers.is_empty() {
        state.dns_servers.clone()
    } else {
        lp.validated_private_dns_servers
            .iter()
            .filter_map(|s| s.to_ip())
            .collect()
    };

    for server in &servers {
        let ctx = if server.is_ipv6() {
            &state.probe_ctx_v6
        } else {
            &state.probe_ctx_v4
        };
        let result = tcp::connect(SocketAddr::new(*server, 853), ctx).await;
        if result.ok {
            reachable.push(server.to_string());
        } else {
            unreachable.push(format!("{server} ({})", result.detail));
        }
    }

    let builder = builder
        .ev("dot_reachable", reachable.join(", "))
        .ev("dot_unreachable", unreachable.join("; "));

    if reachable.is_empty() && !servers.is_empty() {
        let strict = mode == proto::PrivateDnsMode::Strict;
        let detail = if strict {
            "Private DNS is in strict mode but no server answers on port 853; Android will \
             not fall back to plaintext DNS, so name resolution is completely down"
                .to_string()
        } else {
            "no Private DNS server answers on port 853; Android will fall back to plaintext \
             DNS, with a delay on every first lookup"
                .to_string()
        };
        return if strict {
            builder.fail(detail)
        } else {
            builder.warn(detail)
        };
    }

    if !lp.private_dns_active && mode != proto::PrivateDnsMode::Off {
        return builder
            .warn("Private DNS is configured but the framework does not report it as active");
    }

    builder.pass(format!(
        "Private DNS ({mode:?}) is working; {} server(s) answer on port 853",
        reachable.len()
    ))
}

async fn check_nat64(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::Nat64Dns64, "NAT64 / DNS64");

    let framework_prefix = state
        .network
        .as_ref()
        .and_then(|n| n.link_properties.as_ref())
        .and_then(|lp| lp.nat64_prefix.as_ref())
        .map(|p| p.display())
        .unwrap_or_default();

    let builder = builder
        .ev("clat_active", state.clat.active.to_string())
        .ev("clat_interface", state.clat.clat_interface.clone())
        .ev("framework_nat64_prefix", framework_prefix.clone());

    if state.dns_servers.is_empty() {
        return builder.skip("no DNS servers to run the RFC 7050 discovery query against");
    }

    // RFC 7050: ipv4only.arpa has no AAAA records, so any AAAA answer was
    // synthesised by a DNS64 server and carries the NAT64 prefix.
    let server = state.dns_servers[0];
    let ctx = if server.is_ipv6() {
        &state.probe_ctx_v6
    } else {
        &state.probe_ctx_v4
    };
    let answer = dns::query(
        SocketAddr::new(server, 53),
        dns::DNS64_PROBE_NAME,
        dns::TYPE_AAAA,
        ctx,
    )
    .await;

    let builder = builder.ev("probe_server", server.to_string());

    let synthesised = match &answer {
        Ok(a) => a
            .addresses
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => dns::extract_nat64_prefix(*v6),
                _ => None,
            })
            .next(),
        Err(_) => None,
    };

    let builder = match &answer {
        Ok(a) => builder.ev("rcode", a.rcode.name()).ev(
            "ipv4only_arpa_aaaa",
            a.addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        Err(e) => builder.ev("probe_error", e.to_string()),
    };

    match (synthesised, state.clat.active) {
        (Some((prefix, len)), true) => builder.pass(format!(
            "DNS64 is synthesising with prefix {prefix}/{len} and clatd is running on {}",
            state.clat.clat_interface
        )),
        (Some((prefix, len)), false) => builder.warn(format!(
            "DNS64 is synthesising with prefix {prefix}/{len} but no clat interface exists; \
             apps using raw IPv4 sockets or IPv4 literals have no path out"
        )),
        (None, true) => builder.warn(format!(
            "clatd is running on {} but the resolver does not synthesise AAAA records for \
             ipv4only.arpa; the NAT64 prefix may have been learned another way, or DNS64 \
             has stopped",
            state.clat.clat_interface
        )),
        (None, false) => builder.skip("this network is not using NAT64/DNS64"),
    }
}

async fn check_mtu(state: &DiagState) -> proto::Check {
    let builder = CheckBuilder::new(proto::CheckId::MtuPmtu, "MTU / path MTU");

    let Some(iface) = state.egress_v4.as_ref().or(state.egress_v6.as_ref()) else {
        return builder.skip("no egress interface to measure");
    };

    // Prefer IPv4 for the probe: IPv6 forbids fragmentation entirely, so a DF
    // probe there measures the same thing with fewer usable sizes.
    let (target, ctx, family) = if state.lookup_v4.route.is_some() {
        (
            state.v4_endpoint.ip(),
            &state.probe_ctx_v4,
            proto::IpFamily::V4,
        )
    } else if state.lookup_v6.route.is_some() {
        (
            state.v6_endpoint.ip(),
            &state.probe_ctx_v6,
            proto::IpFamily::V6,
        )
    } else {
        return builder.skip("no route to measure a path MTU along");
    };

    let route_mtu = match family {
        proto::IpFamily::V6 => &state.lookup_v6,
        _ => &state.lookup_v4,
    }
    .route
    .as_ref()
    .and_then(|r| r.metrics.as_ref())
    .map(|m| m.mtu)
    .unwrap_or(0);

    let builder = builder
        .family(family)
        .ev("interface", iface.name.clone())
        .ev("interface_mtu", iface.mtu.to_string())
        .ev("route_mtu", route_mtu.to_string());

    let result = mtu::discover(target, iface.mtu, ctx).await;
    let mut check = builder.with_probe(result);

    // A route MTU below the interface MTU means the kernel has already learned
    // about a smaller path, which is PMTU discovery working correctly. Report
    // it as information rather than a failure.
    if route_mtu > 0 && route_mtu < iface.mtu {
        check.status = proto::CheckStatus::Info as i32;
        check.detail = format!(
            "the kernel has cached a path MTU of {route_mtu} for this route, below the \
             interface MTU of {}; PMTU discovery is working",
            iface.mtu
        );
    }

    check
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, up: bool) -> proto::Interface {
        proto::Interface {
            index: 1,
            name: name.to_string(),
            mtu: 1500,
            flags: Some(proto::LinkFlags {
                up,
                running: up,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn empty_state() -> DiagState {
        DiagState {
            interfaces: Vec::new(),
            rules: Vec::new(),
            routes: Vec::new(),
            neighbors: Vec::new(),
            sockets: Vec::new(),
            socket_summary: Default::default(),
            clat: Default::default(),
            network: None,
            net_id: 0,
            probe_ctx_v4: ProbeContext::with_timeout(100),
            probe_ctx_v6: ProbeContext::with_timeout(100),
            lookup_v4: Default::default(),
            lookup_v6: Default::default(),
            egress_v4: None,
            egress_v6: None,
            dns_servers: Vec::new(),
            dns_from_framework: false,
            hostname: DEFAULT_HOSTNAME.to_string(),
            v4_endpoint: SocketAddr::new(IpAddr::V4(DEFAULT_V4_ENDPOINT), 443),
            v6_endpoint: SocketAddr::new(IpAddr::V6(DEFAULT_V6_ENDPOINT), 443),
            timeout_ms: 100,
        }
    }

    #[test]
    fn check_keys_are_unique() {
        let ids = [
            proto::CheckId::AndroidNetworkState,
            proto::CheckId::ActiveInterface,
            proto::CheckId::Ipv4Address,
            proto::CheckId::Ipv6Address,
            proto::CheckId::Ipv4DefaultRoute,
            proto::CheckId::Ipv6DefaultRoute,
            proto::CheckId::GatewayReachabilityV4,
            proto::CheckId::GatewayReachabilityV6,
            proto::CheckId::DnsA,
            proto::CheckId::DnsAaaa,
            proto::CheckId::TcpV4,
            proto::CheckId::TcpV6,
            proto::CheckId::TlsHandshake,
            proto::CheckId::PrivateDns,
            proto::CheckId::Nat64Dns64,
            proto::CheckId::VpnRouting,
            proto::CheckId::FirewallAnomaly,
            proto::CheckId::MtuPmtu,
            proto::CheckId::SuspiciousTcpStates,
            proto::CheckId::FrameworkKernelAgreement,
            proto::CheckId::RoutingRuleCoverage,
            proto::CheckId::DnsLatency,
            proto::CheckId::CaptivePortal,
            proto::CheckId::RouteLookupV4,
            proto::CheckId::RouteLookupV6,
        ];
        let mut keys: Vec<&str> = ids.iter().map(|id| check_key(*id)).collect();
        let total = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), total, "check keys must be unique");
    }

    #[test]
    fn no_egress_interface_is_a_failure_not_a_skip() {
        let check = check_active_interface(&empty_state());
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
    }

    #[test]
    fn a_down_egress_interface_fails() {
        let mut state = empty_state();
        state.egress_v4 = Some(iface("wlan0", false));
        let check = check_active_interface(&state);
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
        assert!(check.detail.contains("not UP"), "{}", check.detail);
    }

    #[test]
    fn a_healthy_egress_interface_passes() {
        let mut state = empty_state();
        state.egress_v4 = Some(iface("wlan0", true));
        let check = check_active_interface(&state);
        assert_eq!(check.status, proto::CheckStatus::Pass as i32);
        assert_eq!(check.evidence.get("interface").unwrap(), "wlan0");
    }

    #[test]
    fn missing_global_address_fails_the_address_check() {
        let mut state = empty_state();
        state.egress_v6 = Some(iface("wlan0", true));
        let check = check_address(&state, proto::IpFamily::V6);
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
    }

    #[test]
    fn disabled_ipv6_is_named_as_the_cause() {
        let mut ifc = iface("wlan0", true);
        ifc.sysctls = Some(proto::InterfaceSysctls {
            ipv6_disabled: true,
            ..Default::default()
        });
        let mut state = empty_state();
        state.egress_v6 = Some(ifc);
        let check = check_address(&state, proto::IpFamily::V6);
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
        assert!(check.detail.contains("disable_ipv6"), "{}", check.detail);
    }

    #[test]
    fn syn_sent_pileup_is_a_failure() {
        let mut state = empty_state();
        state.socket_summary = proto::SocketSummary {
            total: 30,
            syn_sent: 12,
            established: 2,
            ..Default::default()
        };
        let check = check_socket_states(&state);
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
        assert!(check.detail.contains("SYN_SENT"));
    }

    #[test]
    fn healthy_socket_mix_passes() {
        let mut state = empty_state();
        state.socket_summary = proto::SocketSummary {
            total: 20,
            established: 18,
            syn_sent: 1,
            ..Default::default()
        };
        assert_eq!(
            check_socket_states(&state).status,
            proto::CheckStatus::Pass as i32
        );
    }

    #[test]
    fn no_rules_at_all_is_a_failure() {
        let check = check_rule_coverage(&empty_state());
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
    }

    #[test]
    fn vpn_check_skips_when_no_vpn_exists() {
        assert_eq!(
            check_vpn(&empty_state()).status,
            proto::CheckStatus::Skip as i32
        );
    }

    #[test]
    fn framework_vpn_without_a_tun_is_a_disagreement() {
        let mut state = empty_state();
        state.network = Some(proto::AndroidNetwork {
            net_id: 102,
            transports: vec![proto::Transport::Vpn as i32],
            ..Default::default()
        });
        let check = check_vpn(&state);
        assert_eq!(check.status, proto::CheckStatus::Fail as i32);
    }

    #[test]
    fn target_net_id_overrides_the_active_network() {
        let target = proto::DiagnoseTarget {
            net_id: 205,
            ..Default::default()
        };
        let android = proto::AndroidNetworkState {
            has_active_network: true,
            active_net_id: 101,
            ..Default::default()
        };
        assert_eq!(resolve_net_id(&target, Some(&android)), 205);
        assert_eq!(
            resolve_net_id(&proto::DiagnoseTarget::default(), Some(&android)),
            101
        );
    }

    #[test]
    fn framework_dns_servers_are_preferred_over_fallbacks() {
        let network = proto::AndroidNetwork {
            link_properties: Some(proto::LinkPropertiesInfo {
                dns_servers: vec![proto::IpAddress::from_ip("192.168.1.1".parse().unwrap())],
                ..Default::default()
            }),
            ..Default::default()
        };
        let (servers, from_framework) = resolve_dns_servers(Some(&network));
        assert!(from_framework);
        assert_eq!(servers, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);

        let (fallback, from_framework) = resolve_dns_servers(None);
        assert!(!from_framework);
        assert_eq!(fallback.len(), 2);
    }
}
