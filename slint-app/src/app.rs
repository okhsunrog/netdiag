//! Wiring the UI to the daemon.
//!
//! Slint's event loop is single-threaded and its properties may only be touched
//! from it. All daemon work therefore happens on a Tokio runtime, and results
//! come back through `invoke_from_event_loop`, which is the one supported way
//! to cross that boundary.
//!
//! That requirement is why the shared state is `Arc` + `Mutex` rather than the
//! `Rc` + `RefCell` a single-threaded UI would otherwise want:
//! `invoke_from_event_loop` takes a `Send` closure, so anything a background
//! task hands back to the UI has to be `Send` too. A lock is never held across
//! an `.await`; the value is cloned out first.

use std::sync::{Arc, Mutex};

use netdiag_ipc::client::{DEFAULT_SOCKET_NAME, DaemonClient};
use netdiag_ipc::proto;
use slint::{ComponentHandle, Model};
use tokio::runtime::Runtime;

use crate::format::{bytes, model, shared};
use crate::platform::{InstalledApp, Platform};
use crate::ui;
use crate::view;

/// Events kept in the timeline. Older ones are dropped rather than growing
/// without bound on a device that is flapping.
const TIMELINE_CAPACITY: usize = 1000;

/// Packets kept for the UI list. The capture itself is bounded by the daemon;
/// this is only how many rows are worth rendering.
const CAPTURE_UI_LIMIT: usize = 500;

/// What a capture keeps so it can be written out afterwards.
///
/// The packets live here rather than in the view model because the view model
/// holds rendered strings: saving needs the bytes.
#[derive(Default)]
struct Capture {
    /// The 24-byte libpcap file header, as sent by the daemon. Empty until the
    /// capture has actually started.
    ///
    /// It comes from the daemon because only that side knows the interface's
    /// real link type; a header guessed here is wrong on cellular interfaces
    /// and every analyser then misreads the file.
    pcap_header: Vec<u8>,
    interface: String,
    packets: Vec<proto::CapturedPacket>,
    bytes: u64,
    /// Stream id, so Stop can cancel the daemon side rather than just dropping
    /// the receiver and leaving it capturing.
    stream_id: Option<u64>,
}

pub struct AppState {
    pub runtime: Runtime,
    pub platform: Arc<dyn Platform>,
    client: Mutex<Option<Arc<DaemonClient>>>,
    apps: Mutex<Vec<InstalledApp>>,
    filtered: Mutex<Vec<InstalledApp>>,
    /// The last snapshot, kept so the sockets filters re-render without another
    /// round trip to the daemon.
    snapshot: Mutex<Option<proto::Snapshot>>,
    capture: Mutex<Capture>,
}

impl AppState {
    pub fn new(platform: Arc<dyn Platform>) -> anyhow::Result<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        Ok(Arc::new(Self {
            runtime,
            platform,
            client: Mutex::new(None),
            apps: Mutex::new(Vec::new()),
            filtered: Mutex::new(Vec::new()),
            snapshot: Mutex::new(None),
            capture: Mutex::new(Capture::default()),
        }))
    }

    /// Package names sharing a uid, for the sockets screen.
    ///
    /// Several packages can share one uid (`android:sharedUserId`), and the
    /// kernel only ever reports the uid, so this can legitimately return more
    /// than one name.
    fn owner_for_uid(&self, uid: u32) -> String {
        let Ok(apps) = self.apps.lock() else {
            return String::new();
        };
        let names: Vec<&str> = apps
            .iter()
            .filter(|app| app.uid == uid)
            .map(|app| app.label.as_str())
            .take(3)
            .collect();
        names.join(", ")
    }

    fn client(&self) -> Option<Arc<DaemonClient>> {
        self.client.lock().ok()?.clone()
    }

    fn set_client(&self, client: Option<Arc<DaemonClient>>) {
        if let Ok(mut slot) = self.client.lock() {
            *slot = client;
        }
    }
}

/// Apply a value produced off-thread on the UI thread.
fn on_ui<T: Send + 'static>(
    weak: slint::Weak<ui::App>,
    value: T,
    apply: impl FnOnce(&ui::App, T) + Send + 'static,
) {
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(app) = weak.upgrade() {
            apply(&app, value);
        }
    });
}

pub fn wire(app: &ui::App, state: Arc<AppState>) {
    app.set_overview(view::empty_overview());
    app.set_diagnosis(view::empty_diagnosis(false));
    app.set_app_detail(view::empty_app_detail());
    app.set_sockets(view::empty_sockets());
    app.set_capture(view::empty_capture());
    app.set_status_line(shared(state.platform.describe()));

    wire_connect(app, &state);
    wire_refresh(app, &state);
    wire_diagnose(app, &state);
    wire_apps(app, &state);
    wire_sockets(app, &state);
    wire_capture(app, &state);
    wire_toggles(app);
    wire_timeline(app);
}

fn wire_connect(app: &ui::App, state: &Arc<AppState>) {
    let weak = app.as_weak();
    let connect_state = state.clone();
    app.on_connect(move || {
        let Some(app) = weak.upgrade() else { return };
        app.set_connecting(true);
        app.set_connect_error(shared(""));

        let state = connect_state.clone();
        let weak = app.as_weak();
        let start = state.platform.start_daemon();

        state.runtime.clone_handle().spawn(async move {
            let result = async {
                start.await?;
                DaemonClient::connect(DEFAULT_SOCKET_NAME, env!("CARGO_PKG_VERSION")).await
            }
            .await;

            match result {
                Ok(client) => {
                    let hello = client.hello().clone();
                    state.set_client(Some(client));
                    let apps = state.platform.installed_apps();
                    let state_for_ui = state.clone();

                    on_ui(weak.clone(), (hello, apps), move |app, (hello, apps)| {
                        app.set_status_line(shared(format!(
                            "daemon {} on kernel {}",
                            hello.daemon_version, hello.kernel_release
                        )));
                        app.set_connected(true);
                        set_apps(&app, &state_for_ui, apps);
                        // The overview is the first screen, so load it now
                        // rather than making the user pull.
                        app.invoke_refresh();
                    });

                    start_timeline(weak, state);
                }
                Err(e) => {
                    on_ui(weak, format!("{e:#}"), |app, message| {
                        app.set_connecting(false);
                        app.set_connect_error(shared(message));
                    });
                    return;
                }
            }

            // Success path clears the spinner separately so the error path can
            // return early above.
        });

        // The spinner is cleared by whichever branch finishes; clearing it here
        // as well would race with them.
    });

    let weak = app.as_weak();
    let disconnect_state = state.clone();
    app.on_disconnect(move || {
        let Some(app) = weak.upgrade() else { return };
        if let Some(client) = disconnect_state.client() {
            disconnect_state.set_client(None);
            disconnect_state
                .runtime
                .clone_handle()
                .spawn(async move { client.shutdown().await });
        }
        app.set_connected(false);
        app.set_events(model(Vec::<ui::EventRow>::new()));
    });
}

fn wire_refresh(app: &ui::App, state: &Arc<AppState>) {
    let weak = app.as_weak();
    let state = state.clone();
    app.on_refresh(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(client) = state.client() else { return };
        let android_state = state.platform.framework_state();
        let weak = app.as_weak();
        let state = state.clone();

        state.clone().runtime.clone_handle().spawn(async move {
            let result = client
                .unary(proto::client_frame::Body::GetSnapshot(
                    proto::GetSnapshotRequest {
                        include_sockets: true,
                        include_socket_tcp_info: true,
                        include_neighbors: true,
                        include_firewall: true,
                        include_counters: false,
                        include_sysctls: true,
                        include_qdiscs: false,
                        android_state,
                    },
                ))
                .await;

            match result {
                Ok(frame) => {
                    let Some(proto::server_frame::Body::GetSnapshot(response)) = frame.body else {
                        return;
                    };
                    let Some(snapshot) = response.snapshot else {
                        return;
                    };
                    let state_for_ui = state.clone();
                    on_ui(weak, snapshot, move |app, snapshot| {
                        app.set_connecting(false);
                        app.set_overview(view::overview(&snapshot));
                        app.set_interfaces(model(view::interfaces(&snapshot)));
                        app.set_rules(model(view::rules(&snapshot, 40)));
                        app.set_route_tables(model(view::route_tables(&snapshot)));
                        app.set_capture_interfaces(model(capturable_interfaces(&snapshot)));
                        if app.get_capture_interface().is_empty()
                            && let Some(first) = default_capture_interface(&snapshot)
                        {
                            app.set_capture_interface(shared(first));
                        }

                        // The sockets screen reads from the stored snapshot, so
                        // it is stored before the rows are built from it.
                        if let Ok(mut slot) = state_for_ui.snapshot.lock() {
                            *slot = Some(snapshot);
                        }
                        render_sockets(&app, &state_for_ui);
                    });
                }
                Err(e) => on_ui(weak, format!("snapshot failed: {e:#}"), |app, message| {
                    app.set_connecting(false);
                    app.set_connect_error(shared(message));
                }),
            }
        });
    });
}

fn wire_diagnose(app: &ui::App, state: &Arc<AppState>) {
    let weak = app.as_weak();
    let state = state.clone();
    app.on_diagnose(move || {
        let Some(app) = weak.upgrade() else { return };
        let Some(client) = state.client() else { return };
        app.set_diagnosis(view::empty_diagnosis(true));

        let android_state = state.platform.framework_state();
        let weak = app.as_weak();

        state.runtime.clone_handle().spawn(async move {
            let stream = client
                .stream(proto::client_frame::Body::Diagnose(proto::DiagnoseRequest {
                    android_state,
                    ..Default::default()
                }))
                .await;

            let (_id, mut rx) = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    on_ui(weak, format!("{e:#}"), |app, message| {
                        app.set_diagnosis(view::empty_diagnosis(false));
                        app.set_connect_error(shared(message));
                    });
                    return;
                }
            };

            while let Some(frame) = rx.recv().await {
                let Some(proto::server_frame::Body::Diagnose(progress)) = frame.body else {
                    continue;
                };
                match progress.payload {
                    // Stream each check as it completes so the list fills in
                    // progressively rather than showing a spinner for seconds.
                    Some(proto::diagnose_progress::Payload::Check(check)) => {
                        // The conversion happens inside the closure on
                        // purpose: Slint's ModelRc is Rc-based and therefore
                        // not Send, so a view model cannot be built off-thread
                        // and shipped over. Only the protobuf crosses.
                        on_ui(weak.clone(), check, |app, check| {
                            push_check(app, view::check_row(&check));
                        });
                    }
                    Some(proto::diagnose_progress::Payload::Response(response)) => {
                        on_ui(weak.clone(), response, |app, response| {
                            app.set_diagnosis(view::diagnosis(&response));
                        });
                    }
                    None => {}
                }
            }
        });
    });
}

/// Replace-or-append: a check is streamed once and then restated in the final
/// response, and duplicating rows mid-run would be confusing.
fn push_check(app: &ui::App, row: ui::CheckRow) {
    let diagnosis = app.get_diagnosis();
    let mut rows: Vec<ui::CheckRow> = diagnosis.checks.iter().collect();
    match rows.iter().position(|existing| existing.key == row.key) {
        Some(index) => rows[index] = row,
        None => rows.push(row),
    }
    app.set_diagnosis(ui::DiagnosisData {
        checks: model(rows),
        ..diagnosis
    });
}

fn wire_apps(app: &ui::App, state: &Arc<AppState>) {
    let weak = app.as_weak();
    let filter_state = state.clone();
    app.on_filter_changed(move |query| {
        if let Some(app) = weak.upgrade() {
            apply_filter(&app, &filter_state, query.as_str());
        }
    });

    let weak = app.as_weak();
    let select_state = state.clone();
    app.on_select_app(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let Some(client) = select_state.client() else {
            return;
        };
        let Some(selected) = select_state
            .filtered
            .lock()
            .ok()
            .and_then(|list| list.get(index as usize).cloned())
        else {
            return;
        };

        let android_state = select_state.platform.framework_state();
        let weak = app.as_weak();

        select_state.runtime.clone_handle().spawn(async move {
            let result = client
                .unary(proto::client_frame::Body::GetAppNetworkState(
                    proto::GetAppNetworkStateRequest {
                        app: Some(proto::AppRef {
                            package_name: selected.package,
                            uid: selected.uid,
                            label: selected.label,
                            is_system: selected.is_system,
                        }),
                        android_state,
                        include_tcp_info: true,
                        skip_route_lookup: false,
                    },
                ))
                .await;

            match result {
                Ok(frame) => {
                    if let Some(proto::server_frame::Body::GetAppNetworkState(response)) =
                        frame.body
                        && let Some(state) = response.state
                    {
                        on_ui(weak, state, |app, state| {
                            app.set_app_detail(view::app_detail(&state));
                        });
                    }
                }
                Err(e) => on_ui(
                    weak,
                    format!("per-app lookup failed: {e:#}"),
                    |app, message| app.set_connect_error(shared(message)),
                ),
            }
        });
    });

    let weak = app.as_weak();
    app.on_clear_app(move || {
        if let Some(app) = weak.upgrade() {
            app.set_app_detail(view::empty_app_detail());
        }
    });
}

fn set_apps(app: &ui::App, state: &Arc<AppState>, apps: Vec<InstalledApp>) {
    if let Ok(mut slot) = state.apps.lock() {
        *slot = apps;
    }
    apply_filter(app, state, app.get_app_filter().as_str());
}

fn apply_filter(app: &ui::App, state: &Arc<AppState>, query: &str) {
    let Ok(all) = state.apps.lock() else { return };
    let filtered: Vec<InstalledApp> = if query.trim().is_empty() {
        all.clone()
    } else {
        let needle = query.to_lowercase();
        all.iter()
            .filter(|entry| {
                entry.label.to_lowercase().contains(&needle)
                    || entry.package.to_lowercase().contains(&needle)
                    || entry.uid.to_string() == needle
            })
            .cloned()
            .collect()
    };
    drop(all);

    app.set_apps(model(
        filtered
            .iter()
            .map(|entry| ui::AppRow {
                label: shared(entry.label.clone()),
                package: shared(entry.package.clone()),
                uid: entry.uid as i32,
            })
            .collect::<Vec<_>>(),
    ));

    if let Ok(mut slot) = state.filtered.lock() {
        *slot = filtered;
    }
}

fn wire_toggles(app: &ui::App) {
    let weak = app.as_weak();
    app.on_toggle_check(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let diagnosis = app.get_diagnosis();
        let mut rows: Vec<ui::CheckRow> = diagnosis.checks.iter().collect();
        if let Some(row) = rows.get_mut(index as usize) {
            row.expanded = !row.expanded;
        }
        app.set_diagnosis(ui::DiagnosisData {
            checks: model(rows),
            ..diagnosis
        });
    });

    let weak = app.as_weak();
    app.on_toggle_interface(move |index| {
        let Some(app) = weak.upgrade() else { return };
        let mut rows: Vec<ui::InterfaceRow> = app.get_interfaces().iter().collect();
        if let Some(row) = rows.get_mut(index as usize) {
            row.expanded = !row.expanded;
        }
        app.set_interfaces(model(rows));
    });
}

fn wire_timeline(app: &ui::App) {
    let weak = app.as_weak();
    app.on_clear_events(move || {
        if let Some(app) = weak.upgrade() {
            app.set_events(model(Vec::<ui::EventRow>::new()));
        }
    });
}

fn start_timeline(weak: slint::Weak<ui::App>, state: Arc<AppState>) {
    let Some(client) = state.client() else { return };

    // Framework events come from the platform, not the daemon, and land on the
    // same timeline so the lag between "the kernel changed" and "the framework
    // noticed" is visible.
    if let Some(mut framework) = state.platform.take_framework_events() {
        let weak = weak.clone();
        state.runtime.clone_handle().spawn(async move {
            while let Some(event) = framework.recv().await {
                on_ui(weak.clone(), event, |app, event| {
                    push_event(app, view::event_row(&event));
                });
            }
        });
    }

    state.runtime.clone_handle().spawn(async move {
        let Ok((_id, mut rx)) = client
            .stream(proto::client_frame::Body::WatchNetwork(
                proto::WatchNetworkRequest {
                    filter: None,
                    replay_initial_state: true,
                },
            ))
            .await
        else {
            return;
        };

        while let Some(frame) = rx.recv().await {
            let Some(proto::server_frame::Body::Event(event)) = frame.body else {
                continue;
            };
            on_ui(weak.clone(), event, |app, event| {
                push_event(app, view::event_row(&event));
            });
        }
    });
}

/// Newest first, bounded.
fn push_event(app: &ui::App, row: ui::EventRow) {
    let existing = app.get_events();
    let mut rows: Vec<ui::EventRow> = Vec::with_capacity(TIMELINE_CAPACITY.min(existing.row_count() + 1));
    rows.push(row);
    rows.extend(existing.iter().take(TIMELINE_CAPACITY - 1));
    app.set_events(model(rows));
}

/// `Runtime` is not `Clone`, but a `Handle` is, and spawning through the handle
/// is what lets a closure capture only what it needs.
trait CloneHandle {
    fn clone_handle(&self) -> tokio::runtime::Handle;
}

impl CloneHandle for Runtime {
    fn clone_handle(&self) -> tokio::runtime::Handle {
        self.handle().clone()
    }
}

// ---- Sockets ----------------------------------------------------------------

fn wire_sockets(app: &ui::App, state: &Arc<AppState>) {
    let weak = app.as_weak();
    let state = state.clone();
    app.on_sockets_filter_changed(move || {
        if let Some(app) = weak.upgrade() {
            // No round trip: the filters are applied to the snapshot already in
            // hand, so toggling a chip is instant even on a device with
            // thousands of sockets.
            render_sockets(&app, &state);
        }
    });
}

fn render_sockets(app: &ui::App, state: &Arc<AppState>) {
    let Ok(snapshot) = state.snapshot.lock() else {
        return;
    };
    let Some(snapshot) = snapshot.as_ref() else {
        return;
    };
    let filters = view::SocketFilters {
        only_established: app.get_only_established(),
        only_apps: app.get_only_apps(),
        hide_listen: app.get_hide_listen(),
        app_uid_floor: state.platform.app_uid_floor(),
    };
    let owner = |uid: u32| state.owner_for_uid(uid);
    app.set_sockets(view::sockets(snapshot, filters, &owner));
}

// ---- Capture ----------------------------------------------------------------

/// Interfaces worth offering for capture: up, and not loopback.
///
/// Capturing on `lo` is legal and occasionally useful, but it is never what
/// someone debugging connectivity wants first, and a list of thirty down
/// `rmnet` interfaces buries the two that matter.
fn capturable_interfaces(snapshot: &proto::Snapshot) -> Vec<slint::SharedString> {
    snapshot
        .interfaces
        .iter()
        .filter(|link| {
            link.flags.as_ref().is_some_and(|flags| flags.up)
                && proto::LinkKind::try_from(link.kind) != Ok(proto::LinkKind::Loopback)
        })
        .map(|link| shared(link.name.clone()))
        .collect()
}

/// The interface the user most likely means.
///
/// The framework's active network is asked first, because "whatever has a
/// default route" is the wrong answer on Android: the device carries a default
/// route per network in its own table, and on a real phone the first one found
/// was `dummy0` in table 1002 — a placeholder that carries no traffic at all.
fn default_capture_interface(snapshot: &proto::Snapshot) -> Option<String> {
    let android = snapshot.android_state.as_ref();
    let active = android.and_then(|state| {
        state
            .networks
            .iter()
            .find(|network| network.net_id == state.active_net_id)
            .and_then(|network| network.link_properties.as_ref())
            .map(|link| link.interface_name.clone())
            .filter(|name| !name.is_empty())
    });
    if active.is_some() {
        return active;
    }

    // Off Android, or before the framework has an opinion: the first default
    // route through something that can actually carry a packet.
    snapshot
        .routes
        .iter()
        .filter(|route| route.is_default)
        .find_map(|route| {
            route
                .next_hops
                .first()
                .map(|hop| hop.out_interface_name.clone())
                .filter(|name| {
                    !name.is_empty() && !name.starts_with("dummy") && name != "lo"
                })
        })
}

fn wire_capture(app: &ui::App, state: &Arc<AppState>) {
    let weak = app.as_weak();
    let start_state = state.clone();
    app.on_start_capture(move |interface| {
        let Some(app) = weak.upgrade() else { return };
        let Some(client) = start_state.client() else {
            return;
        };
        let interface = interface.to_string();

        if let Ok(mut capture) = start_state.capture.lock() {
            *capture = Capture {
                interface: interface.clone(),
                ..Default::default()
            };
        }
        app.set_capture(ui::CaptureData {
            running: true,
            interface: shared(interface.clone()),
            summary: shared(format!("opening {interface}…")),
            ..view::empty_capture()
        });

        let weak = app.as_weak();
        let state = start_state.clone();
        state.clone().runtime.clone_handle().spawn(async move {
            let stream = client
                .stream(proto::client_frame::Body::StartCapture(
                    proto::StartCaptureRequest {
                        interface_name: interface,
                        // The payload is what makes the saved file useful; the
                        // daemon's own limits keep it bounded.
                        include_payload: true,
                        snaplen: 262_144,
                        max_packets: 5_000,
                        duration_ms: 120_000,
                        ..Default::default()
                    },
                ))
                .await;

            let (id, mut rx) = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    on_ui(weak, format!("{e:#}"), |app, message| {
                        let data = app.get_capture();
                        app.set_capture(ui::CaptureData {
                            running: false,
                            error: shared(message),
                            ..data
                        });
                    });
                    return;
                }
            };
            if let Ok(mut capture) = state.capture.lock() {
                capture.stream_id = Some(id);
            }

            while let Some(frame) = rx.recv().await {
                match frame.body {
                    Some(proto::server_frame::Body::CaptureStarted(started)) => {
                        if let Ok(mut capture) = state.capture.lock() {
                            capture.pcap_header = started.pcap_file_header.clone();
                            capture.interface = started.interface_name.clone();
                        }
                        on_ui(weak.clone(), started, |app, started| {
                            let data = app.get_capture();
                            app.set_capture(ui::CaptureData {
                                interface: shared(started.interface_name.clone()),
                                summary: shared(format!(
                                    "capturing on {} · link type {:?}",
                                    started.interface_name,
                                    proto::LinkType::try_from(started.link_type)
                                        .unwrap_or(proto::LinkType::Unspecified)
                                )),
                                ..data
                            });
                        });
                    }
                    Some(proto::server_frame::Body::Packet(packet)) => {
                        let counters = if let Ok(mut capture) = state.capture.lock() {
                            capture.bytes += packet.original_length as u64;
                            capture.packets.push(packet.clone());
                            Some((capture.packets.len(), capture.bytes))
                        } else {
                            None
                        };
                        on_ui(weak.clone(), (packet, counters), |app, (packet, counters)| {
                            push_packet(app, &packet, counters);
                        });
                    }
                    Some(proto::server_frame::Body::CaptureFinished(finished)) => {
                        on_ui(weak.clone(), finished, |app, finished| {
                            let data = app.get_capture();
                            let stats = finished.stats.unwrap_or_default();
                            app.set_capture(ui::CaptureData {
                                running: false,
                                summary: shared(format!(
                                    "{} captured · {} dropped by the kernel · {}",
                                    stats.packets_captured,
                                    stats.packets_dropped_kernel,
                                    bytes(stats.bytes_captured)
                                )),
                                ..data
                            });
                        });
                    }
                    _ => {}
                }
            }

            // The stream can also end because the daemon hit a limit or the
            // connection dropped, so the button is restored either way.
            on_ui(weak, (), |app, ()| {
                let data = app.get_capture();
                app.set_capture(ui::CaptureData {
                    running: false,
                    ..data
                });
            });
        });
    });

    let weak = app.as_weak();
    let stop_state = state.clone();
    app.on_stop_capture(move || {
        let Some(app) = weak.upgrade() else { return };
        let id = stop_state
            .capture
            .lock()
            .ok()
            .and_then(|capture| capture.stream_id);
        if let (Some(client), Some(id)) = (stop_state.client(), id) {
            // Cancel on the daemon side. Dropping the receiver alone would
            // leave it capturing into a socket nobody reads.
            stop_state
                .runtime
                .clone_handle()
                .spawn(async move { client.cancel(id).await });
        }
        let data = app.get_capture();
        app.set_capture(ui::CaptureData {
            running: false,
            ..data
        });
    });

    let weak = app.as_weak();
    let save_state = state.clone();
    app.on_save_capture(move || {
        let Some(app) = weak.upgrade() else { return };
        let directory = save_state.platform.download_dir();

        let result = save_state
            .capture
            .lock()
            .map_err(|_| "capture state is poisoned".to_string())
            .and_then(|capture| write_pcap(&capture, &directory));

        let data = app.get_capture();
        match result {
            Ok(path) => app.set_capture(ui::CaptureData {
                saved_path: shared(path),
                error: shared(""),
                ..data
            }),
            Err(message) => app.set_capture(ui::CaptureData {
                error: shared(message),
                ..data
            }),
        }
    });
}

/// Newest last: a capture reads as a transcript, unlike the event timeline.
fn push_packet(app: &ui::App, packet: &proto::CapturedPacket, counters: Option<(usize, u64)>) {
    let existing = app.get_capture();
    let mut rows: Vec<ui::PacketRow> = existing.packets.iter().collect();
    rows.push(view::packet_row(packet));
    if rows.len() > CAPTURE_UI_LIMIT {
        rows.drain(..rows.len() - CAPTURE_UI_LIMIT);
    }
    let summary = match counters {
        Some((count, byte_count)) => shared(format!("{count} packets · {}", bytes(byte_count))),
        None => existing.summary.clone(),
    };
    app.set_capture(ui::CaptureData {
        packets: model(rows),
        summary,
        ..existing
    });
}

/// Write the capture as a classic libpcap file.
///
/// The 24-byte file header is the daemon's, verbatim. Each record is the
/// 16-byte classic header — seconds, microseconds, captured length, original
/// length, all little-endian — followed by the bytes.
fn write_pcap(capture: &Capture, directory: &std::path::Path) -> Result<String, String> {
    use std::io::Write;

    if capture.packets.is_empty() {
        return Err("nothing captured yet".to_string());
    }
    if capture.pcap_header.is_empty() {
        return Err("the daemon never sent a pcap header, so the link type is unknown".to_string());
    }

    std::fs::create_dir_all(directory).map_err(|e| format!("could not create {directory:?}: {e}"))?;
    let name = format!(
        "netdiag-{}-{}.pcap",
        if capture.interface.is_empty() {
            "any"
        } else {
            capture.interface.as_str()
        },
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let path = directory.join(name);

    let file = std::fs::File::create(&path).map_err(|e| format!("could not write {path:?}: {e}"))?;
    let mut out = std::io::BufWriter::new(file);
    out.write_all(&capture.pcap_header)
        .map_err(|e| e.to_string())?;

    for packet in &capture.packets {
        let seconds = packet.unix_ms.div_euclid(1000) as u32;
        let micros = (packet.unix_ms.rem_euclid(1000) as u32) * 1000 + packet.unix_us_fraction;
        let mut record = [0u8; 16];
        record[0..4].copy_from_slice(&seconds.to_le_bytes());
        record[4..8].copy_from_slice(&micros.to_le_bytes());
        record[8..12].copy_from_slice(&(packet.data.len() as u32).to_le_bytes());
        record[12..16].copy_from_slice(&packet.original_length.to_le_bytes());
        out.write_all(&record).map_err(|e| e.to_string())?;
        out.write_all(&packet.data).map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())?;

    Ok(path.display().to_string())
}
