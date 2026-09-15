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

use crate::format::{model, shared};
use crate::platform::{InstalledApp, Platform};
use crate::ui;
use crate::view;

/// Events kept in the timeline. Older ones are dropped rather than growing
/// without bound on a device that is flapping.
const TIMELINE_CAPACITY: usize = 1000;

pub struct AppState {
    pub runtime: Runtime,
    pub platform: Arc<dyn Platform>,
    client: Mutex<Option<Arc<DaemonClient>>>,
    apps: Mutex<Vec<InstalledApp>>,
    filtered: Mutex<Vec<InstalledApp>>,
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
        }))
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
    app.set_status_line(shared(state.platform.describe()));

    wire_connect(app, &state);
    wire_refresh(app, &state);
    wire_diagnose(app, &state);
    wire_apps(app, &state);
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

        state.runtime.clone_handle().spawn(async move {
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
                    on_ui(weak, snapshot, |app, snapshot| {
                        app.set_connecting(false);
                        app.set_overview(view::overview(&snapshot));
                        app.set_interfaces(model(view::interfaces(&snapshot)));
                        app.set_rules(model(view::rules(&snapshot, 40)));
                        app.set_route_tables(model(view::route_tables(&snapshot)));
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
