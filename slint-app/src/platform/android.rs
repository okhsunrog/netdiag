//! The boundary to the Android framework.
//!
//! **This file no longer wraps the SDK.** It used to: `ConnectivityManager`,
//! `Network`, `NetworkCapabilities`, `LinkProperties`, `List` and `InetAddress`
//! were all transcribed into `bind_java_type!` declarations, eleven
//! `NET_CAPABILITY_*` values were copied in as integer literals, and reading
//! the framework's state cost roughly 150 JNI round trips per refresh. None of
//! that was checked by anything until it ran.
//!
//! Everything that touches the SDK now lives in `java/`, behind three
//! coarse-grained calls:
//!
//! * `NetdiagFramework.collectNetworkSnapshot()` — the whole framework view.
//! * `NetdiagPackages.list()` — every installed application.
//! * `NetdiagFrameworkWatcher` — `NetworkCallback`, which must be subclassed.
//!
//! What is left here is the boundary itself: `Context`, `ApplicationInfo` for
//! the packaged daemon's path, and the class loader those shims are found
//! through. Three bindings, no SDK constants, one JNI call per question.
//!
//! The trade is deliberate. `javac` checks `NET_CAPABILITY_VALIDATED` against
//! the real SDK; nothing checked the `16` that used to stand in for it. What
//! Rust gains in exchange for giving up direct access is that the part of the
//! Android API this app depends on is now compiled against that API.

use std::sync::Arc;

use jni::objects::{JClassLoader, JObject, LoaderContext};
use jni::{Env, JavaVM, bind_java_type};
use netdiag_ipc::proto;
use tracing::{debug, warn};

use super::{InstalledApp, Platform, StartFuture};

bind_java_type! {
    Context => android.content.Context,
    // Types bound by a different `bind_java_type!` invocation are invisible to
    // this one, so every non-core type used in a signature is named again here.
    type_map = {
        ApplicationInfo => "android.content.pm.ApplicationInfo",
    },
    methods {
        fn get_system_service {
            name = "getSystemService",
            sig = (name: JString) -> JObject,
        },
        fn get_package_name {
            name = "getPackageName",
            sig = () -> JString,
        },
        fn get_application_info {
            name = "getApplicationInfo",
            sig = () -> ApplicationInfo,
        },
    },
}

bind_java_type! {
    NetdiagPackages => "dev.okhsunrog.netdiag.NetdiagPackages",
    type_map = {
        Context => "android.content.Context",
    },
    constructors {
        fn new(context: Context),
    },
    methods {
        fn list {
            name = "list",
            sig = () -> JString,
        },
    },
}

bind_java_type! {
    NetdiagFramework => "dev.okhsunrog.netdiag.NetdiagFramework",
    type_map = {
        Context => "android.content.Context",
    },
    constructors {
        fn new(context: Context),
    },
    methods {
        fn collect_network_snapshot {
            name = "collectNetworkSnapshot",
            sig = () -> JString,
        },
    },
}

bind_java_type! {
    ApplicationInfo => android.content.pm.ApplicationInfo,
    fields {
        // Must match the Java field name exactly, so it cannot be snake_case.
        #[allow(non_snake_case)]
        nativeLibraryDir: JString,
    },
}

pub struct AndroidPlatform {
    app: slint::android::AndroidApp,
    daemon_path: String,
    package_name: String,
    uid: u32,
    /// Taken once by the timeline. The watcher keeps running for the process
    /// lifetime; there is no reason to stop and restart it per subscription.
    framework_events:
        std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<proto::NetworkEvent>>>,
    _watcher: Option<super::watcher::FrameworkWatcherHandle>,
}

impl AndroidPlatform {
    pub fn new(app: slint::android::AndroidApp) -> anyhow::Result<Arc<Self>> {
        // Slint has already created the JavaVM singleton by the time the app
        // runs; this only adopts it if that has somehow not happened.
        if JavaVM::singleton().is_err() {
            // SAFETY: android-activity documents vm_as_ptr() as returning the
            // process JavaVM, which is what JavaVM::from_raw expects.
            unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut _) };
        }

        // SAFETY: getuid never fails.
        let uid = unsafe { libc::getuid() };

        let (package_name, daemon_path) = JavaVM::singleton()?
            .attach_current_thread(|env| {
                let activity = activity_object(env, &app);
                let context = Context::cast_local(env, activity)?;

                let package_name: String = {
                    let value = context.get_package_name(env)?;
                    value.try_to_string(env)?
                };

                // The daemon rides in the APK as libnetdiagd.so for the same
                // reason as in the Compose build: only lib*.so files are
                // extracted to a directory that permits execution.
                let info = context.get_application_info(env)?;
                let native_dir: String = {
                    let value = info.nativeLibraryDir(env)?;
                    value.try_to_string(env)?
                };

                Ok::<_, jni::errors::Error>((package_name, format!("{native_dir}/libnetdiagd.so")))
            })
            .map_err(|e| anyhow::anyhow!("could not read the app context: {e}"))?;

        // Start watching immediately. A failure here costs the framework half
        // of the timeline but nothing else, so it is a warning rather than a
        // reason to refuse to start.
        let (events, watcher) = match super::watcher::install(&app) {
            Ok((events, watcher)) => (Some(events), Some(watcher)),
            Err(e) => {
                warn!("framework event watcher unavailable: {e}");
                (None, None)
            }
        };

        Ok(Arc::new(Self {
            app,
            daemon_path,
            package_name,
            uid,
            framework_events: std::sync::Mutex::new(events),
            _watcher: watcher,
        }))
    }

    /// The fallback when `PackageManager` cannot be read.
    fn only_this_app(&self) -> InstalledApp {
        InstalledApp {
            package: self.package_name.clone(),
            label: format!("{} (this app)", self.package_name),
            uid: self.uid,
            is_system: false,
        }
    }
}

/// The framework's whole view of networking, in one JNI call.
///
/// Everything this used to do method by method — `getAllNetworks`, then per
/// network `getNetworkCapabilities`, eight `hasTransport`, eleven
/// `hasCapability`, `getLinkProperties` and its getters, then walking a
/// `List<InetAddress>` — now happens inside `NetdiagFramework`, in Java, where
/// the SDK names are symbols the compiler checks.
fn collect_framework_state(app: &slint::android::AndroidApp) -> Result<String, jni::errors::Error> {
    JavaVM::singleton()?.attach_current_thread(|env| {
        let loader = app_class_loader(env, app)?;
        NetdiagFrameworkAPI::get(env, &LoaderContext::Loader(&loader))?;

        let activity = activity_object(env, app);
        let context = Context::cast_local(env, activity)?;
        let framework = NetdiagFramework::new(env, &context)?;

        let text = framework.collect_network_snapshot(env)?;
        text.try_to_string(env)
    })
}

/// Ask the Java shim for every installed application.
///
/// The whole list crosses in one string, which costs one JNI call instead of
/// the several hundred that walking `List<ApplicationInfo>` and calling
/// `getApplicationLabel` per entry from Rust would take.
fn collect_installed_apps(
    app: &slint::android::AndroidApp,
) -> Result<Vec<InstalledApp>, jni::errors::Error> {
    JavaVM::singleton()?.attach_current_thread(|env| {
        let loader = app_class_loader(env, app)?;
        NetdiagPackagesAPI::get(env, &LoaderContext::Loader(&loader))?;

        let activity = activity_object(env, app);
        let context = Context::cast_local(env, activity)?;
        let packages = NetdiagPackages::new(env, &context)?;

        let listing = packages.list(env)?;
        let listing = listing.try_to_string(env)?;
        Ok(super::shim::parse_packages(&listing))
    })
}

pub(super) fn activity_object<'a>(env: &Env<'a>, app: &slint::android::AndroidApp) -> JObject<'a> {
    // SAFETY: activity_as_ptr() returns the process's Activity jobject, which
    // stays alive for as long as the app does.
    unsafe { JObject::from_raw(env, app.activity_as_ptr() as *mut _) }
}

bind_java_type! {
    ContextWithLoader => android.content.Context,
    methods {
        fn get_class_loader {
            name = "getClassLoader",
            sig = () -> JClassLoader,
        },
    },
}

/// The class loader that defined this app's own classes.
///
/// Needed for every class in `java/`. These calls happen on threads attached
/// from native code, and there `FindClass` searches the *system* loader, which
/// holds only platform classes — so an app class is not found unless the lookup
/// is handed this loader explicitly.
pub(super) fn app_class_loader<'a>(
    env: &mut Env<'a>,
    app: &slint::android::AndroidApp,
) -> Result<JClassLoader<'a>, jni::errors::Error> {
    let activity = activity_object(env, app);
    let context = ContextWithLoader::cast_local(env, activity)?;
    context.get_class_loader(env)
}

impl Platform for AndroidPlatform {
    fn framework_state(&self) -> Option<proto::AndroidNetworkState> {
        match collect_framework_state(&self.app) {
            Ok(text) => {
                let state = super::shim::parse_framework_snapshot(&text);
                if state.is_none() {
                    warn!("the framework snapshot was in a format this build does not know");
                }
                state
            }
            Err(e) => {
                // The daemon's framework/kernel checks correctly report SKIP
                // when there is no framework state, so failing here degrades
                // the report rather than corrupting it.
                warn!("could not read ConnectivityManager: {e}");
                None
            }
        }
    }

    fn installed_apps(&self) -> Vec<InstalledApp> {
        match collect_installed_apps(&self.app) {
            Ok(apps) if !apps.is_empty() => apps,
            Ok(_) => {
                warn!("PackageManager returned no applications");
                vec![self.only_this_app()]
            }
            Err(e) => {
                // The per-app screen still works against this app's own uid,
                // which is enough to demonstrate the correlation.
                warn!("could not list installed applications: {e}");
                vec![self.only_this_app()]
            }
        }
    }

    fn app_uid_floor(&self) -> u32 {
        // AID_APP_START: the first uid Android hands to an installed app.
        10_000
    }

    fn download_dir(&self) -> std::path::PathBuf {
        // android-activity hands these over without JNI. External first: it is
        // the one `adb pull` and a file manager can reach without root.
        self.app
            .external_data_path()
            .or_else(|| self.app.internal_data_path())
            .unwrap_or_else(std::env::temp_dir)
    }

    fn start_daemon(&self) -> StartFuture {
        let path = self.daemon_path.clone();
        let package = self.package_name.clone();
        let uid = self.uid;

        Box::pin(async move {
            if netdiag_ipc::client::DaemonClient::probe(netdiag_ipc::client::DEFAULT_SOCKET_NAME)
                .await
            {
                return Ok(());
            }

            let command = format!(
                "nohup '{}' --socket @netdiag --allow-uid {uid} --expect-package '{}' \
                 >/dev/null 2>&1 &",
                path.replace('\'', "'\\''"),
                package.replace('\'', "'\\''"),
            );
            debug!("starting the daemon: {command}");

            // Absolute path rather than relying on PATH, and the error says
            // which step failed: a bare "os error 2" could be su, the shell or
            // the daemon, and they need different fixes.
            let su = ["/system/bin/su", "/su/bin/su", "su"]
                .into_iter()
                .find(|candidate| *candidate == "su" || std::path::Path::new(candidate).exists())
                .unwrap_or("su");

            let status = tokio::process::Command::new(su)
                .arg("-c")
                .arg(&command)
                .status()
                .await
                .map_err(|e| anyhow::anyhow!("could not run {su}: {e}"))?;
            if !status.success() {
                anyhow::bail!("{su} refused to start the daemon (exit {status})");
            }

            // Poll rather than sleeping a fixed amount: a fast device should
            // not be made to wait.
            for _ in 0..50 {
                if netdiag_ipc::client::DaemonClient::probe(
                    netdiag_ipc::client::DEFAULT_SOCKET_NAME,
                )
                .await
                {
                    return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            anyhow::bail!("the daemon did not bind @netdiag");
        })
    }

    fn describe(&self) -> String {
        format!("uid {} · {}", self.uid, self.daemon_path)
    }

    fn take_framework_events(
        &self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<proto::NetworkEvent>> {
        self.framework_events.lock().ok()?.take()
    }
}
