//! What differs between running on a phone and running on a desktop.
//!
//! Three things, and they are exactly the three that the Compose build gets
//! from the Android SDK for free:
//!
//! * the framework's own view of networking (`ConnectivityManager`),
//! * the list of installed apps and their uids (`PackageManager`),
//! * starting the root daemon through `su`.
//!
//! On the desktop the first two are simply absent and the daemon is started by
//! hand, which is enough to develop the whole UI without a device attached.

use std::future::Future;
use std::pin::Pin;

use netdiag_ipc::proto;

#[derive(Debug, Clone)]
pub struct InstalledApp {
    pub package: String,
    pub label: String,
    pub uid: u32,
    pub is_system: bool,
}

pub type StartFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

pub trait Platform: Send + Sync + 'static {
    /// The framework's view, captured fresh. `None` where there is no Android
    /// framework: the daemon then skips the correlation checks rather than
    /// comparing against invented data.
    fn framework_state(&self) -> Option<proto::AndroidNetworkState>;

    fn installed_apps(&self) -> Vec<InstalledApp>;

    /// Ensure the daemon is running. On Android this goes through `su`.
    fn start_daemon(&self) -> StartFuture;

    /// One line for the connect screen, so it is obvious which mode this is.
    fn describe(&self) -> String;
}

// ---- Desktop ----------------------------------------------------------------

#[cfg(not(target_os = "android"))]
pub mod desktop {
    use super::*;

    pub struct DesktopPlatform;

    impl Platform for DesktopPlatform {
        fn framework_state(&self) -> Option<proto::AndroidNetworkState> {
            // Not inventing one: the daemon's framework/kernel agreement checks
            // correctly report SKIP when there is nothing to compare against,
            // and a fabricated state would make them lie.
            None
        }

        fn installed_apps(&self) -> Vec<InstalledApp> {
            // Without a PackageManager there is no package->uid mapping. The
            // per-app view still works when a uid is entered directly.
            Vec::new()
        }

        fn start_daemon(&self) -> StartFuture {
            // On the desktop the daemon is started by hand, usually under sudo,
            // so there is nothing to do here beyond letting the connect attempt
            // produce the error if it is not running.
            Box::pin(async { Ok(()) })
        }

        fn describe(&self) -> String {
            "desktop harness · start the daemon with: sudo netdiagd --socket @netdiag".to_string()
        }
    }
}

// ---- Android ----------------------------------------------------------------

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "android")]
pub use android::AndroidPlatform;
