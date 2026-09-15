//! Slint frontend for the Android Network Inspector.
//!
//! An experiment in building the same tool with the UI in Rust rather than
//! Kotlin. The daemon, the protocol and the diagnosis engine are unchanged and
//! shared verbatim through the `netdiag-ipc` crate; only the frontend differs.

pub mod app;
pub mod format;
pub mod platform;
pub mod view;

// Bindings generated from the Android SDK by `jbindgen`, checked in.
//
// Regenerated with, and deliberately against **minSdk**, not the compile SDK:
//
// ```sh
// jbindgen android --api-level 31 --output-file slint-app/src/generated/android_net.rs \
//     --pattern 'android.net.ConnectivityManager' --pattern 'android.net.Network' \
//     --pattern 'android.net.NetworkCapabilities' --pattern 'android.net.LinkProperties'
// ```
//
// Against API 34 the generated `NetworkCapabilities` also binds
// `getEnterpriseIds`, `NET_CAPABILITY_MMTEL` and nine other members added
// after 31. `bind_java_type!` resolves every method and field id eagerly on
// first use of the class, so on an Android 12 device that first use fails —
// over members this app never calls. Generating against the floor the app
// declares is the fix, and it is the opposite of the usual Android instinct.
//
// It has to be included at the crate root: the file declares
// `pub mod android { pub mod net { … } }` and its own `type_map` entries refer
// to `crate::android::net::*`.
#[cfg(target_os = "android")]
include!("generated/android_net.rs");

/// The types generated from `ui/app.slint`.
pub mod ui {
    slint::include_modules!();
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(android_app: slint::android::AndroidApp) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("netdiag"),
    );

    if let Err(e) = run_android(android_app) {
        log::error!("netdiag-slint failed to start: {e:#}");
    }
}

#[cfg(target_os = "android")]
fn run_android(android_app: slint::android::AndroidApp) -> anyhow::Result<()> {
    use slint::ComponentHandle;

    slint::android::init(android_app.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let platform = platform::AndroidPlatform::new(android_app)?;
    let state = app::AppState::new(platform)?;
    let window = ui::App::new().map_err(|e| anyhow::anyhow!("{e}"))?;
    app::wire(&window, state);
    window.run().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}
