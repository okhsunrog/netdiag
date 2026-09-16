//! Framework events, pushed from Java into Rust.
//!
//! The Java half is `java/NetdiagFrameworkWatcher.java`: it subclasses
//! `ConnectivityManager.NetworkCallback`, which Rust cannot do, filters the
//! callback noise, and calls one `native` method per event worth showing.
//!
//! `cargo rapk` compiles that class into the APK's own `classes.dex`, so it is
//! an ordinary application class: defined by the app's class loader, like
//! anything Gradle would have produced.
//!
//! The direction of travel matters. Everything else in this app calls *into*
//! Java; this is Java calling *into* Rust, which is why it needs an exported
//! symbol rather than a method lookup.

use std::sync::OnceLock;

use jni::objects::{JClass, JString, LoaderContext};
use jni::sys::{jint, jlong};
use jni::{Env, JavaVM, bind_java_type, native_method};
use netdiag_ipc::proto;

use super::shim::{event_kind, event_severity};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// Only to name the constructor's parameter type. The class loader comes from
// `android::app_class_loader`; a `bind_java_type!` binding is private to the
// invocation that declares it, so the Java type is named in both places rather
// than the Rust type being shared.
bind_java_type! {
    WatcherContext => android.content.Context,
}

bind_java_type! {
    FrameworkWatcher => "dev.okhsunrog.netdiag.NetdiagFrameworkWatcher",
    type_map = {
        WatcherContext => "android.content.Context",
    },
    constructors {
        fn new(context: WatcherContext),
    },
    methods {
        fn start { name = "start", sig = (), },
        fn stop { name = "stop", sig = (), },
    },
}

/// Where events go once Java hands them over.
///
/// A static because the JVM calls the native method with no context of its own;
/// there is nowhere else to put the destination.
static EVENT_SINK: OnceLock<mpsc::UnboundedSender<proto::NetworkEvent>> = OnceLock::new();

/// The native method Java calls into.
///
/// It must be bound by pointer; symbol lookup cannot find it, and moving the
/// class into the APK did not change that. `native_method!` does export
/// `Java_dev_okhsunrog_netdiag_..._onFrameworkEvent__IIJLjava_lang_String_2`
/// from this `.so` — the VM even names that symbol in the error — but it
/// searches only libraries the VM knows are loaded, and it does not know about
/// this one. `NativeActivity` starts an app by `dlopen`ing its library from
/// `loadNativeCode`, not through `System.loadLibrary`, so nothing registers it
/// against a class loader.
///
/// That makes `RegisterNatives` structural for a `NativeActivity` app rather
/// than a consequence of how the class is packaged.
const ON_FRAMEWORK_EVENT: jni::NativeMethod = native_method! {
    java_type = "dev.okhsunrog.netdiag.NetdiagFrameworkWatcher",
    static extern fn on_framework_event(
        kind: jint,
        severity: jint,
        network_handle: jlong,
        summary: JString,
    ),
};

fn on_framework_event(
    env: &mut Env<'_>,
    _class: JClass<'_>,
    kind: jint,
    severity: jint,
    network_handle: jlong,
    summary: JString<'_>,
) -> Result<(), jni::errors::Error> {
    let summary = if summary.is_null() {
        String::new()
    } else {
        summary.try_to_string(env)?
    };

    let handle = network_handle as u64;
    let event = proto::NetworkEvent {
        unix_ms: now_unix_ms(),
        source: proto::EventSource::Framework as i32,
        severity: event_severity(severity) as i32,
        summary,
        payload: Some(proto::network_event::Payload::Framework(
            proto::FrameworkEvent {
                kind: event_kind(kind) as i32,
                // The netId is the high half of the handle, and it is the join
                // key with everything the daemon reports.
                current_net_id: (handle >> 32) as i32,
                network: Some(proto::AndroidNetwork {
                    network_handle: handle,
                    net_id: (handle >> 32) as i32,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )),
        ..Default::default()
    };

    match EVENT_SINK.get() {
        // Unbounded, so this never blocks the framework's callback thread.
        Some(sink) => {
            if sink.send(event).is_err() {
                debug!("framework event dropped: the UI is no longer listening");
            }
        }
        None => debug!("framework event arrived before the sink was installed"),
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A started watcher. Dropping it unregisters the callback.
pub struct FrameworkWatcherHandle {
    watcher: jni::refs::Global<FrameworkWatcher<'static>>,
}

impl Drop for FrameworkWatcherHandle {
    fn drop(&mut self) {
        let Ok(vm) = JavaVM::singleton() else { return };
        // Global<T> derefs to T, so the bound method is callable directly.
        let _ = vm.attach_current_thread(|env| self.watcher.stop(env));
    }
}

/// Load the Java class, register the event sink, and start watching.
pub fn install(
    app: &slint::android::AndroidApp,
) -> Result<
    (
        mpsc::UnboundedReceiver<proto::NetworkEvent>,
        FrameworkWatcherHandle,
    ),
    jni::errors::Error,
> {
    // Touch the const so the exported symbol is definitely kept.
    let _ = &ON_FRAMEWORK_EVENT;

    let (tx, rx) = mpsc::unbounded_channel();
    if EVENT_SINK.set(tx).is_err() {
        warn!("the framework event sink was already installed; reusing it");
    }

    let watcher = JavaVM::singleton()?.attach_current_thread(|env| {
        let app_loader = super::android::app_class_loader(env, app)?;
        let loader = LoaderContext::Loader(&app_loader);
        FrameworkWatcherAPI::get(env, &loader)?;

        // See ON_FRAMEWORK_EVENT: the VM cannot resolve the implementation by
        // symbol, because it does not know this `.so` is loaded at all.
        let class = loader.load_class(
            env,
            jni::jni_str!("dev.okhsunrog.netdiag.NetdiagFrameworkWatcher"),
            false,
        )?;
        // SAFETY: `native_method!` checks the signature against the Rust
        // function at compile time, and this is the class that declares it.
        unsafe { env.register_native_methods(&class, &[ON_FRAMEWORK_EVENT])? };

        let activity = super::android::activity_object(env, app);
        let context = WatcherContext::cast_local(env, activity)?;
        let watcher = FrameworkWatcher::new(env, &context)?;
        watcher.start(env)?;

        env.new_global_ref(&watcher)
    })?;

    debug!("framework watcher installed");
    Ok((rx, FrameworkWatcherHandle { watcher }))
}
