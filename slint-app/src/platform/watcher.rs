//! Framework events, pushed from Java into Rust.
//!
//! The Java half is `java/NetdiagFrameworkWatcher.java`: it subclasses
//! `ConnectivityManager.NetworkCallback`, which Rust cannot do, filters the
//! callback noise, and calls one `native` method per event worth showing.
//!
//! The dex containing that class is compiled by `build.rs` and embedded here
//! with `include_bytes!`, then loaded at runtime through
//! `InMemoryDexClassLoader`. Nothing is added to the APK: the class rides
//! inside the `.so`.
//!
//! The direction of travel matters. Everything else in this app calls *into*
//! Java; this is Java calling *into* Rust, which is why it needs an exported
//! symbol rather than a method lookup.

use std::sync::OnceLock;

use jni::objects::{JClass, JClassLoader, JString, LoaderContext};
use jni::sys::{jint, jlong};
use jni::{Env, JavaVM, bind_java_type, native_method};
use netdiag_ipc::proto;

use super::shim::{event_kind, event_severity};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// The dex produced by `build.rs` from the single Java source file.
const DEX_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/classes.dex"));

bind_java_type! {
    InMemoryDexClassLoader => "dalvik.system.InMemoryDexClassLoader",
    constructors {
        fn new(dex_buffer: JByteBuffer, parent: JClassLoader),
    },
    is_instance_of = {
        JClassLoader,
    },
}

bind_java_type! {
    ContextForLoader => "android.content.Context",
    methods {
        fn get_class_loader {
            name = "getClassLoader",
            sig = () -> JClassLoader,
        },
    },
}

bind_java_type! {
    FrameworkWatcher => "dev.okhsunrog.netdiag.NetdiagFrameworkWatcher",
    type_map = {
        ContextForLoader => "android.content.Context",
    },
    constructors {
        fn new(context: ContextForLoader),
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

/// The exported native method.
///
/// `extern` makes the macro emit the JNI-mangled symbol, so the VM resolves it
/// from the app's own `.so` without a `RegisterNatives` call. Referenced from
/// [`install`] so the linker cannot decide it is unused.
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
) -> Result<(mpsc::UnboundedReceiver<proto::NetworkEvent>, FrameworkWatcherHandle), jni::errors::Error>
{
    // Touch the const so the exported symbol is definitely kept.
    let _ = &ON_FRAMEWORK_EVENT;

    let (tx, rx) = mpsc::unbounded_channel();
    if EVENT_SINK.set(tx).is_err() {
        warn!("the framework event sink was already installed; reusing it");
    }

    let watcher = JavaVM::singleton()?.attach_current_thread(|env| {
        let activity = super::android::activity_object(env, app);

        // The dex has to be loaded through a loader that can still see the
        // platform classes, so the app's own loader is the parent.
        let activity_ref = env.new_local_ref(&activity)?;
        let context = ContextForLoader::cast_local(env, activity_ref)?;
        let parent = context.get_class_loader(env)?;

        // SAFETY: DEX_DATA is 'static and InMemoryDexClassLoader only reads it.
        let dex_buffer =
            unsafe { env.new_direct_byte_buffer(DEX_DATA.as_ptr() as *mut _, DEX_DATA.len())? };
        let dex_loader = InMemoryDexClassLoader::new(env, &dex_buffer, &parent)?;
        let dex_loader = JClassLoader::cast_local(env, dex_loader)?;

        // Prime the cached class using that loader. Without this the default
        // lookup searches only the platform and the app's own classes, and the
        // shim lives in neither.
        let loader = LoaderContext::Loader(&dex_loader);
        FrameworkWatcherAPI::get(env, &loader)?;

        let activity_ref = env.new_local_ref(&activity)?;
        let context = ContextForLoader::cast_local(env, activity_ref)?;
        let watcher = FrameworkWatcher::new(env, &context)?;
        watcher.start(env)?;

        env.new_global_ref(&watcher)
    })?;

    debug!("framework watcher installed ({} byte dex)", DEX_DATA.len());
    Ok((rx, FrameworkWatcherHandle { watcher }))
}


