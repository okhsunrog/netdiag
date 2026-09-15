//! The Android framework, reached from Rust over JNI.
//!
//! This is the honest cost of writing the frontend in Rust. In Kotlin,
//! `connectivity.getLinkProperties(network).dnsServers` is one expression the
//! compiler checks against the SDK. Here the same call is a declared method
//! name and a JNI type signature that nothing verifies against the real
//! Android API: a wrong signature is a runtime `NoSuchMethodError`, not a build
//! error.
//!
//! `jni` 0.22's `bind_java_type!` makes it far better than raw `call_method` —
//! signatures are declared once, method IDs are cached, and call sites are
//! ordinary typed Rust — but it is still a transcription of an API rather than
//! a use of it, and the transcription is only as right as the person writing
//! it.
//!
//! Two things are deliberately *not* here:
//!
//! * **`NetworkCallback`.** Subclassing a Java abstract class needs a compiled
//!   Java shim in the APK. Slint's own Android backend already ships one, so
//!   the machinery exists, but adding a second means owning a `javac` step in a
//!   build whose appeal is that it is just `cargo`. The framework half of the
//!   timeline is therefore absent rather than half-built.
//! * **`PackageManager.getInstalledApplications`.** A `List<ApplicationInfo>`
//!   plus a label lookup per entry is a lot of JNI for a list; this app's own
//!   uid is enough to make the per-app screen demonstrable.

use std::sync::Arc;

use jni::objects::JObject;
use jni::sys::jint;
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
    ApplicationInfo => android.content.pm.ApplicationInfo,
    fields {
        // Must match the Java field name exactly, so it cannot be snake_case.
        #[allow(non_snake_case)]
        nativeLibraryDir: JString,
    },
}

bind_java_type! {
    ConnectivityManager => android.net.ConnectivityManager,
    type_map = {
        Network => "android.net.Network",
        NetworkCapabilities => "android.net.NetworkCapabilities",
        LinkProperties => "android.net.LinkProperties",
    },
    methods {
        fn get_active_network {
            name = "getActiveNetwork",
            sig = () -> Network,
        },
        fn get_all_networks {
            name = "getAllNetworks",
            sig = () -> [Network],
        },
        fn get_network_capabilities {
            name = "getNetworkCapabilities",
            sig = (network: Network) -> NetworkCapabilities,
        },
        fn get_link_properties {
            name = "getLinkProperties",
            sig = (network: Network) -> LinkProperties,
        },
        fn get_restrict_background_status {
            name = "getRestrictBackgroundStatus",
            sig = () -> jint,
        },
    },
}

bind_java_type! {
    Network => android.net.Network,
    methods {
        fn get_network_handle {
            name = "getNetworkHandle",
            sig = () -> jlong,
        },
    },
}

bind_java_type! {
    NetworkCapabilities => android.net.NetworkCapabilities,
    methods {
        fn has_capability {
            name = "hasCapability",
            sig = (capability: jint) -> jboolean,
        },
        fn has_transport {
            name = "hasTransport",
            sig = (transport: jint) -> jboolean,
        },
    },
}

bind_java_type! {
    LinkProperties => android.net.LinkProperties,
    type_map = {
        JavaList => "java.util.List",
    },
    methods {
        fn get_interface_name {
            name = "getInterfaceName",
            sig = () -> JString,
        },
        fn get_mtu {
            name = "getMtu",
            sig = () -> jint,
        },
        fn get_dns_servers {
            name = "getDnsServers",
            sig = () -> JavaList,
        },
        fn get_domains {
            name = "getDomains",
            sig = () -> JString,
        },
        fn is_private_dns_active {
            name = "isPrivateDnsActive",
            sig = () -> jboolean,
        },
        fn get_private_dns_server_name {
            name = "getPrivateDnsServerName",
            sig = () -> JString,
        },
    },
}

bind_java_type! {
    JavaList => java.util.List,
    methods {
        fn size {
            name = "size",
            sig = () -> jint,
        },
        fn get {
            name = "get",
            sig = (index: jint) -> JObject,
        },
    },
}

bind_java_type! {
    InetAddress => java.net.InetAddress,
    methods {
        fn get_address {
            name = "getAddress",
            sig = () -> [jbyte],
        },
    },
}

// NET_CAPABILITY_* and TRANSPORT_* values. They are part of the platform ABI
// and stable across releases; the Kotlin build gets them as named constants
// from the SDK instead.
const NET_CAPABILITY_NOT_METERED: jint = 11;
const NET_CAPABILITY_INTERNET: jint = 12;
const NET_CAPABILITY_NOT_RESTRICTED: jint = 13;
const NET_CAPABILITY_TRUSTED: jint = 14;
const NET_CAPABILITY_NOT_VPN: jint = 15;
const NET_CAPABILITY_VALIDATED: jint = 16;
const NET_CAPABILITY_CAPTIVE_PORTAL: jint = 17;
const NET_CAPABILITY_NOT_ROAMING: jint = 18;
const NET_CAPABILITY_FOREGROUND: jint = 19;
const NET_CAPABILITY_NOT_CONGESTED: jint = 20;
const NET_CAPABILITY_NOT_SUSPENDED: jint = 21;

const TRANSPORTS: &[(jint, proto::Transport)] = &[
    (0, proto::Transport::Cellular),
    (1, proto::Transport::Wifi),
    (2, proto::Transport::Bluetooth),
    (3, proto::Transport::Ethernet),
    (4, proto::Transport::Vpn),
    (7, proto::Transport::Usb),
];

/// `Network.getNetworkHandle()` packs the netId into the high 32 bits. The
/// netId is what appears in routing table numbers and socket fwmarks, so it is
/// the join key with everything the daemon reports.
const HANDLE_NET_ID_SHIFT: u32 = 32;

pub struct AndroidPlatform {
    app: slint::android::AndroidApp,
    daemon_path: String,
    package_name: String,
    uid: u32,
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

                Ok::<_, jni::errors::Error>((
                    package_name,
                    format!("{native_dir}/libnetdiagd.so"),
                ))
            })
            .map_err(|e| anyhow::anyhow!("could not read the app context: {e}"))?;

        Ok(Arc::new(Self {
            app,
            daemon_path,
            package_name,
            uid,
        }))
    }
}

fn activity_object<'a>(env: &Env<'a>, app: &slint::android::AndroidApp) -> JObject<'a> {
    // SAFETY: activity_as_ptr() returns the process's Activity jobject, which
    // stays alive for as long as the app does.
    unsafe { JObject::from_raw(env, app.activity_as_ptr() as *mut _) }
}

impl Platform for AndroidPlatform {
    fn framework_state(&self) -> Option<proto::AndroidNetworkState> {
        match collect_framework_state(&self.app) {
            Ok(state) => Some(state),
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
        vec![InstalledApp {
            package: self.package_name.clone(),
            label: format!("{} (this app)", self.package_name),
            uid: self.uid,
            is_system: false,
        }]
    }

    fn start_daemon(&self) -> StartFuture {
        let path = self.daemon_path.clone();
        let package = self.package_name.clone();
        let uid = self.uid;

        Box::pin(async move {
            if netdiag_ipc::client::DaemonClient::probe(
                netdiag_ipc::client::DEFAULT_SOCKET_NAME,
            )
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

            let status = tokio::process::Command::new("su")
                .arg("-c")
                .arg(&command)
                .status()
                .await?;
            if !status.success() {
                anyhow::bail!("su refused to start the daemon (exit {status})");
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
}

fn collect_framework_state(
    app: &slint::android::AndroidApp,
) -> Result<proto::AndroidNetworkState, jni::errors::Error> {
    JavaVM::singleton()?.attach_current_thread(|env| {
        let activity = activity_object(env, app);
        let context = Context::cast_local(env, activity)?;

        let service_name = env.new_string("connectivity")?;
        let manager_object = context.get_system_service(env, &service_name)?;
        let mut manager = ConnectivityManager::cast_local(env, manager_object)?;

        let active_handle = match manager.get_active_network(env) {
            Ok(network) if !network.is_null() => {
                let network = network;
                network.get_network_handle(env)? as u64
            }
            _ => 0,
        };

        let restrict_background_status = manager.get_restrict_background_status(env).unwrap_or(0);
        let mut state = proto::AndroidNetworkState {
            captured_at_unix_ms: now_unix_ms(),
            sdk_int: sdk_int(),
            active_network_handle: active_handle,
            active_net_id: (active_handle >> HANDLE_NET_ID_SHIFT) as i32,
            has_active_network: active_handle != 0,
            restrict_background_status,
            data_saver_enabled: restrict_background_status == 3,
            ..Default::default()
        };

        let networks = manager.get_all_networks(env)?;
        let count = networks.len(env)?;
        for index in 0..count {
            let element = networks.get_element(env, index as usize)?;
            if element.is_null() {
                continue;
            }
            match describe_network(env, &mut manager, element, active_handle) {
                Ok(network) => state.networks.push(network),
                Err(e) => debug!("skipping a network: {e}"),
            }
        }

        Ok(state)
    })
}

fn describe_network(
    env: &mut Env<'_>,
    manager: &mut ConnectivityManager<'_>,
    network_object: Network<'_>,
    active_handle: u64,
) -> Result<proto::AndroidNetwork, jni::errors::Error> {
    let network = network_object;
    let handle = network.get_network_handle(env)? as u64;

    let mut result = proto::AndroidNetwork {
        network_handle: handle,
        net_id: (handle >> HANDLE_NET_ID_SHIFT) as i32,
        is_default: handle == active_handle,
        ..Default::default()
    };

    if let Ok(caps) = manager.get_network_capabilities(env, &network)
        && !caps.is_null()
    {
        let caps = caps;
        for (value, transport) in TRANSPORTS {
            if caps.has_transport(env, *value).unwrap_or(false) {
                result.transports.push(*transport as i32);
            }
        }
        let has = |capability: jint| caps.has_capability(env, capability).unwrap_or(false);
        result.capabilities = Some(proto::NetworkCapabilitiesInfo {
            internet: has(NET_CAPABILITY_INTERNET),
            validated: has(NET_CAPABILITY_VALIDATED),
            captive_portal: has(NET_CAPABILITY_CAPTIVE_PORTAL),
            not_restricted: has(NET_CAPABILITY_NOT_RESTRICTED),
            not_metered: has(NET_CAPABILITY_NOT_METERED),
            not_roaming: has(NET_CAPABILITY_NOT_ROAMING),
            not_congested: has(NET_CAPABILITY_NOT_CONGESTED),
            not_suspended: has(NET_CAPABILITY_NOT_SUSPENDED),
            not_vpn: has(NET_CAPABILITY_NOT_VPN),
            trusted: has(NET_CAPABILITY_TRUSTED),
            foreground: has(NET_CAPABILITY_FOREGROUND),
            ..Default::default()
        });
    }

    if let Ok(link) = manager.get_link_properties(env, &network)
        && !link.is_null()
    {
        result.link_properties = Some(describe_link_properties(env, link)?);
    }

    Ok(result)
}

fn describe_link_properties(
    env: &mut Env<'_>,
    link: LinkProperties<'_>,
) -> Result<proto::LinkPropertiesInfo, jni::errors::Error> {
    let link = link;

    let interface_name = match link.get_interface_name(env) {
        Ok(value) if !value.is_null() => value.try_to_string(env)?,
        _ => String::new(),
    };
    let private_dns_server_name = match link.get_private_dns_server_name(env) {
        Ok(value) if !value.is_null() => value.try_to_string(env)?,
        _ => String::new(),
    };
    let private_dns_active = link.is_private_dns_active(env).unwrap_or(false);

    let mut info = proto::LinkPropertiesInfo {
        interface_name,
        mtu: link.get_mtu(env).unwrap_or(0),
        private_dns_active,
        private_dns_mode: if !private_dns_server_name.is_empty() {
            proto::PrivateDnsMode::Strict as i32
        } else if private_dns_active {
            proto::PrivateDnsMode::Opportunistic as i32
        } else {
            proto::PrivateDnsMode::Off as i32
        },
        private_dns_server_name,
        ..Default::default()
    };

    if let Ok(domains) = link.get_domains(env)
        && !domains.is_null()
    {
        let domains: String = domains.try_to_string(env)?;
        info.domains = domains
            .split(' ')
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect();
    }

    // DNS servers are a List<InetAddress>; each element's getAddress() gives
    // the raw bytes the schema stores.
    if let Ok(list) = link.get_dns_servers(env)
        && !list.is_null()
    {
        let list = list;
        let count = list.size(env).unwrap_or(0);
        for index in 0..count {
            let Ok(element) = list.get(env, index) else {
                continue;
            };
            if element.is_null() {
                continue;
            }
            let Ok(address) = InetAddress::cast_local(env, element) else {
                continue;
            };
            let Ok(bytes) = address.get_address(env) else {
                continue;
            };
            let Ok(raw) = env.convert_byte_array(&bytes) else {
                continue;
            };
            info.dns_servers.push(proto::IpAddress { addr: raw });
        }
    }

    Ok(info)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

unsafe extern "C" {
    /// Bionic's API-level query. Not exposed by the `libc` crate, but it is a
    /// plain symbol in libc.so and saves a JNI round trip for a constant.
    fn android_get_device_api_level() -> libc::c_int;
}

fn sdk_int() -> i32 {
    // SAFETY: the function takes no arguments and cannot fail.
    unsafe { android_get_device_api_level() }
}
