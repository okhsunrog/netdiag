//! The Java shim's vocabulary, and the one place that translates it.
//!
//! Deliberately **not** gated on `target_os = "android"`. The values are plain
//! integers, and keeping them host-compilable is what lets the drift test below
//! run under a normal `cargo test` instead of only on a device.
//!
//! These are not the wire enum values. The shim is compiled into the same APK
//! by the same `cargo rapk` invocation, so the two can never be different
//! versions; the only real risk is someone editing the Java constants without
//! editing this table, and that is exactly what the test catches.
//!
//! The package list is parsed here for the same reason: it is the other half of
//! a format defined in Java, and a host-runnable test is worth more than a
//! device-only one.

use netdiag_ipc::proto;

pub mod java_kind {
    pub const AVAILABLE: i32 = 1;
    pub const LOST: i32 = 2;
    pub const LOSING: i32 = 3;
    pub const IPV6_CHANGED: i32 = 4;
    pub const BLOCKED_CHANGED: i32 = 5;
    pub const VALIDATION_CHANGED: i32 = 6;
    pub const DNS_CHANGED: i32 = 7;
}

pub mod java_severity {
    pub const INFO: i32 = 1;
    pub const NOTICE: i32 = 2;
    pub const WARNING: i32 = 3;
}

/// Translate the shim's vocabulary into the wire enum.
pub fn event_kind(java: i32) -> proto::FrameworkEventKind {
    use proto::FrameworkEventKind as K;
    match java {
        java_kind::AVAILABLE => K::Available,
        java_kind::LOST => K::Lost,
        java_kind::LOSING => K::Losing,
        java_kind::IPV6_CHANGED => K::LinkPropertiesChanged,
        java_kind::BLOCKED_CHANGED => K::BlockedStatusChanged,
        java_kind::VALIDATION_CHANGED => K::ValidationChanged,
        java_kind::DNS_CHANGED => K::DnsServersChanged,
        _ => K::Unspecified,
    }
}

pub fn event_severity(java: i32) -> proto::EventSeverity {
    use proto::EventSeverity as S;
    match java {
        java_severity::INFO => S::Info,
        java_severity::NOTICE => S::Notice,
        java_severity::WARNING => S::Warning,
        _ => S::Info,
    }
}

/// Parse what `NetdiagPackages.list()` returns: one application per line, as
/// `uid \t system \t package \t label`.
///
/// Malformed lines are skipped rather than failing the whole list. A label is
/// arbitrary user-visible text, and losing one app from the screen is a much
/// better failure than losing the screen.
///
/// `PackageManager` returns an arbitrary order, so the result is sorted: user
/// apps first, then system ones, each by label. The Compose build hides system
/// packages by default and takes a parameter to include them; this screen has
/// no such toggle, and a tool for reading sockets by uid should not make system
/// uids unreachable. They are sorted below rather than removed, and the filter
/// box finds them.
pub fn parse_packages(listing: &str) -> Vec<super::InstalledApp> {
    let mut apps = parse_package_lines(listing);
    apps.sort_by(|a, b| {
        a.is_system
            .cmp(&b.is_system)
            .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
    });
    apps
}

fn parse_package_lines(listing: &str) -> Vec<super::InstalledApp> {
    listing
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            let uid = fields.next()?.parse().ok()?;
            let is_system = fields.next()? == "1";
            let package = fields.next()?;
            // A label is allowed to be empty; the package name is not a
            // pleasant fallback but it is always meaningful.
            let label = match fields.next() {
                Some(label) if !label.is_empty() => label,
                _ => package,
            };
            Some(super::InstalledApp {
                package: package.to_owned(),
                label: label.to_owned(),
                uid,
                is_system,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a constant straight out of the Java source.
    fn declared(name: &str) -> i32 {
        let java = include_str!("../../java/NetdiagFrameworkWatcher.java");
        let needle = format!("static final int {name} = ");
        let line = java
            .lines()
            .find(|line| line.contains(&needle))
            .unwrap_or_else(|| panic!("{name} is not declared in the Java shim"));
        line.rsplit("= ")
            .next()
            .and_then(|value| value.trim().trim_end_matches(';').parse().ok())
            .unwrap_or_else(|| panic!("could not parse the value of {name}"))
    }

    /// If someone renumbers the Java constants without updating this table,
    /// this is what fails — rather than events quietly arriving with the wrong
    /// label on a device, which is the one failure mode this design has.
    #[test]
    fn the_table_matches_the_java_shim() {
        assert_eq!(declared("KIND_AVAILABLE"), java_kind::AVAILABLE);
        assert_eq!(declared("KIND_LOST"), java_kind::LOST);
        assert_eq!(declared("KIND_LOSING"), java_kind::LOSING);
        assert_eq!(declared("KIND_IPV6_CHANGED"), java_kind::IPV6_CHANGED);
        assert_eq!(declared("KIND_BLOCKED_CHANGED"), java_kind::BLOCKED_CHANGED);
        assert_eq!(
            declared("KIND_VALIDATION_CHANGED"),
            java_kind::VALIDATION_CHANGED
        );
        assert_eq!(declared("KIND_DNS_CHANGED"), java_kind::DNS_CHANGED);

        assert_eq!(declared("SEVERITY_INFO"), java_severity::INFO);
        assert_eq!(declared("SEVERITY_NOTICE"), java_severity::NOTICE);
        assert_eq!(declared("SEVERITY_WARNING"), java_severity::WARNING);
    }

    #[test]
    fn every_java_kind_maps_to_a_real_wire_value() {
        for kind in [
            java_kind::AVAILABLE,
            java_kind::LOST,
            java_kind::LOSING,
            java_kind::IPV6_CHANGED,
            java_kind::BLOCKED_CHANGED,
            java_kind::VALIDATION_CHANGED,
            java_kind::DNS_CHANGED,
        ] {
            assert_ne!(
                event_kind(kind),
                proto::FrameworkEventKind::Unspecified,
                "java kind {kind} has no wire mapping"
            );
        }
    }

    #[test]
    fn an_unknown_value_degrades_instead_of_panicking() {
        // A shim from the future must not take the app down.
        assert_eq!(event_kind(9999), proto::FrameworkEventKind::Unspecified);
        assert_eq!(event_severity(9999), proto::EventSeverity::Info);
    }

    /// The separators here must be the ones the Java writes.
    #[test]
    fn package_separators_match_the_java() {
        let java = include_str!("../../java/NetdiagPackages.java");
        assert!(
            java.contains(r"char FIELD = '\t'"),
            "NetdiagPackages no longer separates fields with a tab"
        );
        assert!(
            java.contains(r"char RECORD = '\n'"),
            "NetdiagPackages no longer separates records with a newline"
        );
    }

    /// The names the Java emits must be the names this side matches on.
    #[test]
    fn capability_names_match_the_java() {
        let java = include_str!("../../java/NetdiagFramework.java");
        for name in [
            "INTERNET", "VALIDATED", "CAPTIVE_PORTAL", "NOT_RESTRICTED", "NOT_METERED",
            "NOT_ROAMING", "NOT_CONGESTED", "NOT_SUSPENDED", "NOT_VPN", "TRUSTED", "FOREGROUND",
        ] {
            assert!(
                java.contains(&format!("\"{name}\"")),
                "NetdiagFramework no longer emits {name}, so this side would read it as false"
            );
            // And the SDK constant behind it is still named in the Java, which
            // is what makes javac the thing checking it.
            assert!(
                java.contains(&format!("NET_CAPABILITY_{name}")),
                "{name} is emitted without reference to its SDK constant"
            );
        }
    }

    #[test]
    fn transport_names_match_the_java() {
        let java = include_str!("../../java/NetdiagFramework.java");
        for name in ["CELLULAR", "WIFI", "BLUETOOTH", "ETHERNET", "VPN", "USB"] {
            assert!(
                transport(name).is_some(),
                "{name} has no wire mapping on the Rust side"
            );
            assert!(
                java.contains(&format!("TRANSPORT_{name}")),
                "NetdiagFramework no longer reports {name}"
            );
        }
    }

    #[test]
    fn parses_a_framework_snapshot() {
        let text = "V\t1\t34\t476741369856\t1\n\
                    N\t476741369856\tWIFI,VPN\tINTERNET,VALIDATED,NOT_METERED\ttun0\t1280\t0\t\texample.com\t1.1.1.1,fd3f::1\n\
                    N\t455266533376\tCELLULAR\tINTERNET\trmnet16\t1500\t1\tdns.example\t\t8.8.8.8\n";
        let state = parse_framework_snapshot(text).expect("should parse");

        assert_eq!(state.sdk_int, 34);
        assert_eq!(state.active_net_id, 111);
        assert!(state.has_active_network);
        assert_eq!(state.networks.len(), 2);

        let vpn = &state.networks[0];
        assert!(vpn.is_default);
        assert_eq!(
            vpn.transports,
            vec![proto::Transport::Wifi as i32, proto::Transport::Vpn as i32]
        );
        let caps = vpn.capabilities.as_ref().unwrap();
        assert!(caps.validated && caps.internet && caps.not_metered);
        assert!(!caps.not_vpn, "NOT_VPN was absent, so it must read as false");

        let link = vpn.link_properties.as_ref().unwrap();
        assert_eq!(link.interface_name, "tun0");
        assert_eq!(link.mtu, 1280);
        assert_eq!(link.domains, vec!["example.com"]);
        // 1.1.1.1 as four bytes, fd3f::1 as sixteen.
        assert_eq!(link.dns_servers.len(), 2);
        assert_eq!(link.dns_servers[0].addr, vec![1, 1, 1, 1]);
        assert_eq!(link.dns_servers[1].addr.len(), 16);

        let cell = &state.networks[1];
        assert!(!cell.is_default);
        let cell_link = cell.link_properties.as_ref().unwrap();
        assert_eq!(cell_link.private_dns_server_name, "dns.example");
        assert_eq!(
            cell_link.private_dns_mode,
            proto::PrivateDnsMode::Strict as i32
        );
    }

    #[test]
    fn an_unknown_format_version_is_refused_rather_than_misread() {
        // Better no framework state — the daemon reports SKIP — than a state
        // parsed from a layout this build does not understand.
        assert!(parse_framework_snapshot("V\t2\t34\t0\t0\n").is_none());
    }

    #[test]
    fn a_link_local_dns_address_keeps_its_scope_out_of_the_bytes() {
        let text = "V\t1\t34\t0\t0\nN\t4294967296\t\t\twlan0\t1500\t0\t\t\tfe80::1%wlan0\n";
        let state = parse_framework_snapshot(text).expect("should parse");
        let dns = &state.networks[0].link_properties.as_ref().unwrap().dns_servers;
        assert_eq!(dns.len(), 1, "the scope must not make the address unparseable");
        assert_eq!(dns[0].addr.len(), 16);
    }

    #[test]
    fn parses_a_package_listing() {
        let apps = parse_packages("10400\t0\tcom.example.shop\tShop\n1000\t1\tandroid\tSystem\n");
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].uid, 10400);
        assert_eq!(apps[0].package, "com.example.shop");
        assert_eq!(apps[0].label, "Shop");
        assert!(!apps[0].is_system);
        assert!(apps[1].is_system);
    }

    #[test]
    fn user_apps_sort_first_then_by_label_ignoring_case() {
        let apps = parse_packages(
            "1\t1\tsys.a\tAaa system\n2\t0\tcom.z\tzebra\n3\t0\tcom.a\tApple\n4\t1\tsys.b\tBbb system\n",
        );
        let order: Vec<&str> = apps.iter().map(|a| a.label.as_str()).collect();
        // "Apple" before "zebra" needs the case-insensitive compare; a plain
        // sort puts every capital letter ahead of every lowercase one.
        assert_eq!(order, ["Apple", "zebra", "Aaa system", "Bbb system"]);
    }

    #[test]
    fn a_label_may_contain_spaces_and_be_empty() {
        let apps = parse_packages("101\t0\tcom.a\tSome Long Name\n102\t0\tcom.b\t\n");
        // Looked up by package, because the result is sorted by label.
        let find = |package: &str| {
            apps.iter()
                .find(|a| a.package == package)
                .unwrap_or_else(|| panic!("{package} is missing"))
        };
        assert_eq!(find("com.a").label, "Some Long Name");
        // An empty label falls back to something a person can still act on.
        assert_eq!(find("com.b").label, "com.b");
    }

    #[test]
    fn a_broken_line_drops_only_itself() {
        let apps = parse_packages("not-a-uid\t0\tcom.a\tA\n10\t0\tcom.b\tB\n\n");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].package, "com.b");
    }
}

// ---- The framework snapshot -------------------------------------------------

/// Parse what `NetdiagFramework.collectNetworkSnapshot()` returns.
///
/// The format is one `V` header line and one `N` line per network, tab
/// separated. Transports and capabilities arrive as the names the Java chose,
/// never as SDK integers — that is the point of the facade: `javac` checks
/// `NET_CAPABILITY_VALIDATED` against the real SDK, and this side only has to
/// agree with a word.
///
/// Anything unparseable is skipped rather than failing the whole snapshot. A
/// missing network degrades the report; a missing report makes the app useless
/// exactly when something is wrong.
pub fn parse_framework_snapshot(text: &str) -> Option<proto::AndroidNetworkState> {
    /// Refuse a format this code does not know rather than misreading it.
    const SUPPORTED_FORMAT: &str = "1";

    let mut state = proto::AndroidNetworkState {
        // The Java does not timestamp its own answer; this side is where the
        // snapshot becomes a thing with a time on it.
        captured_at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
        ..Default::default()
    };
    let mut seen_header = false;

    for line in text.lines() {
        let mut fields = line.split('\t');
        match fields.next() {
            Some("V") => {
                if fields.next() != Some(SUPPORTED_FORMAT) {
                    return None;
                }
                state.sdk_int = fields.next()?.parse().ok()?;
                let handle: u64 = fields.next()?.parse().ok()?;
                state.active_network_handle = handle;
                state.active_net_id = (handle >> 32) as i32;
                state.has_active_network = handle != 0;
                state.restrict_background_status = fields.next()?.parse().unwrap_or(0);
                // RESTRICT_BACKGROUND_STATUS_ENABLED
                state.data_saver_enabled = state.restrict_background_status == 3;
                seen_header = true;
            }
            Some("N") => {
                if let Some(network) = parse_network(fields, state.active_network_handle) {
                    state.networks.push(network);
                }
            }
            _ => {}
        }
    }

    seen_header.then_some(state)
}

fn parse_network<'a>(
    mut fields: impl Iterator<Item = &'a str>,
    active_handle: u64,
) -> Option<proto::AndroidNetwork> {
    let handle: u64 = fields.next()?.parse().ok()?;
    let transports = fields.next().unwrap_or_default();
    let capabilities = fields.next().unwrap_or_default();

    let interface_name = fields.next().unwrap_or_default().to_owned();
    let mtu: i32 = fields.next().unwrap_or("0").parse().unwrap_or(0);
    let private_dns_active = fields.next().unwrap_or("0") == "1";
    let private_dns_server_name = fields.next().unwrap_or_default().to_owned();
    let domains = fields.next().unwrap_or_default();
    let dns = fields.next().unwrap_or_default();

    Some(proto::AndroidNetwork {
        network_handle: handle,
        net_id: (handle >> 32) as i32,
        is_default: handle != 0 && handle == active_handle,
        transports: transports
            .split(',')
            .filter_map(transport)
            .map(|t| t as i32)
            .collect(),
        capabilities: Some(capabilities_from(capabilities)),
        link_properties: Some(proto::LinkPropertiesInfo {
            interface_name,
            mtu,
            private_dns_mode: if !private_dns_server_name.is_empty() {
                proto::PrivateDnsMode::Strict as i32
            } else if private_dns_active {
                proto::PrivateDnsMode::Opportunistic as i32
            } else {
                proto::PrivateDnsMode::Off as i32
            },
            private_dns_server_name,
            private_dns_active,
            domains: domains
                .split(' ')
                .filter(|d| !d.is_empty())
                .map(str::to_owned)
                .collect(),
            dns_servers: dns.split(',').filter_map(ip_address).collect(),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn transport(name: &str) -> Option<proto::Transport> {
    use proto::Transport as T;
    Some(match name {
        "CELLULAR" => T::Cellular,
        "WIFI" => T::Wifi,
        "BLUETOOTH" => T::Bluetooth,
        "ETHERNET" => T::Ethernet,
        "VPN" => T::Vpn,
        "USB" => T::Usb,
        // WIFI_AWARE and LOWPAN have no wire value; they are reported by name
        // so that adding one later is a change here and not in the Java.
        _ => return None,
    })
}

fn capabilities_from(list: &str) -> proto::NetworkCapabilitiesInfo {
    let has = |name: &str| list.split(',').any(|entry| entry == name);
    proto::NetworkCapabilitiesInfo {
        internet: has("INTERNET"),
        validated: has("VALIDATED"),
        captive_portal: has("CAPTIVE_PORTAL"),
        not_restricted: has("NOT_RESTRICTED"),
        not_metered: has("NOT_METERED"),
        not_roaming: has("NOT_ROAMING"),
        not_congested: has("NOT_CONGESTED"),
        not_suspended: has("NOT_SUSPENDED"),
        not_vpn: has("NOT_VPN"),
        trusted: has("TRUSTED"),
        foreground: has("FOREGROUND"),
        ..Default::default()
    }
}

/// `InetAddress.getHostAddress()` back into the raw bytes the schema stores.
///
/// A link-local IPv6 address comes with a scope (`fe80::1%wlan0`), which no IP
/// parser accepts, so it is trimmed first.
fn ip_address(text: &str) -> Option<proto::IpAddress> {
    let text = text.split('%').next()?.trim();
    if text.is_empty() {
        return None;
    }
    let parsed: std::net::IpAddr = text.parse().ok()?;
    // The schema stores only the bytes; four of them means v4 and sixteen v6,
    // so there is nothing else to record.
    Some(proto::IpAddress {
        addr: match parsed {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        },
    })
}
