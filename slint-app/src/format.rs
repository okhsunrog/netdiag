//! Turning protobuf messages into the flat rows the UI renders.
//!
//! The split is deliberate: Rust decides *what a value says* (how an address
//! is written, which status a check maps to, how a rule reads), and `.slint`
//! decides only how it is arranged on screen. Pushing the formatting into the
//! markup would mean reimplementing it in a language with no tests, and the
//! Compose build already showed how much of this logic there is.

use std::net::IpAddr;

use netdiag_ipc::proto;
use slint::{ModelRc, SharedString, VecModel};

use crate::ui;

pub fn shared(text: impl Into<String>) -> SharedString {
    SharedString::from(text.into())
}

pub fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

// ---- Primitives -------------------------------------------------------------

pub fn ip(address: &proto::IpAddress) -> String {
    match address.addr.len() {
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&address.addr);
            IpAddr::from(octets).to_string()
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&address.addr);
            IpAddr::from(octets).to_string()
        }
        _ => "-".to_string(),
    }
}

pub fn prefix(value: &proto::IpPrefix) -> String {
    match &value.address {
        Some(address) if !address.addr.is_empty() => {
            format!("{}/{}", ip(address), value.prefix_len)
        }
        _ => format!("*/{}", value.prefix_len),
    }
}

pub fn check_status(status: proto::CheckStatus) -> ui::Status {
    match status {
        proto::CheckStatus::Pass => ui::Status::Pass,
        proto::CheckStatus::Fail => ui::Status::Fail,
        proto::CheckStatus::Warn => ui::Status::Warn,
        proto::CheckStatus::Info => ui::Status::Info,
        _ => ui::Status::Skip,
    }
}

pub fn severity_status(severity: proto::FindingSeverity) -> ui::Status {
    match severity {
        proto::FindingSeverity::Critical | proto::FindingSeverity::High => ui::Status::Fail,
        proto::FindingSeverity::Medium => ui::Status::Warn,
        proto::FindingSeverity::Low => ui::Status::Info,
        _ => ui::Status::Skip,
    }
}

pub fn severity_label(severity: proto::FindingSeverity) -> &'static str {
    match severity {
        proto::FindingSeverity::Critical => "Critical",
        proto::FindingSeverity::High => "High",
        proto::FindingSeverity::Medium => "Medium",
        proto::FindingSeverity::Low => "Low",
        proto::FindingSeverity::Info => "Info",
        _ => "Unknown",
    }
}

pub fn status_label(status: proto::CheckStatus) -> &'static str {
    match status {
        proto::CheckStatus::Pass => "PASS",
        proto::CheckStatus::Fail => "FAIL",
        proto::CheckStatus::Warn => "WARN",
        proto::CheckStatus::Info => "INFO",
        proto::CheckStatus::Skip => "SKIP",
        _ => "….",
    }
}

pub fn tcp_state_label(state: proto::TcpState) -> &'static str {
    match state {
        proto::TcpState::Established => "ESTABLISHED",
        proto::TcpState::SynSent => "SYN_SENT",
        proto::TcpState::SynRecv => "SYN_RECV",
        proto::TcpState::FinWait1 => "FIN_WAIT1",
        proto::TcpState::FinWait2 => "FIN_WAIT2",
        proto::TcpState::TimeWait => "TIME_WAIT",
        proto::TcpState::Close => "CLOSE",
        proto::TcpState::CloseWait => "CLOSE_WAIT",
        proto::TcpState::LastAck => "LAST_ACK",
        proto::TcpState::Listen => "LISTEN",
        proto::TcpState::Closing => "CLOSING",
        _ => "UNKNOWN",
    }
}

pub fn transport_label(transport: proto::Transport) -> &'static str {
    match transport {
        proto::Transport::Cellular => "Cellular",
        proto::Transport::Wifi => "Wi-Fi",
        proto::Transport::Bluetooth => "Bluetooth",
        proto::Transport::Ethernet => "Ethernet",
        proto::Transport::Vpn => "VPN",
        proto::Transport::Usb => "USB",
        proto::Transport::Thread => "Thread",
        proto::Transport::Satellite => "Satellite",
        _ => "Unknown",
    }
}

pub fn link_kind_label(kind: proto::LinkKind) -> &'static str {
    match kind {
        proto::LinkKind::Loopback => "loopback",
        proto::LinkKind::Wifi => "Wi-Fi",
        proto::LinkKind::Cellular => "cellular",
        proto::LinkKind::Ethernet => "Ethernet",
        proto::LinkKind::VpnTun => "VPN",
        proto::LinkKind::Bluetooth => "Bluetooth",
        proto::LinkKind::Clat => "464XLAT",
        proto::LinkKind::Bridge => "bridge",
        proto::LinkKind::Dummy => "dummy",
        _ => "other",
    }
}

pub fn field(key: &str, value: impl Into<String>) -> ui::Field {
    ui::Field {
        key: shared(key),
        value: shared(value),
        status: ui::Status::Skip,
        mono: true,
    }
}

pub fn field_prose(key: &str, value: impl Into<String>) -> ui::Field {
    ui::Field {
        mono: false,
        ..field(key, value)
    }
}

pub fn field_status(key: &str, value: impl Into<String>, status: ui::Status) -> ui::Field {
    ui::Field {
        status,
        ..field(key, value)
    }
}

pub fn chip(text: impl Into<String>, status: ui::Status) -> ui::ChipData {
    ui::ChipData {
        text: shared(text),
        status,
    }
}

// ---- Routes and rules -------------------------------------------------------

/// Render a route the way `ip route` shows it, because that is the form anyone
/// debugging this recognises from a terminal.
pub fn route_line(route: &proto::Route) -> String {
    let destination = if route.is_default {
        "default".to_string()
    } else {
        route
            .destination
            .as_ref()
            .map(prefix)
            .unwrap_or_else(|| "?".to_string())
    };

    let hop = route.next_hops.first();
    let via = hop
        .and_then(|h| h.gateway.as_ref())
        .filter(|g| !g.addr.is_empty())
        .map(|g| format!("via {} ", ip(g)))
        .unwrap_or_default();
    let dev = hop
        .map(|h| {
            if h.out_interface_name.is_empty() {
                format!("dev if{}", h.out_interface_index)
            } else {
                format!("dev {}", h.out_interface_name)
            }
        })
        .unwrap_or_default();

    let mut line = format!("{destination} {via}{dev}");
    if route.priority != 0 {
        line.push_str(&format!(" metric {}", route.priority));
    }
    if let Some(metrics) = &route.metrics
        && metrics.mtu != 0
    {
        line.push_str(&format!(" mtu {}", metrics.mtu));
    }
    line
}

/// Render a rule the way `ip rule` shows it.
///
/// `ip rule` separates the priority with a tab. This does not: Slint's text
/// rendering has no tab stops and draws the character as a missing glyph, so on
/// the device it came out as `13000:▯fwmark`.
pub fn rule_line(rule: &proto::RoutingRule) -> String {
    let mut line = format!("{}: ", rule.priority);
    if let Some(source) = &rule.source
        && source.address.is_some()
    {
        line.push_str(&format!("from {} ", prefix(source)));
    }
    if let Some(destination) = &rule.destination
        && destination.address.is_some()
    {
        line.push_str(&format!("to {} ", prefix(destination)));
    }
    if !rule.input_interface.is_empty() {
        line.push_str(&format!("iif {} ", rule.input_interface));
    }
    if !rule.output_interface.is_empty() {
        line.push_str(&format!("oif {} ", rule.output_interface));
    }
    if rule.has_fwmark {
        line.push_str(&format!("fwmark 0x{:x}", rule.fwmark));
        if rule.fwmask != 0 {
            line.push_str(&format!("/0x{:x}", rule.fwmask));
        }
        line.push(' ');
    }
    if rule.has_uid_range {
        if rule.invert {
            line.push_str("not ");
        }
        line.push_str(&format!(
            "uidrange {}-{} ",
            rule.uid_range_start, rule.uid_range_end
        ));
    }
    if rule.table_name.is_empty() {
        line.push_str(&format!("lookup {}", rule.table));
    } else {
        line.push_str(&format!("lookup {}", rule.table_name));
    }
    line
}

pub fn socket_tuple(socket: &proto::Socket) -> String {
    let local = format!(
        "{}:{}",
        socket
            .local_address
            .as_ref()
            .map(ip)
            .unwrap_or_else(|| "-".into()),
        socket.local_port
    );
    let remote = if socket.remote_port == 0 {
        "*:*".to_string()
    } else {
        format!(
            "{}:{}",
            socket
                .remote_address
                .as_ref()
                .map(ip)
                .unwrap_or_else(|| "-".into()),
            socket.remote_port
        )
    };
    format!("{local} -> {remote}")
}

pub fn socket_status(state: proto::TcpState) -> ui::Status {
    match state {
        proto::TcpState::Established => ui::Status::Pass,
        proto::TcpState::SynSent | proto::TcpState::CloseWait => ui::Status::Warn,
        proto::TcpState::Listen => ui::Status::Info,
        _ => ui::Status::Skip,
    }
}

// ---- Time -------------------------------------------------------------------

/// HH:MM:SS.mmm in local time, without pulling in a date library for one
/// format string.
///
/// The timeline is read next to the device's own clock — the user notices a
/// three-hour offset immediately — so this has to be local, not UTC.
pub fn time_of_day(unix_ms: i64) -> String {
    let total_seconds = unix_ms.div_euclid(1000);
    let millis = unix_ms.rem_euclid(1000);
    let seconds_today = (total_seconds + utc_offset_seconds(total_seconds)).rem_euclid(86_400);
    let hours = seconds_today / 3600;
    let minutes = (seconds_today % 3600) / 60;
    let seconds = seconds_today % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}")
}

/// Seconds east of UTC at the given instant, from the C library.
///
/// `localtime_r` is asked for the offset *at that timestamp* rather than at
/// startup, so an event recorded either side of a DST change still renders with
/// the offset that was in force when it happened. On Android this reads the
/// `persist.sys.timezone` the framework sets, so it follows the device.
fn utc_offset_seconds(unix_seconds: i64) -> i64 {
    // SAFETY: `tm` is fully written by localtime_r before it is read, and the
    // call is the reentrant variant, so it does not touch shared state.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let time = unix_seconds as libc::time_t;
        if libc::localtime_r(&time, &mut tm).is_null() {
            // No timezone database, or a timestamp it cannot represent. UTC is
            // wrong but readable; refusing to render a time would be worse.
            return 0;
        }
        tm.tm_gmtoff as i64
    }
}

pub fn bytes(value: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = value as f64;
    if value < KIB {
        format!("{value:.0} B")
    } else if value < KIB * KIB {
        format!("{:.1} KiB", value / KIB)
    } else if value < KIB * KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else {
        format!("{:.2} GiB", value / (KIB * KIB * KIB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_v4_and_v6_addresses() {
        let v4 = proto::IpAddress {
            addr: vec![192, 168, 1, 1],
        };
        assert_eq!(ip(&v4), "192.168.1.1");

        let v6 = proto::IpAddress {
            addr: vec![0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11],
        };
        assert_eq!(ip(&v6), "2606:4700:4700::1111");
    }

    #[test]
    fn an_unset_address_is_not_rendered_as_a_number() {
        assert_eq!(ip(&proto::IpAddress::default()), "-");
    }

    #[test]
    fn renders_a_default_route_like_ip_route() {
        let route = proto::Route {
            is_default: true,
            table: 1051,
            next_hops: vec![proto::NextHop {
                out_interface_name: "tun0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(route_line(&route), "default dev tun0");
    }

    #[test]
    fn renders_a_gateway_route() {
        let route = proto::Route {
            is_default: true,
            priority: 100,
            next_hops: vec![proto::NextHop {
                gateway: Some(proto::IpAddress {
                    addr: vec![10, 77, 77, 1],
                }),
                out_interface_name: "wlan0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(route_line(&route), "default via 10.77.77.1 dev wlan0 metric 100");
    }

    #[test]
    fn renders_an_inverted_uid_rule_like_ip_rule() {
        let rule = proto::RoutingRule {
            priority: 16000,
            has_uid_range: true,
            uid_range_start: 10342,
            uid_range_end: 10342,
            invert: true,
            table: 1003,
            table_name: "vpn_fallthrough".into(),
            ..Default::default()
        };
        assert_eq!(
            rule_line(&rule),
            "16000: not uidrange 10342-10342 lookup vpn_fallthrough"
        );
    }

    #[test]
    fn renders_an_fwmark_rule() {
        let rule = proto::RoutingRule {
            priority: 13000,
            has_fwmark: true,
            fwmark: 0xc0067,
            fwmask: 0xcffff,
            table: 1051,
            ..Default::default()
        };
        assert_eq!(
            rule_line(&rule),
            "13000: fwmark 0xc0067/0xcffff lookup 1051"
        );
    }

    #[test]
    fn a_listening_socket_has_no_remote() {
        let socket = proto::Socket {
            local_address: Some(proto::IpAddress {
                addr: vec![0, 0, 0, 0],
            }),
            local_port: 5555,
            ..Default::default()
        };
        assert_eq!(socket_tuple(&socket), "0.0.0.0:5555 -> *:*");
    }

    #[test]
    fn time_of_day_keeps_milliseconds() {
        // 1970-01-01T01:02:03.456Z, shifted so the expectation holds whatever
        // zone the test machine is in.
        let utc_seconds = 3600 + 120 + 3;
        let ms = utc_seconds * 1000 + 456;
        let local = (utc_seconds + utc_offset_seconds(utc_seconds)).rem_euclid(86_400);
        let expected = format!(
            "{:02}:{:02}:{:02}.456",
            local / 3600,
            (local % 3600) / 60,
            local % 60
        );
        assert_eq!(time_of_day(ms), expected);
    }

    #[test]
    fn time_of_day_is_local_not_utc() {
        // The bug this guards against: rendering UTC while sitting next to the
        // device's own clock. It can only be observed where the two differ, so
        // on a UTC machine this asserts nothing and passes.
        let now = 1_757_000_000_i64;
        if utc_offset_seconds(now) == 0 {
            return;
        }
        let utc_today = now.rem_euclid(86_400);
        let as_utc = format!(
            "{:02}:{:02}:{:02}.000",
            utc_today / 3600,
            (utc_today % 3600) / 60,
            utc_today % 60
        );
        assert_ne!(time_of_day(now * 1000), as_utc);
    }

    #[test]
    fn time_of_day_handles_negative_input_without_panicking() {
        // A device with a clock before the epoch is nonsense, but it must not
        // crash the timeline.
        let _ = time_of_day(-1);
    }

    #[test]
    fn formats_byte_sizes() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
