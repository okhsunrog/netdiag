//! State that has no netlink interface: sysctls, SNMP counters, the resolver
//! configuration and network namespaces.

use std::collections::HashMap;

use crate::proto;
use crate::util;

/// Sysctls read for the global view. Kept as an explicit list rather than a
/// recursive walk of /proc/sys/net: the walk is slow, most of it is noise, and
/// on Android a lot of it is unreadable even as root under SELinux.
const GLOBAL_SYSCTLS: &[&str] = &[
    "ipv4/ip_forward",
    "ipv4/tcp_congestion_control",
    "ipv4/tcp_available_congestion_control",
    "ipv4/tcp_fastopen",
    "ipv4/tcp_mtu_probing",
    "ipv4/tcp_base_mss",
    "ipv4/tcp_syn_retries",
    "ipv4/tcp_synack_retries",
    "ipv4/tcp_retries2",
    "ipv4/tcp_fin_timeout",
    "ipv4/tcp_keepalive_time",
    "ipv4/tcp_keepalive_intvl",
    "ipv4/tcp_keepalive_probes",
    "ipv4/tcp_ecn",
    "ipv4/tcp_timestamps",
    "ipv4/tcp_sack",
    "ipv4/tcp_rmem",
    "ipv4/tcp_wmem",
    "ipv4/ip_no_pmtu_disc",
    "ipv4/route/min_pmtu",
    "ipv4/route/mtu_expires",
    "ipv4/ping_group_range",
    "ipv4/conf/all/rp_filter",
    "ipv6/conf/all/forwarding",
    "ipv6/conf/all/disable_ipv6",
    "ipv6/conf/all/accept_ra",
    "ipv6/conf/default/accept_ra",
    "ipv6/conf/all/use_tempaddr",
    "ipv6/route/max_size",
    "core/default_qdisc",
    "core/somaxconn",
    "core/rmem_max",
    "core/wmem_max",
];

pub fn read_global_sysctls() -> proto::GlobalSysctls {
    let mut raw = HashMap::new();
    for key in GLOBAL_SYSCTLS {
        if let Some(value) = util::read_trimmed(format!("/proc/sys/net/{key}")) {
            // Multi-value sysctls are tab separated in /proc; normalise so the
            // UI does not have to.
            raw.insert(
                key.to_string(),
                value.split_whitespace().collect::<Vec<_>>().join(" "),
            );
        }
    }

    let get_i32 = |key: &str| -> i32 {
        raw.get(key)
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1)
    };
    let get_str = |key: &str| -> String { raw.get(key).cloned().unwrap_or_default() };

    let default_qdisc = get_str("core/default_qdisc");

    proto::GlobalSysctls {
        ipv4_forwarding: get_i32("ipv4/ip_forward"),
        ipv6_forwarding: get_i32("ipv6/conf/all/forwarding"),
        ipv6_disable: get_i32("ipv6/conf/all/disable_ipv6"),
        tcp_congestion_control: get_str("ipv4/tcp_congestion_control"),
        tcp_available_congestion_control: get_str("ipv4/tcp_available_congestion_control"),
        tcp_fastopen: get_i32("ipv4/tcp_fastopen"),
        tcp_mtu_probing: get_i32("ipv4/tcp_mtu_probing"),
        tcp_base_mss: get_i32("ipv4/tcp_base_mss"),
        tcp_syn_retries: get_i32("ipv4/tcp_syn_retries"),
        tcp_synack_retries: get_i32("ipv4/tcp_synack_retries"),
        tcp_retries2: get_i32("ipv4/tcp_retries2"),
        tcp_fin_timeout: get_i32("ipv4/tcp_fin_timeout"),
        tcp_keepalive_time: get_i32("ipv4/tcp_keepalive_time"),
        tcp_ecn: get_i32("ipv4/tcp_ecn"),
        tcp_timestamps: get_i32("ipv4/tcp_timestamps"),
        tcp_sack: get_i32("ipv4/tcp_sack"),
        default_qdisc_present: i32::from(!default_qdisc.is_empty()),
        default_qdisc,
        ping_group_range: get_str("ipv4/ping_group_range"),
        ip_no_pmtu_disc: get_i32("ipv4/ip_no_pmtu_disc"),
        route_min_pmtu: get_i32("ipv4/route/min_pmtu"),
        raw,
    }
}

/// Can an unprivileged process open an ICMP datagram socket? Android usually
/// sets net.ipv4.ping_group_range to cover all gids, which is why `ping` works
/// without setuid. If it does not, our own ICMP probes need a raw socket.
pub fn ping_group_range_allows(gid: u32) -> bool {
    let Some(value) = util::read_trimmed("/proc/sys/net/ipv4/ping_group_range") else {
        return false;
    };
    let mut parts = value.split_whitespace();
    let (Some(lo), Some(hi)) = (parts.next(), parts.next()) else {
        return false;
    };
    let (Ok(lo), Ok(hi)) = (lo.parse::<u64>(), hi.parse::<u64>()) else {
        return false;
    };
    let gid = gid as u64;
    lo <= gid && gid <= hi
}

/// Parse the two-line-per-protocol format used by /proc/net/snmp and
/// /proc/net/netstat:
///
/// ```text
/// Tcp: RtoAlgorithm RtoMin ... InSegs OutSegs
/// Tcp: 1 200 ... 12345 67890
/// ```
fn parse_snmp_style(text: &str) -> HashMap<String, HashMap<String, i64>> {
    let mut out: HashMap<String, HashMap<String, i64>> = HashMap::new();
    let mut lines = text.lines();
    while let (Some(header), Some(values)) = (lines.next(), lines.next()) {
        let Some((proto_name, header_rest)) = header.split_once(':') else {
            continue;
        };
        let Some((values_proto, values_rest)) = values.split_once(':') else {
            continue;
        };
        if proto_name != values_proto {
            continue;
        }
        let entry = out.entry(proto_name.to_ascii_lowercase()).or_default();
        for (name, value) in header_rest
            .split_whitespace()
            .zip(values_rest.split_whitespace())
        {
            if let Ok(v) = value.parse::<i64>() {
                entry.insert(name.to_string(), v);
            }
        }
    }
    out
}

/// /proc/net/snmp6 and /proc/net/dev_snmp6/* use a flat `Name value` layout.
fn parse_flat_counters(text: &str) -> HashMap<String, i64> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let value = parts.next()?.parse::<i64>().ok()?;
            Some((name.to_string(), value))
        })
        .collect()
}

pub fn read_counters() -> proto::ProtocolCounters {
    let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    let netstat = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let snmp6 = std::fs::read_to_string("/proc/net/snmp6").unwrap_or_default();

    let snmp = parse_snmp_style(&snmp);
    let netstat = parse_snmp_style(&netstat);
    let v6 = parse_flat_counters(&snmp6);

    // snmp6 is one flat namespace with Ip6/Icmp6/Udp6 prefixes.
    let take_prefix = |prefix: &str| -> HashMap<String, i64> {
        v6.iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k[prefix.len()..].to_string(), *v))
            .collect()
    };

    proto::ProtocolCounters {
        ip: snmp.get("ip").cloned().unwrap_or_default(),
        icmp: snmp.get("icmp").cloned().unwrap_or_default(),
        tcp: snmp.get("tcp").cloned().unwrap_or_default(),
        udp: snmp.get("udp").cloned().unwrap_or_default(),
        ip6: take_prefix("Ip6"),
        icmp6: take_prefix("Icmp6"),
        udp6: take_prefix("Udp6"),
        tcp_ext: netstat.get("tcpext").cloned().unwrap_or_default(),
        ip_ext: netstat.get("ipext").cloned().unwrap_or_default(),
    }
}

/// On Android /etc/resolv.conf normally does not exist: netd owns DNS and hands
/// resolver configuration to apps through the framework instead. Reporting that
/// absence explicitly stops it from looking like a collection failure.
pub fn read_resolver_state() -> proto::ResolverState {
    let path = "/etc/resolv.conf";
    let Some(text) = util::read_trimmed(path) else {
        return proto::ResolverState {
            resolv_conf_present: false,
            resolv_conf_note: "no /etc/resolv.conf; on Android the resolver lives in netd and \
                               DNS servers are published through LinkProperties instead"
                .to_string(),
            ..Default::default()
        };
    };

    let mut servers = Vec::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            if let Ok(ip) = rest.trim().parse::<std::net::IpAddr>() {
                servers.push(proto::IpAddress::from_ip(ip));
            }
        } else if let Some(rest) = line.strip_prefix("search") {
            domains.extend(rest.split_whitespace().map(str::to_string));
        }
    }

    proto::ResolverState {
        resolv_conf_servers: servers,
        resolv_conf_domains: domains,
        resolv_conf_present: true,
        resolv_conf_note: String::new(),
    }
}

/// Network namespaces. Android puts almost everything in the init namespace,
/// but some vendors and some VPN implementations do not, and a route that
/// "does not exist" because it is in another namespace is worth spotting.
pub fn read_namespaces() -> Vec<proto::NetworkNamespace> {
    let mut out = Vec::new();

    let current_inode = std::fs::metadata("/proc/self/ns/net")
        .ok()
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.ino()
        })
        .unwrap_or(0);

    out.push(proto::NetworkNamespace {
        id: -1,
        name: "self".to_string(),
        inode: current_inode,
        is_current: true,
    });

    if let Ok(entries) = std::fs::read_dir("/var/run/netns") {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            use std::os::unix::fs::MetadataExt;
            let inode = meta.ino();
            out.push(proto::NetworkNamespace {
                id: -1,
                name: entry.file_name().to_string_lossy().to_string(),
                inode,
                is_current: inode == current_inode,
            });
        }
    }

    out
}

/// Detect 464XLAT from the kernel side. Android runs clatd when a network is
/// IPv6-only, creating a `v4-<iface>` tun; its presence is proof the network
/// has no native IPv4, which reframes every "IPv4 is broken" symptom.
pub fn detect_clat(interfaces: &[proto::Interface]) -> proto::Clat464State {
    let clat = interfaces
        .iter()
        .find(|i| i.kind == proto::LinkKind::Clat as i32 || i.name.starts_with("v4-"));

    let Some(clat) = clat else {
        return proto::Clat464State {
            active: false,
            detection_method: "no v4-* interface present".to_string(),
            ..Default::default()
        };
    };

    let base = clat.name.strip_prefix("v4-").unwrap_or("").to_string();
    let up = clat
        .flags
        .as_ref()
        .map(|f| f.up && f.running)
        .unwrap_or(false);

    let v4 = clat
        .addresses
        .iter()
        .filter_map(|a| a.prefix.as_ref()?.ip())
        .find(|ip| ip.is_ipv4());
    let v6 = clat
        .addresses
        .iter()
        .filter_map(|a| a.prefix.as_ref()?.ip())
        .find(|ip| ip.is_ipv6());

    proto::Clat464State {
        active: up,
        clat_interface: clat.name.clone(),
        base_interface: base,
        clat_ipv4_address: v4.map(proto::IpAddress::from_ip),
        clat_ipv6_address: v6.map(proto::IpAddress::from_ip),
        // The NAT64 prefix itself is not visible on the interface; the
        // framework reports it via LinkProperties, and the DNS64 probe
        // confirms it independently.
        detected_nat64_prefix: None,
        detection_method: format!("clat interface {} present", clat.name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snmp_two_line_format() {
        let text = "Tcp: RtoAlgorithm RtoMin InSegs\nTcp: 1 200 12345\n\
                    Udp: InDatagrams NoPorts\nUdp: 10 2\n";
        let parsed = parse_snmp_style(text);
        assert_eq!(parsed["tcp"]["InSegs"], 12345);
        assert_eq!(parsed["tcp"]["RtoMin"], 200);
        assert_eq!(parsed["udp"]["NoPorts"], 2);
    }

    #[test]
    fn ignores_mismatched_snmp_pairs() {
        // A truncated read must not pair a Tcp header with Udp values.
        let text = "Tcp: InSegs\nUdp: 5\n";
        assert!(parse_snmp_style(text).is_empty());
    }

    #[test]
    fn parses_flat_counters() {
        let parsed = parse_flat_counters("Ip6InReceives 42\nIp6OutNoRoutes 7\n");
        assert_eq!(parsed["Ip6InReceives"], 42);
        assert_eq!(parsed["Ip6OutNoRoutes"], 7);
    }

    #[test]
    fn detects_clat_interface() {
        let interfaces = vec![proto::Interface {
            index: 42,
            name: "v4-rmnet_data0".to_string(),
            kind: proto::LinkKind::Clat as i32,
            flags: Some(proto::LinkFlags {
                up: true,
                running: true,
                ..Default::default()
            }),
            ..Default::default()
        }];
        let clat = detect_clat(&interfaces);
        assert!(clat.active);
        assert_eq!(clat.base_interface, "rmnet_data0");
    }

    #[test]
    fn reports_no_clat_cleanly() {
        let interfaces = vec![proto::Interface {
            name: "wlan0".to_string(),
            ..Default::default()
        }];
        assert!(!detect_clat(&interfaces).active);
    }
}
