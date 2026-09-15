//! Cross-layer correlation: following one app's traffic from its uid down to
//! the interface its packets actually leave by.
//!
//! ```text
//! package name -> uid -> sockets -> policy rules / fwmark -> table -> interface
//! ```
//!
//! The app resolves the package name to a uid (only it has a PackageManager);
//! everything below that is kernel state. Two joins make the chain work:
//!
//! * **uid -> route**: rather than reimplementing fib rule matching, the
//!   daemon asks the kernel to route a packet *as that uid* (RTM_GETROUTE with
//!   RTA_UID). The answer is the kernel's own decision, including every uid
//!   range rule a VPN installed, so it cannot drift from reality.
//! * **socket -> Network**: Android writes the netId into the low bits of a
//!   socket's SO_MARK. inet_diag reports the mark, so every socket can be
//!   attributed to a framework `Network` object without guessing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use rtnetlink::Handle;

use crate::collect::{firewall, routes, sockets};
use crate::proto;
use crate::util;

/// Destinations used for the per-uid route lookups. Any global address works;
/// these are stable, anycast, and unlikely to have a host-specific route.
const PROBE_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

pub struct CorrelationInput<'a> {
    pub app: proto::AppRef,
    pub android_state: Option<&'a proto::AndroidNetworkState>,
    pub include_tcp_info: bool,
    pub skip_route_lookup: bool,
}

pub async fn app_network_state(
    handle: &Handle,
    interfaces: &[proto::Interface],
    if_names: &HashMap<u32, String>,
    input: CorrelationInput<'_>,
) -> Result<proto::AppNetworkState> {
    let uid = input.app.uid;

    let all_rules = routes::get_rules(handle, proto::IpFamily::Unspecified, None).await?;
    let matching_rules: Vec<proto::RoutingRule> = all_rules
        .iter()
        .filter(|r| routes::rule_can_match_uid(r, uid))
        // A rule with no uid selector matches everyone and says nothing about
        // this app; only keep those plus the ones that name it explicitly.
        .filter(|r| r.has_uid_range || r.has_fwmark)
        .cloned()
        .collect();

    let (lookup_v4, lookup_v6) = if input.skip_route_lookup {
        (proto::RouteLookup::default(), proto::RouteLookup::default())
    } else {
        (
            routes::route_lookup(
                handle,
                IpAddr::V4(PROBE_V4),
                None,
                Some(uid),
                None,
                0,
                if_names,
            )
            .await,
            routes::route_lookup(
                handle,
                IpAddr::V6(PROBE_V6),
                None,
                Some(uid),
                None,
                0,
                if_names,
            )
            .await,
        )
    };

    let egress_v4 = egress_name(&lookup_v4);
    let egress_v6 = egress_name(&lookup_v6);

    let routing = proto::UidRoutingPath {
        uid,
        matching_rules,
        table_v4: lookup_v4.route.as_ref().map(|r| r.table).unwrap_or(0),
        table_v6: lookup_v6.route.as_ref().map(|r| r.table).unwrap_or(0),
        egress_interface_v4: egress_v4.clone(),
        egress_interface_v6: egress_v6.clone(),
        lookup_v4: Some(lookup_v4.clone()),
        lookup_v6: Some(lookup_v6.clone()),
    };

    let filter = proto::SocketFilter {
        uids: vec![uid],
        include_tcp_info: input.include_tcp_info,
        ..Default::default()
    };
    let dump = sockets::get_sockets(&filter, if_names).await?;
    let mut app_sockets = dump.sockets;
    for socket in &mut app_sockets {
        if !input.app.package_name.is_empty() {
            socket.package_names = vec![input.app.package_name.clone()];
        }
    }

    let observed_net_ids = observed_net_ids(&app_sockets);

    let android_network = input.android_state.and_then(|state| {
        // Prefer the Network the app's own sockets are pinned to; fall back to
        // the system default. An app that called Network.bindSocket will
        // legitimately differ from the default, and saying so is the point.
        observed_net_ids
            .first()
            .and_then(|net_id| state.networks.iter().find(|n| n.net_id == *net_id))
            .or_else(|| state.networks.iter().find(|n| n.is_default))
            .cloned()
    });

    let vpn = assess_vpn(
        interfaces,
        &all_rules,
        &vpn_tables(handle, interfaces).await,
        uid,
        &lookup_v4,
        &lookup_v6,
        input.android_state,
    );

    let uid_firewall = firewall::read_uid_firewall(uid);
    let firewall_note = if !uid_firewall.source_available {
        "per-uid firewall state could not be read from netd's eBPF map".to_string()
    } else if uid_firewall.raw_match == 0 {
        "no per-uid firewall rules apply".to_string()
    } else {
        format!(
            "firewall bits: {}",
            firewall::decode_match_bits(uid_firewall.raw_match).join(", ")
        )
    };

    let ipv4_path_ok = lookup_v4.route.is_some();
    let ipv6_path_ok = lookup_v6.route.is_some();

    let summary = build_summary(
        &input.app,
        &egress_v4,
        &egress_v6,
        &dump.summary,
        &vpn,
        ipv4_path_ok,
        ipv6_path_ok,
    );

    Ok(proto::AppNetworkState {
        app: Some(input.app),
        android_network,
        routing: Some(routing),
        sockets: app_sockets,
        socket_summary: Some(dump.summary),
        vpn: Some(vpn),
        firewall_note,
        observed_net_ids,
        ipv4_path_ok,
        ipv6_path_ok,
        summary,
    })
}

fn egress_name(lookup: &proto::RouteLookup) -> String {
    lookup
        .route
        .as_ref()
        .and_then(|r| r.next_hops.first())
        .map(|h| h.out_interface_name.clone())
        .unwrap_or_default()
}

/// netIds this app's sockets are actually pinned to, most used first.
fn observed_net_ids(app_sockets: &[proto::Socket]) -> Vec<i32> {
    let mut counts: HashMap<i32, usize> = HashMap::new();
    for socket in app_sockets {
        if socket.has_mark && socket.net_id != 0 {
            *counts.entry(socket.net_id as i32).or_insert(0) += 1;
        }
    }
    let mut ids: Vec<(i32, usize)> = counts.into_iter().collect();
    ids.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ids.into_iter().map(|(id, _)| id).collect()
}

/// Routing tables whose default route leaves through a VPN interface.
///
/// Needed to tell "no rule mentions this uid" apart from "a rule deliberately
/// leaves this uid out of the VPN", which look identical from the uid's own
/// point of view but mean very different things.
async fn vpn_tables(handle: &Handle, interfaces: &[proto::Interface]) -> Vec<u32> {
    let vpn_indexes: Vec<u32> = interfaces
        .iter()
        .filter(|i| i.kind == proto::LinkKind::VpnTun as i32)
        .map(|i| i.index)
        .collect();
    if vpn_indexes.is_empty() {
        return Vec::new();
    }

    let names = HashMap::new();
    let Ok(dump) =
        routes::get_routes(handle, proto::IpFamily::Unspecified, 0, true, 0, &names).await
    else {
        return Vec::new();
    };

    let mut tables: Vec<u32> = dump
        .routes
        .iter()
        .filter(|r| {
            r.next_hops
                .iter()
                .any(|h| vpn_indexes.contains(&h.out_interface_index))
        })
        .map(|r| r.table)
        .collect();
    tables.sort_unstable();
    tables.dedup();
    tables
}

fn assess_vpn(
    interfaces: &[proto::Interface],
    rules: &[proto::RoutingRule],
    vpn_tables: &[u32],
    uid: u32,
    lookup_v4: &proto::RouteLookup,
    lookup_v6: &proto::RouteLookup,
    android_state: Option<&proto::AndroidNetworkState>,
) -> proto::VpnAssessment {
    let vpn_iface = interfaces.iter().find(|i| {
        i.kind == proto::LinkKind::VpnTun as i32 && i.flags.as_ref().map(|f| f.up).unwrap_or(false)
    });

    let Some(vpn) = vpn_iface else {
        return proto::VpnAssessment::default();
    };

    let uses_vpn = [lookup_v4, lookup_v6].iter().any(|lookup| {
        lookup
            .route
            .as_ref()
            .and_then(|r| r.next_hops.first())
            .map(|h| h.out_interface_index == vpn.index)
            .unwrap_or(false)
    });

    // An inverted uid range rule is how Android carves an app out of a VPN.
    let bypass_rule = rules.iter().find(|r| {
        r.has_uid_range && r.invert && uid >= r.uid_range_start && uid <= r.uid_range_end
    });
    // A non-inverted rule naming this uid and pointing somewhere other than
    // the VPN's table also constitutes a bypass.
    let explicit_rule = rules.iter().find(|r| {
        r.has_uid_range && !r.invert && uid >= r.uid_range_start && uid <= r.uid_range_end
    });

    // How many uid ranges point into the VPN's table, and does any cover us?
    // Android implements a VPN's per-app allow/deny list by installing one
    // uidrange rule per contiguous block of included uids. An app that is
    // excluded simply falls into a gap between those ranges, so the absence of
    // a matching rule *is* the exclusion — there is no explicit "deny" entry
    // to find.
    let vpn_uid_rules: Vec<&proto::RoutingRule> = rules
        .iter()
        .filter(|r| r.has_uid_range && vpn_tables.contains(&r.table))
        .collect();
    let covered_by_vpn_rule = vpn_uid_rules
        .iter()
        .any(|r| uid >= r.uid_range_start && uid <= r.uid_range_end && !r.invert);

    let bypass_reason = if let Some(rule) = bypass_rule {
        format!(
            "rule priority {} explicitly excludes uids {}-{} from table {}",
            rule.priority, rule.uid_range_start, rule.uid_range_end, rule.table
        )
    } else if !uses_vpn && !vpn_uid_rules.is_empty() && !covered_by_vpn_rule {
        format!(
            "uid {uid} falls outside all {} uid range(s) that route into the VPN's table, \
             so the VPN app's per-app list excludes this app",
            vpn_uid_rules.len()
        )
    } else if !uses_vpn {
        match explicit_rule {
            Some(rule) => format!(
                "rule priority {} sends uids {}-{} to table {} instead of the VPN",
                rule.priority, rule.uid_range_start, rule.uid_range_end, rule.table
            ),
            None => "the kernel route lookup does not select the VPN interface".to_string(),
        }
    } else {
        String::new()
    };

    // The framework's own opinion, for the disagreement check.
    let vpn_network = android_state.and_then(|state| {
        state
            .networks
            .iter()
            .find(|n| n.transports.contains(&(proto::Transport::Vpn as i32)))
    });
    let framework_says_in_vpn = vpn_network
        .and_then(|n| n.capabilities.as_ref())
        .map(|caps| {
            caps.vpn_uid_ranges.is_empty()
                || caps
                    .vpn_uid_ranges
                    .iter()
                    .any(|r| uid as i32 >= r.start && uid as i32 <= r.stop)
        })
        .unwrap_or(false);

    let ipv6_inside_vpn = lookup_v6
        .route
        .as_ref()
        .and_then(|r| r.next_hops.first())
        .map(|h| h.out_interface_index == vpn.index)
        .unwrap_or(false);

    let v4_in_vpn = lookup_v4
        .route
        .as_ref()
        .and_then(|r| r.next_hops.first())
        .map(|h| h.out_interface_index == vpn.index)
        .unwrap_or(false);

    proto::VpnAssessment {
        vpn_present: true,
        vpn_interface: vpn.name.clone(),
        vpn_net_id: vpn_network.map(|n| n.net_id).unwrap_or(0),
        app_uses_vpn: uses_vpn,
        app_bypasses_vpn: !uses_vpn,
        bypass_reason,
        framework_says_in_vpn,
        disagreement: framework_says_in_vpn != uses_vpn,
        // One family in the tunnel and the other outside it.
        split_tunnel: v4_in_vpn != ipv6_inside_vpn,
        ipv6_inside_vpn,
    }
}

fn build_summary(
    app: &proto::AppRef,
    egress_v4: &str,
    egress_v6: &str,
    sockets: &proto::SocketSummary,
    vpn: &proto::VpnAssessment,
    ipv4_ok: bool,
    ipv6_ok: bool,
) -> String {
    let name = if app.package_name.is_empty() {
        format!("uid {}", app.uid)
    } else {
        app.package_name.clone()
    };

    let path = match (ipv4_ok, ipv6_ok) {
        (true, true) => format!("IPv4 via {egress_v4}, IPv6 via {egress_v6}"),
        (true, false) => format!("IPv4 via {egress_v4}, no IPv6 path"),
        (false, true) => format!("IPv6 via {egress_v6}, no IPv4 path"),
        (false, false) => "no route out for either family".to_string(),
    };

    let vpn_note = if !vpn.vpn_present {
        String::new()
    } else if vpn.app_uses_vpn {
        format!("; goes through {}", vpn.vpn_interface)
    } else {
        format!("; bypasses {}", vpn.vpn_interface)
    };

    format!(
        "{name}: {path}{vpn_note}. {} socket(s), {} established, {} in SYN_SENT.",
        sockets.total, sockets.established, sockets.syn_sent
    )
}

/// Decode a socket's mark for display, e.g. "0x10065 (netId 101, explicitly
/// selected)".
pub fn describe_mark(mark: u32) -> String {
    if mark == 0 {
        return "0 (unmarked, uses the default network)".to_string();
    }
    let net_id = util::net_id_from_mark(mark);
    let mut notes = Vec::new();
    if net_id != 0 {
        notes.push(format!("netId {net_id}"));
    }
    if mark & util::FWMARK_EXPLICITLY_SELECTED != 0 {
        notes.push("explicitly selected".to_string());
    }
    if mark & util::FWMARK_PROTECTED_FROM_VPN != 0 {
        notes.push("protected from VPN".to_string());
    }
    if notes.is_empty() {
        format!("0x{mark:x}")
    } else {
        format!("0x{mark:x} ({})", notes.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_with_mark(mark: u32) -> proto::Socket {
        proto::Socket {
            has_mark: mark != 0,
            mark,
            net_id: util::net_id_from_mark(mark),
            ..Default::default()
        }
    }

    fn vpn_interface() -> proto::Interface {
        proto::Interface {
            index: 42,
            name: "tun0".to_string(),
            kind: proto::LinkKind::VpnTun as i32,
            flags: Some(proto::LinkFlags {
                up: true,
                running: true,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn lookup_via(index: u32) -> proto::RouteLookup {
        proto::RouteLookup {
            route: Some(proto::Route {
                table: 101,
                next_hops: vec![proto::NextHop {
                    out_interface_index: index,
                    out_interface_name: format!("if{index}"),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn observed_net_ids_are_ordered_by_use() {
        let sockets = vec![
            socket_with_mark(util::mark_for_net_id(101)),
            socket_with_mark(util::mark_for_net_id(102)),
            socket_with_mark(util::mark_for_net_id(101)),
            socket_with_mark(0),
        ];
        assert_eq!(observed_net_ids(&sockets), vec![101, 102]);
    }

    #[test]
    fn unmarked_sockets_contribute_no_net_id() {
        assert!(observed_net_ids(&[socket_with_mark(0)]).is_empty());
    }

    #[test]
    fn describes_a_mark_in_android_terms() {
        let text = describe_mark(util::mark_for_net_id(101));
        assert!(text.contains("netId 101"), "{text}");
        assert!(text.contains("explicitly selected"), "{text}");
        assert!(describe_mark(0).contains("unmarked"));
    }

    #[test]
    fn no_vpn_interface_means_no_assessment() {
        let assessment = assess_vpn(&[], &[], &[], 10342, &lookup_via(3), &lookup_via(3), None);
        assert!(!assessment.vpn_present);
    }

    #[test]
    fn app_routed_through_the_tun_uses_the_vpn() {
        let interfaces = vec![vpn_interface()];
        let assessment = assess_vpn(
            &interfaces,
            &[],
            &[],
            10342,
            &lookup_via(42),
            &lookup_via(42),
            None,
        );
        assert!(assessment.vpn_present);
        assert!(assessment.app_uses_vpn);
        assert!(!assessment.app_bypasses_vpn);
        assert!(!assessment.split_tunnel);
    }

    /// The common Android case: a VPN's per-app list is expressed as a set of
    /// uid ranges, and an excluded app is simply absent from all of them.
    /// There is no "deny" rule to point at, so the explanation has to come
    /// from the gap itself.
    #[test]
    fn an_app_outside_every_vpn_uid_range_is_explained_as_an_exclusion() {
        let interfaces = vec![vpn_interface()];
        let rules = vec![
            proto::RoutingRule {
                priority: 13000,
                has_uid_range: true,
                uid_range_start: 0,
                uid_range_end: 10399,
                table: 1051,
                ..Default::default()
            },
            proto::RoutingRule {
                priority: 13000,
                has_uid_range: true,
                uid_range_start: 10401,
                uid_range_end: 99999,
                table: 1051,
                ..Default::default()
            },
        ];
        let assessment = assess_vpn(
            &interfaces,
            &rules,
            &[1051],
            // 10400 sits in the gap between the two ranges.
            10400,
            &lookup_via(3),
            &lookup_via(3),
            None,
        );
        assert!(assessment.app_bypasses_vpn);
        assert!(
            assessment
                .bypass_reason
                .contains("falls outside all 2 uid range"),
            "unhelpful reason: {}",
            assessment.bypass_reason
        );
    }

    #[test]
    fn an_app_inside_a_vpn_uid_range_is_not_called_an_exclusion() {
        let interfaces = vec![vpn_interface()];
        let rules = vec![proto::RoutingRule {
            priority: 13000,
            has_uid_range: true,
            uid_range_start: 10000,
            uid_range_end: 19999,
            table: 1051,
            ..Default::default()
        }];
        let assessment = assess_vpn(
            &interfaces,
            &rules,
            &[1051],
            10400,
            &lookup_via(42),
            &lookup_via(42),
            None,
        );
        assert!(assessment.app_uses_vpn);
        assert!(assessment.bypass_reason.is_empty());
    }

    #[test]
    fn an_inverted_uid_rule_is_reported_as_the_bypass_reason() {
        let interfaces = vec![vpn_interface()];
        let rules = vec![proto::RoutingRule {
            priority: 16000,
            has_uid_range: true,
            uid_range_start: 10342,
            uid_range_end: 10342,
            invert: true,
            table: 1003,
            ..Default::default()
        }];
        let assessment = assess_vpn(
            &interfaces,
            &rules,
            &[1003],
            10342,
            &lookup_via(3),
            &lookup_via(3),
            None,
        );
        assert!(assessment.app_bypasses_vpn);
        assert!(assessment.bypass_reason.contains("excludes uids 10342"));
    }

    #[test]
    fn split_tunnel_is_detected_when_only_one_family_is_inside() {
        let interfaces = vec![vpn_interface()];
        let assessment = assess_vpn(
            &interfaces,
            &[],
            &[],
            10342,
            &lookup_via(42), // IPv4 inside the tunnel
            &lookup_via(3),  // IPv6 outside it
            None,
        );
        assert!(assessment.split_tunnel);
        assert!(!assessment.ipv6_inside_vpn);
    }

    #[test]
    fn framework_and_kernel_vpn_disagreement_is_flagged() {
        let interfaces = vec![vpn_interface()];
        let android = proto::AndroidNetworkState {
            networks: vec![proto::AndroidNetwork {
                net_id: 102,
                transports: vec![proto::Transport::Vpn as i32],
                capabilities: Some(proto::NetworkCapabilitiesInfo {
                    vpn_uid_ranges: vec![proto::UidRange {
                        start: 10000,
                        stop: 19999,
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        // The framework puts this uid inside the VPN; the kernel routes it out
        // of a different interface.
        let assessment = assess_vpn(
            &interfaces,
            &[],
            &[],
            10342,
            &lookup_via(3),
            &lookup_via(3),
            Some(&android),
        );
        assert!(assessment.framework_says_in_vpn);
        assert!(!assessment.app_uses_vpn);
        assert!(assessment.disagreement);
    }

    #[test]
    fn summary_reads_as_a_sentence() {
        let app = proto::AppRef {
            package_name: "org.mozilla.firefox".to_string(),
            uid: 10342,
            ..Default::default()
        };
        let summary = build_summary(
            &app,
            "wlan0",
            "",
            &proto::SocketSummary {
                total: 14,
                established: 12,
                syn_sent: 2,
                ..Default::default()
            },
            &proto::VpnAssessment {
                vpn_present: true,
                vpn_interface: "tun0".to_string(),
                app_uses_vpn: false,
                ..Default::default()
            },
            true,
            false,
        );
        assert!(summary.contains("org.mozilla.firefox"));
        assert!(summary.contains("no IPv6 path"));
        assert!(summary.contains("bypasses tun0"));
        assert!(summary.contains("12 established"));
    }
}
