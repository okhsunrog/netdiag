//! Routes and policy-routing rules (RTM_GETROUTE / RTM_GETRULE), plus the
//! kernel-authoritative route lookup that answers "where would this packet
//! actually go for this uid?".

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow};
use futures::TryStreamExt;
use netlink_packet_core::{NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::AddressFamily;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteMetric, RouteScope,
    RouteType,
};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

use crate::proto;
use crate::util;

// RTM_GETROUTE. Not re-exported by netlink-packet-route in a form we can use
// directly for a hand-built request, so it is named here.
const RTM_GETROUTE: u16 = 26;

pub struct RouteDump {
    pub routes: Vec<proto::Route>,
    pub table_names: HashMap<u32, String>,
}

pub async fn get_routes(
    handle: &Handle,
    family: proto::IpFamily,
    table: u32,
    only_default: bool,
    interface_index: u32,
    if_names: &HashMap<u32, String>,
) -> Result<RouteDump> {
    let mut routes = Vec::new();

    let versions: &[IpVersion] = match family {
        proto::IpFamily::V4 => &[IpVersion::V4],
        proto::IpFamily::V6 => &[IpVersion::V6],
        proto::IpFamily::Unspecified => &[IpVersion::V4, IpVersion::V6],
    };

    for version in versions {
        // An empty message of the right family is a dump request for that
        // family's whole table set.
        let dump_all = match version {
            IpVersion::V4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
            IpVersion::V6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
        };
        let mut stream = handle.route().get(dump_all).execute();
        while let Some(msg) = stream
            .try_next()
            .await
            .context("RTM_GETROUTE dump failed")?
        {
            let route = route_to_proto(&msg, if_names);
            if table != 0 && route.table != table {
                continue;
            }
            if only_default && !route.is_default {
                continue;
            }
            if interface_index != 0
                && !route
                    .next_hops
                    .iter()
                    .any(|nh| nh.out_interface_index == interface_index)
            {
                continue;
            }
            routes.push(route);
        }
    }

    // Sort the way `ip route` conceptually does: table, then most specific
    // prefix first, then metric.
    routes.sort_by(|a, b| {
        a.table
            .cmp(&b.table)
            .then(
                b.destination
                    .as_ref()
                    .map(|d| d.prefix_len)
                    .unwrap_or(0)
                    .cmp(&a.destination.as_ref().map(|d| d.prefix_len).unwrap_or(0)),
            )
            .then(a.priority.cmp(&b.priority))
    });

    let mut table_names = HashMap::new();
    for r in &routes {
        if !r.table_name.is_empty() {
            table_names.insert(r.table, r.table_name.clone());
        }
    }

    Ok(RouteDump {
        routes,
        table_names,
    })
}

pub fn route_to_proto(msg: &RouteMessage, if_names: &HashMap<u32, String>) -> proto::Route {
    let family = match msg.header.address_family {
        AddressFamily::Inet => proto::IpFamily::V4,
        AddressFamily::Inet6 => proto::IpFamily::V6,
        _ => proto::IpFamily::Unspecified,
    };

    // The table id in the header is only 8 bits; anything above 255 (which is
    // every Android per-network table) arrives in RTA_TABLE instead.
    let mut table = msg.header.table as u32;
    let mut destination: Option<IpAddr> = None;
    let mut preferred_source: Option<IpAddr> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut oif: u32 = 0;
    let mut priority: u32 = 0;
    let mut metrics = proto::RouteMetrics::default();
    let mut expires = 0u32;
    let mut multipath: Vec<proto::NextHop> = Vec::new();

    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Destination(a) => destination = route_address_to_ip(a),
            RouteAttribute::PrefSource(a) => preferred_source = route_address_to_ip(a),
            RouteAttribute::Gateway(a) => gateway = route_address_to_ip(a),
            RouteAttribute::Oif(i) => oif = *i,
            RouteAttribute::Priority(p) => priority = *p,
            RouteAttribute::Expires(e) => expires = *e,
            RouteAttribute::CacheInfo(ci) => {
                if ci.expires != 0 {
                    expires = ci.expires;
                }
            }
            RouteAttribute::Metrics(ms) => {
                for m in ms {
                    match m {
                        RouteMetric::Mtu(v) => metrics.mtu = *v,
                        RouteMetric::Lock(v) => {
                            // RTAX_MTU is bit 2 of the lock mask.
                            metrics.mtu_locked = v & (1 << 2) != 0;
                        }
                        RouteMetric::Advmss(v) => metrics.advmss = *v,
                        RouteMetric::Window(v) => metrics.window = *v,
                        RouteMetric::Hoplimit(v) => metrics.hoplimit = *v,
                        RouteMetric::InitCwnd(v) => metrics.initcwnd = *v,
                        RouteMetric::InitRwnd(v) => metrics.initrwnd = *v,
                        RouteMetric::Rtt(v) => metrics.rtt_ms = *v,
                        _ => {}
                    }
                }
            }
            RouteAttribute::MultiPath(hops) => {
                for hop in hops {
                    let mut gw = None;
                    for a in &hop.attributes {
                        if let RouteAttribute::Gateway(g) = a {
                            gw = route_address_to_ip(g);
                        }
                    }
                    multipath.push(proto::NextHop {
                        gateway: gw.map(proto::IpAddress::from_ip),
                        out_interface_index: hop.interface_index,
                        out_interface_name: if_names
                            .get(&hop.interface_index)
                            .cloned()
                            .unwrap_or_default(),
                        weight: hop.hops as u32 + 1,
                        flags: hop.flags.bits() as u32,
                    });
                }
            }
            _ => {}
        }
    }

    let next_hops = if multipath.is_empty() {
        vec![proto::NextHop {
            gateway: gateway.map(proto::IpAddress::from_ip),
            out_interface_index: oif,
            out_interface_name: if_names.get(&oif).cloned().unwrap_or_default(),
            weight: 1,
            flags: 0,
        }]
    } else {
        multipath
    };

    let prefix_len = msg.header.destination_prefix_length;
    let is_default = prefix_len == 0 && destination.is_none();

    let destination = Some(match destination {
        Some(ip) => proto::IpPrefix::new(ip, prefix_len),
        None => proto::IpPrefix {
            address: None,
            prefix_len: prefix_len as u32,
        },
    });

    proto::Route {
        family: family as i32,
        destination,
        preferred_source: preferred_source.map(proto::IpAddress::from_ip),
        table,
        table_name: table_name(table),
        protocol: route_protocol_to_proto(&msg.header.protocol) as i32,
        protocol_raw: u8::from(msg.header.protocol) as u32,
        scope: route_scope_to_proto(&msg.header.scope) as i32,
        r#type: route_type_to_proto(&msg.header.kind) as i32,
        priority,
        next_hops,
        metrics: Some(metrics),
        flags: msg.header.flags.bits(),
        expires_sec: expires,
        is_default,
    }
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(a) => Some(IpAddr::V4(*a)),
        RouteAddress::Inet6(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/// Table names. Android keeps no rt_tables file, so well-known ids are named
/// from netd's fixed allocations and per-network tables are labelled with the
/// netId they belong to.
pub fn table_name(table: u32) -> String {
    if let Some(name) = util::well_known_table_name(table) {
        return name.to_string();
    }
    // netd allocates per-Network tables starting at 1000 on some releases and
    // at the netId itself on others; either way the id is the useful label.
    format!("net{table}")
}

fn route_protocol_to_proto(p: &netlink_packet_route::route::RouteProtocol) -> proto::RouteProtocol {
    use netlink_packet_route::route::RouteProtocol as K;
    use proto::RouteProtocol as P;
    match p {
        K::IcmpRedirect => P::Redirect,
        K::Kernel => P::Kernel,
        K::Boot => P::Boot,
        K::Static => P::Static,
        K::Ra => P::Ra,
        K::Dhcp => P::Dhcp,
        K::Unspec => P::Unspecified,
        _ => P::Other,
    }
}

fn route_scope_to_proto(s: &RouteScope) -> proto::RouteScope {
    use proto::RouteScope as P;
    match s {
        RouteScope::Universe => P::Universe,
        RouteScope::Site => P::Site,
        RouteScope::Link => P::Link,
        RouteScope::Host => P::Host,
        RouteScope::NoWhere => P::Nowhere,
        _ => P::Unspecified,
    }
}

fn route_type_to_proto(t: &RouteType) -> proto::RouteType {
    use proto::RouteType as P;
    match t {
        RouteType::Unicast => P::Unicast,
        RouteType::Local => P::Local,
        RouteType::Broadcast => P::Broadcast,
        RouteType::Anycast => P::Anycast,
        RouteType::Multicast => P::Multicast,
        RouteType::BlackHole => P::Blackhole,
        RouteType::Unreachable => P::Unreachable,
        RouteType::Prohibit => P::Prohibit,
        RouteType::Throw => P::Throw,
        RouteType::Nat => P::Nat,
        _ => P::Unspecified,
    }
}

// ---- Rules ------------------------------------------------------------------

pub async fn get_rules(
    handle: &Handle,
    family: proto::IpFamily,
    uid_filter: Option<u32>,
) -> Result<Vec<proto::RoutingRule>> {
    let versions: &[IpVersion] = match family {
        proto::IpFamily::V4 => &[IpVersion::V4],
        proto::IpFamily::V6 => &[IpVersion::V6],
        proto::IpFamily::Unspecified => &[IpVersion::V4, IpVersion::V6],
    };

    let mut rules = Vec::new();
    for version in versions {
        let mut stream = handle.rule().get(version.clone()).execute();
        while let Some(msg) = stream.try_next().await.context("RTM_GETRULE dump failed")? {
            let rule = rule_to_proto(&msg);
            if let Some(uid) = uid_filter
                && !rule_can_match_uid(&rule, uid)
            {
                continue;
            }
            rules.push(rule);
        }
    }

    // Rules are evaluated in ascending priority order; show them that way.
    rules.sort_by_key(|r| (r.family, r.priority));
    Ok(rules)
}

pub fn rule_to_proto(msg: &RuleMessage) -> proto::RoutingRule {
    let family = match msg.header.family {
        AddressFamily::Inet => proto::IpFamily::V4,
        AddressFamily::Inet6 => proto::IpFamily::V6,
        _ => proto::IpFamily::Unspecified,
    };

    let mut rule = proto::RoutingRule {
        family: family as i32,
        table: msg.header.table as u32,
        action: rule_action_to_proto(&msg.header.action) as i32,
        tos: msg.header.tos as u32,
        invert: msg.header.flags.contains(RuleFlags::Invert),
        ..Default::default()
    };

    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Priority(p) => rule.priority = *p,
            RuleAttribute::Table(t) => rule.table = *t,
            RuleAttribute::FwMark(m) => {
                rule.fwmark = *m;
                rule.has_fwmark = true;
            }
            RuleAttribute::FwMask(m) => rule.fwmask = *m,
            RuleAttribute::Iifname(n) => rule.input_interface = n.clone(),
            RuleAttribute::Oifname(n) => rule.output_interface = n.clone(),
            RuleAttribute::Source(a) => {
                rule.source = Some(proto::IpPrefix::new(*a, msg.header.src_len));
            }
            RuleAttribute::Destination(a) => {
                rule.destination = Some(proto::IpPrefix::new(*a, msg.header.dst_len));
            }
            RuleAttribute::UidRange(r) => {
                rule.uid_range_start = r.start;
                rule.uid_range_end = r.end;
                rule.has_uid_range = true;
            }
            RuleAttribute::SuppressPrefixLen(v) => {
                rule.suppress_prefix_len = *v;
                rule.has_suppress_prefix_len = true;
            }
            RuleAttribute::SuppressIfGroup(v) => {
                rule.suppress_interface_group = *v;
                rule.has_suppress_interface_group = true;
            }
            RuleAttribute::Protocol(p) => rule.protocol = u8::from(*p) as u32,
            RuleAttribute::Goto(g) => rule.table = *g,
            _ => {}
        }
    }

    rule.table_name = table_name(rule.table);
    rule
}

fn rule_action_to_proto(a: &RuleAction) -> proto::RuleAction {
    use proto::RuleAction as P;
    match a {
        RuleAction::ToTable => P::ToTable,
        RuleAction::Goto => P::Goto,
        RuleAction::Nop => P::Nop,
        RuleAction::Blackhole => P::Blackhole,
        RuleAction::Unreachable => P::Unreachable,
        RuleAction::Prohibit => P::Prohibit,
        _ => P::Unspecified,
    }
}

/// Whether a rule's uid selector can apply to `uid`. A rule with no uid range
/// applies to everyone, which is why the default is `true`.
pub fn rule_can_match_uid(rule: &proto::RoutingRule, uid: u32) -> bool {
    if !rule.has_uid_range {
        return true;
    }
    let in_range = uid >= rule.uid_range_start && uid <= rule.uid_range_end;
    if rule.invert { !in_range } else { in_range }
}

// ---- Kernel route lookup ----------------------------------------------------

/// Ask the kernel to run the full policy-routing pipeline for one packet.
///
/// This is `ip route get`: RTM_GETROUTE without NLM_F_DUMP, with
/// RTM_F_LOOKUP_TABLE set so the reply reports which table the lookup landed
/// in. Passing RTA_UID makes the kernel evaluate Android's per-uid rules, so
/// the answer is the real decision for that app rather than our own
/// reimplementation of rule matching.
pub async fn route_lookup(
    handle: &Handle,
    destination: IpAddr,
    source_hint: Option<IpAddr>,
    uid: Option<u32>,
    fwmark: Option<u32>,
    out_interface_index: u32,
    if_names: &HashMap<u32, String>,
) -> proto::RouteLookup {
    let mut lookup = proto::RouteLookup {
        destination: Some(proto::IpAddress::from_ip(destination)),
        source_hint: source_hint.map(proto::IpAddress::from_ip),
        uid: uid.unwrap_or(0),
        fwmark: fwmark.unwrap_or(0),
        out_interface_index,
        ..Default::default()
    };

    match do_route_lookup(
        handle,
        destination,
        source_hint,
        uid,
        fwmark,
        out_interface_index,
    )
    .await
    {
        Ok(msg) => {
            let route = route_to_proto(&msg, if_names);
            lookup.table = route.table;
            lookup.route = Some(route);
        }
        Err(e) => {
            // The kernel's own words ("Network is unreachable") are the useful
            // part; wrapping them in a generic phrase only buries them.
            lookup.error = Some(
                proto::Error::kernel(e.to_string())
                    .with_detail(format!("RTM_GETROUTE to {destination}")),
            );
        }
    }

    lookup
}

async fn do_route_lookup(
    handle: &Handle,
    destination: IpAddr,
    source_hint: Option<IpAddr>,
    uid: Option<u32>,
    fwmark: Option<u32>,
    out_interface_index: u32,
) -> Result<RouteMessage> {
    let mut route = RouteMessage::default();
    route.header.address_family = match destination {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    route.header.destination_prefix_length = match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    route.header.table = RouteHeader::RT_TABLE_UNSPEC;
    route.header.flags = RouteFlags::LookupTable;

    route
        .attributes
        .push(RouteAttribute::Destination(match destination {
            IpAddr::V4(a) => RouteAddress::Inet(a),
            IpAddr::V6(a) => RouteAddress::Inet6(a),
        }));
    if let Some(src) = source_hint {
        route.header.source_prefix_length = match src {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        route.attributes.push(RouteAttribute::Source(match src {
            IpAddr::V4(a) => RouteAddress::Inet(a),
            IpAddr::V6(a) => RouteAddress::Inet6(a),
        }));
    }
    if let Some(uid) = uid {
        route.attributes.push(RouteAttribute::Uid(uid));
    }
    if let Some(mark) = fwmark {
        route.attributes.push(RouteAttribute::Mark(mark));
    }
    if out_interface_index != 0 {
        route
            .attributes
            .push(RouteAttribute::Oif(out_interface_index));
    }

    let mut header = NetlinkHeader::default();
    header.message_type = RTM_GETROUTE;
    header.flags = NLM_F_REQUEST;
    let mut request = NetlinkMessage::new(
        header,
        NetlinkPayload::from(RouteNetlinkMessage::GetRoute(route)),
    );
    request.finalize();

    let mut handle = handle.clone();
    let mut response = handle
        .request(request)
        .map_err(|e| anyhow!("failed to send RTM_GETROUTE: {e}"))?;

    use futures::StreamExt;
    while let Some(message) = response.next().await {
        match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                return Ok(route);
            }
            NetlinkPayload::Error(err) => {
                return Err(anyhow!("{}", err));
            }
            _ => {}
        }
    }
    Err(anyhow!("kernel returned no route for {destination}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_with_uid_range(start: u32, end: u32, invert: bool) -> proto::RoutingRule {
        proto::RoutingRule {
            has_uid_range: true,
            uid_range_start: start,
            uid_range_end: end,
            invert,
            ..Default::default()
        }
    }

    #[test]
    fn rule_without_uid_range_matches_everyone() {
        let rule = proto::RoutingRule::default();
        assert!(rule_can_match_uid(&rule, 10342));
        assert!(rule_can_match_uid(&rule, 0));
    }

    #[test]
    fn uid_range_is_inclusive_at_both_ends() {
        let rule = rule_with_uid_range(10000, 10999, false);
        assert!(rule_can_match_uid(&rule, 10000));
        assert!(rule_can_match_uid(&rule, 10999));
        assert!(!rule_can_match_uid(&rule, 9999));
        assert!(!rule_can_match_uid(&rule, 11000));
    }

    #[test]
    fn inverted_uid_range_excludes_the_range() {
        // This is how an app is carved out of a VPN.
        let rule = rule_with_uid_range(10342, 10342, true);
        assert!(!rule_can_match_uid(&rule, 10342));
        assert!(rule_can_match_uid(&rule, 10343));
    }

    #[test]
    fn names_well_known_tables() {
        assert_eq!(table_name(254), "main");
        assert_eq!(table_name(255), "local");
        assert_eq!(table_name(1003), "vpn_fallthrough");
        assert_eq!(table_name(101), "net101");
    }
}
