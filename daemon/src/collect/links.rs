//! Interfaces and addresses from NETLINK_ROUTE (RTM_GETLINK / RTM_GETADDR).

use std::collections::HashMap;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressScope};
use netlink_packet_route::link::{
    InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, State,
};
use rtnetlink::Handle;

use crate::proto;
use crate::util;

/// Dump every interface with its addresses and the sysctls that explain its
/// IPv6 behaviour.
pub async fn get_interfaces(
    handle: &Handle,
    include_stats: bool,
    include_sysctls: bool,
) -> Result<Vec<proto::Interface>> {
    let mut by_index: HashMap<u32, proto::Interface> = HashMap::new();

    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await.context("RTM_GETLINK dump failed")? {
        let iface = link_to_proto(&msg, include_stats);
        by_index.insert(iface.index, iface);
    }

    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs.try_next().await.context("RTM_GETADDR dump failed")? {
        let index = msg.header.index;
        let Some(iface) = by_index.get_mut(&index) else {
            continue;
        };
        if let Some(addr) = address_to_proto(&msg) {
            iface.addresses.push(addr);
        }
    }

    let mut out: Vec<proto::Interface> = by_index.into_values().collect();
    out.sort_by_key(|i| i.index);

    if include_sysctls {
        for iface in &mut out {
            iface.sysctls = Some(read_interface_sysctls(&iface.name));
        }
    }

    Ok(out)
}

fn link_to_proto(
    msg: &netlink_packet_route::link::LinkMessage,
    include_stats: bool,
) -> proto::Interface {
    let mut iface = proto::Interface {
        index: msg.header.index,
        flags: Some(link_flags_to_proto(msg.header.flags)),
        netns_id: -1,
        ..Default::default()
    };

    let mut info_kind: Option<String> = None;

    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(name) => iface.name = name.clone(),
            LinkAttribute::IfAlias(alias) => iface.alias = alias.clone(),
            LinkAttribute::Mtu(mtu) => iface.mtu = *mtu,
            LinkAttribute::Address(mac) => iface.mac_address = mac.clone(),
            LinkAttribute::Broadcast(b) => iface.broadcast_address = b.clone(),
            LinkAttribute::TxQueueLen(len) => iface.tx_queue_len = *len,
            LinkAttribute::Qdisc(q) => iface.qdisc = q.clone(),
            LinkAttribute::Link(idx) => iface.link_index = *idx,
            LinkAttribute::Controller(idx) => iface.master_index = *idx,
            LinkAttribute::Group(g) => iface.group = *g,
            LinkAttribute::LinkNetNsId(id) => iface.netns_id = *id,
            LinkAttribute::OperState(state) => {
                iface.oper_state = oper_state_to_proto(state) as i32;
            }
            LinkAttribute::Xdp(x) => iface.has_xdp = !x.is_empty(),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Kind(kind) = info {
                        info_kind = Some(info_kind_name(kind));
                    }
                }
            }
            LinkAttribute::Stats64(stats) if include_stats => {
                iface.stats = Some(proto::LinkStats {
                    rx_packets: stats.rx_packets,
                    tx_packets: stats.tx_packets,
                    rx_bytes: stats.rx_bytes,
                    tx_bytes: stats.tx_bytes,
                    rx_errors: stats.rx_errors,
                    tx_errors: stats.tx_errors,
                    rx_dropped: stats.rx_dropped,
                    tx_dropped: stats.tx_dropped,
                });
            }
            _ => {}
        }
    }

    iface.link_type = info_kind.clone().unwrap_or_default();
    iface.kind = classify_link(
        &iface.name,
        msg.header.link_layer_type,
        info_kind.as_deref(),
        msg.header.flags,
    ) as i32;
    iface
}

/// Android does not label interfaces for us, so the kind is inferred from the
/// ARPHRD type, the kernel's link kind, and the naming conventions the platform
/// has used consistently for years.
fn classify_link(
    name: &str,
    ll_type: LinkLayerType,
    info_kind: Option<&str>,
    flags: LinkFlags,
) -> proto::LinkKind {
    use proto::LinkKind;

    if flags.contains(LinkFlags::Loopback) || ll_type == LinkLayerType::Loopback {
        return LinkKind::Loopback;
    }
    // A v4-<iface> device is clatd's 464XLAT translation interface. Check this
    // before the tun check: clat is implemented as a tun device but means
    // something much more specific.
    if name.starts_with("v4-") {
        return LinkKind::Clat;
    }
    match info_kind {
        Some("tun") | Some("wireguard") | Some("ppp") | Some("ipip") | Some("ip6tnl") => {
            return LinkKind::VpnTun;
        }
        Some("bridge") => return LinkKind::Bridge,
        Some("dummy") => return LinkKind::Dummy,
        _ => {}
    }
    if ll_type == LinkLayerType::Ieee80211 || name.starts_with("wlan") || name.starts_with("ap_") {
        return LinkKind::Wifi;
    }
    // rmnet_data*/rmnet*/ccmni*/pdp* are the cellular data interfaces on
    // Qualcomm, MediaTek and Exynos modems respectively.
    if name.starts_with("rmnet")
        || name.starts_with("ccmni")
        || name.starts_with("pdp")
        || name.starts_with("seth")
        || name.starts_with("wwan")
        || ll_type == LinkLayerType::Rawip
    {
        return LinkKind::Cellular;
    }
    if name.starts_with("tun") || name.starts_with("tap") || name.starts_with("ppp") {
        return LinkKind::VpnTun;
    }
    if name.starts_with("bt-") || name.starts_with("bnep") {
        return LinkKind::Bluetooth;
    }
    if ll_type == LinkLayerType::Ether {
        return LinkKind::Ethernet;
    }
    LinkKind::Other
}

fn info_kind_name(kind: &InfoKind) -> String {
    match kind {
        InfoKind::Other(s) => s.clone(),
        other => format!("{other:?}").to_lowercase(),
    }
}

fn link_flags_to_proto(flags: LinkFlags) -> proto::LinkFlags {
    proto::LinkFlags {
        up: flags.contains(LinkFlags::Up),
        running: flags.contains(LinkFlags::Running),
        loopback: flags.contains(LinkFlags::Loopback),
        point_to_point: flags.contains(LinkFlags::Pointopoint),
        broadcast: flags.contains(LinkFlags::Broadcast),
        multicast: flags.contains(LinkFlags::Multicast),
        no_arp: flags.contains(LinkFlags::Noarp),
        promisc: flags.contains(LinkFlags::Promisc),
        lower_up: flags.contains(LinkFlags::LowerUp),
        dormant: flags.contains(LinkFlags::Dormant),
        raw: flags.bits(),
    }
}

fn oper_state_to_proto(state: &State) -> proto::OperState {
    use proto::OperState as P;
    match state {
        State::Unknown => P::Unknown,
        State::NotPresent => P::NotPresent,
        State::Down => P::Down,
        State::LowerLayerDown => P::LowerLayerDown,
        State::Testing => P::Testing,
        State::Dormant => P::Dormant,
        State::Up => P::Up,
        _ => P::Unspecified,
    }
}

fn address_to_proto(
    msg: &netlink_packet_route::address::AddressMessage,
) -> Option<proto::LinkAddress> {
    let mut address: Option<std::net::IpAddr> = None;
    let mut local: Option<std::net::IpAddr> = None;
    let mut label = String::new();
    let mut broadcast = None;
    let mut flags = AddressFlags::from_bits_retain(msg.header.flags.bits() as u32);
    let mut valid = 0u32;
    let mut preferred = 0u32;

    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Address(a) => address = Some(*a),
            AddressAttribute::Local(a) => local = Some(*a),
            AddressAttribute::Label(l) => label = l.clone(),
            AddressAttribute::Broadcast(b) => {
                broadcast = Some(proto::IpAddress::from_ip(std::net::IpAddr::V4(*b)));
            }
            AddressAttribute::Flags(f) => flags = *f,
            AddressAttribute::CacheInfo(ci) => {
                valid = ci.ifa_valid;
                preferred = ci.ifa_preferred;
            }
            _ => {}
        }
    }

    // On point-to-point links IFA_LOCAL is the address of this end and
    // IFA_ADDRESS is the peer's; everywhere else they are the same.
    let ip = local.or(address)?;

    Some(proto::LinkAddress {
        prefix: Some(proto::IpPrefix::new(ip, msg.header.prefix_len)),
        scope: scope_to_proto(&msg.header.scope) as i32,
        flags: Some(proto::AddressFlags {
            permanent: flags.contains(AddressFlags::Permanent),
            temporary: flags.contains(AddressFlags::Secondary),
            deprecated: flags.contains(AddressFlags::Deprecated),
            tentative: flags.contains(AddressFlags::Tentative),
            dadfailed: flags.contains(AddressFlags::Dadfailed),
            managed_temp: flags.contains(AddressFlags::Managetempaddr),
            no_prefix_route: flags.contains(AddressFlags::Noprefixroute),
            optimistic: flags.contains(AddressFlags::Optimistic),
            home: flags.contains(AddressFlags::Homeaddress),
            stable_privacy: flags.contains(AddressFlags::StablePrivacy),
            raw: flags.bits(),
        }),
        valid_lifetime_sec: valid,
        preferred_lifetime_sec: preferred,
        label,
        broadcast,
    })
}

fn scope_to_proto(scope: &AddressScope) -> proto::AddressScope {
    use proto::AddressScope as P;
    match scope {
        AddressScope::Universe => P::Global,
        AddressScope::Site => P::Site,
        AddressScope::Link => P::Link,
        AddressScope::Host => P::Host,
        AddressScope::Nowhere => P::Nowhere,
        _ => P::Unspecified,
    }
}

/// Per-interface sysctls. `disable_ipv6` and `accept_ra` in particular explain
/// a large share of "IPv6 is configured but does not work" reports.
pub fn read_interface_sysctls(name: &str) -> proto::InterfaceSysctls {
    let v6 = |key: &str| format!("/proc/sys/net/ipv6/conf/{name}/{key}");
    let v4 = |key: &str| format!("/proc/sys/net/ipv4/conf/{name}/{key}");

    proto::InterfaceSysctls {
        ipv6_disabled: util::read_i32(v6("disable_ipv6")).unwrap_or(0) != 0,
        accept_ra: util::read_i32(v6("accept_ra")).unwrap_or(-1),
        accept_ra_defrtr: util::read_i32(v6("accept_ra_defrtr")).unwrap_or(-1),
        accept_ra_rt_info_max_plen: util::read_i32(v6("accept_ra_rt_info_max_plen")).unwrap_or(-1),
        autoconf: util::read_i32(v6("autoconf")).unwrap_or(-1),
        use_tempaddr: util::read_i32(v6("use_tempaddr")).unwrap_or(-1),
        forwarding_v4: util::read_i32(v4("forwarding")).unwrap_or(-1),
        forwarding_v6: util::read_i32(v6("forwarding")).unwrap_or(-1),
        rp_filter: util::read_i32(v4("rp_filter")).unwrap_or(-1),
        arp_ignore: util::read_i32(v4("arp_ignore")).unwrap_or(-1),
        dad_transmits: util::read_i32(v6("dad_transmits")).unwrap_or(-1),
        mtu_v6: util::read_i32(v6("mtu")).unwrap_or(-1),
        hop_limit: util::read_i32(v6("hop_limit")).unwrap_or(-1),
    }
}

/// Helper used all over the diagnosis code: does this interface have a global
/// (routable) address of the given family?
pub fn has_global_address(iface: &proto::Interface, family: proto::IpFamily) -> bool {
    iface.addresses.iter().any(|a| {
        let Some(prefix) = &a.prefix else {
            return false;
        };
        let Some(ip) = prefix.ip() else { return false };
        let matches_family = match family {
            proto::IpFamily::V4 => ip.is_ipv4(),
            proto::IpFamily::V6 => ip.is_ipv6(),
            proto::IpFamily::Unspecified => true,
        };
        matches_family
            && a.scope == proto::AddressScope::Global as i32
            && !a
                .flags
                .as_ref()
                .map(|f| f.tentative || f.dadfailed)
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_android_interface_names() {
        use proto::LinkKind;
        let none = LinkFlags::empty();
        assert_eq!(
            classify_link("wlan0", LinkLayerType::Ether, None, none),
            LinkKind::Wifi
        );
        assert_eq!(
            classify_link("rmnet_data0", LinkLayerType::Rawip, None, none),
            LinkKind::Cellular
        );
        assert_eq!(
            classify_link("tun0", LinkLayerType::None, Some("tun"), none),
            LinkKind::VpnTun
        );
        assert_eq!(
            classify_link("lo", LinkLayerType::Loopback, None, LinkFlags::Loopback),
            LinkKind::Loopback
        );
    }

    #[test]
    fn clat_wins_over_tun() {
        // clatd's interface is a tun device, but calling it a VPN would be
        // actively misleading in the UI.
        assert_eq!(
            classify_link(
                "v4-rmnet_data0",
                LinkLayerType::None,
                Some("tun"),
                LinkFlags::empty()
            ),
            proto::LinkKind::Clat
        );
    }
}
