//! Neighbour table (ARP for IPv4, NDP for IPv6) from RTM_GETNEIGH.
//!
//! A default gateway sitting in FAILED or INCOMPLETE is one of the clearest
//! signals that the link is up but the next hop is gone, which the framework's
//! VALIDATED bit can lag behind by tens of seconds.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::Handle;

use crate::proto;

pub async fn get_neighbors(
    handle: &Handle,
    family: proto::IpFamily,
    interface_index: u32,
    only_routers: bool,
    if_names: &HashMap<u32, String>,
) -> Result<Vec<proto::Neighbor>> {
    let families: &[AddressFamily] = match family {
        proto::IpFamily::V4 => &[AddressFamily::Inet],
        proto::IpFamily::V6 => &[AddressFamily::Inet6],
        proto::IpFamily::Unspecified => &[AddressFamily::Inet, AddressFamily::Inet6],
    };

    let mut out = Vec::new();
    for address_family in families {
        let mut stream = handle
            .neighbours()
            .get()
            .set_address_family(*address_family)
            .execute();
        while let Some(msg) = stream
            .try_next()
            .await
            .context("RTM_GETNEIGH dump failed")?
        {
            let n = neighbor_to_proto(&msg, if_names);
            if interface_index != 0 && n.interface_index != interface_index {
                continue;
            }
            if only_routers && !n.is_router {
                continue;
            }
            out.push(n);
        }
    }

    out.sort_by(|a, b| {
        a.interface_index.cmp(&b.interface_index).then(
            a.address
                .as_ref()
                .map(|x| x.addr.clone())
                .cmp(&b.address.as_ref().map(|x| x.addr.clone())),
        )
    });
    Ok(out)
}

pub fn neighbor_to_proto(
    msg: &NeighbourMessage,
    if_names: &HashMap<u32, String>,
) -> proto::Neighbor {
    let family = match msg.header.family {
        AddressFamily::Inet => proto::IpFamily::V4,
        AddressFamily::Inet6 => proto::IpFamily::V6,
        _ => proto::IpFamily::Unspecified,
    };

    let mut n = proto::Neighbor {
        family: family as i32,
        interface_index: msg.header.ifindex,
        interface_name: if_names
            .get(&msg.header.ifindex)
            .cloned()
            .unwrap_or_default(),
        state: neighbour_state_to_proto(&msg.header.state) as i32,
        is_router: msg.header.flags.contains(NeighbourFlags::Router),
        flags: msg.header.flags.bits() as u32,
        ..Default::default()
    };

    for attr in &msg.attributes {
        match attr {
            NeighbourAttribute::Destination(addr) => {
                let ip = match addr {
                    NeighbourAddress::Inet(a) => Some(IpAddr::V4(*a)),
                    NeighbourAddress::Inet6(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                };
                n.address = ip.map(proto::IpAddress::from_ip);
            }
            NeighbourAttribute::LinkLayerAddress(mac) => n.link_address = mac.clone(),
            NeighbourAttribute::Probes(p) => n.probes = *p,
            NeighbourAttribute::CacheInfo(ci) => {
                // The kernel reports these in units of 1/100 s (USER_HZ).
                n.confirmed_ms = ci.confirmed.saturating_mul(10);
                n.used_ms = ci.used.saturating_mul(10);
                n.updated_ms = ci.updated.saturating_mul(10);
            }
            _ => {}
        }
    }

    n
}

fn neighbour_state_to_proto(s: &NeighbourState) -> proto::NeighborState {
    use proto::NeighborState as P;
    match s {
        NeighbourState::Incomplete => P::Incomplete,
        NeighbourState::Reachable => P::Reachable,
        NeighbourState::Stale => P::Stale,
        NeighbourState::Delay => P::Delay,
        NeighbourState::Probe => P::Probe,
        NeighbourState::Failed => P::Failed,
        NeighbourState::Noarp => P::Noarp,
        NeighbourState::Permanent => P::Permanent,
        NeighbourState::None => P::None,
        _ => P::Unspecified,
    }
}

/// Is this neighbour entry usable for forwarding right now? STALE counts: the
/// kernel will revalidate it on first use without dropping traffic.
pub fn is_usable(state: proto::NeighborState) -> bool {
    matches!(
        state,
        proto::NeighborState::Reachable
            | proto::NeighborState::Stale
            | proto::NeighborState::Delay
            | proto::NeighborState::Probe
            | proto::NeighborState::Permanent
            | proto::NeighborState::Noarp
    )
}

/// Find the neighbour entry for a gateway address, if the kernel has one.
pub fn find_gateway(
    neighbors: &[proto::Neighbor],
    gateway: IpAddr,
    interface_index: u32,
) -> Option<&proto::Neighbor> {
    neighbors.iter().find(|n| {
        n.address.as_ref().and_then(|a| a.to_ip()) == Some(gateway)
            && (interface_index == 0 || n.interface_index == interface_index)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_entries_still_forward() {
        assert!(is_usable(proto::NeighborState::Stale));
        assert!(is_usable(proto::NeighborState::Reachable));
    }

    #[test]
    fn failed_and_incomplete_do_not_forward() {
        assert!(!is_usable(proto::NeighborState::Failed));
        assert!(!is_usable(proto::NeighborState::Incomplete));
    }
}
