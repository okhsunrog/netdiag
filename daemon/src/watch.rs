//! Realtime network events.
//!
//! One netlink multicast socket feeds one broadcast channel that every
//! subscriber reads. Opening a socket per subscriber would work, but it would
//! also mean N copies of every event being parsed N times, and the daemon
//! would lose the single point where state transitions are computed.
//!
//! Some events are only meaningful as transitions rather than as raw
//! notifications. "An IPv6 address was removed" is noise ten times an hour on
//! a device using privacy addresses; "this interface no longer has any global
//! IPv6 address" is the thing a person actually wants on a timeline. That
//! distinction needs memory of the previous state, which is kept here.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use rtnetlink::MulticastGroup;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::collect::{neigh, routes};
use crate::proto;
use crate::util;

/// Buffer depth for the broadcast channel. A slow subscriber that falls this
/// far behind is disconnected by tokio with a Lagged error, which the session
/// reports rather than silently dropping events.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Groups we subscribe to. Everything the timeline needs and nothing else;
/// subscribing to TC or netconf would add a lot of traffic for no benefit.
const GROUPS: &[MulticastGroup] = &[
    MulticastGroup::Link,
    MulticastGroup::Ipv4Ifaddr,
    MulticastGroup::Ipv6Ifaddr,
    MulticastGroup::Ipv4Route,
    MulticastGroup::Ipv6Route,
    MulticastGroup::Ipv4Rule,
    MulticastGroup::Ipv6Rule,
    MulticastGroup::Neigh,
];

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<proto::NetworkEvent>,
    sequence: Arc<AtomicU64>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            sender,
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<proto::NetworkEvent> {
        self.sender.subscribe()
    }

    /// Stamp and publish. Timestamping here rather than at the call site keeps
    /// the sequence numbers strictly increasing in publication order.
    pub fn publish(&self, mut event: proto::NetworkEvent) {
        event.sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        event.unix_ms = util::now_unix_ms();
        event.monotonic_ns = util::monotonic_ns();
        // An error here only means nobody is listening yet.
        let _ = self.sender.send(event);
    }

    pub fn publish_daemon(&self, message: impl Into<String>) {
        self.publish(proto::NetworkEvent {
            source: proto::EventSource::Daemon as i32,
            severity: proto::EventSeverity::Info as i32,
            summary: message.into(),
            payload: None,
            ..Default::default()
        });
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Remembers enough of the previous state to turn notifications into
/// transitions.
#[derive(Default)]
struct StateCache {
    if_names: HashMap<u32, String>,
    if_mtu: HashMap<u32, u32>,
    /// Interfaces that currently have at least one global address per family.
    has_global_v4: HashSet<u32>,
    has_global_v6: HashSet<u32>,
    /// Addresses seen per interface, so the "last one removed" edge is exact.
    addresses: HashMap<u32, HashSet<String>>,
    neighbor_states: HashMap<(u32, String), proto::NeighborState>,
}

/// Start the kernel event monitor. Runs until the process exits.
pub async fn run(bus: EventBus) -> Result<()> {
    let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(GROUPS)
        .context("could not subscribe to netlink multicast groups")?;
    tokio::spawn(connection);

    let mut cache = StateCache::default();
    bus.publish_daemon("kernel event monitor started");

    while let Some((message, _addr)) = messages.next().await {
        let NetlinkPayload::InnerMessage(inner) = message.payload else {
            continue;
        };
        match translate(inner, &mut cache) {
            Ok(Some(event)) => bus.publish(event),
            Ok(None) => {}
            Err(e) => debug!("could not translate a netlink event: {e}"),
        }
    }

    warn!("the netlink multicast stream ended; no further kernel events will be reported");
    Ok(())
}

fn translate(
    message: RouteNetlinkMessage,
    cache: &mut StateCache,
) -> Result<Option<proto::NetworkEvent>> {
    use RouteNetlinkMessage as M;
    Ok(match message {
        M::NewLink(msg) => Some(link_event(&msg, true, cache)),
        M::DelLink(msg) => Some(link_event(&msg, false, cache)),
        M::NewAddress(msg) => address_event(&msg, true, cache),
        M::DelAddress(msg) => address_event(&msg, false, cache),
        M::NewRoute(msg) => Some(route_event(&msg, true, cache)),
        M::DelRoute(msg) => Some(route_event(&msg, false, cache)),
        M::NewRule(msg) => Some(rule_event(&msg, true)),
        M::DelRule(msg) => Some(rule_event(&msg, false)),
        M::NewNeighbour(msg) => neighbor_event(&msg, true, cache),
        M::DelNeighbour(msg) => neighbor_event(&msg, false, cache),
        _ => None,
    })
}

fn base_event(severity: proto::EventSeverity, summary: String) -> proto::NetworkEvent {
    proto::NetworkEvent {
        source: proto::EventSource::Kernel as i32,
        severity: severity as i32,
        summary,
        ..Default::default()
    }
}

fn link_event(
    msg: &netlink_packet_route::link::LinkMessage,
    added: bool,
    cache: &mut StateCache,
) -> proto::NetworkEvent {
    use netlink_packet_route::link::{LinkAttribute, LinkFlags};

    let index = msg.header.index;
    let mut name = cache.if_names.get(&index).cloned().unwrap_or_default();
    let mut mtu = 0u32;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = n.clone(),
            LinkAttribute::Mtu(m) => mtu = *m,
            _ => {}
        }
    }
    if name.is_empty() {
        name = format!("if{index}");
    }

    let up = msg.header.flags.contains(LinkFlags::Up);
    let running = msg.header.flags.contains(LinkFlags::Running);
    let previous_mtu = cache.if_mtu.get(&index).copied().unwrap_or(0);
    let mtu_changed = mtu != 0 && previous_mtu != 0 && mtu != previous_mtu;

    if added {
        cache.if_names.insert(index, name.clone());
        if mtu != 0 {
            cache.if_mtu.insert(index, mtu);
        }
    } else {
        cache.if_names.remove(&index);
        cache.if_mtu.remove(&index);
        cache.has_global_v4.remove(&index);
        cache.has_global_v6.remove(&index);
        cache.addresses.remove(&index);
    }

    let summary = if !added {
        format!("{name} removed")
    } else if mtu_changed {
        format!("{name} MTU {previous_mtu} -> {mtu}")
    } else if up && running {
        format!("{name} up")
    } else if up {
        format!("{name} up, no carrier")
    } else {
        format!("{name} down")
    };

    let severity = if !added || !up {
        proto::EventSeverity::Notice
    } else {
        proto::EventSeverity::Info
    };

    let mut event = base_event(severity, summary);
    event.payload = Some(proto::network_event::Payload::Link(proto::LinkEvent {
        added,
        interface: Some(proto::Interface {
            index,
            name,
            mtu,
            ..Default::default()
        }),
        went_up: added && up,
        went_down: added && !up,
        mtu_changed,
        previous_mtu,
    }));
    event
}

fn address_event(
    msg: &netlink_packet_route::address::AddressMessage,
    added: bool,
    cache: &mut StateCache,
) -> Option<proto::NetworkEvent> {
    use netlink_packet_route::address::{AddressAttribute, AddressScope};

    let index = msg.header.index;
    let name = cache
        .if_names
        .get(&index)
        .cloned()
        .unwrap_or_else(|| format!("if{index}"));

    let mut ip: Option<IpAddr> = None;
    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Local(a) => ip = Some(*a),
            AddressAttribute::Address(a) if ip.is_none() => ip = Some(*a),
            _ => {}
        }
    }
    let ip = ip?;
    let text = format!("{ip}/{}", msg.header.prefix_len);
    let is_global = msg.header.scope == AddressScope::Universe;
    let family = if ip.is_ipv4() {
        proto::IpFamily::V4
    } else {
        proto::IpFamily::V6
    };

    // Track which addresses exist so "family lost" fires exactly once, on the
    // removal of the last global address of that family.
    let entry = cache.addresses.entry(index).or_default();
    if added {
        entry.insert(text.clone());
    } else {
        entry.remove(&text);
    }

    let set = match family {
        proto::IpFamily::V6 => &mut cache.has_global_v6,
        _ => &mut cache.has_global_v4,
    };
    let had = set.contains(&index);
    let has_now = if !is_global {
        had
    } else if added {
        set.insert(index);
        true
    } else {
        // Recompute from the tracked set rather than assuming this was the
        // only one.
        let any_left = cache
            .addresses
            .get(&index)
            .map(|addrs| {
                addrs.iter().any(|a| {
                    a.split('/')
                        .next()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .map(|parsed| parsed.is_ipv6() == (family == proto::IpFamily::V6))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        let set = match family {
            proto::IpFamily::V6 => &mut cache.has_global_v6,
            _ => &mut cache.has_global_v4,
        };
        if !any_left {
            set.remove(&index);
        }
        any_left
    };

    let gained = !had && has_now;
    let lost = had && !has_now;

    let family_name = if family == proto::IpFamily::V6 {
        "IPv6"
    } else {
        "IPv4"
    };
    let summary = if gained {
        format!("{name} gained {family_name} ({text})")
    } else if lost {
        format!("{name} lost {family_name} (last global address {text} removed)")
    } else if added {
        format!("{name} address added {text}")
    } else {
        format!("{name} address removed {text}")
    };

    let severity = if lost {
        proto::EventSeverity::Warning
    } else if gained {
        proto::EventSeverity::Notice
    } else {
        proto::EventSeverity::Debug
    };

    let mut event = base_event(severity, summary);
    event.payload = Some(proto::network_event::Payload::Address(
        proto::AddressEvent {
            added,
            interface_index: index,
            interface_name: name,
            address: Some(proto::LinkAddress {
                prefix: Some(proto::IpPrefix::new(ip, msg.header.prefix_len)),
                scope: if is_global {
                    proto::AddressScope::Global as i32
                } else {
                    proto::AddressScope::Unspecified as i32
                },
                ..Default::default()
            }),
            family_gained: gained,
            family_lost: lost,
            family: family as i32,
        },
    ));
    Some(event)
}

fn route_event(
    msg: &netlink_packet_route::route::RouteMessage,
    added: bool,
    cache: &mut StateCache,
) -> proto::NetworkEvent {
    let route = routes::route_to_proto(msg, &cache.if_names);
    let hop = route.next_hops.first().cloned().unwrap_or_default();
    let destination = route
        .destination
        .as_ref()
        .map(|d| {
            if route.is_default {
                "default".to_string()
            } else {
                d.display()
            }
        })
        .unwrap_or_else(|| "?".to_string());

    let via = hop
        .gateway
        .as_ref()
        .map(|g| format!(" via {}", g.display()))
        .unwrap_or_default();
    let dev = if hop.out_interface_name.is_empty() {
        String::new()
    } else {
        format!(" dev {}", hop.out_interface_name)
    };

    let verb = if added { "added" } else { "removed" };
    let summary = format!(
        "route {verb}: {destination}{via}{dev} table {}",
        route.table
    );

    let severity = if route.is_default {
        proto::EventSeverity::Notice
    } else {
        proto::EventSeverity::Debug
    };

    let mut event = base_event(severity, summary);
    event.payload = Some(proto::network_event::Payload::Route(proto::RouteEvent {
        added,
        default_route_changed: route.is_default,
        route: Some(route),
    }));
    event
}

fn rule_event(msg: &netlink_packet_route::rule::RuleMessage, added: bool) -> proto::NetworkEvent {
    let rule = routes::rule_to_proto(msg);
    let verb = if added { "added" } else { "removed" };
    let selector = if rule.has_uid_range {
        format!(" uidrange {}-{}", rule.uid_range_start, rule.uid_range_end)
    } else if rule.has_fwmark {
        format!(" fwmark 0x{:x}/0x{:x}", rule.fwmark, rule.fwmask)
    } else {
        String::new()
    };

    let summary = format!(
        "rule {verb}: priority {}{selector} lookup {}",
        rule.priority, rule.table
    );

    let mut event = base_event(proto::EventSeverity::Notice, summary);
    event.payload = Some(proto::network_event::Payload::Rule(proto::RuleEvent {
        added,
        rule: Some(rule),
    }));
    event
}

fn neighbor_event(
    msg: &netlink_packet_route::neighbour::NeighbourMessage,
    added: bool,
    cache: &mut StateCache,
) -> Option<proto::NetworkEvent> {
    let neighbor = neigh::neighbor_to_proto(msg, &cache.if_names);
    let address = neighbor.address.as_ref()?.display();
    let state = proto::NeighborState::try_from(neighbor.state).ok()?;
    let key = (neighbor.interface_index, address.clone());
    let previous = cache
        .neighbor_states
        .insert(key.clone(), state)
        .unwrap_or(proto::NeighborState::Unspecified);
    if !added {
        cache.neighbor_states.remove(&key);
    }

    // Neighbour churn is by far the noisiest group. Only transitions that
    // change whether the neighbour is usable are worth a timeline entry.
    let was_usable = neigh::is_usable(previous);
    let is_usable = neigh::is_usable(state);
    if added && was_usable == is_usable && previous != proto::NeighborState::Unspecified {
        return None;
    }

    let name = if neighbor.interface_name.is_empty() {
        format!("if{}", neighbor.interface_index)
    } else {
        neighbor.interface_name.clone()
    };

    let summary = if !added {
        format!("neighbour {address} removed on {name}")
    } else if is_usable {
        format!("neighbour {address} reachable on {name}")
    } else {
        format!("neighbour {address} is {state:?} on {name}")
    };

    let severity = if added && !is_usable {
        proto::EventSeverity::Warning
    } else {
        proto::EventSeverity::Info
    };

    let is_gateway = neighbor.is_router;
    let mut event = base_event(severity, summary);
    event.payload = Some(proto::network_event::Payload::Neighbor(
        proto::NeighborEvent {
            added,
            neighbor: Some(neighbor),
            previous_state: previous as i32,
            is_gateway,
        },
    ));
    Some(event)
}

/// Does an event pass a subscription's filter?
pub fn matches_filter(event: &proto::NetworkEvent, filter: &proto::EventFilter) -> bool {
    use proto::network_event::Payload;

    if event.severity < filter.min_severity {
        return false;
    }

    // An all-false filter means "everything", which is what a client that sent
    // no filter at all gets.
    let nothing_selected = !filter.links
        && !filter.addresses
        && !filter.routes
        && !filter.rules
        && !filter.neighbors
        && !filter.sockets;

    match &event.payload {
        Some(Payload::Link(_)) => nothing_selected || filter.links,
        Some(Payload::Address(_)) => nothing_selected || filter.addresses,
        Some(Payload::Route(_)) => nothing_selected || filter.routes,
        Some(Payload::Rule(_)) => nothing_selected || filter.rules,
        Some(Payload::Neighbor(e)) => {
            if !(nothing_selected || filter.neighbors) {
                return false;
            }
            if filter.exclude_neighbor_probe_noise {
                let state = e
                    .neighbor
                    .as_ref()
                    .and_then(|n| proto::NeighborState::try_from(n.state).ok())
                    .unwrap_or(proto::NeighborState::Unspecified);
                if matches!(
                    state,
                    proto::NeighborState::Probe | proto::NeighborState::Delay
                ) {
                    return false;
                }
            }
            true
        }
        Some(Payload::Socket(e)) => {
            if !(nothing_selected || filter.sockets) {
                return false;
            }
            if filter.socket_uids.is_empty() {
                return true;
            }
            e.socket
                .as_ref()
                .map(|s| filter.socket_uids.contains(&s.uid))
                .unwrap_or(false)
        }
        // Framework and daemon events are always delivered: they are low
        // volume and they are what makes the timeline cross-layer.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with(payload: proto::network_event::Payload) -> proto::NetworkEvent {
        proto::NetworkEvent {
            payload: Some(payload),
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_filter_accepts_everything() {
        let filter = proto::EventFilter::default();
        assert!(matches_filter(
            &event_with(proto::network_event::Payload::Link(Default::default())),
            &filter
        ));
        assert!(matches_filter(
            &event_with(proto::network_event::Payload::Route(Default::default())),
            &filter
        ));
    }

    #[test]
    fn selecting_one_class_excludes_the_others() {
        let filter = proto::EventFilter {
            routes: true,
            ..Default::default()
        };
        assert!(matches_filter(
            &event_with(proto::network_event::Payload::Route(Default::default())),
            &filter
        ));
        assert!(!matches_filter(
            &event_with(proto::network_event::Payload::Link(Default::default())),
            &filter
        ));
    }

    #[test]
    fn daemon_events_always_pass() {
        let filter = proto::EventFilter {
            routes: true,
            ..Default::default()
        };
        assert!(matches_filter(
            &event_with(proto::network_event::Payload::Daemon(Default::default())),
            &filter
        ));
    }

    #[test]
    fn neighbour_probe_noise_can_be_excluded() {
        let filter = proto::EventFilter {
            neighbors: true,
            exclude_neighbor_probe_noise: true,
            ..Default::default()
        };
        let probing = event_with(proto::network_event::Payload::Neighbor(
            proto::NeighborEvent {
                neighbor: Some(proto::Neighbor {
                    state: proto::NeighborState::Probe as i32,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ));
        assert!(!matches_filter(&probing, &filter));

        let failed = event_with(proto::network_event::Payload::Neighbor(
            proto::NeighborEvent {
                neighbor: Some(proto::Neighbor {
                    state: proto::NeighborState::Failed as i32,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ));
        assert!(matches_filter(&failed, &filter));
    }

    #[test]
    fn socket_events_can_be_narrowed_to_uids() {
        let filter = proto::EventFilter {
            sockets: true,
            socket_uids: vec![10342],
            ..Default::default()
        };
        let mine = event_with(proto::network_event::Payload::Socket(proto::SocketEvent {
            socket: Some(proto::Socket {
                uid: 10342,
                ..Default::default()
            }),
            ..Default::default()
        }));
        let theirs = event_with(proto::network_event::Payload::Socket(proto::SocketEvent {
            socket: Some(proto::Socket {
                uid: 10999,
                ..Default::default()
            }),
            ..Default::default()
        }));
        assert!(matches_filter(&mine, &filter));
        assert!(!matches_filter(&theirs, &filter));
    }

    #[test]
    fn severity_floor_is_applied() {
        let filter = proto::EventFilter {
            min_severity: proto::EventSeverity::Warning as i32,
            ..Default::default()
        };
        let debug = proto::NetworkEvent {
            severity: proto::EventSeverity::Debug as i32,
            payload: Some(proto::network_event::Payload::Address(Default::default())),
            ..Default::default()
        };
        let warning = proto::NetworkEvent {
            severity: proto::EventSeverity::Warning as i32,
            payload: Some(proto::network_event::Payload::Address(Default::default())),
            ..Default::default()
        };
        assert!(!matches_filter(&debug, &filter));
        assert!(matches_filter(&warning, &filter));
    }

    #[tokio::test]
    async fn the_bus_stamps_sequence_numbers_in_order() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        bus.publish_daemon("first");
        bus.publish_daemon("second");

        let a = rx.recv().await.unwrap();
        let b = rx.recv().await.unwrap();
        assert_eq!(a.summary, "first");
        assert_eq!(b.summary, "second");
        assert!(b.sequence > a.sequence);
        assert!(b.monotonic_ns >= a.monotonic_ns);
    }
}
