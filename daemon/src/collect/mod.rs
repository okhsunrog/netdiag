//! Collectors that turn kernel state into the protobuf types.
//!
//! Everything here reads; nothing here changes the device's configuration. The
//! daemon is a diagnostic tool and deliberately has no code path that installs
//! a route, brings an interface up, or flushes a table.

pub mod firewall;
pub mod links;
pub mod neigh;
pub mod procnet;
pub mod routes;
pub mod sockets;

use std::collections::HashMap;

use crate::proto;

/// index -> name map, needed by nearly every other collector to turn the
/// kernel's interface indexes into something a human can read.
pub fn interface_names(interfaces: &[proto::Interface]) -> HashMap<u32, String> {
    interfaces
        .iter()
        .map(|i| (i.index, i.name.clone()))
        .collect()
}
