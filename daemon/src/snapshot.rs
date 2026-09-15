//! One consistent-ish capture of every layer at once.
//!
//! "Consistent-ish" is deliberate: there is no way to freeze the kernel's
//! networking state across several netlink dumps, so a snapshot taken during a
//! Wi-Fi to cellular handover can contain routes for an interface that has
//! already gone. Rather than pretend otherwise, collection is ordered so the
//! most stable things come first, the elapsed time is recorded, and anything
//! that failed is listed in `collection_warnings` instead of being silently
//! dropped.

use anyhow::Result;
use rtnetlink::Handle;
use tracing::warn;

use crate::collect::{self, firewall, links, neigh, procnet, routes, sockets};
use crate::proto;
use crate::util::{self, Stopwatch};

pub async fn collect_snapshot(
    handle: &Handle,
    request: &proto::GetSnapshotRequest,
) -> Result<proto::Snapshot> {
    let clock = Stopwatch::start();
    let mut warnings: Vec<String> = Vec::new();

    let interfaces = links::get_interfaces(handle, true, request.include_sysctls).await?;
    let if_names = collect::interface_names(&interfaces);

    let route_dump =
        routes::get_routes(handle, proto::IpFamily::Unspecified, 0, false, 0, &if_names).await?;

    let rules = routes::get_rules(handle, proto::IpFamily::Unspecified, None)
        .await
        .unwrap_or_else(|e| {
            warnings.push(format!("routing rules unavailable: {e}"));
            Vec::new()
        });

    let neighbors = if request.include_neighbors {
        neigh::get_neighbors(handle, proto::IpFamily::Unspecified, 0, false, &if_names)
            .await
            .unwrap_or_else(|e| {
                warnings.push(format!("neighbour table unavailable: {e}"));
                Vec::new()
            })
    } else {
        Vec::new()
    };

    let (socket_list, socket_summary) = if request.include_sockets {
        let filter = proto::SocketFilter {
            include_tcp_info: request.include_socket_tcp_info,
            ..Default::default()
        };
        match sockets::get_sockets(&filter, &if_names).await {
            Ok(dump) => {
                if dump.truncated {
                    warnings.push(
                        "the socket list was truncated at the daemon's row limit".to_string(),
                    );
                }
                (dump.sockets, Some(dump.summary))
            }
            Err(e) => {
                warnings.push(format!("socket diagnostics unavailable: {e}"));
                (Vec::new(), None)
            }
        }
    } else {
        (Vec::new(), None)
    };

    let firewall_state = if request.include_firewall {
        Some(firewall::collect(true).await)
    } else {
        None
    };

    let qdiscs = if request.include_qdiscs {
        collect_qdiscs(handle, &if_names).await.unwrap_or_else(|e| {
            warnings.push(format!("qdisc dump unavailable: {e}"));
            Vec::new()
        })
    } else {
        Vec::new()
    };

    let clat = procnet::detect_clat(&interfaces);

    Ok(proto::Snapshot {
        captured_at_unix_ms: util::now_unix_ms(),
        kernel_release: util::kernel_release(),
        table_names: route_dump.table_names.clone(),
        routes: route_dump.routes,
        rules,
        neighbors,
        sockets: socket_list,
        socket_summary,
        sysctls: if request.include_sysctls {
            Some(procnet::read_global_sysctls())
        } else {
            None
        },
        counters: if request.include_counters {
            Some(procnet::read_counters())
        } else {
            None
        },
        firewall: firewall_state,
        qdiscs,
        namespaces: procnet::read_namespaces(),
        resolver: Some(procnet::read_resolver_state()),
        clat: Some(clat),
        android_state: request.android_state.clone(),
        collection_duration_ms: clock.elapsed_ms(),
        collection_warnings: warnings,
        interfaces,
    })
}

/// Queueing disciplines. Mostly informational, but a qdisc with a large drop
/// count is a real explanation for loss that looks like a network problem.
async fn collect_qdiscs(
    handle: &Handle,
    if_names: &std::collections::HashMap<u32, String>,
) -> Result<Vec<proto::Qdisc>> {
    use futures::TryStreamExt;
    use netlink_packet_route::tc::{TcAttribute, TcStats2};

    let mut out = Vec::new();
    let mut stream = handle.qdisc().get().execute();

    while let Some(msg) = stream.try_next().await? {
        let index = msg.header.index as u32;
        let mut qdisc = proto::Qdisc {
            interface_index: index,
            interface_name: if_names.get(&index).cloned().unwrap_or_default(),
            handle: msg.header.handle.into(),
            parent: msg.header.parent.into(),
            ..Default::default()
        };

        for attr in &msg.attributes {
            match attr {
                TcAttribute::Kind(kind) => qdisc.kind = kind.clone(),
                TcAttribute::Stats2(stats) => {
                    for stat in stats {
                        match stat {
                            TcStats2::Basic(basic) => {
                                qdisc.bytes_sent = basic.bytes;
                                qdisc.packets_sent = basic.packets as u64;
                            }
                            TcStats2::Queue(queue) => {
                                qdisc.drops = queue.drops as u64;
                                qdisc.overlimits = queue.overlimits as u64;
                                qdisc.requeues = queue.requeues as u64;
                                qdisc.backlog_bytes = queue.backlog;
                                qdisc.backlog_packets = queue.qlen;
                            }
                            _ => {}
                        }
                    }
                }
                TcAttribute::Stats(stats) => {
                    if qdisc.bytes_sent == 0 {
                        qdisc.bytes_sent = stats.bytes;
                        qdisc.packets_sent = stats.packets as u64;
                    }
                    if qdisc.drops == 0 {
                        qdisc.drops = stats.drops as u64;
                        qdisc.overlimits = stats.overlimits as u64;
                    }
                }
                _ => {}
            }
        }

        if qdisc.kind.is_empty() {
            warn!("qdisc on interface {index} has no kind attribute; skipping");
            continue;
        }
        out.push(qdisc);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_request_defaults_to_the_cheap_fields() {
        // Everything expensive is opt-in, so an empty request stays fast.
        let request = proto::GetSnapshotRequest::default();
        assert!(!request.include_sockets);
        assert!(!request.include_firewall);
        assert!(!request.include_counters);
    }
}
