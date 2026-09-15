//! Building the UI's view models from daemon responses.

use netdiag_ipc::proto;

use crate::format::*;
use crate::ui;

// ---- Overview ---------------------------------------------------------------

pub fn overview(snapshot: &proto::Snapshot) -> ui::OverviewData {
    let android = snapshot.android_state.as_ref();
    let active = android.and_then(|state| {
        state
            .networks
            .iter()
            .find(|network| network.net_id == state.active_net_id)
            .or_else(|| state.networks.iter().find(|network| network.is_default))
    });

    let caps = active.and_then(|n| n.capabilities.clone()).unwrap_or_default();
    let link = active
        .and_then(|n| n.link_properties.clone())
        .unwrap_or_default();

    let transports: Vec<String> = active
        .map(|n| {
            n.transports
                .iter()
                .filter_map(|t| proto::Transport::try_from(*t).ok())
                .map(|t| transport_label(t).to_string())
                .collect()
        })
        .unwrap_or_default();

    let mut chips = Vec::new();
    if active.is_some() {
        chips.push(chip(
            if caps.validated { "VALIDATED" } else { "NOT VALIDATED" },
            if caps.validated {
                ui::Status::Pass
            } else {
                ui::Status::Warn
            },
        ));
        chips.push(chip(
            if caps.not_metered { "UNMETERED" } else { "METERED" },
            if caps.not_metered {
                ui::Status::Pass
            } else {
                ui::Status::Info
            },
        ));
        if caps.captive_portal {
            chips.push(chip("PORTAL", ui::Status::Fail));
        }
        if active
            .map(|n| n.transports.contains(&(proto::Transport::Vpn as i32)))
            .unwrap_or(false)
        {
            chips.push(chip("VPN", ui::Status::Info));
        }
        if caps.internet {
            chips.push(chip("INTERNET", ui::Status::Pass));
        }
    } else {
        chips.push(chip("NO FRAMEWORK STATE", ui::Status::Skip));
    }

    let other_networks: Vec<slint::SharedString> = android
        .map(|state| {
            state
                .networks
                .iter()
                .filter(|n| Some(n.net_id) != active.map(|a| a.net_id))
                .map(|n| {
                    let transports: Vec<&str> = n
                        .transports
                        .iter()
                        .filter_map(|t| proto::Transport::try_from(*t).ok())
                        .map(transport_label)
                        .collect();
                    shared(format!(
                        "netId {}  {}  {}",
                        n.net_id,
                        transports.join("+"),
                        n.link_properties
                            .as_ref()
                            .map(|lp| lp.interface_name.clone())
                            .unwrap_or_default()
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let default_routes: Vec<slint::SharedString> = snapshot
        .routes
        .iter()
        .filter(|r| r.is_default)
        .map(|r| shared(format!("{} table {}", route_line(r), r.table)))
        .collect();

    let sockets_line = snapshot
        .socket_summary
        .as_ref()
        .map(|s| format!("{} total, {} established", s.total, s.established))
        .unwrap_or_default();

    let clat_line = snapshot
        .clat
        .as_ref()
        .filter(|c| c.active)
        .map(|c| format!("active on {} over {}", c.clat_interface, c.base_interface))
        .unwrap_or_default();

    ui::OverviewData {
        connected: true,
        transport: shared(if transports.is_empty() {
            "—".to_string()
        } else {
            transports.join(" + ")
        }),
        interface_name: shared(if link.interface_name.is_empty() {
            "—".to_string()
        } else {
            link.interface_name.clone()
        }),
        net_id: shared(
            active
                .map(|n| n.net_id.to_string())
                .unwrap_or_else(|| "—".to_string()),
        ),
        dns: shared(
            link.dns_servers
                .iter()
                .map(ip)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        mtu: shared(if link.mtu > 0 {
            link.mtu.to_string()
        } else {
            String::new()
        }),
        framework_chips: model(chips),
        other_networks: model(other_networks),
        default_routes: model(if default_routes.is_empty() {
            vec![shared("no default route in any table")]
        } else {
            default_routes
        }),
        sockets_line: shared(sockets_line),
        clat_line: shared(clat_line),
        kernel_release: shared(snapshot.kernel_release.clone()),
        collection: shared(format!(
            "{} ms · {} routes · {} rules · {} sockets",
            snapshot.collection_duration_ms,
            snapshot.routes.len(),
            snapshot.rules.len(),
            snapshot.sockets.len()
        )),
        warnings: model(
            snapshot
                .collection_warnings
                .iter()
                .map(shared)
                .collect::<Vec<_>>(),
        ),
    }
}

pub fn interfaces(snapshot: &proto::Snapshot) -> Vec<ui::InterfaceRow> {
    let mut rows: Vec<&proto::Interface> = snapshot.interfaces.iter().collect();
    // Interfaces that are down are almost always the platform's dozens of
    // pre-created rmnet devices; showing them first would bury the two or
    // three that matter.
    rows.sort_by_key(|i| {
        let up = i.flags.as_ref().map(|f| f.up).unwrap_or(false);
        (!up, usize::MAX - i.addresses.len(), i.index)
    });

    rows.into_iter()
        .map(|iface| {
            let flags = iface.flags.clone().unwrap_or_default();
            let kind = proto::LinkKind::try_from(iface.kind).unwrap_or(proto::LinkKind::Unspecified);

            let mut chips = vec![chip(
                if flags.up { "UP" } else { "DOWN" },
                if flags.up {
                    ui::Status::Pass
                } else {
                    ui::Status::Skip
                },
            )];
            if flags.up && !flags.running {
                chips.push(chip("NO CARRIER", ui::Status::Warn));
            }
            if let Some(sysctls) = &iface.sysctls
                && sysctls.ipv6_disabled
            {
                chips.push(chip("IPv6 OFF", ui::Status::Fail));
            }

            let addresses = iface
                .addresses
                .iter()
                .filter_map(|a| a.prefix.as_ref().map(prefix))
                .collect::<Vec<_>>()
                .join("  ");

            let mut fields = Vec::new();
            if let Some(stats) = &iface.stats {
                fields.push(field("rx", bytes(stats.rx_bytes)));
                fields.push(field("tx", bytes(stats.tx_bytes)));
                if stats.rx_dropped > 0 || stats.tx_dropped > 0 {
                    fields.push(field_status(
                        "dropped",
                        format!("rx {} / tx {}", stats.rx_dropped, stats.tx_dropped),
                        ui::Status::Warn,
                    ));
                }
            }
            if let Some(sysctls) = &iface.sysctls {
                if sysctls.ipv6_disabled {
                    fields.push(field_status(
                        "disable_ipv6",
                        "1 — IPv6 is off on this interface",
                        ui::Status::Fail,
                    ));
                }
                fields.push(field("accept_ra", sysctls.accept_ra.to_string()));
            }
            if !iface.mac_address.is_empty() {
                fields.push(field(
                    "mac",
                    iface
                        .mac_address
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                ));
            }

            ui::InterfaceRow {
                name: shared(iface.name.clone()),
                subtitle: shared(format!(
                    "{} · index {} · MTU {}",
                    link_kind_label(kind),
                    iface.index,
                    iface.mtu
                )),
                addresses: shared(if addresses.is_empty() {
                    "no addresses".to_string()
                } else {
                    addresses
                }),
                chips: model(chips),
                fields: model(fields),
                expanded: false,
            }
        })
        .collect()
}

// ---- Routing ----------------------------------------------------------------

pub fn rules(snapshot: &proto::Snapshot, limit: usize) -> Vec<slint::SharedString> {
    snapshot
        .rules
        .iter()
        // Android installs hundreds of per-uid rules; the ones that define the
        // overall policy are the ones with a selector.
        .filter(|r| r.has_uid_range || r.has_fwmark)
        .take(limit)
        .map(|r| shared(rule_line(r)))
        .collect()
}

pub fn route_tables(snapshot: &proto::Snapshot) -> Vec<ui::RouteTableRow> {
    let mut tables: Vec<u32> = snapshot.routes.iter().map(|r| r.table).collect();
    tables.sort_unstable();
    tables.dedup();

    tables
        .into_iter()
        .map(|table| {
            let routes: Vec<&proto::Route> = snapshot
                .routes
                .iter()
                .filter(|r| r.table == table)
                .collect();
            let name = snapshot.table_names.get(&table).cloned().unwrap_or_default();
            let defaults = routes.iter().filter(|r| r.is_default).count();

            ui::RouteTableRow {
                title: shared(if name.is_empty() {
                    format!("Table {table}")
                } else {
                    format!("Table {table} ({name})")
                }),
                subtitle: shared(format!(
                    "{} routes{}",
                    routes.len(),
                    if defaults > 0 {
                        format!(", {defaults} default")
                    } else {
                        String::new()
                    }
                )),
                lines: model(
                    routes
                        .iter()
                        .take(24)
                        .map(|r| shared(route_line(r)))
                        .collect::<Vec<_>>(),
                ),
            }
        })
        .collect()
}

// ---- Diagnosis --------------------------------------------------------------

pub fn check_row(check: &proto::Check) -> ui::CheckRow {
    let status = proto::CheckStatus::try_from(check.status).unwrap_or(proto::CheckStatus::Unspecified);

    let mut evidence: Vec<(String, String)> = check
        .evidence
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    evidence.sort_by(|a, b| a.0.cmp(&b.0));

    ui::CheckRow {
        key: shared(check.key.clone()),
        title: shared(if check.title.is_empty() {
            check.key.clone()
        } else {
            check.title.clone()
        }),
        detail: shared(check.detail.clone()),
        status: check_status(status),
        duration: shared(if check.duration_ms > 0 {
            format!("{} ms", check.duration_ms)
        } else {
            String::new()
        }),
        evidence: model(
            evidence
                .into_iter()
                .map(|(k, v)| field(&k, v))
                .collect::<Vec<_>>(),
        ),
        expanded: false,
    }
}

pub fn finding_row(finding: &proto::Finding) -> ui::FindingRow {
    let severity =
        proto::FindingSeverity::try_from(finding.severity).unwrap_or(proto::FindingSeverity::Unspecified);

    ui::FindingRow {
        key: shared(finding.key.clone()),
        title: shared(finding.title.clone()),
        severity: shared(severity_label(severity)),
        status: severity_status(severity),
        confidence: finding.confidence as i32,
        // The interpretation is written as prose with blank lines between
        // paragraphs; preserving them is what makes it readable.
        paragraphs: model(
            finding
                .interpretation
                .split("\n\n")
                .map(|p| shared(p.replace('\n', " ").trim().to_string()))
                .collect::<Vec<_>>(),
        ),
        actions: model(
            finding
                .suggested_actions
                .iter()
                .map(shared)
                .collect::<Vec<_>>(),
        ),
        based_on: shared(format!(
            "based on: {}",
            finding.supporting_checks.join(", ")
        )),
    }
}

pub fn diagnosis(response: &proto::DiagnoseResponse) -> ui::DiagnosisData {
    let mut counts = vec![chip(format!("{} pass", response.passed), ui::Status::Pass)];
    if response.failed > 0 {
        counts.push(chip(format!("{} fail", response.failed), ui::Status::Fail));
    }
    if response.warned > 0 {
        counts.push(chip(format!("{} warn", response.warned), ui::Status::Warn));
    }
    if response.skipped > 0 {
        counts.push(chip(format!("{} skip", response.skipped), ui::Status::Skip));
    }

    ui::DiagnosisData {
        running: false,
        summary: shared(response.summary.clone()),
        counts: model(counts),
        checks: model(response.checks.iter().map(check_row).collect::<Vec<_>>()),
        findings: model(response.findings.iter().map(finding_row).collect::<Vec<_>>()),
    }
}

pub fn empty_diagnosis(running: bool) -> ui::DiagnosisData {
    ui::DiagnosisData {
        running,
        summary: shared(if running { "Running checks…" } else { "" }),
        counts: model(Vec::<ui::ChipData>::new()),
        checks: model(Vec::<ui::CheckRow>::new()),
        findings: model(Vec::<ui::FindingRow>::new()),
    }
}

// ---- Per-app ----------------------------------------------------------------

pub fn app_detail(state: &proto::AppNetworkState) -> ui::AppDetailData {
    let app = state.app.clone().unwrap_or_default();
    let routing = state.routing.clone().unwrap_or_default();
    let vpn = state.vpn.clone().unwrap_or_default();
    let summary = state.socket_summary.clone().unwrap_or_default();

    let chips = vec![
        chip(
            if state.ipv4_path_ok { "IPv4 OK" } else { "IPv4 FAILED" },
            if state.ipv4_path_ok {
                ui::Status::Pass
            } else {
                ui::Status::Fail
            },
        ),
        chip(
            if state.ipv6_path_ok { "IPv6 OK" } else { "IPv6 FAILED" },
            if state.ipv6_path_ok {
                ui::Status::Pass
            } else {
                ui::Status::Fail
            },
        ),
    ];

    let mut framework = Vec::new();
    if let Some(network) = &state.android_network {
        let caps = network.capabilities.clone().unwrap_or_default();
        let transports: Vec<&str> = network
            .transports
            .iter()
            .filter_map(|t| proto::Transport::try_from(*t).ok())
            .map(transport_label)
            .collect();
        framework.push(field_prose("Transport", transports.join(" + ")));
        framework.push(field(
            "Interface",
            network
                .link_properties
                .as_ref()
                .map(|lp| lp.interface_name.clone())
                .unwrap_or_else(|| "—".into()),
        ));
        framework.push(field("Network ID", network.net_id.to_string()));
        framework.push(field_status(
            "VALIDATED",
            if caps.validated { "yes" } else { "no" },
            if caps.validated {
                ui::Status::Pass
            } else {
                ui::Status::Warn
            },
        ));
    }

    let mut routing_fields = Vec::new();
    routing_fields.push(lookup_field("IPv4", routing.lookup_v4.as_ref(), &routing.egress_interface_v4, routing.table_v4));
    routing_fields.push(lookup_field("IPv6", routing.lookup_v6.as_ref(), &routing.egress_interface_v6, routing.table_v6));

    let mut vpn_fields = Vec::new();
    if vpn.vpn_present {
        vpn_fields.push(field("Interface", vpn.vpn_interface.clone()));
        vpn_fields.push(field_prose(
            "This app",
            if vpn.app_uses_vpn {
                "goes through the VPN"
            } else {
                "bypasses the VPN"
            },
        ));
        if !vpn.bypass_reason.is_empty() {
            vpn_fields.push(field_prose("Reason", vpn.bypass_reason.clone()));
        }
        if vpn.split_tunnel {
            vpn_fields.push(field_status(
                "Split tunnel",
                "one address family is inside the tunnel and the other is not",
                ui::Status::Warn,
            ));
        }
        if vpn.disagreement {
            vpn_fields.push(field_status(
                "Disagreement",
                format!(
                    "the framework says this app is {} the VPN, but the kernel routes it {} the tunnel",
                    if vpn.framework_says_in_vpn { "inside" } else { "outside" },
                    if vpn.app_uses_vpn { "into" } else { "around" }
                ),
                ui::Status::Fail,
            ));
        }
    }

    // The owner is already the heading of this screen, so the rows leave it
    // blank rather than repeating the package name on every line.
    let sockets: Vec<ui::SocketRow> = state
        .sockets
        .iter()
        .take(40)
        .map(|socket| socket_row(socket, String::new()))
        .collect();

    ui::AppDetailData {
        present: true,
        label: shared(if app.label.is_empty() {
            app.package_name.clone()
        } else {
            app.label.clone()
        }),
        package: shared(app.package_name.clone()),
        uid: app.uid as i32,
        summary: shared(state.summary.clone()),
        chips: model(chips),
        framework: model(framework),
        rules: model(
            routing
                .matching_rules
                .iter()
                .take(12)
                .map(|r| shared(rule_line(r)))
                .collect::<Vec<_>>(),
        ),
        routing: model(routing_fields),
        vpn_present: vpn.vpn_present,
        vpn_title: shared(format!("VPN · {}", vpn.vpn_interface)),
        vpn_chip: chip(
            if vpn.app_uses_vpn { "IN TUNNEL" } else { "BYPASSES" },
            if vpn.app_uses_vpn {
                ui::Status::Pass
            } else {
                ui::Status::Warn
            },
        ),
        vpn: model(vpn_fields),
        sockets: model(sockets),
        socket_summary: shared(format!(
            "{} open, {} established, {} in SYN_SENT",
            summary.total, summary.established, summary.syn_sent
        )),
        firewall: shared(state.firewall_note.clone()),
    }
}

fn lookup_field(
    family: &str,
    lookup: Option<&proto::RouteLookup>,
    egress: &str,
    table: u32,
) -> ui::Field {
    let Some(lookup) = lookup else {
        return field(family, "not looked up");
    };
    if let Some(error) = &lookup.error {
        return field_status(family, format!("no route: {}", error.message), ui::Status::Fail);
    }
    let Some(route) = &lookup.route else {
        return field(family, "not looked up");
    };
    let via = route
        .next_hops
        .first()
        .and_then(|h| h.gateway.as_ref())
        .filter(|g| !g.addr.is_empty())
        .map(ip)
        .unwrap_or_else(|| "on-link".to_string());
    field(
        family,
        format!(
            "table {table} via {via} dev {}",
            if egress.is_empty() { "—" } else { egress }
        ),
    )
}

pub fn empty_app_detail() -> ui::AppDetailData {
    ui::AppDetailData {
        present: false,
        label: shared(""),
        package: shared(""),
        uid: 0,
        summary: shared(""),
        chips: model(Vec::<ui::ChipData>::new()),
        framework: model(Vec::<ui::Field>::new()),
        rules: model(Vec::<slint::SharedString>::new()),
        routing: model(Vec::<ui::Field>::new()),
        vpn_present: false,
        vpn_title: shared(""),
        vpn_chip: chip("", ui::Status::Skip),
        vpn: model(Vec::<ui::Field>::new()),
        sockets: model(Vec::<ui::SocketRow>::new()),
        socket_summary: shared(""),
        firewall: shared(""),
    }
}

// ---- Timeline ---------------------------------------------------------------

pub fn event_row(event: &proto::NetworkEvent) -> ui::EventRow {
    let source = proto::EventSource::try_from(event.source).unwrap_or(proto::EventSource::Unspecified);
    let severity =
        proto::EventSeverity::try_from(event.severity).unwrap_or(proto::EventSeverity::Unspecified);

    ui::EventRow {
        time: shared(time_of_day(event.unix_ms)),
        source: shared(match source {
            proto::EventSource::Kernel => "KRNL",
            proto::EventSource::Framework => "FMWK",
            proto::EventSource::Daemon => "DMON",
            _ => "????",
        }),
        status: match severity {
            proto::EventSeverity::Warning => ui::Status::Fail,
            proto::EventSeverity::Notice => ui::Status::Warn,
            proto::EventSeverity::Info => ui::Status::Info,
            _ => ui::Status::Skip,
        },
        summary: shared(event.summary.clone()),
    }
}

pub fn empty_overview() -> ui::OverviewData {
    ui::OverviewData {
        connected: false,
        transport: shared("—"),
        interface_name: shared("—"),
        net_id: shared("—"),
        dns: shared(""),
        mtu: shared(""),
        framework_chips: model(Vec::<ui::ChipData>::new()),
        other_networks: model(Vec::<slint::SharedString>::new()),
        default_routes: model(Vec::<slint::SharedString>::new()),
        sockets_line: shared(""),
        clat_line: shared(""),
        kernel_release: shared(""),
        collection: shared(""),
        warnings: model(Vec::<slint::SharedString>::new()),
    }
}

// ---- Sockets ----------------------------------------------------------------

/// Which sockets the screen shows.
///
/// `app_uid_floor` comes from the platform: on Android everything below 10000
/// is the system, on a Linux desktop everything below 1000 is. Hard-coding
/// Android's value made the desktop harness hide every socket it had.
#[derive(Clone, Copy)]
pub struct SocketFilters {
    pub only_established: bool,
    pub only_apps: bool,
    pub hide_listen: bool,
    pub app_uid_floor: u32,
}

impl SocketFilters {
    fn keeps(&self, socket: &proto::Socket) -> bool {
        let state = proto::TcpState::try_from(socket.state).unwrap_or(proto::TcpState::Unspecified);
        if self.only_established && state != proto::TcpState::Established {
            return false;
        }
        if self.only_apps && socket.uid < self.app_uid_floor {
            return false;
        }
        if self.hide_listen && state == proto::TcpState::Listen {
            return false;
        }
        true
    }
}

/// Every socket on the device, grouped so the uid that owns it is what the eye
/// lands on first.
///
/// `owner` is resolved from the installed-app list rather than from the daemon:
/// the kernel knows the uid, and only the framework knows the name.
pub fn sockets(
    snapshot: &proto::Snapshot,
    filters: SocketFilters,
    owner_for_uid: &dyn Fn(u32) -> String,
) -> ui::SocketsData {
    let mut kept: Vec<&proto::Socket> = snapshot
        .sockets
        .iter()
        .filter(|socket| filters.keeps(socket))
        .collect();

    // By uid, then by state, so every socket of one app sits together.
    kept.sort_by(|a, b| a.uid.cmp(&b.uid).then_with(|| a.state.cmp(&b.state)));

    let total = snapshot.sockets.len();
    let shown = kept.len();
    let rows: Vec<ui::SocketRow> = kept
        .into_iter()
        .take(400)
        .map(|socket| socket_row(socket, owner_for_uid(socket.uid)))
        .collect();

    let summary = match snapshot.socket_summary.as_ref() {
        Some(s) => format!(
            "{} sockets · {} established · {} listening · {} time-wait",
            s.total, s.established, s.listen, s.time_wait
        ),
        None => format!("{total} sockets"),
    };

    let hidden = if shown == total {
        String::new()
    } else {
        format!("{} hidden by filters", total - shown)
    };

    ui::SocketsData {
        summary: shared(summary),
        hidden: shared(hidden),
        rows: model(rows),
    }
}

/// One socket row, shared by the sockets screen and the per-app detail.
pub fn socket_row(socket: &proto::Socket, owner: String) -> ui::SocketRow {
    let state = proto::TcpState::try_from(socket.state).unwrap_or(proto::TcpState::Unspecified);

    let mut meta = format!("uid {}", socket.uid);
    if socket.has_mark && socket.net_id != 0 {
        meta.push_str(&format!("  netId {}", socket.net_id));
    }
    if !socket.interface_name.is_empty() {
        meta.push_str(&format!("  {}", socket.interface_name));
    }
    // Retransmits are the cheapest signal that a socket is connected but the
    // path is not carrying its packets.
    if socket.retransmits != 0 {
        meta.push_str(&format!("  {} retx", socket.retransmits));
    }

    ui::SocketRow {
        state: shared(tcp_state_label(state)),
        status: socket_status(state),
        tuple: shared(socket_tuple(socket)),
        meta: shared(meta),
        owner: shared(owner),
    }
}

pub fn empty_sockets() -> ui::SocketsData {
    ui::SocketsData {
        summary: shared(""),
        hidden: shared(""),
        rows: model(Vec::<ui::SocketRow>::new()),
    }
}

// ---- Capture ----------------------------------------------------------------

/// One captured frame as a line a person can scan.
///
/// The daemon already decoded the headers into `PacketSummary`, so this does no
/// parsing: guessing at bytes in two places is how the two sides end up
/// disagreeing about what was on the wire.
pub fn packet_row(packet: &proto::CapturedPacket) -> ui::PacketRow {
    let summary = packet.summary.clone().unwrap_or_default();
    let arrow = if packet.outgoing { "→" } else { "←" };

    let decoded = match (summary.source.as_ref(), summary.destination.as_ref()) {
        (Some(source), Some(destination)) => {
            let port = |p: u32| if p == 0 { String::new() } else { format!(":{p}") };
            Some(format!(
                "{}{} {arrow} {}{}",
                ip(source),
                port(summary.source_port),
                ip(destination),
                port(summary.destination_port)
            ))
        }
        _ => None,
    };
    // A frame the daemon could not decode is still worth showing; it is
    // evidence that something unexpected is on the interface.
    let endpoints = decoded
        .clone()
        .unwrap_or_else(|| format!("{arrow} {} bytes", packet.original_length));

    let protocol = if summary.protocol_name.is_empty() {
        format!("ip proto {}", summary.ip_protocol)
    } else {
        summary.protocol_name.clone()
    };

    let mut detail = format!("{protocol}  {} B", packet.original_length);
    if packet.original_length as usize > packet.data.len() && !packet.data.is_empty() {
        detail.push_str(&format!(" (captured {})", packet.data.len()));
    }
    let flags: String = [
        (summary.syn, "SYN"),
        (summary.ack, "ACK"),
        (summary.fin, "FIN"),
        (summary.rst, "RST"),
        (summary.psh, "PSH"),
    ]
    .iter()
    .filter(|(set, _)| *set)
    .map(|(_, name)| *name)
    .collect::<Vec<_>>()
    .join(" ");
    if !flags.is_empty() {
        detail.push_str(&format!("  [{flags}]"));
    }
    // The daemon's description restates the endpoints it decoded, which the
    // line above already shows. It is only worth printing when this side could
    // not decode them — an ICMP error, say, where the description carries the
    // reason and there is nothing else to go on.
    if !summary.description.is_empty() && decoded.is_none() {
        detail.push_str(&format!("  {}", summary.description));
    }

    ui::PacketRow {
        time: shared(time_of_day(packet.unix_ms)),
        // An ICMP "fragmentation needed" or "packet too big" is the whole
        // reason this screen exists, so it is coloured as a finding.
        status: if summary.icmp_mtu != 0 {
            ui::Status::Fail
        } else if summary.rst {
            ui::Status::Warn
        } else {
            ui::Status::Skip
        },
        summary: shared(endpoints),
        detail: shared(detail),
    }
}

pub fn empty_capture() -> ui::CaptureData {
    ui::CaptureData {
        running: false,
        interface: shared(""),
        summary: shared(""),
        error: shared(""),
        saved_path: shared(""),
        packets: model(Vec::<ui::PacketRow>::new()),
    }
}
