//! TCP/UDP socket diagnostics over NETLINK_INET_DIAG.
//!
//! This is the only interface that gives, in one dump, the 4-tuple, the owning
//! uid, the socket's SO_MARK and `struct tcp_info`. /proc/net/tcp has neither
//! the mark nor tcp_info, and cannot be read for other uids on modern Android
//! anyway, so inet_diag is not merely a faster path here: it is the only one.
//!
//! The mark matters more than it looks. Android writes the netId of the
//! Network a socket is pinned to into the low 16 bits of the mark, so the mark
//! is the join key between "a socket in the kernel" and "a Network object in
//! the framework".

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::{
    AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, SockDiagMessage,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags, Timer, nlas::Nla},
};
use netlink_sys::{
    AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket, protocols::NETLINK_SOCK_DIAG,
};

use crate::proto;
use crate::util;

/// Default cap on returned rows. A busy device has a few hundred sockets; the
/// limit exists so a pathological case cannot build a 100 MB response.
pub const DEFAULT_SOCKET_LIMIT: u32 = 4096;

pub struct SocketDump {
    pub sockets: Vec<proto::Socket>,
    pub summary: proto::SocketSummary,
    pub truncated: bool,
}

pub async fn get_sockets(
    filter: &proto::SocketFilter,
    if_names: &HashMap<u32, String>,
) -> Result<SocketDump> {
    let protocols = wanted_protocols(filter);
    let families = wanted_families(filter);
    let limit = if filter.limit == 0 {
        DEFAULT_SOCKET_LIMIT
    } else {
        filter.limit
    };

    let mut socket =
        TokioSocket::new(NETLINK_SOCK_DIAG).context("failed to open a NETLINK_SOCK_DIAG socket")?;
    socket
        .socket_mut()
        .bind_auto()
        .context("failed to bind the sock_diag socket")?;

    let mut out: Vec<proto::Socket> = Vec::new();
    let mut truncated = false;

    'outer: for protocol in &protocols {
        for family in &families {
            let responses = dump(&mut socket, *family, *protocol, filter).await?;
            for response in responses {
                let Some(s) = response_to_proto(&response, *protocol, if_names) else {
                    continue;
                };
                if !passes_filter(&s, filter) {
                    continue;
                }
                if out.len() as u32 >= limit {
                    truncated = true;
                    break 'outer;
                }
                out.push(s);
            }
        }
    }

    let summary = summarize(&out);
    Ok(SocketDump {
        sockets: out,
        summary,
        truncated,
    })
}

fn wanted_protocols(filter: &proto::SocketFilter) -> Vec<u8> {
    if filter.protocols.is_empty() {
        return vec![IPPROTO_TCP, IPPROTO_UDP];
    }
    filter
        .protocols
        .iter()
        .filter_map(|p| match proto::SocketProtocol::try_from(*p) {
            Ok(proto::SocketProtocol::Tcp) => Some(IPPROTO_TCP),
            Ok(proto::SocketProtocol::Udp) => Some(IPPROTO_UDP),
            _ => None,
        })
        .collect()
}

fn wanted_families(filter: &proto::SocketFilter) -> Vec<u8> {
    if filter.families.is_empty() {
        return vec![AF_INET, AF_INET6];
    }
    filter
        .families
        .iter()
        .filter_map(|f| match proto::IpFamily::try_from(*f) {
            Ok(proto::IpFamily::V4) => Some(AF_INET),
            Ok(proto::IpFamily::V6) => Some(AF_INET6),
            _ => None,
        })
        .collect()
}

async fn dump(
    socket: &mut TokioSocket,
    family: u8,
    protocol: u8,
    filter: &proto::SocketFilter,
) -> Result<Vec<netlink_packet_sock_diag::inet::InetResponse>> {
    // Ask for tcp_info and the congestion control algorithm only when the
    // caller wants them; they roughly double the size of every row.
    let mut extensions = ExtensionFlags::empty();
    if filter.include_tcp_info && protocol == IPPROTO_TCP {
        extensions |= ExtensionFlags::INFO | ExtensionFlags::CONG;
    }

    let request = InetRequest {
        family,
        protocol,
        extensions,
        states: state_flags(filter, protocol),
        // An all-zero socket id means "every socket", which is what a dump is.
        socket_id: if family == AF_INET {
            SocketId::new_v4()
        } else {
            SocketId::new_v6()
        },
    };

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(
        header,
        NetlinkPayload::from(SockDiagMessage::InetRequest(request)),
    );
    packet.finalize();

    let mut buf = vec![0u8; packet.buffer_len()];
    packet.serialize(&mut buf);
    socket
        .send_to(&buf, &SocketAddr::new(0, 0))
        .await
        .context("failed to send the inet_diag dump request")?;

    let mut out = Vec::new();
    let mut receive_buffer = vec![0u8; 8 * 1024];

    'recv: loop {
        let (bytes, _addr) = socket
            .recv_from_full()
            .await
            .context("failed to read the inet_diag dump")?;
        receive_buffer.clear();
        receive_buffer.extend_from_slice(&bytes);

        let mut offset = 0;
        loop {
            if offset >= receive_buffer.len() {
                break;
            }
            let slice = &receive_buffer[offset..];
            let message = <NetlinkMessage<SockDiagMessage>>::deserialize(slice)
                .context("malformed inet_diag response")?;
            let length = message.header.length as usize;
            if length == 0 {
                break 'recv;
            }

            match message.payload {
                NetlinkPayload::Done(_) => break 'recv,
                NetlinkPayload::Error(e) => {
                    // ENOENT here just means "no sockets of this kind".
                    if e.code.map(|c| c.get()).unwrap_or(0) == -libc::ENOENT {
                        break 'recv;
                    }
                    return Err(anyhow::anyhow!("inet_diag returned an error: {e}"));
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    out.push(*response);
                }
                _ => {}
            }

            offset += length;
            if length == 0 || offset >= receive_buffer.len() {
                break;
            }
        }
    }

    Ok(out)
}

/// Which TCP states to ask the kernel for. Narrowing this server-side is much
/// cheaper than filtering a full dump in userspace.
fn state_flags(filter: &proto::SocketFilter, protocol: u8) -> StateFlags {
    if protocol == IPPROTO_UDP {
        // UDP sockets are reported as ESTABLISHED (connected) or CLOSE.
        return StateFlags::all();
    }
    if filter.states.is_empty() {
        return StateFlags::all();
    }
    let mut flags = StateFlags::empty();
    for s in &filter.states {
        let Ok(state) = proto::TcpState::try_from(*s) else {
            continue;
        };
        flags |= match state {
            proto::TcpState::Established => StateFlags::ESTABLISHED,
            proto::TcpState::SynSent => StateFlags::SYN_SENT,
            proto::TcpState::SynRecv => StateFlags::SYN_RECV,
            proto::TcpState::FinWait1 => StateFlags::FIN_WAIT1,
            proto::TcpState::FinWait2 => StateFlags::FIN_WAIT2,
            proto::TcpState::TimeWait => StateFlags::TIME_WAIT,
            proto::TcpState::Close => StateFlags::CLOSE,
            proto::TcpState::CloseWait => StateFlags::CLOSE_WAIT,
            proto::TcpState::LastAck => StateFlags::LAST_ACK,
            proto::TcpState::Listen => StateFlags::LISTEN,
            proto::TcpState::Closing => StateFlags::CLOSING,
            _ => StateFlags::empty(),
        };
    }
    if flags.is_empty() {
        StateFlags::all()
    } else {
        flags
    }
}

fn response_to_proto(
    response: &netlink_packet_sock_diag::inet::InetResponse,
    protocol: u8,
    if_names: &HashMap<u32, String>,
) -> Option<proto::Socket> {
    let header = &response.header;
    let id = &header.socket_id;

    let family = if header.family == AF_INET {
        proto::IpFamily::V4
    } else {
        proto::IpFamily::V6
    };

    let mut s = proto::Socket {
        family: family as i32,
        protocol: if protocol == IPPROTO_TCP {
            proto::SocketProtocol::Tcp as i32
        } else {
            proto::SocketProtocol::Udp as i32
        },
        state: tcp_state_to_proto(header.state) as i32,
        local_address: Some(normalize_address(id.source_address)),
        local_port: id.source_port as u32,
        remote_address: Some(normalize_address(id.destination_address)),
        remote_port: id.destination_port as u32,
        uid: header.uid,
        inode: header.inode as u64,
        interface_index: id.interface_id,
        interface_name: if_names.get(&id.interface_id).cloned().unwrap_or_default(),
        rx_queue: header.recv_queue,
        tx_queue: header.send_queue,
        socket_cookie: u64::from_ne_bytes(id.cookie),
        ..Default::default()
    };

    // Timer kind uses the same numbering as `ss`: 1 retransmit, 2 keepalive,
    // 3 timewait, 4 zero-window probe.
    if let Some(timer) = &header.timer {
        let (kind, expires, retransmits) = match timer {
            Timer::Retransmit(d, n) => (1u32, d.as_millis() as u32, *n as u32),
            Timer::KeepAlive(d) => (2, d.as_millis() as u32, 0),
            Timer::TimeWait => (3, 0, 0),
            Timer::Probe(d) => (4, d.as_millis() as u32, 0),
        };
        s.timer = kind;
        s.timer_expires_ms = expires;
        s.retransmits = retransmits;
    }

    for nla in &response.nlas {
        match nla {
            Nla::Mark(mark) => {
                s.mark = *mark;
                s.has_mark = true;
                s.net_id = util::net_id_from_mark(*mark);
            }
            Nla::Congestion(cc) => s.congestion_control = cc.clone(),
            Nla::TcpInfo(info) => s.tcp_info = Some(tcp_info_to_proto(info)),
            _ => {}
        }
    }

    Some(s)
}

/// inet_diag always reports addresses as 16 bytes. An IPv4 socket's address
/// arrives as an Ipv4Addr already, but a dual-stack IPv6 socket carries a
/// v4-mapped address that is far more readable as plain IPv4.
fn normalize_address(addr: IpAddr) -> proto::IpAddress {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => proto::IpAddress::from_ip(IpAddr::V4(v4)),
            None => proto::IpAddress::from_ip(IpAddr::V6(v6)),
        },
        other => proto::IpAddress::from_ip(other),
    }
}

fn tcp_state_to_proto(state: u8) -> proto::TcpState {
    use proto::TcpState as P;
    match state {
        1 => P::Established,
        2 => P::SynSent,
        3 => P::SynRecv,
        4 => P::FinWait1,
        5 => P::FinWait2,
        6 => P::TimeWait,
        7 => P::Close,
        8 => P::CloseWait,
        9 => P::LastAck,
        10 => P::Listen,
        11 => P::Closing,
        12 => P::NewSynRecv,
        _ => P::Unspecified,
    }
}

fn tcp_info_to_proto(info: &netlink_packet_sock_diag::inet::nlas::TcpInfo) -> proto::TcpInfo {
    proto::TcpInfo {
        rto_us: info.rto,
        ato_us: info.ato,
        snd_mss: info.snd_mss,
        rcv_mss: info.rcv_mss,
        unacked: info.unacked,
        sacked: info.sacked,
        lost: info.lost,
        retrans: info.retrans,
        total_retrans: info.total_retrans,
        rtt_us: info.rtt,
        rtt_var_us: info.rttvar,
        snd_cwnd: info.snd_cwnd,
        snd_ssthresh: info.snd_ssthresh,
        advmss: info.advmss,
        pmtu: info.pmtu,
        last_data_sent_ms: info.last_data_sent,
        last_data_recv_ms: info.last_data_recv,
        last_ack_recv_ms: info.last_ack_recv,
        bytes_sent: info.bytes_sent,
        bytes_received: info.bytes_received,
        delivered: info.delivered as u64,
        ca_state: info.ca_state as u32,
        probes: info.probes as u32,
        backoff: info.backoff as u32,
        // Anything currently in flight and unacknowledged with retransmits
        // already spent is a connection actively fighting the network.
        retransmitting: info.retrans > 0 || info.retransmits > 0,
    }
}

fn passes_filter(s: &proto::Socket, filter: &proto::SocketFilter) -> bool {
    if !filter.uids.is_empty() && !filter.uids.contains(&s.uid) {
        return false;
    }
    if !filter.interface_indexes.is_empty()
        && !filter.interface_indexes.contains(&s.interface_index)
    {
        return false;
    }
    if filter.local_port != 0 && s.local_port != filter.local_port {
        return false;
    }
    if filter.remote_port != 0 && s.remote_port != filter.remote_port {
        return false;
    }
    true
}

pub fn summarize(sockets: &[proto::Socket]) -> proto::SocketSummary {
    let mut summary = proto::SocketSummary {
        total: sockets.len() as u32,
        ..Default::default()
    };

    for s in sockets {
        let state = proto::TcpState::try_from(s.state).unwrap_or(proto::TcpState::Unspecified);
        *summary
            .by_state
            .entry(state.as_str_name().to_string())
            .or_insert(0) += 1;

        match state {
            proto::TcpState::Established => summary.established += 1,
            proto::TcpState::SynSent => summary.syn_sent += 1,
            proto::TcpState::CloseWait => summary.close_wait += 1,
            proto::TcpState::FinWait1 | proto::TcpState::FinWait2 => summary.fin_wait += 1,
            proto::TcpState::TimeWait => summary.time_wait += 1,
            proto::TcpState::Listen => summary.listen += 1,
            _ => {}
        }

        if s.family == proto::IpFamily::V4 as i32 {
            summary.v4_count += 1;
        } else if s.family == proto::IpFamily::V6 as i32 {
            summary.v6_count += 1;
        }

        if s.tcp_info
            .as_ref()
            .map(|i| i.retransmitting)
            .unwrap_or(false)
        {
            summary.retransmitting += 1;
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_mapped_addresses_become_plain_ipv4() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        let normalized = normalize_address(mapped);
        assert_eq!(
            normalized.to_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn real_v6_addresses_are_left_alone() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
        assert_eq!(normalize_address(v6).to_ip(), Some(v6));
    }

    #[test]
    fn summary_counts_states() {
        let sockets = vec![
            proto::Socket {
                state: proto::TcpState::Established as i32,
                family: proto::IpFamily::V4 as i32,
                ..Default::default()
            },
            proto::Socket {
                state: proto::TcpState::SynSent as i32,
                family: proto::IpFamily::V6 as i32,
                ..Default::default()
            },
            proto::Socket {
                state: proto::TcpState::SynSent as i32,
                family: proto::IpFamily::V6 as i32,
                ..Default::default()
            },
        ];
        let summary = summarize(&sockets);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.established, 1);
        assert_eq!(summary.syn_sent, 2);
        assert_eq!(summary.v4_count, 1);
        assert_eq!(summary.v6_count, 2);
    }

    #[test]
    fn net_id_is_extracted_from_the_mark() {
        // netId 101 with the explicitlySelected bit set.
        assert_eq!(util::net_id_from_mark(0x10065), 101);
    }
}
