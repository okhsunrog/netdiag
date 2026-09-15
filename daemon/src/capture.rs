//! Packet capture from real interfaces using AF_PACKET.
//!
//! The obvious way to capture packets on Android is a `VpnService` that routes
//! traffic through a tun device. This does not do that, on purpose: Android
//! allows exactly one active VpnService, so a capture built that way cannot run
//! at the same time as the VPN the user is usually trying to debug. It also
//! only ever sees what is routed into the tun, which excludes the traffic that
//! is escaping the VPN — precisely the traffic in question.
//!
//! AF_PACKET with CAP_NET_RAW sees the real frames on the real interface,
//! including traffic from other apps, ICMP errors, and DHCP/RA exchanges that
//! never reach a tun.
//!
//! Filtering happens in userspace rather than via an attached cBPF program.
//! Captures here are short and targeted, the volumes are small, and it keeps a
//! filter compiler out of a process running as root. `CaptureFilter` leaves
//! room for a `bpf_expression` to be compiled in kernel later without a
//! protocol change.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::proto;
use crate::util;

const ETH_P_ALL: u16 = 0x0003;
const DEFAULT_SNAPLEN: u32 = 262_144;

// linux/if_packet.h. Bionic's headers carry these, but the `libc` crate only
// exposes them for target_os = "linux", so they are defined here rather than
// leaving the Android build without promiscuous mode and drop counters.
/// The frame was sent by this host rather than received.
const PACKET_OUTGOING: u8 = 4;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_STATISTICS: libc::c_int = 6;
const PACKET_MR_PROMISC: libc::c_ushort = 1;

/// `struct packet_mreq` from linux/if_packet.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [libc::c_uchar; 8],
}

/// `struct tpacket_stats` from linux/if_packet.h.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TpacketStats {
    packets: libc::c_uint,
    drops: libc::c_uint,
}

/// A live capture socket.
pub struct Capture {
    fd: AsyncFd<OwnedFd>,
    pub link_type: proto::LinkType,
    pub interface_index: u32,
    pub interface_name: String,
    pub snaplen: u32,
    stop: Arc<AtomicBool>,
    packets: u64,
    bytes: u64,
    filtered_out: u64,
}

impl Capture {
    /// Open a capture on `interface_name`, or on every interface when it is
    /// empty.
    pub fn open(request: &proto::StartCaptureRequest) -> Result<Self> {
        // SAFETY: plain socket(2) with constant arguments.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                ETH_P_ALL.to_be() as libc::c_int,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error())
                .context("could not open an AF_PACKET socket (CAP_NET_RAW required)");
        }
        // SAFETY: `raw` was just created and is not owned elsewhere.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        let (index, name) = if request.interface_name.is_empty() {
            (0u32, "any".to_string())
        } else {
            let index = interface_index(&request.interface_name)
                .with_context(|| format!("no interface named {}", request.interface_name))?;
            (index, request.interface_name.clone())
        };

        if index != 0 {
            bind_to_interface(owned.as_raw_fd(), index)?;
        }
        if request.promiscuous && index != 0 {
            set_promiscuous(owned.as_raw_fd(), index)?;
        }

        set_nonblocking(owned.as_raw_fd())?;

        // The link type has to match what the kernel actually hands us. On
        // Android, cellular interfaces are ARPHRD_RAWIP and deliver bare IP
        // packets with no Ethernet header; writing those into a pcap labelled
        // ETHERNET produces a file that every analyser misreads.
        let link_type = if index == 0 {
            proto::LinkType::LinuxSll
        } else {
            link_type_for(&name)
        };

        Ok(Self {
            fd: AsyncFd::new(owned)?,
            link_type,
            interface_index: index,
            interface_name: name,
            snaplen: if request.snaplen == 0 {
                DEFAULT_SNAPLEN
            } else {
                request.snaplen
            },
            stop: Arc::new(AtomicBool::new(false)),
            packets: 0,
            bytes: 0,
            filtered_out: 0,
        })
    }

    /// Shared flag that another task sets to stop this capture. Handing out
    /// the flag rather than a `&mut Capture` is what lets `StopCapture` arrive
    /// on the same connection while the capture loop is blocked on a packet.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub fn stats(&self, id: u64) -> proto::CaptureStats {
        proto::CaptureStats {
            capture_id: id,
            packets_captured: self.packets,
            packets_dropped_kernel: self.kernel_drops(),
            packets_filtered_out: self.filtered_out,
            bytes_captured: self.bytes,
        }
    }

    /// PACKET_STATISTICS resets on read, so this is only called when finishing
    /// a capture.
    fn kernel_drops(&self) -> u64 {
        let mut stats = TpacketStats::default();
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        // SAFETY: out-parameters are correctly sized for PACKET_STATISTICS.
        let ret = unsafe {
            libc::getsockopt(
                self.fd.get_ref().as_raw_fd(),
                libc::SOL_PACKET,
                PACKET_STATISTICS,
                &mut stats as *mut TpacketStats as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 { 0 } else { stats.drops as u64 }
    }

    /// Wait for and return the next packet that passes `filter`.
    pub async fn next_packet(
        &mut self,
        filter: &proto::CaptureFilter,
        include_payload: bool,
    ) -> Result<Option<proto::CapturedPacket>> {
        let mut buf = vec![0u8; self.snaplen as usize];

        loop {
            if self.should_stop() {
                return Ok(None);
            }

            let mut guard = self.fd.ready(Interest::READABLE).await?;
            let read = guard.try_io(|inner| recv_with_addr(inner.as_raw_fd(), &mut buf));
            let (len, outgoing, ifindex) = match read {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            };

            let data = &buf[..len.min(buf.len())];
            let summary = decode(data, self.link_type);

            if !passes(&summary, filter) {
                self.filtered_out += 1;
                continue;
            }

            self.packets += 1;
            self.bytes += len as u64;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();

            return Ok(Some(proto::CapturedPacket {
                capture_id: 0,
                sequence: self.packets,
                unix_ms: now.as_millis() as i64,
                unix_us_fraction: now.subsec_micros() % 1000,
                original_length: len as u32,
                data: if include_payload {
                    data.to_vec()
                } else {
                    Vec::new()
                },
                // On an "any" capture the kernel reports the real interface
                // per packet; when bound, it is always ours.
                interface_index: if ifindex != 0 {
                    ifindex
                } else {
                    self.interface_index
                },
                interface_name: self.interface_name.clone(),
                outgoing,
                summary: Some(summary),
            }));
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid descriptor owned by the caller.
    let flags = util::cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    util::cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(())
}

fn interface_index(name: &str) -> Result<u32> {
    let c_name = std::ffi::CString::new(name)?;
    // SAFETY: `c_name` is a valid NUL-terminated string that outlives the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        bail!(
            "if_nametoindex({name}) failed: {}",
            io::Error::last_os_error()
        );
    }
    Ok(index)
}

fn bind_to_interface(fd: RawFd, index: u32) -> Result<()> {
    // SAFETY: sockaddr_ll is plain data; zeroed is a valid starting state.
    let mut addr: libc::sockaddr_ll = unsafe { MaybeUninit::zeroed().assume_init() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ALL.to_be();
    addr.sll_ifindex = index as i32;

    // SAFETY: `addr` is a correctly initialised sockaddr_ll of the given size.
    util::cvt(unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    })
    .context("could not bind the capture socket to the interface")?;
    Ok(())
}

fn set_promiscuous(fd: RawFd, index: u32) -> Result<()> {
    let mreq = PacketMreq {
        mr_ifindex: index as libc::c_int,
        mr_type: PACKET_MR_PROMISC,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    // SAFETY: `mreq` is a correctly sized packet_mreq for this option.
    util::cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_ADD_MEMBERSHIP,
            &mreq as *const PacketMreq as *const libc::c_void,
            std::mem::size_of::<PacketMreq>() as libc::socklen_t,
        )
    })
    .context("could not enable promiscuous mode")?;
    Ok(())
}

/// recvfrom into `buf`, also reporting direction and interface from the
/// sockaddr_ll the kernel fills in.
fn recv_with_addr(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, bool, u32)> {
    // SAFETY: zeroed sockaddr_ll is valid; the kernel fills it in.
    let mut addr: libc::sockaddr_ll = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

    // SAFETY: buf is valid for writes of buf.len(); addr/addr_len are valid
    // out-parameters.
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
            &mut addr_len,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        n as usize,
        addr.sll_pkttype == PACKET_OUTGOING,
        addr.sll_ifindex as u32,
    ))
}

/// pcap link type for an interface, inferred from Android's naming.
fn link_type_for(name: &str) -> proto::LinkType {
    if name.starts_with("rmnet")
        || name.starts_with("ccmni")
        || name.starts_with("pdp")
        || name.starts_with("tun")
        || name.starts_with("v4-")
        || name.starts_with("ppp")
    {
        proto::LinkType::Raw
    } else {
        proto::LinkType::Ethernet
    }
}

// ---- Decoding ---------------------------------------------------------------

/// Decode enough of the packet for a list view: addresses, ports, flags, and
/// the ICMP types that explain MTU problems.
pub fn decode(data: &[u8], link_type: proto::LinkType) -> proto::PacketSummary {
    let mut summary = proto::PacketSummary::default();

    let ip = match link_type {
        proto::LinkType::Ethernet => {
            if data.len() < 14 {
                return summary;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            match ethertype {
                0x0800 | 0x86dd => &data[14..],
                0x0806 => {
                    summary.protocol_name = "ARP".to_string();
                    summary.description = "ARP".to_string();
                    return summary;
                }
                // VLAN-tagged: skip the 4-byte tag and re-read the ethertype.
                0x8100 if data.len() >= 18 => &data[18..],
                _ => return summary,
            }
        }
        _ => data,
    };

    if ip.is_empty() {
        return summary;
    }

    match ip[0] >> 4 {
        4 => decode_v4(ip, &mut summary),
        6 => decode_v6(ip, &mut summary),
        _ => {}
    }

    summary.description = describe(&summary);
    summary
}

fn decode_v4(ip: &[u8], summary: &mut proto::PacketSummary) {
    if ip.len() < 20 {
        return;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ip.len() < ihl {
        return;
    }
    summary.family = proto::IpFamily::V4 as i32;
    summary.ttl = ip[8] as u32;
    summary.ip_protocol = ip[9] as u32;
    summary.source = Some(proto::IpAddress {
        addr: ip[12..16].to_vec(),
    });
    summary.destination = Some(proto::IpAddress {
        addr: ip[16..20].to_vec(),
    });
    decode_l4(&ip[ihl..], ip[9], summary, false);
}

fn decode_v6(ip: &[u8], summary: &mut proto::PacketSummary) {
    if ip.len() < 40 {
        return;
    }
    summary.family = proto::IpFamily::V6 as i32;
    summary.ttl = ip[7] as u32; // hop limit
    summary.ip_protocol = ip[6] as u32;
    summary.source = Some(proto::IpAddress {
        addr: ip[8..24].to_vec(),
    });
    summary.destination = Some(proto::IpAddress {
        addr: ip[24..40].to_vec(),
    });
    // Extension headers are not walked; the next-header value is reported as
    // it is, which is honest and enough for a summary line.
    decode_l4(&ip[40..], ip[6], summary, true);
}

fn decode_l4(payload: &[u8], protocol: u8, summary: &mut proto::PacketSummary, v6: bool) {
    match protocol {
        6 => {
            summary.protocol_name = "TCP".to_string();
            if payload.len() < 20 {
                return;
            }
            summary.source_port = u16::from_be_bytes([payload[0], payload[1]]) as u32;
            summary.destination_port = u16::from_be_bytes([payload[2], payload[3]]) as u32;
            summary.tcp_seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let flags = payload[13];
            summary.fin = flags & 0x01 != 0;
            summary.syn = flags & 0x02 != 0;
            summary.rst = flags & 0x04 != 0;
            summary.psh = flags & 0x08 != 0;
            summary.ack = flags & 0x10 != 0;
            summary.tcp_window = u16::from_be_bytes([payload[14], payload[15]]) as u32;
        }
        17 => {
            summary.protocol_name = "UDP".to_string();
            if payload.len() < 8 {
                return;
            }
            summary.source_port = u16::from_be_bytes([payload[0], payload[1]]) as u32;
            summary.destination_port = u16::from_be_bytes([payload[2], payload[3]]) as u32;
        }
        1 | 58 => {
            summary.protocol_name = if v6 { "ICMPv6" } else { "ICMP" }.to_string();
            if payload.len() < 8 {
                return;
            }
            summary.icmp_type = payload[0] as u32;
            summary.icmp_code = payload[1] as u32;
            // "Fragmentation needed" (v4 type 3 code 4) and "Packet too big"
            // (v6 type 2) carry the next-hop MTU, which is the direct evidence
            // for an MTU problem.
            let carries_mtu =
                (!v6 && payload[0] == 3 && payload[1] == 4) || (v6 && payload[0] == 2);
            if carries_mtu {
                summary.icmp_mtu = if v6 {
                    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])
                } else {
                    u16::from_be_bytes([payload[6], payload[7]]) as u32
                };
            }
        }
        _ => {
            summary.protocol_name = format!("IP proto {protocol}");
        }
    }
}

fn describe(summary: &proto::PacketSummary) -> String {
    let src = summary
        .source
        .as_ref()
        .map(|a| a.display())
        .unwrap_or_default();
    let dst = summary
        .destination
        .as_ref()
        .map(|a| a.display())
        .unwrap_or_default();

    match summary.protocol_name.as_str() {
        "TCP" => {
            let mut flags = String::new();
            for (set, name) in [
                (summary.syn, "SYN"),
                (summary.ack, "ACK"),
                (summary.fin, "FIN"),
                (summary.rst, "RST"),
                (summary.psh, "PSH"),
            ] {
                if set {
                    if !flags.is_empty() {
                        flags.push(',');
                    }
                    flags.push_str(name);
                }
            }
            format!(
                "TCP {}:{} -> {}:{} [{}]",
                src, summary.source_port, dst, summary.destination_port, flags
            )
        }
        "UDP" => format!(
            "UDP {}:{} -> {}:{}",
            src, summary.source_port, dst, summary.destination_port
        ),
        name if name.starts_with("ICMP") => {
            if summary.icmp_mtu > 0 {
                format!(
                    "{name} {src} -> {dst} type {} code {} next-hop MTU {}",
                    summary.icmp_type, summary.icmp_code, summary.icmp_mtu
                )
            } else {
                format!(
                    "{name} {src} -> {dst} type {} code {}",
                    summary.icmp_type, summary.icmp_code
                )
            }
        }
        "" => String::new(),
        name => format!("{name} {src} -> {dst}"),
    }
}

/// Apply the filter to a decoded summary. Empty lists mean "no constraint".
pub fn passes(summary: &proto::PacketSummary, filter: &proto::CaptureFilter) -> bool {
    let protocol_selected = filter.tcp || filter.udp || filter.icmp || filter.arp;
    if protocol_selected {
        let matched = (filter.tcp && summary.ip_protocol == 6)
            || (filter.udp && summary.ip_protocol == 17)
            || (filter.icmp && (summary.ip_protocol == 1 || summary.ip_protocol == 58))
            || (filter.arp && summary.protocol_name == "ARP");
        if !matched {
            return false;
        }
    }

    if !filter.families.is_empty() && !filter.families.contains(&summary.family) {
        return false;
    }

    if !filter.hosts.is_empty() {
        let matched = filter.hosts.iter().any(|h| {
            Some(&h.addr) == summary.source.as_ref().map(|a| &a.addr)
                || Some(&h.addr) == summary.destination.as_ref().map(|a| &a.addr)
        });
        if !matched {
            return false;
        }
    }

    if !filter.ports.is_empty() {
        let matched = filter.ports.contains(&summary.source_port)
            || filter.ports.contains(&summary.destination_port);
        if !matched {
            return false;
        }
    }

    true
}

// ---- pcap ------------------------------------------------------------------

/// A classic libpcap file header, so captured packets can be written to a
/// `.pcap` the user can open in Wireshark. The app writes the file; the daemon
/// only needs to say what header it should carry.
pub fn pcap_header(link_type: proto::LinkType, snaplen: u32) -> [u8; 24] {
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic, microseconds
    header[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
    header[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
    // thiszone and sigfigs stay zero.
    header[16..20].copy_from_slice(&snaplen.to_le_bytes());
    header[20..24].copy_from_slice(&(link_type as u32).to_le_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 TCP SYN from 192.168.1.10:1234 to 1.1.1.1:443.
    fn v4_tcp_syn() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[8] = 64; // TTL
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[13] = 0x02; // SYN
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        p.extend_from_slice(&tcp);
        p
    }

    #[test]
    fn decodes_a_raw_ip_tcp_packet() {
        let summary = decode(&v4_tcp_syn(), proto::LinkType::Raw);
        assert_eq!(summary.protocol_name, "TCP");
        assert_eq!(summary.source_port, 1234);
        assert_eq!(summary.destination_port, 443);
        assert!(summary.syn);
        assert!(!summary.ack);
        assert_eq!(summary.ttl, 64);
        assert_eq!(summary.destination.as_ref().unwrap().display(), "1.1.1.1");
        assert!(
            summary.description.contains("SYN"),
            "{}",
            summary.description
        );
    }

    #[test]
    fn strips_the_ethernet_header() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&v4_tcp_syn());
        let summary = decode(&frame, proto::LinkType::Ethernet);
        assert_eq!(summary.source_port, 1234);
    }

    #[test]
    fn recognises_arp() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let summary = decode(&frame, proto::LinkType::Ethernet);
        assert_eq!(summary.protocol_name, "ARP");
    }

    #[test]
    fn extracts_the_next_hop_mtu_from_fragmentation_needed() {
        // ICMPv4 type 3 code 4 carrying an MTU of 1400.
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[9] = 1; // ICMP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[192, 168, 1, 10]);
        let mut icmp = vec![0u8; 8];
        icmp[0] = 3;
        icmp[1] = 4;
        icmp[6..8].copy_from_slice(&1400u16.to_be_bytes());
        p.extend_from_slice(&icmp);

        let summary = decode(&p, proto::LinkType::Raw);
        assert_eq!(summary.protocol_name, "ICMP");
        assert_eq!(summary.icmp_mtu, 1400);
        assert!(
            summary.description.contains("1400"),
            "{}",
            summary.description
        );
    }

    #[test]
    fn extracts_the_mtu_from_icmpv6_packet_too_big() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 58; // ICMPv6
        p[7] = 64;
        let mut icmp = vec![0u8; 8];
        icmp[0] = 2; // packet too big
        icmp[4..8].copy_from_slice(&1280u32.to_be_bytes());
        p.extend_from_slice(&icmp);

        let summary = decode(&p, proto::LinkType::Raw);
        assert_eq!(summary.protocol_name, "ICMPv6");
        assert_eq!(summary.icmp_mtu, 1280);
    }

    #[test]
    fn an_empty_filter_passes_everything() {
        let summary = decode(&v4_tcp_syn(), proto::LinkType::Raw);
        assert!(passes(&summary, &proto::CaptureFilter::default()));
    }

    #[test]
    fn protocol_filter_excludes_other_protocols() {
        let summary = decode(&v4_tcp_syn(), proto::LinkType::Raw);
        assert!(passes(
            &summary,
            &proto::CaptureFilter {
                tcp: true,
                ..Default::default()
            }
        ));
        assert!(!passes(
            &summary,
            &proto::CaptureFilter {
                udp: true,
                ..Default::default()
            }
        ));
    }

    #[test]
    fn port_filter_matches_either_direction() {
        let summary = decode(&v4_tcp_syn(), proto::LinkType::Raw);
        assert!(passes(
            &summary,
            &proto::CaptureFilter {
                ports: vec![443],
                ..Default::default()
            }
        ));
        assert!(passes(
            &summary,
            &proto::CaptureFilter {
                ports: vec![1234],
                ..Default::default()
            }
        ));
        assert!(!passes(
            &summary,
            &proto::CaptureFilter {
                ports: vec![80],
                ..Default::default()
            }
        ));
    }

    #[test]
    fn host_filter_matches_either_endpoint() {
        let summary = decode(&v4_tcp_syn(), proto::LinkType::Raw);
        let cloudflare = proto::IpAddress::from_ip("1.1.1.1".parse().unwrap());
        assert!(passes(
            &summary,
            &proto::CaptureFilter {
                hosts: vec![cloudflare],
                ..Default::default()
            }
        ));
        let elsewhere = proto::IpAddress::from_ip("8.8.8.8".parse().unwrap());
        assert!(!passes(
            &summary,
            &proto::CaptureFilter {
                hosts: vec![elsewhere],
                ..Default::default()
            }
        ));
    }

    #[test]
    fn cellular_interfaces_capture_as_raw_ip() {
        // Getting this wrong produces a pcap that every analyser misreads.
        assert_eq!(link_type_for("rmnet_data0"), proto::LinkType::Raw);
        assert_eq!(link_type_for("tun0"), proto::LinkType::Raw);
        assert_eq!(link_type_for("v4-rmnet_data0"), proto::LinkType::Raw);
        assert_eq!(link_type_for("wlan0"), proto::LinkType::Ethernet);
    }

    #[test]
    fn pcap_header_is_well_formed() {
        let header = pcap_header(proto::LinkType::Ethernet, 65535);
        assert_eq!(&header[0..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(u16::from_le_bytes([header[4], header[5]]), 2);
        assert_eq!(
            u32::from_le_bytes([header[16], header[17], header[18], header[19]]),
            65535
        );
        assert_eq!(
            u32::from_le_bytes([header[20], header[21], header[22], header[23]]),
            1
        );
    }

    #[test]
    fn truncated_packets_do_not_panic() {
        for len in 0..40 {
            let data = vec![0x45u8; len];
            let _ = decode(&data, proto::LinkType::Raw);
            let _ = decode(&data, proto::LinkType::Ethernet);
        }
        for len in 0..44 {
            let mut data = vec![0u8; len];
            if !data.is_empty() {
                data[0] = 0x60;
            }
            let _ = decode(&data, proto::LinkType::Raw);
        }
    }
}
