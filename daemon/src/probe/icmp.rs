//! ICMP echo, used mainly to ask "is the default gateway actually there?".
//!
//! Two socket flavours are supported. `SOCK_DGRAM` ICMP sockets are preferred:
//! the kernel owns the identifier and the checksum, and there is no IP header
//! to skip on receive. They are gated behind `net.ipv4.ping_group_range`, so
//! when that is closed the probe falls back to `SOCK_RAW`, which root can
//! always open and which hands back the full IP datagram.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::{ProbeContext, ProbeResult, apply_context, explain_io_error};
use crate::util;

const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    /// Kernel-managed identifier and checksum; receive buffer starts at the
    /// ICMP header.
    Datagram,
    /// Raw; for IPv4 the receive buffer starts at the IP header.
    Raw,
}

struct IcmpSocket {
    fd: AsyncFd<OwnedFd>,
    kind: SocketKind,
    v6: bool,
}

impl IcmpSocket {
    fn open(v6: bool, ctx: &ProbeContext) -> io::Result<Self> {
        let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let protocol = if v6 {
            libc::IPPROTO_ICMPV6
        } else {
            libc::IPPROTO_ICMP
        };

        let (raw_fd, kind) = match open_socket(domain, libc::SOCK_DGRAM, protocol) {
            Ok(fd) => (fd, SocketKind::Datagram),
            Err(_) => (
                open_socket(domain, libc::SOCK_RAW, protocol)?,
                SocketKind::Raw,
            ),
        };

        // SAFETY: `raw_fd` was just returned by socket(2) and is not owned
        // anywhere else.
        let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        apply_context(owned.as_raw_fd(), ctx).map_err(|e| io::Error::other(e.to_string()))?;
        set_nonblocking(owned.as_raw_fd())?;

        Ok(Self {
            fd: AsyncFd::new(owned)?,
            kind,
            v6,
        })
    }
}

fn open_socket(domain: i32, ty: i32, protocol: i32) -> io::Result<RawFd> {
    // SAFETY: plain socket(2) call with constant arguments.
    let fd = unsafe { libc::socket(domain, ty, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid file descriptor owned by the caller.
    let flags = util::cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    util::cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(())
}

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    // An odd-length buffer is padded with a zero byte, per RFC 1071.
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo(v6: bool, id: u16, sequence: u16, payload: &[u8], fill_checksum: bool) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.push(if v6 {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMPV4_ECHO_REQUEST
    });
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum placeholder
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);

    // IPv6 checksums cover a pseudo-header, so the kernel always computes them
    // for ICMPv6 sockets. IPv4 raw sockets need us to do it.
    if fill_checksum && !v6 {
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// Was this an echo reply to our request? For datagram sockets the kernel
/// rewrites the id, so only the sequence number is ours to check.
fn matches_reply(buf: &[u8], v6: bool, kind: SocketKind, sequence: u16) -> bool {
    let icmp = if !v6 && kind == SocketKind::Raw {
        // Skip the IPv4 header, whose length lives in the low nibble of byte 0
        // in 32-bit words.
        if buf.is_empty() {
            return false;
        }
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        if buf.len() < ihl + 8 {
            return false;
        }
        &buf[ihl..]
    } else {
        buf
    };

    if icmp.len() < 8 {
        return false;
    }
    let expected_type = if v6 {
        ICMPV6_ECHO_REPLY
    } else {
        ICMPV4_ECHO_REPLY
    };
    if icmp[0] != expected_type {
        return false;
    }
    u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
}

/// Send `count` echo requests and report the first reply. Used for gateway
/// reachability, where one answer is enough to prove the next hop is alive.
pub async fn ping(
    target: IpAddr,
    count: u16,
    payload_len: usize,
    ctx: &ProbeContext,
) -> ProbeResult {
    let started = Instant::now();
    let v6 = target.is_ipv6();

    let socket = match IcmpSocket::open(v6, ctx) {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult::failure(
                started.elapsed().as_millis() as u64,
                format!("could not open an ICMP socket: {}", explain_io_error(&e)),
            )
            .with("routing", ctx.describe());
        }
    };

    let id = (std::process::id() & 0xffff) as u16;
    let payload = vec![0x61u8; payload_len];
    let dest = SocketAddr::new(target, 0);

    for sequence in 1..=count.max(1) {
        let packet = build_echo(v6, id, sequence, &payload, socket.kind == SocketKind::Raw);
        if let Err(e) = send_to(&socket, &packet, dest).await {
            return ProbeResult::failure(
                started.elapsed().as_millis() as u64,
                format!(
                    "could not send an echo request to {target}: {}",
                    explain_io_error(&e)
                ),
            )
            .with("routing", ctx.describe());
        }

        let sent_at = Instant::now();
        let deadline = ctx.timeout / count.max(1) as u32;
        match tokio::time::timeout(deadline, wait_for_reply(&socket, sequence)).await {
            Ok(Ok(())) => {
                let rtt = sent_at.elapsed().as_millis() as u64;
                return ProbeResult::success(
                    started.elapsed().as_millis() as u64,
                    format!("{target} replied in {rtt} ms"),
                )
                .with("target", target.to_string())
                .with("rtt_ms", rtt.to_string())
                .with("sequence", sequence.to_string())
                .with("payload_bytes", payload_len.to_string())
                .with("socket", format!("{:?}", socket.kind))
                .with("routing", ctx.describe());
            }
            Ok(Err(e)) => {
                return ProbeResult::failure(
                    started.elapsed().as_millis() as u64,
                    format!("ICMP receive failed: {}", explain_io_error(&e)),
                )
                .with("routing", ctx.describe());
            }
            // Timed out on this sequence; try the next one.
            Err(_) => continue,
        }
    }

    ProbeResult::failure(
        started.elapsed().as_millis() as u64,
        format!(
            "{target} did not answer {} echo request(s) within {} ms",
            count.max(1),
            ctx.timeout.as_millis()
        ),
    )
    .with("target", target.to_string())
    .with("payload_bytes", payload_len.to_string())
    .with("socket", format!("{:?}", socket.kind))
    .with("routing", ctx.describe())
}

async fn send_to(socket: &IcmpSocket, packet: &[u8], dest: SocketAddr) -> io::Result<()> {
    loop {
        let mut guard = socket.fd.ready(Interest::WRITABLE).await?;
        let result = guard.try_io(|inner| {
            let (addr, len) = socket_addr_to_raw(dest);
            // SAFETY: `addr` outlives the call, `len` describes it, and the
            // packet slice is valid for reading.
            let sent = unsafe {
                libc::sendto(
                    inner.as_raw_fd(),
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &addr as *const libc::sockaddr_storage as *const libc::sockaddr,
                    len,
                )
            };
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
        match result {
            Ok(r) => return r,
            // The readiness was stale; loop and wait again.
            Err(_would_block) => continue,
        }
    }
}

async fn wait_for_reply(socket: &IcmpSocket, sequence: u16) -> io::Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let mut guard = socket.fd.ready(Interest::READABLE).await?;
        let read = guard.try_io(|inner| {
            // SAFETY: the buffer is valid and writable for `buf.len()` bytes.
            let n = unsafe {
                libc::recv(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        let n = match read {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        };
        // Other processes' pings land here too on a raw socket; keep reading
        // until one of ours shows up.
        if matches_reply(&buf[..n], socket.v6, socket.kind, sequence) {
            return Ok(());
        }
    }
}

fn socket_addr_to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is a plain-old-data type; an all-zero value is
    // valid and is then filled in for the relevant family.
    let mut storage: libc::sockaddr_storage = unsafe { MaybeUninit::zeroed().assume_init() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits inside sockaddr_storage.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const libc::sockaddr_in as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits inside sockaddr_storage.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const libc::sockaddr_in6 as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_known_packet() {
        // An echo request with a zeroed checksum field; the result folds to a
        // value that makes the whole buffer sum to 0xffff.
        let packet = build_echo(false, 0x1234, 1, b"abcdefgh", true);
        assert_eq!(checksum(&packet), 0, "a checksummed packet re-sums to zero");
    }

    #[test]
    fn echo_header_layout_is_correct() {
        let packet = build_echo(false, 0xbeef, 7, b"xy", false);
        assert_eq!(packet[0], ICMPV4_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0xbeef);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 7);
        assert_eq!(&packet[8..], b"xy");
    }

    #[test]
    fn v6_echo_uses_the_v6_type() {
        let packet = build_echo(true, 1, 1, b"", false);
        assert_eq!(packet[0], ICMPV6_ECHO_REQUEST);
    }

    #[test]
    fn matches_a_datagram_reply_by_sequence() {
        let mut reply = vec![ICMPV4_ECHO_REPLY, 0, 0, 0, 0x12, 0x34, 0x00, 0x05];
        reply.extend_from_slice(b"payload");
        assert!(matches_reply(&reply, false, SocketKind::Datagram, 5));
        assert!(!matches_reply(&reply, false, SocketKind::Datagram, 6));
    }

    #[test]
    fn skips_the_ip_header_on_raw_sockets() {
        // Minimal 20-byte IPv4 header (IHL = 5) followed by an echo reply.
        let mut packet = vec![0x45u8; 20];
        packet[0] = 0x45;
        packet.extend_from_slice(&[ICMPV4_ECHO_REPLY, 0, 0, 0, 0x12, 0x34, 0x00, 0x09]);
        assert!(matches_reply(&packet, false, SocketKind::Raw, 9));
    }

    #[test]
    fn an_echo_request_is_not_mistaken_for_a_reply() {
        let request = build_echo(false, 1, 3, b"", true);
        assert!(!matches_reply(&request, false, SocketKind::Datagram, 3));
    }
}
