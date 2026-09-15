//! Path MTU discovery.
//!
//! Two complementary methods:
//!
//! 1. Connect a UDP socket with PMTU discovery enabled and read back IP_MTU /
//!    IPV6_MTU. This costs one syscall and reports what the kernel currently
//!    believes about the path, including any value it learned from a
//!    "fragmentation needed" or "packet too big" ICMP message.
//!
//! 2. Send don't-fragment ICMP echoes at decreasing sizes. This finds the real
//!    limit when the kernel has not learned one, and it is the only way to see
//!    a black hole: a path where large packets vanish and no ICMP error comes
//!    back. That case is invisible to method 1 by definition, because the
//!    missing ICMP error is the whole problem.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Instant;

use super::{ProbeContext, ProbeResult, apply_context, icmp};
use crate::util;

/// The smallest MTU IPv6 permits; nothing below this is worth probing.
pub const IPV6_MIN_MTU: usize = 1280;
/// Classic Ethernet MTU, the value almost every path is trying to be.
pub const ETHERNET_MTU: usize = 1500;

/// IP and ICMP header overhead subtracted from an MTU to get the echo payload
/// size that exactly fills it.
const V4_OVERHEAD: usize = 20 + 8;
const V6_OVERHEAD: usize = 40 + 8;

/// Ask the kernel what it thinks the path MTU to `target` is.
pub fn kernel_path_mtu(target: IpAddr, ctx: &ProbeContext) -> std::io::Result<u32> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    apply_context(socket.as_raw_fd(), ctx).map_err(|e| std::io::Error::other(e.to_string()))?;

    let fd = socket.as_raw_fd();
    // Turn on PMTU discovery so the kernel maintains a value for this path and
    // refuses to fragment locally.
    let (level, discover_opt, mtu_opt, do_value) = if target.is_ipv4() {
        (
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_MTU,
            libc::IP_PMTUDISC_DO,
        )
    } else {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_MTU,
            libc::IPV6_PMTUDISC_DO,
        )
    };

    let value: libc::c_int = do_value;
    // SAFETY: valid fd, and the option value is a correctly sized c_int.
    util::cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            discover_opt,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })?;

    // IP_MTU is only meaningful on a connected socket.
    socket.connect(SocketAddr::new(target, 9))?;

    let mut mtu: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `mtu` and `len` are valid out-parameters of the expected types.
    util::cvt(unsafe {
        libc::getsockopt(
            fd,
            level,
            mtu_opt,
            &mut mtu as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    })?;

    Ok(mtu as u32)
}

/// Payload size that makes a DF echo request exactly `mtu` bytes on the wire.
pub fn payload_for_mtu(mtu: usize, v6: bool) -> usize {
    let overhead = if v6 { V6_OVERHEAD } else { V4_OVERHEAD };
    mtu.saturating_sub(overhead)
}

/// Candidate MTUs to probe, largest first, covering the sizes that actually
/// occur: Ethernet, PPPoE, common VPN overheads, and the IPv6 floor.
pub fn candidate_mtus(interface_mtu: usize, v6: bool) -> Vec<usize> {
    let floor = if v6 { IPV6_MIN_MTU } else { 576 };
    let mut candidates: Vec<usize> = [
        interface_mtu,
        ETHERNET_MTU,
        1492, // PPPoE
        1480, // IPv4-in-IPv4
        1450, // common WireGuard/IPsec
        1420,
        1400,
        1280, // IPv6 minimum
        1024,
        576,
    ]
    .into_iter()
    // Probing above the local link MTU fails with EMSGSIZE before a packet
    // ever leaves the device, which says nothing about the path.
    .filter(|m| *m >= floor && *m <= interface_mtu)
    .collect();
    candidates.sort_unstable_by(|a, b| b.cmp(a));
    candidates.dedup();
    candidates
}

/// Probe the real path MTU by shrinking a DF echo until one gets through.
///
/// `interface_mtu` bounds the search: sending larger than the local link
/// allows fails locally with EMSGSIZE and tells us nothing about the path.
pub async fn discover(target: IpAddr, interface_mtu: u32, ctx: &ProbeContext) -> ProbeResult {
    let started = Instant::now();
    let v6 = target.is_ipv6();
    let interface_mtu = if interface_mtu == 0 {
        ETHERNET_MTU
    } else {
        interface_mtu as usize
    };

    // Start from what the kernel already knows, when it knows anything.
    let kernel_mtu = kernel_path_mtu(target, ctx).ok();

    let candidates = candidate_mtus(interface_mtu, v6);
    let mut largest_ok: Option<usize> = None;
    let mut smallest_failed: Option<usize> = None;

    for mtu in &candidates {
        let payload = payload_for_mtu(*mtu, v6);
        let result = icmp::ping(target, 1, payload, ctx).await;
        if result.ok {
            largest_ok = Some(*mtu);
            break;
        }
        smallest_failed = Some(*mtu);
    }

    let duration_ms = started.elapsed().as_millis() as u64;
    let mut evidence = vec![
        ("target".to_string(), target.to_string()),
        ("interface_mtu".to_string(), interface_mtu.to_string()),
        ("routing".to_string(), ctx.describe()),
        (
            "probed_sizes".to_string(),
            candidates
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ];
    if let Some(mtu) = kernel_mtu {
        evidence.push(("kernel_path_mtu".to_string(), mtu.to_string()));
    }

    let mut result = match (largest_ok, smallest_failed) {
        // Everything got through at full size: the path is clean.
        (Some(mtu), None) => ProbeResult::success(
            duration_ms,
            format!("{mtu} byte packets reach {target} without fragmentation"),
        ),
        // Something in between works: there is a smaller MTU on the path.
        (Some(ok), Some(failed)) => ProbeResult::failure(
            duration_ms,
            format!(
                "{failed} byte packets do not reach {target} but {ok} byte packets do; \
                 the path MTU is between {ok} and {failed}"
            ),
        ),
        // Nothing got through. Either ICMP is filtered outright (very common)
        // or the path is badly broken; say so rather than claiming an MTU.
        (None, _) => ProbeResult::failure(
            duration_ms,
            format!(
                "no echo reply from {target} at any size; ICMP is probably filtered, \
                 so path MTU could not be measured"
            ),
        ),
    };

    if let Some(mtu) = largest_ok {
        result = result.with("measured_path_mtu", mtu.to_string());
    }
    for (k, v) in evidence {
        result = result.with(k, v);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_accounts_for_headers() {
        assert_eq!(payload_for_mtu(1500, false), 1500 - 28);
        assert_eq!(payload_for_mtu(1500, true), 1500 - 48);
    }

    #[test]
    fn payload_never_underflows() {
        assert_eq!(payload_for_mtu(10, false), 0);
    }

    #[test]
    fn candidates_are_descending_and_deduped() {
        let candidates = candidate_mtus(1500, false);
        assert_eq!(candidates[0], 1500);
        let mut sorted = candidates.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(candidates, sorted);
        sorted.dedup();
        assert_eq!(candidates.len(), sorted.len());
    }

    #[test]
    fn v6_candidates_stop_at_the_minimum_mtu() {
        // Sending below 1280 on IPv6 is not a legal thing to discover.
        assert!(
            candidate_mtus(1500, true)
                .into_iter()
                .all(|m| m >= IPV6_MIN_MTU)
        );
    }

    #[test]
    fn a_small_interface_mtu_bounds_the_search() {
        // A 1400-byte link cannot send a 1500-byte probe at all.
        let candidates = candidate_mtus(1400, false);
        assert_eq!(candidates[0], 1400);
        assert!(!candidates.contains(&1500));
    }
}
