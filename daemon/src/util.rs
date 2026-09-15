//! Small shared helpers: clocks, /proc readers, Android fwmark decoding.

use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds. Used for display and for correlating with the
/// framework's own timestamps.
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Monotonic nanoseconds since boot. Event ordering uses this so a clock jump
/// (common right after a network comes up and NTP corrects the time) cannot
/// reorder the timeline.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the call.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Read a file, trim it, and return None on any error. Almost everything under
/// /proc and /sys is optional depending on kernel config and SELinux policy, so
/// a missing file is normal rather than exceptional.
pub fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn read_i32(path: impl AsRef<Path>) -> Option<i32> {
    read_trimmed(path)?.split_whitespace().next()?.parse().ok()
}

pub fn kernel_release() -> String {
    read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_default()
}

/// Android's fwmark layout (see system/netd/include/Fwmark.h).
///
/// ```text
///   bits  0..15  netId
///   bit  16      explicitlySelected
///   bit  17      protectedFromVpn
///   bits 18..19  permission
///   bit  20      uidBillingDone
/// ```
///
/// Rules installed by netd match on `fwmark & mask`, so recovering the netId
/// from a socket's SO_MARK is what lets us say "this socket is pinned to
/// Network 101".
pub const FWMARK_NET_ID_MASK: u32 = 0xffff;
pub const FWMARK_EXPLICITLY_SELECTED: u32 = 1 << 16;
pub const FWMARK_PROTECTED_FROM_VPN: u32 = 1 << 17;

pub fn net_id_from_mark(mark: u32) -> u32 {
    mark & FWMARK_NET_ID_MASK
}

/// Build the fwmark a socket would carry if it were pinned to `net_id`.
/// Probes use this with SO_MARK to send traffic over a chosen Network.
pub fn mark_for_net_id(net_id: u32) -> u32 {
    (net_id & FWMARK_NET_ID_MASK) | FWMARK_EXPLICITLY_SELECTED
}

/// Well-known Linux routing table ids. Android additionally allocates one
/// table per Network, normally numbered the same as the netId (97..) plus a
/// few fixed ones for local networks and VPN fallthrough.
pub fn well_known_table_name(table: u32) -> Option<&'static str> {
    match table {
        255 => Some("local"),
        254 => Some("main"),
        253 => Some("default"),
        0 => Some("unspec"),
        // netd's fixed allocations.
        97 => Some("local_network"),
        98 => Some("legacy_system"),
        99 => Some("legacy_network"),
        1003 => Some("vpn_fallthrough"),
        _ => None,
    }
}

/// Wrap a libc call that returns -1 on error.
pub fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Format a byte slice as a MAC address, or an empty string when it is not one.
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Duration helper used for check timings.
pub struct Stopwatch(std::time::Instant);

impl Stopwatch {
    pub fn start() -> Self {
        Self(std::time::Instant::now())
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}
