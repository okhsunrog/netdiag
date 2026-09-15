//! Active probes.
//!
//! Every probe can be pinned to a specific Android Network. That matters more
//! than it sounds: on a device with Wi-Fi and cellular both up, an unmarked
//! socket takes the default network, so probing "is IPv6 broken?" without
//! pinning tells you about whichever network won, not the one the user is
//! asking about. Setting SO_MARK to the netId's fwmark makes netd's routing
//! rules send the probe over exactly the network under test, and
//! SO_BINDTODEVICE pins the egress interface when a mark is not enough.
//!
//! Setting SO_MARK needs CAP_NET_ADMIN, which is precisely why these probes
//! live in the root daemon rather than in the app.

pub mod dns;
pub mod icmp;
pub mod mtu;
pub mod tcp;
pub mod tls;

use std::os::fd::RawFd;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::util;

/// How a probe should be routed.
#[derive(Debug, Clone, Default)]
pub struct ProbeContext {
    /// SO_MARK to set. Built from an Android netId via `util::mark_for_net_id`.
    pub mark: Option<u32>,
    /// SO_BINDTODEVICE interface name.
    pub bind_device: Option<String>,
    /// Source address to bind to, when a specific address must be exercised
    /// (e.g. testing a temporary IPv6 address rather than the stable one).
    pub source: Option<std::net::IpAddr>,
    pub timeout: Duration,
}

impl ProbeContext {
    pub fn with_timeout(timeout_ms: u32) -> Self {
        Self {
            timeout: Duration::from_millis(if timeout_ms == 0 {
                DEFAULT_TIMEOUT_MS
            } else {
                timeout_ms as u64
            }),
            ..Default::default()
        }
    }

    pub fn pinned_to_net_id(mut self, net_id: i32) -> Self {
        if net_id > 0 {
            self.mark = Some(util::mark_for_net_id(net_id as u32));
        }
        self
    }

    pub fn on_device(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !name.is_empty() {
            self.bind_device = Some(name);
        }
        self
    }

    /// Short description used in check evidence so a reader can tell how the
    /// probe was routed.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(mark) = self.mark {
            parts.push(format!(
                "mark=0x{mark:x} (netId {})",
                util::net_id_from_mark(mark)
            ));
        }
        if let Some(dev) = &self.bind_device {
            parts.push(format!("dev={dev}"));
        }
        if let Some(src) = &self.source {
            parts.push(format!("src={src}"));
        }
        if parts.is_empty() {
            "default network".to_string()
        } else {
            parts.join(" ")
        }
    }
}

pub const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Apply the routing context to a socket that has been created but not yet
/// connected or bound.
pub fn apply_context(fd: RawFd, ctx: &ProbeContext) -> Result<()> {
    if let Some(mark) = ctx.mark {
        set_mark(fd, mark).context("SO_MARK failed; probes cannot be pinned to a network")?;
    }
    if let Some(dev) = &ctx.bind_device {
        bind_to_device(fd, dev).with_context(|| format!("SO_BINDTODEVICE({dev}) failed"))?;
    }
    Ok(())
}

pub fn set_mark(fd: RawFd, mark: u32) -> std::io::Result<()> {
    // SAFETY: `fd` is a valid socket for the duration of the call, and the
    // option value is a properly sized u32.
    util::cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

pub fn bind_to_device(fd: RawFd, name: &str) -> std::io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: the pointer and length describe a valid, initialised byte slice.
    util::cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len() as libc::socklen_t,
        )
    })?;
    Ok(())
}

/// Outcome shared by all probes so the diagnosis engine can treat them
/// uniformly.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub ok: bool,
    pub duration_ms: u64,
    /// One-line human summary, e.g. "connected in 42 ms" or "timed out".
    pub detail: String,
    /// Structured detail merged into the check's evidence map.
    pub evidence: Vec<(String, String)>,
    pub error: Option<String>,
}

impl ProbeResult {
    pub fn success(duration_ms: u64, detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            duration_ms,
            detail: detail.into(),
            evidence: Vec::new(),
            error: None,
        }
    }

    pub fn failure(duration_ms: u64, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            ok: false,
            duration_ms,
            detail: detail.clone(),
            evidence: Vec::new(),
            error: Some(detail),
        }
    }

    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push((key.into(), value.into()));
        self
    }

    /// The failure reason as a protobuf error, for checks that carry one.
    pub fn to_error(&self) -> Option<crate::proto::Error> {
        self.error
            .as_ref()
            .map(|e| crate::proto::Error::kernel(e.clone()))
    }
}

/// Translate an io error into the language a user can act on. "Network is
/// unreachable" and "connection timed out" mean very different things: the
/// first is a local routing problem, the second is somewhere out on the path.
pub fn explain_io_error(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENETUNREACH) => {
            "network unreachable (no route for this family on this network)".to_string()
        }
        Some(libc::EHOSTUNREACH) => "host unreachable (ICMP said so, or no neighbour)".to_string(),
        Some(libc::ECONNREFUSED) => {
            "connection refused (something answered, and said no)".to_string()
        }
        Some(libc::EACCES) | Some(libc::EPERM) => {
            "permission denied (firewall or SELinux blocked the socket)".to_string()
        }
        Some(libc::EADDRNOTAVAIL) => "source address not available on this interface".to_string(),
        Some(libc::ETIMEDOUT) => "timed out with no response".to_string(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_describes_its_pinning() {
        let ctx = ProbeContext::with_timeout(0)
            .pinned_to_net_id(101)
            .on_device("wlan0");
        let text = ctx.describe();
        assert!(text.contains("netId 101"), "{text}");
        assert!(text.contains("wlan0"), "{text}");
    }

    #[test]
    fn unpinned_context_says_so() {
        assert_eq!(ProbeContext::with_timeout(0).describe(), "default network");
    }

    #[test]
    fn net_id_zero_does_not_set_a_mark() {
        // netId 0 means "no network", not "network zero"; marking with it
        // would route the probe into a table that does not exist.
        assert!(
            ProbeContext::with_timeout(0)
                .pinned_to_net_id(0)
                .mark
                .is_none()
        );
    }

    #[test]
    fn default_timeout_is_applied() {
        assert_eq!(
            ProbeContext::with_timeout(0).timeout,
            Duration::from_millis(DEFAULT_TIMEOUT_MS)
        );
        assert_eq!(
            ProbeContext::with_timeout(500).timeout,
            Duration::from_millis(500)
        );
    }
}
