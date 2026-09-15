//! Peer authorization.
//!
//! The daemon runs as root, so anything that can reach its socket can ask it
//! to dump every socket on the device. Access is therefore decided from the
//! kernel-supplied peer credentials (SO_PEERCRED), never from anything the
//! client sends in a message: a client can lie about its identity in a
//! protobuf field, it cannot lie to the kernel about its uid.
//!
//! On an abstract-namespace socket there are no filesystem permissions at all,
//! which makes this check the only thing standing between the daemon and every
//! other process on the device.

use anyhow::{Context, Result, bail};
use tokio::net::UnixStream;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    /// argv[0] of the peer, read from /proc. Advisory only: it is used to make
    /// log lines useful and to enforce `expect_package`, never as the sole
    /// basis for granting access.
    pub cmdline: Option<String>,
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "uid={} gid={}", self.uid, self.gid)?;
        if let Some(pid) = self.pid {
            write!(f, " pid={pid}")?;
        }
        if let Some(cmd) = &self.cmdline {
            write!(f, " cmdline={cmd}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthPolicy {
    /// UIDs allowed to connect. Empty means "root only", which is the safe
    /// default if the operator forgot to pass --allow-uid.
    pub allowed_uids: Vec<u32>,
    /// When set, the peer's /proc/<pid>/cmdline must equal this package name.
    /// Android names an app's main process after its package, so this catches
    /// the case where a different app happens to share a uid.
    pub expect_package: Option<String>,
}

impl AuthPolicy {
    pub fn describe(&self) -> String {
        let mut uids: Vec<String> = self.allowed_uids.iter().map(|u| u.to_string()).collect();
        if uids.is_empty() {
            uids.push("0".to_string());
        }
        let mut s = format!("uids=[{}]", uids.join(","));
        if let Some(pkg) = &self.expect_package {
            s.push_str(&format!(" package={pkg}"));
        }
        s
    }

    fn uid_allowed(&self, uid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        self.allowed_uids.contains(&uid)
    }
}

/// Read the peer's credentials and decide whether to keep talking to it.
pub fn authorize(stream: &UnixStream, policy: &AuthPolicy) -> Result<PeerIdentity> {
    let cred = stream
        .peer_cred()
        .context("SO_PEERCRED failed; refusing the connection")?;

    let pid = cred.pid();
    let identity = PeerIdentity {
        uid: cred.uid(),
        gid: cred.gid(),
        pid,
        cmdline: pid.and_then(read_cmdline),
    };

    if !policy.uid_allowed(identity.uid) {
        bail!(
            "peer {identity} is not in the allowed uid set ({})",
            policy.describe()
        );
    }

    if let Some(expected) = &policy.expect_package {
        match &identity.cmdline {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                bail!("peer {identity} runs as {actual}, expected {expected}");
            }
            None => {
                // Not fatal on its own: /proc may be unreadable for the peer's
                // pid, and the uid check has already passed.
                warn!("could not read cmdline for peer {identity}; accepting on uid alone");
            }
        }
    }

    Ok(identity)
}

/// argv[0] from /proc/<pid>/cmdline, which on Android is the process name and
/// therefore usually the package name.
fn read_cmdline(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first = raw.split(|b| *b == 0).next()?;
    if first.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(first).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_always_allowed() {
        let policy = AuthPolicy::default();
        assert!(policy.uid_allowed(0));
    }

    #[test]
    fn unlisted_app_uid_is_rejected() {
        let policy = AuthPolicy {
            allowed_uids: vec![10342],
            ..Default::default()
        };
        assert!(policy.uid_allowed(10342));
        assert!(!policy.uid_allowed(10999));
    }

    #[test]
    fn empty_allowlist_means_root_only() {
        let policy = AuthPolicy::default();
        assert!(!policy.uid_allowed(10342));
    }
}
