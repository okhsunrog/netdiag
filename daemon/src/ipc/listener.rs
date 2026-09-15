//! The listening socket.
//!
//! Two address forms are supported, because the right one depends on the
//! device's SELinux policy rather than on taste:
//!
//! * **Abstract namespace** (`@netdiag`) — no filesystem entry, so no labels
//!   to get wrong and nothing left behind if the daemon is killed. This is the
//!   default. It has no file permissions at all, which is exactly why the
//!   SO_PEERCRED check in [`super::auth`] is not optional.
//! * **Filesystem path** — a socket file the daemon chowns to the client's uid
//!   and chmods to 0600. Useful when the abstract namespace is blocked by
//!   policy, and when a socket inside the app's own data directory is easier
//!   to reason about than an SELinux rule.

use std::os::fd::AsRawFd;
// Abstract-namespace support lives under a different module per target even
// though the underlying kernel feature is identical.
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener as StdUnixListener};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::net::UnixListener;
use tracing::{info, warn};

use crate::util;

#[derive(Debug, Clone)]
pub enum SocketAddress {
    /// Leading '@' in the CLI argument.
    Abstract(String),
    Path(PathBuf),
}

impl SocketAddress {
    pub fn parse(spec: &str) -> Self {
        match spec.strip_prefix('@') {
            Some(name) => SocketAddress::Abstract(name.to_string()),
            None => SocketAddress::Path(PathBuf::from(spec)),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SocketAddress::Abstract(name) => format!("@{name} (abstract namespace)"),
            SocketAddress::Path(path) => path.display().to_string(),
        }
    }
}

/// Bind the listening socket, applying ownership and permissions where the
/// address form supports them.
pub fn bind(address: &SocketAddress, owner_uid: Option<u32>) -> Result<UnixListener> {
    let listener = match address {
        SocketAddress::Abstract(name) => {
            let addr = SocketAddr::from_abstract_name(name.as_bytes())
                .with_context(|| format!("invalid abstract socket name @{name}"))?;
            let std_listener = StdUnixListener::bind_addr(&addr)
                .with_context(|| format!("could not bind @{name}"))?;
            std_listener.set_nonblocking(true)?;
            UnixListener::from_std(std_listener)?
        }
        SocketAddress::Path(path) => {
            remove_stale_socket(path)?;
            if let Some(parent) = path.parent()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("could not create {} for the socket", parent.display())
                })?;
            }
            let std_listener = StdUnixListener::bind(path)
                .with_context(|| format!("could not bind {}", path.display()))?;
            std_listener.set_nonblocking(true)?;
            apply_permissions(path, owner_uid)?;
            UnixListener::from_std(std_listener)?
        }
    };

    info!("listening on {}", address.describe());
    Ok(listener)
}

/// A socket file left behind by a previous run blocks bind with EADDRINUSE.
/// Only remove it if nothing is actually listening, so two daemons cannot
/// silently steal the address from each other.
fn remove_stale_socket(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!("{} is already in use by a running daemon", path.display()),
        Err(_) => {
            warn!("removing the stale socket at {}", path.display());
            std::fs::remove_file(path)
                .with_context(|| format!("could not remove {}", path.display()))?;
            Ok(())
        }
    }
}

/// Hand the socket to the client's uid and make it readable by nobody else.
/// Filesystem permissions are a second line of defence; the peer credential
/// check is the first.
fn apply_permissions(path: &Path, owner_uid: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("could not chmod {}", path.display()))?;

    if let Some(uid) = owner_uid {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        // SAFETY: `c_path` is a valid NUL-terminated path for the call.
        util::cvt(unsafe { libc::chown(c_path.as_ptr(), uid, uid) })
            .with_context(|| format!("could not chown {} to uid {uid}", path.display()))?;
    }

    Ok(())
}

/// Best-effort cleanup on shutdown. An abstract socket disappears with the
/// process and needs nothing.
pub fn cleanup(address: &SocketAddress) {
    if let SocketAddress::Path(path) = address
        && path.exists()
        && let Err(e) = std::fs::remove_file(path)
    {
        warn!("could not remove {}: {e}", path.display());
    }
}

/// Log the fd number, which is occasionally the only way to tell two daemons
/// apart in a bug report.
pub fn describe_listener(listener: &UnixListener) -> String {
    format!("fd {}", listener.as_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_abstract_and_filesystem_addresses() {
        match SocketAddress::parse("@netdiag") {
            SocketAddress::Abstract(name) => assert_eq!(name, "netdiag"),
            other => panic!("expected an abstract address, got {other:?}"),
        }
        match SocketAddress::parse("/data/local/tmp/netdiag.sock") {
            SocketAddress::Path(path) => {
                assert_eq!(path, PathBuf::from("/data/local/tmp/netdiag.sock"));
            }
            other => panic!("expected a path address, got {other:?}"),
        }
    }

    #[test]
    fn descriptions_are_unambiguous() {
        assert!(
            SocketAddress::parse("@netdiag")
                .describe()
                .contains("abstract")
        );
        assert_eq!(
            SocketAddress::parse("/tmp/x.sock").describe(),
            "/tmp/x.sock"
        );
    }

    #[tokio::test]
    async fn binds_and_accepts_on_an_abstract_socket() {
        let name = format!("netdiag-test-{}", std::process::id());
        let address = SocketAddress::parse(&format!("@{name}"));
        let listener = bind(&address, None).expect("bind should succeed");

        let connect_name = name.clone();
        let client = tokio::spawn(async move {
            let addr = SocketAddr::from_abstract_name(connect_name.as_bytes()).unwrap();
            std::os::unix::net::UnixStream::connect_addr(&addr).is_ok()
        });

        let (_stream, _addr) = listener.accept().await.expect("accept should succeed");
        assert!(client.await.unwrap());
    }

    #[tokio::test]
    async fn refuses_to_replace_a_live_filesystem_socket() {
        let dir = std::env::temp_dir().join(format!("netdiag-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("live.sock");
        let address = SocketAddress::Path(path.clone());

        let _first = bind(&address, None).expect("first bind should succeed");
        let second = bind(&address, None);
        assert!(
            second.is_err(),
            "a second daemon must not steal the address"
        );

        cleanup(&address);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn removes_a_stale_socket_file() {
        let dir = std::env::temp_dir().join(format!("netdiag-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stale.sock");
        // A plain file where the socket should be: nothing is listening.
        std::fs::write(&path, b"stale").unwrap();

        let address = SocketAddress::Path(path.clone());
        let listener = bind(&address, None);
        assert!(
            listener.is_ok(),
            "a stale file should be cleared: {listener:?}"
        );

        cleanup(&address);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
