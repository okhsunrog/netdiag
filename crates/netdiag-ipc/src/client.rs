//! Rust client for the daemon.
//!
//! Mirrors what the Kotlin client does, for the same reasons: one socket
//! carries every call, requests are tagged with a client-assigned id, and a
//! single reader task fans replies back to whoever is waiting on that id. A
//! slow `Diagnose` therefore never blocks a live `WatchNetwork` sharing the
//! connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

use crate::codec;
use crate::proto;

/// The abstract-namespace socket the daemon binds by default.
pub const DEFAULT_SOCKET_NAME: &str = "netdiag";

/// Depth of a per-call reply queue. Streaming calls can burst (capture), so
/// this is deeper than a unary call would need.
const REPLY_QUEUE_DEPTH: usize = 256;

type Pending = Arc<Mutex<HashMap<u64, mpsc::Sender<proto::ServerFrame>>>>;

/// A connected daemon client.
pub struct DaemonClient {
    writer: Mutex<WriteHalf<UnixStream>>,
    pending: Pending,
    next_id: AtomicU64,
    /// Filled in once the handshake completes. It cannot be a plain field
    /// because the handshake is itself a request, which needs the client to
    /// already exist.
    hello: std::sync::OnceLock<proto::HelloResponse>,
}

impl DaemonClient {
    /// Connect to an abstract-namespace socket and complete the handshake.
    ///
    /// The daemon refuses every other request until Hello has been exchanged,
    /// so this is not optional.
    pub async fn connect(socket_name: &str, client_version: &str) -> Result<Arc<Self>> {
        let stream = connect_abstract(socket_name)
            .await
            .with_context(|| format!("could not connect to @{socket_name}"))?;

        let (reader, writer) = tokio::io::split(stream);
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));

        let client = Arc::new(Self {
            writer: Mutex::new(writer),
            pending: pending.clone(),
            next_id: AtomicU64::new(1),
            hello: std::sync::OnceLock::new(),
        });

        tokio::spawn(read_loop(reader, pending));

        let frame = client
            .unary(proto::client_frame::Body::Hello(proto::HelloRequest {
                protocol_version: proto::PROTOCOL_VERSION,
                client_name: "netdiag-slint".to_string(),
                client_version: client_version.to_string(),
            }))
            .await?;

        match frame.body {
            Some(proto::server_frame::Body::Hello(hello)) => {
                let _ = client.hello.set(hello);
            }
            other => bail!("expected a Hello response, got {other:?}"),
        }

        Ok(client)
    }

    /// The daemon's handshake response: version, kernel release and which
    /// capabilities it actually has on this device.
    pub fn hello(&self) -> &proto::HelloResponse {
        self.hello.get().expect("handshake completed in connect()")
    }

    /// Is anything listening on that socket?
    ///
    /// Connecting and dropping is both cheaper and more reliable than parsing
    /// `ps` output, and it tests the thing that actually matters.
    pub async fn probe(socket_name: &str) -> bool {
        connect_abstract(socket_name).await.is_ok()
    }

    /// Send a request and wait for its single reply.
    pub async fn unary(&self, body: proto::client_frame::Body) -> Result<proto::ServerFrame> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel(REPLY_QUEUE_DEPTH);
        self.pending.lock().await.insert(id, tx);

        let result = async {
            self.send(proto::ClientFrame {
                id,
                body: Some(body),
            })
            .await?;
            let frame = rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("the connection closed before a reply arrived"))?;
            check_error(&frame)?;
            Ok(frame)
        }
        .await;

        self.pending.lock().await.remove(&id);
        result
    }

    /// Start a streaming call. Frames arrive on the returned receiver until the
    /// daemon sends `stream_end`, at which point the channel closes.
    ///
    /// Dropping the receiver is not enough to stop the daemon — the socket
    /// stays open for other calls — so [`Self::cancel`] must be called with the
    /// returned id to stop a stream early. Leaving a capture running as root
    /// because a UI screen was closed is exactly the failure this avoids.
    pub async fn stream(
        self: &Arc<Self>,
        body: proto::client_frame::Body,
    ) -> Result<(u64, mpsc::Receiver<proto::ServerFrame>)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (raw_tx, mut raw_rx) = mpsc::channel(REPLY_QUEUE_DEPTH);
        self.pending.lock().await.insert(id, raw_tx);

        self.send(proto::ClientFrame {
            id,
            body: Some(body),
        })
        .await?;

        // Translate the raw frames into a stream that ends at stream_end, so
        // callers never have to special-case the terminator.
        let (tx, rx) = mpsc::channel(REPLY_QUEUE_DEPTH);
        let pending = self.pending.clone();
        tokio::spawn(async move {
            while let Some(frame) = raw_rx.recv().await {
                if let Some(proto::server_frame::Body::StreamEnd(end)) = &frame.body {
                    if let Some(error) = &end.error {
                        debug!("stream {id} ended with an error: {}", error.message);
                    }
                    break;
                }
                if tx.send(frame).await.is_err() {
                    break;
                }
            }
            pending.lock().await.remove(&id);
        });

        Ok((id, rx))
    }

    /// Tell the daemon to stop a stream.
    pub async fn cancel(&self, target_id: u64) -> Result<()> {
        self.unary(proto::client_frame::Body::Cancel(proto::CancelRequest {
            target_id,
        }))
        .await?;
        Ok(())
    }

    async fn send(&self, frame: proto::ClientFrame) -> Result<()> {
        let mut writer = self.writer.lock().await;
        codec::write_frame(&mut *writer, &frame).await
    }

    pub async fn shutdown(&self) {
        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
    }
}

fn check_error(frame: &proto::ServerFrame) -> Result<()> {
    if let Some(proto::server_frame::Body::Error(error)) = &frame.body {
        bail!("{} ({:?})", error.message, error.code());
    }
    Ok(())
}

async fn read_loop(mut reader: ReadHalf<UnixStream>, pending: Pending) {
    loop {
        match codec::read_frame::<proto::ServerFrame, _>(&mut reader).await {
            Ok(Some(frame)) => {
                let sender = pending.lock().await.get(&frame.id).cloned();
                match sender {
                    // A late frame for a call already abandoned: expected
                    // between cancelling a stream and its stream_end arriving.
                    None => debug!("dropping a frame for unknown request {}", frame.id),
                    Some(sender) => {
                        if sender.send(frame).await.is_err() {
                            // Receiver gone; the entry is cleaned up by whoever
                            // owns it.
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                debug!("the daemon connection dropped: {e}");
                break;
            }
        }
    }
    pending.lock().await.clear();
}

/// Connect to a socket in the Linux abstract namespace.
///
/// Tokio has no API for this, so the address is built by hand: an abstract
/// address is `sun_path[0] == 0` followed by the name, with the length
/// covering exactly the name and that leading NUL.
async fn connect_abstract(name: &str) -> Result<UnixStream> {
    use std::os::unix::io::FromRawFd;

    let bytes = name.as_bytes();
    // sun_path is 108 bytes and the first is the leading NUL.
    if bytes.len() >= 107 {
        bail!("abstract socket name is too long");
    }

    // SAFETY: a zeroed sockaddr_un is valid; the family and path are filled in
    // below and the length passed to connect covers only what was written.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in bytes.iter().enumerate() {
        addr.sun_path[index + 1] = *byte as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()) as libc::socklen_t;

    // SAFETY: plain socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_UNIX) failed");
    }

    // SAFETY: `addr` is a valid sockaddr_un and `len` describes the bytes
    // actually written into it.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            len,
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: `fd` is ours and is not used again.
        unsafe { libc::close(fd) };
        return Err(error).context("connect to the daemon socket failed");
    }

    // SAFETY: `fd` is a connected AF_UNIX stream socket that we exclusively own.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    UnixStream::from_std(std_stream).context("could not register the socket with tokio")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_over_long_abstract_name() {
        let name = "x".repeat(200);
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(connect_abstract(&name));
        assert!(result.is_err());
    }
}
