//! TCP connect probes.
//!
//! Distinguishing "no route" from "timed out" from "refused" is most of the
//! diagnostic value here, so the probe reports the errno rather than a bare
//! success flag: ENETUNREACH means the kernel would not even try, ETIMEDOUT
//! means the SYN left and nothing came back, ECONNREFUSED means something on
//! the path answered.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Instant;

use tokio::net::TcpSocket;

use super::{ProbeContext, ProbeResult, apply_context, explain_io_error};

pub async fn connect(target: SocketAddr, ctx: &ProbeContext) -> ProbeResult {
    let started = Instant::now();

    let socket = match if target.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    } {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult::failure(
                started.elapsed().as_millis() as u64,
                format!("could not create a socket: {}", explain_io_error(&e)),
            );
        }
    };

    if let Err(e) = apply_context(socket.as_raw_fd(), ctx) {
        return ProbeResult::failure(
            started.elapsed().as_millis() as u64,
            format!("could not pin the socket to the network under test: {e}"),
        )
        .with("routing", ctx.describe());
    }

    if let Some(source) = ctx.source {
        let bind_addr = SocketAddr::new(source, 0);
        if let Err(e) = socket.bind(bind_addr) {
            return ProbeResult::failure(
                started.elapsed().as_millis() as u64,
                format!(
                    "could not bind to source {source}: {}",
                    explain_io_error(&e)
                ),
            )
            .with("routing", ctx.describe());
        }
    }

    let result = tokio::time::timeout(ctx.timeout, socket.connect(target)).await;
    let duration_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(stream)) => {
            let local = stream
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".to_string());
            ProbeResult::success(
                duration_ms,
                format!("connected to {target} in {duration_ms} ms"),
            )
            .with("target", target.to_string())
            .with("local", local)
            .with("routing", ctx.describe())
        }
        Ok(Err(e)) => ProbeResult::failure(
            duration_ms,
            format!("connect to {target} failed: {}", explain_io_error(&e)),
        )
        .with("target", target.to_string())
        .with(
            "errno",
            e.raw_os_error().map(|n| n.to_string()).unwrap_or_default(),
        )
        .with("routing", ctx.describe()),
        Err(_) => ProbeResult::failure(
            duration_ms,
            format!(
                "connect to {target} timed out after {} ms with no SYN-ACK",
                ctx.timeout.as_millis()
            ),
        )
        .with("target", target.to_string())
        .with("routing", ctx.describe()),
    }
}

/// Open a connection and hand back the stream, for probes that need to keep
/// talking (the TLS handshake check).
pub async fn connect_stream(
    target: SocketAddr,
    ctx: &ProbeContext,
) -> std::io::Result<tokio::net::TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    apply_context(socket.as_raw_fd(), ctx).map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(source) = ctx.source {
        socket.bind(SocketAddr::new(source, 0))?;
    }
    tokio::time::timeout(ctx.timeout, socket.connect(target))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn connects_to_a_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let ctx = ProbeContext {
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let result = connect(addr, &ctx).await;
        assert!(result.ok, "{}", result.detail);
    }

    #[tokio::test]
    async fn refused_connections_are_reported_as_such() {
        // Bind and immediately drop, so the port is almost certainly closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let ctx = ProbeContext {
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let result = connect(addr, &ctx).await;
        assert!(!result.ok);
        assert!(
            result.detail.contains("refused") || result.detail.contains("timed out"),
            "unexpected detail: {}",
            result.detail
        );
    }
}
