//! One client connection.
//!
//! Frames are read in a loop and dispatched concurrently, so a three-second
//! Diagnose does not block a Watch subscription on the same socket. All
//! outbound frames funnel through a single writer task, which is what makes
//! interleaved streams safe without a mutex around the socket.
//!
//! Streaming calls are tracked by their client-assigned id so `Cancel` can
//! find and stop them, and so dropping the connection tears them all down
//! rather than leaving a capture running as root forever.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};

use super::auth::PeerIdentity;
use super::codec;
use crate::daemon::Daemon;
use crate::proto;

/// Depth of the per-connection outbound queue. Deep enough to absorb a burst
/// of capture packets, shallow enough that a stalled client is noticed.
const WRITE_QUEUE_DEPTH: usize = 512;

/// Cap on concurrent streaming calls per connection, so one client cannot open
/// a thousand captures.
const MAX_STREAMS: usize = 16;

#[derive(Clone)]
pub struct Responder {
    tx: mpsc::Sender<proto::ServerFrame>,
}

impl Responder {
    /// Queue a frame. Returns false when the client is gone or too slow.
    pub async fn send(&self, frame: proto::ServerFrame) -> bool {
        self.tx.send(frame).await.is_ok()
    }

    pub async fn reply(&self, id: u64, body: proto::server_frame::Body) -> bool {
        self.send(proto::ServerFrame {
            id,
            body: Some(body),
        })
        .await
    }

    pub async fn error(&self, id: u64, error: proto::Error) -> bool {
        warn!(
            id,
            "replying with error: {} {}", error.message, error.detail
        );
        self.reply(id, proto::server_frame::Body::Error(error))
            .await
    }

    /// Terminate a stream. Every streaming call ends with exactly one of these,
    /// including when it ends because of an error.
    pub async fn end_stream(
        &self,
        id: u64,
        reason: &str,
        items_sent: u64,
        error: Option<proto::Error>,
    ) -> bool {
        self.reply(
            id,
            proto::server_frame::Body::StreamEnd(proto::StreamEnd {
                error,
                reason: reason.to_string(),
                items_sent,
            }),
        )
        .await
    }
}

struct StreamRegistry {
    streams: Mutex<HashMap<u64, AbortHandle>>,
}

impl StreamRegistry {
    fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
        }
    }

    async fn insert(&self, id: u64, handle: AbortHandle) -> Result<(), proto::Error> {
        let mut streams = self.streams.lock().await;
        if streams.len() >= MAX_STREAMS {
            return Err(proto::Error::new(
                proto::ErrorCode::ResourceExhausted,
                format!("too many concurrent streams (limit {MAX_STREAMS})"),
            ));
        }
        if let Some(previous) = streams.insert(id, handle) {
            // Reusing an in-flight id is a client bug; stop the old stream
            // rather than leaking it.
            previous.abort();
        }
        Ok(())
    }

    async fn remove(&self, id: u64) {
        self.streams.lock().await.remove(&id);
    }

    async fn cancel(&self, id: u64) -> bool {
        match self.streams.lock().await.remove(&id) {
            Some(handle) => {
                handle.abort();
                true
            }
            None => false,
        }
    }

    async fn abort_all(&self) {
        let mut streams = self.streams.lock().await;
        for (_, handle) in streams.drain() {
            handle.abort();
        }
    }
}

/// Serve one authorized connection until the client disconnects.
pub async fn serve(
    stream: tokio::net::UnixStream,
    peer: PeerIdentity,
    daemon: Arc<Daemon>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<proto::ServerFrame>(WRITE_QUEUE_DEPTH);

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Err(e) = codec::write_frame(&mut writer, &frame).await {
                debug!("write failed, closing the connection: {e}");
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let responder = Responder { tx };
    let registry = Arc::new(StreamRegistry::new());
    let handled = AtomicU64::new(0);

    // A client must say hello before anything else, so version mismatches are
    // reported as a clean error rather than as a confusing schema failure
    // later on.
    let mut greeted = false;

    loop {
        let frame: Option<proto::ClientFrame> = match codec::read_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(e) => {
                debug!("malformed frame from {peer}: {e}");
                let _ = responder
                    .error(
                        0,
                        proto::Error::invalid("malformed frame").with_detail(e.to_string()),
                    )
                    .await;
                break;
            }
        };
        let Some(frame) = frame else {
            break;
        };

        let id = frame.id;
        let Some(body) = frame.body else {
            let _ = responder
                .error(id, proto::Error::invalid("frame carries no request"))
                .await;
            continue;
        };

        if id == 0 {
            let _ = responder
                .error(0, proto::Error::invalid("request id must not be zero"))
                .await;
            continue;
        }

        handled.fetch_add(1, Ordering::Relaxed);

        // Hello and Cancel are handled inline: they are trivial and must not
        // race with the calls they describe.
        match body {
            proto::client_frame::Body::Hello(request) => {
                greeted = true;
                let response = daemon.hello(&request);
                responder
                    .reply(id, proto::server_frame::Body::Hello(response))
                    .await;
                continue;
            }
            proto::client_frame::Body::Cancel(request) => {
                let was_active = registry.cancel(request.target_id).await;
                if was_active {
                    responder
                        .end_stream(request.target_id, "cancelled by the client", 0, None)
                        .await;
                }
                responder
                    .reply(
                        id,
                        proto::server_frame::Body::Cancel(proto::CancelResponse { was_active }),
                    )
                    .await;
                continue;
            }
            other => {
                if !greeted {
                    let _ = responder
                        .error(
                            id,
                            proto::Error::invalid(
                                "send Hello before any other request so versions can be checked",
                            ),
                        )
                        .await;
                    continue;
                }
                dispatch(id, other, &daemon, &responder, &registry, &peer).await;
            }
        }
    }

    registry.abort_all().await;
    drop(responder);
    let _ = writer_task.await;
    info!(
        "connection from {peer} closed after {} request(s)",
        handled.load(Ordering::Relaxed)
    );
    Ok(())
}

async fn dispatch(
    id: u64,
    body: proto::client_frame::Body,
    daemon: &Arc<Daemon>,
    responder: &Responder,
    registry: &Arc<StreamRegistry>,
    peer: &PeerIdentity,
) {
    use proto::client_frame::Body as B;
    use proto::server_frame::Body as R;

    // Unary calls run detached so a slow one cannot block the read loop. Each
    // arm resolves its own response body; `spawn_unary` handles the shared
    // reply-or-error plumbing.
    match body {
        B::GetSnapshot(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_snapshot(request).await.map(R::GetSnapshot)
            });
        }
        B::GetInterfaces(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_interfaces(request).await.map(R::GetInterfaces)
            });
        }
        B::GetRoutes(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_routes(request).await.map(R::GetRoutes)
            });
        }
        B::GetRoutingRules(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_routing_rules(request).await.map(R::GetRoutingRules)
            });
        }
        B::GetNeighbors(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_neighbors(request).await.map(R::GetNeighbors)
            });
        }
        B::GetSockets(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_sockets(request).await.map(R::GetSockets)
            });
        }
        B::GetAppNetworkState(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.get_app_network_state(request)
                    .await
                    .map(R::GetAppNetworkState)
            });
        }
        B::RouteLookup(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.route_lookup(request).await.map(R::RouteLookup)
            });
        }
        B::PushFrameworkEvent(request) => {
            spawn_unary(id, daemon, responder, move |d| async move {
                d.push_framework_event(request)
                    .await
                    .map(R::PushFrameworkEvent)
            });
        }

        // Streaming calls.
        B::Diagnose(request) => {
            spawn_stream(id, daemon, responder, registry, move |daemon, responder| {
                Box::pin(async move { daemon.diagnose_stream(id, request, responder).await })
            })
            .await;
        }
        B::WatchNetwork(request) => {
            spawn_stream(id, daemon, responder, registry, move |daemon, responder| {
                Box::pin(async move { daemon.watch_network(id, request, responder).await })
            })
            .await;
        }
        B::WatchRoutes(request) => {
            spawn_stream(id, daemon, responder, registry, move |daemon, responder| {
                Box::pin(async move { daemon.watch_routes(id, request, responder).await })
            })
            .await;
        }
        B::WatchSockets(request) => {
            spawn_stream(id, daemon, responder, registry, move |daemon, responder| {
                Box::pin(async move { daemon.watch_sockets(id, request, responder).await })
            })
            .await;
        }
        B::StartCapture(request) => {
            info!(
                "{peer} started a packet capture on '{}'",
                request.interface_name
            );
            spawn_stream(id, daemon, responder, registry, move |daemon, responder| {
                Box::pin(async move { daemon.start_capture(id, request, responder).await })
            })
            .await;
        }
        B::StopCapture(request) => {
            let stopped = registry.cancel(request.capture_id).await
                || daemon.stop_capture(request.capture_id).await;
            if stopped {
                responder
                    .end_stream(request.capture_id, "stopped by the client", 0, None)
                    .await;
                responder
                    .reply(
                        id,
                        proto::server_frame::Body::CaptureFinished(proto::CaptureFinished {
                            capture_id: request.capture_id,
                            reason: "stopped".to_string(),
                            ..Default::default()
                        }),
                    )
                    .await;
            } else {
                responder
                    .error(
                        id,
                        proto::Error::not_found(format!(
                            "no capture with id {}",
                            request.capture_id
                        )),
                    )
                    .await;
            }
        }

        // Handled by the caller.
        B::Hello(_) | B::Cancel(_) => {}
    }
}

/// Run a unary call on its own task and reply with either its body or an error.
fn spawn_unary<F, Fut>(id: u64, daemon: &Arc<Daemon>, responder: &Responder, call: F)
where
    F: FnOnce(Arc<Daemon>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<proto::server_frame::Body, proto::Error>> + Send,
{
    let daemon = daemon.clone();
    let responder = responder.clone();
    tokio::spawn(async move {
        match call(daemon).await {
            Ok(body) => responder.reply(id, body).await,
            Err(error) => responder.error(id, error).await,
        };
    });
}

type StreamFuture = std::pin::Pin<Box<dyn std::future::Future<Output = StreamOutcome> + Send>>;

/// How a streaming call ended, so the session can send an accurate StreamEnd.
pub struct StreamOutcome {
    pub reason: String,
    pub items_sent: u64,
    pub error: Option<proto::Error>,
}

impl StreamOutcome {
    pub fn done(reason: impl Into<String>, items_sent: u64) -> Self {
        Self {
            reason: reason.into(),
            items_sent,
            error: None,
        }
    }

    pub fn failed(error: proto::Error, items_sent: u64) -> Self {
        Self {
            reason: "error".to_string(),
            items_sent,
            error: Some(error),
        }
    }
}

async fn spawn_stream<F>(
    id: u64,
    daemon: &Arc<Daemon>,
    responder: &Responder,
    registry: &Arc<StreamRegistry>,
    body: F,
) where
    F: FnOnce(Arc<Daemon>, Responder) -> StreamFuture + Send + 'static,
{
    let daemon = daemon.clone();
    let responder_for_task = responder.clone();
    let registry_for_task = registry.clone();

    let task = tokio::spawn(async move {
        let outcome = body(daemon, responder_for_task.clone()).await;
        responder_for_task
            .end_stream(id, &outcome.reason, outcome.items_sent, outcome.error)
            .await;
        registry_for_task.remove(id).await;
    });

    if let Err(error) = registry.insert(id, task.abort_handle()).await {
        task.abort();
        responder.error(id, error).await;
    }
}
