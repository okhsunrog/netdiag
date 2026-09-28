//! Explicit responsiveness test. No AIM report is submitted: this uses the
//! measurement library directly rather than its CLI/reporting layer.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use cf_mach::nq_core::{
    ConnectionManager, ConnectionTiming, ConnectionType, EstablishedConnection, Network, NqBody,
    OneshotResult, ResponseFuture, Time, Timestamp, TokioTime, oneshot_result,
};
use cf_mach::nq_latency::{Latency, LatencyConfig};
use cf_mach::nq_rpm::{Responsiveness, ResponsivenessConfig, ResponsivenessResult};
use http::{Request, Response};
use hyper::body::Incoming;
use tokio::net::{TcpSocket, lookup_host};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::probe::{ProbeContext, apply_context};
use crate::proto;

/// The upstream Tokio transport has no socket configuration hook. Keep this
/// small adapter so every test TCP socket receives the Android network mark
/// before connect(2), including the unloaded latency probes.
#[derive(Clone)]
struct MarkedNetwork {
    time: Arc<dyn Time>,
    connections: Arc<ConnectionManager>,
    shutdown: CancellationToken,
    context: ProbeContext,
}

impl MarkedNetwork {
    fn new(time: Arc<dyn Time>, shutdown: CancellationToken, context: ProbeContext) -> Self {
        let connections = Arc::new(ConnectionManager::default());
        let all = connections.clone();
        let done = shutdown.clone();
        tokio::spawn(async move {
            done.cancelled().await;
            all.shutdown().await;
        });
        Self {
            time,
            connections,
            shutdown,
            context,
        }
    }
}

impl Network for MarkedNetwork {
    fn resolve(&self, host: String) -> OneshotResult<Vec<SocketAddr>> {
        let (tx, rx) = oneshot_result();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            // Android's system resolver is used here. TCP sockets are pinned;
            // resolver selection is still a limitation on non-default networks.
            let result = tokio::select! {
                _ = shutdown.cancelled() => Err(anyhow::anyhow!("quality test cancelled")),
                result = lookup_host(host) => result.map(|iter| iter.collect()).map_err(Into::into),
            };
            let _ = tx.send(result);
        });
        rx
    }

    fn new_connection(
        &self,
        start: Timestamp,
        remote_addr: SocketAddr,
        domain: String,
        conn_type: ConnectionType,
    ) -> OneshotResult<Arc<RwLock<EstablishedConnection>>> {
        let (tx, rx) = oneshot_result();
        let this = self.clone();
        tokio::spawn(async move {
            let result = tokio::select! {
                _ = this.shutdown.cancelled() => Err(anyhow::anyhow!("quality test cancelled")),
                result = async {
                let socket = if remote_addr.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                apply_context(socket.as_raw_fd(), &this.context)?;
                let stream = socket.connect(remote_addr).await?;
                let mut timing = ConnectionTiming::new(start);
                timing.set_connect(this.time.now());
                stream.set_nodelay(false)?;
                this.connections
                    .new_connection(
                        timing,
                        remote_addr,
                        domain,
                        conn_type,
                        Box::new(stream),
                        &*this.time,
                        this.shutdown.clone(),
                    )
                    .await
                } => result,
            };
            let _ = tx.send(result);
        });
        rx
    }

    fn send_request(
        &self,
        connection: Arc<RwLock<EstablishedConnection>>,
        request: Request<NqBody>,
    ) -> OneshotResult<Response<Incoming>> {
        let (tx, rx) = oneshot_result();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let result = tokio::select! {
                _ = shutdown.cancelled() => Err(anyhow::anyhow!("quality test cancelled")),
                result = async {
                let response: ResponseFuture = {
                    let mut conn = connection.write().await;
                    conn.send_request(request)
                        .context("quality test connection is closed")?
                };
                Ok(response.await?)
                } => result,
            };
            let _ = tx.send(result);
        });
        rx
    }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn leg(result: &ResponsivenessResult) -> Result<proto::NetworkQualityLeg> {
    Ok(proto::NetworkQualityLeg {
        throughput_bps: result.throughput().context("no throughput measurement")? as f64,
        loaded_latency_ms: result
            .self_probe_latencies
            .quantile(0.5)
            .context("no loaded latency measurement")?
            * 1000.0,
        rpm: result.rpm.context("no responsiveness measurement")?,
        failed_connections: result.failed_connections as u32,
    })
}

pub async fn run(
    net_id: i32,
    mut phase: impl FnMut(&'static str),
) -> Result<proto::NetworkQualityResult> {
    let context = ProbeContext::with_timeout(3000).pinned_to_net_id(net_id);
    phase("Measuring idle latency");
    let latency = {
        let shutdown = CancellationToken::new();
        let _cancel = CancelOnDrop(shutdown.clone());
        let time: Arc<dyn Time> = Arc::new(TokioTime::new());
        let transport = Arc::new(MarkedNetwork::new(
            time.clone(),
            shutdown.clone(),
            context.clone(),
        ));
        let network: Arc<dyn Network> = transport.clone();
        let result = Latency::new(LatencyConfig::default())
            .run_test(network, time, shutdown.clone())
            .await?;
        shutdown.cancel();
        transport.connections.shutdown().await;
        result
    };

    let config = ResponsivenessConfig {
        test_duration: Duration::from_secs(12),
        ..ResponsivenessConfig::default()
    };
    phase("Loading download");
    let download = run_leg(config.clone(), true, context.clone()).await?;
    phase("Loading upload");
    let upload = run_leg(config, false, context).await?;

    Ok(proto::NetworkQualityResult {
        net_id,
        unloaded_latency_ms: latency.median().context("no idle latency measurement")? * 1000.0,
        jitter_ms: latency.jitter().unwrap_or_default() * 1000.0,
        download: Some(leg(&download)?),
        upload: Some(leg(&upload)?),
    })
}

async fn run_leg(
    config: ResponsivenessConfig,
    download: bool,
    context: ProbeContext,
) -> Result<ResponsivenessResult> {
    let shutdown = CancellationToken::new();
    let _cancel = CancelOnDrop(shutdown.clone());
    let time: Arc<dyn Time> = Arc::new(TokioTime::new());
    let transport = Arc::new(MarkedNetwork::new(time.clone(), shutdown.clone(), context));
    let network: Arc<dyn Network> = transport.clone();
    let result = Responsiveness::new(config, download)?
        .run_test(network, time, shutdown.clone())
        .await?;
    shutdown.cancel();
    transport.connections.shutdown().await;
    Ok(result)
}
