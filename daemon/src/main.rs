//! netdiagd — the privileged half of the Android Network Inspector.
//!
//! This process is the only part that runs as root. It is started through `su`
//! by the app, listens on a Unix socket, and speaks protobuf. It reads kernel
//! networking state and runs network probes; it never changes the device's
//! configuration.
//!
//! Run `netdiagd --help` for the arguments, or `netdiagd --self-test` to have
//! it collect and print a snapshot without any client, which is the quickest
//! way to check that it works on a new device.

mod capture;
mod collect;
mod correlate;
mod daemon;
mod diag;
mod ipc;
mod probe;
mod proto;
mod snapshot;
mod util;
mod watch;

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::daemon::Daemon;
use crate::ipc::auth::{self, AuthPolicy};
use crate::ipc::listener::{self, SocketAddress};
use crate::watch::EventBus;

const DEFAULT_SOCKET: &str = "@netdiag";

struct Args {
    socket: SocketAddress,
    policy: AuthPolicy,
    /// Chown a filesystem socket to this uid. Ignored for abstract sockets.
    socket_owner: Option<u32>,
    log_filter: String,
    self_test: bool,
}

fn usage() -> &'static str {
    "\
netdiagd — privileged network diagnostics daemon

USAGE:
    netdiagd [OPTIONS]

OPTIONS:
    --socket <ADDR>       Listening address. '@name' uses the abstract
                          namespace (default: @netdiag); anything else is
                          treated as a filesystem path.
    --allow-uid <UID>     Allow this uid to connect. May be repeated. Root is
                          always allowed. With no --allow-uid, only root may
                          connect.
    --expect-package <PKG>
                          Additionally require the peer process to be named
                          PKG (its /proc/<pid>/cmdline). Advisory: the uid
                          check is what actually grants access.
    --log <FILTER>        Tracing filter (default: info).
    --self-test           Collect a snapshot, print a summary, and exit.
    --version             Print the version and exit.
    -h, --help            Print this help and exit.

SECURITY:
    The daemon runs as root. Any process that can reach its socket can read
    every socket on the device, so connections are authorized from SO_PEERCRED
    and never from anything the client sends in a message. Abstract sockets
    have no filesystem permissions at all, which makes that check the only
    barrier; pass --allow-uid with the app's uid.
"
}

fn parse_args() -> Result<Option<Args>> {
    let mut socket = SocketAddress::parse(DEFAULT_SOCKET);
    let mut allowed_uids: Vec<u32> = Vec::new();
    let mut expect_package: Option<String> = None;
    let mut socket_owner: Option<u32> = None;
    let mut log_filter = "info".to_string();
    let mut self_test = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", usage());
                return Ok(None);
            }
            "--version" => {
                println!("netdiagd {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--socket" => {
                let value = args.next().context("--socket needs a value")?;
                socket = SocketAddress::parse(&value);
            }
            "--allow-uid" => {
                let value = args.next().context("--allow-uid needs a value")?;
                let uid: u32 = value
                    .parse()
                    .with_context(|| format!("--allow-uid: '{value}' is not a uid"))?;
                allowed_uids.push(uid);
                // The first allowed uid also owns a filesystem socket, which
                // is almost always what is wanted.
                socket_owner.get_or_insert(uid);
            }
            "--expect-package" => {
                expect_package = Some(args.next().context("--expect-package needs a value")?);
            }
            "--log" => {
                log_filter = args.next().context("--log needs a value")?;
            }
            "--self-test" => self_test = true,
            other => {
                anyhow::bail!("unknown argument '{other}'; try --help");
            }
        }
    }

    Ok(Some(Args {
        socket,
        policy: AuthPolicy {
            allowed_uids,
            expect_package,
        },
        socket_owner,
        log_filter,
        self_test,
    }))
}

fn main() -> Result<()> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("NETDIAGD_LOG")
                .unwrap_or_else(|_| EnvFilter::new(&args.log_filter)),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;

    runtime.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    // SAFETY: getuid never fails and has no preconditions.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        warn!(
            "running as uid {uid}, not root; netlink dumps of other apps' sockets, SO_MARK \
             and packet capture will all fail"
        );
    }

    let (connection, handle, _messages) =
        rtnetlink::new_connection().context("could not open a NETLINK_ROUTE socket")?;
    tokio::spawn(connection);

    let events = EventBus::new();
    let daemon = Arc::new(Daemon::new(handle, events.clone()));

    info!(
        "netdiagd {} on kernel {}",
        daemon.version,
        util::kernel_release()
    );
    for warning in daemon.warnings() {
        warn!("{warning}");
    }

    if args.self_test {
        return self_test(&daemon).await;
    }

    // The kernel event monitor is global: one socket, many subscribers.
    {
        let events = events.clone();
        tokio::spawn(async move {
            if let Err(e) = watch::run(events).await {
                error!("the kernel event monitor stopped: {e}");
            }
        });
    }

    let listener = listener::bind(&args.socket, args.socket_owner)?;
    info!(
        "authorizing peers by {} ({})",
        args.policy.describe(),
        listener::describe_listener(&listener)
    );

    let address = args.socket.clone();
    let policy = Arc::new(args.policy);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!("accept failed: {e}");
                        continue;
                    }
                };

                let peer = match auth::authorize(&stream, &policy) {
                    Ok(peer) => peer,
                    Err(e) => {
                        // Refusing loudly matters: this is the line a
                        // malicious local app would be probing.
                        warn!("refused a connection: {e}");
                        continue;
                    }
                };

                info!("accepted a connection from {peer}");
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    if let Err(e) = ipc::session::serve(stream, peer, daemon).await {
                        warn!("session ended with an error: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }

    listener::cleanup(&address);
    Ok(())
}

/// Collect everything once and print a human summary. This is the fastest way
/// to tell whether the daemon works on a device, and it needs no client.
async fn self_test(daemon: &Arc<Daemon>) -> Result<()> {
    let request = proto::GetSnapshotRequest {
        include_sockets: true,
        include_socket_tcp_info: true,
        include_neighbors: true,
        include_firewall: true,
        include_qdiscs: true,
        include_counters: true,
        include_sysctls: true,
        android_state: None,
    };

    let response = daemon
        .get_snapshot(request)
        .await
        .map_err(|e| anyhow::anyhow!("snapshot failed: {} {}", e.message, e.detail))?;
    let snapshot = response.snapshot.unwrap_or_default();

    println!("netdiagd self-test");
    println!("  kernel:            {}", snapshot.kernel_release);
    println!(
        "  collection took:   {} ms",
        snapshot.collection_duration_ms
    );
    println!("  interfaces:        {}", snapshot.interfaces.len());
    for iface in &snapshot.interfaces {
        let flags = iface.flags.unwrap_or_default();
        let addresses: Vec<String> = iface
            .addresses
            .iter()
            .filter_map(|a| a.prefix.as_ref().map(|p| p.display()))
            .collect();
        println!(
            "    {:<16} idx {:<3} mtu {:<5} {:<10} {}",
            iface.name,
            iface.index,
            iface.mtu,
            if flags.up { "UP" } else { "DOWN" },
            addresses.join(" ")
        );
    }
    println!("  routes:            {}", snapshot.routes.len());
    for route in snapshot.routes.iter().filter(|r| r.is_default) {
        let hop = route.next_hops.first().cloned().unwrap_or_default();
        println!(
            "    default via {:<24} dev {:<14} table {}",
            hop.gateway
                .as_ref()
                .map(|g| g.display())
                .unwrap_or_else(|| "on-link".into()),
            hop.out_interface_name,
            route.table
        );
    }
    println!("  rules:             {}", snapshot.rules.len());
    println!("  neighbours:        {}", snapshot.neighbors.len());
    println!("  sockets:           {}", snapshot.sockets.len());
    if let Some(summary) = &snapshot.socket_summary {
        println!(
            "    established {}  syn-sent {}  listen {}  time-wait {}",
            summary.established, summary.syn_sent, summary.listen, summary.time_wait
        );
    }
    if let Some(firewall) = &snapshot.firewall {
        println!("  firewall:          {}", firewall.collection_note);
    }
    if let Some(clat) = &snapshot.clat {
        println!(
            "  464xlat:           {}",
            if clat.active {
                format!("active on {}", clat.clat_interface)
            } else {
                "not active".to_string()
            }
        );
    }
    for warning in &snapshot.collection_warnings {
        println!("  warning:           {warning}");
    }

    println!("\nrunning a passive diagnosis...");
    let report = diag::run(
        &daemon.handle,
        proto::DiagnoseRequest {
            passive_only: false,
            ..Default::default()
        },
        None,
    )
    .await;

    println!(
        "  {} passed, {} failed, {} warned, {} skipped in {} ms",
        report.passed, report.failed, report.warned, report.skipped, report.total_duration_ms
    );
    for check in &report.checks {
        let status =
            proto::CheckStatus::try_from(check.status).unwrap_or(proto::CheckStatus::Unspecified);
        let mark = match status {
            proto::CheckStatus::Pass => "PASS",
            proto::CheckStatus::Fail => "FAIL",
            proto::CheckStatus::Warn => "WARN",
            proto::CheckStatus::Skip => "SKIP",
            proto::CheckStatus::Info => "INFO",
            _ => "....",
        };
        println!("  [{mark}] {:<22} {}", check.key, check.detail);
    }
    println!("\n  {}", report.summary);
    for f in &report.findings {
        println!(
            "\n  {} (confidence {}%)\n{}",
            f.title,
            f.confidence,
            f.interpretation
                .lines()
                .map(|l| format!("    {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        for action in &f.suggested_actions {
            println!("    -> {action}");
        }
    }

    Ok(())
}
