# Android Network Inspector

A deep network-stack diagnostic tool for rooted Android devices.

Most Android network tools are a ping/traceroute/DNS toolbox reimplemented with
a nicer UI. This is not that. It reads the **Android framework's** view of
networking and the **Linux kernel's** view at the same time, lines them up, and
tries to explain *why* connectivity is broken — including the cases where
Android insists everything is `VALIDATED` while packets are going nowhere.

```text
Jetpack Compose UI
        |
        | protobuf over a Unix domain socket
        |
        v
Rust root daemon (netdiagd)
        |
        +-- netlink (NETLINK_ROUTE)
        +-- inet_diag (NETLINK_INET_DIAG)
        +-- /proc, /sys
        +-- netfilter / eBPF firewall maps
        +-- AF_PACKET capture
        +-- active probes (ICMP, DNS, TCP, TLS, PMTU)
```

The app itself never runs as root. A small Rust daemon does, started through
`su` and reachable only over a Unix socket whose peer it authorizes from
`SO_PEERCRED`.

## Why the two-layer view matters

Android's networking is policy routing all the way down. Every `Network` gets
its own routing table, per-app rules steer traffic into and around VPNs, and
`ConnectivityManager` reports a curated summary that can lag behind — or
outright disagree with — what the kernel will actually do with a packet.

Some things that are invisible from either layer alone:

- **`VALIDATED` but broken.** Validation is a cached point-in-time result. A
  network that worked when it was validated and broke afterwards keeps the flag,
  so apps keep using it and the system does not switch away.
- **An app silently outside the VPN.** A VPN's per-app list is implemented as a
  set of `uidrange` routing rules. An excluded app is simply *absent* from all
  of them — there is no "deny" entry to find, only a gap.
- **IPv6 that is configured, advertised in DNS, and dead.** Every local check
  passes; only the end-to-end connection fails, and applications stall on Happy
  Eyeballs waiting for a timeout.
- **Per-app blocking that no `iptables` dump shows.** Since Android 13 this
  lives in eBPF maps owned by `netd`, so a netfilter dump looks reassuringly
  empty on a device that is actively blocking an app.

## What it does

**Overview** — the framework's view and the kernel's, side by side, deliberately
not merged.

**Diagnose** — about twenty checks across framework, kernel and network, then a
rule-based interpretation layer that explains what the combination means. Checks
are facts; findings are interpretations, and the two are kept separate so a
wrong interpretation never corrupts the evidence.

**Routing** — routes grouped by table (because that is how Android uses them),
policy rules rendered the way `ip rule` shows them, and the neighbour table.

**Sockets** — every socket with its owning uid and the netId from its `SO_MARK`.
Those two columns are what make it more than `ss -tanp`.

**Apps** — the cross-layer chain for one app:

```text
package name -> uid -> sockets -> policy rules / fwmark -> table -> interface
```

**Timeline** — kernel events (netlink multicast) and framework events
(`NetworkCallback`) interleaved on one axis. The lag between "the kernel dropped
the route" and "ConnectivityManager noticed" is only visible this way.

**Capture** — packet capture via `AF_PACKET` on a real interface, saved as a
`.pcap`. Deliberately *not* `VpnService`-based: Android allows one active
VpnService, so a tun-based capture cannot run alongside the VPN you are trying to
debug, and would only see what is routed into the tun anyway.

### Sample output

From a real device running a v4-only VPN:

```text
[PASS] iface.active        traffic leaves via tun0 (index 51, MTU 1280)
[INFO] route.lookup.v4     packets to 1.1.1.1 take table 1051 out of tun0 via on-link
[FAIL] route.lookup.v6     the kernel could not route to 2606:4700:4700::1111:
                           No route to host (os error 113)
[FAIL] addr.v6             tun0 has no global IPv6 address
[INFO] vpn.routing         tun0 carries IPv4 only, and IPv6 is deliberately
                           blackholed inside the VPN's routing table

  The VPN blocks IPv6 on purpose (confidence 90%)

  Traffic goes through the VPN, the tunnel carries no IPv6, and the VPN's
  routing table (1051) sends the IPv6 default route to loopback.

  That is Android deliberately blackholing IPv6 for a VPN that only supports
  IPv4. It is the correct behaviour: IPv6 connections fail immediately,
  applications fall back to IPv4 without a stall, and no IPv6 traffic escapes
  the tunnel. Every IPv6 failure elsewhere in this report follows from this
  and is expected.
```

And a real framework/kernel disagreement found on the same device:

```text
VPN                                                          BYPASSES
Interface     tun0
This app      bypasses the VPN
Reason        uid 10400 falls outside all 242 uid range(s) that route into
              the VPN's table, so the VPN app's per-app list excludes this app
Disagreement  the framework says this app is inside the VPN, but the kernel
              routes it around the tunnel
```

## Repository layout

```text
proto/              the API. Single source of truth for every frontend.
crates/netdiag-ipc/ generated Rust types, framing and client, shared by the
                    daemon and the Slint app.
daemon/             the Rust root daemon (netdiagd).
android/            the Compose app (the primary frontend).
slint-app/          a second frontend in Slint; see docs/slint-experiment.md.
scripts/            build-daemon.sh — cross-compiles the daemon into the APK.
```

There are two frontends because the second one was an experiment in writing the
UI in Rust. The Compose app is the one to use; [docs/slint-experiment.md](docs/slint-experiment.md)
records what the Slint version cost and bought, including the parts that came
out worse.

## The API is the contract

Everything crossing the process boundary is defined once, in
`proto/netdiag/v1/*.proto`. The Rust side generates from it with `prost` at
build time; the Android side generates from **the same directory** with the
protobuf Gradle plugin. Neither side hand-writes a struct that mirrors the
other, and there is no copy of the schema to drift.

`buf` enforces this in CI: `buf lint` for style, and `buf breaking` against the
`main` branch so a wire-incompatible change fails the build rather than
appearing as a mystery parse error on a device.

### Transport

- Unix `SOCK_STREAM`, abstract namespace by default (`@netdiag`).
- Protobuf **length-delimited** framing — exactly what prost's
  `encode_length_delimited` writes and Java's `parseDelimitedFrom` reads, so
  neither side invents a header.
- One socket carries every call. Requests carry a client-assigned `id`; a single
  reader on each side fans replies back to whoever is waiting, so a three-second
  `Diagnose` and a live `WatchNetwork` share the connection without blocking.
- Streaming calls end with exactly one `stream_end`. `Cancel` stops one.

There is no gRPC here on purpose: one process talks to one daemon over one
socket, and a small dispatcher is far easier to audit for something running as
root than a full HTTP/2 stack.

## Security

The daemon runs as root, so anything that can reach its socket can read every
socket on the device. Access is decided from kernel-supplied peer credentials
(`SO_PEERCRED`), never from anything the client sends in a message: a client can
lie about its identity in a protobuf field, it cannot lie to the kernel about
its uid.

```sh
netdiagd --socket @netdiag --allow-uid 10401 --expect-package dev.okhsunrog.netdiag
```

- `--allow-uid` is the allowlist. With none given, only root may connect.
- `--expect-package` additionally requires the peer process to be named that
  (its `/proc/<pid>/cmdline`). Advisory — the uid check is what grants access.
- Abstract sockets have no filesystem permissions at all, which is precisely why
  the peer credential check is not optional. A filesystem path can be used
  instead, and is then chowned to the client uid and chmodded `0600`.

The daemon **only reads.** There is no code path in it that installs a route,
brings an interface up, or flushes a table.

## Building

Requirements: a Rust toolchain with the `aarch64-linux-android` target,
`cargo-ndk`, the Android NDK, `protoc`, and a JDK.

```sh
cargo install cargo-ndk
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/ndk

./scripts/build-daemon.sh          # cross-compile the daemon into the APK tree
cd android && ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The daemon ships inside the APK as `libnetdiagd.so`. That name is not cosmetic:
the package installer extracts files from `lib/<abi>/` to a directory that
permits execution, and it only does that for names matching `lib*.so`. An asset
would land on a `noexec` mount, and copying a binary out at runtime is exactly
what W^X restrictions on recent Android releases prevent.

### Running the daemon without the app

The daemon is useful on its own, and `--self-test` is the quickest way to check
it works on a new device: it collects a full snapshot, runs a diagnosis, and
prints both.

```sh
adb push daemon/target/aarch64-linux-android/release/netdiagd /data/local/tmp/
adb shell 'su -c "/data/local/tmp/netdiagd --self-test"'
```

### Tests

```sh
cargo test --workspace           # 138 unit tests, no device needed
cd proto && buf lint && buf breaking --against '../.git#branch=main,subdir=proto'
```

The Slint frontend is a separate cargo workspace (it tracks Slint's master
branch, which should not be in the daemon's dependency graph). It also runs on
the desktop against a daemon on the development machine, which is the quickest
way to look at the UI:

```sh
sudo ./target/debug/netdiagd --socket @netdiag --allow-uid "$(id -u)"
cd slint-app && cargo run --bin netdiag-slint-desktop -- --connect
```

The daemon's tests are pure functions over parsing, filtering and the rule
engine, so they run anywhere. The diagnosis rules in particular are tested
against the exact check combinations that should and should not fire them —
including regressions like "do not claim an MTU black hole when the MTU probe
passed".

## Device support

Built and verified on a Pixel 8 Pro (Android 17, kernel 6.1, KernelSU). It
should work on any rooted device with a reasonably modern kernel; the daemon
probes its own capabilities at startup and reports what is unavailable rather
than failing, so a device without, say, readable eBPF maps still gets everything
else.

The app must be granted root in your root manager before it can start the
daemon.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
