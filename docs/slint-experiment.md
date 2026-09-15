# The Slint frontend: what the experiment showed

A second frontend for the same tool, with the UI in Rust ([Slint]) instead of
Kotlin and Compose. The daemon, the protocol and the diagnosis engine are
untouched and shared verbatim; only the frontend differs. This is a record of
what that actually cost and bought.

[Slint]: https://slint.dev

Built against Slint `master` (1.18.0-unreleased), because `FlexboxLayout` and
the per-item `cross-axis-self-alignment` property are not in a release yet.
Verified against `bf511bc` and again against `9405a2df`, so it is not pinned to
one exact revision; `slint-app/Cargo.lock` records what a given build used.

`slint-app/` is deliberately **its own cargo workspace**. Tracking someone's
master branch should not sit in the daemon's dependency graph, and the daemon's
CI should never have to fetch it.

```sh
cd slint-app
# Slint compiles its own Java helper with `javac -source 8`, which JDK 26
# rejects, and picks an android.jar too old for that helper.
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export ANDROID_JAR="$ANDROID_HOME/platforms/android-34/android.jar"
cargo ndk -t arm64-v8a -P 31 build --release --lib
```

## The short version

Slint is a good fit for roughly 80% of this app and a poor fit for the other
20% — and the 20% is the half that makes the tool interesting.

Everything that talks to the daemon got **better**: one language, one build, and
the frontend links the daemon's own protocol code instead of regenerating it.
Everything that talks to the **Android framework** got worse, because from Rust
that is JNI, and JNI has no compile-time knowledge of the Android SDK.

## What got better

### One protocol implementation instead of two

The refactor that made this possible is worth more than the UI itself. The
shared `crates/netdiag-ipc` now holds the generated protobuf types, the
length-delimited framing and the client, and *both* the daemon and the Slint app
link it:

```text
proto/                    the schema, unchanged
crates/netdiag-ipc/       prost types + framing + client   <- shared
daemon/                   uses netdiag-ipc
slint-app/                uses netdiag-ipc
android/                  regenerates from proto/ via Gradle
```

The Compose app has to regenerate the schema through the protobuf Gradle plugin
and carries its own Kotlin client — about 260 lines of framing, correlation and
stream handling that mirror the Rust ones. The Slint app carries none of it. The
schema is still the contract for both, but there is now one less implementation
of it to keep honest.

### The UI runs on the desktop

```sh
sudo netdiagd --socket @netdiag --allow-uid "$(id -u)"
cd slint-app && cargo run --bin netdiag-slint-desktop -- --connect --tab 1
```

The whole interface runs against a daemon on the development machine, with real
kernel data. The Compose app has no equivalent — its UI cannot run outside
Android, so every iteration is a Gradle build and an `adb install`.

The harness renders itself to a PNG (`--snapshot out.png`) using
`Window::take_snapshot()`, so screens can be reviewed without capturing the
developer's screen.

### Build and size

| | Compose | Slint |
|---|---|---|
| Toolchain | AGP + Gradle + Kotlin + protobuf-gradle-plugin + JDK | cargo (+ a JDK for Slint's own Java helper) |
| Debug APK | 69 MB | not measured; the Rust+Skia binary alone is far smaller than the Compose runtime |
| UI iterate | Gradle build → `adb install` | `cargo run` on the desktop |

## What got worse

### The Android framework is JNI

This is the whole cost, and it lands exactly on the app's differentiator.
Reading `ConnectivityManager` is what makes this more than a kernel dump, and in
Kotlin it is ordinary code the compiler checks against the SDK:

```kotlin
val caps = connectivity.getNetworkCapabilities(network)
val validated = caps.hasCapability(NET_CAPABILITY_VALIDATED)
```

In Rust the same thing is a declared method name and a JNI signature that
nothing verifies:

```rust
bind_java_type! {
    ConnectivityManager => android.net.ConnectivityManager,
    type_map = { NetworkCapabilities => "android.net.NetworkCapabilities" },
    methods {
        fn get_network_capabilities {
            name = "getNetworkCapabilities",
            sig = (network: Network) -> NetworkCapabilities,
        },
    },
}
const NET_CAPABILITY_VALIDATED: jint = 16;   // no SDK constant to import
```

`jni` 0.22's `bind_java_type!` is much better than raw `call_method` — IDs are
cached, signatures are declared once, call sites are typed Rust — but it is a
*transcription* of an API, not a use of it. A wrong signature or a renamed
method is a runtime `NoSuchMethodError`. The SDK constants have to be copied in
as integer literals. Roughly 250 lines of clear Kotlin became roughly 400 lines
of binding declarations covering less ground.

### Two things were not built

- **`NetworkCallback`** for framework-side timeline events. Subclassing a Java
  abstract class needs a compiled Java shim in the APK. Slint's own Android
  backend already ships one, so the machinery is not exotic — but adding a
  second means owning a `javac` step in a build whose appeal is that it is just
  `cargo`. The Slint timeline therefore shows kernel events only.
- **`PackageManager.getInstalledApplications`**. A `List<ApplicationInfo>` plus
  a per-entry label lookup is a lot of JNI for a list, so the Slint app's
  per-app screen offers only its own uid.

Both are doable. Neither is free, and both are free in Kotlin.

### Toolchain friction

Two things that cost real time and are worth knowing before starting:

- Slint's Android backend compiles its Java helper with `javac -source 8`, which
  **JDK 26 rejects outright**. A JDK ≤ 21 is required: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk`.
- It picks an `android.jar` automatically and picked one too old for its own
  helper (`android.window.OnBackInvokedCallback` is API 33+). `ANDROID_JAR` has
  to be set explicitly.

### Slint constraints found the hard way

- **`ModelRc` is `Rc`-based and not `Send`.** View models cannot be built on a
  background thread and handed to the UI thread. Anything crossing
  `invoke_from_event_loop` must be `Send`, so the protobuf crosses and the
  conversion happens on the UI thread. Once understood this is a clean rule, but
  it forced a rewrite of the state layer from `Rc`/`RefCell` to `Arc`/`Mutex`.
- **A `Window` with no size collapses.** Android ignores it, but on the desktop
  the window shrinks to its minimum and every screen looks broken until
  `preferred-width`/`preferred-height` are set.

## Where FlexboxLayout earned its place

Exactly one pattern, used everywhere that pattern appears: a **wrapping row of
status chips**. A variable number of variable-width badges that must reflow on a
narrow phone.

```slint
component ChipFlow inherits FlexboxLayout {
    in property <[ChipData]> chips;
    flex-direction: row;
    flex-wrap: wrap;
    alignment: start;
    cross-axis-alignment: center;
    spacing-horizontal: 6px;
    spacing-vertical: 6px;
    for chip in root.chips: Chip { text: chip.text; status: chip.status; }
}
```

`HorizontalLayout` would clip on a small screen or force a fixed chip count.
Everything else stays on `HorizontalLayout`/`VerticalLayout`, which the Slint
docs themselves describe as simpler and faster for a single line — using
Flexbox everywhere would be cargo-culting CSS.

The per-item `cross-axis-self-alignment: start` is used on the status badge in
check and socket rows, so the badge stays at the top of a row whose text wraps
to several lines instead of being vertically centred against it. That previously
needed a wrapper element.

`layout-order` is available and was **not** used: nothing here needs a visual
order that differs from declaration order, and using it to prove a point would
only make the markup harder to follow.

## Verified, and not

**Verified on the desktop, against a real daemon:** connect and handshake, the
snapshot path, the streaming diagnosis (checks arriving progressively, findings
rendering), interface and routing views, the chip flex-wrap. The diagnosis output
is identical to the Compose build's and the CLI's, because it is the same daemon:
10 pass / 3 fail / 1 warn / 8 skip on the same machine, with the same two
findings.

**Verified by compilation only:** the entire Android layer. It cross-compiles
cleanly for `aarch64-linux-android`, but the device was unavailable, so the JNI
bindings have **never been executed**. Compilation checks the Rust; it does not
check that `getLinkProperties` really has the signature declared for it. Expect
the first run on hardware to find mistakes in exactly that layer.

**Not built:** framework timeline events, the installed-app list, sockets and
capture screens.

## Would I ship it

For this app, no — not as the primary frontend. The framework side is half the
product, and Kotlin gets it for free while Rust pays for every call and loses
compile-time checking on the part most likely to break across Android releases.

For a frontend that mostly renders daemon data — which is most of this app's
screens — Slint is clearly good, and the desktop harness alone is a real
productivity win. The genuine and lasting result of the experiment is the shared
`netdiag-ipc` crate: that was worth doing regardless of which UI wins.
