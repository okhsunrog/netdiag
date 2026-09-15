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

The APK is built with [`cargo-rapk`], which unlike `cargo-apk` compiles this
app's Java into the APK:

```sh
cd slint-app
# Slint compiles its own Java helper with `javac -source 8`, which JDK 26
# rejects. This is Slint's constraint, not this app's.
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
# cargo-rapk looks for intermediates under target/ unconditionally, so a
# `build-dir` in ~/.cargo/config.toml makes it fail with a bare ENOENT.
export CARGO_BUILD_BUILD_DIR=target
cargo rapk build --lib
```

[`cargo-rapk`]: https://crates.io/crates/cargo-rapk

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
android/                  regenerated from proto/ via Gradle (since removed)
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
| Debug APK | 69 MB | 279 MB |
| Native code, release | — | 17 MB (+ 2.7 MB daemon) |
| UI iterate | Gradle build → `adb install` | `cargo run` on the desktop |

The debug APK number looks alarming and means nothing: Rust debug info is not
stripped, so `libnetdiag_slint.so` is 276 MB of symbols. The release figure is
the real one — 17 MB for the UI, Skia, the protocol and the client, which is
compact for a self-contained renderer. The Compose release APK was not measured
(no signing config), so the honest comparison is "both are in the tens of
megabytes", not a win for either.

And it cannot be built end to end: `cargo apk build --release` compiles fine and
then refuses to package without `[package.metadata.android.signing.release]`.
Gradle generates a debug keystore for you; this does not.

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

### What was not built

Sockets and capture screens. `NetworkCallback` and the installed-app list were
both on this list, written off as too expensive over JNI; both are now built,
and neither turned out to be a JNI problem. See below.

### Toolchain friction

Four things that cost real time and are worth knowing before starting:

- Slint's Android backend compiles its Java helper with `javac -source 8`, which
  **JDK 26 rejects outright**. A JDK ≤ 21 is required: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk`.
- It picks an `android.jar` automatically and picked one too old for its own
  helper (`android.window.OnBackInvokedCallback` is API 33+). `ANDROID_JAR` has
  to be set explicitly.
- `cargo-apk` fails with a bare `No such file or directory (os error 2)` if the
  user's cargo config sets the newer `build-dir`, because it looks for
  intermediates under `target/<triple>/<profile>/build` unconditionally.
  `CARGO_BUILD_BUILD_DIR=target` works around it. Nothing in the error names
  the cause; `strace` did.
- `tracing` output does **not** reach logcat on its own. `android_logger` is a
  `log` backend, so `tracing` needs its `log` feature enabled before anything
  appears. Until then the app looks silent while working fine.

### On packaging: cargo-apk, cargo-apk2, cargo-rapk

All three are the same program — `cargo-subcommand` plus a fork of `ndk-build`,
same CLI, same `[package.metadata.android]`. `cargo-apk` (rust-mobile, edition
2018) is the original and effectively frozen; `cargo-apk2` is a refresh with no
new capability.

`cargo-rapk` is the one that differs, and it matters here: it compiles Java and
Kotlin sources into the APK's own `classes.dex`, and it collects them
**transitively from the dependency graph**, so a library crate can contribute
Java, activities and services through its own metadata:

```toml
[package.metadata.android.cargo_rapk]
java_sources = ["java"]
```

That is the plugin model this app works around. With classes in the APK the
shim would be loaded by the app's own class loader, which makes both the
`InMemoryDexClassLoader` and the `RegisterNatives` below unnecessary. It is not
adopted here — the current path is device-verified and asks nothing of the APK
builder — but it is the condition under which the workaround stops being needed.

### Slint constraints found the hard way

- **`ModelRc` is `Rc`-based and not `Send`.** View models cannot be built on a
  background thread and handed to the UI thread. Anything crossing
  `invoke_from_event_loop` must be `Send`, so the protobuf crosses and the
  conversion happens on the UI thread. Once understood this is a clean rule, but
  it forced a rewrite of the state layer from `Rc`/`RefCell` to `Arc`/`Mutex`.
- **A `Window` with no size collapses.** Android ignores it, but on the desktop
  the window shrinks to its minimum and every screen looks broken until
  `preferred-width`/`preferred-height` are set.
- **Android draws the app under the status and gesture bars.** Nothing warns
  about this; the title simply sits behind the clock. `safe-area-insets` on the
  root `Window` is the fix, and it has no desktop equivalent to test against.

## The Java in this app, and what it cost to allow it

`java/` holds two files, compiled into the APK's own `classes.dex` by
`cargo rapk`, declared in one line:

```toml
[package.metadata.android]
java_sources = ["java"]
```

- `NetdiagFrameworkWatcher` subclasses `ConnectivityManager.NetworkCallback`,
  which must be subclassed to receive anything and which Rust cannot subclass.
- `NetdiagPackages` wraps `PackageManager.getInstalledApplications`. In Rust
  that is a `List<ApplicationInfo>` plus a `getApplicationLabel` per entry —
  several hundred JNI round trips and a page of bindings for four lines of Java.

### It was a packaging problem, not a JNI problem

This is the part worth taking away, and getting it wrong cost the whole first
version of this experiment.

`cargo-apk` cannot put a class in an APK. So the first build compiled the one
Java file from `build.rs` with the [`android-build`] crate (javac + d8),
embedded it with `include_bytes!`, and loaded it at runtime through
`InMemoryDexClassLoader`. That worked, and it dragged in a JDK version guard, an
`android.jar` discovery problem, and a class with no class loader of its own.

[`android-build`]: https://crates.io/crates/android-build

Under that cost, *writing more Java looked expensive*, so the app list was
written off as "a lot of JNI for a list" and simply not built. The per-app
screen — on an app whose entire premise is mapping uids to something a person
recognises — showed one row.

`cargo rapk` compiles Java and Kotlin into the APK. Migrating to it deleted the
build script's Java half, the `android-build` dependency, the JDK guard, the
`android.jar` lookup, the embedded dex and the `InMemoryDexClassLoader` — and
then the app list took one Java class and about 40 lines of Rust.

So the honest version of "Slint makes the Android half expensive" is narrower
than it first appeared: **JNI made the Android half expensive, and an APK
builder that could not compile Java made avoiding JNI expensive too.** Remove
the second and the first stops being decisive, because anything genuinely
awkward over JNI can just be written in Java.

It did not remove everything. `RegisterNatives` is still required, for a reason
that has nothing to do with packaging — see below.

### Why the shim carries no protobuf

The first design had the Java class build real protobuf messages, so the
`.proto` would be the contract on that hop too. Measuring killed it:

| | dex |
|---|---|
| The shim as built | **5.2 KB** |
| With protobuf-javalite, R8-shrunk | 242 KB |
| With protobuf-javalite, unshrunk | 1.0 MB |

Size was not even the deciding factor. Without Gradle there is no dependency
resolution, so the jar would have to be vendored into the repository or
downloaded from `build.rs`, and protobuf-lite's reflective dispatch needs
careful R8 keep rules.

The deeper reason is that the hop does not deserve a schema at all. Protobuf
here exists to cross the boundary between the app and the daemon: two
separately built artifacts that can be different versions, and where the app
may be Kotlin. The shim is compiled by the same `cargo rapk` invocation as the
Rust consuming it, into the same APK, loaded by the same process. It
cannot be version-skewed, and a schema protects against skew. Putting protobuf
there was pattern-matching from the Compose build, where Kotlin legitimately
constructs these messages because Kotlin *is* the app.

So the shim has its own seven-value vocabulary, and one Rust function maps it
onto the wire enums. The single failure mode that design has — someone
renumbering the Java constants without updating the table — is covered by a test
that parses the constants out of the Java source. It lives in a module that is
deliberately *not* gated on `target_os = "android"`, so it runs under an
ordinary `cargo test` rather than only on a device.

### A NativeActivity app must use RegisterNatives

Java calling *into* Rust is the one direction that does not work by default. The
`native_method!` macro exports the correctly mangled symbol from the `.so` —
confirmed with `llvm-nm`, and the VM even names that exact symbol in its error —
and the first callback still threw `UnsatisfiedLinkError`. So the method is
bound by function pointer:

```rust
let class = loader.load_class(env, jni::jni_str!("dev.okhsunrog.netdiag.NetdiagFrameworkWatcher"), false)?;
unsafe { env.register_native_methods(&class, &[ON_FRAMEWORK_EVENT])? };
```

The first explanation written here was that the VM searches only libraries
associated with the *defining class's* class loader, and a class from an
`InMemoryDexClassLoader` has none. That was wrong, and moving the class into the
APK disproved it: with the class defined by the app's own loader, the error was
byte for byte the same.

The actual cause is the app's `.so`, not its class. `NativeActivity` starts an
app by `dlopen`ing the library from its `loadNativeCode` method — not through
`System.loadLibrary` — so the VM never records the library as loaded and never
searches it, whoever defined the class. `RegisterNatives` is therefore
**structural for any `NativeActivity` app**, and no packaging change removes it.

Worth stating plainly because the first explanation was plausible, fixed the
symptom, and was believed until an unrelated change happened to test it.

### Reimplementing a platform convenience reintroduced a bug

The timeline renders `HH:MM:SS.mmm`, and Rust has no date formatting in std. The
hand-rolled version divided the Unix timestamp by 86400 and printed UTC, three
hours off the clock in the same status bar. The Compose build never had this
bug, because `SimpleDateFormat` uses the device's zone for free. The fix asks
the C library for `tm_gmtoff` *at the event's own timestamp*, so events either
side of a DST change still render correctly. This is a small, concrete instance
of the general trade: avoiding a dependency means reimplementing what the
platform already knew.

### The toolchain guard that stopped being needed

`build.rs` used to check the JDK version before doing anything, because both
failure modes were otherwise a wall of javac output: JDK 22+ rejects `-source 8`,
and older JDKs cannot read the SDK's class files. It also had to locate an
`android.jar`, because the automatic search picked one too old.

None of that is this project's problem any more — `cargo rapk` owns the javac
invocation and takes the `android.jar` from the declared `target_sdk_version`.
The build script is back to one line of `slint_build::compile`.

`JAVA_HOME` still has to point at a JDK ≤ 21, because Slint's *own* Android
backend compiles its helper with `-source 8` from its own build script. That
constraint belongs to Slint, not to this app.

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

**Verified on a Pixel 8 Pro, rooted with KernelSU:** the whole Android layer,
which had previously only been compiled. The app resolves its own uid and the
packaged daemon path over JNI, launches the daemon through `su`, and the daemon
accepts the connection after checking `SO_PEERCRED` against both the uid and the
package name:

```
accepted a connection from uid=10411 gid=10411 pid=27948 cmdline=dev.okhsunrog.netdiag.slint
client netdiag-slint 0.1.0 connected, protocol 1 (negotiated 1)
```

The framework events arrive too, which is the full Java → dex → `RegisterNatives`
→ Rust → Slint chain, interleaved on one timeline with kernel netlink events —
the thing the whole tool exists to show. Toggling Wi-Fi produced:

```
20:24:30.710  FMWK  wlan0 gained IPv6
20:24:30.709  FMWK  wlan0 DNS [/fd3f:817f:103d::1, /10.77.77.1]
20:24:30.681  KRNL  route added: fd3f:817f:103d::/64 dev wlan0 table 1047
20:24:30.361  FMWK  wlan0 VALIDATED: false -> true
20:24:30.331  KRNL  rule removed: priority 29040 uidrange 10151-10151 lookup 1030
```

Notably, none of the JNI signatures were wrong. The mistakes the device found
were all in the *surrounding* assumptions — class loading, safe areas, logging,
timezones — not in the transcribed API.

**Not built:** sockets and capture screens.

## The cost, counted

Hand-written lines, excluding generated protobuf on both sides:

| | Compose (Kotlin) | Slint (Rust + `.slint` + Java) |
|---|---|---|
| Total | 4591 | 3033 + 969 + 264 = 4266 |
| Framework + daemon launch | 777 | **1433** |
| UI: screens, view models, formatting | **2130** | 3526 |
| Protocol client | 435 | **0** |
| Screens | 7 | 5 |

The difference runs in *both* directions and nearly cancels:

- **The UI is genuinely more compact in Slint**: 2130 against 3526 for the same
  screens. Declarative `.slint` is denser than Compose, and much of `view.rs` is
  mechanical protobuf-to-model mapping.
- **The framework layer costs about 1.8× more** — 1433 against 777 — and none of
  it is checked by any compiler. Some of that gap is comments and host-runnable
  tests that the Kotlin has no equivalent of, but not most of it.
- **The protocol client disappeared entirely.** 435 lines of hand-written Kotlin
  framing and stream handling became a `use netdiag-ipc`.

The framework row got *worse* after the move to `cargo rapk`, not better, and
that is the honest result: the migration did not make the Android half cheap. It
made it **possible**. The installed-app list is in that 1433 now, at roughly 200
lines against Kotlin's 25; before, it was in neither column, because under
`cargo-apk` the only way to write it was several hundred JNI round trips and it
was skipped. Paying 8× for a feature is a bad trade. Not shipping the feature is
a worse one, and that was the actual choice.

So: Slint wins the half that renders daemon data, loses the half that talks to
Android, and the two roughly trade off in volume. Which half you weight decides
the answer, and for this app the framework half is the product.

## Would I ship it

For this app, no — not as the primary frontend. The framework side is half the
product, and Kotlin gets it for free while Rust pays for every call and loses
compile-time checking on the part most likely to break across Android releases.

Running it on hardware sharpened *why*, and not in the way expected. The feared
failure — a mistyped JNI signature surfacing as a runtime `NoSuchMethodError` —
did not happen once: `bind_java_type!` declarations transcribed carefully from
the SDK docs were simply correct. The real cost was everything Android does
implicitly for an app built the normal way. An ordinary Activity gets inset
handling from its theme. `Log` goes to logcat without a bridge. A Kotlin
`SimpleDateFormat` knows the device's timezone. `ip rule` output with a tab in
it renders in a `TextView` and comes out as `13000:▯fwmark` in Slint. Each of
those was a separate on-device debugging session, and none of them is about the
UI toolkit — they are the cost of leaving the platform's default build behind.

### What the cargo-rapk migration changed, and what it did not

Migrating the APK build from `cargo-apk` to `cargo-rapk` was worth doing, and it
moved the conclusion less than expected.

It removed a real category of cost: the build script's Java half, the
`android-build` dependency, the JDK version guard, the `android.jar` discovery,
the embedded dex, the `InMemoryDexClassLoader`, and — most importantly — the
*assumption* that adding Java was expensive. Under that assumption the
installed-app list had been written off and not built at all. It took one Java
class.

It also disproved something written confidently here: that `RegisterNatives` was
the price of keeping the dex in the `.so`. It is not. `NativeActivity` `dlopen`s
the app's library instead of going through `System.loadLibrary`, so the VM never
knows the library is loaded and symbol lookup cannot work however the class is
packaged. The workaround survived the migration that was supposed to delete it.

What it did not change is the shape of the trade. Java in the APK is *available*
now, not cheap: the app list is about 200 lines against Kotlin's 25. Every
framework feature is still either a JNI transcription with no compile-time
checking, or a Java file plus a Rust parser plus a drift test. Kotlin is one
expression the compiler checks.

### The verdict

For a frontend that mostly renders daemon data — which is most of this app's
screens — Slint is clearly good, and the desktop harness alone is a real
productivity win. For the half that talks to Android it is not, and no build
tool fixes that.

The genuine and lasting result of the experiment is the shared `netdiag-ipc`
crate: it deleted 435 lines of hand-written Kotlin protocol code and left one
implementation of the wire format instead of two. That was worth doing
regardless of which UI wins — and it only happened because something else
needed to speak the protocol.

## Afterword: the frontend that lost the argument was kept

This document recommends Compose. The project went the other way, and the
Compose frontend has since been deleted. Both of those are true, and the
document is left as written rather than quietly revised, because the reason is
worth recording.

The analysis above optimises for one thing: the best tool for the least effort.
On that measure the conclusion still holds — the framework half costs about 1.8×
in Rust and loses compile-time checking, and nothing found since changes that.

But this is a personal instrument, not a product with an audience, and its owner
had already written Compose apps. Under *that* objective the same facts read
differently:

| | as a product | as this project |
|---|---|---|
| framework layer costs 1.8× | overhead | the part worth learning |
| `RegisterNatives` forced by `NativeActivity`'s `dlopen` | a wart | a fact about Android worth knowing |
| Slint tracked on `master`, `cargo-rapk` at 0.21, JDK pinned ≤ 21 | unacceptable risk | acceptable, and more interesting |

A cost is only a cost relative to what you are buying. This document measured
effort because that is what a product optimises; the project was optimising for
what the effort teaches. Both columns are honest; they are answers to different
questions, and the document never asked which question applied.

What the removal actually took was small, because the shared `netdiag-ipc` crate
had already absorbed the protocol: two screens, no new RPCs, no protocol work.
The sockets screen reads the snapshot the overview already fetches, and capture
reuses the streaming and cancellation that `Diagnose` and `WatchNetwork` use.

Two things found while closing the gap are worth keeping:

- **The "apps only" socket filter was hard-coded to Android's uid floor.** On a
  Linux desktop every uid is below 10000, so the desktop harness rendered an
  empty list with "119 hidden by filters" underneath. The floor now comes from
  the platform — 10000 on Android, 1000 on Linux — which is the same concept
  drawn where each system draws it.
- **"The interface with a default route" is the wrong default on Android.**
  Every network has its own table and its own default route, and the first one
  found on a real phone was `dummy0` in table 1002. The framework's active
  network is the right question to ask.

The wrapping tab bar is the second place `FlexboxLayout` earned its keep: seven
tabs fit one row on a Pixel and not at the 320px this window claims as its
minimum, and one piece of markup covers both.
