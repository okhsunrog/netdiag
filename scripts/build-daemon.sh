#!/usr/bin/env bash
#
# Cross-compile the Rust daemon for Android and place it where the APK build
# will pick it up.
#
# The binary is installed as `libnetdiagd.so`, which looks odd for an
# executable. It is deliberate: the package installer extracts files from
# `lib/<abi>/` into a directory that permits execution, and it only does that
# for names matching `lib*.so`. Anything shipped as an asset lands on a noexec
# mount, and copying a binary out at runtime is exactly what the W^X
# restrictions on recent Android releases prevent. Naming it as a library is
# the supported way to ship an executable in an APK.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON_DIR="$REPO_ROOT/daemon"
# cargo-rapk copies this tree into the APK's lib/<abi>/ verbatim; the directory
# is named in slint-app/Cargo.toml as `runtime_libs`.
JNI_LIBS_DIR="$REPO_ROOT/slint-app/runtime-libs"

ABI="${ABI:-arm64-v8a}"
PROFILE="${PROFILE:-release}"
API_LEVEL="${API_LEVEL:-31}"

case "$ABI" in
    arm64-v8a)     RUST_TARGET="aarch64-linux-android" ;;
    armeabi-v7a)   RUST_TARGET="armv7-linux-androideabi" ;;
    x86_64)        RUST_TARGET="x86_64-linux-android" ;;
    x86)           RUST_TARGET="i686-linux-android" ;;
    *)
        echo "error: unsupported ABI '$ABI'" >&2
        exit 1
        ;;
esac

if [[ -z "${ANDROID_NDK_HOME:-}" && -z "${ANDROID_NDK_ROOT:-}" ]]; then
    echo "error: set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to your NDK path" >&2
    exit 1
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "error: cargo-ndk is not installed. Run: cargo install cargo-ndk" >&2
    exit 1
fi

if ! command -v protoc >/dev/null 2>&1; then
    echo "error: protoc is not installed; prost-build needs it to generate the API" >&2
    exit 1
fi

echo "building netdiagd for $ABI ($RUST_TARGET, API $API_LEVEL, $PROFILE)"

cd "$DAEMON_DIR"

BUILD_ARGS=(ndk -t "$ABI" -P "$API_LEVEL" build)
if [[ "$PROFILE" == "release" ]]; then
    BUILD_ARGS+=(--release)
fi

cargo "${BUILD_ARGS[@]}"

BINARY="$(cargo build --message-format=json --quiet 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if message.get("reason") == "compiler-artifact" and message.get("executable"):
        print(message["executable"])
' | head -1)"

# cargo-ndk writes to the target directory for the cross target; find it
# relative to whatever target dir cargo is actually using.
TARGET_DIR="$(dirname "$(dirname "$BINARY")")"
SOURCE="$TARGET_DIR/$RUST_TARGET/$PROFILE/netdiagd"

if [[ ! -f "$SOURCE" ]]; then
    echo "error: built binary not found at $SOURCE" >&2
    exit 1
fi

mkdir -p "$JNI_LIBS_DIR/$ABI"
DEST="$JNI_LIBS_DIR/$ABI/libnetdiagd.so"
cp "$SOURCE" "$DEST"
chmod 755 "$DEST"

SIZE="$(du -h --apparent-size "$DEST" | cut -f1)"
echo "installed $DEST ($SIZE)"
echo
echo "next: cd slint-app && cargo rapk build --lib"
