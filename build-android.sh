#!/usr/bin/env bash
# Builds libdoodleart_core.so for the Kotlin :security module with cargo-ndk.
#
#   ./build-android.sh <debug|qa|release> [--out DIR] [--abi ABI]... [--platform API]
#
#   build type  selects the embedded server keys (config/server-keys.<type>.conf or $DOODLEART_SERVER_KEYS_FILE) and the
#               APK signing-cert allowlist (cargo feature build-<type>). qa / release refuse to build until the owner
#               has supplied the real server public key.
#   --out       jniLibs root (default: target/jniLibs/<type>); the .so lands in <out>/<abi>/libdoodleart_core.so
#   --abi       arm64-v8a, armeabi-v7a, x86_64 (default: all three); repeatable
#   --platform  minimum API level (default 24 = app minSdk)
#
# Always the hardened release profile (LTO, codegen-units=1, stripped, panic=unwind + catch_unwind at the FFI
# boundary), 16 KB page alignment, source paths remapped. After the build, tools/check-so.sh verifies exports,
# alignment and string hygiene of every produced library and fails the build otherwise; with DOODLEART_CHECK_IMPORTS=1
# (core:check in CI) it also compares the dynamic imports with tests/fixtures/android-imports/<type>-<abi>.txt.
#
# Environment: ANDROID_NDK_HOME (default: newest NDK >= 27 under $ANDROID_HOME/ndk), ANDROID_HOME
# (default ~/Library/Android/sdk), DOODLEART_SERVER_KEYS_FILE (optional key config override), DOODLEART_PROJECT_CONF
# (optional project config instead of config/project.conf, relative to this crate; a release build also needs
# DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1, see build.rs). OBFSTR_SEED is not read from the caller: the script exports the
# project config's value, or unsets it when the config has none. DOODLEART_APPLE_LIB (build-ios.sh's) is unset: an
# Android library is never an Apple library. DOODLEART_CHECK_IMPORTS=1: see above.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_TYPE="${1:-}"
shift || true
case "$BUILD_TYPE" in
  debug | qa | release) ;;
  *)
    echo "usage: $0 <debug|qa|release> [--out DIR] [--abi ABI]... [--platform API]" >&2
    exit 2
    ;;
esac

OUT="$CRATE_DIR/target/jniLibs/$BUILD_TYPE"
PLATFORM=24
ABIS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --abi) ABIS+=("$2"); shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ ${#ABIS[@]} -gt 0 ]] || ABIS=(arm64-v8a armeabi-v7a x86_64)
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  # NDK r27+ (r28 links 16 KB-aligned by default; the flag below makes it explicit for every version).
  ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | awk -F/ '{ split($NF, v, "."); if (v[1] >= 27) print }' | tail -n 1)"
fi
[[ -d "${ANDROID_NDK_HOME:-}" ]] || { echo "no NDK >= 27 found; set ANDROID_NDK_HOME" >&2; exit 1; }
export ANDROID_NDK_HOME

command -v cargo-ndk >/dev/null || { echo "cargo-ndk missing: cargo install cargo-ndk" >&2; exit 1; }
for triple in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
  rustup target list --installed 2>/dev/null | grep -qx "$triple" || echo "warning: rustup target $triple not installed" >&2
done

# The obfstr crate reads OBFSTR_SEED from the environment when it compiles; a build script cannot set it. Export exactly
# the project config's value (build.rs validates the config and fails a release build when the environment disagrees),
# and nothing when the config leaves it unset, so a seed left in the caller's shell never changes the library.
PROJECT_CONF="${DOODLEART_PROJECT_CONF:-config/project.conf}"
[[ "$PROJECT_CONF" == /* ]] || PROJECT_CONF="$CRATE_DIR/$PROJECT_CONF"
[[ -f "$PROJECT_CONF" ]] || { echo "project config not found: $PROJECT_CONF" >&2; exit 1; }
SEED="$(sed -E -n -e 's/#.*//' -e 's/^[[:space:]]*OBFSTR_SEED[[:space:]]*=[[:space:]]*//p' "$PROJECT_CONF" |
  tail -n 1 | sed -E 's/[[:space:]]+$//')"
if [[ -n "$SEED" ]]; then
  export OBFSTR_SEED="$SEED"
  SEED_SOURCE=project
else
  unset OBFSTR_SEED
  SEED_SOURCE=default
fi

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
SYSROOT="$(rustc --print sysroot)"
# rustc applies the LAST matching --remap-path-prefix, so go from general to specific: $HOME, then the sysroot,
# registry and crate (all usually under $HOME), then every source file.
RUSTFLAGS_LIST=(
  "-C" "link-arg=-Wl,-z,max-page-size=16384"
  "-C" "link-arg=-Wl,-z,now"
  "-C" "debuginfo=0"
  "--remap-path-prefix=$HOME=~"
  "--remap-path-prefix=$SYSROOT=rust"
  "--remap-path-prefix=$CARGO_HOME_DIR/registry/src=crates"
  "--remap-path-prefix=$CRATE_DIR=doodleart-core"
)
# Panic locations embed source paths ("src/risk/frida.rs") even in stripped binaries: every source file is mapped to a
# neutral, keyed, stable name, src/m<first 8 hex of SHA-256(REMAP_SALT || 0x00 || path)>.rs (tools/remap-paths.sh,
# shared with build-ios.sh; REMAP_SALT comes from the project config and is required).
# shellcheck source=tools/remap-paths.sh
source "$CRATE_DIR/tools/remap-paths.sh"
REMAP_SALT="$(doodleart_remap_salt "$PROJECT_CONF")"
doodleart_remap_flags "$CRATE_DIR" "$REMAP_SALT"
# CARGO_ENCODED_RUSTFLAGS keeps each flag whole (separated by 0x1f): RUSTFLAGS is split on spaces, which breaks
# every path flag as soon as $HOME, the crate or the sysroot contains a space. It also wins over RUSTFLAGS and the
# target rustflags of .cargo/config.toml, so nothing else is merged in.
unset RUSTFLAGS DOODLEART_APPLE_LIB
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${RUSTFLAGS_LIST[*]}")"
export CARGO_ENCODED_RUSTFLAGS

target_args=()
for abi in "${ABIS[@]}"; do
  target_args+=(-t "$abi")
done

echo "doodleart-core: build type=$BUILD_TYPE abis=${ABIS[*]} platform=$PLATFORM ndk=$(basename "$ANDROID_NDK_HOME") out=$OUT obfstr-seed=$SEED_SOURCE"
(
  cd "$CRATE_DIR"
  cargo ndk "${target_args[@]}" -P "$PLATFORM" -o "$OUT" \
    build --release --locked --no-default-features --features "build-$BUILD_TYPE"
)

if [[ "${DOODLEART_CHECK_IMPORTS:-}" == 1 ]]; then
  "$CRATE_DIR/tools/check-so.sh" --imports-baseline "$BUILD_TYPE" "$OUT" "${ABIS[@]}"
else
  "$CRATE_DIR/tools/check-so.sh" "$OUT" "${ABIS[@]}"
fi
