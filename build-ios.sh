#!/usr/bin/env bash
# Builds DoodleArtCore.xcframework, doodleart-core for the iOS app (Swift package DoodleArtSecurity; theme-x spec 2026-11-05 §4.5).
#
#   ./build-ios.sh <debug|release> [--out DIR] [--no-xcframework] [--install DIR]
#
#   build type  debug (feature build-debug, kid 2026-11 of the local app service) or release (build-release,
#               config/server-keys.release.conf or $DOODLEART_SERVER_KEYS_FILE: a placeholder until the owner sets the
#               production key, so a release build stops). There is no qa build for iOS (theme-x Q-11).
#   --out       output directory (default: $CARGO_TARGET_DIR/ios/<type>, else target/ios/<type>)
#   --no-xcframework
#               stop before xcodebuild: build, prelink, strip and check the three slices, then package them as
#               DoodleArtCore-<type>.slices.zip (packaging "slices": for checks and tests, never for an app). For
#               machines without Xcode (CommandLineTools only).
#   --install   also copy what an app links into DIR/<type>/: <triple>/libdoodleart_core.a of the three iOS slices,
#               include/{doodleart_core.h,module.modulemap} and DoodleArtCore.manifest.json, for an app that finds them
#               by build settings (SWIFT_INCLUDE_PATHS and LIBRARY_SEARCH_PATHS with SDK and arch conditions) instead
#               of an xcframework, so only the configuration that wants the core uses it (README.md). This module map (unlike the xcframework's)
#               carries `link "doodleart_core"`: the `import DoodleArtCore` autolinks the library, and an app built
#               without DIR (no module, `#if canImport(DoodleArtCore)` false) links nothing and still builds.
#
# Slices: aarch64-apple-ios (devices), aarch64-apple-ios-sim (Simulator on Apple silicon), x86_64-apple-ios (Simulator on
# Intel Macs, and the x86_64 half of a generic Simulator build), aarch64-apple-darwin (macOS, only for host tests; never
# shipped). The xcframework keeps the three arm64 slices (theme-x §4.5, Q-15); the x86_64 Simulator slice goes to
# --install only. Deployment targets:
# iOS 16.0 (ios/ios_doodle_art/Podfile `platform :ios, '16.0'`) and macOS 13.0: the macOS release of the iOS 16 generation;
# every Mac that runs Xcode 15 or later runs macOS 13.5 or later, so the slice links into the package's host tests
# without "built for newer macOS" warnings as long as Package.swift declares .macOS(.v13) or later.
#
# Each slice: `DOODLEART_APPLE_LIB=1 cargo rustc --lib --release --locked --no-default-features --features build-<type>
# --crate-type staticlib --target <triple>` (build.rs: an Apple library, cfg doodleart_apple_lib, so the C ABI of
# src/ffi.rs and the Apple scan are compiled and the Android parts are not, the macOS slice included; no workspace,
# spec deviation D-P4-2), every source path remapped exactly like build-android.sh, OBFSTR_SEED from the project
# config. Before the prelink, the symbols the Rust staticlib defines are checked (llvm-nm): no JNI_OnLoad / Java_*, no
# doodleart_* function the header does not declare, no doodleart_debug_* in a release library. The prelink below hides
# everything it does not export, so such a symbol would no longer show as an export afterwards.
# Then the public surface of the static library is reduced: `ld -r` prelinks the Rust staticlib into ONE relocatable
# object, loading only the archive members the exported functions need (-u per export: compiler_builtins members
# carrying LLVM bitcode are not pulled in), keeps only the functions of include/doodleart_core.h global
# (-exported_symbols_list; everything else, rust_eh_personality and the compiler-rt helpers included, becomes local),
# renames the local symbols to temporary names (-x: otherwise names like risk::port::frida_port_open stay readable) and
# writes no debug map (-S: no STABS naming the cargo objects; ld -r never copies the inputs' DWARF, and with -x the
# output is byte-identical without -S, so -S only guards a future change). `strip -x` afterwards removes nothing more
# (measured: it rewrites the object 1.4 KB larger), so it is not run. libtool wraps the object into
# libdoodleart_core.a (ZERO_AR_DATE=1: no timestamps). tools/check-macho.sh then checks every slice.
# The host slice is linked with tests/c-abi/init_info.c and run: the manifest must agree with what the library
# reports (build type, crate version, kids, ABI version, project id).
#
# Output in --out:
#   slices/<triple>/libdoodleart_core.a, Headers/DoodleArtCore/{doodleart_core.h,module.modulemap}
#     The headers sit in a DoodleArtCore/ subdirectory: Xcode copies the Headers of every static-library xcframework
#     into one include/ directory, where two module.modulemap files at the top would collide. `import DoodleArtCore`
#     finds Headers/DoodleArtCore/module.modulemap through the Headers search path (checked with clang and swiftc).
#   DoodleArtCore.xcframework (xcodebuild -create-xcframework), or DoodleArtCore-slices/ with --no-xcframework
#   DoodleArtCore.manifest.json: schema, module, packaging, projectId, buildType, kids, crateVersion, abiVersion, gitSha,
#     gitDirty, rustc, deploymentTargets, nativeStaticLibs, headers, sha256. sha256 maps every file the app consumes
#     (<triple>/libdoodleart_core.a for each slice, Headers/DoodleArtCore/<file>) to its SHA-256; xcodebuild copies the
#     libraries unchanged, so the same digests hold inside the xcframework.
#   DoodleArtCore-<type>.xcframework.zip (or .slices.zip): the payload directory and the manifest, deterministic (sorted,
#     fixed dates and modes, no extra attributes). Its own SHA-256 cannot be inside it: it is in <zip>.sha256
#     (shasum format) and in the iOS app's core.lock; tools/fetch-core.sh verifies it before unpacking.
#   DoodleArtCore-<type>.manifest.json: a copy of the manifest, published next to the zip.
#
# Needs macOS with the rustup targets aarch64-apple-ios, aarch64-apple-ios-sim and aarch64-apple-darwin, the rustup
# llvm-tools component (check-macho.sh), Apple's ld and libtool (CommandLineTools are enough), clang, python3, zip and
# git; xcodebuild of a full Xcode unless --no-xcframework. Honours CARGO_TARGET_DIR. Environment as build-android.sh:
# DOODLEART_SERVER_KEYS_FILE, DOODLEART_PROJECT_CONF (a release build also needs DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1);
# OBFSTR_SEED is never taken from the caller.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DEPLOYMENT_TARGET=16.0
MACOS_DEPLOYMENT_TARGET=13.0
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin)
# The slices of the xcframework (arm64 only) and of --install (the app).
XCFRAMEWORK_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
INSTALL_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
HOST_TARGET=aarch64-apple-darwin
MODULE=DoodleArtCore

usage() {
  echo "usage: $0 <debug|release> [--out DIR] [--no-xcframework] [--install DIR]" >&2
  exit 2
}
die() {
  echo "build-ios: $*" >&2
  exit 1
}

BUILD_TYPE="${1:-}"
shift || true
case "$BUILD_TYPE" in
  debug | release) ;;
  qa) die "there is no qa build for iOS (theme-x spec 2026-11-05 Q-11): use debug or release" ;;
  *) usage ;;
esac
OUT=""
XCFRAMEWORK=1
INSTALL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) [[ $# -ge 2 ]] || usage; OUT="$2"; shift 2 ;;
    --install) [[ $# -ge 2 ]] || usage; INSTALL="$2"; shift 2 ;;
    --no-xcframework) XCFRAMEWORK=0; shift ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
[[ -n "$OUT" ]] || OUT="${CARGO_TARGET_DIR:-$CRATE_DIR/target}/ios/$BUILD_TYPE"

# Prerequisites, each with the command that fixes it.
[[ "$(uname -s)" == Darwin ]] || die "macOS only (Apple ld, libtool, xcodebuild)"
for tool in cargo rustc rustup python3 clang ld libtool zip shasum git; do
  command -v "$tool" >/dev/null || die "$tool missing (Rust: https://rustup.rs; Apple tools: xcode-select --install)"
done
installed="$(rustup target list --installed 2>/dev/null)"
for triple in "${TARGETS[@]}"; do
  grep -qx "$triple" <<< "$installed" || die "rustup target $triple not installed: rustup target add $triple"
done
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="$SYSROOT/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
[[ -x "$LLVM_BIN/llvm-nm" && -x "$LLVM_BIN/llvm-objdump" ]] || die "llvm-tools missing: rustup component add llvm-tools"
if [[ $XCFRAMEWORK -eq 1 ]] && ! xcodebuild -version >/dev/null 2>&1; then
  die "xcodebuild of a full Xcode is needed to create $MODULE.xcframework (CommandLineTools have none: install Xcode,
then sudo xcode-select -s /Applications/Xcode.app). --no-xcframework builds and checks the slices without it."
fi

# OBFSTR_SEED exactly as build-android.sh: the project config's value, or unset.
PROJECT_CONF="${DOODLEART_PROJECT_CONF:-config/project.conf}"
[[ "$PROJECT_CONF" == /* ]] || PROJECT_CONF="$CRATE_DIR/$PROJECT_CONF"
[[ -f "$PROJECT_CONF" ]] || die "project config not found: $PROJECT_CONF"
SEED="$(sed -E -n -e 's/#.*//' -e 's/^[[:space:]]*OBFSTR_SEED[[:space:]]*=[[:space:]]*//p' "$PROJECT_CONF" |
  tail -n 1 | sed -E 's/[[:space:]]+$//')"
if [[ -n "$SEED" ]]; then
  export OBFSTR_SEED="$SEED"
  SEED_SOURCE=project
else
  unset OBFSTR_SEED
  SEED_SOURCE=default
fi

# Source path remapping, the same flags as build-android.sh: rustc applies the LAST matching --remap-path-prefix, so
# general first ($HOME, sysroot, registry, crate), then every source file to its keyed name (tools/remap-paths.sh, one
# implementation for both scripts; REMAP_SALT of the project config).
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS_LIST=(
  "-C" "debuginfo=0"
  "--remap-path-prefix=$HOME=~"
  "--remap-path-prefix=$SYSROOT=rust"
  "--remap-path-prefix=$CARGO_HOME_DIR/registry/src=crates"
  "--remap-path-prefix=$CRATE_DIR=doodleart-core"
)
# shellcheck source=tools/remap-paths.sh
source "$CRATE_DIR/tools/remap-paths.sh"
REMAP_SALT="$(doodleart_remap_salt "$PROJECT_CONF")" || die "no valid REMAP_SALT in $PROJECT_CONF"
doodleart_remap_flags "$CRATE_DIR" "$REMAP_SALT" || die "source path remapping failed"
# Every slice, macOS included, is an Apple library (build.rs).
export DOODLEART_APPLE_LIB=1
unset RUSTFLAGS
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${RUSTFLAGS_LIST[*]}")"
export CARGO_ENCODED_RUSTFLAGS
# rustc stamps these into LC_BUILD_VERSION (minos) of the objects it emits.
export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
export ZERO_AR_DATE=1

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d "$OUT/.build-ios.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# The exported functions: those of the header, without the debug-only hooks in a release library.
sed -E -n 's/^(DoodleArtBuf|int32_t|void)[[:space:]]+(doodleart_[a-z0-9_]+)\(.*/_\2/p' "$CRATE_DIR/include/doodleart_core.h" |
  LC_ALL=C sort > "$STAGE/header-functions.txt"
cp "$STAGE/header-functions.txt" "$STAGE/exports.txt"
if [[ "$BUILD_TYPE" != debug ]]; then
  grep -v '^_doodleart_debug_' "$STAGE/exports.txt" > "$STAGE/exports.tmp" || true
  mv "$STAGE/exports.tmp" "$STAGE/exports.txt"
fi
[[ $(wc -l < "$STAGE/exports.txt") -ge 17 ]] || die "include/doodleart_core.h: fewer than 17 functions found"
UNDEFINED=()
while IFS= read -r symbol; do UNDEFINED+=(-u "$symbol"); done < "$STAGE/exports.txt"

echo "doodleart-core: iOS build type=$BUILD_TYPE targets=${TARGETS[*]} ios=$IOS_DEPLOYMENT_TARGET" \
  "macos=$MACOS_DEPLOYMENT_TARGET out=$OUT obfstr-seed=$SEED_SOURCE xcframework=$([[ $XCFRAMEWORK -eq 1 ]] && echo yes || echo no)"

NATIVE_LIBS=""
for triple in "${TARGETS[@]}"; do
  case "$triple" in
    aarch64-apple-ios) platform=ios; arch=arm64; minos="$IOS_DEPLOYMENT_TARGET" ;;
    aarch64-apple-ios-sim) platform=ios-simulator; arch=arm64; minos="$IOS_DEPLOYMENT_TARGET" ;;
    x86_64-apple-ios) platform=ios-simulator; arch=x86_64; minos="$IOS_DEPLOYMENT_TARGET" ;;
    aarch64-apple-darwin) platform=macos; arch=arm64; minos="$MACOS_DEPLOYMENT_TARGET" ;;
  esac
  echo "== $triple"
  json="$STAGE/cargo-$triple.json"
  log="$STAGE/cargo-$triple.log"
  if ! (cd "$CRATE_DIR" && cargo rustc --lib --release --locked --no-default-features --features "build-$BUILD_TYPE" \
    --crate-type staticlib --target "$triple" --message-format=json-render-diagnostics \
    -- --print native-static-libs) > "$json" 2> "$log"; then
    cat "$log" >&2
    die "cargo build failed for $triple"
  fi
  # The static library cargo produced, and the build_config.rs build.rs generated for this target (the build type,
  # kids and project id compiled into it).
  python3 -I - "$json" "$STAGE/build-$triple.txt" <<'PY'
import json, os, re, sys
library = out_dir = None
for line in open(sys.argv[1], encoding="utf-8"):
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message["target"]["name"] == "doodleart_core":
        library = next((name for name in message["filenames"] if name.endswith(".a")), library)
    elif message.get("reason") == "build-script-executed" and "doodleart-core" in message.get("package_id", ""):
        out_dir = message["out_dir"]
if not library or not out_dir:
    sys.exit("build-ios: no static library or build script output in the cargo messages")
config = open(os.path.join(out_dir, "build_config.rs"), encoding="utf-8").read()
build_type = re.search(r'^pub const BUILD_TYPE: &str = "([a-z]+)";$', config, re.M).group(1)
keys_block = re.search(r"^pub const SERVER_KEYS: [^=]+= &\[\n(.*?)^\];$", config, re.M | re.S).group(1)
kids = re.findall(r'^    \("([^"]*)", \[', keys_block, re.M)
project_id = re.search(r'^pub const PROJECT_ID: &str = "([a-z0-9-]+)";$', config, re.M).group(1)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write(f"library={library}\nbuildType={build_type}\nkids={','.join(kids)}\nprojectId={project_id}\n")
PY
  raw="$(sed -n 's/^library=//p' "$STAGE/build-$triple.txt")"
  [[ -f "$raw" ]] || die "static library missing: $raw"
  native="$(sed -n 's/^note: native-static-libs: //p' "$log" | tail -n 1)"
  [[ -n "$native" ]] || die "rustc printed no native-static-libs for $triple"
  [[ -z "$NATIVE_LIBS" || "$NATIVE_LIBS" == "$native" ]] ||
    die "native libraries differ between slices: $NATIVE_LIBS / $native"
  NATIVE_LIBS="$native"

  # What the Rust staticlib defines, before the prelink hides it (see the top of this file).
  "$LLVM_BIN/llvm-nm" --defined-only --extern-only --format=just-symbols "$raw" 2>/dev/null | LC_ALL=C sort -u \
    > "$STAGE/raw-defined-$triple.txt" || die "llvm-nm cannot read $raw"
  [[ -s "$STAGE/raw-defined-$triple.txt" ]] || die "llvm-nm found no symbol in $raw"
  raw_problems="$(
    grep -E '^_(JNI_OnLoad|Java_)' "$STAGE/raw-defined-$triple.txt" | sed 's/^/JNI symbol /' || true
    grep -E '^_doodleart_[a-z0-9_]+$' "$STAGE/raw-defined-$triple.txt" | grep -vxF -f "$STAGE/header-functions.txt" |
      sed 's/^/not declared by include\/doodleart_core.h: /' || true
    if [[ "$BUILD_TYPE" != debug ]]; then
      grep -E '^_doodleart_debug_' "$STAGE/raw-defined-$triple.txt" | sed 's/^/debug-only hook in a release library: /' || true
    fi
  )"
  [[ -z "$raw_problems" ]] || die "the $triple staticlib defines symbols it must not:
$raw_problems"

  mkdir -p "$STAGE/obj/$triple" "$STAGE/slices/$triple"
  if ! ld -r -arch "$arch" -platform_version "$platform" "$minos" "$minos" \
    -exported_symbols_list "$STAGE/exports.txt" -x -S "${UNDEFINED[@]}" "$raw" \
    -o "$STAGE/obj/$triple/doodleart_core.o" 2> "$STAGE/ld-$triple.log"; then
    cat "$STAGE/ld-$triple.log" >&2
    die "ld -r failed for $triple"
  fi
  [[ ! -s "$STAGE/ld-$triple.log" ]] || sed 's/^/   ld: /' "$STAGE/ld-$triple.log"
  libtool -static -no_warning_for_no_symbols -o "$STAGE/slices/$triple/libdoodleart_core.a" \
    "$STAGE/obj/$triple/doodleart_core.o"
  echo "   $(wc -c < "$raw" | tr -d ' ') bytes (cargo) ->" \
    "$(wc -c < "$STAGE/slices/$triple/libdoodleart_core.a" | tr -d ' ') bytes (prelinked)"
done

# All slices must embed the same configuration.
for key in buildType kids projectId; do
  values="$(for triple in "${TARGETS[@]}"; do sed -n "s/^$key=//p" "$STAGE/build-$triple.txt"; done | sort -u)"
  [[ $(printf '%s\n' "$values" | wc -l) -eq 1 && -n "$values" ]] || die "slices disagree on $key: $values"
done
EMBEDDED_TYPE="$(sed -n 's/^buildType=//p' "$STAGE/build-$HOST_TARGET.txt")"
KIDS="$(sed -n 's/^kids=//p' "$STAGE/build-$HOST_TARGET.txt")"
PROJECT_ID="$(sed -n 's/^projectId=//p' "$STAGE/build-$HOST_TARGET.txt")"
[[ "$EMBEDDED_TYPE" == "$BUILD_TYPE" ]] || die "build_config says $EMBEDDED_TYPE, not $BUILD_TYPE"

mkdir -p "$STAGE/Headers/$MODULE"
cp "$CRATE_DIR/include/doodleart_core.h" "$CRATE_DIR/include/module.modulemap" "$STAGE/Headers/$MODULE/"

# Link the shipped host slice with the shipped headers, run it, and read back what the library reports.
host_lib="$STAGE/slices/$HOST_TARGET/libdoodleart_core.a"
# shellcheck disable=SC2086 # $NATIVE_LIBS is a list of linker flags
clang -std=c11 -Wall -Wextra -Werror -pedantic -mmacosx-version-min="$MACOS_DEPLOYMENT_TARGET" \
  -I "$STAGE/Headers/$MODULE" "$CRATE_DIR/tests/c-abi/init_info.c" "$host_lib" ${NATIVE_LIBS//-lSystem/} \
  -o "$STAGE/init_info" || die "the prelinked $HOST_TARGET slice does not link with tests/c-abi/init_info.c"
"$STAGE/init_info" > "$STAGE/init_info.txt" || die "doodleart_init of the $HOST_TARGET slice failed"
CRATE_VERSION="$(cd "$CRATE_DIR" && cargo metadata --no-deps --format-version 1 --locked --offline | python3 -I -c '
import json, sys
print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "doodleart-core"))')"
ABI_VERSION="$(sed -n -E 's/^#define DOODLEART_ABI_VERSION ([0-9]+)$/\1/p' "$CRATE_DIR/include/doodleart_core.h")"
# expect_reported <field> <expected> <source of the expected value>
expect_reported() {
  local value
  value="$(sed -n "s/^$1=//p" "$STAGE/init_info.txt")"
  [[ "$value" == "$2" ]] || die "doodleart_init of the $HOST_TARGET slice reports $1 '$value', $3 says '$2'"
}
expect_reported buildType "$BUILD_TYPE" "the build type"
expect_reported crateVersion "$CRATE_VERSION" Cargo.toml
expect_reported kidsCsv "$KIDS" build_config.rs
expect_reported abiVersion "$ABI_VERSION" include/doodleart_core.h
expect_reported projectId "$PROJECT_ID" build_config.rs
echo "== $HOST_TARGET slice links and runs: $BUILD_TYPE $CRATE_VERSION kids=$KIDS abi=$ABI_VERSION project=$PROJECT_ID"

"$CRATE_DIR/tools/check-macho.sh" --type "$BUILD_TYPE" "$STAGE/slices"

GIT_SHA="$(git -C "$CRATE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
# Dirty unless git proves the crate clean (a git error, e.g. an unsafe.directory refusal, counts as dirty).
GIT_DIRTY=true
if git_status="$(git -C "$CRATE_DIR" status --porcelain -- . 2>/dev/null)" && [[ -z "$git_status" ]]; then
  GIT_DIRTY=false
fi
if [[ $XCFRAMEWORK -eq 1 ]]; then
  PACKAGING=xcframework PAYLOAD="$MODULE.xcframework" ZIP="$MODULE-$BUILD_TYPE.xcframework.zip"
  PACKAGED_TARGETS=("${XCFRAMEWORK_TARGETS[@]}")
else
  PACKAGING=slices PAYLOAD="$MODULE-slices" ZIP="$MODULE-$BUILD_TYPE.slices.zip"
  PACKAGED_TARGETS=("${TARGETS[@]}")
fi

python3 -I - "$STAGE" "$STAGE/$MODULE.manifest.json" "$MODULE" "$PACKAGING" "$PROJECT_ID" "$BUILD_TYPE" "$KIDS" \
  "$CRATE_VERSION" "$ABI_VERSION" "$GIT_SHA" "$GIT_DIRTY" "$(rustc --version)" "$IOS_DEPLOYMENT_TARGET" \
  "$MACOS_DEPLOYMENT_TARGET" "$NATIVE_LIBS" "${PACKAGED_TARGETS[@]}" <<'PY'
import hashlib, json, os, sys
(stage, out, module, packaging, project_id, build_type, kids, crate_version, abi_version, git_sha, git_dirty, rustc,
 ios, macos, native, *targets) = sys.argv[1:]
def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()
hashes = {f"{triple}/libdoodleart_core.a": digest(os.path.join(stage, "slices", triple, "libdoodleart_core.a"))
          for triple in targets}
for name in ("doodleart_core.h", "module.modulemap"):
    hashes[f"Headers/{module}/{name}"] = digest(os.path.join(stage, "Headers", module, name))
manifest = {
    "schema": 1,
    "module": module,
    "packaging": packaging,
    "projectId": project_id,
    "buildType": build_type,
    "kids": kids.split(","),
    "crateVersion": crate_version,
    "abiVersion": int(abi_version),
    "gitSha": git_sha,
    "gitDirty": git_dirty == "true",
    "rustc": rustc,
    "deploymentTargets": {"iOS": ios, "macOS": macos},
    "nativeStaticLibs": native,
    "headers": f"Headers/{module}",
    "sha256": hashes,
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
PY

mkdir -p "$STAGE/pkg"
if [[ $XCFRAMEWORK -eq 1 ]]; then
  xcargs=()
  for triple in "${XCFRAMEWORK_TARGETS[@]}"; do
    xcargs+=(-library "$STAGE/slices/$triple/libdoodleart_core.a" -headers "$STAGE/Headers")
  done
  xcodebuild -create-xcframework "${xcargs[@]}" -output "$STAGE/pkg/$PAYLOAD" > "$STAGE/xcodebuild.log" 2>&1 ||
    { cat "$STAGE/xcodebuild.log" >&2; die "xcodebuild -create-xcframework failed"; }
else
  mkdir -p "$STAGE/pkg/$PAYLOAD"
  for triple in "${PACKAGED_TARGETS[@]}"; do
    cp -R "$STAGE/slices/$triple" "$STAGE/pkg/$PAYLOAD/"
  done
  cp -R "$STAGE/Headers" "$STAGE/pkg/$PAYLOAD/"
fi
cp "$STAGE/$MODULE.manifest.json" "$STAGE/pkg/"
# The package as shipped: the xcframework's Info.plist (exactly the three arm64 slices, headers beside each), every
# library inside it (identifier and platform must agree) and the manifest (its sha256 must list exactly them).
"$CRATE_DIR/tools/check-macho.sh" --type "$BUILD_TYPE" "$STAGE/pkg" > "$STAGE/check-package.log" 2>&1 ||
  { cat "$STAGE/check-package.log" >&2; die "the packaged $PAYLOAD fails tools/check-macho.sh"; }
grep -E '^   (xcframework|manifest):' "$STAGE/check-package.log" || true
# Deterministic zip: sorted entries, fixed modes and dates (TZ=UTC: zip stores local DOS time), no directory entries,
# no extra attributes.
(
  cd "$STAGE/pkg"
  find . -type d -exec chmod 755 {} +
  find . -type f -exec chmod 644 {} +
  TZ=UTC find . -exec touch -h -t 198001010000.00 {} +
  find "$PAYLOAD" "$MODULE.manifest.json" -type f | LC_ALL=C sort | TZ=UTC zip -X -D -q -@ "$STAGE/$ZIP"
)
(cd "$STAGE" && shasum -a 256 "$ZIP" > "$ZIP.sha256")
cp "$STAGE/$MODULE.manifest.json" "$STAGE/$MODULE-$BUILD_TYPE.manifest.json"

# Replace the previous outputs of this script in OUT (only those names: OUT may hold other files).
for name in slices Headers "$MODULE.xcframework" "$MODULE-slices" "$MODULE.manifest.json" \
  "$MODULE-$BUILD_TYPE.xcframework.zip" "$MODULE-$BUILD_TYPE.xcframework.zip.sha256" \
  "$MODULE-$BUILD_TYPE.slices.zip" "$MODULE-$BUILD_TYPE.slices.zip.sha256" "$MODULE-$BUILD_TYPE.manifest.json"; do
  rm -rf "${OUT:?}/$name"
done
mv "$STAGE/slices" "$STAGE/Headers" "$STAGE/pkg/$PAYLOAD" "$STAGE/$MODULE.manifest.json" "$STAGE/$ZIP" \
  "$STAGE/$ZIP.sha256" "$STAGE/$MODULE-$BUILD_TYPE.manifest.json" "$OUT/"

echo "doodleart-core: $OUT/$ZIP ($(wc -c < "$OUT/$ZIP" | tr -d ' ') bytes, sha256 $(cut -d ' ' -f 1 "$OUT/$ZIP.sha256"))"
if [[ -n "$INSTALL" ]]; then
  dest="$INSTALL/$BUILD_TYPE"
  rm -rf "$dest"
  mkdir -p "$dest/include"
  for triple in "${INSTALL_TARGETS[@]}"; do
    mkdir -p "$dest/$triple"
    cp "$OUT/slices/$triple/libdoodleart_core.a" "$dest/$triple/"
  done
  cp "$OUT/Headers/$MODULE/doodleart_core.h" "$dest/include/"
  cat > "$dest/include/module.modulemap" <<MODULEMAP
// Clang module of the C ABI for the iOS app (written by build-ios.sh --install): \`import $MODULE\` autolinks
// libdoodleart_core.a, found through LIBRARY_SEARCH_PATHS of the configuration (doodleart-core/README.md).
module $MODULE {
    header "doodleart_core.h"
    link "doodleart_core"
    export *
}
MODULEMAP
  cp "$OUT/$MODULE.manifest.json" "$dest/"
  echo "doodleart-core: installed ${INSTALL_TARGETS[*]} + include/ + manifest into $dest"
fi
if [[ $XCFRAMEWORK -eq 0 ]]; then
  echo "doodleart-core: --no-xcframework: $ZIP holds the bare slices (packaging slices), not an xcframework"
fi
if [[ "$GIT_DIRTY" == true ]]; then
  echo "doodleart-core: warning: built from uncommitted changes under $CRATE_DIR (gitDirty: not publishable)"
fi
