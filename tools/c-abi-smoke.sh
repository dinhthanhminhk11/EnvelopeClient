#!/usr/bin/env bash
# C ABI smoke test of the iOS interface (theme-x spec 2026-11-05 §4.4, §7.1), on the macOS host: for each build type, builds
# the host static library (aarch64-apple-darwin, `DOODLEART_APPLE_LIB=1 cargo rustc --crate-type staticlib`, the way the
# iOS slices are built), then
#   1. checks its exported symbols: exactly the functions of include/doodleart_core.h (doodleart_debug_* only in debug),
#      no JNI_OnLoad, no Java_*;
#   2. compiles the header as strict C11 and C++17 and imports include/module.modulemap as the clang module
#      DoodleArtCore (Objective-C @import);
#   3. links and runs tests/c-abi/smoke.c (every vector of tests/fixtures, the Apple risk scan in a traced child),
#      smoke.cpp (extern "C" names), smoke.m (module import) and, when swiftc is present, smoke.swift (what
#      `import DoodleArtCore` gives Swift);
#   4. links and runs tests/c-abi/risk_probe.c: the Apple scan's hook and frida checks fire in the library as built
#      (DYLD_INSERT_LIBRARIES set, a "libhooker" library loaded, a listener on 127.0.0.1:27042, a "frida-gadget"
#      library loaded), which the imports check of check-macho.sh cannot prove (Rust std imports the same dyld and
#      getenv functions);
#   5. links tests/c-abi/two_rust.c with the library AND tests/c-abi/other_rust.rs, an ordinary Rust staticlib (its std
#      and runtime global), and runs it: the "Linking" promise of include/doodleart_core.h (no duplicate symbol; each
#      library catches its own panics and keeps its own panic hook). It holds for the prelinked library of
#      build-ios.sh, so with --prebuilt a link failure fails; the raw cargo staticlib exports its Rust runtime and
#      clashes with the other one (reported, not a failure: the prelink is what hides it), and if it links, it must
#      pass the same run. A panic inside a doodleart_* function cannot be caused from C: src/ffi/tests.rs covers it.
# Once, before the libraries: tests/c-abi/kinfo_layout.c against the host SDK must print
# tests/fixtures/kinfo-proc-macos-sdk.txt, the struct kinfo_proc layout the debugger check of src/risk/apple.rs uses
# (its unit test compares the same file with the Rust constants); and the plain host build (`cargo build --lib`, no
# DOODLEART_APPLE_LIB: what a Kotlin host harness loads into a JVM) must export JNI_OnLoad and no
# doodleart_* function, while the Apple libraries never contain JNI_OnLoad (build.rs, cfg doodleart_apple_lib).
#
#   tools/c-abi-smoke.sh [debug|release]...      (default: debug release)
#   tools/c-abi-smoke.sh --prebuilt <type>=<dir>...
#
# --prebuilt tests a build-ios.sh output instead of building: the shipped, prelinked host slice
# <dir>/slices/aarch64-apple-darwin/libdoodleart_core.a with the shipped headers <dir>/Headers/DoodleArtCore (the module map
# found through <dir>/Headers, as Xcode finds it) and the manifest's nativeStaticLibs. The build type must match the
# manifest; a type with no --prebuilt is built as usual when it is listed.
#
# Needs macOS with Apple clang (the CommandLineTools are enough; no Xcode, no iOS SDK), python3, and the rustup
# llvm-tools component (`rustup component add llvm-tools`): Apple's nm cannot read the LLVM 21 bitcode members of a
# Rust static library. Honours CARGO_TARGET_DIR. Like build-android.sh it exports OBFSTR_SEED from the project config
# (DOODLEART_PROJECT_CONF, default config/project.conf) and unsets it when the config has none.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_TARGET=aarch64-apple-darwin
usage() {
  echo "usage: $0 [debug|release]... | $0 --prebuilt <debug|release>=<build-ios.sh output dir>..." >&2
  exit 2
}
TYPES=()
PREBUILT_debug=""
PREBUILT_release=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    debug | release) TYPES+=("$1"); shift ;;
    --prebuilt)
      [[ $# -ge 2 ]] || usage
      case "$2" in
        debug=?*) PREBUILT_debug="${2#debug=}"; TYPES+=(debug) ;;
        release=?*) PREBUILT_release="${2#release=}"; TYPES+=(release) ;;
        *) usage ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done
[[ ${#TYPES[@]} -gt 0 ]] || TYPES=(debug release)

[[ "$(uname -s)" == Darwin ]] || { echo "c-abi-smoke: macOS only (host target $HOST_TARGET)" >&2; exit 1; }
command -v clang >/dev/null || { echo "c-abi-smoke: clang missing (xcode-select --install)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "c-abi-smoke: python3 missing" >&2; exit 1; }
SYSROOT="$(rustc --print sysroot)"
LLVM_NM="$SYSROOT/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-nm"
[[ -x "$LLVM_NM" ]] || { echo "c-abi-smoke: $LLVM_NM missing: rustup component add llvm-tools" >&2; exit 1; }

PROJECT_CONF="${DOODLEART_PROJECT_CONF:-config/project.conf}"
[[ "$PROJECT_CONF" == /* ]] || PROJECT_CONF="$CRATE_DIR/$PROJECT_CONF"
[[ -f "$PROJECT_CONF" ]] || { echo "project config not found: $PROJECT_CONF" >&2; exit 1; }
conf_value() {
  sed -E -n -e 's/#.*//' -e "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$PROJECT_CONF" | tail -n 1 |
    sed -E 's/[[:space:]]+$//'
}
SEED="$(conf_value OBFSTR_SEED)"
if [[ -n "$SEED" ]]; then export OBFSTR_SEED="$SEED"; else unset OBFSTR_SEED; fi
PROJECT_ID="$(conf_value PROJECT_ID)"
# The libraries built here are Apple libraries, like build-ios.sh's slices (build.rs).
export DOODLEART_APPLE_LIB=1

WORK="$(mktemp -d "${TMPDIR:-/tmp}/doodleart-c-abi.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
python3 -I "$CRATE_DIR/tests/c-abi/gen_vectors.py" "$CRATE_DIR/../server/src/core/envelope/testdata" "$WORK/vectors.h"

# Function names the header declares, sorted.
header_functions() {
  sed -E -n 's/^(DoodleArtBuf|int32_t|void)[[:space:]]+(doodleart_[a-z0-9_]+)\(.*/\2/p' "$CRATE_DIR/include/doodleart_core.h" |
    LC_ALL=C sort
}

status=0
fail() {
  echo "   FAIL $*"
  status=1
}

echo "== kinfo_proc layout"
if clang -std=c11 -Wall -Wextra -Werror -pedantic -o "$WORK/kinfo_layout" "$CRATE_DIR/tests/c-abi/kinfo_layout.c" &&
  "$WORK/kinfo_layout" > "$WORK/kinfo_layout.txt"; then
  if diff <(grep -v '^#' "$CRATE_DIR/tests/fixtures/kinfo-proc-macos-sdk.txt") "$WORK/kinfo_layout.txt" \
    > "$WORK/kinfo_layout.diff"; then
    echo "   the SDK matches tests/fixtures/kinfo-proc-macos-sdk.txt"
  else
    fail "kinfo_proc differs from tests/fixtures/kinfo-proc-macos-sdk.txt (< fixture, > SDK):"
    sed 's/^/     /' "$WORK/kinfo_layout.diff"
  fi
else
  fail "tests/c-abi/kinfo_layout.c does not build or run"
fi

# The plain host build is not an Apple library: it keeps the JNI glue for the Kotlin host harness. It is a debug build:
# DOODLEART_SERVER_KEYS_FILE (the release keys of a release run) does not apply to it.
echo "== plain host build (cargo build --lib, no DOODLEART_APPLE_LIB)"
if (cd "$CRATE_DIR" && env -u DOODLEART_APPLE_LIB -u DOODLEART_SERVER_KEYS_FILE cargo build --lib --locked --message-format=json-render-diagnostics) \
  > "$WORK/host-build.json" 2> "$WORK/host-build.log"; then
  dylib="$(python3 -I -c '
import json, sys
for line in open(sys.argv[1]):
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message["target"]["name"] == "doodleart_core":
        print(next((name for name in message["filenames"] if name.endswith(".dylib")), ""))
' "$WORK/host-build.json" | tail -n 1)"
  if [[ -f "$dylib" ]]; then
    host_exports="$("$LLVM_NM" --defined-only --extern-only --format=just-symbols "$dylib" | LC_ALL=C sort -u)"
    if grep -qx '_JNI_OnLoad' <<< "$host_exports" && ! grep -q '^_doodleart_' <<< "$host_exports"; then
      echo "   $(basename "$dylib"): exports JNI_OnLoad, no doodleart_* (the Android natives for the host harness)"
    else
      fail "the plain host build must export _JNI_OnLoad and no _doodleart_*: $(grep -E '^_(JNI_|doodleart_)' <<< "$host_exports" | tr '\n' ' ')"
    fi
  else
    fail "no dylib in the plain host build's cargo output"
  fi
else
  cat "$WORK/host-build.log" >&2
  fail "cargo build --lib (plain host build) failed"
fi

# Libraries named like a tweak and like Frida's gadget, for tests/c-abi/risk_probe.c (built once).
printf 'int doodleart_probe_hooker(void) { return 1; }\n' > "$WORK/hooker.c"
printf 'int doodleart_probe_gadget(void) { return 2; }\n' > "$WORK/gadget.c"
clang -dynamiclib -o "$WORK/libhooker-probe.dylib" "$WORK/hooker.c" &&
  clang -dynamiclib -o "$WORK/frida-gadget-probe.dylib" "$WORK/gadget.c" ||
  fail "cannot build the probe libraries of risk_probe.c"

# Another Rust static library for step 5, built once by the same rustc (an app's other Rust dependency).
if ! rustc --edition 2021 --crate-type staticlib --crate-name other_rust --target "$HOST_TARGET" -C panic=unwind \
  -C opt-level=2 -o "$WORK/libother_rust.a" "$CRATE_DIR/tests/c-abi/other_rust.rs" 2> "$WORK/other-rust.log"; then
  cat "$WORK/other-rust.log" >&2
  fail "tests/c-abi/other_rust.rs does not build"
fi

# Sets lib (a copy in WORK), native (linker flags without -lSystem), INCLUDE_C and INCLUDE_MODULES for one type.
# Built here: the cargo staticlib of the host target, the header from include/.
build_library() {
  local type="$1" log="$WORK/build-$1.log"
  echo "== $type"
  if ! (cd "$CRATE_DIR" && cargo rustc --lib --release --locked --no-default-features --features "build-$type" \
    --crate-type staticlib --target "$HOST_TARGET" --message-format=json-render-diagnostics \
    -- --print native-static-libs) > "$WORK/build-$type.json" 2> "$log"; then
    cat "$log" >&2
    echo "c-abi-smoke: cargo build failed ($type)" >&2
    exit 1
  fi
  lib="$(python3 -I -c '
import json, sys
for line in open(sys.argv[1]):
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message["target"]["name"] == "doodleart_core":
        print(next(name for name in message["filenames"] if name.endswith(".a")))
' "$WORK/build-$type.json")"
  [[ -f "$lib" ]] || { echo "c-abi-smoke: no static library in the cargo output ($type)" >&2; exit 1; }
  # rustc prints the system libraries a static library needs (cargo replays the note for a fresh build).
  native="$(sed -n 's/^note: native-static-libs: //p' "$log" | tail -n 1)"
  [[ -n "$native" ]] || { echo "c-abi-smoke: rustc printed no native-static-libs ($type)" >&2; exit 1; }
  INCLUDE_C="$CRATE_DIR/include"
  INCLUDE_MODULES="$CRATE_DIR/include"
}
# The same from a build-ios.sh output: its prelinked host slice, its Headers/DoodleArtCore, its manifest's linker flags.
prebuilt_library() {
  local type="$1" dir="$2" manifest="$2/DoodleArtCore.manifest.json"
  echo "== $type (prebuilt: $dir)"
  lib="$dir/slices/$HOST_TARGET/libdoodleart_core.a"
  [[ -f "$lib" && -f "$manifest" ]] || { echo "c-abi-smoke: not a build-ios.sh output: $dir" >&2; exit 1; }
  manifest_field() {
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$manifest" "$1"
  }
  [[ "$(manifest_field buildType)" == "$type" ]] ||
    { echo "c-abi-smoke: $dir is a $(manifest_field buildType) build, not $type" >&2; exit 1; }
  native="$(manifest_field nativeStaticLibs)"
  INCLUDE_C="$dir/Headers/DoodleArtCore"
  INCLUDE_MODULES="$dir/Headers"
}

for type in "${TYPES[@]}"; do
  prebuilt="$([[ "$type" == debug ]] && echo "$PREBUILT_debug" || echo "$PREBUILT_release")"
  if [[ -n "$prebuilt" ]]; then
    prebuilt_library "$type" "$prebuilt"
  else
    build_library "$type"
  fi
  cp "$lib" "$WORK/libdoodleart_core-$type.a"
  lib="$WORK/libdoodleart_core-$type.a"
  echo "   library: $(wc -c < "$lib" | tr -d ' ') bytes, native libs: $native"
  native="${native//-lSystem/}" # clang and swiftc always link libSystem; a second -lSystem only makes ld warn

  # 1. Exports.
  "$LLVM_NM" --defined-only --extern-only --format=just-symbols "$lib" 2>/dev/null | LC_ALL=C sort -u \
    > "$WORK/defined-$type.txt"
  sed -n 's/^_doodleart_/doodleart_/p' "$WORK/defined-$type.txt" > "$WORK/exported-$type.txt"
  if [[ "$type" == debug ]]; then
    header_functions > "$WORK/expected-$type.txt"
  else
    header_functions | grep -v '^doodleart_debug_' > "$WORK/expected-$type.txt"
  fi
  if diff "$WORK/expected-$type.txt" "$WORK/exported-$type.txt" > "$WORK/exports-$type.diff"; then
    echo "   exports: the $(wc -l < "$WORK/exported-$type.txt" | tr -d ' ') functions of the header"
  else
    fail "exports differ from the header (< header, > library):"
    sed 's/^/     /' "$WORK/exports-$type.diff"
  fi
  if grep -qE '^_(JNI_OnLoad|Java_)' "$WORK/defined-$type.txt"; then
    fail "JNI symbols in an Apple library: $(grep -E '^_(JNI_OnLoad|Java_)' "$WORK/defined-$type.txt" | tr '\n' ' ')"
  fi

  # 2. The header as strict C11 and C++17, and as the clang module DoodleArtCore.
  cat > "$WORK/expect.h" <<EOF
#define EXPECT_BUILD_TYPE "$type"
#define EXPECT_PROJECT_ID "$PROJECT_ID"
#define EXPECT_DEBUG_HOOKS $([[ "$type" == debug ]] && echo 1 || echo 0)
EOF
  strict=(-Wall -Wextra -Werror -pedantic -Wnullability-completeness -Wstrict-prototypes)
  printf '#include "doodleart_core.h"\n' > "$WORK/include.c"
  clang -std=c11 "${strict[@]}" -fsyntax-only -I "$INCLUDE_C" "$WORK/include.c" || fail "header as C11"
  clang++ -std=c++17 -Wall -Wextra -Werror -pedantic -fsyntax-only -x c++ -I "$INCLUDE_C" "$WORK/include.c" ||
    fail "header as C++17"

  # 3. Link and run.
  # shellcheck disable=SC2086 # $native is a list of linker flags
  if clang -std=c11 "${strict[@]}" -I "$INCLUDE_C" -I "$WORK" "$CRATE_DIR/tests/c-abi/smoke.c" "$lib" \
    $native -o "$WORK/smoke-c-$type"; then
    "$WORK/smoke-c-$type" | sed 's/^/   /' || fail "C smoke test"
  else
    fail "C smoke test does not build"
  fi
  # shellcheck disable=SC2086
  if clang++ -std=c++17 -Wall -Wextra -Werror -I "$INCLUDE_C" "$CRATE_DIR/tests/c-abi/smoke.cpp" "$lib" \
    $native -o "$WORK/smoke-cpp-$type"; then
    "$WORK/smoke-cpp-$type" | sed 's/^/   /' || fail "C++ smoke test"
  else
    fail "C++ smoke test does not build (extern \"C\" guard?)"
  fi
  # shellcheck disable=SC2086
  if clang -fmodules -fmodules-cache-path="$WORK/module-cache-$type" -Wall -Werror -I "$INCLUDE_MODULES" \
    "$CRATE_DIR/tests/c-abi/smoke.m" "$lib" $native -o "$WORK/smoke-m-$type"; then
    if "$WORK/smoke-m-$type"; then echo "   c-abi smoke (module DoodleArtCore): ok"; else fail "module smoke test"; fi
  else
    fail "@import DoodleArtCore does not build (include/module.modulemap)"
  fi
  if command -v swiftc >/dev/null; then
    printf '#include "vectors.h"\n#include "expect.h"\n' > "$WORK/bridge.h"
    swift_flags=()
    [[ "$type" == debug ]] && swift_flags+=(-D DOODLEART_DEBUG_HOOKS)
    # shellcheck disable=SC2086
    if swiftc -swift-version 5 -I "$INCLUDE_MODULES" -Xcc -I"$INCLUDE_C" -import-objc-header "$WORK/bridge.h" \
      -module-cache-path "$WORK/swift-module-cache-$type" ${swift_flags[@]+"${swift_flags[@]}"} \
      "$CRATE_DIR/tests/c-abi/smoke.swift" \
      "$lib" $native -o "$WORK/smoke-swift-$type" 2> "$WORK/swiftc-$type.log"; then
      "$WORK/smoke-swift-$type" | sed 's/^/   /' || fail "Swift smoke test"
    else
      cat "$WORK/swiftc-$type.log" >&2
      fail "Swift smoke test does not build"
    fi
  else
    echo "   Swift smoke test skipped: no swiftc"
  fi

  # 4. The Apple scan's hook and frida checks, run.
  # shellcheck disable=SC2086
  if clang -std=c11 "${strict[@]}" -I "$INCLUDE_C" -I "$WORK" "$CRATE_DIR/tests/c-abi/risk_probe.c" "$lib" \
    $native -o "$WORK/risk-probe-$type"; then
    "$WORK/risk-probe-$type" "$WORK/libhooker-probe.dylib" "$WORK/frida-gadget-probe.dylib" | sed 's/^/   /' ||
      fail "risk probe"
  else
    fail "risk_probe.c does not build"
  fi

  # 5. Next to another Rust static library.
  if [[ -f "$WORK/libother_rust.a" ]]; then
    link_log="$WORK/two-rust-link-$type.log"
    # shellcheck disable=SC2086
    if clang -std=c11 "${strict[@]}" -I "$INCLUDE_C" -I "$WORK" "$CRATE_DIR/tests/c-abi/two_rust.c" "$lib" \
      "$WORK/libother_rust.a" $native -o "$WORK/two-rust-$type" > "$link_log" 2>&1; then
      if grep -q 'duplicate symbol' "$link_log"; then
        fail "duplicate symbols next to another Rust static library: $(grep 'duplicate symbol' "$link_log" | head -3 | tr '\n' ' ')"
      fi
      "$WORK/two-rust-$type" | sed 's/^/   /' || fail "two Rust libraries"
    elif [[ -n "$prebuilt" ]]; then
      sed 's/^/     /' "$link_log" | head -20
      fail "the shipped library does not link next to another Rust static library"
    elif grep -q 'duplicate symbol' "$link_log"; then
      echo "   two Rust libraries: the raw cargo staticlib clashes with another Rust staticlib" \
        "($(grep -c 'duplicate symbol' "$link_log") duplicate symbols), as expected: build-ios.sh's prelink hides its" \
        "runtime (--prebuilt checks the shipped library)"
    else
      sed 's/^/     /' "$link_log" | head -20
      fail "two_rust.c does not link"
    fi
  fi
done

[[ $status -eq 0 ]] && echo "c-abi-smoke: OK (${TYPES[*]})" || echo "c-abi-smoke: FAILED"
exit $status
