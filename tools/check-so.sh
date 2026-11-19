#!/usr/bin/env bash
# Verifies libdoodleart_core.so builds: only JNI_OnLoad exported (no Java_* symbols), every PT_LOAD aligned to 16 KB,
# no text relocations, stripped, no plaintext sensitive strings (they go through obfstr), no source file under its
# unkeyed remapped name (src/m<first 8 hex of SHA-256(path)>.rs: guessable, see tools/remap-paths.sh), and every
# strong undefined symbol exists in the NDK stubs of API $DOODLEART_MIN_API (default 24 = minSdk), so the library loads
# on Android 7.
#   tools/check-so.sh [--imports-baseline <debug|qa|release>] <jniLibs dir> [abi...]
# --imports-baseline: the dynamic imports (llvm-nm -D --undefined-only: kind and name) must equal
# tests/fixtures/android-imports/<type>-<abi>.txt line for line: a change of the live library's imports (a new libc
# function pulled in by neutral code) fails with the diff. build-android.sh passes it with DOODLEART_CHECK_IMPORTS=1
# (core:check); off by default, so a Gradle build with another rustc or NDK is not stopped by the fixture. A deliberate
# change updates the fixture in the same commit (the command is printed with the diff).
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMPORTS_BASELINE=""
if [[ "${1:-}" == --imports-baseline ]]; then
  [[ "${2:-}" =~ ^(debug|qa|release)$ ]] || { echo "usage: $0 [--imports-baseline <debug|qa|release>] <dir> [abi...]" >&2; exit 2; }
  IMPORTS_BASELINE="$2"
  shift 2
fi
DIR="$1"
shift
ABIS=("$@")
[[ ${#ABIS[@]} -gt 0 ]] || ABIS=(arm64-v8a armeabi-v7a x86_64)

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK="${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* | sort -V | tail -n 1)}"
BIN="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/bin | head -n 1)"
READELF="$BIN/llvm-readelf"
NM="$BIN/llvm-nm"
STUBS="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/sysroot/usr/lib | head -n 1)"
MIN_API="${DOODLEART_MIN_API:-24}"

# Must never appear as plaintext in the binary. ("/proc/self/maps" is not listed: Rust std's own backtrace symbolizer
# contains it on some targets, independent of our checks, which read it through obfstr.)
SENSITIVE=(
  frida linjector gum-js-loop magisk zygisk XposedBridge "/proc/self/mem" TracerPid "risk/" apk_identity
  "com/cem/doodleart" handshakeBegin "doodle/v1/" DAPI1 DAAA1 DAAS1 CNHW1 "ro.kernel.qemu" goldfish "/system/xbin/su"
  "apk_resigned" "APK Sig Block 42"
)

# The names an unkeyed hash of the source paths would give: none may appear in a library (tools/remap-paths.sh).
# shellcheck source=tools/remap-paths.sh
source "$CRATE_DIR/tools/remap-paths.sh"
UNKEYED_NAMES="$(doodleart_unkeyed_remap_names "$CRATE_DIR")"
[[ $(wc -l <<< "$UNKEYED_NAMES") -ge 10 ]] || { echo "check-so: cannot list the sources of $CRATE_DIR/src" >&2; exit 1; }

status=0
for abi in "${ABIS[@]}"; do
  so="$DIR/$abi/libdoodleart_core.so"
  echo "== $abi: $so ($(wc -c < "$so" | tr -d ' ') bytes)"
  [[ -f "$so" ]] || { echo "   missing"; status=1; continue; }

  exported="$("$NM" -D --defined-only "$so" | awk '{ print $NF }' | sort -u | tr '\n' ' ')"
  if [[ "$exported" == "JNI_OnLoad " ]]; then
    echo "   exports: JNI_OnLoad only"
  else
    echo "   FAIL exports: $exported"
    status=1
  fi
  if "$READELF" --dyn-syms -W "$so" | grep -q "Java_"; then
    echo "   FAIL: Java_* symbol present"
    status=1
  fi

  aligns="$("$READELF" -l -W "$so" | awk '$1 == "LOAD" { print $NF }' | sort -u | tr '\n' ' ')"
  if [[ "$aligns" == "0x4000 " ]]; then
    echo "   PT_LOAD alignment: 16 KB ($("$READELF" -l -W "$so" | grep -c ' LOAD ') segments)"
  else
    echo "   FAIL PT_LOAD alignment: $aligns"
    status=1
  fi

  if "$READELF" -d -W "$so" | grep -q TEXTREL; then
    echo "   FAIL: TEXTREL present"
    status=1
  fi
  if "$READELF" -S -W "$so" | grep -qE '\.symtab|\.debug_'; then
    echo "   FAIL: not stripped"
    status=1
  fi

  case "$abi" in
    arm64-v8a) triple=aarch64-linux-android ;;
    armeabi-v7a) triple=arm-linux-androideabi ;;
    x86_64) triple=x86_64-linux-android ;;
    *) triple="" ;;
  esac
  if [[ -n "$triple" && ! -f "$STUBS/$triple/$MIN_API/libc.so" ]]; then
    echo "   FAIL: no NDK stubs for API $MIN_API ($STUBS/$triple/$MIN_API)"
    status=1
  elif [[ -n "$triple" ]]; then
    available="$(for lib in libc.so libdl.so libm.so liblog.so; do
      if [[ -f "$STUBS/$triple/$MIN_API/$lib" ]]; then
        "$NM" -D --defined-only "$STUBS/$triple/$MIN_API/$lib" | awk '{ print $NF }'
      fi
    done | sed 's/@.*//' | sort -u)"
    # Weak references ("w") resolve to null on older releases; std probes them before use (e.g. getrandom, API 28).
    too_new="$("$NM" -D --undefined-only "$so" | awk '$1 == "U" { print $NF }' | sed 's/@.*//' | while read -r sym; do
      grep -qx "$sym" <<< "$available" || echo "$sym"
    done | tr '\n' ' ')"
    if [[ -z "$too_new" ]]; then
      echo "   imports: all present in API $MIN_API stubs"
    else
      echo "   FAIL imports missing from API $MIN_API: $too_new"
      status=1
    fi
  fi

  if [[ -n "$IMPORTS_BASELINE" ]]; then
    fixture="$CRATE_DIR/tests/fixtures/android-imports/$IMPORTS_BASELINE-$abi.txt"
    if [[ ! -f "$fixture" ]]; then
      echo "   FAIL imports: no baseline $fixture"
      status=1
    elif diff "$fixture" <("$NM" -D --undefined-only "$so" | awk '{ print $(NF - 1), $NF }' | LC_ALL=C sort) \
      > "${TMPDIR:-/tmp}/check-so-imports.$$" 2>&1; then
      echo "   imports: identical to tests/fixtures/android-imports/$IMPORTS_BASELINE-$abi.txt ($(wc -l < "$fixture" | tr -d ' '))"
    else
      echo "   FAIL imports differ from tests/fixtures/android-imports/$IMPORTS_BASELINE-$abi.txt (< fixture, > library):"
      sed 's/^/     /' "${TMPDIR:-/tmp}/check-so-imports.$$"
      echo "     if intended: llvm-nm -D --undefined-only <so> | awk '{ print \$(NF - 1), \$NF }' | LC_ALL=C sort > <fixture>"
      status=1
    fi
    rm -f "${TMPDIR:-/tmp}/check-so-imports.$$"
  fi

  leaked=()
  for token in "${SENSITIVE[@]}"; do
    if LC_ALL=C grep -aqF -- "$token" "$so"; then
      leaked+=("$token")
    fi
  done
  if [[ ${#leaked[@]} -eq 0 ]]; then
    echo "   plaintext sensitive strings: none"
  else
    echo "   FAIL plaintext strings: ${leaked[*]}"
    status=1
  fi
  unkeyed=()
  while read -r name source; do
    if LC_ALL=C grep -aqF -- "$name" "$so"; then
      unkeyed+=("$name=$source")
    fi
  done <<< "$UNKEYED_NAMES"
  if [[ ${#unkeyed[@]} -gt 0 ]]; then
    echo "   FAIL source files under their unkeyed (guessable) remapped names: ${unkeyed[*]}"
    status=1
  fi
  if LC_ALL=C grep -aq -- "$HOME" "$so"; then
    echo "   FAIL: absolute home path in binary (remap-path-prefix)"
    status=1
  fi
  # Dependency sources must show as crates/<registry>/<crate>/…: a ~/.cargo path means the registry remap lost to
  # a more general one (rustc applies the last matching --remap-path-prefix).
  leaked_path="$(LC_ALL=C grep -aoE -- '[[:alnum:]_./~-]*(\.cargo/registry|~/)[[:alnum:]_./-]*\.rs' "$so" | head -n 1 || true)"
  if [[ -n "$leaked_path" ]]; then
    echo "   FAIL: unmapped source path: $leaked_path"
    status=1
  fi
done
exit $status
