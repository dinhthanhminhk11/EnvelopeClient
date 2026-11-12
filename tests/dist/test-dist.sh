#!/usr/bin/env bash
# Tests of the iOS distribution tools on real build outputs (theme-x spec 2026-11-05 §4.5, §4.6): tools/check-macho.sh,
# tools/fetch-core.sh and tools/publish-core.sh, every refusal included, the registry side against
# tests/dist/fake_registry.py on 127.0.0.1 (redirect to "object storage", credential checks, request log).
#
#   tests/dist/test-dist.sh <build-ios.sh debug output dir> <build-ios.sh release output dir>
#
# The key configs the outputs were built with: DOODLEART_SERVER_KEYS_FILE for the release output (default
# config/server-keys.release.conf), DOODLEART_DEBUG_SERVER_KEYS_FILE for the debug output (default
# config/server-keys.debug.conf; build-ios.sh debug reads DOODLEART_SERVER_KEYS_FILE, so another project passes its debug
# key file here), both relative to this crate like build.rs reads them; the project config from DOODLEART_PROJECT_CONF.
#
# The outputs may come from `build-ios.sh <type> [--no-xcframework]`. The publish/fetch round trip needs xcframework
# packaging: without one (no Xcode), the test assembles a stand-in DoodleArtCore.xcframework from the real slices with an
# Info.plist in xcodebuild's format, so everything after xcodebuild is exercised. Writes only to a temporary directory;
# needs macOS (clang, libtool, ld), python3, curl and the rustup llvm-tools. Exit status 0 = every case passed.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# -eq 2 ]] || { echo "usage: $0 <debug output dir> <release output dir>" >&2; exit 2; }
DEBUG_OUT="$(cd "$1" && pwd)"
RELEASE_OUT="$(cd "$2" && pwd)"
MODULE=DoodleArtCore
LLVM_BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
CHECK="$CRATE_DIR/tools/check-macho.sh"
# Every library is checked against the key config it was built with (CI: the production key file of
# DOODLEART_SERVER_KEYS_FILE when set, for the release output), passed to check-macho.sh with --keys; the variables are
# relative to this crate, as build.rs reads them, and are not passed on.
RELEASE_KEYS="${DOODLEART_SERVER_KEYS_FILE:-config/server-keys.release.conf}"
[[ "$RELEASE_KEYS" == /* ]] || RELEASE_KEYS="$CRATE_DIR/$RELEASE_KEYS"
DEBUG_KEYS="${DOODLEART_DEBUG_SERVER_KEYS_FILE:-config/server-keys.debug.conf}"
[[ "$DEBUG_KEYS" == /* ]] || DEBUG_KEYS="$CRATE_DIR/$DEBUG_KEYS"
unset DOODLEART_SERVER_KEYS_FILE DOODLEART_DEBUG_SERVER_KEYS_FILE
# The expectations come from the configs the outputs were built with (another project's included: its project config
# through DOODLEART_PROJECT_CONF, which check-macho.sh reads too, its keys through the two variables above).
conf_value() { # conf_value <file> <key>
  sed -E -n -e 's/#.*//' -e "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" "$1" | tail -n 1 | sed -E 's/[[:space:]]+$//'
}
PROJECT_CONF="${DOODLEART_PROJECT_CONF:-config/project.conf}"
[[ "$PROJECT_CONF" == /* ]] || PROJECT_CONF="$CRATE_DIR/$PROJECT_CONF"
PROJECT_ID="$(conf_value "$PROJECT_CONF" PROJECT_ID)"
DEBUG_KID="$(conf_value "$DEBUG_KEYS" current.kid)"
[[ -n "$PROJECT_ID" && -n "$DEBUG_KID" ]] || { echo "no PROJECT_ID in $PROJECT_CONF or no debug kid" >&2; exit 2; }
CHECK_RELEASE=("$CHECK" --type release --keys "$RELEASE_KEYS")
CHECK_DEBUG=("$CHECK" --keys "$DEBUG_KEYS")
FETCH="$CRATE_DIR/tools/fetch-core.sh"
PUBLISH="$CRATE_DIR/tools/publish-core.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/doodleart-test-dist.XXXXXX")"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
# The fake registry's token: random, so the leak checks below cannot match by accident.
TOKEN="tok-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"

passed=0
failed=0
# expect <0|1> <name> <patterns> <command...>: the command must exit 0 (0) or non-zero (1), and its combined output
# must contain every line of <patterns> (fixed strings; empty = no check). The token must never appear.
expect() {
  local want="$1" name="$2" patterns="$3" status=0 missing=""
  shift 3
  "$@" > "$WORK/out.txt" 2>&1 || status=$?
  while IFS= read -r pattern; do
    [[ -z "$pattern" ]] || grep -qF -- "$pattern" "$WORK/out.txt" || missing="$missing [$pattern]"
  done <<< "$patterns"
  if grep -qF -- "$TOKEN" "$WORK/out.txt"; then missing="$missing [token printed!]"; fi
  if { [[ "$want" == 0 && $status -eq 0 ]] || [[ "$want" == 1 && $status -ne 0 ]]; } && [[ -z "$missing" ]]; then
    passed=$((passed + 1))
    echo "ok   $name"
  else
    failed=$((failed + 1))
    echo "FAIL $name (exit $status, expected $([[ "$want" == 0 ]] && echo 0 || echo 'non-zero'); missing:$missing)"
    sed 's/^/       /' "$WORK/out.txt" | tail -n 20
  fi
}
check_true() {
  local name="$1"
  shift
  if "$@"; then passed=$((passed + 1)); echo "ok   $name"; else failed=$((failed + 1)); echo "FAIL $name"; fi
}
sha_of() { shasum -a 256 "$1" | cut -d ' ' -f 1; }

# Small objects for crafted libraries: clang -c needs no SDK (nothing is included).
cobj() { # cobj <target triple> <out.o> <C source>
  printf '%s\n' "$3" > "$WORK/src.c"
  clang -target "$1" -Wno-incompatible-sysroot -c "$WORK/src.c" -o "$2"
}
# craft <name> <slice dir name> <release slice triple> <extra objects...>: a library = the release slice's object plus
# the extra objects, at <WORK>/craft/<name>/<slice dir name>/libdoodleart_core.a; prints its path.
craft() {
  local name="$1" slice="$2" triple="$3" dir
  shift 3
  dir="$WORK/craft/$name/$slice"
  mkdir -p "$dir" "$WORK/craft/$name/obj"
  (cd "$WORK/craft/$name/obj" && "$LLVM_BIN/llvm-ar" x "$RELEASE_OUT/slices/$triple/libdoodleart_core.a")
  ZERO_AR_DATE=1 libtool -static -no_warning_for_no_symbols -o "$dir/libdoodleart_core.a" \
    "$WORK/craft/$name/obj/doodleart_core.o" "$@"
  echo "$dir/libdoodleart_core.a"
}

echo "== check-macho.sh"
expect 0 "release slices pass" $'check-macho: OK\nexports: the 18 functions' "${CHECK_RELEASE[@]}" "$RELEASE_OUT/slices"
expect 0 "debug output with its manifest passes (type from the manifest)" \
  "manifest: debug, projectId $PROJECT_ID, kids $DEBUG_KID"$'\ncheck-macho: OK' "${CHECK_DEBUG[@]}" "$DEBUG_OUT"
expect 0 "release output with its manifest passes" $'manifest: release\ncheck-macho: OK' "${CHECK_RELEASE[@]}" "$RELEASE_OUT"
expect 1 "a debug library checked as release" \
  $'exports differ from the header: extra [_doodleart_debug_clock_advance_ms]\ndoodleart_debug (debug clock hook)\nserver keys of the expected key config missing' \
  "${CHECK_RELEASE[@]}" "$DEBUG_OUT/slices/aarch64-apple-ios/libdoodleart_core.a"
expect 1 "release checked against the debug key config" \
  $'has the kid dev\nserver keys of the expected key config missing (kid dev)\nis for the build type debug, not release' \
  "$CHECK" --type release --keys "$CRATE_DIR/config/server-keys.debug.conf" "$RELEASE_OUT/slices/aarch64-apple-ios"
{ grep -v '^project' "$RELEASE_KEYS"; echo "project = another-project"; } > "$WORK/other-project-keys.conf"
expect 1 "a key config tagged for another project" "is for project another-project, the project config is $PROJECT_ID" \
  "$CHECK" --type release --keys "$WORK/other-project-keys.conf" "$RELEASE_OUT/slices/aarch64-apple-ios"
grep -v '^project\|^build_type' "$RELEASE_KEYS" > "$WORK/untagged-keys.conf"
printf 'PROJECT_ID = another-project\n' > "$WORK/another-project.conf"
for tags in none project type; do
  case "$tags" in
    none) cp "$WORK/untagged-keys.conf" "$WORK/partly-tagged-keys.conf" ;;
    project) { cat "$WORK/untagged-keys.conf"; echo "project = another-project"; } > "$WORK/partly-tagged-keys.conf" ;;
    type) { cat "$WORK/untagged-keys.conf"; echo "build_type = release"; } > "$WORK/partly-tagged-keys.conf" ;;
  esac
  expect 1 "another project's config needs both tags (tags: $tags)" "its key config must name project and build_type" \
    env DOODLEART_PROJECT_CONF="$WORK/another-project.conf" "$CHECK" --type release --keys "$WORK/partly-tagged-keys.conf" \
    "$RELEASE_OUT/slices/aarch64-apple-ios"
done
# Without DOODLEART_PROJECT_CONF an untagged key config is DoodleArt's only with DoodleArt's committed keys (build.rs).
if [[ -z "${DOODLEART_PROJECT_CONF:-}" ]]; then
  expect 0 "an untagged copy of the committed release keys" "check-macho: OK" \
    "$CHECK" --type release --keys "$WORK/untagged-keys.conf" "$RELEASE_OUT/slices/aarch64-apple-ios"
  sed -E 's/^(current\.public_key[[:space:]]*=[[:space:]]*)[0-9a-f]{2}/\100/; s/^(current\.kid[[:space:]]*=).*/\1 foreign-1/' \
    "$WORK/untagged-keys.conf" > "$WORK/foreign-keys.conf"
  expect 1 "an untagged key config with a key DoodleArt did not commit" \
    "has no project tag and keys (kid foreign-1) that config/server-keys.release.conf does not have" \
    "$CHECK" --type release --keys "$WORK/foreign-keys.conf" "$RELEASE_OUT/slices/aarch64-apple-ios"
fi
expect 1 "no type and no manifest" "pass --type" "$CHECK" "$RELEASE_OUT/slices"
raw="${CARGO_TARGET_DIR:-$CRATE_DIR/target}/aarch64-apple-ios/release/libdoodleart_core.a"
if [[ -f "$raw" ]]; then
  mkdir -p "$WORK/raw/aarch64-apple-ios" && cp "$raw" "$WORK/raw/aarch64-apple-ios/"
  expect 1 "the unprocessed cargo staticlib" \
    $'LLVM bitcode (__LLVM segment) left\nDWARF debug sections left\nexports differ from the header' \
    "${CHECK_RELEASE[@]}" "$WORK/raw"
fi
cobj arm64-apple-ios16.0 "$WORK/jb.o" '__attribute__((used)) static const char planted_jb[] = "/Applications/Cydia.app";'
expect 1 "an Apple risk-scan string in plaintext (any case)" "plaintext strings: cydia" \
  "${CHECK_RELEASE[@]}" "$(craft jb aarch64-apple-ios aarch64-apple-ios "$WORK/jb.o")"
cobj arm64-apple-ios16.0 "$WORK/tracer.o" '__attribute__((used)) static const char planted_tracer[] = "TracerPid";'
expect 1 "a check-so.sh SENSITIVE string (list read from check-so.sh)" "plaintext strings: TracerPid" \
  "${CHECK_RELEASE[@]}" "$(craft tracer aarch64-apple-ios aarch64-apple-ios "$WORK/tracer.o")"
cobj arm64-apple-ios16.0 "$WORK/stub.o" '__attribute__((used)) static const char planted_stub[] = "doodleart-stub";'
expect 1 "doodleart-stub" "plaintext strings: doodleart-stub" \
  "${CHECK_RELEASE[@]}" "$(craft stub aarch64-apple-ios aarch64-apple-ios "$WORK/stub.o")"
cobj arm64-apple-ios16.0 "$WORK/path.o" '__attribute__((used)) static const char planted_path[] = "\x01src/risk/apple.rs";'
expect 1 "an unmapped source path of the crate" "unmapped source paths: risk/apple.rs" \
  "${CHECK_RELEASE[@]}" "$(craft path aarch64-apple-ios aarch64-apple-ios "$WORK/path.o")"
unkeyed="src/m$(printf '%s' risk/apple.rs | shasum -a 256 | cut -c 1-8).rs"
cobj arm64-apple-ios16.0 "$WORK/unkeyed.o" "__attribute__((used)) static const char planted_unkeyed[] = \"$unkeyed\";"
expect 1 "a source file under its unkeyed remapped name (guessable)" \
  "source files under their unkeyed (guessable) remapped names: $unkeyed=risk/apple.rs" \
  "${CHECK_RELEASE[@]}" "$(craft unkeyed aarch64-apple-ios aarch64-apple-ios "$WORK/unkeyed.o")"
cobj arm64-apple-ios16.0 "$WORK/dep.o" '__attribute__((used)) static const char planted_dep[] = "crates/index/getrandom-0.2.16/src/error.rs";'
expect 0 "a dependency path ending like a crate file is not a leak" "check-macho: OK" \
  "${CHECK_RELEASE[@]}" "$(craft dep aarch64-apple-ios aarch64-apple-ios "$WORK/dep.o")"
cobj arm64-apple-ios16.0 "$WORK/home.o" '__attribute__((used)) static const char planted_home[] = "/Users/runner/work/x.c";'
expect 1 "an absolute user path" "absolute paths in the binary" \
  "${CHECK_RELEASE[@]}" "$(craft home aarch64-apple-ios aarch64-apple-ios "$WORK/home.o")"
cobj arm64-apple-ios16.0 "$WORK/own.o" 'int doodleart_missing(void);
__attribute__((used)) static int call(void) { return doodleart_missing(); }'
expect 1 "an unresolved symbol of the core itself" "unresolved own symbols: _doodleart_missing" \
  "${CHECK_RELEASE[@]}" "$(craft own aarch64-apple-ios aarch64-apple-ios "$WORK/own.o")"
cobj arm64-apple-ios16.0 "$WORK/extra.o" 'int doodleart_extra(void) { return 1; }'
expect 1 "an extra exported symbol" "exports differ from the header: extra [_doodleart_extra]" \
  "${CHECK_RELEASE[@]}" "$(craft extra aarch64-apple-ios aarch64-apple-ios "$WORK/extra.o")"
cobj arm64-apple-ios16.0 "$WORK/stat.o" 'int stat(const char *, void *); int ptrace(int, int, char *, int);
__attribute__((used)) static int probe(void) { return stat("x", 0) + ptrace(31, 0, 0, 0); }'
expect 1 "forbidden imports (stat, ptrace)" $'forbidden imports: _ptrace _stat\nrequired-reason API, File timestamp' \
  "${CHECK_RELEASE[@]}" "$(craft stat aarch64-apple-ios aarch64-apple-ios "$WORK/stat.o")"
cobj arm64-apple-macos13.0 "$WORK/mac.o" '__attribute__((used)) static const char planted_mac[] = "x";'
expect 1 "a macOS object inside an iOS library" "members are not built for one Apple platform" \
  "${CHECK_RELEASE[@]}" "$(craft mixed aarch64-apple-ios aarch64-apple-ios "$WORK/mac.o")"
cobj arm64-apple-ios17.0-simulator "$WORK/sim17.o" '__attribute__((used)) static const char planted_sim[] = "x";'
expect 1 "an object for a newer iOS than the deployment target" "newer than the deployment target 16.0" \
  "${CHECK_RELEASE[@]}" "$(craft sim17 aarch64-apple-ios-sim aarch64-apple-ios-sim "$WORK/sim17.o")"
mkdir -p "$WORK/misplaced/aarch64-apple-ios"
cp "$RELEASE_OUT/slices/aarch64-apple-darwin/libdoodleart_core.a" "$WORK/misplaced/aarch64-apple-ios/"
expect 1 "a macOS slice where the iOS slice belongs" "the path names a ios slice but the library is built for macos" \
  "${CHECK_RELEASE[@]}" "$WORK/misplaced"
# Stubs of every exported function and nothing else: an iOS library without the risk scan's probes.
stubs="$(grep -v '^_doodleart_debug_' <<< "$(sed -E -n 's/^(DoodleArtBuf|int32_t|void)[[:space:]]+(doodleart_[a-z0-9_]+)\(.*/_\2/p' \
  "$CRATE_DIR/include/doodleart_core.h")" | sed -E 's/^_(.*)/void \1(void) {}/')"
cobj arm64-apple-ios16.0 "$WORK/stubs.o" "$stubs"
mkdir -p "$WORK/stubs/aarch64-apple-ios"
ZERO_AR_DATE=1 libtool -static -o "$WORK/stubs/aarch64-apple-ios/libdoodleart_core.a" "$WORK/stubs.o"
expect 1 "an iOS library without the Apple scan's imports" \
  "imports of the Apple risk scan / unwinder missing on ios: _access _unlink _sysctl _socket _connect __Unwind_RaiseException" \
  "${CHECK_RELEASE[@]}" "$WORK/stubs"
cobj arm64-apple-macos13.0 "$WORK/macfs.o" 'int access(const char *, int); int unlink(const char *);
__attribute__((used)) static int probe(void) { return access("x", 0) + unlink("x"); }'
expect 1 "filesystem probes in the macOS slice" "filesystem probe imports on macos: _access _unlink" \
  "${CHECK_RELEASE[@]}" "$(craft macfs aarch64-apple-darwin aarch64-apple-darwin "$WORK/macfs.o")"
mkdir -p "$WORK/wiring/aarch64-apple-ios"
cp "$RELEASE_OUT/slices/aarch64-apple-ios/libdoodleart_core.a" "$WORK/wiring/aarch64-apple-ios/"
expect 0 "the iOS slice imports the Apple scan's probes" "check-macho: OK" "${CHECK_RELEASE[@]}" "$WORK/wiring"
debug_key="$(sed -n -E 's/^current\.public_key[[:space:]]*=[[:space:]]*([0-9a-f]{64}).*/\1/p' "$CRATE_DIR/config/server-keys.debug.conf")"
key_bytes="$(sed -E 's/(..)/0x\1,/g' <<< "$debug_key")"
cobj arm64-apple-ios16.0 "$WORK/key.o" "__attribute__((used)) static const unsigned char planted_key[32] = {$key_bytes};"
expect 1 "the debug server key inside a release library" "a debug server key is embedded (kid dev" \
  "${CHECK_RELEASE[@]}" "$(craft key aarch64-apple-ios aarch64-apple-ios "$WORK/key.o")"
# Manifest mismatches.
cp -R "$RELEASE_OUT" "$WORK/manifest-kids"
python3 -I - "$WORK/manifest-kids/$MODULE.manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest["kids"] = ["prod-2026-11a"]
json.dump(manifest, open(sys.argv[1], "w"))
PY
expect 1 "manifest kids differ from the key config" "kids ['prod-2026-11a'], expected" "${CHECK_RELEASE[@]}" "$WORK/manifest-kids"
cp -R "$RELEASE_OUT" "$WORK/manifest-sha"
rm -rf "$WORK/manifest-sha/$MODULE-slices" "$WORK/manifest-sha/$MODULE.xcframework"
cp "$(craft swapped aarch64-apple-ios aarch64-apple-ios "$WORK/dep.o")" "$WORK/manifest-sha/slices/aarch64-apple-ios/"
expect 1 "a library whose sha256 the manifest does not list" \
  $'libraries not listed in the manifest\'s sha256\nlibraries of the manifest\'s sha256 not found: aarch64-apple-ios/libdoodleart_core.a' \
  "${CHECK_RELEASE[@]}" "$WORK/manifest-sha"
# An app binary: string checks only.
cobj arm64-apple-macos13.0 "$WORK/app-clean.o" 'int main(void) { return 0; }'
clang -target arm64-apple-macos13.0 "$WORK/app-clean.o" -o "$WORK/app-clean"
expect 0 "a clean Mach-O executable (string checks only)" "Mach-O file: string checks only" \
  "${CHECK_RELEASE[@]}" "$WORK/app-clean"
cobj arm64-apple-macos13.0 "$WORK/app-frida.o" 'const char *volatile s = "frida-gadget"; int main(void) { return s[0] == 0; }'
clang -target arm64-apple-macos13.0 "$WORK/app-frida.o" -o "$WORK/app-frida"
expect 1 "a Mach-O executable with a sensitive string" "plaintext strings:" "${CHECK_RELEASE[@]}" "$WORK/app-frida"

# A stand-in xcframework (xcodebuild's layout and Info.plist) when the outputs have none, plus a clean manifest:
# publish-core refuses dirty trees and slices packaging, and these outputs may be both.
make_publishable() { # make_publishable <type> <output dir> <dest>
  local type="$1" out="$2" dest="$3"
  mkdir -p "$dest/pkg"
  if [[ -d "$out/$MODULE.xcframework" ]]; then
    cp -R "$out/$MODULE.xcframework" "$dest/pkg/"
  else
    python3 -I - "$out" "$dest/pkg/$MODULE.xcframework" <<'PY'
import os, plistlib, shutil, sys
out, root = sys.argv[1:]
libraries = []
for triple, identifier, platform, variant in (("aarch64-apple-ios", "ios-arm64", "ios", None),
                                              ("aarch64-apple-ios-sim", "ios-arm64-simulator", "ios", "simulator"),
                                              ("aarch64-apple-darwin", "macos-arm64", "macos", None)):
    os.makedirs(os.path.join(root, identifier))
    shutil.copy(os.path.join(out, "slices", triple, "libdoodleart_core.a"), os.path.join(root, identifier))
    shutil.copytree(os.path.join(out, "Headers"), os.path.join(root, identifier, "Headers"))
    entry = {"BinaryPath": "libdoodleart_core.a", "HeadersPath": "Headers", "LibraryIdentifier": identifier,
             "LibraryPath": "libdoodleart_core.a", "SupportedArchitectures": ["arm64"], "SupportedPlatform": platform}
    if variant:
        entry["SupportedPlatformVariant"] = variant
    libraries.append(entry)
with open(os.path.join(root, "Info.plist"), "wb") as handle:
    plistlib.dump({"AvailableLibraries": libraries, "CFBundlePackageType": "XFWK", "XCFrameworkFormatVersion": "1.0"},
                  handle)
PY
  fi
  python3 -I - "$out/$MODULE.manifest.json" "$dest/pkg/$MODULE.manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest.update(packaging="xcframework", gitDirty=False)
with open(sys.argv[2], "w") as handle:
    json.dump(manifest, handle, indent=2)
PY
  cp "$dest/pkg/$MODULE.manifest.json" "$dest/$MODULE-$type.manifest.json"
  (cd "$dest/pkg" && find "$MODULE.xcframework" "$MODULE.manifest.json" -type f | LC_ALL=C sort |
    zip -X -D -q -@ "$dest/$MODULE-$type.xcframework.zip")
  (cd "$dest" && shasum -a 256 "$MODULE-$type.xcframework.zip" > "$MODULE-$type.xcframework.zip.sha256")
}
make_publishable debug "$DEBUG_OUT" "$WORK/pub/debug"
make_publishable release "$RELEASE_OUT" "$WORK/pub/release"
expect 0 "the xcframework passes check-macho (Info.plist, identifiers vs platforms, manifest)" \
  $'xcframework: ios-arm64, ios-arm64-simulator, macos-arm64\nmanifest: release\ncheck-macho: OK' \
  "${CHECK_RELEASE[@]}" "$WORK/pub/release/pkg"
cp -R "$WORK/pub/release/pkg" "$WORK/xcf-two"
python3 -I - "$WORK/xcf-two/$MODULE.xcframework/Info.plist" <<'PY'
import plistlib, sys
info = plistlib.load(open(sys.argv[1], "rb"))
info["AvailableLibraries"] = [entry for entry in info["AvailableLibraries"] if entry["SupportedPlatform"] != "macos"]
plistlib.dump(info, open(sys.argv[1], "wb"))
PY
expect 1 "an xcframework without the macOS slice in its Info.plist" "expected iOS device, iOS Simulator and macOS" \
  "${CHECK_RELEASE[@]}" "$WORK/xcf-two"

echo "== fetch-core.sh (local zips)"
DEBUG_ZIP="$(ls "$DEBUG_OUT"/$MODULE-debug.*.zip)"
DEBUG_SHA="$(sha_of "$DEBUG_ZIP")"
DEST="$WORK/dest"
expect 0 "installs a local zip with its sha256" $'sha256 '"$DEBUG_SHA"$' verified\ninstalled into' \
  "$FETCH" --type debug --dest "$DEST" --from-file "$DEBUG_ZIP" --sha256 "$DEBUG_SHA" --project-id "$PROJECT_ID"
check_true "manifest installed" test -f "$DEST/$MODULE.manifest.json"
installed="$(sha_of "$DEST/$MODULE.manifest.json")"
expect 1 "wrong sha256" "SHA-256 mismatch" "$FETCH" --type debug --dest "$DEST" --from-file "$DEBUG_ZIP" \
  --sha256 "$(printf '%064d' 0)"
expect 1 "no sha256" "refusing to install an unverified core" "$FETCH" --type debug --dest "$DEST" --from-file "$DEBUG_ZIP"
expect 1 "wrong build type" "the zip is a debug build, --type is release" \
  "$FETCH" --type release --dest "$DEST" --from-file "$DEBUG_ZIP" --sha256 "$DEBUG_SHA"
expect 1 "wrong projectId" "the lock expects other" \
  "$FETCH" --type debug --dest "$DEST" --from-file "$DEBUG_ZIP" --sha256 "$DEBUG_SHA" --project-id other
printf 'registry = https://example.invalid/api/v4\nmystery = 1\n' > "$WORK/bad.lock"
expect 1 "a lock with an unknown key" "unknown key 'mystery'" "$FETCH" --type debug --dest "$DEST" --lock "$WORK/bad.lock"
expect 1 "a plain-http registry" "registry must be an https URL" "$FETCH" --type debug --dest "$DEST" \
  --registry http://example.invalid/api/v4 --project 1 --package p --version 1 --sha256 "$DEBUG_SHA"
evil_zip() { # evil_zip <name> <python statements using z (ZipFile) and manifest (bytes)>
  python3 -I - "$DEBUG_ZIP" "$WORK/$1.zip" "$2" <<'PY'
import sys, zipfile
source, target, code = sys.argv[1:]
manifest = zipfile.ZipFile(source).read("DoodleArtCore.manifest.json")
with zipfile.ZipFile(target, "w") as z:
    for info in zipfile.ZipFile(source).infolist():
        z.writestr(info, zipfile.ZipFile(source).read(info.filename))
    exec(code)
PY
  echo "$WORK/$1.zip"
}
for case in "traversal|z.writestr('DoodleArtCore-slices/../../evil', b'x')|unsafe entry" \
  "absolute|z.writestr('/tmp/evil', b'x')|unsafe entry" \
  "extra|z.writestr('evil.sh', b'x')|unexpected entry" \
  "link|i = zipfile.ZipInfo('DoodleArtCore-slices/link'); i.external_attr = 0o120777 << 16; z.writestr(i, '/etc')|link entry"; do
  IFS='|' read -r name code message <<< "$case"
  zip_path="$(evil_zip "$name" "$code")"
  expect 1 "zip with a $name entry" "$message" "$FETCH" --type debug --dest "$DEST" --from-file "$zip_path" \
    --sha256 "$(sha_of "$zip_path")"
done
python3 -I - "$DEBUG_ZIP" "$WORK/tampered.zip" <<'PY'
import sys, zipfile
source, target = sys.argv[1:]
with zipfile.ZipFile(target, "w") as z:
    for info in zipfile.ZipFile(source).infolist():
        data = zipfile.ZipFile(source).read(info.filename)
        if info.filename.endswith("aarch64-apple-ios/libdoodleart_core.a"):
            data = data[:-1] + bytes([data[-1] ^ 1])
        z.writestr(info, data)
PY
expect 1 "a library that does not match the manifest" "do not match the manifest's sha256" \
  "$FETCH" --type debug --dest "$DEST" --from-file "$WORK/tampered.zip" --sha256 "$(sha_of "$WORK/tampered.zip")"
check_true "failed installs left the installed core untouched" test "$(sha_of "$DEST/$MODULE.manifest.json")" = "$installed"
check_true "no staging directory left behind" test -z "$(find "$DEST" -maxdepth 1 -name '.fetch-core.*')"

echo "== publish-core.sh (local checks)"
expect 0 "dry run over the outputs" "package = doodleart-core-$PROJECT_ID"$'\ndebug.sha256 = \nrelease.sha256 = ' \
  env -u CI_COMMIT_SHA "$PUBLISH" --dry-run "$DEBUG_OUT" "$RELEASE_OUT"
if [[ ! -d "$DEBUG_OUT/$MODULE.xcframework" ]]; then
  expect 1 "slices packaging is not publishable" "is not publishable" \
    env -u CI_COMMIT_SHA "$PUBLISH" "$DEBUG_OUT"
fi
expect 1 "two outputs of one build type" "two release outputs" \
  env -u CI_COMMIT_SHA "$PUBLISH" --dry-run "$RELEASE_OUT" "$WORK/pub/release"
expect 1 "gitSha must be CI_COMMIT_SHA" "is not CI_COMMIT_SHA" \
  env CI_COMMIT_SHA="$(printf '%040d' 0)" "$PUBLISH" --dry-run "$WORK/pub/debug"
expect 1 "no credential" "no credential" env -u CI_JOB_TOKEN -u DOODLEART_CORE_PRIVATE_TOKEN -u CI_COMMIT_SHA \
  DOODLEART_CORE_REGISTRY=https://example.invalid/api/v4 DOODLEART_CORE_PROJECT=1 "$PUBLISH" "$WORK/pub/debug"
cp -R "$WORK/pub/debug" "$WORK/pub-badsha"
printf '%064d  %s\n' 0 "$MODULE-debug.xcframework.zip" > "$WORK/pub-badsha/$MODULE-debug.xcframework.zip.sha256"
expect 1 "a .sha256 file that does not match its zip" "xcframework.zip.sha256 does not match the zip" \
  env -u CI_COMMIT_SHA "$PUBLISH" --dry-run "$WORK/pub-badsha"
cp -R "$WORK/pub/debug" "$WORK/pub-dirty"
python3 -I - "$WORK/pub-dirty/$MODULE-debug.manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest["gitDirty"] = True
json.dump(manifest, open(sys.argv[1], "w"))
PY
expect 1 "a build from a dirty tree is not publishable" "built from a dirty tree" env -u CI_COMMIT_SHA \
  CI_JOB_TOKEN=x DOODLEART_CORE_REGISTRY=https://example.invalid/api/v4 DOODLEART_CORE_PROJECT=1 "$PUBLISH" "$WORK/pub-dirty"

echo "== publish and fetch through a fake registry"
python3 -I "$CRATE_DIR/tests/dist/fake_registry.py" "$TOKEN" > "$WORK/server.port" 2> "$WORK/server.log" &
SERVER_PID=$!
for _ in $(seq 50); do [[ -s "$WORK/server.port" ]] && break; sleep 0.1; done
PORT="$(head -n 1 "$WORK/server.port")"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "fake registry did not start" >&2; cat "$WORK/server.log" >&2; exit 1; }
API="http://127.0.0.1:$PORT/api/v4"
COMMIT="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["gitSha"])' "$WORK/pub/debug/$MODULE-debug.manifest.json")"
registry_log() { curl --silent "http://127.0.0.1:$PORT/__log"; }
publish() { env -u DOODLEART_CORE_PRIVATE_TOKEN CI_JOB_TOKEN="$1" CI_API_V4_URL="$API" CI_PROJECT_ID=42 CI_COMMIT_SHA="$COMMIT" \
  "$PUBLISH" --lock-out "$WORK/core.lock" "$WORK/pub/debug" "$WORK/pub/release"; }
expect 1 "publish with a wrong token" "HTTP 401" publish wrong-token
expect 0 "publish both build types" \
  $'uploaded DoodleArtCore-debug.xcframework.zip\nuploaded DoodleArtCore-release.manifest.json\nuploaded DoodleArtCore-release.xcframework.zip.sha256\nlock written to' \
  publish "$TOKEN"
check_true "uploads in order zip, manifest, sha256, all with JOB-TOKEN" python3 -I -c '
import json, sys
puts = [entry for entry in json.loads(sys.argv[1]) if entry["method"] == "PUT"]
names = [entry["path"].rsplit("/", 1)[1] for entry in puts]
ok = all(entry["auth"] == {"JOB-TOKEN": True} for entry in puts)
for kind in ("debug", "release"):
    mine = [name for name in names if f"-{kind}." in name]
    ok &= mine == [f"DoodleArtCore-{kind}.xcframework.zip", f"DoodleArtCore-{kind}.manifest.json",
                   f"DoodleArtCore-{kind}.xcframework.zip.sha256"]
sys.exit(0 if ok and len(puts) == 6 else 1)
' "$(registry_log)"
check_true "the lock pins the uploaded zips" grep -qx "release.sha256 = $(sha_of "$WORK/pub/release/$MODULE-release.xcframework.zip")" "$WORK/core.lock"
# A ~/.curlrc (here $CURL_HOME/.curlrc) is never read: an `insecure` or `proxy` line there would expose the token.
mkdir -p "$WORK/curlhome"
printf 'user-agent = "curlrc-was-read"\nproxy = "http://127.0.0.1:9"\n' > "$WORK/curlhome/.curlrc"
expect 0 "publishing again uploads nothing (and reads no .curlrc)" $'already published with the same sha256\ncore.lock:' \
  env -u DOODLEART_CORE_PRIVATE_TOKEN CURL_HOME="$WORK/curlhome" CI_JOB_TOKEN="$TOKEN" CI_API_V4_URL="$API" CI_PROJECT_ID=42 \
  CI_COMMIT_SHA="$COMMIT" "$PUBLISH" --lock-out "$WORK/core.lock" "$WORK/pub/debug" "$WORK/pub/release"
check_true "still six uploads" python3 -I -c '
import json, sys
sys.exit(0 if sum(entry["method"] == "PUT" for entry in json.loads(sys.argv[1])) == 6 else 1)' "$(registry_log)"
lock_version() { sed -n 's/^version = //p' "$1"; }
VERSION_1="$(lock_version "$WORK/core.lock")"
check_true "the version names the commit and the build digest" python3 -I -c '
import hashlib, json, re, sys
lock, debug_zip, release_zip, manifest = sys.argv[1:]
version = dict(line.split(" = ", 1) for line in open(lock).read().splitlines() if " = " in line)["version"]
meta = json.load(open(manifest))
digest = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
build = hashlib.sha256(f"debug {digest(debug_zip)}\nrelease {digest(release_zip)}\n".encode()).hexdigest()
expected = meta["crateVersion"] + "-" + meta["gitSha"][:12] + "-" + build[:8]
sys.exit(0 if version == expected else 1)
' "$WORK/core.lock" "$WORK/pub/debug/$MODULE-debug.xcframework.zip" "$WORK/pub/release/$MODULE-release.xcframework.zip" \
  "$WORK/pub/debug/$MODULE-debug.manifest.json"
# Another build of the same commit (stored instead of deflated: other bytes, as a rustup or Xcode update gives): a
# version of its own; the published one, which an app may pin, is left alone (the fetches below use its lock).
alt_build() { # alt_build <dir> <zip option>: the debug output zipped another way
  mkdir -p "$1"
  cp "$WORK/pub/debug/$MODULE-debug.manifest.json" "$1/"
  (cd "$WORK/pub/debug/pkg" && find "$MODULE.xcframework" "$MODULE.manifest.json" -type f | LC_ALL=C sort |
    zip -X -D -q "$2" -@ "$1/$MODULE-debug.xcframework.zip")
  (cd "$1" && shasum -a 256 "$MODULE-debug.xcframework.zip" > "$MODULE-debug.xcframework.zip.sha256")
}
alt_build "$WORK/pub-alt/debug" -0
expect 0 "another build of the same commit publishes a version of its own" \
  $'uploaded DoodleArtCore-debug.xcframework.zip\nuploaded DoodleArtCore-release.xcframework.zip.sha256\nlock written to' \
  env -u DOODLEART_CORE_PRIVATE_TOKEN CI_JOB_TOKEN="$TOKEN" CI_API_V4_URL="$API" CI_PROJECT_ID=42 CI_COMMIT_SHA="$COMMIT" \
  "$PUBLISH" --lock-out "$WORK/alt.lock" "$WORK/pub-alt/debug" "$WORK/pub/release"
check_true "its lock names another version and the other debug zip" test "$(lock_version "$WORK/alt.lock")" != "$VERSION_1" -a \
  "$(sed -n 's/^debug.sha256 = //p' "$WORK/alt.lock")" = "$(sha_of "$WORK/pub-alt/debug/$MODULE-debug.xcframework.zip")"
check_true "twelve uploads, none into the first version" python3 -I -c '
import json, sys
puts = [entry["path"] for entry in json.loads(sys.argv[1]) if entry["method"] == "PUT"]
first = [path for path in puts if f"/{sys.argv[2]}/" in path]
sys.exit(0 if len(puts) == 12 and len(first) == 6 else 1)' "$(registry_log)" "$VERSION_1"
# A file planted under the version of a build before that build publishes: never pinned, the job stops, no lock.
alt_build "$WORK/pub-planted/debug" -1
planted_version="$(env -u CI_COMMIT_SHA "$PUBLISH" --dry-run "$WORK/pub-planted/debug" "$WORK/pub/release" |
  sed -n 's/^  version = //p')"
[[ -n "$planted_version" && "$planted_version" != "$VERSION_1" ]] || { echo "no dry-run version" >&2; exit 1; }
printf '%064d  %s\n' 7 "$MODULE-debug.xcframework.zip" > "$WORK/planted.sha256"
printf 'header = "JOB-TOKEN: %s"\n' "$TOKEN" | curl -q --silent --fail --config - --upload-file "$WORK/planted.sha256" \
  "$API/projects/42/packages/generic/doodleart-core-$PROJECT_ID/$planted_version/$MODULE-debug.xcframework.zip.sha256" \
  > /dev/null
expect 1 "a file someone else put under this build's version stops the job" \
  "already in the registry with sha256 $(printf '%064d' 7), but this build is $(sha_of "$WORK/pub-planted/debug/$MODULE-debug.xcframework.zip")"$'\nNot pinned, nothing\nno lock written' \
  env -u DOODLEART_CORE_PRIVATE_TOKEN CI_JOB_TOKEN="$TOKEN" CI_API_V4_URL="$API" CI_PROJECT_ID=42 CI_COMMIT_SHA="$COMMIT" \
  "$PUBLISH" --lock-out "$WORK/planted.lock" "$WORK/pub-planted/debug" "$WORK/pub/release"
check_true "no lock written for it" test ! -e "$WORK/planted.lock"
check_true "nothing uploaded after the planted file" python3 -I -c '
import json, sys
sys.exit(0 if sum(entry["method"] == "PUT" for entry in json.loads(sys.argv[1])) == 13 else 1)' "$(registry_log)"
fetch() { # fetch <type> <dest> [env assignments...]
  local type="$1" dest="$2"
  shift 2
  env -u CI_JOB_TOKEN -u DOODLEART_CORE_DEPLOY_TOKEN -u DOODLEART_CORE_PRIVATE_TOKEN "$@" \
    "$FETCH" --type "$type" --dest "$dest" --lock "$WORK/core.lock"
}
expect 1 "fetch without a credential" "HTTP 401" fetch release "$WORK/app/Core"
expect 0 "fetch release with a deploy token through the redirect" \
  $'(auth: Deploy-Token)\nredirected to http://127.0.0.1:'"$PORT"$' (followed without credentials)\nverified\n"buildType": "release"' \
  fetch release "$WORK/app/Core" DOODLEART_CORE_DEPLOY_TOKEN="$TOKEN"
check_true "the xcframework and its manifest are installed" test -f "$WORK/app/Core/$MODULE.xcframework/Info.plist"
expect 0 "the installed core passes check-macho" $'xcframework: ios-arm64, ios-arm64-simulator, macos-arm64\ncheck-macho: OK' \
  "${CHECK_RELEASE[@]}" "$WORK/app/Core"
expect 0 "fetch debug with CI_JOB_TOKEN replaces it (and reads no .curlrc)" $'(auth: JOB-TOKEN)\n"buildType": "debug"' \
  fetch debug "$WORK/app/Core" CI_JOB_TOKEN="$TOKEN" CURL_HOME="$WORK/curlhome"
check_true "no request carried the .curlrc's user agent" python3 -I -c '
import json, sys
log = json.loads(sys.argv[1])
sys.exit(0 if log and not any(entry["ua"] == "curlrc-was-read" for entry in log) else 1)
' "$(registry_log)"
check_true "credentials went to the registry only, never to the redirect target" python3 -I -c '
import json, sys
log = json.loads(sys.argv[1])
blobs = [entry for entry in log if entry["path"].startswith("/blob/")]
gets = [entry for entry in log if entry["method"] == "GET" and "/packages/generic/" in entry["path"]]
ok = len(blobs) >= 2 and all(entry["auth"] == {} for entry in blobs)
ok &= any(entry["auth"] == {"Deploy-Token": True} for entry in gets)
ok &= any(entry["auth"] == {"JOB-TOKEN": True} for entry in gets)
sys.exit(0 if ok else 1)
' "$(registry_log)"
expect 1 "a redirect to plain http on another host is refused" "refusing a redirect to http://example.invalid" \
  env -u CI_JOB_TOKEN DOODLEART_CORE_DEPLOY_TOKEN="$TOKEN" "$FETCH" --type release --dest "$WORK/app/Core" \
  --registry "$API" --project 42 --package insecure-redirect --version 1 --sha256 "$(printf '%064d' 0)"
curl --silent --fail -X POST "http://127.0.0.1:$PORT/__tamper/$MODULE-release.xcframework.zip" > /dev/null
expect 1 "a zip changed in the registry" "SHA-256 mismatch" fetch release "$WORK/app/Core" CI_JOB_TOKEN="$TOKEN"
check_true "the debug core stays installed" grep -q '"buildType": "debug"' "$WORK/app/Core/$MODULE.manifest.json"

echo "test-dist: $passed passed, $failed failed"
[[ $failed -eq 0 ]]
