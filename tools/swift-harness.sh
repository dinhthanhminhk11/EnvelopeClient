#!/usr/bin/env bash
# End-to-end check of the Swift sample (swift/Sources: CoreBridge, DeviceIdentity, AppAttest, SecureChannel) over the
# secure session, on the macOS host (no Xcode needed): compiles it with tests/swift-harness against the macOS slice of
# build-ios.sh and runs it against a running app service (`make migrate-up` then `make run-app` in server/).
#
#   tools/swift-harness.sh [--stub] [--fresh] [BASE_URL]      (default http://localhost:9100)
#
#   --stub    App Attest stand-ins as on the Simulator (the server needs `make run-app ATTESTATION_MODE=observe`: the
#             stub verifier of the local profile)
#   --fresh   new device id and key first (registration again)
# A run opens three sessions and the server allows 20 handshakes per minute per device key: more than six runs within a
# minute fail with 429 at session/start (the channel then reports unavailable and falls back to plain).
# Needs target/ios/debug from `./build-ios.sh debug --no-xcframework`. The device key is a software key and the
# "Keychain" a UserDefaults suite of the harness (DOODLEART_SAMPLE_DEFAULTS_STORE), never the login keychain.
set -euo pipefail
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$CRATE_DIR/target/ios/debug"
[[ -f "$CORE/slices/aarch64-apple-darwin/libdoodleart_core.a" ]] ||
  { echo "swift-harness: run ./build-ios.sh debug --no-xcframework first" >&2; exit 1; }
FLAGS=(-D DEBUG -D DOODLEART_SOFTWARE_KEY -D DOODLEART_SAMPLE_DEFAULTS_STORE)
ARGS=()
PLIST_ID=com.cem.doodle.art.harness
for arg in "$@"; do
  case "$arg" in
    --stub) FLAGS+=(-D DOODLEART_APP_ATTEST_STUB); PLIST_ID=com.cem.doodle.art.harness.stub ;;
    *) ARGS+=("$arg") ;;
  esac
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/doodleart-swift-harness.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
sed "s/com.cem.doodle.art.harness</$PLIST_ID</" "$CRATE_DIR/tests/swift-harness/Info.plist" > "$WORK/Info.plist"
swiftc -parse-as-library "${FLAGS[@]}" -I "$CORE/Headers/DoodleArtCore" -L "$CORE/slices/aarch64-apple-darwin" \
  -ldoodleart_core -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$WORK/Info.plist" \
  "$CRATE_DIR/tests/swift-harness/main.swift" "$CRATE_DIR"/swift/Sources/*.swift -o "$WORK/harness"
"$WORK/harness" "${ARGS[@]+"${ARGS[@]}"}"
