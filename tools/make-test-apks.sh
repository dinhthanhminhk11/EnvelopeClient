#!/usr/bin/env bash
# Regenerates tests/fixtures/apk/*.apk: tiny ZIPs signed with build-tools apksigner, used by the apk_identity tests.
#   debug-v2v3.apk     ~/.android/debug.keystore (androiddebugkey), schemes v1+v2+v3
#   debug-v1only.apk   same key, v1 (JAR) signature only: no APK Signing Block
#   upload-v2.apk      a throwaway upload key (alias doodleart), v2 only
#   foreign-v2v3.apk   a throwaway key generated here, v2+v3
#   rotated-v2v3.apk   v2 by the debug key, v3 by the throwaway key (signing-key rotation lineage)
#   unsigned.apk       the bare ZIP
# The upload keystore password is in app/build.gradle.kts (committed by owner decision, theme-x plan §1.3); the debug keystore
# uses Android's well-known default password. Nothing secret is printed.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$CRATE_DIR/tests/fixtures/apk"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
# Newest build-tools that actually contains apksigner (half-installed versions can be empty directories).
APKSIGNER="$(ls -d "$SDK"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -n 1)"
[[ -x "$APKSIGNER" ]] || { echo "apksigner not found under $SDK/build-tools" >&2; exit 1; }
DEBUG_KS="$HOME/.android/debug.keystore"
UPLOAD_KS="$CRATE_DIR/../key/doodleart"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"

# Minimal APK-shaped ZIP: a placeholder manifest, a stored (uncompressed) fake .so for the entry lookup test.
python3 - "$WORK/base.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr(zipfile.ZipInfo("AndroidManifest.xml"), b"\x03\x00\x08\x00placeholder", compress_type=zipfile.ZIP_DEFLATED)
    z.writestr(zipfile.ZipInfo("lib/arm64-v8a/libprobe.so"), b"\x7fELF\x02\x01\x01" + bytes(57), compress_type=zipfile.ZIP_STORED)
    z.writestr(zipfile.ZipInfo("res/raw/hello.txt"), b"hello doodleart\n", compress_type=zipfile.ZIP_DEFLATED)
PY

keytool -genkeypair -keystore "$WORK/foreign.p12" -storetype PKCS12 -storepass foreign123 -keypass foreign123 \
  -alias foreign -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Not DoodleArt, O=Attacker" >/dev/null 2>&1

common=(--min-sdk-version 24 --v4-signing-enabled false)
debug_signer=(--ks "$DEBUG_KS" --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android)
upload_signer=(--ks "$UPLOAD_KS" --ks-key-alias doodleart --ks-pass pass:doodleart --key-pass pass:doodleart)
foreign_signer=(--ks "$WORK/foreign.p12" --ks-key-alias foreign --ks-pass pass:foreign123 --key-pass pass:foreign123)

cp "$WORK/base.zip" "$OUT/unsigned.apk"
"$APKSIGNER" sign "${common[@]}" "${debug_signer[@]}" --v1-signing-enabled true --v2-signing-enabled true \
  --v3-signing-enabled true --out "$OUT/debug-v2v3.apk" "$WORK/base.zip"
"$APKSIGNER" sign "${common[@]}" "${debug_signer[@]}" --v1-signing-enabled true --v2-signing-enabled false \
  --v3-signing-enabled false --out "$OUT/debug-v1only.apk" "$WORK/base.zip"
"$APKSIGNER" sign "${common[@]}" "${upload_signer[@]}" --v1-signing-enabled false --v2-signing-enabled true \
  --v3-signing-enabled false --out "$OUT/upload-v2.apk" "$WORK/base.zip"
"$APKSIGNER" sign "${common[@]}" "${foreign_signer[@]}" --v1-signing-enabled false --v2-signing-enabled true \
  --v3-signing-enabled true --out "$OUT/foreign-v2v3.apk" "$WORK/base.zip"

"$APKSIGNER" rotate --out "$WORK/lineage.bin" --old-signer "${debug_signer[@]}" --new-signer "${foreign_signer[@]}"
"$APKSIGNER" sign "${common[@]}" --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --rotation-min-sdk-version 28 --lineage "$WORK/lineage.bin" \
  "${debug_signer[@]}" --next-signer "${foreign_signer[@]}" --out "$OUT/rotated-v2v3.apk" "$WORK/base.zip"

rm -f "$OUT"/*.idsig
for apk in "$OUT"/*.apk; do
  echo "== $(basename "$apk")"
  "$APKSIGNER" verify --min-sdk-version 24 --print-certs -v "$apk" 2>/dev/null \
    | grep -E "Verified using v[123]|certificate SHA-256" || echo "   (not verifiable: expected for unsigned)"
done
