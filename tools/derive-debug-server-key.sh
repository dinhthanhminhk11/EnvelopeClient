#!/usr/bin/env bash
# Writes config/server-keys.debug.conf from ENVELOPE_SIGNING_KEY / ENVELOPE_SIGNING_KID of the developer machine's app
# service (server/.env, or the file given). Only the public key and the kid go into the file; the seed stays in .env.
#   tools/derive-debug-server-key.sh [path/to/server/.env]
set -euo pipefail
CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-$CRATE_DIR/../server/.env}"
[[ -f "$ENV_FILE" ]] || { echo "derive-debug-server-key: no $ENV_FILE" >&2; exit 1; }
command -v node >/dev/null || { echo "derive-debug-server-key: node is needed" >&2; exit 1; }
seed="$(sed -n 's/^ENVELOPE_SIGNING_KEY=//p' "$ENV_FILE" | tail -n 1)"
kid="$(sed -n 's/^ENVELOPE_SIGNING_KID=//p' "$ENV_FILE" | tail -n 1)"
[[ -n "$seed" && -n "$kid" ]] || { echo "derive-debug-server-key: ENVELOPE_SIGNING_KEY / ENVELOPE_SIGNING_KID empty in $ENV_FILE" >&2; exit 1; }
public="$(SEED="$seed" node -e '
const c = require("crypto");
const seed = Buffer.from(process.env.SEED, "base64url");
if (seed.length !== 32) { console.error("ENVELOPE_SIGNING_KEY is not a 32-byte base64url seed"); process.exit(1); }
const key = c.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
process.stdout.write(c.createPublicKey(key).export({ format: "der", type: "spki" }).subarray(12).toString("hex"));')"
cat > "$CRATE_DIR/config/server-keys.debug.conf" <<CONF
# Server Ed25519 public keys embedded in the DEBUG build type: the app service of a developer machine
# (\`make run-app\` in server/, ENVELOPE_SIGNING_KEY / ENVELOPE_SIGNING_KID of server/.env). Written by
# tools/derive-debug-server-key.sh. Public values only: the private seed stays in server/.env.
project = doodleart
build_type = debug
current.kid = $kid
current.public_key = $public
next.kid =
next.public_key =
CONF
echo "derive-debug-server-key: kid $kid, public key $public -> config/server-keys.debug.conf"
