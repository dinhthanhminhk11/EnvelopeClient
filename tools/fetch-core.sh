#!/usr/bin/env bash
# Installs a published DoodleArtCore build (build-ios.sh output, uploaded by tools/publish-core.sh) for an app: downloads
# DoodleArtCore-<type>.xcframework.zip from the GitLab Generic Package Registry, verifies its SHA-256 against the lock,
# unpacks it safely and installs DoodleArtCore.xcframework + DoodleArtCore.manifest.json into the destination directory,
# replacing the previous ones (theme-x spec 2026-11-05 §4.5, §4.6 c). Generic: the iOS team wires it into Fastlane, a Run
# Script or a dev's shell; nothing here knows the app's layout.
#
#   tools/fetch-core.sh --type <debug|release> --dest DIR [--lock FILE] [--from-file ZIP]
#                       [--registry URL] [--project ID] [--package NAME] [--version VERSION] [--file NAME]
#                       [--sha256 HEX] [--project-id ID]
#
#   --type       build type to install; the manifest inside the zip must say the same
#   --dest       directory that receives DoodleArtCore.xcframework and DoodleArtCore.manifest.json (created if missing)
#   --lock       lock file (the app's core.lock, committed), see below; options given on the command line win
#   --from-file  install a local zip instead of downloading it (a build-ios.sh output, a manual download); its SHA-256
#                is still checked against the lock / --sha256
#   --sha256     expected SHA-256 of the zip (instead of <type>.sha256 of the lock)
#   --project-id expected projectId of the manifest (instead of projectId of the lock)
#
# Lock file: `key = value` lines, `#` comments; an unknown key stops. Written by tools/publish-core.sh (printed in the
# core:publish job log and kept as its artifact core.lock):
#   registry = https://gitlab.com/api/v4        GitLab API v4 root (default: $CI_API_V4_URL)
#   project = 12345678                          project id, or its URL-encoded path (default: $CI_PROJECT_ID)
#   package = doodleart-core-doodleart                generic package name: doodleart-core-<projectId>
#   version = 0.1.0-ae2c4e161ffd-5f0c2a9e       <crateVersion>-<first 12 hex of the git commit>-<first 8 hex of the
#                                               build digest> (tools/publish-core.sh); opaque here
#   projectId = doodleart                          expected manifest projectId
#   debug.file = DoodleArtCore-debug.xcframework.zip
#   debug.sha256 = <64 hex>
#   release.file = DoodleArtCore-release.xcframework.zip
#   release.sha256 = <64 hex>
# The SHA-256 is mandatory: nothing is installed unverified.
#
# Credentials (never printed, never in a URL or a command line: curl reads the header from its standard input):
# CI_JOB_TOKEN (GitLab CI, header JOB-TOKEN), else DOODLEART_CORE_DEPLOY_TOKEN (a deploy token with
# read_package_registry, header Deploy-Token), else DOODLEART_CORE_PRIVATE_TOKEN (a personal or project access token,
# header PRIVATE-TOKEN), else none (public package). The registry may answer with a redirect to object storage: it is
# followed WITHOUT the credential header (the signed URL carries its own authorisation) and its query is never printed.
# Only https is accepted, except http://127.0.0.1 / http://localhost (local tests). curl runs with -q: no ~/.curlrc
# or $CURL_HOME/.curlrc is read (an `insecure` or `proxy` line there would expose the credential).
#
# The zip must hold DoodleArtCore.manifest.json and exactly one payload directory, DoodleArtCore.xcframework (packaging
# "xcframework") or DoodleArtCore-slices (packaging "slices", --no-xcframework builds: accepted with a warning, never for
# an app build). Entries that are absolute, contain "..", are links or lie outside those names stop the install, so do
# a manifest that does not match --type / projectId, or libraries whose SHA-256 is not in the manifest. The manifest
# is printed at the end. Needs bash, curl, python3 (unzip and checks), shasum or sha256sum.
set -euo pipefail

MODULE=DoodleArtCore
die() {
  echo "fetch-core: $*" >&2
  exit 1
}
usage() {
  echo "usage: $0 --type <debug|release> --dest DIR [--lock FILE] [--from-file ZIP] [--registry URL] [--project ID]" >&2
  echo "       [--package NAME] [--version VERSION] [--file NAME] [--sha256 HEX] [--project-id ID]" >&2
  exit 2
}

TYPE="" DEST="" LOCK="" FROM_FILE="" REGISTRY="" PROJECT="" PACKAGE="" VERSION="" FILE="" SHA256="" PROJECT_ID=""
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || usage
  case "$1" in
    --type) TYPE="$2" ;;
    --dest) DEST="$2" ;;
    --lock) LOCK="$2" ;;
    --from-file) FROM_FILE="$2" ;;
    --registry) REGISTRY="$2" ;;
    --project) PROJECT="$2" ;;
    --package) PACKAGE="$2" ;;
    --version) VERSION="$2" ;;
    --file) FILE="$2" ;;
    --sha256) SHA256="$2" ;;
    --project-id) PROJECT_ID="$2" ;;
    *) echo "fetch-core: unknown option $1" >&2; usage ;;
  esac
  shift 2
done
[[ "$TYPE" == debug || "$TYPE" == release ]] || { echo "fetch-core: --type debug|release is required" >&2; usage; }
[[ -n "$DEST" ]] || { echo "fetch-core: --dest is required" >&2; usage; }
command -v python3 >/dev/null || die "python3 missing"

# Lock values fill what the command line left empty.
if [[ -n "$LOCK" ]]; then
  [[ -f "$LOCK" ]] || die "lock file not found: $LOCK"
  lock_values="$(python3 -I - "$LOCK" "$TYPE" <<'PY'
import re, sys
path, build_type = sys.argv[1:]
allowed = {"registry", "project", "package", "version", "projectId", "debug.file", "debug.sha256", "release.file",
           "release.sha256"}
values = {}
for number, raw in enumerate(open(path, encoding="utf-8"), 1):
    line = raw.split("#", 1)[0].strip()
    if not line:
        continue
    if "=" not in line:
        sys.exit(f"fetch-core: {path}: line {number}: expected key = value")
    key, value = (part.strip() for part in line.split("=", 1))
    if key not in allowed:
        sys.exit(f"fetch-core: {path}: line {number}: unknown key {key!r}")
    if key in values:
        sys.exit(f"fetch-core: {path}: line {number}: {key} given twice")
    if not re.fullmatch(r"[A-Za-z0-9._:/%+-]*", value):
        sys.exit(f"fetch-core: {path}: line {number}: unexpected characters in {key}")
    values[key] = value
for key, name in (("registry", "REGISTRY"), ("project", "PROJECT"), ("package", "PACKAGE"), ("version", "VERSION"),
                  ("projectId", "PROJECT_ID"), (f"{build_type}.file", "FILE"), (f"{build_type}.sha256", "SHA256")):
    print(f"{name}={values.get(key, '')}")
PY
)" || exit 1
  lock_value() { sed -n "s/^$1=//p" <<< "$lock_values"; }
  [[ -n "$REGISTRY" ]] || REGISTRY="$(lock_value REGISTRY)"
  [[ -n "$PROJECT" ]] || PROJECT="$(lock_value PROJECT)"
  [[ -n "$PACKAGE" ]] || PACKAGE="$(lock_value PACKAGE)"
  [[ -n "$VERSION" ]] || VERSION="$(lock_value VERSION)"
  [[ -n "$PROJECT_ID" ]] || PROJECT_ID="$(lock_value PROJECT_ID)"
  [[ -n "$FILE" ]] || FILE="$(lock_value FILE)"
  [[ -n "$SHA256" ]] || SHA256="$(lock_value SHA256)"
fi
if [[ -z "$FILE" && -n "$FROM_FILE" ]]; then FILE="$(basename "$FROM_FILE")"; fi
[[ -n "$FILE" ]] || FILE="$MODULE-$TYPE.xcframework.zip"
SHA256="$(tr 'A-F' 'a-f' <<< "$SHA256")"
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] ||
  die "no valid SHA-256 for the $TYPE zip (lock $TYPE.sha256 or --sha256): refusing to install an unverified core"
[[ -z "$PROJECT_ID" || "$PROJECT_ID" =~ ^[a-z0-9-]{1,32}$ ]] || die "invalid projectId: $PROJECT_ID"

sha256_of() {
  if command -v shasum >/dev/null; then shasum -a 256 "$1" | cut -d ' ' -f 1
  elif command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f 1
  else die "shasum or sha256sum missing"; fi
}

mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"
WORK="$(mktemp -d "$DEST/.fetch-core.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ZIP="$WORK/$FILE"

# Allowed URL schemes: https anywhere, http only to the loopback host (tests).
url_allowed() {
  [[ "$1" =~ ^https:// || "$1" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/|$) ]]
}
url_origin() {
  sed -E 's#^([a-z]+://[^/?#]*).*#\1#' <<< "$1"
}

if [[ -n "$FROM_FILE" ]]; then
  [[ -f "$FROM_FILE" ]] || die "zip not found: $FROM_FILE"
  cp "$FROM_FILE" "$ZIP"
  echo "fetch-core: $TYPE from $FROM_FILE"
else
  command -v curl >/dev/null || die "curl missing"
  [[ -n "$REGISTRY" ]] || REGISTRY="${CI_API_V4_URL:-}"
  [[ -n "$PROJECT" ]] || PROJECT="${CI_PROJECT_ID:-}"
  REGISTRY="${REGISTRY%/}"
  url_allowed "$REGISTRY/" || die "registry must be an https URL (lock registry or --registry): ${REGISTRY:-unset}"
  [[ "$PROJECT" =~ ^[A-Za-z0-9._%-]+$ ]] ||
    die "project must be a project id or its URL-encoded path (lock project or --project): ${PROJECT:-unset}"
  [[ "$PACKAGE" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid package name (lock package or --package): ${PACKAGE:-unset}"
  [[ "$VERSION" =~ ^[A-Za-z0-9._+-]+$ ]] || die "invalid package version (lock version or --version): ${VERSION:-unset}"
  [[ "$FILE" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid file name: $FILE"
  URL="$REGISTRY/projects/$PROJECT/packages/generic/$PACKAGE/$VERSION/$FILE"

  header=""
  if [[ -n "${CI_JOB_TOKEN:-}" ]]; then header=JOB-TOKEN; token="$CI_JOB_TOKEN"
  elif [[ -n "${DOODLEART_CORE_DEPLOY_TOKEN:-}" ]]; then header=Deploy-Token; token="$DOODLEART_CORE_DEPLOY_TOKEN"
  elif [[ -n "${DOODLEART_CORE_PRIVATE_TOKEN:-}" ]]; then header=PRIVATE-TOKEN; token="$DOODLEART_CORE_PRIVATE_TOKEN"
  else token=""; fi
  # The token goes into a curl config piped to its standard input by the printf builtin: never in argv (ps) and never
  # on disk (bash 3.2 here-strings are temporary files). Characters that would need quoting there are refused.
  [[ -z "$token" || "$token" =~ ^[A-Za-z0-9._~+/=:-]+$ ]] || die "the $header token contains unexpected characters"
  curl_config=""
  [[ -z "$header" ]] || curl_config="header = \"$header: $token\""
  echo "fetch-core: $TYPE from $URL${header:+ (auth: $header)}"
  # http only reaches curl for a loopback URL (url_allowed); redirects followed by curl itself must be https.
  # -q first: no .curlrc (an `insecure` or `proxy` line there would expose the token).
  CURL=(curl -q --silent --show-error --connect-timeout 20 --max-time 900 --retry 2 --proto '=https,http' --proto-redir '=https')
  # First request: with the credential, no redirect following.
  code_and_location="$(printf '%s\n' "$curl_config" | "${CURL[@]}" --max-redirs 0 --output "$ZIP" \
    --write-out '%{http_code} %{redirect_url}' --config - "$URL")" || die "download failed: $URL"
  code="${code_and_location%% *}"
  location="${code_and_location#* }"
  [[ "$code" == "$location" ]] && location=""
  case "$code" in
    200) ;;
    301 | 302 | 303 | 307 | 308)
      [[ -n "$location" ]] || die "HTTP $code without a Location"
      url_allowed "$location" || die "refusing a redirect to $(url_origin "$location") (not https)"
      echo "fetch-core: redirected to $(url_origin "$location") (followed without credentials)"
      rm -f "$ZIP"
      "${CURL[@]}" --fail --location --max-redirs 5 --output "$ZIP" "$location" < /dev/null ||
        die "download from $(url_origin "$location") failed"
      ;;
    401 | 403)
      die "HTTP $code: no access to the package (CI_JOB_TOKEN of a project allowed to read it, or" \
        "DOODLEART_CORE_DEPLOY_TOKEN with read_package_registry)"
      ;;
    404) die "HTTP 404: $PACKAGE $VERSION has no file $FILE (not published, or no access)" ;;
    *) die "HTTP $code from $URL" ;;
  esac
fi

actual="$(sha256_of "$ZIP")"
[[ "$actual" == "$SHA256" ]] || die "SHA-256 mismatch for $FILE: expected $SHA256, got $actual. Nothing was installed."
echo "fetch-core: sha256 $actual verified"

# Unpack into WORK/unpacked with every safety check, then validate the manifest against the payload.
python3 -I - "$ZIP" "$WORK/unpacked" "$TYPE" "$PROJECT_ID" "$MODULE" <<'PY' || exit 1
import hashlib, json, os, plistlib, stat, sys, zipfile
zip_path, out, build_type, project_id, module = sys.argv[1:]
manifest_name = f"{module}.manifest.json"
payloads = {"xcframework": f"{module}.xcframework", "slices": f"{module}-slices"}
def die(message):
    sys.exit(f"fetch-core: {message}. Nothing was installed.")
try:
    archive = zipfile.ZipFile(zip_path)
except zipfile.BadZipFile as error:
    die(f"not a zip file ({error})")
tops = set()
for info in archive.infolist():
    name = info.filename
    parts = name.split("/")
    if name.startswith("/") or "\\" in name or ".." in parts or "" in parts[:-1] or ":" in parts[0]:
        die(f"unsafe entry {name!r}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        die(f"link entry {name!r}")
    if parts[0] != manifest_name and parts[0] not in payloads.values():
        die(f"unexpected entry {name!r}")
    if parts[0] == manifest_name and len(parts) != 1:
        die(f"unexpected entry {name!r}")
    tops.add(parts[0])
if manifest_name not in tops:
    die(f"{manifest_name} missing from the zip")
manifest = json.loads(archive.read(manifest_name))
packaging = manifest.get("packaging")
if manifest.get("schema") != 1 or manifest.get("module") != module or packaging not in payloads:
    die(f"unsupported manifest (schema {manifest.get('schema')}, module {manifest.get('module')}, packaging {packaging})")
if tops != {manifest_name, payloads[packaging]}:
    die(f"the zip holds {sorted(tops)}, expected {manifest_name} and {payloads[packaging]}")
if manifest.get("buildType") != build_type:
    die(f"the zip is a {manifest.get('buildType')} build, --type is {build_type}")
if project_id and manifest.get("projectId") != project_id:
    die(f"the zip is for project {manifest.get('projectId')}, the lock expects {project_id}")
for info in archive.infolist():
    target = os.path.join(out, info.filename)
    if info.is_dir():
        os.makedirs(target, exist_ok=True)
        continue
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with archive.open(info) as source, open(target, "wb") as sink:
        sink.write(source.read())
    os.chmod(target, 0o644)
expected = {value for key, value in manifest.get("sha256", {}).items() if key.endswith(".a")}
found = {}
for directory, _, names in os.walk(os.path.join(out, payloads[packaging])):
    for name in names:
        if name.endswith(".a"):
            path = os.path.join(directory, name)
            found[os.path.relpath(path, out)] = hashlib.sha256(open(path, "rb").read()).hexdigest()
if not found or set(found.values()) != expected:
    die(f"the libraries in the zip do not match the manifest's sha256 ({len(found)} found, {len(expected)} listed)")
if packaging == "xcframework":
    info_plist = os.path.join(out, payloads[packaging], "Info.plist")
    if not os.path.isfile(info_plist):
        die("DoodleArtCore.xcframework/Info.plist missing")
    plistlib.load(open(info_plist, "rb"))
PY

packaging="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["packaging"])' "$WORK/unpacked/$MODULE.manifest.json")"
[[ "$packaging" == xcframework ]] || echo "fetch-core: warning: packaging $packaging (a --no-xcframework build): bare slices for checks and tests, not for an app" >&2
# Replace the installed core: remove both payload kinds and the manifest, then move the new ones in.
rm -rf "${DEST:?}/$MODULE.xcframework" "${DEST:?}/$MODULE-slices" "${DEST:?}/$MODULE.manifest.json"
for entry in "$WORK/unpacked"/*; do
  mv "$entry" "$DEST/"
done
echo "fetch-core: installed into $DEST:"
for entry in "$MODULE.xcframework" "$MODULE-slices" "$MODULE.manifest.json"; do
  if [[ -e "$DEST/$entry" ]]; then echo "  $entry"; fi
done
cat "$DEST/$MODULE.manifest.json"
