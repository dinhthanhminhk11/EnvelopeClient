#!/usr/bin/env bash
# Uploads build-ios.sh outputs to the GitLab Generic Package Registry and prints the core.lock that pins them (spec
# 2026-11-05 §4.6 b; the core:publish job of .gitlab-ci.yml). tools/fetch-core.sh is the consumer side.
#
#   tools/publish-core.sh [--dry-run] [--lock-out FILE] <build-ios output dir>...
#
# Each directory is one `build-ios.sh <type> --out DIR` output: DoodleArtCore-<type>.xcframework.zip, its .sha256 file
# and DoodleArtCore-<type>.manifest.json. All of them must come from one commit: same projectId, crateVersion and gitSha,
# a clean tree (gitDirty false) and, in CI, gitSha == $CI_COMMIT_SHA. Packaging "slices" (--no-xcframework) is only
# accepted with --dry-run.
#
# Package: doodleart-core-<projectId>; version: <crateVersion>-<first 12 hex of gitSha>-<first 8 hex of the build digest>,
# e.g. 0.1.0-ae2c4e161ffd-5f0c2a9e (valid for GitLab generic packages: names [A-Za-z0-9._-], versions [A-Za-z0-9._+-]).
# The build digest is the SHA-256 of the lines "<type> <zip sha256>\n" of the published build types, sorted. The
# build is reproducible for one toolchain only: the manifest inside each zip names rustc, and the slices are
# prelinked by the runner's ld, so the same commit built after a rustup or Xcode update gives other zips. They get a
# version of their own instead of colliding with the one an app already pins in its core.lock, which is never
# replaced or deleted. Files per build type, uploaded in this order: the zip, the manifest, then the .sha256, so a
# version whose .sha256 exists is complete. A build type whose .sha256 is already in the registry with THIS build's
# digest is not uploaded again (a re-run of the same build). A different digest under this version cannot come from
# this build (the version names its digest): someone else wrote it. Every pipeline of the project, unprotected
# branches included, can write the registry with its CI_JOB_TOKEN, and core.lock is the trust anchor of the iOS app,
# so the job stops, writes no lock, pins nothing it read from the registry and deletes nothing.
#
# Registry: $CI_API_V4_URL/projects/$CI_PROJECT_ID (or DOODLEART_CORE_REGISTRY / DOODLEART_CORE_PROJECT). Credential:
# CI_JOB_TOKEN (header JOB-TOKEN), else DOODLEART_CORE_PRIVATE_TOKEN (PRIVATE-TOKEN, api scope); never printed, never in a
# URL or a command line. Only https, except http://127.0.0.1 / http://localhost (tests). curl runs with -q: no
# ~/.curlrc or $CURL_HOME/.curlrc (an `insecure` or `proxy` there would expose the token).
# --dry-run checks everything and prints the uploads and the lock without any network access.
# --lock-out writes the lock to FILE as well (the job's artifact).
set -euo pipefail

MODULE=DoodleArtCore
die() {
  echo "publish-core: $*" >&2
  exit 1
}
usage() {
  echo "usage: $0 [--dry-run] [--lock-out FILE] <build-ios output dir>..." >&2
  exit 2
}

DRY_RUN=0
LOCK_OUT=""
DIRS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --lock-out) [[ $# -ge 2 ]] || usage; LOCK_OUT="$2"; shift 2 ;;
    -*) usage ;;
    *) DIRS+=("$1"); shift ;;
  esac
done
[[ ${#DIRS[@]} -gt 0 ]] || usage
command -v python3 >/dev/null || die "python3 missing"

# Validate the outputs; prints `type file sha256 manifest` per build type, then `package version projectId`.
plan="$(python3 -I - "$DRY_RUN" "${CI_COMMIT_SHA:-}" "$MODULE" "${DIRS[@]}" <<'PY'
import hashlib, json, os, re, sys
dry_run, commit, module, *dirs = sys.argv[1:]
def die(message):
    sys.exit(f"publish-core: {message}")
rows, seen = [], {}
for directory in dirs:
    manifests = [name for name in os.listdir(directory) if re.fullmatch(rf"{module}-(debug|release)\.manifest\.json", name)]
    if len(manifests) != 1:
        die(f"{directory}: expected one {module}-<type>.manifest.json, found {manifests}")
    manifest_path = os.path.join(directory, manifests[0])
    manifest = json.load(open(manifest_path, encoding="utf-8"))
    build_type = manifest.get("buildType")
    if manifests[0] != f"{module}-{build_type}.manifest.json":
        die(f"{manifest_path}: buildType {build_type!r} does not match the file name")
    if build_type in seen:
        die(f"two {build_type} outputs: {seen[build_type]} and {directory}")
    seen[build_type] = directory
    packaging = manifest.get("packaging")
    if packaging != "xcframework" and not (packaging == "slices" and dry_run == "1"):
        die(f"{manifest_path}: packaging {packaging!r} is not publishable (build without --no-xcframework)")
    zip_name = f"{module}-{build_type}.{'xcframework' if packaging == 'xcframework' else 'slices'}.zip"
    zip_path = os.path.join(directory, zip_name)
    sha_line = open(zip_path + ".sha256", encoding="utf-8").read().split()
    digest = hashlib.sha256(open(zip_path, "rb").read()).hexdigest()
    if sha_line[:2] != [digest, zip_name]:
        die(f"{zip_path}.sha256 does not match the zip ({digest})")
    if manifest.get("gitDirty") is not False and dry_run != "1":
        die(f"{manifest_path}: built from a dirty tree (gitDirty)")
    if commit and manifest.get("gitSha") != commit:
        die(f"{manifest_path}: gitSha {manifest.get('gitSha')} is not CI_COMMIT_SHA {commit}")
    rows.append((build_type, zip_name, digest, manifest_path, manifest))
first = rows[0][4]
for key in ("projectId", "crateVersion", "gitSha", "abiVersion"):
    values = {row[4].get(key) for row in rows}
    if len(values) != 1:
        die(f"the outputs disagree on {key}: {sorted(map(str, values))}")
if not re.fullmatch(r"[0-9a-f]{40}", first.get("gitSha", "")):
    die(f"gitSha {first.get('gitSha')!r} is not a commit id")
package = f"doodleart-core-{first['projectId']}"
# The build digest (header): the version changes with the bytes of any published zip.
build_digest = hashlib.sha256("".join(f"{row[0]} {row[2]}\n" for row in sorted(rows)).encode()).hexdigest()
version = f"{first['crateVersion']}-{first['gitSha'][:12]}-{build_digest[:8]}"
if not re.fullmatch(r"[A-Za-z0-9._-]+", package) or not re.fullmatch(r"[A-Za-z0-9._+-]+", version):
    die(f"invalid package {package!r} or version {version!r}")
for build_type, zip_name, digest, manifest_path, _ in sorted(rows):
    print(f"{build_type} {zip_name} {digest} {manifest_path}")
print(f"package {package} {version} {first['projectId']}")
PY
)" || exit 1

read -r _ PACKAGE VERSION PROJECT_ID <<< "$(tail -n 1 <<< "$plan")"
REGISTRY="${DOODLEART_CORE_REGISTRY:-${CI_API_V4_URL:-}}"
REGISTRY="${REGISTRY%/}"
PROJECT="${DOODLEART_CORE_PROJECT:-${CI_PROJECT_ID:-}}"
if [[ $DRY_RUN -eq 0 ]]; then
  [[ "$REGISTRY" =~ ^https:// || "$REGISTRY" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/|$) ]] ||
    die "registry must be https (CI_API_V4_URL or DOODLEART_CORE_REGISTRY): ${REGISTRY:-unset}"
  [[ "$PROJECT" =~ ^[A-Za-z0-9._%-]+$ ]] || die "project id missing (CI_PROJECT_ID or DOODLEART_CORE_PROJECT)"
  if [[ -n "${CI_JOB_TOKEN:-}" ]]; then header=JOB-TOKEN; token="$CI_JOB_TOKEN"
  elif [[ -n "${DOODLEART_CORE_PRIVATE_TOKEN:-}" ]]; then header=PRIVATE-TOKEN; token="$DOODLEART_CORE_PRIVATE_TOKEN"
  else die "no credential: CI_JOB_TOKEN (CI) or DOODLEART_CORE_PRIVATE_TOKEN"; fi
  [[ "$token" =~ ^[A-Za-z0-9._~+/=:-]+$ ]] || die "the $header token contains unexpected characters"
  command -v curl >/dev/null || die "curl missing"
fi
BASE="${REGISTRY:-<registry>}/projects/${PROJECT:-<project>}/packages/generic/$PACKAGE/$VERSION"
echo "publish-core: $PACKAGE $VERSION -> $BASE$([[ $DRY_RUN -eq 1 ]] && echo ' (dry run)')"

# -q first: no .curlrc (an `insecure` or `proxy` line there would expose the token).
CURL=(curl -q --silent --show-error --connect-timeout 20 --max-time 900 --retry 2 --proto '=https,http' --proto-redir '=https')
# The credential reaches curl through a config on its standard input (printf builtin: not in argv, not on disk).
with_token() {
  printf 'header = "%s: %s"\n' "$header" "$token" | "${CURL[@]}" --config - "$@"
}
# Digest of an already published <zip>.sha256, or nothing (404). Redirects are followed without the credential.
published_sha() {
  local url="$BASE/$1.sha256" body="$WORK/published.sha256" result code location
  result="$(with_token --max-redirs 0 --output "$body" --write-out '%{http_code} %{redirect_url}' "$url")" ||
    die "cannot query $url"
  code="${result%% *}"
  location="${result#* }"
  case "$code" in
    200) ;;
    404) return 0 ;;
    301 | 302 | 303 | 307 | 308)
      [[ "$location" =~ ^https:// || "$location" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?/ ]] ||
        die "refusing a redirect that is not https"
      "${CURL[@]}" --fail --location --max-redirs 5 --output "$body" "$location" < /dev/null ||
        die "cannot read the published $1.sha256"
      ;;
    *) die "HTTP $code when checking $url" ;;
  esac
  cut -d ' ' -f 1 "$body"
}
upload() {
  local file="$1" name="$2" url="$BASE/$2" response
  response="$WORK/response.json"
  if ! with_token --fail-with-body --upload-file "$file" --output "$response" "$url"; then
    echo "publish-core: upload of $name failed:" >&2
    head -c 2000 "$response" >&2 || true
    echo >&2
    exit 1
  fi
  echo "publish-core:   uploaded $name ($(wc -c < "$file" | tr -d ' ') bytes)"
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/publish-core.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
LOCK="$WORK/core.lock"
{
  echo "# DoodleArtCore for tools/fetch-core.sh, published by tools/publish-core.sh${CI_PIPELINE_URL:+ in $CI_PIPELINE_URL}"
  echo "registry = ${REGISTRY:-<registry>}"
  echo "project = ${PROJECT:-<project>}"
  echo "package = $PACKAGE"
  echo "version = $VERSION"
  echo "projectId = $PROJECT_ID"
} > "$LOCK"

while read -r build_type zip digest manifest; do
  [[ "$build_type" != package ]] || continue
  dir="$(dirname "$manifest")"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "publish-core: would upload $zip, $(basename "$manifest"), $zip.sha256 (sha256 $digest)"
  else
    existing="$(published_sha "$zip")"
    if [[ -z "$existing" ]]; then
      upload "$dir/$zip" "$zip"
      upload "$manifest" "$(basename "$manifest")"
      upload "$dir/$zip.sha256" "$zip.sha256"
    elif [[ "$existing" == "$digest" ]]; then
      echo "publish-core: $zip is already published with the same sha256: nothing uploaded"
    else
      [[ "$existing" =~ ^[0-9a-f]{64}$ ]] || die "the published $zip.sha256 is malformed"
      die "$zip of $PACKAGE $VERSION is already in the registry with sha256 $existing, but this build is $digest" \
        "and the version names this build's digest: that file was not uploaded by this build. Not pinned, nothing" \
        "deleted, no lock written (any pipeline of the project can write the registry): find out who uploaded it" \
        "(Packages API, package_files[].pipelines) before touching it; never delete a version an app pins in core.lock."
    fi
  fi
  echo "$build_type.file = $zip" >> "$LOCK"
  echo "$build_type.sha256 = $digest" >> "$LOCK"
done <<< "$plan"

echo "publish-core: core.lock:"
sed 's/^/  /' "$LOCK"
if [[ -n "$LOCK_OUT" ]]; then
  cp "$LOCK" "$LOCK_OUT"
  echo "publish-core: lock written to $LOCK_OUT"
fi
