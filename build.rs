//! Build-time configuration for doodleart-core.
//!
//! Selects the build type from the `build-*` cargo feature and embeds, as generated Rust constants:
//! - the server Ed25519 public keys (current + optional next) read from `config/server-keys.<type>.conf`, or from the
//!   file named by `DOODLEART_SERVER_KEYS_FILE` (a relative path is relative to this crate, like `DOODLEART_PROJECT_CONF`);
//! - for the debug build type only, the debug signing-cert allowlist from `config/debug-certs.conf` (debug keystores
//!   differ per machine);
//! - from the project config (`config/project.conf`, or the file named by `DOODLEART_PROJECT_CONF`): the project id and
//!   the release and QA APK signing-cert allowlists, which `src/apk_identity.rs` picks by build type.
//!
//! # Apple libraries
//!
//! An Apple library (the iOS device and Simulator libraries, any other Apple OS except macOS, and the macOS slice that
//! build-ios.sh and tools/c-abi-smoke.sh build with `DOODLEART_APPLE_LIB=1`) gets the cfg `doodleart_apple_lib`: src/lib.rs
//! then leaves out the Android-only parts (JNI with `JNI_OnLoad`, APK identity, device signals, the Android scan) and
//! compiles the C ABI and the Apple scan instead. There is no APK, so `debug-certs.conf` is not read and every APK
//! allowlist is empty, and there is no QA build: `build-qa` stops the build. A plain macOS build (`cargo build`,
//! `cargo test` on a Mac) is NOT an Apple library: it keeps the Android parts, `JNI_OnLoad` included, for a host
//! harness of a future Kotlin module and the host unit tests.
//! `DOODLEART_APPLE_LIB` is "1" or unset: any other value, or "1" for a non-Apple target, stops the build. Android output
//! is unchanged. `doodleart_simulator_target` is set when the target triple names a simulator (`*-sim`,
//! `x86_64-apple-ios`): src/risk/apple.rs checks its own simulator cfg against it at compile time.
//!
//! Release and QA configs ship with a placeholder: the build stops with an explicit error until the owner supplies the
//! real key (host tests of the release code use tests/fixtures/server-keys.release-test.conf). Nothing here is secret:
//! these are public keys and certificate digests.
//!
//! # Per-project values (from theme-x, where this crate began)
//!
//! The core also serves other projects. Each project brings its own copy of every value below and never shares one
//! with another project:
//! - the project config (`config/project.conf`, or `DOODLEART_PROJECT_CONF`): `PROJECT_ID`, the release and QA APK
//!   signing-cert allowlists, `REMAP_SALT` (the key of the source path remapping, tools/remap-paths.sh: required by
//!   build-android.sh and build-ios.sh, only validated here) and, recommended, `OBFSTR_SEED`. An iOS-only project still
//!   needs a release and a QA digest for the host `cargo test --features build-release / build-qa` (a plain host build
//!   is Android-shaped, see above): any digest of its own, since it never builds an APK;
//! - the server Ed25519 public keys and their kids (`config/server-keys.<type>.conf`, or `DOODLEART_SERVER_KEYS_FILE`).
//!   The handshake transcript and the AAD carry no app id, so two projects that embed the same key accept each other's
//!   backend: one key pair per project and environment, and a kid is never reused by another project. A key file names
//!   its project and build type (`project = <PROJECT_ID>`, `build_type = debug|qa|release`): when present they must
//!   match the build, and a build with `DOODLEART_PROJECT_CONF` requires both, so another project that forgets
//!   `DOODLEART_SERVER_KEYS_FILE` (DoodleArt's committed keys) or `DOODLEART_PROJECT_CONF` (DoodleArt's project) with a tagged key
//!   file stops instead of embedding DoodleArt's values. A key file without the `project` tag built with the default
//!   project config is taken as DoodleArt's only when every key in it is in DoodleArt's committed
//!   `config/server-keys.<type>.conf`: otherwise every build stops;
//! - server side, outside this crate but just as per project: the Ed25519 private keys, `DEVICE_HMAC_PEPPER`, and the
//!   package name, signing-cert digest and App Attest app id the backend checks.
//!
//! `config/debug-certs.conf` is per machine (debug keystores), not per project. Not per project at all: the protocol
//! ids (`doodle/v1/*`, `DAPI1`, `DAAS1`, `CNHW1`, `application/vnd.doodle.sealed`: server/docs/app-security.md) are
//! protocol names, and so are the C ABI names (`doodleart_*`, doodleart_core.h, DoodleArtCore) and the `DOODLEART_*`
//! variables.
//!
//! Still fixed for DoodleArt (later work, needed before another project builds from this crate):
//! - the JNI class `com/cem/doodleart/security/NativeCore` (src/jni.rs) and the library name `doodleart_core` (Cargo.toml);
//! - tools/check-so.sh: the class path in SENSITIVE and the file name libdoodleart_core.so;
//! - the tests: src/test_support.rs and the interop / C ABI tests need server/ of this monorepo (the vector files and
//!   the Go interop peer, `go` on the PATH; they panic without it); tests/dist/test-dist.sh takes the project config
//!   (`DOODLEART_PROJECT_CONF`) and the key configs of both outputs (`DOODLEART_SERVER_KEYS_FILE`,
//!   `DOODLEART_DEBUG_SERVER_KEYS_FILE`), but its fake registry layout is DoodleArt's;
//! - `config/debug-certs.conf` has no override variable;
//! - tools/check-macho.sh refuses the debug keys of `config/server-keys.debug.conf` in a release library: another
//!   project relies on the `build_type` tag of its key files instead;
//! - tools/derive-debug-server-key.sh writes DoodleArt's committed `config/server-keys.debug.conf` from server/.env only:
//!   another project writes and tags its debug key file itself;
//! - no CI job builds or tests this crate yet (theme-x had core:check / core:publish).
//!
//! `PROJECT_ID` is only reported by the C ABI init reply and the iOS manifest: never on the wire, not in the JNI
//! replies. `DOODLEART_PROJECT_CONF` (a path; a relative one is relative to this crate) replaces `config/project.conf` for
//! debug and QA builds; a release build also needs `DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1`, so a variable left over in a
//! shell or a CI job cannot swap the certificate allowlist of a production library. The obfstr crate reads
//! `OBFSTR_SEED` from the environment when it compiles, which a build script cannot change: build-android.sh (and
//! build-ios.sh) export the configured value, and this script checks that the environment agrees with the project
//! config (an error for release builds, a warning otherwise).
//!
//! `main` only prints and writes what [`configure`] decides from the environment; the unit tests call [`configure`]
//! with a fake environment (src/lib.rs compiles this file into them).

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const KEYS_ENV: &str = "DOODLEART_SERVER_KEYS_FILE";
const PROJECT_CONF_ENV: &str = "DOODLEART_PROJECT_CONF";
const PROJECT_CONF_RELEASE_ENV: &str = "DOODLEART_PROJECT_CONF_ALLOW_RELEASE";
const OBFSTR_SEED_ENV: &str = "OBFSTR_SEED";
const APPLE_LIB_ENV: &str = "DOODLEART_APPLE_LIB";

fn main() {
    for name in [KEYS_ENV, PROJECT_CONF_ENV, PROJECT_CONF_RELEASE_ENV, OBFSTR_SEED_ENV, APPLE_LIB_ENV] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=config");
    println!("cargo:rustc-check-cfg=cfg(doodleart_build_type, values(\"debug\", \"qa\", \"release\"))");
    println!("cargo:rustc-check-cfg=cfg(doodleart_apple_lib)");
    println!("cargo:rustc-check-cfg=cfg(doodleart_simulator_target)");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let plan = configure(&|name: &str| env::var_os(name), &manifest_dir).unwrap_or_else(|error| fail(&error));
    for path in &plan.read {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    for cfg in &plan.cfgs {
        println!("cargo:rustc-cfg={cfg}");
    }
    for warning in &plan.warnings {
        println!("cargo:warning=doodleart-core build config: {warning}");
    }
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("build_config.rs");
    fs::write(&out_path, &plan.build_config).expect("write build_config.rs");
}

/// What the build script decides: the generated `build_config.rs`, the cfgs, the files it read, the warnings.
#[derive(Debug)]
struct Plan {
    build_config: String,
    cfgs: Vec<String>,
    read: Vec<PathBuf>,
    warnings: Vec<String>,
}

/// The whole decision, from the environment cargo gives a build script (`env`) and the crate directory. Reads the
/// config files; never prints.
fn configure(env: &dyn Fn(&str) -> Option<OsString>, manifest_dir: &Path) -> Result<Plan, String> {
    let text = |name: &str| env(name).map(|value| value.to_string_lossy().into_owned()).unwrap_or_default();
    let build_type = select_build_type(env)?;
    let target = text("TARGET");
    let apple_lib = is_apple_library(
        &text("CARGO_CFG_TARGET_VENDOR"),
        &text("CARGO_CFG_TARGET_OS"),
        &target,
        env(APPLE_LIB_ENV).as_deref(),
    )?;
    if apple_lib && build_type == "qa" {
        return Err(format!(
            "build-qa is not available for the Apple library {target} (no QA build for iOS, theme-x spec 2026-11-05 Q-11): use \
             --features build-debug or build-release"
        ));
    }
    let mut cfgs = vec![format!("doodleart_build_type=\"{build_type}\"")];
    if apple_lib {
        cfgs.push("doodleart_apple_lib".to_owned());
    }
    if is_simulator_triple(&target) {
        cfgs.push("doodleart_simulator_target".to_owned());
    }

    let mut read = Vec::new();
    let project_override = env(PROJECT_CONF_ENV).filter(|path| !path.is_empty());
    let project_path = project_conf_path(
        manifest_dir,
        project_override.as_deref(),
        env(PROJECT_CONF_RELEASE_ENV).as_deref(),
        build_type,
    )?;
    read.push(project_path.clone());
    let project_text = fs::read_to_string(&project_path)
        .map_err(|error| format!("cannot read the project config {}: {error}", project_path.display()))?;
    let in_project = |error: String| format!("{}: {error}", project_path.display());
    let project = parse_project_conf(&project_text).map_err(in_project)?;

    let keys_path = match env(KEYS_ENV) {
        Some(path) if !path.is_empty() => manifest_dir.join(path),
        _ => manifest_dir.join(format!("config/server-keys.{build_type}.conf")),
    };
    read.push(keys_path.clone());
    let keys_text = fs::read_to_string(&keys_path)
        .map_err(|error| format!("cannot read server key config {}: {error}", keys_path.display()))?;
    let in_keys = |error: String| format!("{}: {error}", keys_path.display());
    let key_file = parse_server_keys(&keys_text, build_type).map_err(in_keys)?;
    check_key_file_tags(&key_file, &project.project_id, build_type, project_override.is_some()).map_err(in_keys)?;
    let mut warnings = Vec::new();
    // A key file without the project tag, with the default project config: DoodleArt's only if DoodleArt committed its keys.
    let committed_keys_path = manifest_dir.join(format!("config/server-keys.{build_type}.conf"));
    if project_override.is_none() && key_file.project.is_none() && keys_path != committed_keys_path {
        read.push(committed_keys_path.clone());
        let committed = fs::read_to_string(&committed_keys_path)
            .ok()
            .and_then(|text| parse_server_keys(&text, build_type).ok())
            .map(|file| file.keys)
            .unwrap_or_default();
        if let Some(warning) =
            check_untagged_keys(&key_file, &committed, &project.project_id, build_type, apple_lib).map_err(in_keys)?
        {
            warnings.push(warning);
        }
    }

    let debug_certs = if build_type == "debug" && !apple_lib {
        let path = manifest_dir.join("config/debug-certs.conf");
        read.push(path.clone());
        let text = fs::read_to_string(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        parse_cert_list(&text).map_err(|error| format!("{}: {error}", path.display()))?
    } else {
        Vec::new()
    };

    let allowlists = apk_cert_allowlists(&project, build_type, apple_lib).map_err(in_project)?;
    if let Some(warning) =
        check_obfstr_seed(project.obfstr_seed.as_deref(), env(OBFSTR_SEED_ENV).as_deref(), build_type)?
    {
        warnings.push(warning);
    }

    let build_config = render_build_config(build_type, &key_file.keys, &debug_certs, &project.project_id, &allowlists);
    Ok(Plan { build_config, cfgs, read, warnings })
}

/// The generated `build_config.rs`. The first three items are the original ones, unchanged; the project items follow.
fn render_build_config(
    build_type: &str,
    keys: &[(String, [u8; 32])],
    debug_certs: &[[u8; 32]],
    project_id: &str,
    allowlists: &ApkAllowlists,
) -> String {
    let mut out = String::new();
    writeln!(out, "// @generated by build.rs: do not edit.").unwrap();
    writeln!(out, "pub const BUILD_TYPE: &str = {build_type:?};").unwrap();
    writeln!(out, "pub const SERVER_KEYS: &[(&str, [u8; 32])] = &[").unwrap();
    for (kid, key) in keys {
        writeln!(out, "    ({kid:?}, {key:?}),").unwrap();
    }
    writeln!(out, "];").unwrap();
    write_digests(&mut out, "DEBUG_CERT_SHA256", debug_certs);
    writeln!(out, "pub const PROJECT_ID: &str = {project_id:?};").unwrap();
    write_digests(&mut out, "RELEASE_APK_CERT_SHA256", allowlists.release);
    write_digests(&mut out, "QA_APK_CERT_SHA256", allowlists.qa);
    out
}

fn write_digests(out: &mut String, name: &str, digests: &[[u8; 32]]) {
    writeln!(out, "pub const {name}: &[[u8; 32]] = &[").unwrap();
    for digest in digests {
        writeln!(out, "    {digest:?},").unwrap();
    }
    writeln!(out, "];").unwrap();
}

fn select_build_type(env: &dyn Fn(&str) -> Option<OsString>) -> Result<&'static str, String> {
    let selected: Vec<&'static str> = [
        ("debug", "CARGO_FEATURE_BUILD_DEBUG"),
        ("qa", "CARGO_FEATURE_BUILD_QA"),
        ("release", "CARGO_FEATURE_BUILD_RELEASE"),
    ]
    .into_iter()
    .filter(|(_, var)| env(var).is_some())
    .map(|(name, _)| name)
    .collect();

    match selected.as_slice() {
        [one] => Ok(one),
        [] => {
            Err("no build type selected: enable exactly one of the features build-debug, build-qa, build-release"
                .into())
        }
        _ => Err(format!(
            "several build types selected ({}): use --no-default-features --features build-<type>",
            selected.join(", ")
        )),
    }
}

/// Whether this build is an Apple library (module documentation): every Apple target except macOS, and macOS with
/// `DOODLEART_APPLE_LIB=1`. From the target cfg cargo hands the build script.
fn is_apple_library(vendor: &str, os: &str, target: &str, apple_lib: Option<&OsStr>) -> Result<bool, String> {
    let requested = match apple_lib.filter(|value| !value.is_empty()) {
        None => false,
        Some(value) if value == OsStr::new("1") => true,
        Some(_) => return Err(format!("{APPLE_LIB_ENV} must be 1 or unset")),
    };
    if vendor != "apple" {
        return if requested {
            Err(format!("{APPLE_LIB_ENV}=1 is for Apple targets only, not {target}: unset it"))
        } else {
            Ok(false)
        };
    }
    Ok(os != "macos" || requested)
}

/// A simulator target, from the triple alone (independent of the cfgs rustc derives from it).
fn is_simulator_triple(target: &str) -> bool {
    target.ends_with("-sim") || matches!(target, "x86_64-apple-ios" | "i386-apple-ios")
}

/// A server key config: the keys (current first, then next if any) and the optional tags naming what it is for.
#[derive(Debug, PartialEq, Eq)]
struct KeyFile {
    keys: Vec<(String, [u8; 32])>,
    project: Option<String>,
    build_type: Option<String>,
}

/// Parses `key = value` lines: `current.kid`, `current.public_key`, `next.kid`, `next.public_key`, and the tags
/// `project` and `build_type`. Other keys are ignored.
fn parse_server_keys(text: &str, build_type: &str) -> Result<KeyFile, String> {
    let mut fields = std::collections::BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected `key = value`", index + 1));
        };
        fields.insert(key.trim().to_owned(), value.trim().to_owned());
    }

    let mut keys = Vec::new();
    for slot in ["current", "next"] {
        let kid = fields.get(&format!("{slot}.kid")).cloned().unwrap_or_default();
        let public_key = fields.get(&format!("{slot}.public_key")).cloned().unwrap_or_default();

        if slot == "next" && kid.is_empty() && public_key.is_empty() {
            continue;
        }
        if public_key.starts_with("REPLACE") || public_key.is_empty() {
            return Err(format!(
                "no real Ed25519 public key for `{slot}` (build type `{build_type}`). The owner must put the server's \
                 raw 32-byte public key (64 hex chars) and its kid there, or point {KEYS_ENV} at a file that has \
                 them. See doodleart-core/README.md (server keys)."
            ));
        }
        if !is_valid_kid(&kid) {
            return Err(format!("`{slot}.kid` must match [A-Za-z0-9._-]{{1,32}}"));
        }
        let Some(bytes) = decode_hex32(&public_key) else {
            return Err(format!("`{slot}.public_key` must be 64 hex characters"));
        };
        if keys.iter().any(|(existing, _): &(String, [u8; 32])| *existing == kid) {
            return Err(format!("duplicate kid `{kid}`"));
        }
        keys.push((kid, bytes));
    }
    let tag = |name: &str| fields.get(name).filter(|value| !value.is_empty()).cloned();
    Ok(KeyFile { keys, project: tag("project"), build_type: tag("build_type") })
}

/// The tags of a key file against the build: each one present must match (`project` = the project config's
/// `PROJECT_ID`, `build_type` = the build type), and a build with another project's config (`DOODLEART_PROJECT_CONF`)
/// needs both (module documentation).
fn check_key_file_tags(
    keys: &KeyFile,
    project_id: &str,
    build_type: &str,
    project_overridden: bool,
) -> Result<(), String> {
    if let Some(project) = &keys.project {
        if project != project_id {
            return Err(format!(
                "the keys are for project `{project}`, the project config is `{project_id}`: point {KEYS_ENV} and \
                 {PROJECT_CONF_ENV} at the files of the same project"
            ));
        }
    }
    if let Some(tagged) = &keys.build_type {
        if tagged != build_type {
            return Err(format!(
                "the keys are for the `{tagged}` build type, not `{build_type}` (a {build_type} library never \
                 embeds the keys of another backend)"
            ));
        }
    }
    if project_overridden && (keys.project.is_none() || keys.build_type.is_none()) {
        return Err(format!(
            "{PROJECT_CONF_ENV} selects the project `{project_id}`: its key file must say `project = {project_id}` and \
             `build_type = {build_type}` (set {KEYS_ENV} to that project's key file)"
        ));
    }
    Ok(())
}

/// A key file without the `project` tag, used with the default project config: its keys must all be in DoodleArt's
/// committed key config of the build type (`committed`), else the library would carry DoodleArt's project id next to
/// another backend's keys. DoodleArt has no untagged legacy key file (theme-x had one for its Android CI), so this
/// stops every build, Apple and Android alike.
fn check_untagged_keys(
    keys: &KeyFile,
    committed: &[(String, [u8; 32])],
    project_id: &str,
    build_type: &str,
    _apple_lib: bool,
) -> Result<Option<String>, String> {
    let foreign: Vec<&str> =
        keys.keys.iter().filter(|key| !committed.contains(key)).map(|(kid, _)| kid.as_str()).collect();
    if foreign.is_empty() {
        return Ok(None);
    }
    Err(format!(
        "the key file has no `project` tag and holds keys (kid {}) that config/server-keys.{build_type}.conf does not \
         have: with the default project config the library would embed the project id `{project_id}` next to another \
         backend's keys. Tag the key file (`project = <PROJECT_ID>`, `build_type = {build_type}`); another project's \
         keys also need {PROJECT_CONF_ENV}",
        foreign.join(", ")
    ))
}

/// `config/debug-certs.conf`: one SHA-256 digest per line, hex with or without `:` separators.
fn parse_cert_list(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut digests = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let digest =
            parse_cert_digest(line).ok_or_else(|| format!("line {}: expected a SHA-256 hex digest", index + 1))?;
        if digests.contains(&digest) {
            return Err(format!("line {}: duplicate digest", index + 1));
        }
        digests.push(digest);
    }
    if digests.is_empty() {
        return Err("lists no debug certificate digest".to_owned());
    }
    Ok(digests)
}

/// The project config (`config/project.conf` or `DOODLEART_PROJECT_CONF`), see the module documentation.
#[derive(Debug, PartialEq, Eq)]
struct ProjectConf {
    project_id: String,
    obfstr_seed: Option<String>,
    /// Read by build-android.sh / build-ios.sh (tools/remap-paths.sh), which require it; validated here only.
    remap_salt: Option<String>,
    release_certs: Vec<[u8; 32]>,
    qa_certs: Vec<[u8; 32]>,
}

/// `KEY = value` lines, `#` starts a comment. `PROJECT_ID` once (required), `OBFSTR_SEED` and `REMAP_SALT` at most
/// once, the two allowlist keys once per digest. Unknown keys and duplicates stop the build; errors never quote a seed
/// or a salt.
fn parse_project_conf(text: &str) -> Result<ProjectConf, String> {
    let mut project_id: Option<String> = None;
    let mut obfstr_seed: Option<String> = None;
    let mut remap_salt: Option<String> = None;
    let (mut release_certs, mut qa_certs) = (Vec::new(), Vec::new());
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_no}: expected `KEY = value`"));
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "PROJECT_ID" => {
                if !is_valid_project_id(value) {
                    return Err(format!("line {line_no}: `PROJECT_ID` must match [a-z0-9-]{{1,32}}"));
                }
                if project_id.replace(value.to_owned()).is_some() {
                    return Err(format!("line {line_no}: `PROJECT_ID` is set twice"));
                }
            }
            "OBFSTR_SEED" => {
                if !is_valid_obfstr_seed(value) {
                    return Err(format!(
                        "line {line_no}: `OBFSTR_SEED` must match [A-Za-z0-9_-]{{16,64}} (leave the key out for \
                         obfstr's default)"
                    ));
                }
                if obfstr_seed.replace(value.to_owned()).is_some() {
                    return Err(format!("line {line_no}: `OBFSTR_SEED` is set twice"));
                }
            }
            "REMAP_SALT" => {
                if !is_valid_remap_salt(value) {
                    return Err(format!("line {line_no}: `REMAP_SALT` must match [0-9a-f]{{32,64}}"));
                }
                if remap_salt.replace(value.to_owned()).is_some() {
                    return Err(format!("line {line_no}: `REMAP_SALT` is set twice"));
                }
            }
            "RELEASE_APK_CERT_SHA256" | "QA_APK_CERT_SHA256" => {
                let list = if key == "RELEASE_APK_CERT_SHA256" { &mut release_certs } else { &mut qa_certs };
                let digest = parse_cert_digest(value)
                    .ok_or_else(|| format!("line {line_no}: `{key}` expects a SHA-256 hex digest"))?;
                if list.contains(&digest) {
                    return Err(format!("line {line_no}: duplicate `{key}` digest"));
                }
                list.push(digest);
            }
            _ => {
                return Err(format!(
                    "line {line_no}: unknown key `{key}` (expected PROJECT_ID, OBFSTR_SEED, REMAP_SALT, \
                     RELEASE_APK_CERT_SHA256 or QA_APK_CERT_SHA256)"
                ))
            }
        }
    }
    let project_id = project_id.ok_or_else(|| "no `PROJECT_ID`".to_owned())?;
    Ok(ProjectConf { project_id, obfstr_seed, remap_salt, release_certs, qa_certs })
}

/// `config/project.conf`, or the file `DOODLEART_PROJECT_CONF` names (relative to the crate). A release build only takes
/// the override with `DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1`.
fn project_conf_path(
    manifest_dir: &Path,
    override_path: Option<&OsStr>,
    allow_release: Option<&OsStr>,
    build_type: &str,
) -> Result<PathBuf, String> {
    let Some(path) = override_path.filter(|path| !path.is_empty()) else {
        return Ok(manifest_dir.join("config/project.conf"));
    };
    if build_type == "release" && allow_release != Some(OsStr::new("1")) {
        return Err(format!(
            "{PROJECT_CONF_ENV} is set for a release build, which takes its project id and APK certificate allowlist \
             from config/project.conf. Unset it, or set {PROJECT_CONF_RELEASE_ENV}=1 when this release belongs to \
             the project of that file"
        ));
    }
    Ok(manifest_dir.join(path))
}

/// The APK allowlists build.rs embeds as `RELEASE_APK_CERT_SHA256` and `QA_APK_CERT_SHA256`.
#[derive(Debug, PartialEq, Eq)]
struct ApkAllowlists<'a> {
    release: &'a [[u8; 32]],
    qa: &'a [[u8; 32]],
}

/// The release and QA allowlists to embed. Apple libraries have no APK: both empty, nothing required (an iOS-only
/// project needs no digest). Elsewhere the allowlist of the selected release or QA build type must list at least one
/// certificate.
fn apk_cert_allowlists<'a>(
    project: &'a ProjectConf,
    build_type: &str,
    apple_lib: bool,
) -> Result<ApkAllowlists<'a>, String> {
    if apple_lib {
        return Ok(ApkAllowlists { release: &[], qa: &[] });
    }
    let required = match build_type {
        "release" => Some((&project.release_certs, "RELEASE_APK_CERT_SHA256")),
        "qa" => Some((&project.qa_certs, "QA_APK_CERT_SHA256")),
        _ => None,
    };
    if let Some((certs, key)) = required {
        if certs.is_empty() {
            return Err(format!(
                "no `{key}`: a {build_type} build needs the SHA-256 of the certificate that signs its APK (every \
                 install would report apk_resigned). A host build for tests needs one too: an iOS-only project, which \
                 never builds an APK, gives any digest of its own"
            ));
        }
    }
    Ok(ApkAllowlists { release: &project.release_certs, qa: &project.qa_certs })
}

/// The obfstr crate takes its seed from `OBFSTR_SEED` in the environment of the compiler, so the environment must
/// carry exactly the configured seed (unset when the config has none; an empty value is a different seed). Release:
/// an error; other build types: the warning to print. Messages never quote a seed.
fn check_obfstr_seed(
    configured: Option<&str>,
    environment: Option<&OsStr>,
    build_type: &str,
) -> Result<Option<String>, String> {
    let problem = match (configured, environment) {
        (None, None) => return Ok(None),
        (Some(seed), Some(value)) if value == OsStr::new(seed) => return Ok(None),
        (None, Some(_)) => "is set in the environment but the project config leaves it unset",
        (Some(_), None) => "is set in the project config but not in the environment",
        (Some(_), Some(_)) => "in the environment differs from the project config",
    };
    let message = format!(
        "{OBFSTR_SEED_ENV} {problem}: obfstr reads it from the environment when it compiles, so this build would not \
         use the project's obfuscation seed. Build with build-android.sh / build-ios.sh, which export the configured \
         value"
    );
    if build_type == "release" {
        Err(message)
    } else {
        Ok(Some(message))
    }
}

fn is_valid_project_id(id: &str) -> bool {
    (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_valid_obfstr_seed(seed: &str) -> bool {
    (16..=64).contains(&seed.len()) && seed.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_valid_remap_salt(salt: &str) -> bool {
    (32..=64).contains(&salt.len()) && salt.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_valid_kid(kid: &str) -> bool {
    !kid.is_empty() && kid.len() <= 32 && kid.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// A certificate SHA-256 as 64 hex characters, `:` separators ignored (keytool prints `C2:4A:…`).
fn parse_cert_digest(text: &str) -> Option<[u8; 32]> {
    let compact: String = text.chars().filter(|c| *c != ':').collect();
    decode_hex32(&compact)
}

fn decode_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out[index] = (high * 16 + low) as u8;
    }
    Some(out)
}

fn fail(message: &str) -> ! {
    // A panic in build.rs prints the message and stops the build; keep it on one readable line.
    panic!("doodleart-core build config: {message}");
}

/// Compiled into the crate's unit tests through `build_script` in src/lib.rs (Cargo never tests a build script), so
/// these run with `cargo test`. Only the pure functions above are called.
#[cfg(test)]
mod tests {
    use super::*;

    /// The former `ALLOWED_CERT_SHA256` constants of src/apk_identity.rs (release: app signing key, QA: upload key).
    // The placeholders of config/project.conf (DoodleArt has no Android app yet): SHA-256 of a fixed sentence.
    const RELEASE_HEX: &str = "598359c6c743530f324e80207c64d68ee95e169aeddb38e85ead7dc3af114655";
    const QA_HEX: &str = "9a66a46a0247df31fbcb43150d7fbb68ae94e0e5001bdaff55de7569de98e815";
    const OTHER_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const SEED: &str = "0123456789abcdefXYZ_-";
    const SALT: &str = "00112233445566778899aabbccddeeff";

    /// Independent of `decode_hex32`, the function under test.
    fn digest(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..64).step_by(2).map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap()).collect();
        bytes.try_into().unwrap()
    }

    fn colon_upper(hex: &str) -> String {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap().to_uppercase())
            .collect::<Vec<_>>()
            .join(":")
    }

    fn parse(text: &str) -> ProjectConf {
        parse_project_conf(text).unwrap_or_else(|error| panic!("{error}\n{text}"))
    }

    fn parse_error(text: &str) -> String {
        match parse_project_conf(text) {
            Ok(conf) => panic!("accepted {conf:?}\n{text}"),
            Err(error) => error,
        }
    }

    fn conf(release: &[&str], qa: &[&str]) -> ProjectConf {
        ProjectConf {
            project_id: "p".to_owned(),
            obfstr_seed: None,
            remap_salt: None,
            release_certs: release.iter().map(|hex| digest(hex)).collect(),
            qa_certs: qa.iter().map(|hex| digest(hex)).collect(),
        }
    }

    #[test]
    fn committed_project_conf_is_the_doodleart_config() {
        let committed = parse(include_str!("config/project.conf"));
        // The salt of the source path remapping is DoodleArt's own random value (not repeated here); parse() checked it.
        assert!(committed.remap_salt.as_deref().is_some_and(is_valid_remap_salt), "no REMAP_SALT");
        assert!(committed.obfstr_seed.as_deref().is_some_and(is_valid_obfstr_seed), "no OBFSTR_SEED");
        let expected = ProjectConf {
            project_id: "doodleart".to_owned(),
            obfstr_seed: committed.obfstr_seed.clone(),
            remap_salt: committed.remap_salt.clone(),
            release_certs: vec![digest(RELEASE_HEX)],
            qa_certs: vec![digest(QA_HEX)],
        };
        assert_eq!(committed, expected);
    }

    #[test]
    fn project_conf_syntax() {
        let text = format!(
            "# header\n\n  PROJECT_ID=my-app-2  # inline comment\nOBFSTR_SEED = {SEED}\nREMAP_SALT={SALT}\n\
             RELEASE_APK_CERT_SHA256 = {RELEASE_HEX}\n\tRELEASE_APK_CERT_SHA256\t=\t{}  # second release cert\n\
             QA_APK_CERT_SHA256 = {RELEASE_HEX}\n",
            colon_upper(QA_HEX)
        );
        let expected = ProjectConf {
            project_id: "my-app-2".to_owned(),
            obfstr_seed: Some(SEED.to_owned()),
            remap_salt: Some(SALT.to_owned()),
            release_certs: vec![digest(RELEASE_HEX), digest(QA_HEX)],
            // The same certificate may be allowed for both build types.
            qa_certs: vec![digest(RELEASE_HEX)],
        };
        assert_eq!(parse(&text), expected);
        // Only PROJECT_ID is required.
        assert_eq!(parse("PROJECT_ID = x"), ProjectConf { project_id: "x".to_owned(), ..conf(&[], &[]) });
    }

    #[test]
    fn project_id_rule() {
        let max = "a".repeat(32);
        for id in ["a", "doodleart", "my-app-2", "0", "-", max.as_str()] {
            assert_eq!(parse(&format!("PROJECT_ID = {id}")).project_id, id);
        }
        let too_long = "a".repeat(33);
        for id in ["", "DoodleArt", "theme_x", "theme x", "theme.x", "thème", too_long.as_str()] {
            let error = parse_error(&format!("PROJECT_ID = {id}"));
            assert!(error.contains("line 1: `PROJECT_ID` must match"), "{id:?}: {error}");
        }
        assert_eq!(parse_error("# none\nOBFSTR_SEED = 0123456789abcdef"), "no `PROJECT_ID`");
        assert_eq!(parse_error("PROJECT_ID = a\n\nPROJECT_ID = a"), "line 3: `PROJECT_ID` is set twice");
    }

    #[test]
    fn obfstr_seed_rule() {
        let (min, max) = ("A".repeat(16), "z".repeat(64));
        for seed in [min.as_str(), max.as_str(), SEED, "a-b_c-d_e-f_g-h_"] {
            let conf = parse(&format!("PROJECT_ID = p\nOBFSTR_SEED = {seed}"));
            assert_eq!(conf.obfstr_seed.as_deref(), Some(seed));
        }
        let (short, long) = ("A".repeat(15), "z".repeat(65));
        for seed in ["", short.as_str(), long.as_str(), "0123456789 abcdef", "0123456789abcdef=x", "0123456789abcdéf"]
        {
            let error = parse_error(&format!("PROJECT_ID = p\nOBFSTR_SEED = {seed}"));
            assert!(error.starts_with("line 2: `OBFSTR_SEED` must match"), "{seed:?}: {error}");
            assert!(seed.is_empty() || !error.contains(seed), "the error quotes the seed: {error}");
        }
        let error = parse_error(&format!("PROJECT_ID = p\nOBFSTR_SEED = {SEED}\nOBFSTR_SEED = {SEED}"));
        assert_eq!(error, "line 3: `OBFSTR_SEED` is set twice");
    }

    #[test]
    fn remap_salt_rule() {
        let (min, max) = ("0".repeat(32), "f".repeat(64));
        for salt in [min.as_str(), max.as_str(), SALT, "0123456789abcdef0123456789abcdef01"] {
            let conf = parse(&format!("PROJECT_ID = p\nREMAP_SALT = {salt}"));
            assert_eq!(conf.remap_salt.as_deref(), Some(salt));
        }
        assert_eq!(parse("PROJECT_ID = p").remap_salt, None);
        let (short, long) = ("a".repeat(31), "a".repeat(65));
        let upper = SALT.to_uppercase();
        let not_hex = SALT.replace('0', "g");
        for salt in
            ["", short.as_str(), long.as_str(), upper.as_str(), not_hex.as_str(), "0011 2233445566778899aabbccddeeff"]
        {
            let error = parse_error(&format!("PROJECT_ID = p\nREMAP_SALT = {salt}"));
            assert_eq!(error, "line 2: `REMAP_SALT` must match [0-9a-f]{32,64}", "{salt:?}");
        }
        let error = parse_error(&format!("PROJECT_ID = p\nREMAP_SALT = {SALT}\nREMAP_SALT = {SALT}"));
        assert_eq!(error, "line 3: `REMAP_SALT` is set twice");
        assert!(!error.contains(SALT));
    }

    #[test]
    fn cert_digest_rules() {
        let (long, not_hex) = (format!("{RELEASE_HEX}00"), RELEASE_HEX.replace('c', "g"));
        let bad: [&str; 5] = [&RELEASE_HEX[..62], &long, &not_hex, "", "c2:4a"];
        for key in ["RELEASE_APK_CERT_SHA256", "QA_APK_CERT_SHA256"] {
            for value in bad {
                let error = parse_error(&format!("PROJECT_ID = p\n{key} = {value}"));
                assert_eq!(error, format!("line 2: `{key}` expects a SHA-256 hex digest"), "{value:?}");
            }
            // Same certificate, other spelling: still a duplicate.
            let error =
                parse_error(&format!("PROJECT_ID = p\n{key} = {RELEASE_HEX}\n{key} = {}", colon_upper(RELEASE_HEX)));
            assert_eq!(error, format!("line 3: duplicate `{key}` digest"));
        }
        let both = parse(&format!(
            "PROJECT_ID = p\nRELEASE_APK_CERT_SHA256 = {OTHER_HEX}\nRELEASE_APK_CERT_SHA256 = {}",
            colon_upper(RELEASE_HEX)
        ));
        assert_eq!(both.release_certs, vec![digest(OTHER_HEX), digest(RELEASE_HEX)]);
        assert!(both.qa_certs.is_empty());
    }

    #[test]
    fn unknown_keys_and_malformed_lines_stop_the_build() {
        for line in ["PROJECTID = p", "project_id = p", "SERVER_KEY = x", "DEBUG_APK_CERT_SHA256 = 00"] {
            let error = parse_error(&format!("PROJECT_ID = p\n{line}"));
            assert!(error.starts_with("line 2: unknown key `"), "{line}: {error}");
        }
        assert_eq!(parse_error("PROJECT_ID doodleart"), "line 1: expected `KEY = value`");
    }

    #[test]
    fn release_and_qa_builds_need_their_allowlist() {
        let release_only = conf(&[RELEASE_HEX], &[]);
        let qa_only = conf(&[], &[QA_HEX]);
        let both = conf(&[RELEASE_HEX], &[QA_HEX]);
        let none = conf(&[], &[]);

        for (project, build_type) in [(&release_only, "release"), (&qa_only, "qa"), (&both, "release"), (&both, "qa")]
            .into_iter()
            .chain([(&none, "debug"), (&both, "debug"), (&release_only, "debug")])
        {
            let embedded = apk_cert_allowlists(project, build_type, false).unwrap();
            let expected = ApkAllowlists { release: &project.release_certs, qa: &project.qa_certs };
            assert_eq!(embedded, expected, "{build_type}");
        }
        for (project, build_type, key) in [
            (&qa_only, "release", "RELEASE_APK_CERT_SHA256"),
            (&none, "release", "RELEASE_APK_CERT_SHA256"),
            (&release_only, "qa", "QA_APK_CERT_SHA256"),
            (&none, "qa", "QA_APK_CERT_SHA256"),
        ] {
            let error = apk_cert_allowlists(project, build_type, false).unwrap_err();
            assert!(error.starts_with(&format!("no `{key}`: a {build_type} build")), "{error}");
        }
        // Apple libraries have no APK: nothing embedded, nothing required (build-qa never gets this far there).
        for (project, build_type) in [(&both, "release"), (&both, "debug"), (&none, "release"), (&none, "debug")] {
            let embedded = apk_cert_allowlists(project, build_type, true).unwrap();
            assert_eq!(embedded, ApkAllowlists { release: &[], qa: &[] }, "{build_type}");
        }
    }

    #[test]
    fn project_conf_override_policy() {
        let dir = Path::new("/crate");
        let os = OsStr::new;
        let default = PathBuf::from("/crate/config/project.conf");
        for build_type in ["debug", "qa", "release"] {
            assert_eq!(project_conf_path(dir, None, None, build_type).unwrap(), default);
            assert_eq!(project_conf_path(dir, Some(os("")), None, build_type).unwrap(), default);
            assert_eq!(project_conf_path(dir, None, Some(os("1")), build_type).unwrap(), default);
        }
        for build_type in ["debug", "qa"] {
            let relative = project_conf_path(dir, Some(os("../other/project.conf")), None, build_type).unwrap();
            assert_eq!(relative, PathBuf::from("/crate/../other/project.conf"));
            let absolute = project_conf_path(dir, Some(os("/etc/b.conf")), None, build_type).unwrap();
            assert_eq!(absolute, PathBuf::from("/etc/b.conf"));
        }
        for allow in [None, Some(os("")), Some(os("0")), Some(os("true")), Some(os("1 "))] {
            let error = project_conf_path(dir, Some(os("/etc/b.conf")), allow, "release").unwrap_err();
            assert!(error.contains("DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1"), "{allow:?}: {error}");
        }
        let allowed = project_conf_path(dir, Some(os("/etc/b.conf")), Some(os("1")), "release").unwrap();
        assert_eq!(allowed, PathBuf::from("/etc/b.conf"));
    }

    #[test]
    fn obfstr_seed_must_match_the_environment() {
        let os = OsStr::new;
        for build_type in ["debug", "qa", "release"] {
            assert_eq!(check_obfstr_seed(None, None, build_type), Ok(None));
            assert_eq!(check_obfstr_seed(Some(SEED), Some(os(SEED)), build_type), Ok(None));
        }
        let mismatches = [
            (None, Some(os("0123456789abcdef-env")), "is set in the environment but"),
            (None, Some(os("")), "is set in the environment but"),
            (Some(SEED), None, "is set in the project config but not"),
            (Some(SEED), Some(os("0123456789abcdef-env")), "in the environment differs from"),
            (Some(SEED), Some(os("")), "in the environment differs from"),
        ];
        for (configured, environment, problem) in mismatches {
            let error = check_obfstr_seed(configured, environment, "release").unwrap_err();
            assert!(error.starts_with(&format!("OBFSTR_SEED {problem}")), "{error}");
            assert!(!error.contains(SEED) && !error.contains("-env"), "the message quotes a seed: {error}");
            for build_type in ["debug", "qa"] {
                let warning = check_obfstr_seed(configured, environment, build_type).unwrap();
                assert_eq!(warning, Some(error.clone()), "{build_type}");
            }
        }
    }

    #[test]
    fn debug_cert_list() {
        assert!(!parse_cert_list(include_str!("config/debug-certs.conf")).unwrap().is_empty());
        let text = format!("# c\n{}  # machine a\n\n{OTHER_HEX}\n", colon_upper(RELEASE_HEX));
        assert_eq!(parse_cert_list(&text).unwrap(), vec![digest(RELEASE_HEX), digest(OTHER_HEX)]);
        assert_eq!(
            parse_cert_list(&format!("{OTHER_HEX}\n{}", OTHER_HEX.to_uppercase())),
            Err("line 2: duplicate digest".to_owned())
        );
        assert_eq!(parse_cert_list("# only comments\n\n"), Err("lists no debug certificate digest".to_owned()));
        assert_eq!(
            parse_cert_list(&format!("{OTHER_HEX}\nnot hex")),
            Err("line 2: expected a SHA-256 hex digest".to_owned())
        );
    }

    /// The items Android already had keep their exact text and come first; the project items are appended.
    #[test]
    fn rendered_config_appends_the_project_items() {
        let (key, release, qa, debug) = ([7u8; 32], digest(RELEASE_HEX), digest(QA_HEX), digest(OTHER_HEX));
        let keys = vec![("kid-a".to_owned(), key), ("kid-b".to_owned(), release)];
        let out = render_build_config(
            "release",
            &keys,
            &[debug],
            "doodleart",
            &ApkAllowlists { release: &[release, qa], qa: &[qa] },
        );
        let original = format!(
            "// @generated by build.rs: do not edit.\npub const BUILD_TYPE: &str = \"release\";\n\
             pub const SERVER_KEYS: &[(&str, [u8; 32])] = &[\n    (\"kid-a\", {key:?}),\n    \
             (\"kid-b\", {release:?}),\n];\npub const DEBUG_CERT_SHA256: &[[u8; 32]] = &[\n    {debug:?},\n];\n"
        );
        let project = format!(
            "pub const PROJECT_ID: &str = \"doodleart\";\n\
             pub const RELEASE_APK_CERT_SHA256: &[[u8; 32]] = &[\n    {release:?},\n    {qa:?},\n];\n\
             pub const QA_APK_CERT_SHA256: &[[u8; 32]] = &[\n    {qa:?},\n];\n"
        );
        assert_eq!(out, format!("{original}{project}"));
        let empty = render_build_config("debug", &keys[..1], &[], "p", &ApkAllowlists { release: &[], qa: &[] });
        assert!(empty.ends_with(
            "pub const PROJECT_ID: &str = \"p\";\npub const RELEASE_APK_CERT_SHA256: &[[u8; 32]] = &[\n];\n\
             pub const QA_APK_CERT_SHA256: &[[u8; 32]] = &[\n];\n"
        ));
    }

    // ---- configure(): what main() does with the environment ----------------------------------------------------

    const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
    const KEY_HEX: &str = "8f3f4ad6e2c06e7b0c3c3c3e0bd3a35b3a0a5b5e2a1cfb9f8d7c6b5a49382716";

    /// A fake build-script environment: the target, one build-type feature and the given variables.
    fn fake_env(target: &str, build_type: &str, vars: &[(&str, &str)]) -> std::collections::HashMap<String, OsString> {
        let (vendor, os) = match target {
            "aarch64-linux-android" | "armv7-linux-androideabi" | "x86_64-linux-android" => ("unknown", "android"),
            "x86_64-unknown-linux-gnu" => ("unknown", "linux"),
            "aarch64-apple-darwin" => ("apple", "macos"),
            "aarch64-apple-ios" | "aarch64-apple-ios-sim" | "x86_64-apple-ios" | "aarch64-apple-ios-macabi" => {
                ("apple", "ios")
            }
            other => panic!("no fake cfg for {other}"),
        };
        let mut map: std::collections::HashMap<String, OsString> = [
            ("TARGET", target),
            ("CARGO_CFG_TARGET_VENDOR", vendor),
            ("CARGO_CFG_TARGET_OS", os),
            (&*format!("CARGO_FEATURE_BUILD_{}", build_type.to_uppercase()), "1"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), OsString::from(value)))
        .collect();
        for (name, value) in vars {
            map.insert((*name).to_owned(), OsString::from(value));
        }
        map
    }

    fn run(env: &std::collections::HashMap<String, OsString>) -> Result<Plan, String> {
        configure(&|name: &str| env.get(name).cloned(), Path::new(MANIFEST_DIR))
    }

    fn plan(target: &str, build_type: &str, vars: &[(&str, &str)]) -> Plan {
        run(&fake_env(target, build_type, vars)).unwrap_or_else(|error| panic!("{target} {build_type}: {error}"))
    }

    fn refusal(target: &str, build_type: &str, vars: &[(&str, &str)]) -> String {
        match run(&fake_env(target, build_type, vars)) {
            Ok(plan) => panic!("{target} {build_type} {vars:?}: accepted, cfgs {:?}", plan.cfgs),
            Err(error) => error,
        }
    }

    /// A file of this test in the temp directory (absolute path as a String).
    fn temp_file(name: &str, text: &str) -> String {
        let dir = std::env::temp_dir().join(format!("doodleart-build-rs-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn key_file(project: Option<&str>, build_type: Option<&str>, kid: &str) -> String {
        let mut text = String::new();
        if let Some(project) = project {
            writeln!(text, "project = {project}").unwrap();
        }
        if let Some(build_type) = build_type {
            writeln!(text, "build_type = {build_type}").unwrap();
        }
        writeln!(text, "current.kid = {kid}\ncurrent.public_key = {KEY_HEX}").unwrap();
        text
    }

    /// What a DoodleArt release plan needs on the host: the test release keys (config/server-keys.release.conf is a
    /// placeholder that stops the build) and the committed OBFSTR_SEED (build-ios.sh / build-android.sh export it).
    const RELEASE_TEST_KEYS: &str = "tests/fixtures/server-keys.release-test.conf";

    fn committed_seed() -> String {
        parse(include_str!("config/project.conf")).obfstr_seed.expect("OBFSTR_SEED in config/project.conf")
    }

    fn with_release(vars: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> =
            vars.iter().map(|(name, value)| (*name, (*value).to_owned())).collect();
        if !out.iter().any(|(name, _)| *name == KEYS_ENV) {
            out.push((KEYS_ENV, RELEASE_TEST_KEYS.to_owned()));
        }
        if !out.iter().any(|(name, _)| *name == OBFSTR_SEED_ENV || *name == PROJECT_CONF_ENV) {
            out.push((OBFSTR_SEED_ENV, committed_seed()));
        }
        out
    }

    fn release_plan(target: &str, vars: &[(&'static str, &str)]) -> Plan {
        let vars = with_release(vars);
        let borrowed: Vec<(&str, &str)> = vars.iter().map(|(name, value)| (*name, value.as_str())).collect();
        plan(target, "release", &borrowed)
    }

    fn release_refusal(target: &str, vars: &[(&'static str, &str)]) -> String {
        let vars = with_release(vars);
        let borrowed: Vec<(&str, &str)> = vars.iter().map(|(name, value)| (*name, value.as_str())).collect();
        refusal(target, "release", &borrowed)
    }

    #[test]
    fn the_committed_release_keys_stop_the_build_until_the_owner_sets_them() {
        let seed = committed_seed();
        for target in ["aarch64-linux-android", "aarch64-apple-ios"] {
            let error = refusal(target, "release", &[(OBFSTR_SEED_ENV, seed.as_str())]);
            assert!(error.contains("no real Ed25519 public key for `current`"), "{target}: {error}");
        }
    }

    fn line_of<'a>(config: &'a str, prefix: &str) -> &'a str {
        config.lines().find(|line| line.starts_with(prefix)).unwrap_or_else(|| panic!("no {prefix} in\n{config}"))
    }

    /// Android builds: DoodleArt's committed configs, the APK allowlists, no Apple cfg; debug reads debug-certs.conf.
    #[test]
    fn android_builds_use_the_committed_configs() {
        let release = release_plan("aarch64-linux-android", &[]);
        assert_eq!(release.cfgs, ["doodleart_build_type=\"release\""]);
        assert!(release.warnings.is_empty(), "{:?}", release.warnings);
        let config = &release.build_config;
        assert_eq!(line_of(config, "pub const BUILD_TYPE"), "pub const BUILD_TYPE: &str = \"release\";");
        assert_eq!(line_of(config, "pub const PROJECT_ID"), "pub const PROJECT_ID: &str = \"doodleart\";");
        assert!(config.contains("(\"release-test-a\", [") && config.contains("(\"release-test-b\", ["), "{config}");
        assert!(config.contains(&format!(
            "pub const RELEASE_APK_CERT_SHA256: &[[u8; 32]] = &[\n    {:?},\n];",
            digest(RELEASE_HEX)
        )));
        assert!(config.contains("pub const DEBUG_CERT_SHA256: &[[u8; 32]] = &[\n];"), "{config}");
        let dir = Path::new(MANIFEST_DIR);
        assert_eq!(release.read, [dir.join("config/project.conf"), dir.join(RELEASE_TEST_KEYS)]);

        let debug = plan("armv7-linux-androideabi", "debug", &[]);
        assert_eq!(debug.cfgs, ["doodleart_build_type=\"debug\""]);
        assert!(debug.read.contains(&dir.join("config/debug-certs.conf")));
        assert!(!debug.build_config.contains("pub const DEBUG_CERT_SHA256: &[[u8; 32]] = &[\n];"));
        assert!(debug.build_config.contains("(\"2026-11\", ["));
        // A plain host build (the Kotlin host harness, `cargo test`) is not an Apple library, on Linux or on a Mac.
        for target in ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"] {
            let host = plan(target, "debug", &[]);
            assert_eq!(host.cfgs, ["doodleart_build_type=\"debug\""], "{target}");
            assert!(host.read.contains(&dir.join("config/debug-certs.conf")), "{target}");
        }
    }

    #[test]
    fn exactly_one_build_type() {
        let mut none = fake_env("aarch64-linux-android", "debug", &[]);
        none.remove("CARGO_FEATURE_BUILD_DEBUG");
        assert!(run(&none).unwrap_err().starts_with("no build type selected"));
        let two = fake_env("aarch64-linux-android", "debug", &[("CARGO_FEATURE_BUILD_RELEASE", "1")]);
        assert!(run(&two).unwrap_err().starts_with("several build types selected (debug, release)"));
    }

    /// Every Apple target except macOS is an Apple library; macOS only with DOODLEART_APPLE_LIB=1 (the slice of
    /// build-ios.sh and c-abi-smoke.sh). No debug-certs.conf, no APK allowlist, no QA build there.
    #[test]
    fn apple_libraries() {
        let dir = Path::new(MANIFEST_DIR);
        for (target, vars) in [
            ("aarch64-apple-ios", &[][..]),
            ("aarch64-apple-ios", &[(APPLE_LIB_ENV, "1")][..]),
            ("aarch64-apple-ios-sim", &[][..]),
            ("aarch64-apple-darwin", &[(APPLE_LIB_ENV, "1")][..]),
        ] {
            let debug = plan(target, "debug", vars);
            assert!(debug.cfgs.contains(&"doodleart_apple_lib".to_owned()), "{target}");
            assert!(!debug.read.contains(&dir.join("config/debug-certs.conf")), "{target}");
            assert!(debug.build_config.contains("pub const DEBUG_CERT_SHA256: &[[u8; 32]] = &[\n];"), "{target}");
            let release = release_plan(target, vars);
            assert!(release.cfgs.contains(&"doodleart_apple_lib".to_owned()), "{target}");
            assert!(release.build_config.contains("pub const RELEASE_APK_CERT_SHA256: &[[u8; 32]] = &[\n];"));
            assert!(release.build_config.contains("pub const QA_APK_CERT_SHA256: &[[u8; 32]] = &[\n];"));
            let error = refusal(target, "qa", vars);
            assert!(error.starts_with(&format!("build-qa is not available for the Apple library {target}")), "{error}");
        }
        // An empty value is unset; anything but 1 stops; 1 on a non-Apple target stops.
        assert!(!plan("aarch64-apple-darwin", "debug", &[(APPLE_LIB_ENV, "")])
            .cfgs
            .contains(&"doodleart_apple_lib".into()));
        for value in ["0", "true", "yes", "1 "] {
            assert_eq!(
                refusal("aarch64-apple-darwin", "debug", &[(APPLE_LIB_ENV, value)]),
                "DOODLEART_APPLE_LIB must be 1 or unset"
            );
        }
        for target in ["aarch64-linux-android", "x86_64-unknown-linux-gnu"] {
            let error = release_refusal(target, &[(APPLE_LIB_ENV, "1")]);
            assert!(error.starts_with("DOODLEART_APPLE_LIB=1 is for Apple targets only"), "{error}");
        }
        // An iOS-only project needs no APK digest for any slice, the macOS one included.
        let ios_only = temp_file("ios-only.conf", "PROJECT_ID = ios-only\n");
        let keys = temp_file("ios-only-keys.conf", &key_file(Some("ios-only"), Some("release"), "io-1"));
        let vars = [(PROJECT_CONF_ENV, ios_only.as_str()), (PROJECT_CONF_RELEASE_ENV, "1"), (KEYS_ENV, keys.as_str())];
        for target in ["aarch64-apple-ios", "aarch64-apple-ios-sim"] {
            assert!(plan(target, "release", &vars).build_config.contains("pub const PROJECT_ID: &str = \"ios-only\";"));
        }
        let with_lib = [&vars[..], &[(APPLE_LIB_ENV, "1")]].concat();
        assert!(plan("aarch64-apple-darwin", "release", &with_lib).cfgs.contains(&"doodleart_apple_lib".into()));
        let error = refusal("aarch64-apple-darwin", "release", &vars);
        assert!(error.contains("no `RELEASE_APK_CERT_SHA256`"), "{error}");
    }

    #[test]
    fn simulator_cfg_comes_from_the_triple() {
        for (target, simulator) in [
            ("aarch64-apple-ios-sim", true),
            ("x86_64-apple-ios", true),
            ("aarch64-apple-ios", false),
            ("aarch64-apple-ios-macabi", false),
            ("aarch64-apple-darwin", false),
            ("aarch64-linux-android", false),
        ] {
            assert_eq!(is_simulator_triple(target), simulator, "{target}");
            let cfgs = plan(target, "debug", &[]).cfgs;
            assert_eq!(cfgs.contains(&"doodleart_simulator_target".to_owned()), simulator, "{target}");
        }
    }

    /// The wiring of the release override, the seed check and the key file through configure().
    #[test]
    fn overrides_reach_the_decision() {
        let other = temp_file("other.conf", &format!("PROJECT_ID = other\nRELEASE_APK_CERT_SHA256 = {OTHER_HEX}\n"));
        let other_keys = temp_file("other-release.conf", &key_file(Some("other"), Some("release"), "o-1"));
        // A leftover DOODLEART_PROJECT_CONF never swaps the allowlist of a release library...
        for allow in [None, Some("0"), Some("")] {
            let mut vars = vec![(PROJECT_CONF_ENV, other.as_str()), (KEYS_ENV, other_keys.as_str())];
            vars.extend(allow.map(|value| (PROJECT_CONF_RELEASE_ENV, value)));
            assert!(
                refusal("aarch64-linux-android", "release", &vars).contains("DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1")
            );
        }
        // ...unless allowed, with that project's own keys.
        let allowed =
            [(PROJECT_CONF_ENV, other.as_str()), (PROJECT_CONF_RELEASE_ENV, "1"), (KEYS_ENV, other_keys.as_str())];
        let config = plan("aarch64-linux-android", "release", &allowed).build_config;
        assert!(config.contains("pub const PROJECT_ID: &str = \"other\";") && config.contains("(\"o-1\", ["));
        assert!(config.contains(&format!(
            "pub const RELEASE_APK_CERT_SHA256: &[[u8; 32]] = &[\n    {:?},\n];",
            digest(OTHER_HEX)
        )));
        // OBFSTR_SEED: release refuses a mismatch, debug warns.
        let error = release_refusal("aarch64-linux-android", &[(OBFSTR_SEED_ENV, "0123456789abcdef")]);
        assert!(error.starts_with("OBFSTR_SEED in the environment differs from"), "{error}");
        let warned = plan("aarch64-linux-android", "debug", &[(OBFSTR_SEED_ENV, "0123456789abcdef")]);
        assert_eq!(warned.warnings.len(), 1);
        assert!(warned.warnings[0].starts_with("OBFSTR_SEED in the environment differs from"));
        let seed = committed_seed();
        assert!(plan("aarch64-linux-android", "debug", &[(OBFSTR_SEED_ENV, seed.as_str())]).warnings.is_empty());
        // DOODLEART_SERVER_KEYS_FILE: relative to the crate, like DOODLEART_PROJECT_CONF.
        let relative = plan("aarch64-linux-android", "debug", &[(KEYS_ENV, "config/server-keys.debug.conf")]);
        assert!(relative.read.contains(&Path::new(MANIFEST_DIR).join("config/server-keys.debug.conf")));
        assert!(refusal("aarch64-linux-android", "debug", &[(KEYS_ENV, "no/such.conf")])
            .starts_with("cannot read server key config"));
    }

    /// Key files are bound to their project and build type: another project that forgets one of the two variables
    /// stops instead of embedding DoodleArt's keys or DoodleArt's project (theme-x spec 2026-11-05 D-P4-4).
    #[test]
    fn key_files_are_bound_to_project_and_build_type() {
        let project_b = temp_file("b.conf", &format!("PROJECT_ID = b\nRELEASE_APK_CERT_SHA256 = {OTHER_HEX}\n"));
        let b_release = temp_file("b-release.conf", &key_file(Some("b"), Some("release"), "b-1"));
        let b_debug = temp_file("b-debug.conf", &key_file(Some("b"), Some("debug"), "b-dev"));
        let untagged = temp_file("untagged.conf", &key_file(None, None, "u-1"));
        let release_of_b = [(PROJECT_CONF_ENV, project_b.as_str()), (PROJECT_CONF_RELEASE_ENV, "1")];
        // (a) project B forgets DOODLEART_SERVER_KEYS_FILE: DoodleArt's keys say project doodleart.
        let error = release_refusal("aarch64-linux-android", &release_of_b);
        assert!(error.contains("the keys are for project `doodleart`, the project config is `b`"), "{error}");
        let error = release_refusal("aarch64-apple-ios", &release_of_b);
        assert!(error.contains("the keys are for project `doodleart`"), "{error}");
        // (b) project B forgets DOODLEART_PROJECT_CONF: its keys say project b.
        let error = release_refusal("aarch64-linux-android", &[(KEYS_ENV, b_release.as_str())]);
        assert!(error.contains("the keys are for project `b`, the project config is `doodleart`"), "{error}");
        // The debug keys of a project in its release build.
        let with_debug_keys = [&release_of_b[..], &[(KEYS_ENV, b_debug.as_str())]].concat();
        let error = refusal("aarch64-linux-android", "release", &with_debug_keys);
        assert!(error.contains("the keys are for the `debug` build type, not `release`"), "{error}");
        let error = refusal("aarch64-linux-android", "debug", &[(KEYS_ENV, RELEASE_TEST_KEYS)]);
        assert!(error.contains("the keys are for the `release` build type, not `debug`"), "{error}");
        // Another project's config needs both tags, whatever the file carries otherwise.
        let only_project = temp_file("b-only-project.conf", &key_file(Some("b"), None, "b-x"));
        let only_type = temp_file("b-only-type.conf", &key_file(None, Some("release"), "b-y"));
        for keys in [&untagged, &only_project, &only_type] {
            let vars = [&release_of_b[..], &[(KEYS_ENV, keys.as_str())]].concat();
            let error = refusal("aarch64-linux-android", "release", &vars);
            assert!(error.contains("must say `project = b` and `build_type = release`"), "{keys}: {error}");
            let error = refusal("aarch64-apple-ios", "release", &vars);
            assert!(error.contains("must say `project = b` and `build_type = release`"), "{keys}: {error}");
        }
        let with_keys = [&release_of_b[..], &[(KEYS_ENV, b_release.as_str())]].concat();
        assert!(plan("aarch64-linux-android", "release", &with_keys).build_config.contains("(\"b-1\", ["));
    }

    /// An untagged key file with DoodleArt's default project config stops every build, unless DoodleArt committed every
    /// key in it; a tagged file is checked by its tags only (the committed files are tagged).
    #[test]
    fn untagged_key_files_are_refused() {
        let foreign = temp_file("untagged-foreign.conf", &key_file(None, None, "u-1"));
        let foreign_typed = temp_file("untagged-typed.conf", &key_file(None, Some("release"), "u-2"));
        let fixture = fs::read_to_string(Path::new(MANIFEST_DIR).join(RELEASE_TEST_KEYS)).unwrap();
        let untagged_fixture: String =
            fixture.lines().filter(|line| !line.starts_with("project")).map(|line| format!("{line}\n")).collect();
        let untagged_fixture = temp_file("untagged-fixture.conf", &untagged_fixture);

        for (keys, kid) in [(&foreign, "u-1"), (&foreign_typed, "u-2"), (&untagged_fixture, "release-test-a")] {
            for target in ["aarch64-apple-ios", "aarch64-apple-ios-sim", "aarch64-linux-android"] {
                let error = release_refusal(target, &[(KEYS_ENV, keys.as_str())]);
                assert!(error.contains(&format!("no `project` tag and holds keys (kid {kid}")), "{target}: {error}");
                assert!(error.contains("config/server-keys.release.conf does not have"), "{error}");
            }
            let mac = release_refusal("aarch64-apple-darwin", &[(KEYS_ENV, keys.as_str()), (APPLE_LIB_ENV, "1")]);
            assert!(mac.contains("no `project` tag"), "{mac}");
        }
        let tagged = temp_file("tagged-other-key.conf", &key_file(Some("doodleart"), Some("release"), "t-1"));
        assert!(release_plan("aarch64-apple-ios", &[(KEYS_ENV, tagged.as_str())]).warnings.is_empty());
    }

    #[test]
    fn committed_key_files_name_their_project_and_build_type() {
        for build_type in ["debug", "qa", "release"] {
            let text =
                fs::read_to_string(Path::new(MANIFEST_DIR).join(format!("config/server-keys.{build_type}.conf")))
                    .unwrap();
            let tags: Vec<&str> =
                text.lines().filter(|line| line.starts_with("project") || line.starts_with("build_type")).collect();
            assert_eq!(tags, ["project = doodleart", &format!("build_type = {build_type}")], "{build_type}");
        }
    }

    #[test]
    fn key_file_syntax() {
        let text = format!(
            "# c\nproject = p\nbuild_type = qa\ncurrent.kid = k1\ncurrent.public_key = {KEY_HEX}\n\
                            next.kid = k2\nnext.public_key = {}\nother = ignored\n",
            KEY_HEX.to_uppercase()
        );
        let parsed = parse_server_keys(&text, "qa").unwrap();
        assert_eq!(parsed.keys.iter().map(|(kid, _)| kid.as_str()).collect::<Vec<_>>(), ["k1", "k2"]);
        assert_eq!((parsed.project.as_deref(), parsed.build_type.as_deref()), (Some("p"), Some("qa")));
        let empty_tags =
            parse_server_keys(&format!("project =\ncurrent.kid = k\ncurrent.public_key = {KEY_HEX}"), "qa");
        assert_eq!(empty_tags.unwrap().project, None);
        assert!(parse_server_keys("current.kid = k\ncurrent.public_key = REPLACE_ME", "qa")
            .unwrap_err()
            .starts_with("no real Ed25519"));
        assert_eq!(parse_server_keys("current.kid k", "qa").unwrap_err(), "line 1: expected `key = value`");
        let duplicate =
            format!("current.kid = k\ncurrent.public_key = {KEY_HEX}\nnext.kid = k\nnext.public_key = {KEY_HEX}");
        assert_eq!(parse_server_keys(&duplicate, "qa").unwrap_err(), "duplicate kid `k`");
    }
}
