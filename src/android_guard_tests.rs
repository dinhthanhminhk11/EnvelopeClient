//! Protocol ids of the contract with the doodle-art server (server/docs/app-security.md sections 3, 3a): `doodle/v1/*`,
//! DAPI1, DAAS1 (theme-x TXPI1, TXAS1 renamed), CNHW1 and the sealed media type. They are protocol ids, not app ids:
//! no platform or refactor changes them. The server vectors (envelope-v1.json, app-attest-v1.json) pin the complete
//! byte layouts; this test pins the ids themselves in one place, so a rename fails with the name of the frame that
//! changed. The RegisterNatives table is
//! pinned next to it, in `jni::tests`. The last tests cover the build.rs output Android depends on: the build type, the
//! APK certificate allowlists moved to the project config (D-P4-4) and the JNI init reply that must not carry the
//! project id.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::codec::{hex_encode, unframe, Frame};
use crate::device_signals::{encode_hw_fingerprint, HwSignals};
use crate::envelope::wire;
use crate::integrity_hash::{self, IntegrityRequest};
use crate::{api, apk_identity, build_config};

fn first_field(frame: &[u8]) -> String {
    let fields = unframe(frame).expect("a frame");
    String::from_utf8(fields[0].to_vec()).expect("a UTF-8 tag")
}

#[test]
fn frame_tags_are_frozen() {
    let key = [7u8; 32];
    let request_id = integrity_hash::new_request_id().unwrap();
    let dapi1 =
        IntegrityRequest { method: "GET", path_with_query: "/api/v1/x", request_id: &request_id, sid: "", body: b"" };
    let frames: [(&str, Vec<u8>); 9] = [
        ("doodle/v1/register", wire::register_message(&[0u8; 24], "device", "key", "ios")),
        ("doodle/v1/start", wire::device_signature_message(&key, 1, "install", "device", "1.0.0", "")),
        ("doodle/v1/transcript", wire::transcript_input(&key, "device", &key, "sid", 1, 2, "kid")),
        ("doodle/v1/start-resp", wire::start_response_aad("sid")),
        ("doodle/v1/req", wire::request_aad("GET", "/api/v1/x", "sid", 1, 2, "1.0.0")),
        ("doodle/v1/resp", wire::response_aad("sid", 1, 200, "")),
        ("DAPI1", integrity_hash::preimage(&dapi1).unwrap()),
        ("DAAS1", integrity_hash::session_assert_preimage(b"signature message")),
        ("CNHW1", encode_hw_fingerprint(&HwSignals::default())),
    ];
    for (tag, frame) in &frames {
        assert_eq!(first_field(frame), *tag);
    }
}

#[test]
fn key_derivation_and_media_type_ids_are_frozen() {
    let (shared, transcript) = ([3u8; 32], [5u8; 32]);
    let keys = wire::derive_session_keys(&shared, &transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(&transcript), &shared);
    let (mut c2s, mut s2c) = ([0u8; 32], [0u8; 32]);
    hkdf.expand(b"doodle/v1/c2s", &mut c2s).unwrap();
    hkdf.expand(b"doodle/v1/s2c", &mut s2c).unwrap();
    assert_eq!(*keys.c2s, c2s);
    assert_eq!(*keys.s2c, s2c);

    let secret = [9u8; 32];
    let framed = Frame::new().text("doodle/v1/ios-device").bytes(&secret).finish();
    assert_eq!(integrity_hash::ios_device_hash(&secret).unwrap(), hex_encode(&Sha256::digest(framed)));

    assert_eq!(wire::SEALED_CONTENT_TYPE, "application/vnd.doodle.sealed");
    assert_eq!(wire::ENVELOPE_VERSION, 1);
}

/// build.rs reads the debug certificate allowlist for every debug build except Apple libraries (iOS has no APK);
/// release and QA builds pin theirs in apk_identity.rs. Runs on the host, so it guards the Android/macOS side.
#[test]
#[allow(clippy::const_is_empty)] // the constants under test are what build.rs generated for this build
fn build_config_matches_the_build_type() {
    let build_type = if cfg!(feature = "build-release") {
        "release"
    } else if cfg!(feature = "build-qa") {
        "qa"
    } else {
        "debug"
    };
    assert_eq!(build_config::BUILD_TYPE, build_type);
    let apple_lib = cfg!(doodleart_apple_lib);
    assert_eq!(build_config::DEBUG_CERT_SHA256.is_empty(), build_type != "debug" || apple_lib);
    assert!(!build_config::SERVER_KEYS.is_empty());
}

/// D-P4-4 moved the release and QA APK allowlists from constants in src/apk_identity.rs to config/project.conf. Those
/// constants are the golden: what build.rs generates from the committed config equals them byte for byte, and
/// `apk_identity` checks against the allowlist of the build type. Skipped when DOODLEART_PROJECT_CONF builds another
/// project (its own values are not DoodleArt's).
#[test]
#[allow(clippy::const_is_empty)] // the constants under test are what build.rs generated for this build
fn project_config_matches_the_former_constants() {
    if option_env!("DOODLEART_PROJECT_CONF").is_some_and(|path| !path.is_empty()) {
        eprintln!("skipped: DOODLEART_PROJECT_CONF selects another project's config");
        return;
    }
    // src/apk_identity.rs before P4: hex32("…") of the app signing key (release) and of the upload key (QA).
    const RELEASE: &str = "598359c6c743530f324e80207c64d68ee95e169aeddb38e85ead7dc3af114655";
    const QA: &str = "9a66a46a0247df31fbcb43150d7fbb68ae94e0e5001bdaff55de7569de98e815";
    let hex = |digests: &[[u8; 32]]| digests.iter().map(|digest| hex_encode(digest)).collect::<Vec<_>>();

    assert_eq!(build_config::PROJECT_ID, "doodleart");
    if cfg!(doodleart_apple_lib) {
        // An Apple library has no APK (build.rs): no allowlist at all.
        assert!(build_config::RELEASE_APK_CERT_SHA256.is_empty() && build_config::QA_APK_CERT_SHA256.is_empty());
        return;
    }
    assert_eq!(hex(build_config::RELEASE_APK_CERT_SHA256), [RELEASE]);
    assert_eq!(hex(build_config::QA_APK_CERT_SHA256), [QA]);
    match build_config::BUILD_TYPE {
        "release" => assert_eq!(hex(apk_identity::ALLOWED_CERT_SHA256), [RELEASE]),
        "qa" => assert_eq!(hex(apk_identity::ALLOWED_CERT_SHA256), [QA]),
        _ => assert_eq!(apk_identity::ALLOWED_CERT_SHA256, build_config::DEBUG_CERT_SHA256),
    }
}

/// The JNI init reply stays `frame(buildType, crateVersion, kidsCsv)`, byte for byte: the project id only goes to the
/// C ABI init reply and the iOS manifest (D-P4-4).
#[test]
fn jni_init_reply_has_no_project_id() {
    let reply = api::init(None);
    let kids: Vec<&str> = build_config::SERVER_KEYS.iter().map(|(kid, _)| *kid).collect();
    let expected = Frame::new().text(build_config::BUILD_TYPE).text(env!("CARGO_PKG_VERSION")).text(&kids.join(","));
    assert_eq!(reply, [&[api::STATUS_OK][..], &expected.finish()].concat());
    let fields = unframe(&reply[1..]).expect("a frame");
    assert!(!fields.contains(&build_config::PROJECT_ID.as_bytes()));
}

/// Every C ABI and JNI entry relies on `catch_unwind`, which only works with `panic = "unwind"`: under "abort" a panic
/// would kill the app and every other check (cargo test runs the dev profile) would stay green. Pins the release
/// profile that build-android.sh and build-ios.sh build with.
#[test]
fn release_profile_unwinds() {
    let manifest = include_str!("../Cargo.toml");
    let release = manifest.split("[profile.release]").nth(1).expect("a [profile.release] section");
    let release = release.split("\n[").next().unwrap_or(release);
    let panic: Vec<&str> = release.lines().map(str::trim).filter(|line| line.starts_with("panic")).collect();
    assert_eq!(panic, ["panic = \"unwind\""], "{release}");
}
