//! The C ABI called the way Swift calls it (raw `(ptr, len)` pairs, `DoodleArtBuf` replies), on the host: the header
//! against the Rust signatures, the NULL / length / ownership rules, panic containment at every entry, the vectors of
//! the server (envelope-v1.json, app-attest-v1.json), and whole sessions against the Go server (the interop peer of
//! src/interop_tests.rs: real routes, middleware and usecases).

use std::ptr::{self, NonNull};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;
use crate::codec::{b64url_decode_exact, b64url_encode, hex_decode, hex_encode, is_uuid, unframe, Frame};
use crate::envelope::{wire, SealedRequest};
use crate::interop_tests::{self as interop, http, sealed_headers, Device};
use crate::test_support::{attest_vectors, envelope_vectors, frees_leak_sentinel, GoPeer, SECRET_SENTINEL};
use crate::{build_config, integrity_hash};

const HEADER: &str = include_str!("../../include/doodleart_core.h");
const MODULE_MAP: &str = include_str!("../../include/module.modulemap");
const DEVICE_ID: &[u8] = b"8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30";

// ---- calling helpers ----------------------------------------------------------------------------------------------

type Pair = (*const u8, usize);

/// The `(ptr, len)` pair Swift passes for a byte string: `None` is `(NULL, 0)`, `Some(b"")` a non-NULL empty one.
fn pair(bytes: Option<&[u8]>) -> Pair {
    bytes.map_or((ptr::null(), 0), |bytes| (bytes.as_ptr(), bytes.len()))
}

/// A pair that breaks the NULL rule.
const NULL_WITH_LENGTH: Pair = (ptr::null(), 1);

/// A pair over the size limit (never read: refused first).
fn oversized() -> Pair {
    (NonNull::<u8>::dangling().as_ptr(), MAX_INPUT_BYTES + 1)
}

fn is_live(buf: DoodleArtBuf) -> bool {
    live().get(&(buf.ptr as usize)) == Some(&buf.len)
}

/// Copies a reply out and releases it, as Swift does. Nothing is asserted about the registry after the release: a test
/// running in parallel may get a reply at the same address and length at once (the allocator reuses blocks), so
/// "not live any more" is only checked where the length is unique (`buffers_are_released_exactly_once`).
fn take(buf: DoodleArtBuf) -> Vec<u8> {
    assert!(!buf.ptr.is_null() && buf.len > 0, "{buf:?}");
    assert!(is_live(buf), "a reply is registered until released");
    // SAFETY: a reply of the C ABI: len readable bytes owned by Rust until doodleart_buf_free below.
    let bytes = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec();
    doodleart_buf_free(buf);
    bytes
}

fn status_of(buf: DoodleArtBuf) -> u8 {
    take(buf)[0]
}

fn ok_raw(buf: DoodleArtBuf) -> Vec<u8> {
    let reply = take(buf);
    assert_eq!(reply[0], 0, "reply {reply:?}");
    reply[1..].to_vec()
}

fn ok_fields(buf: DoodleArtBuf) -> Vec<Vec<u8>> {
    let payload = ok_raw(buf);
    unframe(&payload).expect("a framed payload").into_iter().map(<[u8]>::to_vec).collect()
}

fn u64_field(field: &[u8]) -> u64 {
    u64::from_be_bytes(field.try_into().expect("an 8-byte number"))
}

fn text(case: &Value, name: &str) -> Vec<u8> {
    case[name].as_str().unwrap_or_else(|| panic!("{name} in {case}")).as_bytes().to_vec()
}

// Safe wrappers: each passes `pair(...)` values, which are NULL or a live slice, as the contract requires.

fn device_key_id(spki: Option<&[u8]>) -> DoodleArtBuf {
    let spki = pair(spki);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_device_key_id(spki.0, spki.1) }
}

fn handshake_begin(device_id: Option<&[u8]>, device_key_id: Option<&[u8]>, app_version: Option<&[u8]>) -> DoodleArtBuf {
    let (a, b, c) = (pair(device_id), pair(device_key_id), pair(app_version));
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_handshake_begin(a.0, a.1, b.0, b.1, c.0, c.1) }
}

fn handshake_body(handshake: i64, device_sig: Option<&[u8]>) -> DoodleArtBuf {
    let sig = pair(device_sig);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_handshake_body(handshake, sig.0, sig.1) }
}

fn handshake_finish(handshake: i64, http_status: i32, body: Option<&[u8]>) -> DoodleArtBuf {
    handshake_finish_at(handshake, http_status, 0, body)
}

fn handshake_finish_at(handshake: i64, http_status: i32, server_time: i64, body: Option<&[u8]>) -> DoodleArtBuf {
    let body = pair(body);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_handshake_finish(handshake, http_status, server_time, body.0, body.1) }
}

fn session_seal(session: i64, method: &[u8], path: &[u8], body: Option<&[u8]>) -> DoodleArtBuf {
    let (m, p, b) = (pair(Some(method)), pair(Some(path)), pair(body));
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_session_seal(session, m.0, m.1, p.0, p.1, b.0, b.1) }
}

fn session_response(
    session: i64,
    seq: i64,
    status: i32,
    content_type: Option<&[u8]>,
    content_encoding: Option<&[u8]>,
    body: Option<&[u8]>,
) -> DoodleArtBuf {
    let (c, e, b) = (pair(content_type), pair(content_encoding), pair(body));
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_session_response(session, seq, status, c.0, c.1, e.0, e.1, b.0, b.1) }
}

fn session_open(session: i64, seq: i64, status: i32, sealed: Option<&[u8]>) -> DoodleArtBuf {
    let sealed = pair(sealed);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_session_open(session, seq, status, ptr::null(), 0, sealed.0, sealed.1) }
}

fn integrity(args: [Option<&[u8]>; 5]) -> DoodleArtBuf {
    let [m, p, r, s, b] = args.map(pair);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_integrity_hash(m.0, m.1, p.0, p.1, r.0, r.1, s.0, s.1, b.0, b.1) }
}

fn register_message(args: [Option<&[u8]>; 4]) -> DoodleArtBuf {
    let [n, d, k, p] = args.map(pair);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_register_message(n.0, n.1, d.0, d.1, k.0, k.1, p.0, p.1) }
}

fn ios_device_hash(secret: Option<&[u8]>) -> DoodleArtBuf {
    let secret = pair(secret);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_ios_device_hash(secret.0, secret.1) }
}

fn session_assert_hash(message: Option<&[u8]>) -> DoodleArtBuf {
    let message = pair(message);
    // SAFETY: pair() gives NULL or a slice that outlives the call.
    unsafe { doodleart_session_assert_hash(message.0, message.1) }
}

/// The 4 arguments of `doodleart_register_message` for the vector registration, in C ABI order.
fn register_args() -> [Vec<u8>; 4] {
    let v = envelope_vectors();
    let nonce = b64url_encode(&hex_decode(v["nonce"].as_str().unwrap()).unwrap());
    [nonce.into_bytes(), text(&v, "device_id"), text(&v, "key_id"), text(&v, "platform")]
}

// ---- header ↔ Rust ------------------------------------------------------------------------------------------------

/// `(return type, name, [(parameter type, parameter name)])` of every function the header declares, in order.
type Declaration = (String, String, Vec<(String, String)>);

fn header_functions() -> Vec<Declaration> {
    let mut code = String::new();
    let mut rest = HEADER;
    while let Some(start) = rest.find("/*") {
        code.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("closed comment");
        rest = &rest[start + end + 2..];
    }
    code.push_str(rest);
    let code: Vec<&str> = code.lines().filter(|line| !line.trim_start().starts_with('#')).collect();
    code.join("\n")
        .split(';')
        .filter_map(|statement| {
            let statement = statement.split_whitespace().collect::<Vec<_>>().join(" ");
            let statement = statement.trim_start_matches(['}', ' ']);
            let (head, parameters) = statement.split_once('(')?;
            let (returned, name) = head.rsplit_once(' ')?;
            if !name.starts_with("doodleart_") {
                return None;
            }
            let parameters = parameters.strip_suffix(')').expect("one parameter list");
            let parameters =
                if parameters == "void" { Vec::new() } else { parameters.split(',').map(parameter).collect() };
            Some((returned.to_owned(), name.to_owned(), parameters))
        })
        .collect()
}

/// `"const uint8_t *DOODLEART_NULLABLE spki"` → `("const uint8_t*", "spki")`.
fn parameter(declaration: &str) -> (String, String) {
    let declaration = declaration.replace("DOODLEART_NULLABLE", " ");
    let declaration = declaration.trim();
    let split = declaration.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).expect("a type and a name") + 1;
    let kind = declaration[..split].split_whitespace().collect::<Vec<_>>().join(" ").replace(" *", "*");
    (kind, declaration[split..].to_owned())
}

macro_rules! c_type {
    (Buf) => {
        "DoodleArtBuf"
    };
    (I32) => {
        "int32_t"
    };
    (I64) => {
        "int64_t"
    };
    (Ptr) => {
        "const uint8_t*"
    };
    (Len) => {
        "size_t"
    };
}

macro_rules! rust_type {
    (Buf) => {
        DoodleArtBuf
    };
    (I32) => {
        i32
    };
    (I64) => {
        i64
    };
    (Ptr) => {
        *const u8
    };
    (Len) => {
        usize
    };
}

/// `(name, C return type, C parameter types, address)` of a Rust entry. The cast only compiles when the function's
/// signature is exactly `extern "C" fn(<args>) -> <ret>` (safe or unsafe), so the C types computed from the same
/// tokens are the ones it implements.
macro_rules! entry {
    ($name:ident, ($($arg:ident),*) -> $ret:ident) => {
        (
            stringify!($name),
            c_type!($ret),
            vec![$(c_type!($arg)),*],
            $name as unsafe extern "C" fn($(rust_type!($arg)),*) -> rust_type!($ret) as usize,
        )
    };
    ($name:ident, ($($arg:ident),*)) => {
        (
            stringify!($name),
            "void",
            vec![$(c_type!($arg)),*],
            $name as unsafe extern "C" fn($(rust_type!($arg)),*) as usize,
        )
    };
}

type Entry = (&'static str, &'static str, Vec<&'static str>, usize);

fn rust_entries() -> Vec<Entry> {
    #[allow(unused_mut)] // a release build has no debug entry to add
    let mut entries = vec![
        entry!(doodleart_init, () -> Buf),
        entry!(doodleart_device_key_id, (Ptr, Len) -> Buf),
        entry!(doodleart_handshake_begin, (Ptr, Len, Ptr, Len, Ptr, Len) -> Buf),
        entry!(doodleart_handshake_body, (I64, Ptr, Len) -> Buf),
        entry!(doodleart_handshake_finish, (I64, I32, I64, Ptr, Len) -> Buf),
        entry!(doodleart_handshake_abort, (I64) -> I32),
        entry!(doodleart_session_seal, (I64, Ptr, Len, Ptr, Len, Ptr, Len) -> Buf),
        entry!(doodleart_session_response, (I64, I64, I32, Ptr, Len, Ptr, Len, Ptr, Len) -> Buf),
        entry!(doodleart_session_open, (I64, I64, I32, Ptr, Len, Ptr, Len) -> Buf),
        entry!(doodleart_session_abandon, (I64, I64) -> I32),
        entry!(doodleart_session_close, (I64) -> I32),
        entry!(doodleart_integrity_hash, (Ptr, Len, Ptr, Len, Ptr, Len, Ptr, Len, Ptr, Len) -> Buf),
        entry!(doodleart_register_message, (Ptr, Len, Ptr, Len, Ptr, Len, Ptr, Len) -> Buf),
        entry!(doodleart_ios_device_hash, (Ptr, Len) -> Buf),
        entry!(doodleart_session_assert_hash, (Ptr, Len) -> Buf),
        entry!(doodleart_handshake_assert_hash, (I64) -> Buf),
        entry!(doodleart_risk_scan, () -> Buf),
        entry!(doodleart_buf_free, (Buf)),
    ];
    #[cfg(feature = "build-debug")]
    entries.push(entry!(doodleart_debug_clock_advance_ms, (I64) -> I32));
    entries
}

/// The functions the Swift sample (swift/Sources) calls: all of them stay (additive changes only).
const SPEC_FUNCTIONS: [&str; 17] = [
    "doodleart_init",
    "doodleart_device_key_id",
    "doodleart_handshake_begin",
    "doodleart_handshake_body",
    "doodleart_handshake_finish",
    "doodleart_handshake_abort",
    "doodleart_session_seal",
    "doodleart_session_response",
    "doodleart_session_open",
    "doodleart_session_abandon",
    "doodleart_session_close",
    "doodleart_integrity_hash",
    "doodleart_register_message",
    "doodleart_ios_device_hash",
    "doodleart_session_assert_hash",
    "doodleart_risk_scan",
    "doodleart_buf_free",
];

/// Header and Rust agree on every function: name, order, return type and parameter types. Debug-only functions are
/// declared in the header for both build types and exist only in debug libraries.
#[test]
fn header_declares_exactly_the_rust_entries() {
    let declared = header_functions();
    let expected: Vec<(String, String, Vec<String>)> = rust_entries()
        .into_iter()
        .map(|(name, returned, parameters, _)| {
            (returned.to_owned(), name.to_owned(), parameters.into_iter().map(str::to_owned).collect())
        })
        .collect();
    let built: Vec<(String, String, Vec<String>)> = declared
        .iter()
        .filter(|(_, name, _)| cfg!(feature = "build-debug") || !name.starts_with("doodleart_debug_"))
        .map(|(returned, name, parameters)| {
            (returned.clone(), name.clone(), parameters.iter().map(|(kind, _)| kind.clone()).collect())
        })
        .collect();
    assert_eq!(built, expected);

    let names: Vec<&str> = declared.iter().map(|(_, name, _)| name.as_str()).collect();
    for name in SPEC_FUNCTIONS {
        assert!(names.contains(&name), "{name} of spec §4.4 is missing");
    }
    assert!(names.contains(&"doodleart_debug_clock_advance_ms"));
    let debug: Vec<&&str> = names.iter().filter(|name| name.starts_with("doodleart_debug_")).collect();
    assert_eq!(debug, [&"doodleart_debug_clock_advance_ms"]);

    // Every byte string is a `name, name_len` pair.
    for (_, name, parameters) in &declared {
        for (index, (kind, parameter)) in parameters.iter().enumerate() {
            if kind == "const uint8_t*" {
                assert_eq!(
                    parameters.get(index + 1),
                    Some(&("size_t".to_owned(), format!("{parameter}_len"))),
                    "{name}"
                );
            }
        }
    }

    let mut addresses: Vec<usize> = rust_entries().iter().map(|(_, _, _, address)| *address).collect();
    addresses.sort_unstable();
    addresses.dedup();
    assert_eq!(addresses.len(), rust_entries().len());
}

/// The header's constants and struct are the Rust ones; the module map exposes the header as `DoodleArtCore`.
#[test]
fn header_constants_and_layout_match() {
    let define = |name: &str| -> u64 {
        let line = HEADER
            .lines()
            .find_map(|line| line.strip_prefix(&format!("#define {name} ")))
            .unwrap_or_else(|| panic!("#define {name}"));
        line.trim().parse().unwrap_or_else(|_| panic!("{name} = {line}"))
    };
    assert_eq!(define("DOODLEART_ABI_VERSION"), api::apple::ABI_VERSION);
    assert_eq!(define("DOODLEART_MAX_INPUT_LEN"), MAX_INPUT_BYTES as u64);
    let statuses = [
        ("OK", 0),
        ("INVALID_ARGUMENT", Error::InvalidArgument.status()),
        ("UNKNOWN_HANDLE", Error::UnknownHandle.status()),
        ("HANDSHAKE_STATE", Error::HandshakeState.status()),
        ("BAD_SERVER_RESPONSE", Error::BadServerResponse.status()),
        ("BAD_SERVER_SIGNATURE", Error::BadServerSignature.status()),
        ("SERVER_REJECTED", Error::ServerRejected { status: 0, code: None, server_time: None }.status()),
        ("DECRYPT_FAILED", Error::DecryptFailed.status()),
        ("REPLAYED_RESPONSE", Error::ReplayedResponse.status()),
        ("SEQ_EXHAUSTED", Error::SeqExhausted.status()),
        ("SESSION_EXPIRED", Error::SessionExpired.status()),
        ("LIMIT_REACHED", Error::LimitReached.status()),
        ("RNG", Error::Rng.status()),
        ("INTERNAL", Error::Internal.status()),
        ("UNSEALED_RESPONSE", Error::UnsealedResponse { status: 0, code: None }.status()),
    ];
    for (name, status) in statuses {
        assert_eq!(define(&format!("DOODLEART_STATUS_{name}")), u64::from(status), "{name}");
    }
    assert_eq!(HEADER.matches("#define DOODLEART_STATUS_").count(), statuses.len());

    let compact = HEADER.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        compact.contains("typedef struct DoodleArtBuf { uint8_t *DOODLEART_NULLABLE ptr; size_t len; } DoodleArtBuf;")
    );
    assert_eq!(std::mem::size_of::<DoodleArtBuf>(), 2 * std::mem::size_of::<usize>());
    assert_eq!(std::mem::offset_of!(DoodleArtBuf, ptr), 0);
    assert_eq!(std::mem::offset_of!(DoodleArtBuf, len), std::mem::size_of::<usize>());
    assert!(compact.contains("#ifdef __cplusplus extern \"C\" {"));

    let module = MODULE_MAP.lines().filter(|line| !line.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    let module = module.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(module, "module DoodleArtCore { header \"doodleart_core.h\" export * }");
}

// ---- replies and vectors ------------------------------------------------------------------------------------------

/// `doodleart_init` is the JNI init reply without an APK path, byte for byte, then `u64(abiVersion)` and `projectId`.
#[test]
fn init_extends_the_jni_reply() {
    let reply = take(doodleart_init());
    let jni = api::init(None);
    assert_eq!(&reply[..jni.len()], &jni[..]);
    let fields = unframe(&reply[1..]).unwrap();
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[0], build_config::BUILD_TYPE.as_bytes());
    assert_eq!(fields[1], env!("CARGO_PKG_VERSION").as_bytes());
    assert_eq!(u64_field(fields[3]), 1);
    assert_eq!(fields[4], build_config::PROJECT_ID.as_bytes());
    assert_eq!(&reply[jni.len()..], Frame::new().u64(1).text(build_config::PROJECT_ID).finish());
}

#[test]
fn device_key_id_of_the_vector_key() {
    let v = envelope_vectors();
    let spki = hex_decode(v["device_spki"].as_str().unwrap()).unwrap();
    assert_eq!(ok_raw(device_key_id(Some(&spki))), text(&v, "key_id"));
    assert_eq!(status_of(device_key_id(Some(&spki[..90]))), 1);
    assert_eq!(status_of(device_key_id(None)), 1);
}

/// DAPI1 of every integrity vector of the server: the JNI fields, then the 32 raw bytes of the hash.
#[test]
fn integrity_hash_vectors_with_the_raw_hash() {
    for case in attest_vectors()["integrity"].as_array().unwrap() {
        let body = text(case, "body");
        let (method, path, request_id, sid) =
            (text(case, "method"), text(case, "path_with_query"), text(case, "request_id"), text(case, "sid"));
        let fields = ok_fields(integrity([Some(&method), Some(&path), Some(&request_id), Some(&sid), Some(&body)]));
        assert_eq!(fields.len(), 3, "{case}");
        assert_eq!(fields[0], request_id);
        assert_eq!(fields[1], text(case, "request_hash_b64"));
        let preimage = hex_decode(case["preimage"].as_str().unwrap()).unwrap();
        assert_eq!(fields[2], Sha256::digest(&preimage).as_slice(), "{case}");
        assert_eq!(hex_encode(&fields[2]), case["request_hash"].as_str().unwrap());
        assert_eq!(fields[2], b64url_decode_exact::<32>(std::str::from_utf8(&fields[1]).unwrap()).unwrap());
        // The first two fields are the JNI reply.
        let jni = api::integrity_hash(Some(&method), Some(&path), Some(&request_id), Some(&sid), Some(&body));
        assert_eq!(api::split_reply(&jni).unwrap().1, [&fields[0][..], &fields[1][..]]);
        // An empty sid and an absent one are the same; so are an empty body and an absent one.
        if sid.is_empty() {
            assert_eq!(
                ok_fields(integrity([Some(&method), Some(&path), Some(&request_id), None, Some(&body)])),
                fields
            );
        }
        if body.is_empty() {
            assert_eq!(ok_fields(integrity([Some(&method), Some(&path), Some(&request_id), Some(&sid), None])), fields);
        }
    }
    // An absent requestId is generated (UUID v4); an empty one is not a UUID.
    let fields = ok_fields(integrity([Some(b"POST"), Some(b"/api/v1/devices/register"), None, None, Some(b"{}")]));
    assert!(is_uuid(std::str::from_utf8(&fields[0]).unwrap()));
    assert_eq!(fields[2].len(), 32);
    assert_eq!(status_of(integrity([Some(b"POST"), Some(b"/api/v1/x"), Some(b""), None, None])), 1);
    assert_eq!(status_of(integrity([Some(b"post"), Some(b"/api/v1/x"), None, None, None])), 1);
}

/// The registration message of the vectors and its SHA-256 (the App Attest clientDataHash of the server's vectors),
/// and the refusals of values the server's schema refuses.
#[test]
fn register_message_vector() {
    let args = register_args();
    let fields = ok_fields(register_message(args.each_ref().map(|arg| Some(arg.as_slice()))));
    assert_eq!(fields.len(), 2);
    assert_eq!(hex_encode(&fields[0]), envelope_vectors()["register_message"].as_str().unwrap());
    assert_eq!(hex_encode(&fields[1]), attest_vectors()["register_client_data_hash"].as_str().unwrap());
    let with = |index: usize, value: Option<&[u8]>| {
        let mut call = args.each_ref().map(|arg| Some(arg.as_slice()));
        call[index] = value;
        status_of(register_message(call))
    };
    assert_eq!(with(0, None), 1, "nonce is required");
    assert_eq!(with(0, Some(&args[0][..31])), 1, "short nonce");
    assert_eq!(with(1, Some(b"6F1C1F9E-3D7A-4C55-9A52-0D6C2F0A8B11")), 1, "upper case device_id");
    assert_eq!(with(2, Some(b"short")), 1, "device_key_id");
    assert_eq!(with(3, Some(b"web")), 1, "platform");
    assert_eq!(with(3, Some(&[0xff])), 1, "not UTF-8");
}

#[test]
fn ios_device_hash_vectors() {
    for case in attest_vectors()["ios_device_hash"].as_array().unwrap() {
        let secret = hex_decode(case["secret"].as_str().unwrap()).unwrap();
        assert_eq!(ok_raw(ios_device_hash(Some(&secret))), text(case, "hash"));
        assert_eq!(status_of(ios_device_hash(Some(&secret[..31]))), 1);
        assert_eq!(status_of(ios_device_hash(Some(&[secret.as_slice(), &[0]].concat()))), 1);
    }
    assert_eq!(status_of(ios_device_hash(None)), 1);
}

/// DAAS1 of the server's vector; anything that is not a signature message is refused.
#[test]
fn session_assert_hash_vector_and_message_check() {
    let vectors = attest_vectors();
    let message = hex_decode(vectors["start_message"].as_str().unwrap()).unwrap();
    let expected = hex_decode(vectors["session_assert_client_data_hash"].as_str().unwrap()).unwrap();
    assert_eq!(ok_raw(session_assert_hash(Some(&message))), expected);

    let fields = unframe(&message).unwrap();
    let rebuilt = |edit: &dyn Fn(&mut Vec<Vec<u8>>)| {
        let mut fields: Vec<Vec<u8>> = fields.iter().map(|field| field.to_vec()).collect();
        edit(&mut fields);
        fields.iter().fold(Frame::new(), |frame, field| frame.bytes(field)).finish()
    };
    assert_eq!(rebuilt(&|_| {}), message);
    let refused: [Vec<u8>; 9] = [
        Vec::new(),
        message[..message.len() - 1].to_vec(),
        [message.as_slice(), &[0, 0, 0, 0]].concat(),
        rebuilt(&|fields| fields[0] = b"doodle/v1/req".to_vec()),
        // Same length, another tag: only the byte comparison with the rebuilt message sees it.
        rebuilt(&|fields| fields[0] = b"doodle/v2/start".to_vec()),
        rebuilt(&|fields| {
            fields[1].pop();
        }),
        rebuilt(&|fields| fields[2].push(0)),
        rebuilt(&|fields| fields[3] = vec![0xff]),
        rebuilt(&|fields| {
            fields.pop();
        }),
    ];
    for bytes in &refused {
        assert_eq!(status_of(session_assert_hash(Some(bytes))), 1, "{}", hex_encode(bytes));
    }
    assert_eq!(status_of(session_assert_hash(None)), 1);
}

/// The JNI risk scan reply, untouched: `frame(riskFlagsCsv, detailsCsv)` with flags of the vocabulary only.
#[test]
fn risk_scan_reply_is_the_jni_one() {
    let fields = ok_fields(doodleart_risk_scan());
    assert_eq!(fields.len(), 2);
    let csv = std::str::from_utf8(&fields[0]).unwrap();
    let flags: Vec<&str> = csv.split(',').filter(|flag| !flag.is_empty()).collect();
    assert!(flags.iter().all(|flag| crate::risk::Flag::parse(flag).is_some()), "{csv}");
    assert!(flags.windows(2).all(|pair| pair[0] < pair[1]), "{csv}");
    if cfg!(feature = "build-release") {
        assert!(fields[1].is_empty());
    }
    // Swift passes no flags: the core's own scan, exactly what the JNI native returns without Kotlin flags.
    assert_eq!(fields, ok_fields_of(&api::risk_scan(None)));
}

/// The scan behind `doodleart_risk_scan` (and `doodleart_handshake_begin`) is the Apple scan (risk/apple.rs, theme-x spec §5.12):
/// on this macOS host its filesystem probes are off (`root.unchecked` first), and no detail of the Android scan.
#[test]
fn risk_scan_is_the_apple_scan() {
    let fields = ok_fields(doodleart_risk_scan());
    let details = std::str::from_utf8(&fields[1]).unwrap();
    if cfg!(feature = "build-release") {
        assert_eq!(details, "");
    } else {
        assert_eq!(details.split(',').next(), Some("root.unchecked"), "{details}");
        assert!(!details.contains("apk.") && !details.contains("hook.text"), "{details}");
    }
    assert!(!std::str::from_utf8(&fields[0]).unwrap().split(',').any(|flag| flag == "root" || flag == "emulator"));
}

fn ok_fields_of(reply: &[u8]) -> Vec<Vec<u8>> {
    let (status, fields) = api::split_reply(reply).expect("a framed reply");
    assert_eq!(status, 0, "reply {reply:?}");
    fields.into_iter().map(<[u8]>::to_vec).collect()
}

// ---- argument rules -----------------------------------------------------------------------------------------------

/// Every `(ptr, len)` argument of every function goes through the NULL and size rules: with otherwise valid arguments
/// (whose status is never INVALID_ARGUMENT), breaking one pair alone gives INVALID_ARGUMENT.
#[test]
fn every_pair_follows_the_null_and_size_rules() {
    let v = envelope_vectors();
    let spki = hex_decode(v["device_spki"].as_str().unwrap()).unwrap();
    let device_key_id = text(&v, "key_id");
    let dapi1 = &attest_vectors()["integrity"][1];
    let integrity_args = ["method", "path_with_query", "request_id", "sid", "body"].map(|name| text(dapi1, name));
    let register_case = register_args();
    let message = hex_decode(v["start_message"].as_str().unwrap()).unwrap();
    let secret = [7u8; 32];
    let unknown = 0x1234_5678_i64;

    // (name, valid pairs, call, status with the valid pairs). SAFETY (every closure): the test passes pair() values
    // (NULL or a live slice) or a broken pair, which is refused before any read.
    type Call = Box<dyn Fn(&[Pair]) -> DoodleArtBuf>;
    let cases: Vec<(&str, Vec<Pair>, Call, u8)> = vec![
        (
            "doodleart_device_key_id",
            vec![pair(Some(&spki))],
            Box::new(|p: &[Pair]| unsafe { doodleart_device_key_id(p[0].0, p[0].1) }),
            0,
        ),
        (
            "doodleart_handshake_begin",
            vec![pair(Some(DEVICE_ID)), pair(Some(&device_key_id)), pair(Some(b"2.0.0"))],
            Box::new(|p: &[Pair]| unsafe { doodleart_handshake_begin(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) }),
            0,
        ),
        (
            "doodleart_handshake_body",
            vec![pair(Some(&[0x30; 8]))],
            Box::new(move |p: &[Pair]| unsafe { doodleart_handshake_body(unknown, p[0].0, p[0].1) }),
            2,
        ),
        (
            "doodleart_handshake_finish",
            vec![pair(Some(b"{}"))],
            Box::new(move |p: &[Pair]| unsafe { doodleart_handshake_finish(unknown, 200, 0, p[0].0, p[0].1) }),
            2,
        ),
        (
            "doodleart_session_seal",
            vec![pair(Some(b"POST")), pair(Some(b"/api/v1/x")), pair(Some(b"{}"))],
            Box::new(move |p: &[Pair]| unsafe {
                doodleart_session_seal(unknown, p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1)
            }),
            2,
        ),
        (
            "doodleart_session_response",
            vec![pair(Some(wire::SEALED_CONTENT_TYPE.as_bytes())), pair(Some(b"gzip")), pair(Some(&[0; 16]))],
            Box::new(move |p: &[Pair]| unsafe {
                doodleart_session_response(unknown, 1, 200, p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1)
            }),
            2,
        ),
        (
            "doodleart_session_open",
            vec![pair(Some(b"")), pair(Some(&[0; 16]))],
            Box::new(move |p: &[Pair]| unsafe {
                doodleart_session_open(unknown, 1, 200, p[0].0, p[0].1, p[1].0, p[1].1)
            }),
            2,
        ),
        (
            "doodleart_integrity_hash",
            integrity_args.iter().map(|arg| pair(Some(arg))).collect(),
            Box::new(|p: &[Pair]| unsafe {
                doodleart_integrity_hash(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1)
            }),
            0,
        ),
        (
            "doodleart_register_message",
            register_case.iter().map(|arg| pair(Some(arg))).collect(),
            Box::new(|p: &[Pair]| unsafe {
                doodleart_register_message(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1)
            }),
            0,
        ),
        (
            "doodleart_ios_device_hash",
            vec![pair(Some(&secret))],
            Box::new(|p: &[Pair]| unsafe { doodleart_ios_device_hash(p[0].0, p[0].1) }),
            0,
        ),
        (
            "doodleart_session_assert_hash",
            vec![pair(Some(&message))],
            Box::new(|p: &[Pair]| unsafe { doodleart_session_assert_hash(p[0].0, p[0].1) }),
            0,
        ),
    ];

    let declared: Vec<String> = header_functions()
        .into_iter()
        .filter(|(_, _, parameters)| parameters.iter().any(|(kind, _)| kind == "const uint8_t*"))
        .map(|(_, name, _)| name)
        .collect();
    assert_eq!(cases.iter().map(|case| case.0).collect::<Vec<_>>(), declared, "every function with a byte argument");

    for (name, valid, call, valid_status) in &cases {
        let reply = take(call(valid));
        assert_eq!(reply[0], *valid_status, "{name} with valid arguments");
        if *name == "doodleart_handshake_begin" {
            let handshake = u64_field(unframe(&reply[1..]).unwrap()[0]) as i64;
            assert_eq!(doodleart_handshake_abort(handshake), 0);
        }
        for index in 0..valid.len() {
            for broken in [NULL_WITH_LENGTH, oversized()] {
                let mut pairs = valid.clone();
                pairs[index] = broken;
                assert_eq!(take(call(&pairs)), [1], "{name}: argument {index} = {broken:?}");
            }
        }
    }
}

/// The size limit is inclusive: an input of exactly 64 MiB is taken (and the unknown session reported), one byte more
/// is refused before the handle is even looked at.
#[test]
fn inputs_of_exactly_the_limit_are_accepted() {
    let sealed = vec![0u8; MAX_INPUT_BYTES];
    // SAFETY: (ptr, len) is a live slice of exactly len bytes.
    let at_limit = unsafe { doodleart_session_open(0x1234, 1, 200, ptr::null(), 0, sealed.as_ptr(), sealed.len()) };
    assert_eq!(take(at_limit), [Error::UnknownHandle.status()]);
    // SAFETY: one byte past the slice, but a length over the limit is refused before any read.
    let over = unsafe { doodleart_session_open(0x1234, 1, 200, ptr::null(), 0, sealed.as_ptr(), sealed.len() + 1) };
    assert_eq!(take(over), [Error::InvalidArgument.status()]);
}

// ---- ownership ----------------------------------------------------------------------------------------------------

/// A reply's block is released by the first matching doodleart_buf_free and only by it; nothing else is ever freed.
/// The reply has a length no other reply of the tests has (4097 bytes), so no test running in parallel can get a reply
/// at its address and length: the second release below then hits an address that holds no live reply, which is
/// ignored (a second release in general is the caller's bug, see the module documentation of ffi.rs).
#[test]
fn buffers_are_released_exactly_once() {
    doodleart_buf_free(DoodleArtBuf::NULL);
    doodleart_buf_free(DoodleArtBuf { ptr: ptr::null_mut(), len: 5 });

    const UNIQUE_LEN: usize = 4097;
    let mut reply = [&[0u8][..], &SECRET_SENTINEL].concat();
    reply.resize(UNIQUE_LEN, 0);
    let buf = DoodleArtBuf::from_reply(reply);
    assert_eq!(buf.len, UNIQUE_LEN);
    assert!(is_live(buf));
    for wrong in [buf.len - 1, buf.len + 1, 0] {
        assert!(!frees_leak_sentinel(|| doodleart_buf_free(DoodleArtBuf { len: wrong, ..buf })), "len {wrong}");
        assert!(is_live(buf), "a wrong length frees nothing");
    }
    assert!(frees_leak_sentinel(|| doodleart_buf_free(buf)), "the reply's block is released");
    assert!(!is_live(buf));
    assert!(!frees_leak_sentinel(|| doodleart_buf_free(buf)), "a second free releases nothing");

    // Memory the core never returned is left alone.
    let mut foreign = [1u8; 4];
    doodleart_buf_free(DoodleArtBuf { ptr: foreign.as_mut_ptr(), len: foreign.len() });
    assert_eq!(foreign, [1; 4]);

    // A real reply: registered until released, its bytes readable until then.
    let reply = doodleart_init();
    assert!(is_live(reply));
    let copy = take(reply);
    assert_eq!(copy[0], 0);
}

// ---- panics -------------------------------------------------------------------------------------------------------

/// Every entry installs the silent hook and contains a panic: INTERNAL for replies and statuses, nothing for
/// doodleart_buf_free, never an unwind into the caller (which would abort the test process).
#[test]
fn every_entry_contains_a_panic_and_installs_the_hook() {
    let none = (ptr::null::<u8>(), 0);
    let internal = Error::Internal.status();
    // SAFETY (every unsafe call below): all pairs are (NULL, 0).
    type ReplyCall = Box<dyn Fn() -> DoodleArtBuf>;
    type StatusCall = Box<dyn Fn() -> i32>;
    // The closures around doodleart_init and doodleart_risk_scan are needed: an extern "C" fn does not implement Fn.
    #[allow(clippy::redundant_closure)]
    let replies: Vec<(&str, ReplyCall)> = vec![
        ("doodleart_init", Box::new(|| doodleart_init())),
        ("doodleart_device_key_id", Box::new(move || unsafe { doodleart_device_key_id(none.0, none.1) })),
        (
            "doodleart_handshake_begin",
            Box::new(move || unsafe { doodleart_handshake_begin(none.0, 0, none.0, 0, none.0, 0) }),
        ),
        ("doodleart_handshake_body", Box::new(move || unsafe { doodleart_handshake_body(1, none.0, 0) })),
        ("doodleart_handshake_finish", Box::new(move || unsafe { doodleart_handshake_finish(1, 200, 0, none.0, 0) })),
        (
            "doodleart_session_seal",
            Box::new(move || unsafe { doodleart_session_seal(1, none.0, 0, none.0, 0, none.0, 0) }),
        ),
        (
            "doodleart_session_response",
            Box::new(move || unsafe { doodleart_session_response(1, 1, 200, none.0, 0, none.0, 0, none.0, 0) }),
        ),
        (
            "doodleart_session_open",
            Box::new(move || unsafe { doodleart_session_open(1, 1, 200, none.0, 0, none.0, 0) }),
        ),
        (
            "doodleart_integrity_hash",
            Box::new(move || unsafe {
                doodleart_integrity_hash(none.0, 0, none.0, 0, none.0, 0, none.0, 0, none.0, 0)
            }),
        ),
        (
            "doodleart_register_message",
            Box::new(move || unsafe { doodleart_register_message(none.0, 0, none.0, 0, none.0, 0, none.0, 0) }),
        ),
        ("doodleart_ios_device_hash", Box::new(move || unsafe { doodleart_ios_device_hash(none.0, 0) })),
        ("doodleart_session_assert_hash", Box::new(move || unsafe { doodleart_session_assert_hash(none.0, 0) })),
        ("doodleart_handshake_assert_hash", Box::new(|| doodleart_handshake_assert_hash(1))),
        ("doodleart_risk_scan", Box::new(|| doodleart_risk_scan())),
    ];
    #[allow(unused_mut)]
    let mut statuses: Vec<(&str, StatusCall)> = vec![
        ("doodleart_handshake_abort", Box::new(|| doodleart_handshake_abort(1))),
        ("doodleart_session_abandon", Box::new(|| doodleart_session_abandon(1, 1))),
        ("doodleart_session_close", Box::new(|| doodleart_session_close(1))),
    ];
    #[cfg(feature = "build-debug")]
    statuses.push(("doodleart_debug_clock_advance_ms", Box::new(|| doodleart_debug_clock_advance_ms(0))));

    let mut covered: Vec<&str> = vec!["doodleart_buf_free"];
    for (name, call) in &replies {
        let checks = test_hooks::hook_checks();
        test_hooks::panic_next_entry();
        let buf = call();
        assert!(!test_hooks::panic_pending(), "{name} did not enter the guard");
        assert_eq!(test_hooks::hook_checks(), checks + 1, "{name} installs the hook");
        assert_eq!(take(buf), [internal], "{name}");
        covered.push(name);
    }
    for (name, call) in &statuses {
        let checks = test_hooks::hook_checks();
        test_hooks::panic_next_entry();
        assert_eq!(call(), i32::from(internal), "{name}");
        assert!(!test_hooks::panic_pending(), "{name} did not enter the guard");
        assert_eq!(test_hooks::hook_checks(), checks + 1, "{name} installs the hook");
        covered.push(name);
    }
    // doodleart_buf_free: the panic happens before the release, so the buffer is still live and can be freed again.
    let buf = doodleart_init();
    let checks = test_hooks::hook_checks();
    test_hooks::panic_next_entry();
    doodleart_buf_free(buf);
    assert!(!test_hooks::panic_pending());
    assert_eq!(test_hooks::hook_checks(), checks + 1);
    assert!(is_live(buf));
    take(buf);

    let mut all: Vec<&str> = rust_entries().into_iter().map(|(name, ..)| name).collect();
    all.sort_unstable();
    covered.sort_unstable();
    assert_eq!(covered, all, "every entry is checked");
    assert!(PANIC_HOOK.is_completed());
}

// ---- handles ------------------------------------------------------------------------------------------------------

/// doodleart_handshake_finish with a status outside 100-599: INVALID_ARGUMENT, and the handshake is consumed.
#[test]
fn handshake_finish_refuses_a_status_outside_100_to_599() {
    let device_key_id = text(&envelope_vectors(), "key_id");
    for status in [99, 600, -1, 65_536, i32::MIN] {
        let fields = ok_fields(handshake_begin(Some(DEVICE_ID), Some(&device_key_id), Some(b"2.0.0")));
        let handshake = u64_field(&fields[0]) as i64;
        assert_eq!(status_of(handshake_finish(handshake, status, Some(b"{}"))), Error::InvalidArgument.status());
        assert_eq!(status_of(handshake_finish(handshake, 200, Some(b"{}"))), Error::UnknownHandle.status());
    }
}

#[test]
fn unknown_handles_and_double_close() {
    let unknown = Error::UnknownHandle.status();
    for handle in [0, -1, i64::MIN, 0x7fff_ffff_ffff_fff0] {
        assert_eq!(status_of(handshake_body(handle, Some(&[0x30; 8]))), unknown);
        assert_eq!(status_of(handshake_finish(handle, 200, Some(b"{}"))), unknown);
        assert_eq!(status_of(doodleart_handshake_assert_hash(handle)), unknown);
        assert_eq!(doodleart_handshake_abort(handle), i32::from(unknown));
        assert_eq!(status_of(session_seal(handle, b"GET", b"/api/v1/x", None)), unknown);
        assert_eq!(status_of(session_response(handle, 1, 200, None, None, None)), unknown);
        assert_eq!(status_of(session_open(handle, 1, 200, Some(&[0; 16]))), unknown);
        assert_eq!(doodleart_session_abandon(handle, 1), i32::from(unknown));
        assert_eq!(doodleart_session_close(handle), i32::from(unknown));
    }

    // A handshake: DAAS1 by handle until it is gone; abort twice.
    let device_key_id = text(&envelope_vectors(), "key_id");
    let fields = ok_fields(handshake_begin(Some(DEVICE_ID), Some(&device_key_id), Some(b"2.0.0")));
    let handshake = u64_field(&fields[0]) as i64;
    // The flags are the core's own scan, none added (Swift passes none).
    assert_eq!(fields[2], ok_fields_of(&api::risk_scan(None))[0]);
    let by_handle = ok_raw(doodleart_handshake_assert_hash(handshake));
    assert_eq!(by_handle, integrity_hash::session_assert_client_data_hash(&fields[1]));
    assert_eq!(by_handle, ok_raw(session_assert_hash(Some(&fields[1]))));
    assert_eq!(ok_raw(doodleart_handshake_assert_hash(handshake)), by_handle, "the handshake stays");
    assert_eq!(doodleart_handshake_abort(handshake), 0);
    assert_eq!(doodleart_handshake_abort(handshake), i32::from(unknown));
    assert_eq!(status_of(doodleart_handshake_assert_hash(handshake)), unknown);
}

// ---- sessions against the Go server ------------------------------------------------------------------------------

/// A device registered on the Go peer, then a session opened through the C ABI, with the DAAS1 checks of the
/// handshake on the way. `assertion` builds the X-Integrity-Token from the DAAS1 hash.
fn c_session(peer: &GoPeer, device: &Device, assertion: impl FnOnce(&[u8]) -> Option<String>) -> (i64, String, Value) {
    peer.trust_keys();
    let fields = ok_fields(handshake_begin(
        Some(device.device_id.as_bytes()),
        Some(device.key_id.as_bytes()),
        Some(interop::APP_VERSION.as_bytes()),
    ));
    assert_eq!(fields.len(), 3);
    let handshake = u64_field(&fields[0]) as i64;
    let message = fields[1].clone();
    let by_handle = ok_raw(doodleart_handshake_assert_hash(handshake));
    assert_eq!(ok_raw(session_assert_hash(Some(&message))), by_handle);

    let signature = peer.sign(device, &message);
    let body = ok_raw(handshake_body(handshake, Some(&signature)));
    assert_eq!(status_of(handshake_body(handshake, Some(&signature))), Error::HandshakeState.status());
    assert_eq!(
        ok_raw(doodleart_handshake_assert_hash(handshake)),
        by_handle,
        "the body does not consume the handshake"
    );
    let mut headers = vec![("Content-Type", "application/json".to_owned()), ("Content-Length", body.len().to_string())];
    if let Some(token) = assertion(&by_handle) {
        headers.push(("X-Integrity-Token", token));
    }
    let reply = http(peer.port, "POST", "/api/v1/session/start", &headers, &body);
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    let server_time: i64 = reply.header("x-server-time").unwrap().parse().unwrap();

    let fields = ok_fields(handshake_finish_at(handshake, i32::from(reply.status), server_time, Some(&reply.body)));
    assert_eq!(status_of(doodleart_handshake_assert_hash(handshake)), Error::UnknownHandle.status());
    assert_eq!(status_of(handshake_finish(handshake, 200, Some(&reply.body))), Error::UnknownHandle.status());
    let sid = String::from_utf8(fields[1].clone()).unwrap();
    let info: Value = serde_json::from_slice(&fields[2]).unwrap();
    assert!(info["session_ttl_seconds"].is_u64(), "{info}");
    (u64_field(&fields[0]) as i64, sid, info)
}

/// `doodleart_session_seal` decoded the way Swift decodes it.
fn c_seal(session: i64, method: &str, path: &str, body: &[u8]) -> SealedRequest {
    let fields = ok_fields(session_seal(session, method.as_bytes(), path.as_bytes(), Some(body)));
    assert_eq!(fields.len(), 6);
    SealedRequest {
        seq: u64_field(&fields[0]),
        ts: u64_field(&fields[1]),
        sid: String::from_utf8(fields[2].clone()).unwrap(),
        app_version: String::from_utf8(fields[3].clone()).unwrap(),
        tag: (!fields[4].is_empty()).then(|| String::from_utf8(fields[4].clone()).unwrap()),
        body: fields[5].clone(),
    }
}

/// Seals through the C ABI, sends over raw HTTP the way URLSession frames it, reads the answer through the C ABI.
fn c_exchange(peer: &GoPeer, session: i64, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let request = c_seal(session, method, path, body);
    let reply = http(peer.port, method, path, &sealed_headers(&request, method), &request.body);
    let opened = take(session_response(
        session,
        request.seq as i64,
        i32::from(reply.status),
        reply.header("content-type").map(str::as_bytes),
        reply.header("x-tx-encoding").map(str::as_bytes),
        Some(&reply.body),
    ));
    (reply.status, opened)
}

#[test]
fn full_session_through_the_c_abi_against_the_go_server() {
    let _serial = interop::serial();
    let peer = interop::peer();
    let device = peer.new_device();
    interop::register(peer, &device, |_| None);
    let (session, sid, info) = c_session(peer, &device, |_| None);
    assert_eq!(info["is_anonymous"], true);

    let opened = |reply: &[u8]| -> Value {
        assert_eq!(reply[0], 0, "reply {reply:?}");
        serde_json::from_slice(&reply[1..]).unwrap()
    };
    let (status, reply) = c_exchange(peer, session, "POST", "/api/v1/echo?q=1", b"{\"probe\":1}");
    assert_eq!(status, 200);
    assert_eq!(opened(&reply)["data"], serde_json::json!({ "body": "{\"probe\":1}", "query": "1" }));
    let (status, reply) = c_exchange(peer, session, "GET", "/api/v1/gz", b"");
    assert_eq!((status, opened(&reply)), (200, serde_json::json!({ "big": true })));
    // A sealed answer opens once: the C ABI refuses a second read of the same seq.
    let request = c_seal(session, "GET", "/api/v1/public", b"");
    assert_eq!(request.sid, sid);
    let reply = http(peer.port, "GET", "/api/v1/public", &sealed_headers(&request, "GET"), b"");
    let sealed_type = Some(wire::SEALED_CONTENT_TYPE.as_bytes());
    let seq = request.seq as i64;
    // A status outside 100-599 is INVALID_ARGUMENT here and DECRYPT_FAILED for the low-level open; neither spends it.
    for status in [99, 600, -1, i32::MIN] {
        assert_eq!(status_of(session_response(session, seq, status, sealed_type, None, Some(&reply.body))), 1);
        assert_eq!(status_of(session_open(session, seq, status, Some(&reply.body))), Error::DecryptFailed.status());
    }
    assert_eq!(status_of(session_open(session, seq, 201, Some(&reply.body))), Error::DecryptFailed.status());
    assert_eq!(
        opened(&take(session_response(session, seq, 200, sealed_type, None, Some(&reply.body))))["data"]["public"],
        true
    );
    assert_eq!(
        status_of(session_response(session, seq, 200, sealed_type, None, Some(&reply.body))),
        Error::ReplayedResponse.status()
    );

    let (status, reply) = c_exchange(peer, session, "POST", "/api/v1/session/end", b"");
    assert_eq!((status, opened(&reply)["meta"]["code"].clone()), (200, serde_json::json!(200)));
    // The server forgot the session: a plain 401 with its code, never data.
    let (status, reply) = c_exchange(peer, session, "GET", "/api/v1/public", b"");
    assert_eq!(status, 401);
    assert_eq!(reply[0], Error::UnsealedResponse { status: 0, code: None }.status());
    let fields = unframe(&reply[1..]).unwrap();
    assert_eq!((u64_field(fields[0]), fields[1]), (401, &b"40101010"[..]));

    assert_eq!(doodleart_session_abandon(session, 999), 0);
    assert_eq!(doodleart_session_close(session), 0);
    assert_eq!(doodleart_session_close(session), i32::from(Error::UnknownHandle.status()));
    assert_eq!(status_of(session_seal(session, b"GET", b"/api/v1/public", None)), Error::UnknownHandle.status());
}

/// The App Attest path of the iOS wrapper on the Simulator, against the stub verifier of the Go server: the register
/// message hash goes into the stub attestation, DAAS1 of the handshake into the stub assertion.
#[test]
fn app_attest_stub_through_the_c_abi() {
    let _serial = interop::serial();
    let peer = interop::peer();
    let device = peer.new_device();
    let key_id = "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=";
    let registered = interop::register(peer, &device, |hash| Some(interop::stub_attestation(key_id, hash)));
    assert_eq!(registered["trust"], "trusted");
    let (session, _, info) = c_session(peer, &device, |hash| Some(format!("doodleart-stub-v1.1.{}", hex_encode(hash))));
    let flags = ok_fields(doodleart_risk_scan())[0].clone();
    let trust = info["trust"].as_str().unwrap();
    if flags.is_empty() {
        assert_eq!(trust, "trusted");
    } else {
        assert_ne!(trust, "trusted", "flags {}", String::from_utf8_lossy(&flags));
    }
    assert_eq!(doodleart_session_close(session), 0);
}

/// The debug clock hook: request ts moves with it, exactly as after a sleep, and a server whose clock did not move
/// refuses the request (409 40901004): what the Swift test of a sleep > 60 s builds on.
#[cfg(feature = "build-debug")]
#[test]
fn debug_clock_advance_moves_the_request_ts() {
    let _serial = interop::serial();
    let peer = interop::peer();
    let device = peer.new_device();
    interop::register(peer, &device, |_| None);
    let (session, _, _) = c_session(peer, &device, |_| None);
    let before = c_seal(session, "GET", "/api/v1/public", b"");
    let reply = http(peer.port, "GET", "/api/v1/public", &sealed_headers(&before, "GET"), b"");
    assert_eq!(reply.status, 200);

    assert_eq!(doodleart_debug_clock_advance_ms(70_000), 0);
    let after = c_seal(session, "GET", "/api/v1/public", b"");
    let moved = after.ts - before.ts;
    assert!((70_000..75_000).contains(&moved), "ts moved {moved} ms");
    let reply = http(peer.port, "GET", "/api/v1/public", &sealed_headers(&after, "GET"), b"");
    assert_eq!((reply.status, interop::meta_code(&reply.body)), (409, 40901004));

    let max = crate::clock::debug_clock::MAX_ADVANCE_MS as i64;
    assert_eq!(doodleart_debug_clock_advance_ms(-1), 1);
    assert_eq!(doodleart_debug_clock_advance_ms(max + 1), 1);
    assert_eq!(doodleart_debug_clock_advance_ms(i64::MIN), 1);
    let unchanged = c_seal(session, "GET", "/api/v1/public", b"").ts - after.ts;
    assert!(unchanged < 5_000, "a refused advance moves nothing ({unchanged} ms)");
    assert_eq!(doodleart_session_close(session), 0);
}
