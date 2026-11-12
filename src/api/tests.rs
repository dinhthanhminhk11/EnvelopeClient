//! The app-facing byte formats, end to end against a server written with the same wire primitives (the Go server
//! itself is src/interop_tests.rs).

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

use super::*;
use crate::codec::{b64url_decode, b64url_decode_exact, b64url_encode, hex_decode};
use crate::envelope::wire::{SessionKeys, DIR_C2S, DIR_S2C};
use crate::test_support::{envelope_vectors, frees_leak_sentinel, SECRET_SENTINEL};

const SEED: [u8; 32] = [7; 32];
const KID: &str = "test-kid";
const DEVICE_KEY_ID: &str = "fVjFucbF6WJmoVSlWverWQKikt99mFOm2YMBW17yajs";

fn use_test_keys() {
    let public = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    TEST_SERVER_KEYS.with(|keys| *keys.borrow_mut() = Some(vec![(KID.to_owned(), public)]));
}

fn ok_fields(reply: &[u8]) -> Vec<Vec<u8>> {
    let (status, fields) = split_reply(reply).expect("framed reply");
    assert_eq!(status, STATUS_OK, "reply {reply:?}");
    fields.into_iter().map(<[u8]>::to_vec).collect()
}

fn ok_raw(reply: &[u8]) -> Vec<u8> {
    assert_eq!(reply[0], STATUS_OK, "reply {reply:?}");
    reply[1..].to_vec()
}

fn u64_field(field: &[u8]) -> u64 {
    u64::from_be_bytes(field.try_into().expect("8-byte number"))
}

fn vector_device_sig() -> Vec<u8> {
    hex_decode(envelope_vectors()["start_signature"].as_str().unwrap()).unwrap()
}

struct ServerSession {
    sid: String,
    c2s: [u8; 32],
    s2c: [u8; 32],
}

/// What devicesession.Usecase.Start does once the signature verified (signature checking is the Go interop test's job).
fn server_answer(request_body: &[u8], server_time: u64) -> (Vec<u8>, ServerSession) {
    let request: Value = serde_json::from_slice(request_body).unwrap();
    let client_pub = b64url_decode_exact::<32>(request["client_pub"].as_str().unwrap()).unwrap();
    let server_secret = StaticSecret::from([9u8; 32]);
    let server_pub = PublicKey::from(&server_secret).to_bytes();
    let shared = server_secret.diffie_hellman(&PublicKey::from(client_pub));
    let sid = b64url_encode(&[3u8; 16]);
    let ts = request["ts"].as_u64().unwrap();
    let device_key_id = request["device_key_id"].as_str().unwrap();
    let transcript = wire::transcript(&client_pub, device_key_id, &server_pub, &sid, ts, server_time, KID);
    let signature = SigningKey::from_bytes(&SEED).sign(&transcript).to_bytes();
    let keys = wire::derive_session_keys(shared.as_bytes(), &transcript);
    let info = br#"{"session_ttl_seconds":86400,"idle_ttl_seconds":7200,"min_app_version":"2.0.0","trust":"limited","user_id":"u","is_anonymous":true}"#;
    let sealed = wire::seal(&keys.s2c, DIR_S2C, 0, &wire::start_response_aad(&sid), info).unwrap();
    let response = serde_json::json!({ "meta": { "code": 200, "message": "Successful" }, "data": {
        "v": 1, "sid": sid, "server_pub": b64url_encode(&server_pub), "kid": KID, "server_time": server_time,
        "signature": b64url_encode(&signature), "sealed": b64url_encode(&sealed),
    }});
    (serde_json::to_vec(&response).unwrap(), ServerSession { sid, c2s: *keys.c2s, s2c: *keys.s2c })
}

fn begin(extra: Option<&[u8]>) -> (i64, Vec<u8>, String) {
    let fields = ok_fields(&handshake_begin(
        Some(b"8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30"),
        Some(DEVICE_KEY_ID.as_bytes()),
        Some(b"2.0.0"),
        extra,
    ));
    let handle = u64_field(&fields[0]);
    assert!(handle > 0 && handle <= i64::MAX as u64);
    (handle as i64, fields[1].clone(), String::from_utf8(fields[2].clone()).unwrap())
}

#[test]
fn full_session_through_the_byte_api() {
    use_test_keys();
    let (handshake, message, flags_csv) = begin(Some(b"debugger,banned_device,restore_blocked,nope"));

    // The message Kotlin signs is the deviceSig frame with this handshake's values.
    let parts = crate::codec::unframe(&message).unwrap();
    assert_eq!(parts[0], b"doodle/v1/start");
    assert_eq!(parts[1].len(), 32);
    assert_eq!(parts[3], b"8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30");
    assert_eq!(parts[4], DEVICE_KEY_ID.as_bytes());
    assert_eq!(parts[6], flags_csv.as_bytes());
    assert!(flags_csv.split(',').any(|flag| flag == "debugger"));
    assert!(
        !flags_csv.contains("banned_device") && !flags_csv.contains("restore_blocked") && !flags_csv.contains("nope")
    );

    let body = ok_raw(&handshake_body(handshake, Some(&vector_device_sig())));
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(b64url_decode(request["client_pub"].as_str().unwrap()).unwrap(), parts[1]);
    assert_eq!(request["ts"].as_u64().unwrap(), u64_field(parts[2]));
    // One body per handshake.
    assert_eq!(handshake_body(handshake, Some(&vector_device_sig())), vec![Error::HandshakeState.status()]);

    let server_time = clock::wall_ms() + 5_000;
    let (response, server) = server_answer(&body, server_time);
    let fields = ok_fields(&handshake_finish(handshake, 200, 0, Some(&response)));
    let session = u64_field(&fields[0]) as i64;
    assert_eq!(fields[1], server.sid.as_bytes());
    let info: Value = serde_json::from_slice(&fields[2]).unwrap();
    assert_eq!(info["trust"], "limited");
    // The handshake handle is gone.
    assert_eq!(handshake_finish(handshake, 200, 0, Some(&response)), vec![Error::UnknownHandle.status()]);

    // POST with a body.
    let sealed = ok_fields(&session_seal(
        session,
        Some(b"POST"),
        Some(b"/api/v1/assets/download-urls"),
        Some(br#"{"assetIds":["a"]}"#),
    ));
    let (seq, ts) = (u64_field(&sealed[0]), u64_field(&sealed[1]));
    assert_eq!(seq, 1);
    assert!(ts.abs_diff(server_time) < 60_000, "ts follows server time");
    assert_eq!(sealed[2], server.sid.as_bytes());
    assert_eq!(sealed[3], b"2.0.0");
    assert!(sealed[4].is_empty() && !sealed[5].is_empty());
    let aad = wire::request_aad("POST", "/api/v1/assets/download-urls", &server.sid, seq, ts, "2.0.0");
    assert_eq!(wire::open(&server.c2s, DIR_C2S, seq, &aad, &sealed[5]).unwrap(), br#"{"assetIds":["a"]}"#);

    let answer =
        wire::seal(&server.s2c, DIR_S2C, seq, &wire::response_aad(&server.sid, seq, 201, ""), b"{\"ok\":true}")
            .unwrap();
    assert_eq!(ok_raw(&session_open(session, seq as i64, 201, None, Some(&answer))), b"{\"ok\":true}");
    assert_eq!(session_open(session, seq as i64, 201, None, Some(&answer)), vec![Error::ReplayedResponse.status()]);

    // GET without a body: tag in X-Tx-Tag.
    let sealed = ok_fields(&session_seal(session, Some(b"GET"), Some(b"/api/v1/themes?page=2"), None));
    let (seq, ts) = (u64_field(&sealed[0]), u64_field(&sealed[1]));
    assert_eq!(seq, 2);
    assert!(sealed[5].is_empty());
    let tag = b64url_decode(std::str::from_utf8(&sealed[4]).unwrap()).unwrap();
    let aad = wire::request_aad("GET", "/api/v1/themes?page=2", &server.sid, seq, ts, "2.0.0");
    assert_eq!(wire::open(&server.c2s, DIR_C2S, seq, &aad, &tag).unwrap(), b"");
    let tampered = {
        let mut answer =
            wire::seal(&server.s2c, DIR_S2C, seq, &wire::response_aad(&server.sid, seq, 200, ""), b"[]").unwrap();
        answer[0] ^= 1;
        answer
    };
    assert_eq!(session_open(session, seq as i64, 200, None, Some(&tampered)), vec![Error::DecryptFailed.status()]);
    assert_eq!(session_abandon(session, seq as i64), 0);
    assert_eq!(session_open(session, seq as i64, 200, None, Some(&tampered)), vec![Error::ReplayedResponse.status()]);

    assert_eq!(session_seal(session, Some(b"get"), Some(b"/api/v1/x"), None), vec![Error::InvalidArgument.status()]);
    assert_eq!(session_close(session), 0);
    assert_eq!(session_close(session), i32::from(Error::UnknownHandle.status()));
    assert_eq!(session_seal(session, Some(b"GET"), Some(b"/api/v1/x"), None), vec![Error::UnknownHandle.status()]);
}

#[test]
fn rejected_handshake_reports_the_server_error() {
    use_test_keys();
    let (handshake, _, _) = begin(None);
    ok_raw(&handshake_body(handshake, Some(&vector_device_sig())));
    let reply = handshake_finish(
        handshake,
        409,
        1_793_000_000_000,
        Some(br#"{"meta":{"code":40901004,"message":"Replay detected"}}"#),
    );
    let (status, fields) = split_reply(&reply).unwrap();
    assert_eq!(status, Error::ServerRejected { status: 0, code: None, server_time: None }.status());
    assert_eq!(fields, vec![&409u64.to_be_bytes()[..], b"40901004", &1_793_000_000_000u64.to_be_bytes()[..]]);
    assert_eq!(handshake_finish(handshake, 200, 0, Some(b"{}")), vec![Error::UnknownHandle.status()]);

    // Every handshake gets its own ephemeral key: a retry after 409 / 429 never reuses client_pub.
    let (first, message_a, _) = begin(None);
    let (second, message_b, _) = begin(None);
    let pub_a = crate::codec::unframe(&message_a).unwrap()[1].to_vec();
    let pub_b = crate::codec::unframe(&message_b).unwrap()[1].to_vec();
    assert_ne!(pub_a, pub_b);
    assert_ne!(first, second);
    assert_eq!(handshake_abort(first), 0);
    assert_eq!(handshake_abort(first), i32::from(Error::UnknownHandle.status()));
    assert_eq!(handshake_abort(second), 0);

    // finish before the body is out of order, and consumes the handshake.
    let (third, _, _) = begin(None);
    assert_eq!(handshake_finish(third, 200, 0, Some(b"{}")), vec![Error::HandshakeState.status()]);
}

#[test]
fn bad_server_signature_is_refused() {
    use_test_keys();
    let (handshake, _, _) = begin(None);
    let body = ok_raw(&handshake_body(handshake, Some(&vector_device_sig())));
    let (response, _) = server_answer(&body, clock::wall_ms());
    // Same answer, but the client only trusts another key.
    TEST_SERVER_KEYS.with(|keys| {
        *keys.borrow_mut() = Some(vec![(KID.to_owned(), SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())])
    });
    assert_eq!(handshake_finish(handshake, 200, 0, Some(&response)), vec![Error::BadServerSignature.status()]);
}

#[test]
fn argument_validation() {
    use_test_keys();
    const ID: &[u8] = b"8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30";
    assert_eq!(handshake_begin(Some(b"bad id!"), Some(DEVICE_KEY_ID.as_bytes()), Some(b"2.0.0"), None), vec![1]);
    assert_eq!(
        handshake_begin(
            Some(b"8B0E5D1C-3F7A-4C2E-9A61-2D4B7C9E1F30"),
            Some(DEVICE_KEY_ID.as_bytes()),
            Some(b"2.0.0"),
            None
        ),
        vec![1]
    );
    assert_eq!(handshake_begin(Some(ID), Some(b"short"), Some(b"2.0.0"), None), vec![1]);
    assert_eq!(handshake_begin(Some(ID), Some(DEVICE_KEY_ID.as_bytes()), Some(b"v2"), None), vec![1]);
    assert_eq!(handshake_begin(None, Some(DEVICE_KEY_ID.as_bytes()), Some(b"2.0.0"), None), vec![1]);
    assert_eq!(handshake_body(0, Some(b"x")), vec![Error::UnknownHandle.status()]);
    assert_eq!(handshake_body(-5, Some(b"x")), vec![Error::UnknownHandle.status()]);
    let (handshake, _, _) = begin(None);
    assert_eq!(handshake_body(handshake, Some(b"not der")), vec![1]);
    assert_eq!(handshake_abort(handshake), 0);
    assert_eq!(session_open(12345, 1, 200, None, Some(&[0; 16])), vec![Error::UnknownHandle.status()]);
}

#[test]
fn init_and_device_key_id() {
    use_test_keys();
    let fields = ok_fields(&init(Some(b"/data/app/~~x==/com.cem.theme.icon.widget-y==/base.apk")));
    assert_eq!(fields[0], build_config::BUILD_TYPE.as_bytes());
    assert_eq!(fields[1], env!("CARGO_PKG_VERSION").as_bytes());
    assert_eq!(fields[2], KID.as_bytes());

    let vectors = envelope_vectors();
    let spki = hex_decode(vectors["device_spki"].as_str().unwrap()).unwrap();
    assert_eq!(ok_raw(&device_key_id(Some(&spki))), DEVICE_KEY_ID.as_bytes());
    assert_eq!(device_key_id(Some(&spki[1..])), vec![1]);
}

#[test]
fn integrity_and_signals_and_risk() {
    let vectors = crate::test_support::attest_vectors();
    let case = &vectors["integrity"][0];
    let text = |name: &str| case[name].as_str().unwrap().as_bytes().to_vec();
    let fields = ok_fields(&integrity_hash(
        Some(&text("method")),
        Some(&text("path_with_query")),
        Some(&text("request_id")),
        Some(&text("sid")),
        Some(&text("body")),
    ));
    assert_eq!(fields[0], text("request_id"));
    assert_eq!(fields[1], text("request_hash_b64"));
    let generated =
        ok_fields(&integrity_hash(Some(b"POST"), Some(b"/api/v1/devices/register"), None, None, Some(b"{}")));
    assert!(crate::codec::is_uuid(std::str::from_utf8(&generated[0]).unwrap()));

    let sensors = device_signals::encode_sensors(&[device_signals::HwSensor {
        sensor_type: 1,
        vendor: "Bosch".into(),
        name: "BMI160".into(),
    }]);
    let json: Value = serde_json::from_slice(&ok_raw(&device_signals(
        Some(b"9774d56d682e549c"),
        None,
        Some(b"unsupported"),
        Some(&sensors),
    )))
    .unwrap();
    assert_eq!(json["drmStatus"], "unsupported");
    assert_eq!(json["androidIdHash"].as_str().unwrap().len(), 64);
    assert_eq!(device_signals(None, None, None, Some(b"\x00\x00\x00\x09garbage")), vec![1]);

    let fields = ok_fields(&risk_scan(Some(b"emulator")));
    assert_eq!(fields.len(), 2);
    assert!(std::str::from_utf8(&fields[0]).unwrap().split(',').any(|flag| flag == "emulator"));
}

/// A session opened through the byte API against `server_answer`, ready for sealed requests.
fn open_session() -> (i64, ServerSession) {
    use_test_keys();
    let (handshake, _, _) = begin(None);
    let body = ok_raw(&handshake_body(handshake, Some(&vector_device_sig())));
    let (response, server) = server_answer(&body, clock::wall_ms());
    let fields = ok_fields(&handshake_finish(handshake, 200, 0, Some(&response)));
    (u64_field(&fields[0]) as i64, server)
}

fn seal_get(session: i64, path: &str) -> u64 {
    u64_field(&ok_fields(&session_seal(session, Some(b"GET"), Some(path.as_bytes()), None))[0])
}

const SEALED: &[u8] = b"application/vnd.doodle.sealed";

/// For a sealed request, only a sealed answer that opens is data. A man in the middle (TLS intercepted on a rooted
/// device) answering `200 application/json` gets `UNSEALED_RESPONSE`, never its payload.
#[test]
fn unsealed_answers_are_never_data() {
    let (session, server) = open_session();
    let seal = |seq: u64, status: u16, plaintext: &[u8]| {
        wire::seal(&server.s2c, DIR_S2C, seq, &wire::response_aad(&server.sid, seq, u64::from(status), ""), plaintext)
            .unwrap()
    };

    // Sealed answer: opened once, content-type matched without case or parameters.
    let seq = seal_get(session, "/api/v1/themes");
    let answer = seal(seq, 200, b"{\"items\":[]}");
    let reply = session_response(
        session,
        seq as i64,
        200,
        Some(b"Application/Vnd.Doodle.Sealed; charset=binary"),
        None,
        Some(&answer),
    );
    assert_eq!(ok_raw(&reply), b"{\"items\":[]}");
    assert_eq!(
        session_response(session, seq as i64, 200, Some(SEALED), None, Some(&answer)),
        vec![Error::ReplayedResponse.status()]
    );

    // Forged plain 200: refused, no payload, and the seq is spent (a sealed answer for it no longer opens).
    let seq = seal_get(session, "/api/v1/assets/download-urls");
    let forged = br#"{"items":[{"url":"https://evil.example/a.zip"}]}"#;
    for content_type in
        [Some(&b"application/json"[..]), Some(b"text/plain"), Some(b"application/vnd.doodle.sealedx"), None]
    {
        let reply = session_response(session, seq as i64, 200, content_type, None, Some(forged));
        let (status, fields) = split_reply(&reply).unwrap();
        assert_eq!(status, 14, "{content_type:?}");
        assert_eq!(fields, vec![&200u64.to_be_bytes()[..], b""]);
    }
    let genuine = seal(seq, 200, b"{}");
    assert_eq!(
        session_response(session, seq as i64, 200, Some(SEALED), None, Some(&genuine)),
        vec![Error::ReplayedResponse.status()]
    );

    // Envelope errors are plain JSON: their code is reported for the retry decision, still as an error.
    for (status, body, code) in [
        (401, &br#"{"meta":{"code":40101010,"message":"Session unknown or expired"}}"#[..], "40101010"),
        (409, br#"{"meta":{"code":40901004}}"#, "40901004"),
        (400, br#"{"meta":{"code":40001005}}"#, "40001005"),
        (429, br#"{"meta":{"code":42900001}}"#, "42900001"),
        (502, b"<html>Bad gateway</html>", ""),
        (404, br#"{"meta":{"code":"404"}}"#, ""),
        (500, br#"{"meta":{"code":1234567890}}"#, ""),
    ] {
        let seq = seal_get(session, "/api/v1/x");
        let reply =
            session_response(session, seq as i64, status, Some(b"application/json; charset=utf-8"), None, Some(body));
        let (reply_status, fields) = split_reply(&reply).unwrap();
        assert_eq!(reply_status, 14);
        assert_eq!(fields, vec![&u64::from(status as u16).to_be_bytes()[..], code.as_bytes()], "{status}");
    }
    // A 2xx/3xx plain body is not even parsed for a code.
    let seq = seal_get(session, "/api/v1/x");
    let reply = session_response(
        session,
        seq as i64,
        302,
        Some(b"application/json"),
        None,
        Some(br#"{"meta":{"code":30200001}}"#),
    );
    assert_eq!(split_reply(&reply).unwrap().1[1], b"");

    // A sealed answer that fails to open is an error, and spends the seq too.
    let seq = seal_get(session, "/api/v1/y");
    let mut tampered = seal(seq, 200, b"{}");
    tampered[0] ^= 1;
    assert_eq!(
        session_response(session, seq as i64, 200, Some(SEALED), None, Some(&tampered)),
        vec![Error::DecryptFailed.status()]
    );
    assert_eq!(
        session_response(session, seq as i64, 200, Some(SEALED), None, Some(&seal(seq, 200, b"{}"))),
        vec![Error::ReplayedResponse.status()]
    );

    assert_eq!(session_response(session, 1, 99, Some(SEALED), None, None), vec![Error::InvalidArgument.status()]);
    assert_eq!(session_close(session), 0);
    assert_eq!(session_response(session, 1, 200, Some(SEALED), None, None), vec![Error::UnknownHandle.status()]);
}

/// An HTTP status outside 100-599 (or outside i32 → u16): `sessionOpen` answers DECRYPT_FAILED and keeps the seq
/// pending (the reply bytes of the live Android natives, which the C ABI header documents); `sessionResponse` and
/// `handshakeFinish` answer INVALID_ARGUMENT, the former before the seq is looked at, the latter after consuming the
/// handshake.
#[test]
fn http_status_outside_100_to_599() {
    let (session, server) = open_session();
    let seq = seal_get(session, "/api/v1/themes");
    let answer =
        wire::seal(&server.s2c, DIR_S2C, seq, &wire::response_aad(&server.sid, seq, 200, ""), b"{\"items\":[]}")
            .unwrap();
    for status in [99, 600, -1, 65_536, 65_736, i32::MIN, i32::MAX] {
        assert_eq!(
            session_open(session, seq as i64, status, None, Some(&answer)),
            vec![Error::DecryptFailed.status()],
            "{status}"
        );
        assert_eq!(
            session_response(session, seq as i64, status, Some(SEALED), None, Some(&answer)),
            vec![Error::InvalidArgument.status()],
            "{status}"
        );
    }
    // Still pending after all of them: the genuine status opens it, once.
    assert_eq!(ok_raw(&session_open(session, seq as i64, 200, None, Some(&answer))), b"{\"items\":[]}");
    assert_eq!(session_open(session, seq as i64, 200, None, Some(&answer)), vec![Error::ReplayedResponse.status()]);
    assert_eq!(session_close(session), 0);

    for status in [99, 600, -1, 65_536] {
        let (handshake, _, _) = begin(None);
        assert_eq!(
            handshake_finish(handshake, status, 0, Some(b"{}")),
            vec![Error::InvalidArgument.status()],
            "{status}"
        );
        assert_eq!(handshake_finish(handshake, 200, 0, Some(b"{}")), vec![Error::UnknownHandle.status()], "{status}");
    }
}

/// The registry's tables hold pointers, never key bytes.
const _: () = assert!(std::mem::size_of::<Slot<Box<Session>>>() <= 16);
const _: () = assert!(std::mem::size_of::<Slot<Box<PendingHandshake>>>() <= 16);

/// Closing a session or finishing a handshake leaves no copy of the keys in memory returned to the allocator: not in
/// the hash table (inline values would leave their old bucket bytes behind) and not in a box freed after its content
/// was moved out (a `finish(self)` would do that).
#[test]
fn registry_leaves_no_key_bytes_in_freed_memory() {
    let leaked = frees_leak_sentinel(|| {
        let mut registry = Registry::default();
        for handle in 1..=8u64 {
            let keys = SessionKeys {
                c2s: zeroize::Zeroizing::new(SECRET_SENTINEL),
                s2c: zeroize::Zeroizing::new(SECRET_SENTINEL),
            };
            let session = Session::new(b64url_encode(&[handle as u8; 16]), "2.0.0".into(), keys, 1, 0, None);
            registry.sessions.insert(handle, Slot { value: Box::new(session), created_mono: handle });
        }
        // What session_close and evict_oldest do.
        registry.sessions.remove(&1);
        evict_oldest(&mut registry.sessions);
        registry.sessions.clear();
        drop(registry);
    });
    assert!(!leaked, "session keys survived in freed memory");

    let leaked = frees_leak_sentinel(|| {
        let mut registry = Registry::default();
        let params = HandshakeParams {
            device_id: "8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30".into(),
            device_key_id: DEVICE_KEY_ID.into(),
            app_version: "2.0.0".into(),
            risk_flags: Vec::new(),
            ts: 1_700_000_000_000,
        };
        let pending = PendingHandshake::from_secret(SECRET_SENTINEL, params).unwrap();
        registry.handshakes.insert(1, Slot { value: Box::new(pending), created_mono: 0 });
        // What handshake_finish does with the removed handshake.
        let pending = registry.handshakes.remove(&1).unwrap().value;
        let keys = ServerKeys::from_raw([(KID, SigningKey::from_bytes(&SEED).verifying_key().to_bytes())]).unwrap();
        let clock = ClockSample { wall_ms: 0, mono_ms: 0 };
        assert!(pending.finish(&keys, 200, None, b"{}", clock).is_err());
        drop(pending);
        drop(registry);
    });
    assert!(!leaked, "the ephemeral X25519 secret survived in freed memory");
}
