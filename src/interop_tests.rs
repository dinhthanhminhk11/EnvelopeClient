//! Interop with the real Go server code: the handshake and sealed routes of the app service (controllers,
//! EnvelopeMiddleware, devicesession usecase, App Attest stub verifier) served by the Go interop peer
//! (server/src/app/routers/interop_peer_test.go, [`GoPeer`]) over in-memory stores. Raw HTTP/1.1, framed the way
//! URLSession and OkHttp frame it, both directions: requests the core seals are opened by Go, answers Go seals are
//! opened (or refused) by the core. The vector tests (src/envelope/vector_tests.rs) pin the bytes; these pin the JSON
//! shapes, headers, error codes and the order of the server checks.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};

use crate::api;
use crate::codec::{b64url_encode, hex_decode, hex_encode, unframe};
use crate::envelope::{wire, SealedRequest};
use crate::error::Error;
use crate::test_support::GoPeer;

pub(crate) const APP_VERSION: &str = "2.1.0";

/// A device key held by the peer (it plays the Secure Enclave): the core never sees the private key.
pub(crate) struct Device {
    pub(crate) id: String,
    pub(crate) spki: Vec<u8>,
    pub(crate) key_id: String,
    /// The lowercase UUID the app generated once.
    pub(crate) device_id: String,
}

pub(crate) fn peer() -> &'static GoPeer {
    GoPeer::shared()
}

/// The tests that talk to the peer run one at a time: they move its clock and the core's debug clock, and share its
/// per-IP rate limits.
pub(crate) fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl GoPeer {
    pub(crate) fn post_json(&self, path: &str, body: &Value) -> HttpReply {
        let body = serde_json::to_vec(body).unwrap();
        let headers = [("Content-Type", "application/json".to_owned()), ("Content-Length", body.len().to_string())];
        http(self.port, "POST", path, &headers, &body)
    }

    fn peer_json(&self, path: &str, body: &Value) -> Value {
        let reply = self.post_json(path, body);
        assert_eq!(reply.status, 200, "{path}: {}", String::from_utf8_lossy(&reply.body));
        serde_json::from_slice(&reply.body).unwrap()
    }

    pub(crate) fn new_device(&self) -> Device {
        let reply = self.peer_json("/peer/devices", &json!({}));
        let spki = hex_decode(reply["spki_hex"].as_str().unwrap()).unwrap();
        let key_id = api_text(&api::device_key_id(Some(&spki)));
        assert_eq!(key_id, wire::device_key_id(&spki));
        let device_id = crate::codec::uuid_v4(rand_bytes());
        Device { id: reply["id"].as_str().unwrap().to_owned(), spki, key_id, device_id }
    }

    pub(crate) fn sign(&self, device: &Device, message: &[u8]) -> Vec<u8> {
        let reply = self.peer_json("/peer/sign", &json!({ "id": device.id, "message_hex": hex_encode(message) }));
        hex_decode(reply["signature_hex"].as_str().unwrap()).unwrap()
    }

    /// Moves the server clock (negative: back), under [`serial`].
    pub(crate) fn advance(&self, ms: i64) {
        self.peer_json("/peer/advance", &json!({ "ms": ms }));
    }

    /// The trusted key set of this peer, as the embedded keys of a build would hold it.
    pub(crate) fn trust_keys(&self) {
        api::TEST_SERVER_KEYS.with(|keys| *keys.borrow_mut() = Some(vec![(self.kid.clone(), self.signing_public)]));
    }
}

fn rand_bytes() -> [u8; 16] {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Fields of a successful byte API reply.
pub(crate) fn ok_fields(reply: &[u8]) -> Vec<Vec<u8>> {
    let (status, payload) = reply.split_first().unwrap();
    assert_eq!(*status, api::STATUS_OK, "reply status {status}: {:?}", api::split_reply(reply));
    unframe(payload).unwrap().into_iter().map(<[u8]>::to_vec).collect()
}

fn api_text(reply: &[u8]) -> String {
    let (status, payload) = reply.split_first().unwrap();
    assert_eq!(*status, api::STATUS_OK);
    String::from_utf8(payload.to_vec()).unwrap()
}

pub(crate) fn u64_field(field: &[u8]) -> u64 {
    u64::from_be_bytes(field.try_into().unwrap())
}

/// The `data` of a plain or opened `{meta, data}` envelope.
pub(crate) fn data_of(body: &[u8]) -> Value {
    let value: Value =
        serde_json::from_slice(body).unwrap_or_else(|_| panic!("JSON: {}", String::from_utf8_lossy(body)));
    assert_eq!(value["meta"]["code"], 200, "{value}");
    value["data"].clone()
}

pub(crate) fn meta_code(body: &[u8]) -> u64 {
    let value: Value = serde_json::from_slice(body).unwrap();
    value["meta"]["code"].as_u64().unwrap()
}

/// `POST /api/v1/auth/challenge` then `POST /api/v1/devices/register` with the register message of the byte API.
/// `attestation` is the JSON object of the body, if any.
pub(crate) fn register(peer: &GoPeer, device: &Device, attestation: impl FnOnce(&[u8; 32]) -> Option<Value>) -> Value {
    let challenge = peer.post_json("/api/v1/auth/challenge", &json!({}));
    assert_eq!(challenge.status, 200);
    let nonce = data_of(&challenge.body)["nonce"].as_str().unwrap().to_owned();
    let fields = ok_fields(&api::register_message(
        Some(nonce.as_bytes()),
        Some(device.device_id.as_bytes()),
        Some(device.key_id.as_bytes()),
        Some(b"ios"),
    ));
    let (message, hash) = (&fields[0], &fields[1]);
    let mut body = json!({
        "nonce": nonce,
        "device": { "device_id": device.device_id, "platform": "ios", "app_version": APP_VERSION },
        "device_public_key": b64url_encode(&device.spki),
        "signature": b64url_encode(&peer.sign(device, message)),
    });
    if let Some(attestation) = attestation(&hash.as_slice().try_into().unwrap()) {
        body["attestation"] = attestation;
    }
    let reply = peer.post_json("/api/v1/devices/register", &body);
    assert_eq!(reply.status, 200, "register: {}", String::from_utf8_lossy(&reply.body));
    data_of(&reply.body)
}

/// The stub attestation of the Simulator for `key_id` (docs/app-security.md section 2b).
pub(crate) fn stub_attestation(key_id: &str, client_data_hash: &[u8; 32]) -> Value {
    let payload = json!({ "key_id": key_id, "client_data_hash": hex_encode(client_data_hash) }).to_string();
    json!({ "type": "app_attest", "key_id": key_id, "data": format!("doodleart-stub-v1.{}", b64url_encode(payload.as_bytes())) })
}

pub(crate) struct Opened {
    pub(crate) session: i64,
    pub(crate) sid: String,
    pub(crate) info: Value,
    pub(crate) flags_csv: String,
}

/// A whole handshake through the byte API. `assertion` builds the `X-Integrity-Token` from the DAAS1 hash.
pub(crate) fn start_with(peer: &GoPeer, device: &Device, assertion: impl FnOnce(&[u8]) -> Option<String>) -> Opened {
    let reply = start_raw(peer, device, assertion);
    let fields = ok_fields(&reply.1);
    Opened {
        session: u64_field(&fields[0]) as i64,
        sid: String::from_utf8(fields[1].clone()).unwrap(),
        info: serde_json::from_slice(&fields[2]).unwrap(),
        flags_csv: reply.0,
    }
}

pub(crate) fn start(peer: &GoPeer, device: &Device) -> Opened {
    start_with(peer, device, |_| None)
}

/// Begins, signs, sends and finishes a handshake; returns the risk flags CSV and the finish reply.
fn start_raw(peer: &GoPeer, device: &Device, assertion: impl FnOnce(&[u8]) -> Option<String>) -> (String, Vec<u8>) {
    peer.trust_keys();
    let begin = ok_fields(&api::handshake_begin(
        Some(device.device_id.as_bytes()),
        Some(device.key_id.as_bytes()),
        Some(APP_VERSION.as_bytes()),
        None,
    ));
    let handshake = u64_field(&begin[0]) as i64;
    let (message, flags_csv) = (&begin[1], String::from_utf8(begin[2].clone()).unwrap());
    let assert_hash = crate::integrity_hash::session_assert_client_data_hash(message);
    let body = ok_fields_raw(&api::handshake_body(handshake, Some(&peer.sign(device, message))));
    let mut headers = vec![("Content-Type", "application/json".to_owned()), ("Content-Length", body.len().to_string())];
    if let Some(token) = assertion(&assert_hash) {
        headers.push(("X-Integrity-Token", token));
    }
    let reply = http(peer.port, "POST", "/api/v1/session/start", &headers, &body);
    let server_time = reply.header("x-server-time").map_or(0, |value| value.parse::<i64>().unwrap());
    (flags_csv, api::handshake_finish(handshake, i32::from(reply.status), server_time, Some(&reply.body)))
}

fn ok_fields_raw(reply: &[u8]) -> Vec<u8> {
    let (status, payload) = reply.split_first().unwrap();
    assert_eq!(*status, api::STATUS_OK);
    payload.to_vec()
}

pub(crate) fn api_seal(session: i64, method: &str, path: &str, body: &[u8]) -> SealedRequest {
    let fields = ok_fields(&api::session_seal(session, Some(method.as_bytes()), Some(path.as_bytes()), Some(body)));
    let tag = String::from_utf8(fields[4].clone()).unwrap();
    SealedRequest {
        seq: u64_field(&fields[0]),
        ts: u64_field(&fields[1]),
        sid: String::from_utf8(fields[2].clone()).unwrap(),
        app_version: String::from_utf8(fields[3].clone()).unwrap(),
        tag: (!tag.is_empty()).then_some(tag),
        body: fields[5].clone(),
    }
}

/// Headers of a sealed request as the apps send them (URLSession, OkHttp): `X-Tx-*`, and either `X-Tx-Tag` with no
/// body and no Content-Type, or the sealed media type.
pub(crate) fn sealed_headers(sealed: &SealedRequest, method: &str) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("X-Tx-Session", sealed.sid.clone()),
        ("X-Tx-Seq", sealed.seq.to_string()),
        ("X-Tx-Ts", sealed.ts.to_string()),
        ("X-App-Version", sealed.app_version.clone()),
        // URLSession always offers gzip: the server then compresses large plaintexts inside the seal.
        ("Accept-Encoding", "gzip, deflate, br".to_owned()),
    ];
    match &sealed.tag {
        Some(tag) => {
            headers.push(("X-Tx-Tag", tag.clone()));
            if !matches!(method, "GET" | "HEAD") {
                headers.push(("Content-Length", "0".into()));
            }
        }
        None => {
            headers.push(("Content-Type", wire::SEALED_CONTENT_TYPE.into()));
            headers.push(("Content-Length", sealed.body.len().to_string()));
        }
    }
    headers
}

pub(crate) struct HttpReply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl HttpReply {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }
}

/// One HTTP/1.1 exchange over a fresh connection (`Connection: close`), exact bytes on the wire.
pub(crate) fn http(port: u16, method: &str, path: &str, headers: &[(&str, String)], body: &[u8]) -> HttpReply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    // One write: a server that answers before reading a body sent apart may reset the connection.
    stream.write_all(&[head.as_bytes(), body].concat()).unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
            // A reset after the whole answer arrived (Go closing with an unread body) is not a failure.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset && complete(&raw) => break,
            Err(error) => panic!("{method} {path}: {error} after {} bytes", raw.len()),
        }
    }

    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("HTTP head");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|line| line.split(' ').nth(1)).and_then(|code| code.parse().ok()).unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let reply = HttpReply { status, headers, body: Vec::new() };
    if reply.header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        body = dechunk(&body);
    }
    HttpReply { body, ..reply }
}

/// A head and a body of its Content-Length.
fn complete(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    head.lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|length| length.trim().parse::<usize>().ok())
        .is_some_and(|length| raw.len() >= split + 4 + length)
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(end) = raw.windows(2).position(|window| window == b"\r\n") {
        let size_text = String::from_utf8_lossy(&raw[..end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).unwrap();
        if size == 0 {
            break;
        }
        out.extend_from_slice(&raw[end + 2..end + 2 + size]);
        raw = &raw[end + 2 + size + 2..];
    }
    out
}

/// Seals through the byte API, sends it and hands the answer to `sessionResponse`, exactly as the Swift wrapper does.
/// Returns the HTTP reply and the byte API reply.
pub(crate) fn exchange(port: u16, session: i64, method: &str, path: &str, body: &[u8]) -> (HttpReply, Vec<u8>) {
    let sealed = api_seal(session, method, path, body);
    let reply = http(port, method, path, &sealed_headers(&sealed, method), &sealed.body);
    let opened = api::session_response(
        session,
        sealed.seq as i64,
        i32::from(reply.status),
        reply.header("content-type").map(str::as_bytes),
        reply.header("x-tx-encoding").map(str::as_bytes),
        Some(&reply.body),
    );
    (reply, opened)
}

pub(crate) fn opened_plaintext(reply: &[u8]) -> Vec<u8> {
    let (status, payload) = reply.split_first().unwrap();
    assert_eq!(*status, api::STATUS_OK, "reply {:?}", api::split_reply(reply));
    payload.to_vec()
}

pub(crate) fn unsealed(reply: &[u8]) -> (u64, String) {
    let (status, fields) = api::split_reply(reply).unwrap();
    assert_eq!(status, Error::UnsealedResponse { status: 0, code: None }.status(), "reply {reply:?}");
    (u64::from_be_bytes(fields[0].try_into().unwrap()), String::from_utf8(fields[1].to_vec()).unwrap())
}

fn rejected(reply: &[u8]) -> (u64, String, u64) {
    let (status, fields) = api::split_reply(reply).unwrap();
    assert_eq!(status, Error::ServerRejected { status: 0, code: None, server_time: None }.status(), "{reply:?}");
    (u64_field(fields[0]), String::from_utf8(fields[1].to_vec()).unwrap(), u64_field(fields[2]))
}

#[test]
fn register_and_handshake_against_the_go_server() {
    let _serial = serial();
    let peer = peer();
    let device = peer.new_device();
    let registered = register(peer, &device, |_| None);
    assert_eq!(registered["device_id"], device.device_id.as_str());
    assert_eq!(registered["device_key_id"], device.key_id.as_str());
    assert_eq!(registered["is_new_user"], true);

    let opened = start(peer, &device);
    assert_eq!(opened.sid.len(), 22);
    assert_eq!(opened.info["user_id"], registered["user_id"]);
    assert_eq!(opened.info["session_ttl_seconds"], 24 * 3600);
    assert_eq!(opened.info["idle_ttl_seconds"], 2 * 3600);
    assert!(
        ["limited", "untrusted"].contains(&opened.info["trust"].as_str().unwrap()),
        "no attestation: {}",
        opened.info
    );
}

#[test]
fn sealed_requests_against_the_real_middleware() {
    let _serial = serial();
    let peer = peer();
    let device = peer.new_device();
    register(peer, &device, |_| None);
    let opened = start(peer, &device);

    // A body and a query, both covered by the AAD; the route sees the plaintext.
    let body = "{\"kind\":\"template\",\"note\":\"\u{1ea1}\"}";
    let (reply, plain) = exchange(peer.port, opened.session, "POST", "/api/v1/echo?q=%C3%A1o%20d", body.as_bytes());
    assert_eq!(reply.header("content-type"), Some(wire::SEALED_CONTENT_TYPE));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let data = data_of(&opened_plaintext(&plain));
    assert_eq!(data["body"], body);
    assert_eq!(data["query"], "áo d");

    // Bodyless GET: X-Tx-Tag. The ETag of the route never leaves a sealed answer.
    let (reply, plain) = exchange(peer.port, opened.session, "GET", "/api/v1/public", b"");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("etag"), None);
    assert_eq!(data_of(&opened_plaintext(&plain))["public"], true);

    // 204 becomes 200 with an empty plaintext.
    let (reply, plain) = exchange(peer.port, opened.session, "GET", "/api/v1/nothing", b"");
    assert_eq!(reply.status, 200);
    assert!(opened_plaintext(&plain).is_empty());

    // gzip moves into the authenticated X-Tx-Encoding; the core decodes it.
    let (reply, plain) = exchange(peer.port, opened.session, "GET", "/api/v1/gz", b"");
    assert_eq!(reply.header("x-tx-encoding"), Some("gzip"));
    assert_eq!(reply.header("content-encoding"), None);
    assert_eq!(opened_plaintext(&plain), br#"{"big":true}"#);

    // A panic of the route is answered sealed: authenticated 500.
    let (reply, plain) = exchange(peer.port, opened.session, "GET", "/api/v1/boom", b"");
    assert_eq!(reply.status, 500);
    assert_eq!(meta_code(&opened_plaintext(&plain)), 50000001);

    // An empty POST, then the session is gone: plain 401 40101010, never data.
    let (reply, plain) = exchange(peer.port, opened.session, "POST", "/api/v1/session/end", b"");
    assert_eq!(reply.status, 200);
    data_of(&opened_plaintext(&plain));
    let (_, plain) = exchange(peer.port, opened.session, "GET", "/api/v1/public", b"");
    assert_eq!(unsealed(&plain), (401, "40101010".to_owned()));
}

#[test]
fn replays_tampering_and_clock() {
    let _serial = serial();
    let peer = peer();
    let device = peer.new_device();
    register(peer, &device, |_| None);
    let opened = start(peer, &device);

    let sealed = api_seal(opened.session, "POST", "/api/v1/echo", b"{}");
    let headers = sealed_headers(&sealed, "POST");
    let first = http(peer.port, "POST", "/api/v1/echo", &headers, &sealed.body);
    assert_eq!(first.status, 200);
    // The same seq again: plain 409 40901004.
    let again = http(peer.port, "POST", "/api/v1/echo", &headers, &sealed.body);
    let code = |reply: &HttpReply| {
        let opened = api::session_response(
            opened.session,
            sealed.seq as i64,
            i32::from(reply.status),
            reply.header("content-type").map(str::as_bytes),
            reply.header("x-tx-encoding").map(str::as_bytes),
            Some(&reply.body),
        );
        opened
    };
    assert_eq!(unsealed(&code(&again)), (409, "40901004".to_owned()));
    // Opening the first answer now: the seq was spent by the unsealed reply.
    assert_eq!(code(&first), api::error_reply(&Error::ReplayedResponse));

    // A changed byte of the sealed body: plain 400 40001005, the seq is not consumed by the server.
    let sealed = api_seal(opened.session, "POST", "/api/v1/echo", b"{\"a\":1}");
    let mut tampered = sealed.body.clone();
    tampered[0] ^= 1;
    let reply = http(peer.port, "POST", "/api/v1/echo", &sealed_headers(&sealed, "POST"), &tampered);
    assert_eq!(reply.status, 400);
    assert_eq!(meta_code(&reply.body), 40001005);

    // The path is in the AAD: the same seal on another path does not open.
    let sealed = api_seal(opened.session, "GET", "/api/v1/public?a=1", b"");
    let reply = http(peer.port, "GET", "/api/v1/public?a=2", &sealed_headers(&sealed, "GET"), b"");
    assert_eq!(meta_code(&reply.body), 40001005);

    // A request ts more than 60 s away from the server clock: 409 40901004.
    let sealed = api_seal(opened.session, "GET", "/api/v1/public", b"");
    peer.advance(61_000);
    let reply = http(peer.port, "GET", "/api/v1/public", &sealed_headers(&sealed, "GET"), b"");
    peer.advance(-61_000);
    assert_eq!((reply.status, meta_code(&reply.body)), (409, 40901004));
}

#[test]
fn handshake_refusals_carry_the_code_and_the_server_clock() {
    let _serial = serial();
    let peer = peer();
    let device = peer.new_device();
    // Not registered: 401 40101009, with X-Server-Time.
    let (_, finish) = start_raw(peer, &device, |_| None);
    let (status, code, server_time) = rejected(&finish);
    assert_eq!((status, code.as_str()), (401, "40101009"));
    assert!(server_time > 1_700_000_000_000, "{server_time}");

    // Another server key than the embedded one: BAD_SERVER_SIGNATURE.
    register(peer, &device, |_| None);
    let other = [7u8; 32];
    let begin = ok_fields(&api::handshake_begin(
        Some(device.device_id.as_bytes()),
        Some(device.key_id.as_bytes()),
        Some(APP_VERSION.as_bytes()),
        None,
    ));
    let handshake = u64_field(&begin[0]) as i64;
    let body = ok_fields_raw(&api::handshake_body(handshake, Some(&peer.sign(&device, &begin[1]))));
    let headers = [("Content-Type", "application/json".to_owned()), ("Content-Length", body.len().to_string())];
    let reply = http(peer.port, "POST", "/api/v1/session/start", &headers, &body);
    assert_eq!(reply.status, 200);
    api::TEST_SERVER_KEYS.with(|keys| {
        *keys.borrow_mut() =
            Some(vec![(peer.kid.clone(), ed25519_dalek::SigningKey::from_bytes(&other).verifying_key().to_bytes())])
    });
    assert_eq!(
        api::handshake_finish(handshake, 200, 0, Some(&reply.body)),
        api::error_reply(&Error::BadServerSignature)
    );

    // The same body again: its client_pub is spent, 409 40901004.
    let again = http(peer.port, "POST", "/api/v1/session/start", &headers, &body);
    assert_eq!((again.status, meta_code(&again.body)), (409, 40901004));
}

#[test]
fn app_attest_stub_assertion_at_the_handshake() {
    let _serial = serial();
    let peer = peer();
    let device = peer.new_device();
    let key_id = b64_std(&rand_bytes().repeat(2));
    let registered = register(peer, &device, |hash| Some(stub_attestation(&key_id, hash)));
    assert_eq!(registered["trust"], "trusted", "the stub verifier accepted the attestation");

    // No assertion: the session is capped at limited (enforce, the default), never refused.
    let opened = start(peer, &device);
    assert_eq!(opened.info["trust"], expected_trust(&opened.flags_csv, "limited"), "flags {:?}", opened.flags_csv);

    // A valid assertion over DAAS1 of the signed message: the session keeps the trust the risk flags leave.
    let counter = std::cell::Cell::new(1u32);
    let assert = |hash: &[u8]| Some(format!("doodleart-stub-v1.{}.{}", counter.get(), hex_encode(hash)));
    let opened = start_with(peer, &device, assert);
    assert_eq!(opened.info["trust"], expected_trust(&opened.flags_csv, "trusted"), "flags {:?}", opened.flags_csv);

    // The same counter again (a replayed or cloned key): limited.
    let opened = start_with(peer, &device, assert);
    assert_eq!(opened.info["trust"], expected_trust(&opened.flags_csv, "limited"));
    counter.set(2);
    let opened = start_with(peer, &device, assert);
    assert_eq!(opened.info["trust"], expected_trust(&opened.flags_csv, "trusted"));
}

/// The trust the server gives a session of `base` after the host's own risk flags (heavy: untrusted, light: limited).
fn expected_trust(flags_csv: &str, base: &'static str) -> &'static str {
    let flags: Vec<&str> = flags_csv.split(',').filter(|flag| !flag.is_empty()).collect();
    if flags.iter().any(|flag| ["frida", "hook", "debugger", "apk_resigned"].contains(flag)) {
        "untrusted"
    } else if flags.iter().any(|flag| ["root", "emulator"].contains(flag)) {
        "limited"
    } else {
        base
    }
}

fn b64_std(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
