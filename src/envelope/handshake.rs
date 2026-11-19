//! Client side of `POST /api/v1/session/start` (server/docs/app-security.md section 4).
//!
//! Sequence:
//! 1. [`PendingHandshake::new`]: fresh X25519 key pair, `ts`, and [`PendingHandshake::signature_message`], the exact
//!    bytes the app signs with its device key (Secure Enclave, Android Keystore; Rust never sees that private key).
//! 2. [`PendingHandshake::request_body`] with the DER signature: the JSON body. One-shot: the `client_pub` it carries
//!    is spent once sent, whatever the outcome (network error, 409, 429...); a retry needs a new handshake.
//! 3. [`PendingHandshake::finish`] with the HTTP status and body: checks the server's Ed25519 signature over the
//!    transcript built with our own `device_key_id`, derives the session keys and opens the sealed session info.
//!
//! The server answers in the golib envelope `{ "meta": { "code", "message" }, "data": { ... } }`: `data` holds the
//! handshake fields, `meta.code` the numeric error code of a refusal.

use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use super::keys::ServerKeys;
use super::session::Session;
use super::validate;
use super::wire::{self, DIR_S2C, ENVELOPE_VERSION, MAX_SAFE_INTEGER};
use crate::codec::{b64url_decode, b64url_decode_exact, b64url_encode};
use crate::error::{Error, Result};

/// Server-reserved flags: the client never sends them.
const RESERVED_FLAGS: [&str; 2] = ["banned_device", "restore_blocked"];
const MAX_RISK_FLAGS: usize = 16;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct HandshakeParams {
    /// The lowercase `device_id` registration returned.
    pub device_id: String,
    pub device_key_id: String,
    pub app_version: String,
    pub risk_flags: Vec<String>,
    /// Client clock in ms, already corrected by the last known server offset.
    pub ts: u64,
}

/// Local clocks sampled when the handshake response arrived.
#[derive(Clone, Copy, Debug)]
pub struct ClockSample {
    pub wall_ms: u64,
    pub mono_ms: u64,
}

pub struct Established {
    pub session: Session,
    /// Decrypted session info JSON: `{ session_ttl_seconds, idle_ttl_seconds, min_app_version, trust, user_id,
    /// is_anonymous }`.
    pub start_info: Vec<u8>,
    pub server_time: u64,
}

pub struct PendingHandshake {
    secret: StaticSecret,
    client_pub: [u8; 32],
    params: HandshakeParams,
    flags_csv: String,
    body_sent: bool,
}

impl PendingHandshake {
    /// New handshake with a fresh ephemeral X25519 key from the OS RNG.
    pub fn new(params: HandshakeParams) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(seed.as_mut()).map_err(|_| Error::Rng)?;
        Self::from_secret(*seed, params)
    }

    /// Deterministic constructor for test vectors. Production code uses [`PendingHandshake::new`].
    #[doc(hidden)]
    pub fn from_secret(mut secret: [u8; 32], mut params: HandshakeParams) -> Result<Self> {
        let raw = Zeroizing::new(secret);
        secret.zeroize();
        let flags = normalize_flags(&params.risk_flags)?;
        if !validate::device_id(&params.device_id)
            || !validate::device_key_id(&params.device_key_id)
            || !validate::app_version(&params.app_version)
            || params.ts == 0
            || params.ts > MAX_SAFE_INTEGER
        {
            return Err(Error::InvalidArgument);
        }
        params.risk_flags = flags;
        let secret = StaticSecret::from(*raw);
        let client_pub = PublicKey::from(&secret).to_bytes();
        let flags_csv = wire::risk_flags_csv(&params.risk_flags);
        Ok(Self { secret, client_pub, params, flags_csv, body_sent: false })
    }

    pub fn client_pub(&self) -> [u8; 32] {
        self.client_pub
    }

    pub fn ts(&self) -> u64 {
        self.params.ts
    }

    pub fn risk_flags(&self) -> &[String] {
        &self.params.risk_flags
    }

    /// `frame("doodle/v1/start", client_pub, u64(ts), device_id, device_key_id, app_version, risk_flags_csv)`.
    pub fn signature_message(&self) -> Vec<u8> {
        wire::device_signature_message(
            &self.client_pub,
            self.params.ts,
            &self.params.device_id,
            &self.params.device_key_id,
            &self.params.app_version,
            &self.flags_csv,
        )
    }

    /// JSON body of `POST /api/v1/session/start` (StartSessionRequest). Callable once per handshake.
    pub fn request_body(&mut self, device_sig_der: &[u8]) -> Result<Vec<u8>> {
        if self.body_sent {
            return Err(Error::HandshakeState);
        }
        if !validate::device_signature(device_sig_der) {
            return Err(Error::InvalidArgument);
        }
        self.body_sent = true;
        let body = json!({
            "device_id": self.params.device_id,
            "device_key_id": self.params.device_key_id,
            "app_version": self.params.app_version,
            "ts": self.params.ts,
            "client_pub": b64url_encode(&self.client_pub),
            "risk_flags": self.params.risk_flags,
            "signature": b64url_encode(device_sig_der),
        });
        serde_json::to_vec(&body).map_err(|_| Error::Internal)
    }

    /// Completes the handshake. A non-200 answer yields [`Error::ServerRejected`]; any other failure means the answer
    /// is not from our server (or not for this handshake) and must not be trusted. Borrows `self` so the ephemeral
    /// secret is never moved out of its (boxed) home: it is wiped where it lives when the handshake is dropped.
    /// `server_time_header` is the `X-Server-Time` header (ms), which the server sends with every handshake answer:
    /// on a refusal it is the clock hint of [`Error::ServerRejected`] (unauthenticated, like the code). A 200 uses the
    /// signed `server_time` of the body instead.
    pub fn finish(
        &self,
        keys: &ServerKeys,
        http_status: u16,
        server_time_header: Option<u64>,
        body: &[u8],
        clock: ClockSample,
    ) -> Result<Established> {
        if !self.body_sent {
            return Err(Error::HandshakeState);
        }
        if http_status != 200 {
            return Err(rejection(http_status, body, server_time_header));
        }
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(Error::BadServerResponse);
        }
        let envelope: Value = serde_json::from_slice(body).map_err(|_| Error::BadServerResponse)?;
        if envelope.get("meta").and_then(|meta| meta.get("code")).and_then(Value::as_u64) != Some(200) {
            return Err(Error::BadServerResponse);
        }
        let response = envelope.get("data").and_then(Value::as_object).ok_or(Error::BadServerResponse)?;

        if response.get("v").and_then(Value::as_u64) != Some(ENVELOPE_VERSION) {
            return Err(Error::BadServerResponse);
        }
        let sid = string_field(response, "sid").filter(|sid| validate::sid(sid)).ok_or(Error::BadServerResponse)?;
        let kid = string_field(response, "kid").filter(|kid| validate::kid(kid)).ok_or(Error::BadServerResponse)?;
        let server_pub =
            string_field(response, "server_pub").and_then(b64url_decode_exact::<32>).ok_or(Error::BadServerResponse)?;
        let server_time = response
            .get("server_time")
            .and_then(Value::as_u64)
            .filter(|time| (1..=MAX_SAFE_INTEGER).contains(time))
            .ok_or(Error::BadServerResponse)?;
        let signature =
            string_field(response, "signature").and_then(b64url_decode_exact::<64>).ok_or(Error::BadServerResponse)?;
        let sealed = string_field(response, "sealed").and_then(b64url_decode).ok_or(Error::BadServerResponse)?;

        // The transcript uses our own device_key_id and ts, never values echoed by the response.
        let transcript = wire::transcript(
            &self.client_pub,
            &self.params.device_key_id,
            &server_pub,
            sid,
            self.params.ts,
            server_time,
            kid,
        );
        keys.verify(kid, &transcript, &signature)?;

        let shared = self.secret.diffie_hellman(&PublicKey::from(server_pub));
        if !shared.was_contributory() {
            return Err(Error::BadServerResponse);
        }
        let session_keys = wire::derive_session_keys(shared.as_bytes(), &transcript);
        drop(shared);

        let start_info = wire::open(&session_keys.s2c, DIR_S2C, 0, &wire::start_response_aad(sid), &sealed)
            .ok_or(Error::DecryptFailed)?;
        let info: Value = serde_json::from_slice(&start_info).map_err(|_| Error::BadServerResponse)?;
        let info = info.as_object().ok_or(Error::BadServerResponse)?;
        let session_ttl_seconds = info.get("session_ttl_seconds").and_then(Value::as_u64);

        let session = Session::new(
            sid.to_owned(),
            self.params.app_version.clone(),
            session_keys,
            server_time,
            clock.mono_ms,
            session_ttl_seconds,
        );
        Ok(Established { session, start_info, server_time })
    }
}

fn string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

/// Deduplicated, sorted, validated flags; reserved server flags are dropped.
fn normalize_flags(flags: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for flag in flags {
        if !validate::risk_flag(flag) {
            return Err(Error::InvalidArgument);
        }
        if RESERVED_FLAGS.contains(&flag.as_str()) || out.contains(flag) {
            continue;
        }
        out.push(flag.clone());
    }
    if out.len() > MAX_RISK_FLAGS {
        return Err(Error::InvalidArgument);
    }
    out.sort_unstable();
    Ok(out)
}

/// `meta.code` of a plain JSON error body (`{ "meta": { "code": 40101010, "message": "..." } }`, docs/app-security.md
/// section 6), as decimal text. Unauthenticated: callers use it to decide what to do next, never as data. A code that
/// is not a 3 to 8 digit number is dropped.
pub(crate) fn plain_error(body: &[u8]) -> Option<String> {
    let parsed: Option<Value> = (body.len() <= MAX_RESPONSE_BYTES).then(|| serde_json::from_slice(body).ok()).flatten();
    parsed
        .as_ref()
        .and_then(|value| value.get("meta"))
        .and_then(|meta| meta.get("code"))
        .and_then(Value::as_u64)
        .map(|code| code.to_string())
        .filter(|code| validate::error_code(code))
}

fn rejection(status: u16, body: &[u8], server_time_header: Option<u64>) -> Error {
    let server_time = server_time_header.filter(|time| (1..=MAX_SAFE_INTEGER).contains(time));
    Error::ServerRejected { status, code: plain_error(body), server_time }
}
