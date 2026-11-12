//! The app-facing API in plain Rust, byte arrays in and out. `ffi.rs` (iOS C ABI) and `jni.rs` (Android) are thin
//! layers over these functions, so the exact formats the apps see are tested on the host.
//!
//! Every byte-array reply is `status (1 byte) ‖ payload`. Status 0 is success; others are [`Error::status`]. Payloads
//! with several values are `frame(...)` (u32be length + bytes per field; numbers are 8-byte big-endian fields).
//! Handles are random positive 63-bit numbers looked up in a registry: never pointers, never reused, unknown ones are
//! refused. All functions are thread-safe.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use rand_core::{OsRng, RngCore};

use crate::build_config;
use crate::clock;
use crate::codec::{unframe, Frame};
#[cfg(any(not(doodleart_apple_lib), test))]
use crate::device_signals::{self, SignalInputs};
use crate::envelope::{plain_error, wire, ClockSample, HandshakeParams, PendingHandshake, ServerKeys, Session};
use crate::error::{Error, Result};
use crate::gzip;
use crate::integrity_hash::{self, IntegrityRequest};
use crate::risk;

pub const STATUS_OK: u8 = 0;

const MAX_HANDSHAKES: usize = 16;
const HANDSHAKE_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_SESSIONS: usize = 32;
/// Largest decoded body of a gzip-encoded sealed response (the catalog is about 0.7 MB).
const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;

struct Slot<T> {
    value: T,
    created_mono: u64,
}

/// Handshakes and sessions are boxed so the tables hold only pointers: each secret (ephemeral X25519 key, session
/// keys) lives in a single heap block and is wiped there when the box drops. Stored inline, `HashMap::remove` would
/// copy the value out and leave the old bucket bytes (keys included) in the table, and a rehash would copy them again.
#[derive(Default)]
struct Registry {
    handshakes: HashMap<u64, Slot<Box<PendingHandshake>>>,
    sessions: HashMap<u64, Slot<Box<Session>>>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));
static APK_PATH_HINT: Mutex<Option<String>> = Mutex::new(None);

fn registry() -> MutexGuard<'static, Registry> {
    // A panic while holding the lock (caught at the FFI boundary) must not disable the API for the process.
    REGISTRY.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn apk_path_hint() -> Option<String> {
    APK_PATH_HINT.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

fn new_handle(taken: impl Fn(u64) -> bool) -> Result<u64> {
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        OsRng.try_fill_bytes(&mut bytes).map_err(|_| Error::Rng)?;
        let handle = u64::from_le_bytes(bytes) & (i64::MAX as u64);
        if handle != 0 && !taken(handle) {
            return Ok(handle);
        }
    }
    Err(Error::Rng)
}

fn handle_of(raw: i64) -> Result<u64> {
    u64::try_from(raw).ok().filter(|handle| *handle != 0).ok_or(Error::UnknownHandle)
}

fn evict_oldest<T>(map: &mut HashMap<u64, Slot<T>>) {
    if let Some(oldest) = map.iter().min_by_key(|(_, slot)| slot.created_mono).map(|(handle, _)| *handle) {
        map.remove(&oldest);
    }
}

fn reply(result: Result<Vec<u8>>) -> Vec<u8> {
    match result {
        Ok(payload) => {
            let mut out = Vec::with_capacity(payload.len() + 1);
            out.push(STATUS_OK);
            out.extend_from_slice(&payload);
            out
        }
        Err(error) => error_reply(&error),
    }
}

/// Error reply. `ServerRejected` carries `frame(u64(httpStatus), code, u64(serverTime or 0))`, `UnsealedResponse`
/// `frame(u64(httpStatus), code)`.
pub fn error_reply(error: &Error) -> Vec<u8> {
    let mut out = vec![error.status()];
    match error {
        Error::ServerRejected { status, code, server_time } => out.extend(
            Frame::new()
                .u64(u64::from(*status))
                .text(code.as_deref().unwrap_or(""))
                .u64(server_time.unwrap_or(0))
                .finish(),
        ),
        Error::UnsealedResponse { status, code } => {
            out.extend(Frame::new().u64(u64::from(*status)).text(code.as_deref().unwrap_or("")).finish());
        }
        _ => {}
    }
    out
}

fn status_code(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => i32::from(error.status()),
    }
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidArgument)
}

fn required(bytes: Option<&[u8]>) -> Result<&[u8]> {
    bytes.ok_or(Error::InvalidArgument)
}

#[cfg(not(test))]
fn server_keys() -> Result<ServerKeys> {
    ServerKeys::embedded()
}

/// Test-only override of the embedded server keys: `(kid, raw public key)` pairs.
#[cfg(test)]
type TestKeys = Option<Vec<(String, [u8; 32])>>;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SERVER_KEYS: std::cell::RefCell<TestKeys> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn server_keys() -> Result<ServerKeys> {
    TEST_SERVER_KEYS.with(|keys| match keys.borrow().as_ref() {
        Some(keys) => ServerKeys::from_raw(keys.iter().map(|(kid, key)| (kid.as_str(), *key))),
        None => ServerKeys::embedded(),
    })
}

/// `nativeInit(apkPath)`: remembers Kotlin's `applicationInfo.sourceDir` as a fallback for the APK check (maps are
/// preferred) and returns `frame(buildType, crateVersion, kidsCsv)`.
pub fn init(apk_path: Option<&[u8]>) -> Vec<u8> {
    reply((|| {
        if let Some(path) = apk_path {
            *APK_PATH_HINT.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(utf8(path)?.to_owned());
        }
        let keys = server_keys()?;
        let kids: Vec<&str> = keys.kids().collect();
        Ok(Frame::new().text(build_config::BUILD_TYPE).text(env!("CARGO_PKG_VERSION")).text(&kids.join(",")).finish())
    })())
}

/// `deviceKeyId(spkiDer)`: base64url(SHA-256(SPKI)) as UTF-8, for an EC P-256 SubjectPublicKeyInfo.
pub fn device_key_id(spki: Option<&[u8]>) -> Vec<u8> {
    const P256_SPKI_PREFIX: [u8; 27] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    reply((|| {
        let spki = required(spki)?;
        if spki.len() != 91 || !spki.starts_with(&P256_SPKI_PREFIX) {
            return Err(Error::InvalidArgument);
        }
        Ok(wire::device_key_id(spki).into_bytes())
    })())
}

/// `registerMessage(nonce, deviceId, deviceKeyId, platform)`: `frame(message, clientDataHash)` for
/// `POST /api/v1/devices/register`. `message` = `frame("doodle/v1/register", nonce bytes, device_id, device_key_id,
/// platform)` is what the device key signs (the body's `signature`); `clientDataHash` = SHA-256(message) is what
/// `attestKey` (App Attest) or the Play Integrity request hash covers. `nonce` is the 32-character challenge text of
/// `POST /api/v1/auth/challenge`; the other values are exactly the body's.
pub fn register_message(
    nonce: Option<&[u8]>,
    device_id: Option<&[u8]>,
    device_key_id: Option<&[u8]>,
    platform: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let nonce = utf8(required(nonce)?)?;
        let device_id = utf8(required(device_id)?)?;
        let device_key_id = utf8(required(device_key_id)?)?;
        let platform = utf8(required(platform)?)?;
        let message = integrity_hash::register_message(nonce, device_id, device_key_id, platform)?;
        let hash = integrity_hash::register_client_data_hash(&message);
        Ok(Frame::new().bytes(&message).bytes(&hash).finish())
    })())
}

/// `handshakeBegin(deviceId, deviceKeyId, appVersion, extraRiskFlags)`: runs the risk scan, merges Kotlin's own flags
/// (comma-separated, filtered to the known vocabulary), creates a fresh X25519 key and returns
/// `frame(u64(handshake), signatureMessage, riskFlagsCsv)`. Kotlin signs `signatureMessage` with the Keystore key
/// (`SHA256withECDSA`) and passes the DER signature to [`handshake_body`].
pub fn handshake_begin(
    device_id: Option<&[u8]>,
    device_key_id: Option<&[u8]>,
    app_version: Option<&[u8]>,
    extra_flags: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let device_id = utf8(required(device_id)?)?.to_owned();
        let device_key_id = utf8(required(device_key_id)?)?.to_owned();
        let app_version = utf8(required(app_version)?)?.to_owned();
        let extra = match extra_flags {
            Some(bytes) => risk::parse_flag_list(utf8(bytes)?),
            None => Vec::new(),
        };
        let mut report = risk::scan(apk_path_hint().as_deref());
        report.merge_flags(extra);
        begin_with_flags(device_id, device_key_id, app_version, report.flag_names(), clock::corrected_wall_ms())
    })())
}

fn begin_with_flags(
    device_id: String,
    device_key_id: String,
    app_version: String,
    risk_flags: Vec<String>,
    ts: u64,
) -> Result<Vec<u8>> {
    let pending = PendingHandshake::new(HandshakeParams { device_id, device_key_id, app_version, risk_flags, ts })?;
    let message = pending.signature_message();
    let flags_csv = wire::risk_flags_csv(pending.risk_flags());
    let now = clock::mono_ms();
    let mut registry = registry();
    registry.handshakes.retain(|_, slot| now.saturating_sub(slot.created_mono) < HANDSHAKE_TTL_MS);
    while registry.handshakes.len() >= MAX_HANDSHAKES {
        evict_oldest(&mut registry.handshakes);
    }
    let handle = new_handle(|candidate| registry.handshakes.contains_key(&candidate))?;
    registry.handshakes.insert(handle, Slot { value: Box::new(pending), created_mono: now });
    Ok(Frame::new().u64(handle).bytes(&message).text(&flags_csv).finish())
}

/// `handshakeBody(handshake, deviceSigDer)`: the JSON body for `POST /api/v1/session/start`. One call per handshake.
pub fn handshake_body(handshake: i64, device_sig: Option<&[u8]>) -> Vec<u8> {
    reply((|| {
        let handle = handle_of(handshake)?;
        let signature = required(device_sig)?;
        let mut registry = registry();
        let slot = registry.handshakes.get_mut(&handle).ok_or(Error::UnknownHandle)?;
        slot.value.request_body(signature)
    })())
}

/// `handshakeFinish(handshake, httpStatus, serverTimeHeader, responseBody)`: consumes the handshake whatever the
/// outcome and returns `frame(u64(session), sid, sessionInfoJson)`. `server_time_header` is the `X-Server-Time` header
/// in ms, 0 when absent (it only matters for a refusal: the clock hint of `SERVER_REJECTED`). Any failure means: start
/// over with [`handshake_begin`] (fresh key).
pub fn handshake_finish(handshake: i64, http_status: i32, server_time_header: i64, body: Option<&[u8]>) -> Vec<u8> {
    reply((|| {
        let handle = handle_of(handshake)?;
        // Dropped (and its ephemeral secret wiped in place) when this closure returns, whatever the outcome.
        let pending = registry().handshakes.remove(&handle).ok_or(Error::UnknownHandle)?.value;
        let status = u16::try_from(http_status)
            .ok()
            .filter(|status| (100..=599).contains(status))
            .ok_or(Error::InvalidArgument)?;
        let body = body.unwrap_or(&[]);
        let keys = server_keys()?;
        let clock = ClockSample { wall_ms: clock::wall_ms(), mono_ms: clock::mono_ms() };
        let server_time_header = u64::try_from(server_time_header).ok().filter(|time| *time > 0);
        let established = match pending.finish(&keys, status, server_time_header, body, clock) {
            Ok(established) => established,
            Err(error) => {
                if let Error::ServerRejected { server_time: Some(server_time), .. } = &error {
                    // Unauthenticated hint, used only for the next handshake ts (a bad value costs one retry).
                    clock::learn_server_time(*server_time, clock.wall_ms);
                }
                return Err(error);
            }
        };
        clock::learn_server_time(established.server_time, clock.wall_ms);
        let sid = established.session.sid().to_owned();
        let mut registry = registry();
        while registry.sessions.len() >= MAX_SESSIONS {
            evict_oldest(&mut registry.sessions);
        }
        let session = new_handle(|candidate| registry.sessions.contains_key(&candidate))?;
        registry.sessions.insert(session, Slot { value: Box::new(established.session), created_mono: clock.mono_ms });
        Ok(Frame::new().u64(session).text(&sid).bytes(&established.start_info).finish())
    })())
}

/// `handshakeAbort(handshake)`: drops a handshake whose request failed before any response (status code).
pub fn handshake_abort(handshake: i64) -> i32 {
    status_code((|| {
        let handle = handle_of(handshake)?;
        registry().handshakes.remove(&handle).map(|_| ()).ok_or(Error::UnknownHandle)
    })())
}

/// `sessionSeal(session, method, pathWithQuery, plaintextBody)`: returns
/// `frame(u64(seq), u64(ts), sid, appVersion, tag, sealedBody)`; exactly one of `tag` / `sealedBody` is non-empty.
pub fn session_seal(
    session: i64,
    method: Option<&[u8]>,
    path_with_query: Option<&[u8]>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let handle = handle_of(session)?;
        let method = utf8(required(method)?)?;
        let path = utf8(required(path_with_query)?)?;
        let body = body.unwrap_or(&[]);
        let mut registry = registry();
        let slot = registry.sessions.get_mut(&handle).ok_or(Error::UnknownHandle)?;
        let sealed = slot.value.seal_request(method, path, body, clock::mono_ms())?;
        Ok(Frame::new()
            .u64(sealed.seq)
            .u64(sealed.ts)
            .text(&sealed.sid)
            .text(&sealed.app_version)
            .text(sealed.tag.as_deref().unwrap_or(""))
            .bytes(&sealed.body)
            .finish())
    })())
}

/// `sessionResponse(session, seq, httpStatus, contentType, contentEncoding, body)`: the answer to a sealed request, the
/// only way the app should read one. `Content-Type: application/vnd.doodle.sealed` (parameters and case ignored) is
/// opened under the AAD of `X-Tx-Encoding: content_encoding` (absent = "") and, for "gzip", decoded: the plaintext,
/// once per seq. Any other answer, 2xx included, is `UNSEALED_RESPONSE` with `frame(u64(httpStatus), code)`, where
/// `code` is the unauthenticated `meta.code` of a 4xx/5xx plain JSON body ("" otherwise, and never parsed for
/// 1xx-3xx: the server does not answer an opened request unsealed). The seq is spent whatever the outcome.
pub fn session_response(
    session: i64,
    seq: i64,
    http_status: i32,
    content_type: Option<&[u8]>,
    content_encoding: Option<&[u8]>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let handle = handle_of(session)?;
        let seq = u64::try_from(seq).map_err(|_| Error::ReplayedResponse)?;
        let status = u16::try_from(http_status)
            .ok()
            .filter(|status| (100..=599).contains(status))
            .ok_or(Error::InvalidArgument)?;
        let body = body.unwrap_or(&[]);
        let sealed = is_sealed_content_type(content_type);
        {
            let mut registry = registry();
            let slot = registry.sessions.get_mut(&handle).ok_or(Error::UnknownHandle)?;
            if sealed {
                let opened = std::str::from_utf8(content_encoding.unwrap_or_default())
                    .map_err(|_| Error::DecryptFailed)
                    .and_then(|encoding| open_decoded(&mut slot.value, seq, status, encoding, body));
                if opened.is_err() {
                    slot.value.abandon(seq);
                }
                return opened;
            }
            slot.value.abandon(seq);
        }
        let code = if status >= 400 { plain_error(body) } else { None };
        Err(Error::UnsealedResponse { status, code })
    })())
}

/// Opens, then decodes a gzip plaintext. Any other non-empty encoding is refused: it was authenticated, but the app
/// could not read it.
fn open_decoded(session: &mut Session, seq: u64, status: u16, encoding: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    let plaintext = session.open_response(seq, status, encoding, sealed)?;
    match encoding {
        "" => Ok(plaintext),
        "gzip" => gzip::decode(&plaintext, MAX_DECODED_BYTES),
        _ => Err(Error::DecryptFailed),
    }
}

fn is_sealed_content_type(content_type: Option<&[u8]>) -> bool {
    content_type.is_some_and(|value| {
        let media_type = value.split(|byte| *byte == b';').next().unwrap_or_default();
        media_type.trim_ascii().eq_ignore_ascii_case(wire::SEALED_CONTENT_TYPE.as_bytes())
    })
}

/// `sessionOpen(session, seq, httpStatus, contentEncoding, sealedBody)`: plaintext of a sealed response, once per seq,
/// decoded like [`session_response`]. Low level: [`session_response`] also handles unsealed answers and is what the
/// app should call.
pub fn session_open(
    session: i64,
    seq: i64,
    http_status: i32,
    content_encoding: Option<&[u8]>,
    sealed: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let handle = handle_of(session)?;
        let seq = u64::try_from(seq).map_err(|_| Error::ReplayedResponse)?;
        let status = u16::try_from(http_status).map_err(|_| Error::DecryptFailed)?;
        let sealed = required(sealed)?;
        let encoding = std::str::from_utf8(content_encoding.unwrap_or_default()).map_err(|_| Error::DecryptFailed)?;
        let mut registry = registry();
        let slot = registry.sessions.get_mut(&handle).ok_or(Error::UnknownHandle)?;
        open_decoded(&mut slot.value, seq, status, encoding, sealed)
    })())
}

/// `sessionAbandon(session, seq)`: forget a seq whose response will never be opened.
pub fn session_abandon(session: i64, seq: i64) -> i32 {
    status_code((|| {
        let handle = handle_of(session)?;
        let mut registry = registry();
        let slot = registry.sessions.get_mut(&handle).ok_or(Error::UnknownHandle)?;
        slot.value.abandon(u64::try_from(seq).unwrap_or(0));
        Ok(())
    })())
}

/// `sessionClose(session)`: wipes the session keys.
pub fn session_close(session: i64) -> i32 {
    status_code((|| {
        let handle = handle_of(session)?;
        registry().sessions.remove(&handle).map(|_| ()).ok_or(Error::UnknownHandle)
    })())
}

/// `integrityHash(method, pathWithQuery, requestId, sid, plaintextBody)`: `frame(requestId, requestHash)`. A null
/// requestId makes Rust generate a UUID v4; a null/empty sid means "" (device registration).
pub fn integrity_hash(
    method: Option<&[u8]>,
    path_with_query: Option<&[u8]>,
    request_id: Option<&[u8]>,
    sid: Option<&[u8]>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let method = utf8(required(method)?)?;
        let path = utf8(required(path_with_query)?)?;
        let request_id = match request_id {
            Some(bytes) => utf8(bytes)?.to_owned(),
            None => integrity_hash::new_request_id()?,
        };
        let sid = utf8(sid.unwrap_or(&[]))?;
        let request =
            IntegrityRequest { method, path_with_query: path, request_id: &request_id, sid, body: body.unwrap_or(&[]) };
        let hash = integrity_hash::request_hash(&request)?;
        Ok(Frame::new().text(&request_id).text(&hash).finish())
    })())
}

/// `deviceSignals(androidIdUtf8, drmId, drmStatus, sensors)`: the `deviceSignals` JSON object for registration.
/// Android only (not part of an Apple library: iOS sends `iosDeviceHash`, theme-x spec 2026-11-05 §4.2).
#[cfg(any(not(doodleart_apple_lib), test))]
pub fn device_signals(
    android_id: Option<&[u8]>,
    drm_id: Option<&[u8]>,
    drm_status: Option<&[u8]>,
    sensors: Option<&[u8]>,
) -> Vec<u8> {
    reply((|| {
        let sensors = match sensors {
            Some(bytes) => device_signals::parse_sensors(bytes)?,
            None => Vec::new(),
        };
        let inputs = SignalInputs {
            android_id,
            drm_id,
            drm_failure: drm_status.map(device_signals::parse_drm_failure),
            hw: device_signals::read_native_hw(sensors),
        };
        Ok(device_signals::device_signals_json(&inputs))
    })())
}

/// `riskScan(extraRiskFlags)`: `frame(riskFlagsCsv, detailsCsv)`; details are empty in release builds.
pub fn risk_scan(extra_flags: Option<&[u8]>) -> Vec<u8> {
    reply((|| {
        let mut report = risk::scan(apk_path_hint().as_deref());
        if let Some(bytes) = extra_flags {
            report.merge_flags(risk::parse_flag_list(utf8(bytes)?));
        }
        Ok(Frame::new().text(&report.csv()).text(&report.details.join(",")).finish())
    })())
}

/// Splits a reply into status and payload fields (tests and documentation helper).
pub fn split_reply(reply: &[u8]) -> Option<(u8, Vec<&[u8]>)> {
    let (status, payload) = reply.split_first()?;
    Some((*status, unframe(payload)?))
}

/// The byte API of the iOS C ABI (src/ffi.rs, include/doodleart_core.h) beyond the JNI natives, Apple targets only. Same
/// conventions as the rest of this module (`status ‖ payload`, the same handle registry); each reply that extends a
/// JNI one starts with that reply's exact fields, so both platforms share one decoder.
#[cfg(target_vendor = "apple")]
pub mod apple {
    use super::*;
    use crate::codec::b64url_decode_exact;

    /// Version of the C ABI (`DOODLEART_ABI_VERSION` in include/doodleart_core.h), reported by [`init`]. Additions (a new
    /// function, a field appended to a reply) keep it; anything that would break a caller built against an older
    /// header changes it.
    pub const ABI_VERSION: u64 = 1;

    /// `doodleart_init()`: the JNI init reply without an APK path (Apple has none), followed by `u64(abiVersion)` and
    /// `projectId`: `frame(buildType, crateVersion, kidsCsv, u64(abiVersion), projectId)`.
    pub fn init() -> Vec<u8> {
        with_fields(super::init(None), |_| Ok(Frame::new().u64(ABI_VERSION).text(build_config::PROJECT_ID)))
    }

    /// `doodleart_integrity_hash(...)`: the JNI reply `frame(requestId, requestHash)` plus the 32 raw bytes of
    /// `requestHash`, which `generateAssertion` takes as `clientDataHash` (theme-x spec 2026-11-05 §3.5).
    pub fn integrity_hash(
        method: Option<&[u8]>,
        path_with_query: Option<&[u8]>,
        request_id: Option<&[u8]>,
        sid: Option<&[u8]>,
        body: Option<&[u8]>,
    ) -> Vec<u8> {
        with_fields(super::integrity_hash(method, path_with_query, request_id, sid, body), |fields| {
            let hash = fields.get(1).and_then(|field| std::str::from_utf8(field).ok()).ok_or(Error::Internal)?;
            let raw = b64url_decode_exact::<32>(hash).ok_or(Error::Internal)?;
            Ok(Frame::new().bytes(&raw))
        })
    }

    /// `doodleart_ios_device_hash(secret)`: `iosDeviceHash` (64 lowercase hex characters) of the 32-byte Keychain secret.
    pub fn ios_device_hash(secret: Option<&[u8]>) -> Vec<u8> {
        reply((|| Ok(integrity_hash::ios_device_hash(required(secret)?)?.into_bytes()))())
    }

    /// `doodleart_session_assert_hash(signatureMessage)`: the 32 raw DAAS1 bytes (theme-x spec §3.5b) for the assertion of
    /// `POST /api/v1/session/start`. Refuses (INVALID_ARGUMENT) anything that is not a handshake signature message, the
    /// likely mistake being the request body or the DER signature: the server would hash the message it rebuilds, and
    /// a wrong assertion leaves the session `limited`.
    pub fn session_assert_hash(signature_message: Option<&[u8]>) -> Vec<u8> {
        reply((|| {
            let message = required(signature_message)?;
            if !is_signature_message(message) {
                return Err(Error::InvalidArgument);
            }
            Ok(integrity_hash::session_assert_client_data_hash(message).to_vec())
        })())
    }

    /// `doodleart_handshake_assert_hash(handshake)`: DAAS1 of the handshake's own signature message (what
    /// [`session_assert_hash`] computes from the bytes [`super::handshake_begin`] returned). Leaves the handshake as
    /// it is.
    pub fn handshake_assert_hash(handshake: i64) -> Vec<u8> {
        reply((|| {
            let handle = handle_of(handshake)?;
            let message = registry().handshakes.get(&handle).ok_or(Error::UnknownHandle)?.value.signature_message();
            Ok(integrity_hash::session_assert_client_data_hash(&message).to_vec())
        })())
    }

    /// `doodleart_debug_clock_advance_ms(ms)`, debug libraries only: moves the session clock forward by `ms` (0 to one
    /// week) to simulate a device asleep that long (theme-x spec §7.1). Status code.
    #[cfg(feature = "build-debug")]
    pub fn debug_clock_advance(ms: i64) -> i32 {
        let advanced = u64::try_from(ms).is_ok_and(clock::debug_clock::advance);
        status_code(if advanced { Ok(()) } else { Err(Error::InvalidArgument) })
    }

    /// Exactly `wire::device_signature_message(...)` of its own fields: the single definition of that layout decides.
    fn is_signature_message(message: &[u8]) -> bool {
        let Some(fields) = unframe(message) else { return false };
        let [_tag, client_pub, ts, device_id, device_key_id, app_version, flags] = fields.as_slice() else {
            return false;
        };
        let (Ok(client_pub), Ok(ts)) = (<[u8; 32]>::try_from(*client_pub), <[u8; 8]>::try_from(*ts)) else {
            return false;
        };
        let text = std::str::from_utf8;
        let (Ok(device_id), Ok(device_key_id), Ok(app_version), Ok(flags)) =
            (text(device_id), text(device_key_id), text(app_version), text(flags))
        else {
            return false;
        };
        wire::device_signature_message(
            &client_pub,
            u64::from_be_bytes(ts),
            device_id,
            device_key_id,
            app_version,
            flags,
        ) == message
    }

    /// Appends the fields `extra` builds (from the reply's own fields) to a successful framed reply; an error reply
    /// passes through unchanged.
    fn with_fields(reply: Vec<u8>, extra: impl FnOnce(&[&[u8]]) -> Result<Frame>) -> Vec<u8> {
        let Some((&STATUS_OK, payload)) = reply.split_first() else { return reply };
        let appended = unframe(payload).ok_or(Error::Internal).and_then(|fields| extra(&fields)).map(Frame::finish);
        match appended {
            Ok(fields) => [reply, fields].concat(),
            Err(error) => error_reply(&error),
        }
    }
}

#[cfg(test)]
mod tests;
