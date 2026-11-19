//! Envelope v1 primitives, byte for byte as server/docs/app-security.md section 3 and server/src/core/envelope/envelope.go.
//! Changing anything here breaks the contract with the server and the vectors in
//! server/src/core/envelope/testdata/envelope-v1.json.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use obfstr::obfstr;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::codec::{b64url_encode, Frame};

pub const ENVELOPE_VERSION: u64 = 1;
pub const DIR_C2S: u32 = 1;
pub const DIR_S2C: u32 = 2;
pub const KEY_LENGTH: usize = 32;
pub const TAG_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 12;
/// seq stays exact in the server's Lua replay window (app-security.md section 5).
pub const MAX_SEQ: u64 = (1 << 53) - 1;
/// `ts`, `server_time` and seq are JSON numbers: keep them exact in any JSON client.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
pub const SEALED_CONTENT_TYPE: &str = "application/vnd.doodle.sealed";

pub type SecretKey = Zeroizing<[u8; KEY_LENGTH]>;

/// `k_c2s` / `k_s2c` derived from the handshake.
pub struct SessionKeys {
    pub c2s: SecretKey,
    pub s2c: SecretKey,
}

/// `nonce = u32be(dir) ‖ u64be(seq)`.
pub fn nonce(direction: u32, seq: u64) -> [u8; NONCE_LENGTH] {
    let mut out = [0u8; NONCE_LENGTH];
    out[..4].copy_from_slice(&direction.to_be_bytes());
    out[4..].copy_from_slice(&seq.to_be_bytes());
    out
}

/// ChaCha20-Poly1305 seal; returns `ciphertext ‖ tag`.
pub fn seal(key: &[u8; KEY_LENGTH], direction: u32, seq: u64, aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce(direction, seq);
    cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad }).ok()
}

/// Opens `ciphertext ‖ tag`; `None` on any failure.
pub fn open(key: &[u8; KEY_LENGTH], direction: u32, seq: u64, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LENGTH {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce(direction, seq);
    cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: sealed, aad }).ok()
}

/// Flags sorted by byte order and joined with "," (flags are ASCII, so this matches JS `sort()`).
pub fn risk_flags_csv(flags: &[String]) -> String {
    let mut sorted: Vec<&str> = flags.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.join(",")
}

/// `deviceKeyId = base64url(SHA-256(SPKI DER))`.
pub fn device_key_id(spki_der: &[u8]) -> String {
    b64url_encode(&Sha256::digest(spki_der))
}

/// `frame("doodle/v1/register", nonce, device_id, device_key_id, platform)`: what the new device key signs at
/// `POST /api/v1/devices/register`, `nonce` being the 24 decoded bytes of the challenge. Its SHA-256 is also the
/// clientDataHash of the App Attest attestation and the Play Integrity challenge of that request.
pub fn register_message(nonce: &[u8], device_id: &str, device_key_id: &str, platform: &str) -> Vec<u8> {
    Frame::with_capacity(160)
        .text(obfstr!("doodle/v1/register"))
        .bytes(nonce)
        .text(device_id)
        .text(device_key_id)
        .text(platform)
        .finish()
}

/// `frame("doodle/v1/start", clientPub, u64(ts), device_id, deviceKeyId, appVersion, riskFlagsCsv)`: the bytes the
/// device key (Secure Enclave, Android Keystore) signs (ECDSA P-256 SHA-256, DER).
pub fn device_signature_message(
    client_pub: &[u8; 32],
    ts: u64,
    device_id: &str,
    device_key_id: &str,
    app_version: &str,
    risk_flags_csv: &str,
) -> Vec<u8> {
    Frame::with_capacity(192)
        .text(obfstr!("doodle/v1/start"))
        .bytes(client_pub)
        .u64(ts)
        .text(device_id)
        .text(device_key_id)
        .text(app_version)
        .text(risk_flags_csv)
        .finish()
}

/// `frame("doodle/v1/transcript", clientPub, deviceKeyId, serverPub, sid, u64(ts), u64(serverTime), kid)`.
#[allow(clippy::too_many_arguments)]
pub fn transcript_input(
    client_pub: &[u8; 32],
    device_key_id: &str,
    server_pub: &[u8; 32],
    sid: &str,
    ts: u64,
    server_time: u64,
    kid: &str,
) -> Vec<u8> {
    Frame::with_capacity(224)
        .text(obfstr!("doodle/v1/transcript"))
        .bytes(client_pub)
        .text(device_key_id)
        .bytes(server_pub)
        .text(sid)
        .u64(ts)
        .u64(server_time)
        .text(kid)
        .finish()
}

pub fn transcript(
    client_pub: &[u8; 32],
    device_key_id: &str,
    server_pub: &[u8; 32],
    sid: &str,
    ts: u64,
    server_time: u64,
    kid: &str,
) -> [u8; 32] {
    Sha256::digest(transcript_input(client_pub, device_key_id, server_pub, sid, ts, server_time, kid)).into()
}

/// `k = HKDF-SHA256(ikm = shared, salt = transcript, info = "doodle/v1/c2s" | "doodle/v1/s2c", 32)`.
pub fn derive_session_keys(shared: &[u8; 32], transcript: &[u8; 32]) -> SessionKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut c2s = Zeroizing::new([0u8; KEY_LENGTH]);
    let mut s2c = Zeroizing::new([0u8; KEY_LENGTH]);
    // 32 bytes is far below the HKDF-SHA256 output limit (255 * 32), so expand cannot fail.
    let _ = hkdf.expand(obfstr!("doodle/v1/c2s").as_bytes(), c2s.as_mut());
    let _ = hkdf.expand(obfstr!("doodle/v1/s2c").as_bytes(), s2c.as_mut());
    SessionKeys { c2s, s2c }
}

/// `frame("doodle/v1/start-resp", sid)`.
pub fn start_response_aad(sid: &str) -> Vec<u8> {
    Frame::new().text(obfstr!("doodle/v1/start-resp")).text(sid).finish()
}

/// `frame("doodle/v1/req", METHOD, pathWithQuery, sid, u64(seq), u64(ts), appVersion)`.
pub fn request_aad(method: &str, path_with_query: &str, sid: &str, seq: u64, ts: u64, app_version: &str) -> Vec<u8> {
    Frame::with_capacity(96 + path_with_query.len())
        .text(obfstr!("doodle/v1/req"))
        .text(method)
        .text(path_with_query)
        .text(sid)
        .u64(seq)
        .u64(ts)
        .text(app_version)
        .finish()
}

/// `frame("doodle/v1/resp", sid, u64(seq), u64(httpStatus), contentEncoding)`: `content_encoding` is the
/// `X-Tx-Encoding` header of the response ("gzip" when the plaintext is compressed, "" otherwise), so a client cannot
/// be made to read a compressed body as plain or the reverse.
pub fn response_aad(sid: &str, seq: u64, status: u64, content_encoding: &str) -> Vec<u8> {
    Frame::new().text(obfstr!("doodle/v1/resp")).text(sid).u64(seq).u64(status).text(content_encoding).finish()
}
