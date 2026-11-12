//! Integrity bindings, byte-identical to server/src/core/envelope (integrity.go, envelope.go; docs/app-security.md
//! section 3a; theme-x request-hash.js with the tags renamed):
//! - registration proof: SHA-256 of `frame("doodle/v1/register", ...)` ([`register_client_data_hash`]);
//! - App Attest assertion of a handshake: DAAS1 ([`session_assert_client_data_hash`]);
//! - protected request: `requestHash = base64url(SHA-256(frame("DAPI1", METHOD, pathWithQuery, requestId, sid,
//!   SHA-256(plaintextBody))))`, on the plaintext body before it is sealed, `sid` "" before a session (no server route
//!   checks it yet);
//! - `iosDeviceHash`, a client-only device signal.
//!
//! Tags are protocol names, never per app.

use obfstr::obfstr;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::codec::{b64url_decode_exact, b64url_encode, hex_encode, is_uuid, uuid_v4, Frame};
use crate::envelope::{validate, wire};
use crate::error::{Error, Result};

pub struct IntegrityRequest<'a> {
    pub method: &'a str,
    pub path_with_query: &'a str,
    /// UUID sent as `X-Integrity-Request-Id`.
    pub request_id: &'a str,
    /// Envelope session id, or "" before a session exists.
    pub sid: &'a str,
    pub body: &'a [u8],
}

/// The framed bytes that get hashed.
pub fn preimage(request: &IntegrityRequest<'_>) -> Result<Vec<u8>> {
    if !validate::method(request.method)
        || !validate::path_with_query(request.path_with_query)
        || !is_uuid(request.request_id)
        || !(request.sid.is_empty() || validate::sid(request.sid))
    {
        return Err(Error::InvalidArgument);
    }
    Ok(Frame::with_capacity(160 + request.path_with_query.len())
        .text(obfstr!("DAPI1"))
        .text(request.method)
        .text(request.path_with_query)
        .text(request.request_id)
        .text(request.sid)
        .bytes(&Sha256::digest(request.body))
        .finish())
}

/// base64url(SHA-256(preimage)).
pub fn request_hash(request: &IntegrityRequest<'_>) -> Result<String> {
    Ok(b64url_encode(&Sha256::digest(preimage(request)?)))
}

/// Fresh lowercase UUID v4 for `X-Integrity-Request-Id`.
pub fn new_request_id() -> Result<String> {
    let mut random = [0u8; 16];
    OsRng.try_fill_bytes(&mut random).map_err(|_| Error::Rng)?;
    Ok(uuid_v4(random))
}

/// [`wire::register_message`] of the request body's own values (`POST /api/v1/devices/register`), checked against the
/// server's schema first: `nonce` is the 32-character challenge text (24 bytes once decoded), `device_id` the
/// lowercase UUID, `platform` "ios" or "android".
pub fn register_message(nonce: &str, device_id: &str, device_key_id: &str, platform: &str) -> Result<Vec<u8>> {
    if !validate::challenge_nonce(nonce)
        || !validate::device_id(device_id)
        || !validate::device_key_id(device_key_id)
        || !validate::platform(platform)
    {
        return Err(Error::InvalidArgument);
    }
    let nonce = b64url_decode_exact::<24>(nonce).ok_or(Error::InvalidArgument)?;
    Ok(wire::register_message(&nonce, device_id, device_key_id, platform))
}

/// The 32 raw bytes of the registration proof: the App Attest `clientDataHash` passed to `attestKey`, and the Play
/// Integrity request hash (base64url of these bytes). SHA-256 of [`register_message`], so a proof cannot be moved to
/// another nonce, device or key.
pub fn register_client_data_hash(register_message: &[u8]) -> [u8; 32] {
    Sha256::digest(register_message).into()
}

/// `frame("DAAS1", signatureMessage)`, `SessionAssertClientDataHash` in server/src/core/envelope/integrity.go.
pub fn session_assert_preimage(signature_message: &[u8]) -> Vec<u8> {
    Frame::with_capacity(13 + signature_message.len()).text(obfstr!("DAAS1")).bytes(signature_message).finish()
}

/// The 32 raw bytes iOS passes to `generateAssertion` for `POST /api/v1/session/start` (header `X-Integrity-Token`):
/// SHA-256 of
/// [`session_assert_preimage`]. `signature_message` is exactly what the device key signed, the handshake's
/// `signatureMessage` (`frame("doodle/v1/start", …)`, [`wire::device_signature_message`]).
pub fn session_assert_client_data_hash(signature_message: &[u8]) -> [u8; 32] {
    Sha256::digest(session_assert_preimage(signature_message)).into()
}

/// `iosDeviceHash = hex(SHA-256(frame("doodle/v1/ios-device", secret)))`: an iOS device signal from a 32-byte random
/// secret the app keeps in the Keychain (theme-x uses it for bans and account restore; the doodle-art server has no
/// use for it yet). 64 lowercase hex characters. The framed copy of the secret is wiped before its memory is freed.
pub fn ios_device_hash(secret: &[u8]) -> Result<String> {
    if secret.len() != 32 {
        return Err(Error::InvalidArgument);
    }
    // One allocation of 4 + 20 (tag) + 4 + 32 bytes. The secret is the last field, so even a reallocation would
    // happen before it is copied: the only copy is the one Zeroizing wipes.
    let preimage =
        Zeroizing::new(Frame::with_capacity(64).text(obfstr!("doodle/v1/ios-device")).bytes(secret).finish());
    Ok(hex_encode(&Sha256::digest(preimage.as_slice())))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::codec::{hex_decode, hex_encode};
    use crate::test_support::{attest_vectors, envelope_vectors, frees_leak_sentinel, SECRET_SENTINEL};

    fn text<'a>(case: &'a Value, name: &str) -> &'a str {
        case[name].as_str().unwrap_or_else(|| panic!("{name} in {case}"))
    }

    #[test]
    fn integrity_vectors_of_the_server() {
        let vectors = attest_vectors();
        let cases = vectors["integrity"].as_array().unwrap();
        assert!(cases.len() >= 3);
        for case in cases {
            let body = text(case, "body").as_bytes();
            let request = IntegrityRequest {
                method: text(case, "method"),
                path_with_query: text(case, "path_with_query"),
                request_id: text(case, "request_id"),
                sid: text(case, "sid"),
                body,
            };
            assert_eq!(hex_encode(&preimage(&request).unwrap()), text(case, "preimage"));
            assert_eq!(request_hash(&request).unwrap(), text(case, "request_hash_b64"));
            assert_eq!(hex_encode(&hex_decode(text(case, "request_hash")).unwrap()), text(case, "request_hash"));
        }
    }

    #[test]
    fn rejects_bad_inputs() {
        let ok = IntegrityRequest {
            method: "POST",
            path_with_query: "/api/v1/devices/register",
            request_id: "0f8fad5b-d9cb-469f-a165-70867728950e",
            sid: "",
            body: b"{}",
        };
        assert!(request_hash(&ok).is_ok());
        assert!(request_hash(&IntegrityRequest { method: "post", ..ok }).is_err());
        assert!(request_hash(&IntegrityRequest { request_id: "nope", ..ok }).is_err());
        assert!(request_hash(&IntegrityRequest { sid: "short", ..ok }).is_err());
        assert!(is_uuid(&new_request_id().unwrap()));
    }

    #[test]
    fn register_message_matches_the_server() {
        let envelope = envelope_vectors();
        let attest = attest_vectors();
        let nonce = b64url_encode(&hex_decode(text(&envelope, "nonce")).unwrap());
        let message = register_message(
            &nonce,
            text(&envelope, "device_id"),
            text(&envelope, "key_id"),
            text(&envelope, "platform"),
        )
        .unwrap();
        assert_eq!(hex_encode(&message), text(&envelope, "register_message"));
        assert_eq!(hex_encode(&register_client_data_hash(&message)), text(&attest, "register_client_data_hash"));

        let refused = |nonce: &str, device_id: &str, platform: &str| {
            register_message(nonce, device_id, text(&envelope, "key_id"), platform).err()
        };
        let device_id = text(&envelope, "device_id");
        assert_eq!(refused(&nonce, &device_id.to_uppercase(), "ios"), Some(Error::InvalidArgument), "uppercase UUID");
        assert_eq!(refused(&nonce[..31], device_id, "ios"), Some(Error::InvalidArgument), "short nonce");
        assert_eq!(refused(&nonce, device_id, "web"), Some(Error::InvalidArgument), "platform");
    }

    #[test]
    fn session_assert_vectors() {
        let vectors = attest_vectors();
        let message = hex_decode(text(&vectors, "start_message")).unwrap();
        assert_eq!(hex_encode(&session_assert_preimage(&message)), text(&vectors, "session_assert_preimage"));
        assert_eq!(
            hex_encode(&session_assert_client_data_hash(&message)),
            text(&vectors, "session_assert_client_data_hash")
        );
        assert_eq!(text(&vectors, "start_message"), text(&envelope_vectors(), "start_message"), "same handshake");
    }

    #[test]
    fn ios_device_hash_vectors() {
        let vectors = attest_vectors();
        for case in vectors["ios_device_hash"].as_array().unwrap() {
            let secret = hex_decode(text(case, "secret")).unwrap();
            assert_eq!(ios_device_hash(&secret).unwrap(), text(case, "hash"));
        }
        assert_eq!(ios_device_hash(&[0u8; 31]).err(), Some(Error::InvalidArgument));
        assert!(!frees_leak_sentinel(|| {
            let _ = ios_device_hash(&SECRET_SENTINEL);
        }));
    }
}
