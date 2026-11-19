//! Shape checks for values that end up in signed frames or headers. They mirror the server's request schemas
//! (server/src/app/requests/secure_session_requests.go, app/middlewares/envelope.go) so a Swift or Kotlin mistake fails
//! here with INVALID_ARGUMENT instead of as an opaque 400 from the server.

use crate::codec::b64url_decode_exact;

/// `device_id` as the server stores it and signs it: a UUID in its canonical lowercase form (36 characters). The app
/// keeps the value `POST /api/v1/devices/register` returned; iOS `UUID().uuidString` is uppercase and must be
/// lowercased first.
pub fn device_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, &b)| match index {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// Platform of `device.platform`: the two values of the server's `platform` validator.
pub fn platform(value: &str) -> bool {
    matches!(value, "ios" | "android")
}

/// base64url of a SHA-256 digest: 43 characters, canonical.
pub fn device_key_id(value: &str) -> bool {
    value.len() == 43 && b64url_decode_exact::<32>(value).is_some()
}

/// `^\d{1,6}(?:\.\d{1,6}){0,3}(?:[-+][0-9A-Za-z.-]{1,40})?$`, at most 32 characters (the server's `app_version`
/// is `max=32` and its header pattern `^[0-9A-Za-z.+_-]{1,64}$`; the version core is compared numerically).
pub fn app_version(value: &str) -> bool {
    if value.len() > 32 {
        return false;
    }
    let (core, suffix) = match value.find(['-', '+']) {
        Some(index) => (&value[..index], Some(&value[index + 1..])),
        None => (value, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let core_ok = (1..=4).contains(&parts.len())
        && parts.iter().all(|part| (1..=6).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()));
    let suffix_ok = suffix.is_none_or(|suffix| {
        (1..=40).contains(&suffix.len()) && suffix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    });
    core_ok && suffix_ok
}

/// `^[a-z0-9_-]{1,32}$`
pub fn risk_flag(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// API error code (`meta.code` of a plain JSON error, docs/app-security.md section 6): a decimal number of 3 to 8
/// digits without a leading zero (`500`, `40101010`).
pub fn error_code(value: &str) -> bool {
    (3..=8).contains(&value.len()) && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())
}

/// HTTP method as the server reads it: uppercase token.
pub fn method(value: &str) -> bool {
    (1..=16).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_uppercase())
}

/// Raw request target as sent on the wire (`encodedPath[?encodedQuery]`): starts with "/", visible ASCII only.
pub fn path_with_query(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 8192 && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `X-Tx-Encoding` of a sealed response: absent ("") or an HTTP content-coding token (the server sends "gzip").
pub fn content_encoding(value: &str) -> bool {
    value.len() <= 32 && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Session id: base64url of 16 bytes (22 characters).
pub fn sid(value: &str) -> bool {
    value.len() == 22 && b64url_decode_exact::<16>(value).is_some()
}

/// `kid` as configured on the server (ENVELOPE_SIGNING_KID).
pub fn kid(value: &str) -> bool {
    (1..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// DER ECDSA P-256 signature: a SEQUENCE of 8..=72 bytes (server accepts 11..=96 base64url chars).
pub fn device_signature(value: &[u8]) -> bool {
    (8..=72).contains(&value.len()) && value[0] == 0x30 && usize::from(value[1]) == value.len() - 2
}

/// Challenge nonce of `POST /api/v1/auth/challenge`: base64url of 24 bytes, exactly 32 characters (`nonce`
/// `len=32` in RegisterDeviceRequest).
pub fn challenge_nonce(value: &str) -> bool {
    value.len() == 32 && b64url_decode_exact::<24>(value).is_some()
}

/// App Attest keyId exactly as `DCAppAttestService.generateKey` returns it and `attestation.key_id` carries it: the
/// standard base64 of 32 bytes, `^[A-Za-z0-9+/]{43}=$`.
pub fn app_attest_key_id(value: &str) -> bool {
    value.len() == 44
        && value.ends_with('=')
        && value.bytes().take(43).all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// `iosDeviceHash` in its one canonical form, the one the core produces: 64 lowercase hex characters.
pub fn ios_device_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_version_matches_server_rules() {
        for ok in ["2.0.0", "2", "1.2.3.4", "2.0.0-beta.1", "2.0.0+build-7", "123456.0"] {
            assert!(app_version(ok), "{ok}");
        }
        for bad in [
            "",
            "2.",
            ".2",
            "1.2.3.4.5",
            "1234567",
            "2.0.0-",
            "2.0.0_x",
            "v2.0.0",
            "2.0.0-a b",
            "1.0.0-abcdefghijklmnopqrstuvwxyz12",
        ] {
            assert!(!app_version(bad), "{bad}");
        }
    }

    #[test]
    fn other_shapes() {
        assert!(device_id("6f1c1f9e-3d7a-4c55-9a52-0d6c2f0a8b11"));
        assert!(!device_id("6F1C1F9E-3D7A-4C55-9A52-0D6C2F0A8B11"), "the server signs the lowercase form");
        assert!(!device_id("6f1c1f9e3d7a4c559a520d6c2f0a8b11"));
        assert!(!device_id("6f1c1f9e-3d7a-4c55-9a52-0d6c2f0a8b1g"));
        assert!(platform("ios") && platform("android") && !platform("iOS"));
        assert!(device_key_id("fVjFucbF6WJmoVSlWverWQKikt99mFOm2YMBW17yajs"));
        assert!(!device_key_id("fVjFucbF6WJmoVSlWverWQKikt99mFOm2YMBW17yaj"));
        assert!(risk_flag("apk_resigned"));
        assert!(!risk_flag("Frida"));
        assert!(error_code("40101010") && error_code("500") && !error_code("0401") && !error_code("abc"));
        assert!(!error_code("401010101"));
        assert!(method("GET") && !method("get"));
        assert!(path_with_query("/api/v1/templates?q=%C3%A1o%20d%C3%A0i&page=2"));
        assert!(!path_with_query("/api/v1/a b") && !path_with_query("api/v1"));
        assert!(sid("AAECAwQFBgcICQoLDA0ODw"));
    }

    #[test]
    fn app_attest_shapes_match_server_schemas() {
        assert!(challenge_nonce("wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX"));
        for bad in
            ["wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX=", "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1db", "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1db+"]
        {
            assert!(!challenge_nonce(bad), "{bad}");
        }

        assert!(app_attest_key_id("zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0="));
        for bad in [
            "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0",
            "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0==",
            "zgSY9YSD-7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=",
        ] {
            assert!(!app_attest_key_id(bad), "{bad}");
        }

        assert!(ios_device_hash("de686ed3ac9f13f58768d379bc440abba165fd7b9e16e5427dd583ee938adf29"));
        assert!(!ios_device_hash("DE686ED3AC9F13F58768D379BC440ABBA165FD7B9E16E5427DD583EE938ADF29"));
        assert!(!ios_device_hash("de686ed3ac9f13f58768d379bc440abba165fd7b9e16e5427dd583ee938adf2"));
    }
}
