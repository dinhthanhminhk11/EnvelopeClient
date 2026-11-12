//! Server Ed25519 public keys trusted for the handshake signature, looked up by `kid`.
//! The embedded set (current + next) is fixed at build time per build type (build.rs); Kotlin cannot change it.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::build_config;
use crate::error::{Error, Result};

pub struct ServerKeys {
    entries: Vec<(String, VerifyingKey)>,
}

impl ServerKeys {
    /// The keys compiled into this build type.
    pub fn embedded() -> Result<Self> {
        Self::from_raw(build_config::SERVER_KEYS.iter().map(|(kid, key)| (*kid, *key)))
    }

    /// Builds a key set from `(kid, raw 32-byte public key)` pairs; rejects keys that are not valid curve points.
    pub fn from_raw<'a>(pairs: impl IntoIterator<Item = (&'a str, [u8; 32])>) -> Result<Self> {
        let mut entries = Vec::new();
        for (kid, raw) in pairs {
            let key = VerifyingKey::from_bytes(&raw).map_err(|_| Error::InvalidArgument)?;
            // A small-order key would accept forged signatures under non-strict verification.
            if key.is_weak() {
                return Err(Error::InvalidArgument);
            }
            entries.push((kid.to_owned(), key));
        }
        Ok(Self { entries })
    }

    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(kid, _)| kid.as_str())
    }

    /// Strict Ed25519 verification (rejects non-canonical and small-order components) with the key named by `kid`.
    pub fn verify(&self, kid: &str, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let key = self
            .entries
            .iter()
            .find(|(candidate, _)| candidate == kid)
            .map(|(_, key)| key)
            .ok_or(Error::BadServerSignature)?;
        key.verify_strict(message, &Signature::from_bytes(signature)).map_err(|_| Error::BadServerSignature)
    }
}
