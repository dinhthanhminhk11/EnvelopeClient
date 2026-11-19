//! Envelope v1, client side: X25519 handshake signed by the server (Ed25519), HKDF session keys,
//! ChaCha20-Poly1305 requests and responses. Byte contract: server/docs/app-security.md section 3.

mod handshake;
mod keys;
mod session;
pub mod validate;
pub mod wire;

pub(crate) use handshake::plain_error;
pub use handshake::{ClockSample, Established, HandshakeParams, PendingHandshake};
pub use keys::ServerKeys;
pub use session::{SealedRequest, Session};

#[cfg(test)]
mod vector_tests;
