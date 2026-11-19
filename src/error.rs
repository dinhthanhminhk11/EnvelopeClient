//! Error type shared by the core modules. Every variant maps to one status byte of the JNI API
//! (include/doodleart_core.h, DOODLEART_STATUS_*); the numbers are part of that contract.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An argument from Kotlin has the wrong shape (bad method, path, id, flag, signature length…).
    InvalidArgument,
    /// Handle unknown, already consumed, expired or evicted.
    UnknownHandle,
    /// Call out of order: handshake body already produced, or finish before the body was produced.
    HandshakeState,
    /// Server answer malformed: bad JSON, missing/oversized field, low-order key, unparsable start info.
    BadServerResponse,
    /// Unknown `kid` or Ed25519 signature over the transcript does not verify. Never retry on the same data.
    BadServerSignature,
    /// Handshake answered with a non-200 status. `code` is the server error code when the body had one;
    /// `server_time` comes from `details.serverTime` (400 invalid_request on a far-off clock).
    ServerRejected { status: u16, code: Option<String>, server_time: Option<u64> },
    /// AEAD open failed (tampered body, wrong status, wrong seq, wrong key).
    DecryptFailed,
    /// The response's seq was never issued by this session or was already opened.
    ReplayedResponse,
    /// seq would exceed 2^53 − 1: open a new session.
    SeqExhausted,
    /// The session passed its absolute lifetime: open a new session.
    SessionExpired,
    /// Too many live handles of this kind (the oldest is evicted for handshakes; sessions report this).
    LimitReached,
    /// The OS random source failed.
    Rng,
    /// A bug: a panic was caught at the FFI boundary.
    Internal,
    /// The answer to a sealed request is not sealed. Never data: `code` is the unauthenticated `error.code` of a
    /// 4xx/5xx plain JSON body (envelope errors such as `session_unknown`), only good for deciding what to do next.
    UnsealedResponse { status: u16, code: Option<String> },
}

impl Error {
    /// Status byte of the JNI API. 0 is success and is not an error.
    pub fn status(&self) -> u8 {
        match self {
            Error::InvalidArgument => 1,
            Error::UnknownHandle => 2,
            Error::HandshakeState => 3,
            Error::BadServerResponse => 4,
            Error::BadServerSignature => 5,
            Error::ServerRejected { .. } => 6,
            Error::DecryptFailed => 7,
            Error::ReplayedResponse => 8,
            Error::SeqExhausted => 9,
            Error::SessionExpired => 10,
            Error::LimitReached => 11,
            Error::Rng => 12,
            Error::Internal => 13,
            Error::UnsealedResponse { .. } => 14,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "doodleart-core error {}", self.status())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
