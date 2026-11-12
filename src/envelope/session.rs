//! An established envelope session: request sealing and response opening (server/docs/app-security.md section 5).

use std::collections::BTreeSet;

use super::validate;
use super::wire::{self, SessionKeys, DIR_C2S, DIR_S2C, MAX_SEQ, TAG_LENGTH};
use crate::codec::b64url_encode;
use crate::error::{Error, Result};

/// Responses we still accept: seqs issued by this session and not opened yet. Bounded so a caller that never opens
/// responses (timeouts, plain JSON errors) cannot grow it without limit; the oldest seq is forgotten first.
const MAX_OUTSTANDING: usize = 1024;
/// Stop using a session slightly before the server's absolute expiry.
const EXPIRY_MARGIN_MS: u64 = 30_000;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// What the app needs to send one sealed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRequest {
    /// `X-Tx-Seq` (decimal) and the seq to pass back when opening the response.
    pub seq: u64,
    /// `X-Tx-Ts` (decimal), server time in ms.
    pub ts: u64,
    /// `X-Tx-Session`.
    pub sid: String,
    /// `X-App-Version`: must be the value covered by the AAD, i.e. the handshake's appVersion.
    pub app_version: String,
    /// `X-Tx-Tag` for bodyless requests (GET, DELETE, empty POST); `None` when `body` is sent. A bodyless request
    /// carries no Content-Type: the server reads a sealed Content-Type, even on an empty body, as a sealed body.
    pub tag: Option<String>,
    /// `ciphertext ‖ tag` sent with `Content-Type: application/vnd.doodle.sealed`; empty for bodyless requests.
    pub body: Vec<u8>,
}

pub struct Session {
    sid: String,
    app_version: String,
    keys: SessionKeys,
    next_seq: u64,
    server_time_at_start: u64,
    mono_at_start: u64,
    expires_at_mono: Option<u64>,
    outstanding: BTreeSet<u64>,
}

impl Session {
    pub(crate) fn new(
        sid: String,
        app_version: String,
        keys: SessionKeys,
        server_time: u64,
        mono_now: u64,
        session_ttl_seconds: Option<u64>,
    ) -> Self {
        let expires_at_mono = session_ttl_seconds
            .map(|ttl| mono_now.saturating_add(ttl.saturating_mul(1000)).saturating_sub(EXPIRY_MARGIN_MS));
        Self {
            sid,
            app_version,
            keys,
            next_seq: 1,
            server_time_at_start: server_time,
            mono_at_start: mono_now,
            expires_at_mono,
            outstanding: BTreeSet::new(),
        }
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }

    pub fn app_version(&self) -> &str {
        &self.app_version
    }

    /// Server time now: `serverTime` of the handshake plus the monotonic time elapsed since.
    pub fn server_now(&self, mono_now: u64) -> u64 {
        self.server_time_at_start.saturating_add(mono_now.saturating_sub(self.mono_at_start))
    }

    pub fn is_expired(&self, mono_now: u64) -> bool {
        self.expires_at_mono.is_some_and(|deadline| mono_now >= deadline)
    }

    /// Seals the next request. `body` empty means a bodyless request (tag goes to `X-Tx-Tag`).
    pub fn seal_request(
        &mut self,
        method: &str,
        path_with_query: &str,
        body: &[u8],
        mono_now: u64,
    ) -> Result<SealedRequest> {
        if self.is_expired(mono_now) {
            return Err(Error::SessionExpired);
        }
        let seq = self.next_seq;
        let ts = self.server_now(mono_now);
        self.seal_at(seq, ts, method, path_with_query, body)
    }

    /// Seals with an explicit seq and ts (vectors and tests). Advances the counter past `seq`.
    #[doc(hidden)]
    pub fn seal_at(
        &mut self,
        seq: u64,
        ts: u64,
        method: &str,
        path_with_query: &str,
        body: &[u8],
    ) -> Result<SealedRequest> {
        if !validate::method(method) || !validate::path_with_query(path_with_query) || body.len() > MAX_BODY_BYTES {
            return Err(Error::InvalidArgument);
        }
        if seq == 0 || seq > MAX_SEQ || seq < self.next_seq {
            return Err(if seq > MAX_SEQ { Error::SeqExhausted } else { Error::InvalidArgument });
        }
        let aad = wire::request_aad(method, path_with_query, &self.sid, seq, ts, &self.app_version);
        let sealed = wire::seal(&self.keys.c2s, DIR_C2S, seq, &aad, body).ok_or(Error::InvalidArgument)?;
        // The seq is spent from here on, even if the request never leaves the device (theme-x wire format §4).
        self.next_seq = seq + 1;
        self.remember(seq);

        let (tag, body) = if body.is_empty() {
            (Some(b64url_encode(&sealed[sealed.len() - TAG_LENGTH..])), Vec::new())
        } else {
            (None, sealed)
        };
        Ok(SealedRequest { seq, ts, sid: self.sid.clone(), app_version: self.app_version.clone(), tag, body })
    }

    /// Opens a sealed response (`Content-Type: application/vnd.doodle.sealed`) for request `seq` answered with
    /// `http_status` and `X-Tx-Encoding: content_encoding` ("" when absent). Each seq opens at most once. Unsealed
    /// answers never reach this: `api::session_response` turns them into errors. The plaintext is returned as sealed:
    /// still compressed when `content_encoding` is "gzip".
    pub fn open_response(
        &mut self,
        seq: u64,
        http_status: u16,
        content_encoding: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.outstanding.contains(&seq) {
            return Err(Error::ReplayedResponse);
        }
        if !(100..=599).contains(&http_status)
            || sealed.len() < TAG_LENGTH
            || sealed.len() > MAX_BODY_BYTES + TAG_LENGTH
        {
            return Err(Error::DecryptFailed);
        }
        if !validate::content_encoding(content_encoding) {
            return Err(Error::DecryptFailed);
        }
        let aad = wire::response_aad(&self.sid, seq, u64::from(http_status), content_encoding);
        let plaintext = wire::open(&self.keys.s2c, DIR_S2C, seq, &aad, sealed).ok_or(Error::DecryptFailed)?;
        self.outstanding.remove(&seq);
        Ok(plaintext)
    }

    /// Forgets an issued seq whose response will never be opened (transport error, plain JSON error).
    pub fn abandon(&mut self, seq: u64) {
        self.outstanding.remove(&seq);
    }

    fn remember(&mut self, seq: u64) {
        self.outstanding.insert(seq);
        while self.outstanding.len() > MAX_OUTSTANDING {
            self.outstanding.pop_first();
        }
    }

    #[cfg(test)]
    pub(crate) fn keys(&self) -> &SessionKeys {
        &self.keys
    }
}
