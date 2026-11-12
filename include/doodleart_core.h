/*
 * doodleart_core.h: C ABI of doodleart-core, the native security core of DoodleArt (ported from theme-x), for the iOS
 * app (Swift module DoodleArtCore, shipped as DoodleArtCore.xcframework).
 * The Rust side is doodleart-core/src/ffi.rs over src/api.rs, the byte API the Android JNI natives also use: same
 * handles, status codes and reply layouts.
 * Wire format: server/docs/app-security.md (sections 3 to 6), vectors server/src/core/envelope/testdata/.
 *
 * Replies
 *   Every function returning DoodleArtBuf returns "status (1 byte) || payload".
 *   - status 0 (DOODLEART_STATUS_OK): the payload is what the function documents. Single values are raw bytes; several
 *     values are frame(f1, f2, ...) = u32be(len(f1)) || f1 || u32be(len(f2)) || f2 || ..., where text is UTF-8 and
 *     u64(x) is an 8-byte big-endian field.
 *   - any other status (DOODLEART_STATUS_*): an error. The payload is empty, except
 *     DOODLEART_STATUS_SERVER_REJECTED:   frame(u64(httpStatus), code, u64(serverTime or 0)),
 *     DOODLEART_STATUS_UNSEALED_RESPONSE: frame(u64(httpStatus), code).
 *   - a NULL ptr would mean that not even an error reply could be allocated: treat it as DOODLEART_STATUS_INTERNAL.
 *   Functions returning int32_t return the status code itself.
 *   A reply may gain fields appended at its end in a later version with the same DOODLEART_ABI_VERSION: read the fields
 *   you know, ignore the rest.
 *
 * Ownership
 *   Rust owns every returned DoodleArtBuf. Copy what you need, then release it exactly once with doodleart_buf_free; never
 *   free() it and never write to it. Simplest: one wrapper that copies the reply into a Data and frees it right away
 *   (Swift: `defer { doodleart_buf_free(buf) }` right after the call), so no DoodleArtBuf outlives the call that returned it.
 *   doodleart_buf_free ignores {NULL, 0}, a wrong len and an address that holds no live reply. A SECOND release of the
 *   same DoodleArtBuf is undefined behaviour: the allocator reuses addresses at once, so the stale {ptr, len} may by then
 *   be another reply (of this thread or another one), which it would release under its owner. Leaks are yours to
 *   avoid too.
 *
 * Inputs
 *   Byte strings are (ptr, len) pairs, read during the call only, never retained or modified.
 *   - (NULL, 0) is "absent", (ptr, 0) the empty string. Where a value is optional, absent is the empty value; where
 *     it is required, both are refused (the status may differ). One exception: requestId of doodleart_integrity_hash,
 *     where absent makes Rust generate one and empty is refused. From Swift, an empty Data may give a NULL address.
 *   - (NULL, len > 0) and len > DOODLEART_MAX_INPUT_LEN are DOODLEART_STATUS_INVALID_ARGUMENT.
 *   - Otherwise ptr must point to len readable bytes for the duration of the call.
 *   Handles (handshake, session) are positive 63-bit numbers, never pointers: an unknown, used, expired or evicted one
 *   is DOODLEART_STATUS_UNKNOWN_HANDLE. An HTTP status outside 100-599 is DOODLEART_STATUS_INVALID_ARGUMENT for
 *   doodleart_handshake_finish (the handshake is consumed) and doodleart_session_response (refused before the seq is
 *   looked at: it stays pending); doodleart_session_open: DECRYPT_FAILED, see there.
 *
 * Threads and panics
 *   Every function is thread-safe. doodleart_handshake_begin and doodleart_risk_scan block (risk scan: a loopback connect of
 *   up to 150 ms, file probes, a walk of the loaded images): never call them on the main thread. A Rust panic never
 *   crosses this boundary: it becomes DOODLEART_STATUS_INTERNAL, and nothing is printed (the first call of any function
 *   installs a silent panic hook in this library's own Rust runtime). The core keeps one clock offset and one handle
 *   table per process.
 *
 * Linking
 *   The library exports the doodleart_* functions of this header and nothing else: build-ios.sh prelinks it into one
 *   object whose other symbols, the Rust runtime included, are all local (tools/check-macho.sh checks it). Another
 *   Rust static library can therefore be linked next to it; each keeps its own runtime and panic hook (step 5 of
 *   tools/c-abi-smoke.sh links and runs both). rustc lists
 *   -liconv -lSystem -lc -lm as the system libraries of every Apple target; libSystem is always linked and the
 *   library references no iconv symbol today (tools/c-abi-smoke.sh links rustc's list).
 *   Privacy manifest: the library imports fstat (Rust std: its backtrace symbolizer reads the size of the app's own
 *   executable), one of Apple's required-reason APIs. The app declares NSPrivacyAccessedAPICategoryFileTimestamp in
 *   its PrivacyInfo.xcprivacy (proposed reason C617.1, files inside the app container; the iOS team confirms it).
 *   check-macho prints the required-reason imports of every build.
 */

#ifndef DOODLEART_CORE_H
#define DOODLEART_CORE_H

#include <stddef.h>
#include <stdint.h>

/* Clang nullability (Swift imports the pointers as optionals); the push silences -Wnullability-extension under
 * -pedantic for this header only. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-extension"
#define DOODLEART_NULLABLE _Nullable
#else
#define DOODLEART_NULLABLE
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Version of this ABI; doodleart_init reports the library's. A change that could break a caller built against an older
 * header changes it; additions (a new function, a field appended to a reply) do not. */
#define DOODLEART_ABI_VERSION 1

/* Largest accepted input length in bytes (64 MiB). */
#define DOODLEART_MAX_INPUT_LEN 67108864

/* Status codes (first byte of every reply; return value of the int32_t functions). The numbers are fixed. */
#define DOODLEART_STATUS_OK 0
/* An argument has the wrong shape (method not upper case, path with a space, an id that does not match the server's
 * pattern, a signature that is not DER, a NULL pointer with a length...). A programming error: do not retry. */
#define DOODLEART_STATUS_INVALID_ARGUMENT 1
/* Handle unknown, already consumed, expired or evicted: start a new handshake. */
#define DOODLEART_STATUS_UNKNOWN_HANDLE 2
/* Call out of order (handshake body requested twice, finish before body): start a new handshake. */
#define DOODLEART_STATUS_HANDSHAKE_STATE 3
/* Handshake answer malformed: do not trust it; back off, then start again. */
#define DOODLEART_STATUS_BAD_SERVER_RESPONSE 4
/* Unknown kid or wrong server signature (man in the middle, or a library of the wrong build type). */
#define DOODLEART_STATUS_BAD_SERVER_SIGNATURE 5
/* The handshake was answered with a status other than 200.
 * Payload frame(u64(httpStatus), code, u64(serverTime or 0)): code is meta.code as decimal text ("" if none),
 * serverTime the X-Server-Time header passed to doodleart_handshake_finish. */
#define DOODLEART_STATUS_SERVER_REJECTED 6
/* AEAD open failed (tampered body, wrong status or seq): do not trust the response. */
#define DOODLEART_STATUS_DECRYPT_FAILED 7
/* The response seq was never issued by this session or was already opened. */
#define DOODLEART_STATUS_REPLAYED_RESPONSE 8
/* seq would pass 2^53 - 1: close the session, open a new one. */
#define DOODLEART_STATUS_SEQ_EXHAUSTED 9
/* The session passed its absolute lifetime: close it, open a new one. */
#define DOODLEART_STATUS_SESSION_EXPIRED 10
/* Reserved (the handle tables evict their oldest entry instead). */
#define DOODLEART_STATUS_LIMIT_REACHED 11
/* The OS random source failed: retry later. */
#define DOODLEART_STATUS_RNG 12
/* A bug: a panic was caught at this boundary. */
#define DOODLEART_STATUS_INTERNAL 13
/* The answer to a sealed request is not sealed, 2xx included: never data. Payload frame(u64(httpStatus), code), code
 * being the unauthenticated meta.code of a 4xx/5xx JSON body as decimal text, e.g. "40101010" ("" otherwise). */
#define DOODLEART_STATUS_UNSEALED_RESPONSE 14

/* A reply owned by Rust: len bytes at ptr. Release with doodleart_buf_free. */
typedef struct DoodleArtBuf {
    uint8_t *DOODLEART_NULLABLE ptr;
    size_t len;
} DoodleArtBuf;

/* Build information, for logs and for checking the library against the app's configuration. Optional: no other
 * function needs it first.
 * OK: frame(buildType, crateVersion, kidsCsv, u64(abiVersion), projectId), e.g. ("debug", "0.1.0", "2026-11", 1,
 * "doodleart"). buildType is "debug" or "release"; kidsCsv lists the embedded server key ids. */
DoodleArtBuf doodleart_init(void);

/* deviceKeyId = base64url(SHA-256(spki)) for a P-256 SubjectPublicKeyInfo: exactly 91 bytes, the 26-byte P-256 SPKI
 * header followed by the 65-byte X9.63 point that SecKeyCopyExternalRepresentation returns for the public key.
 * OK: the 43-character deviceKeyId (raw UTF-8). INVALID_ARGUMENT: not a 91-byte P-256 SPKI. */
DoodleArtBuf doodleart_device_key_id(const uint8_t *DOODLEART_NULLABLE spki, size_t spki_len);

/* Starts a session handshake. Runs the core's own risk scan (blocking; Swift passes no flags), creates a fresh X25519
 * key and takes ts from the device clock plus the last known server offset.
 * device_id: the lowercase UUID POST /api/v1/devices/register returned; device_key_id: doodleart_device_key_id's;
 * app_version: digits and dots (an optional -/+ suffix), at most 32 characters, the X-App-Version of every sealed
 * request of the session.
 * OK: frame(u64(handshake), signatureMessage, riskFlagsCsv). Sign signatureMessage, exactly these bytes, with the
 * Secure Enclave device key (ECDSA P-256 SHA-256, DER), then call doodleart_handshake_body. The App Attest assertion of
 * session/start uses doodleart_handshake_assert_hash (or doodleart_session_assert_hash on signatureMessage).
 * Handshakes live 10 minutes; at most 16 are pending (the oldest is evicted). */
DoodleArtBuf doodleart_handshake_begin(const uint8_t *DOODLEART_NULLABLE device_id, size_t device_id_len,
                                 const uint8_t *DOODLEART_NULLABLE device_key_id, size_t device_key_id_len,
                                 const uint8_t *DOODLEART_NULLABLE app_version, size_t app_version_len);

/* The JSON body of POST /api/v1/session/start for the DER signature of signatureMessage (8 to 72 bytes).
 * OK: the body (raw). Once per handshake: a second call is HANDSHAKE_STATE. */
DoodleArtBuf doodleart_handshake_body(int64_t handshake, const uint8_t *DOODLEART_NULLABLE device_sig, size_t device_sig_len);

/* Completes the handshake with the HTTP status, the X-Server-Time header (ms, 0 if absent) and the body of
 * /api/v1/session/start, whatever they are. Always consumes the handshake: on any failure start again with
 * doodleart_handshake_begin.
 * OK: frame(u64(session), sid, sessionInfoJson), sessionInfoJson = { session_ttl_seconds, idle_ttl_seconds,
 * min_app_version, trust, user_id, is_anonymous }. A status other than 200 is SERVER_REJECTED (the core also learns
 * the server clock from server_time, for the next handshake); BAD_SERVER_RESPONSE and BAD_SERVER_SIGNATURE mean the
 * answer is not to be trusted. At most 32 sessions live (the oldest is evicted). */
DoodleArtBuf doodleart_handshake_finish(int64_t handshake, int32_t http_status, int64_t server_time,
                                        const uint8_t *DOODLEART_NULLABLE body, size_t body_len);

/* Drops a handshake whose request failed before any response. Returns the status (UNKNOWN_HANDLE if already gone). */
int32_t doodleart_handshake_abort(int64_t handshake);

/* Seals a request. method: upper case (GET, POST...); path_with_query: the raw request target exactly as sent,
 * percent-encoded, starting with "/"; body: the plaintext, absent or empty for a bodyless request.
 * OK: frame(u64(seq), u64(ts), sid, appVersion, tag, sealedBody); exactly one of tag / sealedBody is non-empty.
 * Headers: X-Tx-Session = sid, X-Tx-Seq = seq, X-Tx-Ts = ts (decimal), X-App-Version = appVersion, and either
 * X-Tx-Tag = tag with an empty body and no Content-Type, or Content-Type: application/vnd.doodle.sealed with
 * sealedBody. The seq is spent even if the request is never sent: retry with a new seal. */
DoodleArtBuf doodleart_session_seal(int64_t session, const uint8_t *DOODLEART_NULLABLE method, size_t method_len,
                              const uint8_t *DOODLEART_NULLABLE path_with_query, size_t path_with_query_len,
                              const uint8_t *DOODLEART_NULLABLE body, size_t body_len);

/* Reads the answer to a sealed request: the only way to read one. Pass the HTTP status, the Content-Type and
 * X-Tx-Encoding headers (absent if none) and the raw body.
 * OK: the plaintext (raw, gzip already decoded when X-Tx-Encoding is gzip): the {meta, data} JSON of the route,
 * whatever the HTTP status (403, 409... of the route are sealed too). Any answer that is not Content-Type
 * application/vnd.doodle.sealed, 2xx included, is UNSEALED_RESPONSE: never data. DECRYPT_FAILED / REPLAYED_RESPONSE:
 * do not trust it. The seq is spent whatever the outcome. */
DoodleArtBuf doodleart_session_response(int64_t session, int64_t seq, int32_t http_status,
                                        const uint8_t *DOODLEART_NULLABLE content_type, size_t content_type_len,
                                        const uint8_t *DOODLEART_NULLABLE content_encoding, size_t content_encoding_len,
                                        const uint8_t *DOODLEART_NULLABLE body, size_t body_len);

/* Low level: opens a body known to be sealed (once per seq), decoded like doodleart_session_response. Prefer
 * doodleart_session_response.
 * OK: the plaintext (raw). DECRYPT_FAILED leaves the seq pending. An http_status outside 100-599 is DECRYPT_FAILED
 * here, not INVALID_ARGUMENT (as the Android sessionOpen native): pass the status the response really had. */
DoodleArtBuf doodleart_session_open(int64_t session, int64_t seq, int32_t http_status,
                                    const uint8_t *DOODLEART_NULLABLE content_encoding, size_t content_encoding_len,
                                    const uint8_t *DOODLEART_NULLABLE sealed, size_t sealed_len);

/* Forgets a seq whose response will never come (network error). Optional. Returns the status. */
int32_t doodleart_session_abandon(int64_t session, int64_t seq);

/* Closes a session and wipes its keys. Returns the status (UNKNOWN_HANDLE if already gone). */
int32_t doodleart_session_close(int64_t session);

/* DAPI1 requestHash of a protected request (theme-x TXPI1; no doodle-art route checks it yet).
 * request_id: a UUID, absent to let Rust generate a v4 (use a new one for every assertion, retries included);
 * sid: the session's, absent or empty before a session; body: exactly the plaintext that will be sealed.
 * OK: frame(requestId, requestHash, requestHashRaw): requestHash is base64url text, requestHashRaw its 32 raw bytes,
 * the clientDataHash for generateAssertion. Send X-Integrity-Request-Id = requestId. */
DoodleArtBuf doodleart_integrity_hash(const uint8_t *DOODLEART_NULLABLE method, size_t method_len,
                                const uint8_t *DOODLEART_NULLABLE path_with_query, size_t path_with_query_len,
                                const uint8_t *DOODLEART_NULLABLE request_id, size_t request_id_len,
                                const uint8_t *DOODLEART_NULLABLE sid, size_t sid_len,
                                const uint8_t *DOODLEART_NULLABLE body, size_t body_len);

/* The registration message of POST /api/v1/devices/register and its SHA-256:
 * registerMessage = frame("doodle/v1/register", nonce bytes, device_id, device_key_id, platform), what the device key
 * signs (the body's signature, DER); clientDataHash = SHA-256(registerMessage), what attestKey (App Attest) covers.
 * nonce: the 32-character challenge text of POST /api/v1/auth/challenge (a new one per registration); device_id: the
 * lowercase UUID the body sends; device_key_id: doodleart_device_key_id's; platform: "ios" or "android".
 * OK: frame(registerMessage, clientDataHash). INVALID_ARGUMENT when a value does not match the server's schema. */
DoodleArtBuf doodleart_register_message(const uint8_t *DOODLEART_NULLABLE nonce, size_t nonce_len,
                                        const uint8_t *DOODLEART_NULLABLE device_id, size_t device_id_len,
                                        const uint8_t *DOODLEART_NULLABLE device_key_id, size_t device_key_id_len,
                                        const uint8_t *DOODLEART_NULLABLE platform, size_t platform_len);

/* iosDeviceHash = hex(SHA-256(frame("doodle/v1/ios-device", secret))) of the 32-byte random secret kept in the
 * Keychain (a device signal of theme-x; the doodle-art server does not use it yet). OK: 64 lowercase hex characters
 * (raw UTF-8). INVALID_ARGUMENT: secret_len is not 32. */
DoodleArtBuf doodleart_ios_device_hash(const uint8_t *DOODLEART_NULLABLE secret, size_t secret_len);

/* DAAS1 clientDataHash for the App Attest assertion of POST /api/v1/session/start, sent as X-Integrity-Token
 * (base64url of the assertion); the body does not change. signature_message: exactly the signatureMessage of
 * doodleart_handshake_begin.
 * OK: 32 raw bytes. INVALID_ARGUMENT for anything that is not a handshake signature message. */
DoodleArtBuf doodleart_session_assert_hash(const uint8_t *DOODLEART_NULLABLE signature_message, size_t signature_message_len);

/* DAAS1 clientDataHash of a pending handshake's own signatureMessage: the same 32 bytes as
 * doodleart_session_assert_hash(signatureMessage), without passing the message back. The handshake stays as it is.
 * OK: 32 raw bytes. UNKNOWN_HANDLE once the handshake is finished or aborted. */
DoodleArtBuf doodleart_handshake_assert_hash(int64_t handshake);

/* The core's own risk scan (blocking), for logs and for request bodies that carry risk_flags (the handshake runs its
 * own). riskFlags = the CSV split on "," (an empty CSV is [], not [""]).
 * OK: frame(riskFlagsCsv, detailsCsv): sorted flag names joined with ",", empty when none; detailsCsv names the checks
 * that fired and is empty in release builds.
 * Flags on iOS: root (jailbreak files, a file created outside the sandbox), hook (tweak
 * libraries loaded, DYLD_INSERT_LIBRARIES set), frida (Frida's agent or gadget loaded, 127.0.0.1:27042 open), debugger
 * (P_TRACED), emulator (every Simulator build). Never apk_resigned. A run from Xcode reports debugger (and hook when
 * Xcode's diagnostics insert libraries): the device is then untrusted, so trust tests start the app from the home
 * screen (or with `xcrun simctl launch`, no debugger). On the Simulator the emulator flag (light) caps a session at
 * limited even with a passing App Attest stub: trusted is only reachable on a device. The macOS library (host tests)
 * skips the file probes (detail root.unchecked). */
DoodleArtBuf doodleart_risk_scan(void);

/* Releases a reply of any function above, exactly once per reply. Ignores {NULL, 0}; a second release of the same
 * buffer is undefined (see Ownership). */
void doodleart_buf_free(DoodleArtBuf buf);

/* DEBUG LIBRARIES ONLY: absent from release libraries, so a call compiled into a Release app fails to link; keep
 * calls under #if DEBUG. Moves the session clock forward by ms (0 to 604800000, one week) for the rest of the
 * process, as if the device had slept that long. Returns the status (INVALID_ARGUMENT out of range). */
int32_t doodleart_debug_clock_advance_ms(int64_t ms);

#ifdef __cplusplus
}
#endif

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#endif /* DOODLEART_CORE_H */
