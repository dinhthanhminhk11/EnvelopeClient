//! C ABI for the iOS app: the functions declared in include/doodleart_core.h, imported by Swift as the module
//! `DoodleArtCore` (include/module.modulemap). Compiled into Apple libraries only (cfg `doodleart_apple_lib`:
//! the iOS library, the Simulator and the macOS slice of build-ios.sh) and into host `cargo test` on macOS: an Android
//! library or a plain macOS build never contains it, so the Android library's only export stays `JNI_OnLoad`, and an
//! Apple library never contains the JNI glue.
//!
//! Every function is a thin wrapper over the byte API of [`crate::api`], the one the JNI natives wrap: the same handle
//! registry, status codes and reply layouts. Conventions (the header repeats them for the iOS team):
//! - A reply is a [`DoodleArtBuf`] holding `status (1 byte) ‖ payload`: status 0 is success, the others are the JNI
//!   status codes; single values are raw, several values are `frame(...)` (u32be length + bytes per field, numbers as
//!   8-byte big-endian fields). The payload of an error is empty except for SERVER_REJECTED and UNSEALED_RESPONSE.
//! - Rust owns every returned buffer; the caller releases each one exactly once with [`doodleart_buf_free`]. It ignores
//!   `{NULL, 0}`, a wrong length and an address no live reply has, but it cannot tell a stale `DoodleArtBuf` from a live
//!   reply that the allocator placed at the same address with the same length: a second release of a buffer is the
//!   caller's bug and may release another reply (no ABI change can fix that without a generation field in
//!   `DoodleArtBuf`, a later ABI version).
//! - Input byte strings are `(ptr, len)` pairs, borrowed for the call only: `(NULL, 0)` is "absent" (the JNI null),
//!   `(NULL, len > 0)` and `len` over 64 MiB are INVALID_ARGUMENT, `(ptr, 0)` is the empty string.
//! - Every entry runs inside `catch_unwind` and installs, once per process, a panic hook that prints nothing: a panic
//!   becomes the INTERNAL status (13) and never unwinds into Swift (which would abort the app); like `JNI_OnLoad`,
//!   nothing reaches stderr (the messages would describe internals).
//!
//! Packaging (deviation from spec §4.1, decision D-P4-2): no `ios-ffi` crate. Cargo also builds the cdylib of a path
//! dependency, which needs the iOS SDK to link and costs another fat-LTO pass; this module is built into the iOS static
//! library with `cargo rustc --lib --crate-type staticlib --target <apple target>`.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{LazyLock, Mutex, MutexGuard, Once, PoisonError};

use crate::api;
use crate::error::Error;

/// Largest input accepted, as from Kotlin (sealed bodies are far smaller).
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// A reply: `len` bytes at `ptr`, owned by Rust until [`doodleart_buf_free`]. `ptr` is never NULL in practice; a NULL
/// reply would mean that not even the INTERNAL reply could be built, and the caller treats it as INTERNAL.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DoodleArtBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl DoodleArtBuf {
    const NULL: DoodleArtBuf = DoodleArtBuf { ptr: ptr::null_mut(), len: 0 };

    /// Hands `reply` to the caller and records it as live.
    fn from_reply(reply: Vec<u8>) -> DoodleArtBuf {
        // Replies always hold a status byte; an empty one would share its dangling address with every other.
        let reply = if reply.is_empty() { api::error_reply(&Error::Internal) } else { reply };
        let len = reply.len();
        let ptr = Box::into_raw(reply.into_boxed_slice()).cast::<u8>();
        live().insert(ptr as usize, len);
        DoodleArtBuf { ptr, len }
    }
}

/// Buffers handed out and not freed yet: address → length. Lets [`doodleart_buf_free`] refuse a pointer it never returned,
/// a wrong length and a release of an address that holds no live reply, instead of corrupting the heap. It does not
/// make a double free safe: once the allocator hands the address to a new reply of the same length, the stale
/// `DoodleArtBuf` matches that reply (module documentation).
static LIVE: LazyLock<Mutex<HashMap<usize, usize>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn live() -> MutexGuard<'static, HashMap<usize, usize>> {
    // A panic while holding the lock (caught at the entry) must not disable buffer handling for the process.
    LIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `(ptr, len)` → bytes borrowed for the call: `(NULL, 0)` is `None`, `(NULL, len > 0)` and an oversized `len` are
/// INVALID_ARGUMENT.
///
/// # Safety
///
/// When `ptr` is not NULL and `len` is at most [`MAX_INPUT_BYTES`], `ptr` must point to `len` readable bytes that stay
/// valid and unchanged until the call returns (the header's contract for every `(ptr, len)` argument).
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Result<Option<&'a [u8]>, Error> {
    if ptr.is_null() {
        return if len == 0 { Ok(None) } else { Err(Error::InvalidArgument) };
    }
    if len > MAX_INPUT_BYTES {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: ptr is non-null and, by the caller's contract, points to len readable bytes for the duration of the call;
    // len is at most 64 MiB, far below isize::MAX; u8 has no alignment requirement.
    Ok(Some(unsafe { std::slice::from_raw_parts(ptr, len) }))
}

macro_rules! input {
    ($ptr:expr, $len:expr) => {
        // SAFETY: the entry's own contract (header and `# Safety`): each (ptr, len) argument is NULL or `len` readable
        // bytes valid for the call.
        unsafe { input($ptr, $len) }?
    };
}

static PANIC_HOOK: Once = Once::new();

/// Installs the silent panic hook once per process. Called by every entry, so it does not depend on `doodleart_init`
/// coming first.
fn install_panic_hook() {
    #[cfg(test)]
    test_hooks::count_hook_check();
    PANIC_HOOK.call_once(|| std::panic::set_hook(silent_hook()));
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

#[cfg(not(test))]
fn silent_hook() -> PanicHook {
    Box::new(|_| {})
}

/// Unit tests: silent for the panics the tests force, so a real failure in a test running in parallel still prints.
#[cfg(test)]
fn silent_hook() -> PanicHook {
    let default = std::panic::take_hook();
    Box::new(move |info| {
        if !test_hooks::take_forced() {
            default(info);
        }
    })
}

/// Runs `body` under `catch_unwind` after installing the panic hook; `fallback()` on a panic.
fn guarded<T>(fallback: impl FnOnce() -> T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(|| {
        install_panic_hook();
        #[cfg(test)]
        test_hooks::on_entry();
        body()
    }))
    .unwrap_or_else(|_| fallback())
}

/// A reply-returning entry: `body` decodes the inputs (INVALID_ARGUMENT on a bad pair) and calls the byte API.
fn reply_buf(body: impl FnOnce() -> Result<Vec<u8>, Error>) -> DoodleArtBuf {
    guarded(internal_buf, || DoodleArtBuf::from_reply(body().unwrap_or_else(|error| api::error_reply(&error))))
}

fn internal_buf() -> DoodleArtBuf {
    catch_unwind(|| DoodleArtBuf::from_reply(api::error_reply(&Error::Internal))).unwrap_or(DoodleArtBuf::NULL)
}

/// A status-returning entry.
fn status(body: impl FnOnce() -> i32) -> i32 {
    guarded(|| i32::from(Error::Internal.status()), body)
}

/// `frame(buildType, crateVersion, kidsCsv, u64(abiVersion), projectId)`.
#[no_mangle]
pub extern "C" fn doodleart_init() -> DoodleArtBuf {
    reply_buf(|| Ok(api::apple::init()))
}

/// Raw `deviceKeyId` (43 base64url characters) of a 91-byte P-256 SubjectPublicKeyInfo.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_device_key_id(spki: *const u8, spki_len: usize) -> DoodleArtBuf {
    reply_buf(|| Ok(api::device_key_id(input!(spki, spki_len))))
}

/// `frame(u64(handshake), signatureMessage, riskFlagsCsv)`; runs the core's own risk scan (blocking; the Apple scan,
/// risk/apple.rs).
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_handshake_begin(
    device_id: *const u8,
    device_id_len: usize,
    device_key_id: *const u8,
    device_key_id_len: usize,
    app_version: *const u8,
    app_version_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| {
        let device_id = input!(device_id, device_id_len);
        let device_key_id = input!(device_key_id, device_key_id_len);
        let app_version = input!(app_version, app_version_len);
        // No flags from Swift (theme-x spec §4.1, D-24): the core scans by itself, as on Android.
        Ok(api::handshake_begin(device_id, device_key_id, app_version, None))
    })
}

/// Raw JSON body of `POST /api/v1/session/start`; once per handshake.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_handshake_body(
    handshake: i64,
    device_sig: *const u8,
    device_sig_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| Ok(api::handshake_body(handshake, input!(device_sig, device_sig_len))))
}

/// `frame(u64(session), sid, sessionInfoJson)`; consumes the handshake whatever the outcome. `server_time` is the
/// `X-Server-Time` header in ms (0 when absent).
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_handshake_finish(
    handshake: i64,
    http_status: i32,
    server_time: i64,
    body: *const u8,
    body_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| Ok(api::handshake_finish(handshake, http_status, server_time, input!(body, body_len))))
}

/// Drops a handshake whose request got no response (status code).
#[no_mangle]
pub extern "C" fn doodleart_handshake_abort(handshake: i64) -> i32 {
    status(|| api::handshake_abort(handshake))
}

/// `frame(u64(seq), u64(ts), sid, appVersion, tag, sealedBody)`.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_session_seal(
    session: i64,
    method: *const u8,
    method_len: usize,
    path_with_query: *const u8,
    path_with_query_len: usize,
    body: *const u8,
    body_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| {
        let method = input!(method, method_len);
        let path_with_query = input!(path_with_query, path_with_query_len);
        let body = input!(body, body_len);
        Ok(api::session_seal(session, method, path_with_query, body))
    })
}

/// The answer to a sealed request: raw plaintext (gzip decoded), or UNSEALED_RESPONSE `frame(u64(httpStatus), code)`.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn doodleart_session_response(
    session: i64,
    seq: i64,
    http_status: i32,
    content_type: *const u8,
    content_type_len: usize,
    content_encoding: *const u8,
    content_encoding_len: usize,
    body: *const u8,
    body_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| {
        let content_type = input!(content_type, content_type_len);
        let content_encoding = input!(content_encoding, content_encoding_len);
        let body = input!(body, body_len);
        Ok(api::session_response(session, seq, http_status, content_type, content_encoding, body))
    })
}

/// Low level: raw plaintext of a body known to be sealed.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_session_open(
    session: i64,
    seq: i64,
    http_status: i32,
    content_encoding: *const u8,
    content_encoding_len: usize,
    sealed: *const u8,
    sealed_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| {
        let content_encoding = input!(content_encoding, content_encoding_len);
        Ok(api::session_open(session, seq, http_status, content_encoding, input!(sealed, sealed_len)))
    })
}

/// Forgets a seq whose response will never be read (status code).
#[no_mangle]
pub extern "C" fn doodleart_session_abandon(session: i64, seq: i64) -> i32 {
    status(|| api::session_abandon(session, seq))
}

/// Wipes the session keys (status code).
#[no_mangle]
pub extern "C" fn doodleart_session_close(session: i64) -> i32 {
    status(|| api::session_close(session))
}

/// `frame(requestId, requestHash, requestHashRaw)`: DAPI1, with the 32 raw bytes App Attest assertions take.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_integrity_hash(
    method: *const u8,
    method_len: usize,
    path_with_query: *const u8,
    path_with_query_len: usize,
    request_id: *const u8,
    request_id_len: usize,
    sid: *const u8,
    sid_len: usize,
    body: *const u8,
    body_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| {
        let method = input!(method, method_len);
        let path_with_query = input!(path_with_query, path_with_query_len);
        let request_id = input!(request_id, request_id_len);
        let sid = input!(sid, sid_len);
        let body = input!(body, body_len);
        Ok(api::apple::integrity_hash(method, path_with_query, request_id, sid, body))
    })
}

/// `frame(registerMessage, clientDataHash)` for `POST /api/v1/devices/register`: the bytes the device key signs and
/// their SHA-256, the App Attest `clientDataHash`.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_register_message(
    nonce: *const u8,
    nonce_len: usize,
    device_id: *const u8,
    device_id_len: usize,
    device_key_id: *const u8,
    device_key_id_len: usize,
    platform: *const u8,
    platform_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| {
        Ok(api::register_message(
            input!(nonce, nonce_len),
            input!(device_id, device_id_len),
            input!(device_key_id, device_key_id_len),
            input!(platform, platform_len),
        ))
    })
}

/// Raw `iosDeviceHash` (64 lowercase hex characters) of the 32-byte Keychain secret.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_ios_device_hash(secret: *const u8, secret_len: usize) -> DoodleArtBuf {
    reply_buf(|| Ok(api::apple::ios_device_hash(input!(secret, secret_len))))
}

/// Raw 32-byte DAAS1 `clientDataHash` of a handshake signature message.
///
/// # Safety
///
/// Each `(ptr, len)` pair is NULL or `len` readable bytes valid for the call (module documentation).
#[no_mangle]
pub unsafe extern "C" fn doodleart_session_assert_hash(
    signature_message: *const u8,
    signature_message_len: usize,
) -> DoodleArtBuf {
    reply_buf(|| Ok(api::apple::session_assert_hash(input!(signature_message, signature_message_len))))
}

/// Raw 32-byte DAAS1 `clientDataHash` of the handshake's own signature message (additive to spec §4.4).
#[no_mangle]
pub extern "C" fn doodleart_handshake_assert_hash(handshake: i64) -> DoodleArtBuf {
    reply_buf(|| Ok(api::apple::handshake_assert_hash(handshake)))
}

/// `frame(riskFlagsCsv, detailsCsv)` of the core's own risk scan (blocking; the Apple scan, risk/apple.rs); details
/// are empty in release builds.
#[no_mangle]
pub extern "C" fn doodleart_risk_scan() -> DoodleArtBuf {
    reply_buf(|| Ok(api::risk_scan(None)))
}

/// Releases a reply, exactly once per reply. `{NULL, 0}`, a wrong `len` and an address that holds no live reply are
/// ignored (no free of foreign memory). A second release of the same buffer is undefined: if the allocator already
/// reused its address for another reply of the same length, that reply is released (module documentation).
#[no_mangle]
pub extern "C" fn doodleart_buf_free(buf: DoodleArtBuf) {
    guarded(
        || (),
        || {
            if buf.ptr.is_null() {
                return;
            }
            let registered = {
                let mut live = live();
                let known = live.get(&(buf.ptr as usize)) == Some(&buf.len);
                if known {
                    live.remove(&(buf.ptr as usize));
                }
                known
            };
            if registered {
                // SAFETY: (ptr, len) was registered by DoodleArtBuf::from_reply, so it is the Box<[u8]> of exactly len
                // bytes that Box::into_raw produced and that has not been freed (a free unregisters it, here, under
                // the lock): this is the only reconstruction of that Box.
                drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
            }
        },
    )
}

/// Debug libraries only, never in a release build: moves the session clock forward by `ms` (0 to one week) as if the
/// device had slept that long (theme-x spec 2026-11-05 §7.1). Status code.
#[cfg(feature = "build-debug")]
#[no_mangle]
pub extern "C" fn doodleart_debug_clock_advance_ms(ms: i64) -> i32 {
    status(|| api::apple::debug_clock_advance(ms))
}

/// Test-only instrumentation of the entry guard: a forced panic per thread and a count of hook installs.
#[cfg(test)]
mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        static PANIC_NEXT: Cell<bool> = const { Cell::new(false) };
        static FORCED: Cell<bool> = const { Cell::new(false) };
        static HOOK_CHECKS: Cell<u32> = const { Cell::new(0) };
    }

    /// The next guarded entry on this thread panics inside its guard, after installing the hook.
    pub fn panic_next_entry() {
        PANIC_NEXT.with(|next| next.set(true));
    }

    pub fn panic_pending() -> bool {
        PANIC_NEXT.with(Cell::get)
    }

    pub fn on_entry() {
        if PANIC_NEXT.with(|next| next.replace(false)) {
            FORCED.with(|forced| forced.set(true));
            panic!("forced by the ffi tests");
        }
    }

    /// Whether the panic being reported is a forced one (and forget it).
    pub fn take_forced() -> bool {
        FORCED.try_with(|forced| forced.replace(false)).unwrap_or(false)
    }

    pub fn count_hook_check() {
        HOOK_CHECKS.with(|checks| checks.set(checks.get() + 1));
    }

    pub fn hook_checks() -> u32 {
        HOOK_CHECKS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests;
