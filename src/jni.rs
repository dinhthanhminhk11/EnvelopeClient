//! JNI glue: `JNI_OnLoad` registers the natives of `com.cem.doodleart.security.NativeCore` with `RegisterNatives`, so
//! the library exports no `Java_*` symbol (JNI_OnLoad is its only dynamic export).
//!
//! Every entry point runs inside `catch_unwind`: a panic becomes the `INTERNAL` status and never crosses the FFI
//! boundary (the crate builds with panic = "unwind" for that reason). No Java exception is thrown from native code
//! except an OutOfMemoryError raised by the VM itself when a result array cannot be allocated.

use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use jni_sys::{
    jbyte, jbyteArray, jclass, jint, jlong, jsize, JNIEnv, JNINativeMethod, JavaVM, JNI_ERR, JNI_OK, JNI_VERSION_1_6,
};
use obfstr::obfstring as s;

use crate::api;
use crate::error::Error;
use crate::risk::hook;

/// Largest array accepted from Kotlin (sealed bodies are far smaller).
const MAX_INPUT_BYTES: jsize = 64 * 1024 * 1024;

/// Kotlin byte array → bytes. `Ok(None)` for null, `Err` when the array cannot be read.
unsafe fn bytes_in(env: *mut JNIEnv, array: jbyteArray) -> Result<Option<Vec<u8>>, Error> {
    if array.is_null() {
        return Ok(None);
    }
    // SAFETY (whole function): env is the valid JNIEnv of the calling thread and array a live local reference.
    let interface = unsafe { &**env };
    let length = unsafe { (interface.GetArrayLength.ok_or(Error::Internal)?)(env, array) };
    if !(0..=MAX_INPUT_BYTES).contains(&length) {
        return Err(Error::InvalidArgument);
    }
    let mut out = vec![0u8; length as usize];
    unsafe {
        (interface.GetByteArrayRegion.ok_or(Error::Internal)?)(env, array, 0, length, out.as_mut_ptr().cast::<jbyte>())
    };
    if unsafe { (interface.ExceptionCheck.ok_or(Error::Internal)?)(env) } != 0 {
        unsafe { (interface.ExceptionClear.ok_or(Error::Internal)?)(env) };
        return Err(Error::InvalidArgument);
    }
    Ok(Some(out))
}

/// Bytes → new Kotlin byte array; null only if the VM could not allocate it (OutOfMemoryError pending).
unsafe fn bytes_out(env: *mut JNIEnv, data: &[u8]) -> jbyteArray {
    // SAFETY (whole function): env is the valid JNIEnv of the calling thread.
    let interface = unsafe { &**env };
    let (Some(new_array), Some(set_region)) = (interface.NewByteArray, interface.SetByteArrayRegion) else {
        return ptr::null_mut();
    };
    let Ok(length) = jsize::try_from(data.len()) else { return ptr::null_mut() };
    let array = unsafe { new_array(env, length) };
    if array.is_null() {
        return ptr::null_mut();
    }
    unsafe { set_region(env, array, 0, length, data.as_ptr().cast::<jbyte>()) };
    array
}

/// Runs `body` with the decoded inputs, catching panics; returns the reply array. `env` must be the JNIEnv the VM
/// passed to the current native call.
fn reply_array(env: *mut JNIEnv, body: impl FnOnce() -> Result<Vec<u8>, Error>) -> jbyteArray {
    let reply = match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => api::error_reply(&error),
        Err(_) => api::error_reply(&Error::Internal),
    };
    // SAFETY: env is valid for this native call.
    unsafe { bytes_out(env, &reply) }
}

fn guarded_status(body: impl FnOnce() -> i32) -> jint {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| jint::from(Error::Internal.status()))
}

macro_rules! input {
    ($env:expr, $array:expr) => {
        // SAFETY: called from a native method with the JNIEnv and arguments the VM passed in.
        unsafe { bytes_in($env, $array) }?
    };
}

extern "system" fn native_init(env: *mut JNIEnv, _class: jclass, apk_path: jbyteArray) -> jbyteArray {
    reply_array(env, || {
        let apk_path = input!(env, apk_path);
        Ok(api::init(apk_path.as_deref()))
    })
}

extern "system" fn device_key_id(env: *mut JNIEnv, _class: jclass, spki: jbyteArray) -> jbyteArray {
    reply_array(env, || {
        let spki = input!(env, spki);
        Ok(api::device_key_id(spki.as_deref()))
    })
}

extern "system" fn handshake_begin(
    env: *mut JNIEnv,
    _class: jclass,
    device_id: jbyteArray,
    device_key_id: jbyteArray,
    app_version: jbyteArray,
    extra_flags: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let device_id = input!(env, device_id);
        let device_key_id = input!(env, device_key_id);
        let app_version = input!(env, app_version);
        let extra_flags = input!(env, extra_flags);
        Ok(api::handshake_begin(
            device_id.as_deref(),
            device_key_id.as_deref(),
            app_version.as_deref(),
            extra_flags.as_deref(),
        ))
    })
}

extern "system" fn handshake_body(
    env: *mut JNIEnv,
    _class: jclass,
    handshake: jlong,
    device_sig: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let device_sig = input!(env, device_sig);
        Ok(api::handshake_body(handshake, device_sig.as_deref()))
    })
}

extern "system" fn handshake_finish(
    env: *mut JNIEnv,
    _class: jclass,
    handshake: jlong,
    http_status: jint,
    server_time: jlong,
    body: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let body = input!(env, body);
        Ok(api::handshake_finish(handshake, http_status, server_time, body.as_deref()))
    })
}

extern "system" fn handshake_abort(_env: *mut JNIEnv, _class: jclass, handshake: jlong) -> jint {
    guarded_status(|| api::handshake_abort(handshake))
}

extern "system" fn session_seal(
    env: *mut JNIEnv,
    _class: jclass,
    session: jlong,
    method: jbyteArray,
    path_with_query: jbyteArray,
    body: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let method = input!(env, method);
        let path = input!(env, path_with_query);
        let body = input!(env, body);
        Ok(api::session_seal(session, method.as_deref(), path.as_deref(), body.as_deref()))
    })
}

extern "system" fn session_open(
    env: *mut JNIEnv,
    _class: jclass,
    session: jlong,
    seq: jlong,
    http_status: jint,
    content_encoding: jbyteArray,
    sealed: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let content_encoding = input!(env, content_encoding);
        let sealed = input!(env, sealed);
        Ok(api::session_open(session, seq, http_status, content_encoding.as_deref(), sealed.as_deref()))
    })
}

extern "system" fn session_response(
    env: *mut JNIEnv,
    _class: jclass,
    session: jlong,
    seq: jlong,
    http_status: jint,
    content_type: jbyteArray,
    content_encoding: jbyteArray,
    body: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let content_type = input!(env, content_type);
        let content_encoding = input!(env, content_encoding);
        let body = input!(env, body);
        Ok(api::session_response(
            session,
            seq,
            http_status,
            content_type.as_deref(),
            content_encoding.as_deref(),
            body.as_deref(),
        ))
    })
}

extern "system" fn register_message(
    env: *mut JNIEnv,
    _class: jclass,
    nonce: jbyteArray,
    device_id: jbyteArray,
    device_key_id: jbyteArray,
    platform: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let nonce = input!(env, nonce);
        let device_id = input!(env, device_id);
        let device_key_id = input!(env, device_key_id);
        let platform = input!(env, platform);
        Ok(api::register_message(nonce.as_deref(), device_id.as_deref(), device_key_id.as_deref(), platform.as_deref()))
    })
}

extern "system" fn session_abandon(_env: *mut JNIEnv, _class: jclass, session: jlong, seq: jlong) -> jint {
    guarded_status(|| api::session_abandon(session, seq))
}

extern "system" fn session_close(_env: *mut JNIEnv, _class: jclass, session: jlong) -> jint {
    guarded_status(|| api::session_close(session))
}

extern "system" fn integrity_hash(
    env: *mut JNIEnv,
    _class: jclass,
    method: jbyteArray,
    path_with_query: jbyteArray,
    request_id: jbyteArray,
    sid: jbyteArray,
    body: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let method = input!(env, method);
        let path = input!(env, path_with_query);
        let request_id = input!(env, request_id);
        let sid = input!(env, sid);
        let body = input!(env, body);
        Ok(api::integrity_hash(
            method.as_deref(),
            path.as_deref(),
            request_id.as_deref(),
            sid.as_deref(),
            body.as_deref(),
        ))
    })
}

extern "system" fn device_signals(
    env: *mut JNIEnv,
    _class: jclass,
    android_id: jbyteArray,
    drm_id: jbyteArray,
    drm_status: jbyteArray,
    sensors: jbyteArray,
) -> jbyteArray {
    reply_array(env, || {
        let android_id = input!(env, android_id);
        let drm_id = input!(env, drm_id);
        let drm_status = input!(env, drm_status);
        let sensors = input!(env, sensors);
        Ok(api::device_signals(android_id.as_deref(), drm_id.as_deref(), drm_status.as_deref(), sensors.as_deref()))
    })
}

extern "system" fn risk_scan(env: *mut JNIEnv, _class: jclass, extra_flags: jbyteArray) -> jbyteArray {
    reply_array(env, || {
        let extra_flags = input!(env, extra_flags);
        Ok(api::risk_scan(extra_flags.as_deref()))
    })
}

/// JNI name of the Kotlin class whose natives are registered (decrypted at load time).
fn class_name() -> String {
    s!("com/cem/doodleart/security/NativeCore")
}

/// (name, JNI signature, function) of every native of NativeCore. Names and signatures are decrypted at load time.
fn native_table() -> Vec<(String, String, *mut c_void)> {
    vec![
        (s!("nativeInit"), s!("([B)[B"), native_init as *mut c_void),
        (s!("deviceKeyId"), s!("([B)[B"), device_key_id as *mut c_void),
        (s!("handshakeBegin"), s!("([B[B[B[B)[B"), handshake_begin as *mut c_void),
        (s!("handshakeBody"), s!("(J[B)[B"), handshake_body as *mut c_void),
        (s!("handshakeFinish"), s!("(JIJ[B)[B"), handshake_finish as *mut c_void),
        (s!("handshakeAbort"), s!("(J)I"), handshake_abort as *mut c_void),
        (s!("sessionSeal"), s!("(J[B[B[B)[B"), session_seal as *mut c_void),
        (s!("sessionOpen"), s!("(JJI[B[B)[B"), session_open as *mut c_void),
        (s!("sessionResponse"), s!("(JJI[B[B[B)[B"), session_response as *mut c_void),
        (s!("sessionAbandon"), s!("(JJ)I"), session_abandon as *mut c_void),
        (s!("sessionClose"), s!("(J)I"), session_close as *mut c_void),
        (s!("integrityHash"), s!("([B[B[B[B[B)[B"), integrity_hash as *mut c_void),
        (s!("deviceSignals"), s!("([B[B[B[B)[B"), device_signals as *mut c_void),
        (s!("riskScan"), s!("([B)[B"), risk_scan as *mut c_void),
        (s!("registerMessage"), s!("([B[B[B[B)[B"), register_message as *mut c_void),
    ]
}

unsafe fn register(vm: *mut JavaVM) -> Option<()> {
    // SAFETY (whole function): vm is the JavaVM passed to JNI_OnLoad; the env it returns belongs to this thread.
    let mut env: *mut c_void = ptr::null_mut();
    let get_env = unsafe { (**vm).GetEnv }?;
    if unsafe { get_env(vm, &mut env, JNI_VERSION_1_6) } != JNI_OK || env.is_null() {
        return None;
    }
    let env = env.cast::<JNIEnv>();
    let interface = unsafe { &**env };
    let (find_class, register_natives, exception_check, exception_clear, delete_local) = (
        interface.FindClass?,
        interface.RegisterNatives?,
        interface.ExceptionCheck?,
        interface.ExceptionClear?,
        interface.DeleteLocalRef?,
    );

    let class_name = CString::new(class_name()).ok()?;
    let class = unsafe { find_class(env, class_name.as_ptr()) };
    if class.is_null() || unsafe { exception_check(env) } != 0 {
        unsafe { exception_clear(env) };
        return None;
    }

    let table = native_table();
    let names: Vec<(CString, CString)> = table
        .iter()
        .filter_map(|(name, signature, _)| {
            Some((CString::new(name.as_str()).ok()?, CString::new(signature.as_str()).ok()?))
        })
        .collect();
    if names.len() != table.len() {
        return None;
    }
    let methods: Vec<JNINativeMethod> = names
        .iter()
        .zip(&table)
        .map(|((name, signature), (_, _, function))| JNINativeMethod {
            name: name.as_ptr() as *mut c_char,
            signature: signature.as_ptr() as *mut c_char,
            fnPtr: *function,
        })
        .collect();
    let status = unsafe { register_natives(env, class, methods.as_ptr(), methods.len() as jint) };
    let failed = status != JNI_OK || unsafe { exception_check(env) } != 0;
    if failed {
        unsafe { exception_clear(env) };
    }
    unsafe { delete_local(env, class) };
    if failed {
        return None;
    }

    // Baseline of our entry points for the `hook.prologue` check.
    let functions: Vec<usize> = table.iter().map(|(_, _, function)| *function as usize).collect();
    hook::record_prologues(&functions);
    Some(())
}

/// Called by `System.loadLibrary("doodleart_core")`. Returns JNI_ERR (→ UnsatisfiedLinkError in Kotlin, which the
/// :security module catches) only when NativeCore cannot be registered, never because of a risk detection.
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: *mut JavaVM, _reserved: *mut c_void) -> jint {
    // Panics are turned into status codes; nothing is printed (stderr is not logcat, and messages leak internals).
    let registered = catch_unwind(|| {
        std::panic::set_hook(Box::new(|_| {}));
        // SAFETY: vm comes from the VM loading this library.
        unsafe { register(vm) }
    });
    match registered {
        Ok(Some(())) => JNI_VERSION_1_6,
        _ => JNI_ERR,
    }
}

#[cfg(test)]
mod tests {
    //! Android guard: the RegisterNatives contract of the live app (Android 1.4.5). `RegisterNatives` fails, and
    //! `System.loadLibrary` throws, as soon as one entry has no matching `external fun` in NativeCore.kt, so a name,
    //! signature or class change here is a broken release, never a refactor.

    use super::*;

    const CLASS: &str = "com/cem/doodleart/security/NativeCore";

    /// Names and JNI signatures, in table order, as recorded from the 1.4.5 sources (P4 baseline jni-table.txt).
    const GOLDEN: [(&str, &str); 15] = [
        ("nativeInit", "([B)[B"),
        ("deviceKeyId", "([B)[B"),
        ("handshakeBegin", "([B[B[B[B)[B"),
        ("handshakeBody", "(J[B)[B"),
        ("handshakeFinish", "(JIJ[B)[B"),
        ("handshakeAbort", "(J)I"),
        ("sessionSeal", "(J[B[B[B)[B"),
        ("sessionOpen", "(JJI[B[B)[B"),
        ("sessionResponse", "(JJI[B[B[B)[B"),
        ("sessionAbandon", "(JJ)I"),
        ("sessionClose", "(J)I"),
        ("integrityHash", "([B[B[B[B[B)[B"),
        ("deviceSignals", "([B[B[B[B)[B"),
        ("riskScan", "([B)[B"),
        ("registerMessage", "([B[B[B[B)[B"),
    ];

    macro_rules! descriptor {
        (B) => {
            "[B"
        };
        (J) => {
            "J"
        };
        (I) => {
            "I"
        };
    }

    macro_rules! jni_type {
        (B) => {
            jbyteArray
        };
        (J) => {
            jlong
        };
        (I) => {
            jint
        };
    }

    /// `(name, descriptor, address)` of a Rust native. The cast only compiles when the function's Rust signature is
    /// exactly `extern "system" fn(*mut JNIEnv, jclass, <args>) -> <ret>`, so the descriptor computed from the same
    /// tokens is the one the function really implements.
    macro_rules! native {
        ($name:literal, $function:ident, ($($arg:ident),*) -> $ret:ident) => {
            (
                $name,
                concat!("(", $(descriptor!($arg),)* ")", descriptor!($ret)),
                $function as extern "system" fn(*mut JNIEnv, jclass $(, jni_type!($arg))*) -> jni_type!($ret) as usize,
            )
        };
    }

    fn typed_natives() -> [(&'static str, &'static str, usize); 15] {
        [
            native!("nativeInit", native_init, (B) -> B),
            native!("deviceKeyId", device_key_id, (B) -> B),
            native!("handshakeBegin", handshake_begin, (B, B, B, B) -> B),
            native!("handshakeBody", handshake_body, (J, B) -> B),
            native!("handshakeFinish", handshake_finish, (J, I, J, B) -> B),
            native!("handshakeAbort", handshake_abort, (J) -> I),
            native!("sessionSeal", session_seal, (J, B, B, B) -> B),
            native!("sessionOpen", session_open, (J, J, I, B, B) -> B),
            native!("sessionResponse", session_response, (J, J, I, B, B, B) -> B),
            native!("sessionAbandon", session_abandon, (J, J) -> I),
            native!("sessionClose", session_close, (J) -> I),
            native!("integrityHash", integrity_hash, (B, B, B, B, B) -> B),
            native!("deviceSignals", device_signals, (B, B, B, B) -> B),
            native!("riskScan", risk_scan, (B) -> B),
            native!("registerMessage", register_message, (B, B, B, B) -> B),
        ]
    }

    #[test]
    fn class_and_table_are_the_live_contract() {
        assert_eq!(class_name(), CLASS);
        let table = native_table();
        let registered: Vec<(&str, &str)> =
            table.iter().map(|(name, signature, _)| (name.as_str(), signature.as_str())).collect();
        assert_eq!(registered, GOLDEN);
    }

    /// Each entry points at the Rust function whose parameter types match its signature (catches two same-signature
    /// entries swapping functions, e.g. nativeInit / deviceKeyId / riskScan or handshakeAbort / sessionClose).
    #[test]
    fn every_entry_points_at_its_typed_function() {
        let typed = typed_natives();
        let descriptors: Vec<(&str, &str)> = typed.iter().map(|(name, descriptor, _)| (*name, *descriptor)).collect();
        assert_eq!(descriptors, GOLDEN);
        let table = native_table();
        for ((name, _, function), (typed_name, _, typed_function)) in table.iter().zip(&typed) {
            assert_eq!(name, typed_name);
            assert_eq!(*function as usize, *typed_function, "{name}");
        }
        let mut addresses: Vec<usize> = typed.iter().map(|(_, _, function)| *function).collect();
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), GOLDEN.len());
    }

    /// The Kotlin side of the same contract, when the Android module is next to the crate (it is in this repository).
    #[test]
    fn kotlin_native_core_declares_the_same_natives() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../security/src/main/java/com/cem/doodleart/security/NativeCore.kt");
        let kotlin = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: no {path}");
                return;
            }
            Err(error) => panic!("{path}: {error}"),
        };
        let package = kotlin.lines().find_map(|line| line.strip_prefix("package ")).expect("package line").trim();
        assert!(kotlin.contains("object NativeCore"), "{path}");
        assert_eq!(format!("{}/NativeCore", package.replace('.', "/")), CLASS);
        let mut declared = kotlin_externals(&kotlin);
        let mut golden: Vec<(String, String)> =
            GOLDEN.iter().map(|(name, signature)| ((*name).to_owned(), (*signature).to_owned())).collect();
        declared.sort();
        golden.sort();
        assert_eq!(declared, golden);
    }

    /// `(name, JNI descriptor)` of every `external fun name(p: T, …): R` (ByteArray[?] → [B, Long → J, Int → I).
    fn kotlin_externals(source: &str) -> Vec<(String, String)> {
        fn descriptor(kotlin_type: &str) -> &'static str {
            match kotlin_type.trim() {
                "ByteArray" | "ByteArray?" => "[B",
                "Long" => "J",
                "Int" => "I",
                other => panic!("unexpected Kotlin type in NativeCore: {other}"),
            }
        }
        let mut out = Vec::new();
        for declaration in source.split("external fun ").skip(1) {
            let (name, rest) = declaration.split_once('(').expect("parameter list");
            let (parameters, rest) = rest.split_once(')').expect("end of parameter list");
            let returned = rest.trim_start().strip_prefix(':').expect("return type").trim_start();
            let returned: String = returned.chars().take_while(|c| c.is_alphanumeric() || *c == '?').collect();
            let arguments: String = parameters
                .split(',')
                .map(str::trim)
                .filter(|parameter| !parameter.is_empty())
                .map(|parameter| descriptor(parameter.split_once(':').expect("typed parameter").1))
                .collect();
            out.push((name.trim().to_owned(), format!("({arguments}){}", descriptor(&returned))));
        }
        out
    }
}
