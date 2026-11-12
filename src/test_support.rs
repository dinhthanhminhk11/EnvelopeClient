//! Shared helpers for unit tests.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;

use serde_json::Value;

/// The vector files of the server (server/src/core/envelope/testdata), read in place at test time so the Rust tests
/// always follow the Go generator (`go test ./envelope/ -update`): never copied into this crate.
fn server_vectors(name: &str) -> Value {
    let path = format!("{}/../server/src/core/envelope/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("server vectors are JSON")
}

/// envelope-v1.json: frame, handshake, session keys, request and response AEAD.
pub fn envelope_vectors() -> Value {
    server_vectors("envelope-v1.json")
}

/// app-attest-v1.json: registration proof, DAAS1, DAPI1, iosDeviceHash, stub strings.
pub fn attest_vectors() -> Value {
    server_vectors("app-attest-v1.json")
}

pub fn fixture_text(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// A property reader over `name=value` lines.
pub fn props_from(text: &str) -> impl Fn(&str) -> String {
    let map: HashMap<String, String> = text
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    move |name: &str| map.get(name).cloned().unwrap_or_default()
}

/// The Go interop peer: `TestInteropPeer` of server/src/app/routers/interop_peer_test.go, i.e. the real handshake and
/// sealed routes of the app service over in-memory stores, compiled once per test run (`go test -c`) and started as
/// its own process. One process serves the whole test binary; each test makes its own device keys on it.
pub struct GoPeer {
    child: std::process::Child,
    _stdin: std::process::ChildStdin,
    pub port: u16,
    pub kid: String,
    pub signing_public: [u8; 32],
}

impl GoPeer {
    fn spawn() -> Self {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let app = concat!(env!("CARGO_MANIFEST_DIR"), "/../server/src/app");
        let binary = std::path::Path::new(env!("OUT_DIR")).join("doodleart-interop-peer");
        let built = Command::new("go")
            .args(["test", "-c", "-o"])
            .arg(&binary)
            .arg("./routers")
            .current_dir(app)
            .status()
            .expect("go must be installed to run the interop tests (server/src/app)");
        assert!(built.success(), "go test -c ./routers failed in {app}");
        let mut child = Command::new(&binary)
            .args(["-test.run", "^TestInteropPeer$"])
            .env("DOODLEART_INTEROP_PEER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the interop peer");
        let stdin = child.stdin.take().expect("stdin");
        let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let hello = loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).expect("read the peer") > 0, "the interop peer exited");
            if let Some(json) = line.strip_prefix("DOODLEART_PEER ") {
                break serde_json::from_str::<Value>(json).expect("peer hello is JSON");
            }
        };
        let signing_public = crate::codec::hex_decode(hello["signing_public_hex"].as_str().unwrap()).unwrap();
        Self {
            child,
            _stdin: stdin,
            port: u16::try_from(hello["port"].as_u64().unwrap()).unwrap(),
            kid: hello["kid"].as_str().unwrap().to_owned(),
            signing_public: signing_public.try_into().unwrap(),
        }
    }

    /// The peer of this test binary, started on first use.
    pub fn shared() -> &'static GoPeer {
        static PEER: std::sync::LazyLock<GoPeer> = std::sync::LazyLock::new(GoPeer::spawn);
        &PEER
    }
}

impl Drop for GoPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Recognizable stand-in for key material in tests that check where secrets end up.
pub const SECRET_SENTINEL: [u8; 32] = *b"doodleart-core-test-secret-sent!";

thread_local! {
    // const-initialized, no destructor: safe to touch from inside the allocator.
    static SCANNING: Cell<bool> = const { Cell::new(false) };
    static SENTINEL_FREED: Cell<bool> = const { Cell::new(false) };
}

/// The test binary's allocator: the system one, plus, while [`frees_leak_sentinel`] runs on a thread, a search of
/// every block that thread frees for [`SECRET_SENTINEL`]. Proves secrets are wiped before their memory is released.
struct ScanningAllocator;

// SAFETY: every call is forwarded to System unchanged; the scan only reads the block before it is released.
unsafe impl GlobalAlloc for ScanningAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if SCANNING.try_with(Cell::get).unwrap_or(false) {
            // SAFETY: ptr is a live block of layout.size() bytes until System.dealloc below.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(SECRET_SENTINEL.len()).any(|window| window == SECRET_SENTINEL) {
                let _ = SENTINEL_FREED.try_with(|found| found.set(true));
            }
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ScanningAllocator = ScanningAllocator;

/// Runs `body` and reports whether any heap block it freed (on this thread) still held [`SECRET_SENTINEL`].
pub fn frees_leak_sentinel(body: impl FnOnce()) -> bool {
    SENTINEL_FREED.with(|found| found.set(false));
    SCANNING.with(|scanning| scanning.set(true));
    body();
    SCANNING.with(|scanning| scanning.set(false));
    SENTINEL_FREED.with(Cell::get)
}
