//! A second Rust static library for tools/c-abi-smoke.sh (step 5, tests/c-abi/two_rust.c): include/doodleart_core.h
//! ("Linking") promises that an app may link another Rust static library next to DoodleArtCore and that each keeps its
//! own runtime and panic hook. This one is an ordinary rustc staticlib (its Rust std and runtime symbols global, as a
//! third-party Rust library ships them): it installs a panic hook of its own that only counts, and catches its own
//! panics. Built by the smoke test with `rustc --edition 2021 --crate-type staticlib -C panic=unwind`; not part of the
//! cargo crate.

use std::panic;
use std::sync::atomic::{AtomicU32, Ordering};

static HOOK_CALLS: AtomicU32 = AtomicU32::new(0);

/// Installs this library's panic hook: it prints nothing and counts.
#[no_mangle]
pub extern "C" fn other_rust_install_hook() {
    panic::set_hook(Box::new(|_| {
        HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    }));
}

/// How many panics this library's hook has seen.
#[no_mangle]
pub extern "C" fn other_rust_hook_calls() -> u32 {
    HOOK_CALLS.load(Ordering::SeqCst)
}

/// `x + 1`, or -1 for 42: a panic raised and caught inside this library.
#[no_mangle]
pub extern "C" fn other_rust_call(x: i32) -> i32 {
    panic::catch_unwind(|| {
        if x == 42 {
            panic!("other_rust: forced panic");
        }
        x + 1
    })
    .unwrap_or(-1)
}
