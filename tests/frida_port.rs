//! `frida.port` end to end: something listening on 127.0.0.1:27042 raises the heavy flag `frida`, through
//! `risk::port::frida_port_open` and through the scan the handshake runs, and nothing does once it stops listening.
//! `risk::scan` is the scan of the library this test links: the Android scan in a plain build (Linux, a plain macOS
//! build), the Apple scan when the crate is built as an Apple library on a Mac (`DOODLEART_APPLE_LIB=1 cargo test --test
//! frida_port`). core:check runs both; tests/c-abi/risk_probe.c also checks it on the shipped macOS slice.
//!
//! Both scans raise `frida` / `frida.port`, so the test first proves which one it links, from the value of
//! `DOODLEART_APPLE_LIB` this file was compiled with: "1" must give the Apple scan of the macOS library (its first detail
//! `root.unchecked`: it skips the filesystem probes), anything else the Android scan (its APK and `.text` checks find
//! no APK on a host: `apk.*` / `hook.text_unchecked` details). If build.rs ignored or renamed the variable, the
//! DOODLEART_APPLE_LIB=1 run would link the Android scan and fail here instead of testing it twice. Release builds keep no
//! details, so there only the flags are checked.
//!
//! An integration test, so a process of its own: cargo runs the test binaries one after the other, so no unit test
//! runs a scan while this one holds the port, and no Node interop peer is forked while a listener is open here (a
//! child forked between socket() and FD_CLOEXEC on macOS would keep the port open after the drop).

use std::net::{Ipv4Addr, TcpListener};

use doodleart_core::risk::{self, port, Flag};

/// The linked scan is the one `DOODLEART_APPLE_LIB` asked for (module documentation).
fn assert_linked_scan() {
    let apple_lib = option_env!("DOODLEART_APPLE_LIB") == Some("1");
    let report = risk::scan(None);
    assert!(!report.flags.contains(&Flag::ApkResigned), "{report:?}");
    if cfg!(feature = "build-release") {
        assert!(report.details.is_empty(), "{report:?}");
        return;
    }
    let apple_marker = report.details.first().map(String::as_str) == Some("root.unchecked");
    let android_marker =
        report.details.iter().any(|detail| detail.starts_with("apk.") || detail == "hook.text_unchecked");
    if apple_lib {
        assert!(apple_marker && !android_marker, "DOODLEART_APPLE_LIB=1 must link the Apple scan: {report:?}");
    } else {
        assert!(android_marker && !apple_marker, "a plain build must link the Android scan: {report:?}");
    }
}

#[test]
fn frida_server_port_raises_the_frida_flag_only_while_listening() {
    assert_linked_scan();
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 27042)) {
        Ok(listener) => listener,
        Err(error) => {
            // A real frida-server (or anything else) owns the port on this machine: nothing to prove here.
            eprintln!("skipped: 127.0.0.1:27042 is not free ({error})");
            return;
        }
    };
    assert!(port::frida_port_open());
    let report = risk::scan(None);
    assert!(report.flags.contains(&Flag::Frida), "{report:?}");
    if !cfg!(feature = "build-release") {
        assert!(report.details.iter().any(|detail| detail == "frida.port"), "{report:?}");
    }

    drop(listener);
    assert!(!port::frida_port_open());
    let report = risk::scan(None);
    assert!(!report.flags.contains(&Flag::Frida), "{report:?}");
    assert!(!report.details.iter().any(|detail| detail == "frida.port"), "{report:?}");
}
