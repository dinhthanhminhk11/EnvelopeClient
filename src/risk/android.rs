//! The Android scan: every check of the Android scanners, in this fixed order (see each module for what it detects
//! and why it does not fire on ordinary devices). Compiled for non-Apple targets and for unit tests only (see
//! [`super`]); the platform-neutral vocabulary and report live in [`super`] as well.

use std::sync::Mutex;

use obfstr::obfstring as s;

use super::{debugger, emulator, frida, hook, maps, port, root, Flag, RiskReport};
use crate::apk_identity::{self, ApkVerdict};
use crate::sys;

/// A verdict about the installed APK never changes during the process lifetime; Unknown is retried.
static APK_VERDICT: Mutex<Option<ApkVerdict>> = Mutex::new(None);

fn apk_verdict(own_apk: Option<&str>) -> ApkVerdict {
    let mut cached = APK_VERDICT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(verdict) = *cached {
        return verdict;
    }
    let verdict = own_apk.map_or(ApkVerdict::Unknown, apk_identity::check_file);
    if verdict != ApkVerdict::Unknown {
        *cached = Some(verdict);
    }
    verdict
}

/// Runs every check. Blocking (file reads, a 150 ms loopback connect, a bounded memory scan): call it off the main
/// thread. Never panics on hostile input; a check that cannot run contributes nothing.
///
/// `apk_path_hint` is Kotlin's `applicationInfo.sourceDir`. The APK checked is always the one maps shows holding our
/// code; the hint is only compared with it (a `apk.path_mismatch` detail). It never selects the file and a mismatch
/// never suppresses the verdict: a repackaged app controls Kotlin and could otherwise switch the check off.
pub fn scan(apk_path_hint: Option<&str>) -> RiskReport {
    let mut report = RiskReport::default();
    let maps_text = sys::read_text(&s!("/proc/self/maps")).unwrap_or_default();
    let entries = maps::parse(&maps_text);
    let own_map_path = hook::own_map_path(&entries);

    // Frida
    if frida::maps_trace(&entries) {
        report.note(Some(Flag::Frida), || s!("frida.maps"));
    }
    if frida::threads_trace(&frida::thread_names()) {
        report.note(Some(Flag::Frida), || s!("frida.threads"));
    }
    if frida::fds_trace(&frida::fd_targets()) {
        report.note(Some(Flag::Frida), || s!("frida.fds"));
    }
    if port::frida_port_open() {
        report.note(Some(Flag::Frida), || s!("frida.port"));
    }
    if frida::memory_trace(&frida::memory_scan_candidates(&entries, own_map_path)) {
        report.note(Some(Flag::Frida), || s!("frida.memory"));
    }

    // Hooks
    match hook::own_code_changed(&entries) {
        Some(true) => report.note(Some(Flag::Hook), || s!("hook.text")),
        Some(false) => {}
        None => report.note(None, || s!("hook.text_unchecked")),
    }
    if hook::prologues_changed() == Some(true) {
        report.note(Some(Flag::Hook), || s!("hook.prologue"));
    }
    if hook::rwx_file_mapping(&entries, own_map_path) {
        report.note(Some(Flag::Hook), || s!("hook.rwx"));
    }
    let classpath = std::env::var(s!("CLASSPATH")).unwrap_or_default();
    if hook::xposed_trace(&entries, &classpath) {
        report.note(Some(Flag::Hook), || s!("hook.xposed"));
    }

    // Debugger
    if debugger::traced() {
        report.note(Some(Flag::Debugger), || s!("debugger.tracer"));
    }

    // Root
    let exists = |path: &str| sys::exists(path);
    let props = |name: &str| sys::property(name);
    let mut root_strong = false;
    if root::su_present(&exists) {
        root_strong = true;
        report.note(None, || s!("root.su"));
    }
    if root::root_manager_present(&exists) {
        root_strong = true;
        report.note(None, || s!("root.magisk"));
    }
    if root::maps_trace(&entries) {
        root_strong = true;
        report.note(None, || s!("root.maps"));
    }
    if sys::read_text(&s!("/proc/self/mounts")).is_some_and(|mounts| root::mounts_trace(&mounts)) {
        root_strong = true;
        report.note(None, || s!("root.mounts"));
    }
    let prop_signals = root::property_signals(&props);
    if prop_signals.insecure {
        root_strong = true;
        report.note(None, || s!("root.secure"));
    }
    if prop_signals.weak_signals > 0 {
        let weak = prop_signals.weak_signals;
        report.note(None, || format!("{}{weak}", s!("root.weak_props=")));
    }
    if root_strong || prop_signals.weak_signals >= 2 {
        report.note(Some(Flag::Root), || s!("root"));
    }

    // Emulator
    if emulator::property_trace(&props) {
        report.note(Some(Flag::Emulator), || s!("emulator.props"));
    }
    if emulator::file_trace(&exists) {
        report.note(Some(Flag::Emulator), || s!("emulator.files"));
    }

    // Re-signed APK
    let own_apk = own_map_path.and_then(apk_identity::own_base_apk);
    if let (Some(own), Some(hint)) = (own_apk.as_deref(), apk_path_hint) {
        if own != hint {
            report.note(None, || s!("apk.path_mismatch"));
        }
    }
    match apk_verdict(own_apk.as_deref()) {
        ApkVerdict::Resigned => report.note(Some(Flag::ApkResigned), || s!("apk.resigned")),
        ApkVerdict::Unknown => report.note(None, || s!("apk.unknown")),
        ApkVerdict::Allowed => {}
    }

    report
}
