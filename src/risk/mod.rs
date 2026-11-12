//! Runtime risk detection (theme-x plan §7.2). The client never crashes or exits on detection: [`scan`] only returns flags,
//! the handshake carries them under the device signature and the server decides the session `trust`.
//!
//! Output vocabulary is exactly what the server knows (theme-x wire format §3): heavy `frida`, `hook`, `debugger`,
//! `apk_resigned`; light `root`, `emulator`. The server-reserved `banned_device` / `restore_blocked` are never emitted.
//! Each check is documented in its module with why it does not fire on ordinary devices.
//!
//! Platforms: this module (the flag vocabulary, [`RiskReport`], [`parse_flag_list`]) and [`port`] are neutral. The
//! Android scan (`android`) and its scanners (`debugger`, `elf`, `emulator`, `frida`, `hook`, `maps`, `root`) read
//! /proc and Android paths: compiled everywhere but in an Apple library (`doodleart_apple_lib`; unit tests on macOS run
//! them against fixtures), whose [`scan`] is `apple`'s (end of this file), as in the unit tests on a Mac.

#[cfg(any(not(doodleart_apple_lib), test))]
mod android;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod debugger;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod elf;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod emulator;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod frida;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod hook;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod maps;
pub mod port;
#[cfg(any(not(doodleart_apple_lib), test))]
pub mod root;

use std::collections::BTreeSet;

use obfstr::obfstring as s;

#[cfg(not(any(doodleart_apple_lib, all(test, target_vendor = "apple"))))]
pub use android::scan;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    ApkResigned,
    Debugger,
    Emulator,
    Frida,
    Hook,
    Root,
}

impl Flag {
    pub const ALL: [Flag; 6] = [Flag::ApkResigned, Flag::Debugger, Flag::Emulator, Flag::Frida, Flag::Hook, Flag::Root];

    /// Wire name (theme-x wire format §3).
    pub fn name(self) -> String {
        match self {
            Flag::ApkResigned => s!("apk_resigned"),
            Flag::Debugger => s!("debugger"),
            Flag::Emulator => s!("emulator"),
            Flag::Frida => s!("frida"),
            Flag::Hook => s!("hook"),
            Flag::Root => s!("root"),
        }
    }

    /// Parses a wire name; `resigned` is the server's legacy alias of `apk_resigned`.
    pub fn parse(name: &str) -> Option<Flag> {
        if name == obfstr::obfstr!("resigned") {
            return Some(Flag::ApkResigned);
        }
        Flag::ALL.into_iter().find(|flag| flag.name() == name)
    }

    pub fn is_heavy(self) -> bool {
        matches!(self, Flag::Frida | Flag::Hook | Flag::Debugger | Flag::ApkResigned)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RiskReport {
    pub flags: BTreeSet<Flag>,
    /// Which checks fired (`frida.port`, `root.su`…). Only filled in debug and QA builds, for on-device verification;
    /// release builds do not hand an attacker a per-check oracle.
    pub details: Vec<String>,
}

impl RiskReport {
    fn note(&mut self, flag: Option<Flag>, detail: impl FnOnce() -> String) {
        if let Some(flag) = flag {
            self.flags.insert(flag);
        }
        if !cfg!(feature = "build-release") {
            self.details.push(detail());
        }
    }

    pub fn merge_flags(&mut self, flags: impl IntoIterator<Item = Flag>) {
        self.flags.extend(flags);
    }

    /// Sorted wire names.
    pub fn flag_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.flags.iter().map(|flag| flag.name()).collect();
        names.sort_unstable();
        names
    }

    /// `riskFlagsCsv` form: sorted names joined with ",".
    pub fn csv(&self) -> String {
        self.flag_names().join(",")
    }
}

/// Flags Kotlin reports from its own checks (comma-separated); unknown and reserved names are dropped.
pub fn parse_flag_list(csv: &str) -> Vec<Flag> {
    csv.split(',').map(str::trim).filter_map(Flag::parse).collect()
}

// Declared here, after the code every platform compiles, so that adding it moved no line of that code (obfstr derives
// its keys from file and line: the Android library stays byte-identical).
/// The Apple scan (theme-x spec 2026-11-05 §5.12), compiled for Apple targets only; host `cargo test` on macOS runs it against
/// a fake device root. [`scan`] is the library's scan: Apple's in an Apple library and in the unit tests on a Mac,
/// Android's everywhere else (a plain macOS build included: the Kotlin host harness runs the Android natives).
#[cfg(target_vendor = "apple")]
pub mod apple;

/// Apple libraries: the Apple scan ([`apple::scan`]), which `handshake_begin` and `doodleart_risk_scan` run (spec
/// 2026-11-05 D-24). Same contract as the Android scan: blocking, never panics; `apk_path_hint` is Android's and
/// ignored here.
#[cfg(any(doodleart_apple_lib, all(test, target_vendor = "apple")))]
pub fn scan(_apk_path_hint: Option<&str>) -> RiskReport {
    apple::scan()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_is_the_servers() {
        let names: Vec<String> = Flag::ALL.iter().map(|flag| flag.name()).collect();
        assert_eq!(names, ["apk_resigned", "debugger", "emulator", "frida", "hook", "root"]);
        let heavy: Vec<String> = Flag::ALL.iter().filter(|flag| flag.is_heavy()).map(|flag| flag.name()).collect();
        assert_eq!(heavy, ["apk_resigned", "debugger", "frida", "hook"]);
        for name in &names {
            assert!(crate::envelope::validate::risk_flag(name));
        }
    }

    #[test]
    fn kotlin_flags_are_filtered() {
        assert_eq!(
            parse_flag_list("debugger, banned_device,restore_blocked,unknown,resigned,,"),
            vec![Flag::Debugger, Flag::ApkResigned]
        );
        assert!(parse_flag_list("").is_empty());
    }

    #[test]
    fn report_csv_is_sorted() {
        let mut report = RiskReport::default();
        report.merge_flags([Flag::Root, Flag::Frida, Flag::ApkResigned]);
        assert_eq!(report.csv(), "apk_resigned,frida,root");
    }

    /// On the host nothing Android-specific exists; the Android scan must run end to end without panicking.
    #[test]
    fn host_scan_runs() {
        let report = android::scan(None);
        assert!(!report.flags.contains(&Flag::Frida));
        assert!(!report.flags.contains(&Flag::ApkResigned));
    }

    /// [`scan`], which the handshake and the risk scan natives run, is the Apple library's in the unit tests on a Mac
    /// (its filesystem probes off, a `root.unchecked` detail), never the Android scan (whose checks of /proc and of the
    /// APK leave `hook.text_unchecked` / `apk.unknown` details on a host).
    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_targets_run_the_apple_scan() {
        let report = scan(Some("/data/app/base.apk"));
        assert!(!report.flags.contains(&Flag::ApkResigned));
        if cfg!(feature = "build-release") {
            assert!(report.details.is_empty());
        } else {
            assert_eq!(report.details.first().map(String::as_str), Some("root.unchecked"), "{:?}", report.details);
            assert!(!report.details.iter().any(|detail| detail.starts_with("apk.") || detail == "hook.text_unchecked"));
            let android = android::scan(None);
            assert!(android.details.iter().any(|detail| detail == "apk.unknown"), "{:?}", android.details);
        }
    }
}
