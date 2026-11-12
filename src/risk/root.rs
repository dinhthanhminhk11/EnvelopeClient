//! Root detection (light flag `root`: the session is capped at `limited`).
//!
//! Strong signals, one is enough:
//! - `root.su`: an `su` binary at a well-known path (faccessat via raw syscall; only "accessible" counts, EACCES and
//!   ENOENT both read as absent so SELinux denials never look like root).
//! - `root.magisk`: Magisk / KernelSU / APatch files that apps can see (`/sbin/.magisk`, `/debug_ramdisk/.magisk`…).
//! - `root.maps`: Magisk / Zygisk / `/data/adb/` files mapped into our process.
//! - `root.mounts`: mounts whose source or target names Magisk, Zygisk, `/data/adb` or KernelSU (`KSU`).
//! - `root.secure`: `ro.secure=0`.
//!
//! Weak signals, two are needed: `ro.debuggable=1`, `ro.build.type` userdebug/eng, `ro.build.tags` with test-keys.
//! Some low-cost OEM firmware ships test-keys on retail devices; alone it must not cost users their trust level.

use obfstr::obfstring as s;

use super::maps::MapEntry;

fn su_paths() -> Vec<String> {
    vec![
        s!("/system/bin/su"),
        s!("/system/xbin/su"),
        s!("/sbin/su"),
        s!("/su/bin/su"),
        s!("/system/sbin/su"),
        s!("/vendor/bin/su"),
        s!("/system/bin/.ext/su"),
        s!("/system/usr/we-need-root/su"),
        s!("/data/local/su"),
        s!("/data/local/bin/su"),
        s!("/data/local/xbin/su"),
        s!("/cache/su"),
        s!("/dev/su"),
        s!("/system/xbin/daemonsu"),
    ]
}

fn root_manager_paths() -> Vec<String> {
    vec![
        s!("/sbin/.magisk"),
        s!("/sbin/.core"),
        s!("/debug_ramdisk/.magisk"),
        s!("/system/bin/magisk"),
        s!("/data/adb/magisk"),
        s!("/data/adb/ksu"),
        s!("/data/adb/ksud"),
        s!("/data/adb/ap"),
        s!("/data/adb/modules"),
        s!("/cache/.disable_magisk"),
        s!("/dev/.magisk.unblock"),
    ]
}

/// `root.su` / `root.magisk`, with an injectable existence test.
pub fn su_present(exists: &dyn Fn(&str) -> bool) -> bool {
    su_paths().iter().any(|path| exists(path))
}

pub fn root_manager_present(exists: &dyn Fn(&str) -> bool) -> bool {
    root_manager_paths().iter().any(|path| exists(path))
}

/// `root.maps`
pub fn maps_trace(entries: &[MapEntry<'_>]) -> bool {
    let tokens = [s!("magisk"), s!("zygisk"), s!("/data/adb/")];
    entries.iter().any(|entry| {
        let target = entry.match_target();
        tokens.iter().any(|token| target.contains(token.as_str()))
    })
}

/// `root.mounts`: /proc/self/mounts lines are `source target fstype options 0 0`.
pub fn mounts_trace(mounts: &str) -> bool {
    let tokens = [s!("magisk"), s!("zygisk"), s!("/data/adb"), s!("core/mirror")];
    let ksu = s!("KSU");
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (Some(source), Some(target)) = (fields.next(), fields.next()) else { return false };
        source == ksu || tokens.iter().any(|token| source.contains(token.as_str()) || target.contains(token.as_str()))
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PropVerdict {
    pub insecure: bool,
    pub weak_signals: u8,
}

/// `root.secure` and the weak property signals.
pub fn property_signals(prop: &dyn Fn(&str) -> String) -> PropVerdict {
    let mut verdict = PropVerdict { insecure: prop(&s!("ro.secure")) == "0", weak_signals: 0 };
    if prop(&s!("ro.debuggable")) == "1" {
        verdict.weak_signals += 1;
    }
    let build_type = prop(&s!("ro.build.type"));
    if build_type == obfstr::obfstr!("userdebug") || build_type == obfstr::obfstr!("eng") {
        verdict.weak_signals += 1;
    }
    if prop(&s!("ro.build.tags")).contains(s!("test-keys").as_str()) {
        verdict.weak_signals += 1;
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::super::maps;
    use super::*;
    use crate::test_support::{fixture_text, props_from};

    #[test]
    fn su_and_manager_paths() {
        assert!(!su_present(&|_| false));
        assert!(su_present(&|path| path == "/system/xbin/su"));
        assert!(root_manager_present(&|path| path == "/debug_ramdisk/.magisk"));
        assert!(!root_manager_present(&|path| path == "/data/adb"));
    }

    #[test]
    fn mounts() {
        assert!(!mounts_trace(&fixture_text("proc/mounts_clean.txt")));
        assert!(mounts_trace(&fixture_text("proc/mounts_magisk.txt")));
        assert!(mounts_trace("KSU /system/bin overlay ro,relatime 0 0"));
    }

    #[test]
    fn maps() {
        assert!(!maps_trace(&maps::parse(&fixture_text("proc/maps_clean.txt"))));
        assert!(maps_trace(&maps::parse(&fixture_text("proc/maps_hooked.txt"))));
    }

    #[test]
    fn properties() {
        let retail = props_from("ro.secure=1\nro.debuggable=0\nro.build.type=user\nro.build.tags=release-keys");
        assert_eq!(property_signals(&retail), PropVerdict { insecure: false, weak_signals: 0 });
        let cheap_oem = props_from("ro.secure=1\nro.debuggable=0\nro.build.type=user\nro.build.tags=test-keys");
        assert_eq!(property_signals(&cheap_oem).weak_signals, 1);
        let custom_rom = props_from("ro.secure=1\nro.debuggable=1\nro.build.type=userdebug\nro.build.tags=test-keys");
        assert_eq!(property_signals(&custom_rom).weak_signals, 3);
        assert!(property_signals(&props_from("ro.secure=0")).insecure);
    }
}
