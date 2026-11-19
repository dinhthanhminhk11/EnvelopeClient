//! The Apple scan on the macOS host: the signal → flag logic over a fake [`Probe`], and the real [`System`] probes
//! (`access` / `open` / `unlink` under a fake device root, the dyld image list, `getenv`, `sysctl` KERN_PROC_PID, the
//! `kinfo_proc` constants against the measured SDK layout). Nothing here spawns a process (see
//! [`kinfo_proc_constants_are_the_measured_ones`]); the traced case runs in tests/c-abi/smoke.c.

use std::cell::RefCell;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::test_support::fixture_text;

// ---- fake probe ---------------------------------------------------------------------------------------------------

/// A device described by its answers; records what the scan asked.
struct Fake {
    paths: Vec<String>,
    writable: Vec<String>,
    images: Vec<String>,
    env: Vec<String>,
    port: bool,
    traced: Option<bool>,
    simulator: bool,
    asked_paths: RefCell<Vec<String>>,
    asked_dirs: RefCell<Vec<String>>,
    asked_env: RefCell<Vec<String>>,
}

impl Fake {
    /// A stock device: system images only, nothing else.
    fn clean() -> Fake {
        Fake {
            paths: Vec::new(),
            writable: Vec::new(),
            images: stock_images(),
            env: Vec::new(),
            port: false,
            traced: Some(false),
            simulator: false,
            asked_paths: RefCell::default(),
            asked_dirs: RefCell::default(),
            asked_env: RefCell::default(),
        }
    }

    fn with_images(names: &[&str]) -> Fake {
        let mut fake = Fake::clean();
        fake.images.extend(names.iter().map(|name| (*name).to_owned()));
        fake
    }
}

impl Probe for Fake {
    fn path_exists(&self, path: &str) -> bool {
        self.asked_paths.borrow_mut().push(path.to_owned());
        self.paths.iter().any(|existing| existing == path)
    }

    fn can_create_in(&self, dir: &str) -> bool {
        self.asked_dirs.borrow_mut().push(dir.to_owned());
        self.writable.iter().any(|writable| writable == dir)
    }

    fn image_names(&self) -> Vec<String> {
        self.images.clone()
    }

    fn env_set(&self, name: &str) -> bool {
        self.asked_env.borrow_mut().push(name.to_owned());
        self.env.iter().any(|set| set == name)
    }

    fn frida_port_open(&self) -> bool {
        self.port
    }

    fn traced(&self) -> Option<bool> {
        self.traced
    }

    fn simulator(&self) -> bool {
        self.simulator
    }
}

/// Image paths of a stock iPhone app.
fn stock_images() -> Vec<String> {
    [
        "/private/var/containers/Bundle/Application/4C1D2E3F-5A6B-4C7D-8E9F-0A1B2C3D4E5F/DoodleArt.app/DoodleArt",
        "/private/var/containers/Bundle/Application/4C1D2E3F-5A6B-4C7D-8E9F-0A1B2C3D4E5F/DoodleArt.app/Frameworks/\
         AdsMediationManager.framework/AdsMediationManager",
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/system/libdyld.dylib",
        "/usr/lib/libobjc.A.dylib",
        "/System/Library/Frameworks/UIKit.framework/UIKit",
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/System/Library/Frameworks/DeviceCheck.framework/DeviceCheck",
        "/System/Library/PrivateFrameworks/TextInput.framework/TextInput",
        "/usr/lib/swift/libswiftCore.dylib",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect()
}

fn scan_of(probe: &impl Probe) -> RiskReport {
    scan_in(probe, true)
}

/// The detail names in debug and QA builds; none in release builds (RiskReport).
fn assert_details(report: &RiskReport, expected: &[&str]) {
    if cfg!(feature = "build-release") {
        assert!(report.details.is_empty(), "{:?}", report.details);
    } else {
        assert_eq!(report.details, expected);
    }
}

fn assert_only(report: &RiskReport, flags: &[&str], details: &[&str]) {
    assert_eq!(report.flag_names(), flags, "details {:?}", report.details);
    assert_details(report, details);
}

// ---- lists --------------------------------------------------------------------------------------------------------

/// The reviewed lists (module documentation): changing one is a reviewed change of this golden test.
#[test]
fn lists_are_the_reviewed_ones() {
    assert_eq!(
        jailbreak_paths(),
        [
            "/var/jb",
            "/var/binpack",
            "/cores/binpack",
            "/.procursus_strapped",
            "/.bootstrapped",
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/usr/libexec/cydia",
            "/etc/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/lib/dpkg",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/Library/Frameworks/CydiaSubstrate.framework",
            "/Library/PreferenceLoader",
            "/usr/lib/libsubstrate.dylib",
            "/usr/lib/libhooker.dylib",
            "/usr/lib/libsubstitute.dylib",
            "/usr/lib/TweakInject",
            "/usr/lib/ellekit",
            "/usr/sbin/frida-server",
        ]
    );
    assert_eq!(write_probe_dir(), "/private/");
    assert_eq!(
        hook_image_tokens(),
        [
            "mobilesubstrate",
            "cydiasubstrate",
            "substrateloader",
            "substrateinserter",
            "libsubstrate",
            "libhooker",
            "libblackjack",
            "tweakinject",
            "tweakloader",
            "ellekit",
            "libsubstitute",
            "substitute-loader",
            "substitute-inserter",
            "systemhook.dylib",
            "sslkillswitch",
            "cycript",
            "/var/jb/",
            "/procursus/",
        ]
    );
    assert_eq!(frida_image_tokens(), ["frida-agent", "frida-gadget", "fridagadget"]);

    let paths = jailbreak_paths();
    for path in &paths {
        assert!(path.starts_with('/') && !path.ends_with('/') && !path.contains("//"), "{path}");
    }
    let unique: std::collections::BTreeSet<&String> = paths.iter().collect();
    assert_eq!(unique.len(), paths.len());
    // Matched against lowercased paths: an uppercase token could never match.
    for token in hook_image_tokens().iter().chain(&frida_image_tokens()) {
        assert!(!token.is_empty() && *token == token.to_ascii_lowercase(), "{token}");
    }
}

// ---- signal → flag ------------------------------------------------------------------------------------------------

/// A stock device reports nothing, and every check ran: every path, the write probe, the environment.
#[test]
fn stock_device_reports_nothing() {
    let fake = Fake::clean();
    let report = scan_of(&fake);
    assert_only(&report, &[], &[]);
    assert_eq!(*fake.asked_paths.borrow(), jailbreak_paths());
    assert_eq!(*fake.asked_dirs.borrow(), ["/private/"]);
    assert_eq!(*fake.asked_env.borrow(), ["DYLD_INSERT_LIBRARIES"]);
}

#[test]
fn each_jailbreak_path_is_root() {
    for path in jailbreak_paths() {
        let mut fake = Fake::clean();
        fake.paths = vec![path.clone()];
        let report = scan_of(&fake);
        assert_only(&report, &["root"], &["root.paths"]);
        // The first hit is enough.
        assert_eq!(fake.asked_paths.borrow().last(), Some(&path));
    }
    // A path the list does not hold is not looked at.
    let mut fake = Fake::clean();
    fake.paths = vec!["/var/mobile/Containers/Data".to_owned(), "/Applications/MobileSafari.app".to_owned()];
    assert_only(&scan_of(&fake), &[], &[]);
}

#[test]
fn creating_a_file_outside_the_sandbox_is_root() {
    let mut fake = Fake::clean();
    fake.writable = vec!["/private/".to_owned()];
    assert_only(&scan_of(&fake), &["root"], &["root.write"]);

    fake.paths = vec!["/var/jb".to_owned()];
    assert_only(&scan_of(&fake), &["root"], &["root.paths", "root.write"]);

    // Writable elsewhere (the app's own container) is not a signal.
    let mut fake = Fake::clean();
    fake.writable = vec!["/private/var/mobile/Containers/Data/Application/X/tmp/".to_owned()];
    assert_only(&scan_of(&fake), &[], &[]);
}

/// The macOS library: no filesystem probe at all, whatever the files, and a `root.unchecked` detail.
#[test]
fn without_filesystem_probes_no_path_is_touched() {
    let mut fake = Fake::clean();
    fake.paths = jailbreak_paths();
    fake.writable = vec!["/private/".to_owned()];
    let report = scan_in(&fake, false);
    assert_only(&report, &[], &["root.unchecked"]);
    assert!(fake.asked_paths.borrow().is_empty());
    assert!(fake.asked_dirs.borrow().is_empty());
    // The process checks still run.
    assert_eq!(*fake.asked_env.borrow(), ["DYLD_INSERT_LIBRARIES"]);
    fake.port = true;
    assert_only(&scan_in(&fake, false), &["frida"], &["root.unchecked", "frida.port"]);
}

/// The filesystem probes run on iOS (device and Simulator) only: off on this macOS host.
#[test]
fn filesystem_probes_are_on_for_ios_only() {
    assert_eq!(FILESYSTEM_PROBES, cfg!(target_os = "ios"));
}

#[test]
fn each_tweak_library_is_hook() {
    for token in hook_image_tokens() {
        // dyld names keep their case: the match is case-insensitive.
        let image = format!("/Library/Tweaks/{}.dylib", token.to_ascii_uppercase());
        assert_only(&scan_of(&Fake::with_images(&[&image])), &["hook"], &["hook.dyld_image"]);
    }
    for image in [
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateLoader.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libblackjack.dylib",
        "/usr/lib/TweakInject.dylib",
        "/var/jb/usr/lib/TweakLoader.dylib",
        "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/substitute-loader.dylib",
        "/private/preboot/A1B2C3/dopamine-x7Kq/procursus/usr/lib/systemhook.dylib",
        "/var/jb/Library/MobileSubstrate/DynamicLibraries/AnyTweak.dylib",
        "/usr/lib/libcycript.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.dylib",
    ] {
        assert_only(&scan_of(&Fake::with_images(&[image])), &["hook"], &["hook.dyld_image"]);
    }
}

#[test]
fn frida_libraries_are_frida() {
    for token in frida_image_tokens() {
        let image = format!("/private/var/tmp/{}-arm64.dylib", token.to_ascii_uppercase());
        assert_only(&scan_of(&Fake::with_images(&[&image])), &["frida"], &["frida.dyld_image"]);
    }
    for image in [
        "/usr/lib/frida/frida-agent.dylib",
        "/private/var/containers/Bundle/Application/X/App.app/Frameworks/FridaGadget.dylib",
        "/var/jb/usr/lib/frida/frida-agent.dylib",
    ] {
        let report = scan_of(&Fake::with_images(&[image]));
        assert!(report.flags.contains(&Flag::Frida), "{image}");
        assert!(!cfg!(feature = "build-release") || report.details.is_empty());
    }
}

#[test]
fn ordinary_images_are_clean() {
    assert_only(&scan_of(&Fake::clean()), &[], &[]);
    // The libraries of this very test process (system frameworks, the test binary): nothing to report.
    let fake = Fake { images: System::new().image_names(), ..Fake::clean() };
    assert_only(&scan_of(&fake), &[], &[]);
}

#[test]
fn dyld_insert_libraries_is_hook() {
    let mut fake = Fake::clean();
    fake.env = vec!["DYLD_INSERT_LIBRARIES".to_owned()];
    assert_only(&scan_of(&fake), &["hook"], &["hook.dyld_env"]);
    // Other dyld variables are not looked at.
    fake.env = vec!["DYLD_LIBRARY_PATH".to_owned(), "DYLD_FRAMEWORK_PATH".to_owned()];
    assert_only(&scan_of(&fake), &[], &[]);
}

#[test]
fn listening_frida_port_is_frida() {
    let mut fake = Fake::clean();
    fake.port = true;
    assert_only(&scan_of(&fake), &["frida"], &["frida.port"]);
}

#[test]
fn traced_process_is_debugger_and_an_unreadable_flag_is_nothing() {
    let mut fake = Fake::clean();
    fake.traced = Some(true);
    assert_only(&scan_of(&fake), &["debugger"], &["debugger.traced"]);
    fake.traced = None;
    assert_only(&scan_of(&fake), &[], &["debugger.unchecked"]);
}

#[test]
fn simulator_is_emulator() {
    let mut fake = Fake::clean();
    fake.simulator = true;
    assert_only(&scan_of(&fake), &["emulator"], &["emulator.simulator"]);
}

/// Every signal at once: sorted flags, details in check order.
#[test]
fn every_signal_at_once() {
    let fake = Fake {
        paths: vec!["/var/jb".to_owned()],
        writable: vec!["/private/".to_owned()],
        images: vec!["/var/jb/usr/lib/libellekit.dylib".to_owned(), "/usr/lib/frida/frida-agent.dylib".to_owned()],
        env: vec!["DYLD_INSERT_LIBRARIES".to_owned()],
        port: true,
        traced: Some(true),
        simulator: true,
        ..Fake::clean()
    };
    let report = scan_of(&fake);
    assert_eq!(report.csv(), "debugger,emulator,frida,hook,root");
    assert_details(
        &report,
        &[
            "root.paths",
            "root.write",
            "hook.dyld_image",
            "hook.dyld_env",
            "frida.dyld_image",
            "frida.port",
            "debugger.traced",
            "emulator.simulator",
        ],
    );
    // Only the server's vocabulary, never apk_resigned (App Attest covers a re-signed app).
    assert!(report.flag_names().iter().all(|flag| crate::envelope::validate::risk_flag(flag)));
    assert!(!report.flags.contains(&Flag::ApkResigned));
}

// ---- the real probes ----------------------------------------------------------------------------------------------

/// A fresh directory standing for a device root; removed on drop.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> TempRoot {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!("doodleart-apple-scan-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        TempRoot(dir.canonicalize().unwrap())
    }

    fn system(&self) -> System {
        System { root: self.0.to_str().unwrap().to_owned(), ..System::new() }
    }

    /// The `open` probe alone (no `access`).
    fn open_only(&self) -> System {
        System { skip_access: true, ..self.system() }
    }

    /// `path` (absolute, device side) on the host.
    fn host(&self, path: &str) -> PathBuf {
        self.0.join(path.trim_start_matches('/'))
    }

    fn create_file(&self, path: &str) -> PathBuf {
        let host = self.host(path);
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, b"").unwrap();
        host
    }

    fn create_dir(&self, path: &str) -> PathBuf {
        let host = self.host(path);
        std::fs::create_dir_all(&host).unwrap();
        host
    }

    fn entries(&self, path: &str) -> Vec<String> {
        std::fs::read_dir(self.host(path))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn running_as_root() -> bool {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Every listed path is found by the real `access` / `open` under a fake root, as a file and as a directory, and
/// reported as `root.paths` by the scan; an empty root reports nothing.
#[test]
fn real_probe_finds_each_jailbreak_path_under_a_fake_root() {
    let empty = TempRoot::new();
    for path in jailbreak_paths() {
        assert!(!empty.system().path_exists(&path), "{path}");
    }
    let report = scan_in(&empty.system(), true);
    assert!(!report.flags.contains(&Flag::Root), "{:?}", report.details);

    for path in jailbreak_paths() {
        let root = TempRoot::new();
        root.create_file(&path);
        assert!(root.system().path_exists(&path), "file {path}");
        let report = scan_in(&root.system(), true);
        assert!(report.flags.contains(&Flag::Root), "{path}");
        assert!(cfg!(feature = "build-release") || report.details.contains(&"root.paths".to_owned()));

        let root = TempRoot::new();
        root.create_dir(&path);
        assert!(root.system().path_exists(&path), "directory {path}");
    }
}

/// `/var/jb` is a symlink to the jailbreak root: followed. A dangling one reads as absent.
#[test]
fn real_probe_follows_symlinks() {
    let root = TempRoot::new();
    let target = root.create_dir("/private/preboot/ABC/jb-x/procursus");
    std::fs::create_dir_all(root.host("/var")).unwrap();
    symlink(&target, root.host("/var/jb")).unwrap();
    assert!(root.system().path_exists("/var/jb"));

    let dangling = TempRoot::new();
    std::fs::create_dir_all(dangling.host("/var")).unwrap();
    symlink(dangling.host("/nowhere"), dangling.host("/var/jb")).unwrap();
    assert!(!dangling.system().path_exists("/var/jb"));
}

/// Only success counts: a path the sandbox (here: permissions) hides reads as absent. A file that exists but cannot be
/// opened is still present (access(F_OK) only needs the directory).
#[test]
fn real_probe_counts_only_success() {
    if running_as_root() {
        eprintln!("skipped: root ignores permissions");
        return;
    }
    let root = TempRoot::new();
    root.create_file("/etc/apt/sources.list.d");
    let locked = root.host("/etc/apt");
    set_mode(&locked, 0o000);
    let hidden = root.system().path_exists("/etc/apt/sources.list.d");
    set_mode(&locked, 0o755);
    assert!(!hidden, "EACCES reads as absent");

    let unreadable = root.create_file("/.bootstrapped");
    set_mode(&unreadable, 0o000);
    assert!(root.system().path_exists("/.bootstrapped"), "exists although open() fails");
    set_mode(&unreadable, 0o644);

    assert!(!root.system().path_exists("/var/jb\0/x"), "interior NUL");
}

/// The write probe creates a new file and removes it: nothing stays; a missing or read-only directory is no signal.
#[test]
fn real_write_probe_leaves_nothing() {
    let root = TempRoot::new();
    assert!(!root.system().can_create_in("/private/"), "missing directory");

    root.create_dir("/private");
    root.create_file("/private/keep");
    assert!(root.system().can_create_in("/private/"));
    assert_eq!(root.entries("/private"), ["keep"], "the probe file is gone, the rest untouched");
    let report = scan_in(&root.system(), true);
    assert!(report.flags.contains(&Flag::Root));
    assert!(cfg!(feature = "build-release") || report.details == ["root.write"]);
    assert_eq!(root.entries("/private"), ["keep"]);

    if !running_as_root() {
        let dir = root.host("/private");
        set_mode(&dir, 0o555);
        let created = root.system().can_create_in("/private/");
        set_mode(&dir, 0o755);
        assert!(!created, "read-only directory");
    }
}

/// The `open` probe alone sees what `access` sees, files and directories, through a symlink, and only success counts.
#[test]
fn real_open_probe_alone() {
    for path in jailbreak_paths() {
        let root = TempRoot::new();
        assert!(!root.open_only().path_exists(&path), "missing {path}");
        root.create_file(&path);
        assert!(root.open_only().path_exists(&path), "file {path}");
        let root = TempRoot::new();
        root.create_dir(&path);
        assert!(root.open_only().path_exists(&path), "directory {path}");
    }
    let root = TempRoot::new();
    let target = root.create_dir("/private/preboot/ABC/jb-x/procursus");
    std::fs::create_dir_all(root.host("/var")).unwrap();
    symlink(&target, root.host("/var/jb")).unwrap();
    assert!(root.open_only().path_exists("/var/jb"));
    if !running_as_root() {
        // Present, but open() is refused: invisible to this probe alone (access sees it:
        // real_probe_counts_only_success).
        let unreadable = root.create_file("/.bootstrapped");
        set_mode(&unreadable, 0o000);
        let seen = root.open_only().path_exists("/.bootstrapped");
        set_mode(&unreadable, 0o644);
        assert!(!seen);
    }
}

/// O_EXCL: a file that already has the probe's name is neither opened, nor reported, nor removed.
#[test]
fn real_write_probe_never_touches_an_existing_file() {
    let root = TempRoot::new();
    let existing = root.create_file("/private/.0123456789abcdef");
    std::fs::write(&existing, b"keep").unwrap();
    let system = System { probe_name: Some(".0123456789abcdef".to_owned()), ..root.system() };
    assert!(!system.can_create_in("/private/"));
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep");

    std::fs::remove_file(&existing).unwrap();
    assert!(system.can_create_in("/private/"));
    assert!(root.entries("/private").is_empty());
}

#[test]
fn probe_file_names_are_random_and_hidden() {
    let first = probe_file_name().unwrap();
    let second = probe_file_name().unwrap();
    assert_ne!(first, second);
    for name in [&first, &second] {
        assert_eq!(name.len(), 17, "{name}");
        assert!(name.starts_with('.') && name[1..].bytes().all(|byte| byte.is_ascii_hexdigit()), "{name}");
    }
}

/// The real image list of this process: every image (fewer than the bound), the test binary and libSystem among them.
#[test]
fn real_image_list() {
    let names = System::new().image_names();
    // SAFETY: no preconditions.
    let count = unsafe { _dyld_image_count() };
    assert!(count > 0 && count < MAX_IMAGES);
    // Images may load while the test runs, never unload: at least the count read before.
    assert!(names.len() >= count as usize && names.len() <= MAX_IMAGES as usize, "{} / {count}", names.len());
    assert!(names.iter().any(|name| name == "/usr/lib/libSystem.B.dylib"), "{names:?}");
    let exe = std::env::current_exe().unwrap();
    let exe_name = exe.file_name().unwrap().to_str().unwrap();
    assert!(names.iter().any(|name| name.ends_with(&format!("/{exe_name}"))), "{exe_name} in {names:?}");
}

/// NULL names (images unloaded during the walk) are skipped, not the end of the list; at most MAX_IMAGES are read.
#[test]
fn image_walk_skips_null_names_and_is_bounded() {
    let names = [c"/usr/lib/libSystem.B.dylib".as_ptr(), ptr::null(), c"/var/jb/usr/lib/libellekit.dylib".as_ptr()];
    // SAFETY: NULL or C string literals.
    let walked = unsafe { image_names_from(names.len() as u32, |index| names[index as usize]) };
    assert_eq!(walked, ["/usr/lib/libSystem.B.dylib", "/var/jb/usr/lib/libellekit.dylib"]);

    let asked = std::cell::Cell::new(0u32);
    // SAFETY: a C string literal.
    let walked = unsafe {
        image_names_from(u32::MAX, |index| {
            asked.set(index + 1);
            c"/x".as_ptr()
        })
    };
    assert_eq!(asked.get(), MAX_IMAGES);
    assert_eq!(walked.len(), MAX_IMAGES as usize);
}

#[test]
fn real_environment() {
    let system = System::new();
    assert!(system.env_set("PATH"));
    assert!(!system.env_set("DOODLEART_CORE_TEST_SURELY_UNSET_7f3a9c"));
    assert!(!system.env_set("PA\0TH"));
    // SAFETY: NULL, or C string literals.
    unsafe {
        assert!(!non_empty(ptr::null()));
        assert!(!non_empty(c"".as_ptr()));
        assert!(non_empty(c"/usr/lib/x.dylib".as_ptr()));
    }
}

#[test]
fn c_bytes_stops_at_the_terminator_or_the_bound() {
    let text = c"libhooker";
    // SAFETY: a NUL-terminated literal.
    unsafe {
        assert_eq!(c_bytes(text.as_ptr(), MAX_IMAGE_NAME), b"libhooker");
        assert_eq!(c_bytes(text.as_ptr(), 3), b"lib");
        assert_eq!(c_bytes(text.as_ptr(), 0), b"");
    }
}

/// A `kinfo_proc` image: `flag` at the `p_flag` offset, `pid` at the `p_pid` offset.
fn kinfo(len: usize, flag: i32, pid: i32) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    bytes[P_FLAG_OFFSET..P_FLAG_OFFSET + 4].copy_from_slice(&flag.to_ne_bytes());
    bytes[P_PID_OFFSET..P_PID_OFFSET + 4].copy_from_slice(&pid.to_ne_bytes());
    bytes
}

#[test]
fn p_traced_is_read_only_from_a_kinfo_proc_of_ours() {
    const P_LP64: i32 = 0x4;
    const P_EXEC: i32 = 0x4000;
    assert_eq!(traced_from(&kinfo(648, P_LP64 | P_EXEC | P_TRACED, 77), 77), Some(true));
    assert_eq!(traced_from(&kinfo(648, P_LP64 | P_EXEC, 77), 77), Some(false));
    assert_eq!(traced_from(&kinfo(648, !P_TRACED, 77), 77), Some(false));
    // Another pid at our offset: the layout is not the one we know.
    assert_eq!(traced_from(&kinfo(648, P_TRACED, 78), 77), None);
    // Too short (a smaller struct) is unknown; longer (fields appended) is fine.
    assert_eq!(traced_from(&kinfo(647, P_TRACED, 77), 77), None);
    assert_eq!(traced_from(&kinfo(4096, P_TRACED, 77), 77), Some(true));
    assert_eq!(traced_from(&[], 77), None);
    // P_TRACED anywhere but p_flag does not count.
    let mut moved = kinfo(648, 0, 77);
    moved[36..40].copy_from_slice(&P_TRACED.to_ne_bytes());
    assert_eq!(traced_from(&moved, 77), Some(false));
}

/// The buffer is at least one kinfo_proc (the kernel refuses less), larger when the kernel asks for more (its size
/// query answers with slack, about 3.9 KB), and the query is refused beyond 64 KiB.
#[test]
fn kinfo_buffer_follows_the_kernel_within_a_bound() {
    assert_eq!(kinfo_buffer_len(0), Some(KINFO_PROC_SIZE));
    assert_eq!(kinfo_buffer_len(KINFO_PROC_SIZE - 1), Some(KINFO_PROC_SIZE));
    assert_eq!(kinfo_buffer_len(3888), Some(3888));
    assert_eq!(kinfo_buffer_len(MAX_KINFO_BUFFER), Some(MAX_KINFO_BUFFER));
    assert_eq!(kinfo_buffer_len(MAX_KINFO_BUFFER + 1), None);
}

/// `cargo test` runs without a debugger: sysctl answers, the layout checks out (p_pid), P_TRACED is clear.
#[test]
fn this_process_is_not_traced() {
    assert_eq!(System::new().traced(), Some(false));
}

/// The `kinfo_proc` constants are the values measured against the macOS SDK, kept in a fixture that
/// tools/c-abi-smoke.sh checks against the SDK (tests/c-abi/kinfo_layout.c, compiled with clang). No compiler run
/// here: a child process spawned by a unit test inherits the sockets other tests are opening at that instant (macOS
/// sets close-on-exec after `socket()`), which makes their "port closed" checks flaky. The traced case itself runs in
/// tests/c-abi/smoke.c (a forked child under PT_TRACE_ME calls `doodleart_risk_scan`).
#[test]
fn kinfo_proc_constants_are_the_measured_ones() {
    let fixture = fixture_text("kinfo-proc-macos-sdk.txt");
    let measured: Vec<(&str, i64)> = fixture
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let (key, value) = line.split_once('=').unwrap();
            (key, value.parse().unwrap())
        })
        .collect();
    let expected = [
        ("sizeof_kinfo_proc", KINFO_PROC_SIZE as i64),
        ("offsetof_p_flag", P_FLAG_OFFSET as i64),
        ("offsetof_p_pid", P_PID_OFFSET as i64),
        ("P_TRACED", i64::from(P_TRACED)),
        ("CTL_KERN", i64::from(libc::CTL_KERN)),
        ("KERN_PROC", i64::from(libc::KERN_PROC)),
        ("KERN_PROC_PID", i64::from(libc::KERN_PROC_PID)),
    ];
    assert_eq!(measured, expected);
}

#[test]
fn this_host_is_not_a_simulator() {
    assert!(!System::new().simulator());
}

/// The library's scan on this host (macOS): process checks only, `root.unchecked`, nothing to report.
#[test]
fn real_scan_on_this_host() {
    let report = scan();
    assert!(!report.flags.contains(&Flag::Root));
    assert!(!report.flags.contains(&Flag::Emulator));
    assert!(!report.flags.contains(&Flag::Frida));
    if cfg!(feature = "build-release") {
        assert!(report.details.is_empty());
    } else {
        assert_eq!(report.details.first().map(String::as_str), Some("root.unchecked"), "{:?}", report.details);
    }
}
