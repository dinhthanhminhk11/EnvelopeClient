//! The Apple scan (theme-x spec 2026-11-05 §5.12, D-24): the flags the iOS app reports in its handshake and through
//! `doodleart_risk_scan`. Swift does not scan: checks written in Swift (`FileManager`, `_dyld_*`, `sysctl`) are the public
//! hook points a tweak disables first. The flags are the server's vocabulary (server/src/core/usecases/devicesession, heavyRiskFlags / lightRiskFlags):
//! a heavy flag makes the device and the session `untrusted`, a light one caps them at `limited` (theme-x spec §3.7).
//!
//! - `root` (light), a jailbreak:
//!   - `root.paths`: a jailbreak file or directory exists (`/var/jb` of the rootless jailbreaks, Cydia, Sileo,
//!     Substrate, ElleKit, apt…). Probed with `access(F_OK)`, then `open(O_RDONLY)`; only success counts: ENOENT,
//!     EPERM (a sandbox denial) and every other error read as absent, so a sandbox that refuses to answer never looks
//!     like a jailbreak. None of these paths is expected on a stock device, and an App Store app cannot create them
//!     (system volume, outside its container) [đo: checked on a fake root on the host only; to measure: the debug
//!     library on stock iOS 16, 17, 18 and 26 devices and as "Designed for iPad" on a Mac, started from the home
//!     screen, where doodleart_risk_scan must give empty flags and details, no `root.write`: theme-x spec §7.3 #20].
//!   - `root.write`: a new file can be created in `/private/`, outside the sandbox (on a stock device the sealed,
//!     read-only system volume, and the sandbox refuses anyway [đo: the same device run as `root.paths`]).
//!     `O_CREAT | O_EXCL` under a random name, unlinked at once: nothing existing is opened or overwritten, and nothing
//!     stays unless the process dies between the two calls.
//! - `hook` (heavy): a tweak injection library is loaded (`hook.dyld_image`: Substrate, libhooker, ElleKit,
//!   Substitute, TweakInject, Dopamine's systemhook, anything loaded from a jailbreak root), or `DYLD_INSERT_LIBRARIES`
//!   is set (`hook.dyld_env`). The image names come from `_dyld_image_count` / `_dyld_get_image_name` (libSystem; there
//!   is no other way to list them). Note: Xcode sets `DYLD_INSERT_LIBRARIES` for its diagnostics (Main Thread Checker,
//!   sanitizers), so a run from Xcode also reports `hook`, as it reports `debugger` [đo: a Debug run from Xcode with
//!   and without the Main Thread Checker gives `debugger` + `debugger.traced` both times, `hook` / `hook.dyld_env`
//!   only with the checker on: theme-x spec §7.3 #21].
//! - `frida` (heavy): Frida's agent or gadget is loaded (`frida.dyld_image`), or something listens on 127.0.0.1:27042,
//!   frida-server's default port (`frida.port`, shared with Android, [`super::port`]). A loopback connect is not
//!   expected to trigger the Local Network permission prompt of iOS 14+ ([đo] on a device: the first scan shows no
//!   prompt, theme-x spec §7.3 #22).
//! - `debugger` (heavy): `P_TRACED` in our own `kinfo_proc` (`sysctl` KERN_PROC_PID; `debugger.traced`). Read only:
//!   we never call ptrace. Apple does not guarantee the `kinfo_proc` layout (QA1361), so the buffer is sized from the
//!   kernel's answer and the result is used only when `p_pid` at its offset is our pid; otherwise the check reports
//!   nothing (`debugger.unchecked`). Running a Debug build from Xcode always sets `P_TRACED` (theme-x spec §5.12: trust tests
//!   start the app from the home screen).
//! - `emulator` (light): a Simulator build (`emulator.simulator`: `target_env` / `target_abi` "sim", Debug only).
//! - `apk_resigned` is never sent: App Attest refuses a re-signed app.
//!
//! Platforms: the iOS device and Simulator libraries run every check. The macOS library exists for host Swift tests
//! only (never shipped): it runs the process checks and skips the filesystem ones (detail `root.unchecked`), which
//! describe the iOS file system: a Mac is not sandboxed and may carry such files legitimately (Procursus, Homebrew).
//!
//! Limits (theme-x spec §5.12, §8 #20): libc functions only, no direct `svc 0x80` syscalls yet (Darwin syscall numbers are not
//! ABI; theme-x spec §4.1 asks for a measurement [đo] on iOS 16-27 first), so a tweak that hooks `access`, `open`, `sysctl` or
//! the dyld functions can hide itself. Jailbreaks that randomise their root (RootHide) are not found by path.
//!
//! Contract: blocking (a 150 ms loopback connect at most, a few dozen file probes and one walk of the image list):
//! never on the main thread. Never panics and never crashes on what it reads; a check that cannot run reports nothing.
//! The detail names are filled in debug and QA builds only ([`RiskReport`]).

use std::ffi::{c_char, CString};
use std::ptr;

use obfstr::obfstring as s;
use rand_core::{OsRng, RngCore};

use super::{port, Flag, RiskReport};

/// Filesystem probes run on iOS (device and Simulator), not in the macOS library (module documentation).
const FILESYSTEM_PROBES: bool = !cfg!(target_os = "macos");

/// A Simulator build: rustc's `target_env` / `target_abi` "sim". A typo here would flag every iPhone `emulator` (or
/// no Simulator), and no test on the host could see it: build.rs derives `doodleart_simulator_target` from the target
/// triple alone, and every build for an Apple target checks the two agree.
const SIMULATOR_BUILD: bool = cfg!(any(target_env = "sim", target_abi = "sim"));
const _: () = assert!(
    SIMULATOR_BUILD == cfg!(doodleart_simulator_target),
    "the Simulator cfg of src/risk/apple.rs disagrees with the target triple (build.rs doodleart_simulator_target)"
);

/// At most this many dyld images are read (an iOS app loads several hundred).
const MAX_IMAGES: u32 = 4096;
/// At most this many bytes of an image name are read (MAXPATHLEN is 1024).
const MAX_IMAGE_NAME: usize = 4096;

/// `struct kinfo_proc` of <sys/sysctl.h> and <sys/proc.h> on 64-bit Apple targets, measured with the macOS SDK
/// (CommandLineTools MacOSX15.5.sdk, arm64: `sizeof` 648, `kp_proc.p_flag` at 32, `kp_proc.p_pid` at 40,
/// `P_TRACED` 0x800). libc 0.2 does not declare it. Checked at run time by the `p_pid` comparison (QA1361).
/// [đo] Not measured with the iPhoneOS SDK (no Xcode here): a different layout fails open to `debugger.unchecked`,
/// which a release library does not report, so the `debugger` flag would silently stop. To measure (theme-x spec §7.3 #19):
/// compile tests/c-abi/kinfo_layout.c with `xcrun --sdk iphoneos clang -target arm64-apple-ios16.0`, its output must
/// equal tests/fixtures/kinfo-proc-macos-sdk.txt, and a Debug run from Xcode on a device must report
/// `debugger.traced`.
const KINFO_PROC_SIZE: usize = 648;
const P_FLAG_OFFSET: usize = 32;
const P_PID_OFFSET: usize = 40;
const P_TRACED: i32 = 0x0000_0800;
/// Largest buffer the `kinfo_proc` size query may ask for (the kernel answers about 3.9 KB, with slack).
const MAX_KINFO_BUFFER: usize = 64 * 1024;

// dyld's image list (<mach-o/dyld.h>), part of libSystem like the libc functions. Declared here: the libc crate
// deprecates its own bindings of these two in favour of the mach2 crate, a dependency for two functions.
extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(image_index: u32) -> *const c_char;
}

/// Jailbreak files and directories (`root.paths`), none of which exists on a stock device.
fn jailbreak_paths() -> Vec<String> {
    vec![
        // Rootless jailbreaks (Dopamine, palera1n, XinaA15): the jailbreak root.
        s!("/var/jb"),
        // checkra1n and palera1n binpacks.
        s!("/var/binpack"),
        s!("/cores/binpack"),
        // Bootstrap markers of rootful jailbreaks.
        s!("/.procursus_strapped"),
        s!("/.bootstrapped"),
        // Package managers.
        s!("/Applications/Cydia.app"),
        s!("/Applications/Sileo.app"),
        s!("/Applications/Zebra.app"),
        s!("/usr/libexec/cydia"),
        s!("/etc/apt"),
        s!("/var/lib/apt"),
        s!("/var/lib/cydia"),
        s!("/var/lib/dpkg"),
        // Tweak injection.
        s!("/Library/MobileSubstrate/MobileSubstrate.dylib"),
        s!("/Library/MobileSubstrate/DynamicLibraries"),
        s!("/Library/Frameworks/CydiaSubstrate.framework"),
        s!("/Library/PreferenceLoader"),
        s!("/usr/lib/libsubstrate.dylib"),
        s!("/usr/lib/libhooker.dylib"),
        s!("/usr/lib/libsubstitute.dylib"),
        s!("/usr/lib/TweakInject"),
        s!("/usr/lib/ellekit"),
        // An installed frida-server needs a jailbreak (running, it is `frida.port`).
        s!("/usr/sbin/frida-server"),
    ]
}

/// Directory of the `root.write` probe.
fn write_probe_dir() -> String {
    s!("/private/")
}

/// Lowercase substrings of injected tweak libraries (`hook.dyld_image`), matched against lowercased image paths.
fn hook_image_tokens() -> Vec<String> {
    vec![
        s!("mobilesubstrate"),
        s!("cydiasubstrate"),
        s!("substrateloader"),
        s!("substrateinserter"),
        s!("libsubstrate"),
        s!("libhooker"),
        s!("libblackjack"),
        s!("tweakinject"),
        s!("tweakloader"),
        s!("ellekit"),
        s!("libsubstitute"),
        s!("substitute-loader"),
        s!("substitute-inserter"),
        s!("systemhook.dylib"),
        s!("sslkillswitch"),
        s!("cycript"),
        // Anything loaded from a rootless jailbreak root (its symlink or its real location).
        s!("/var/jb/"),
        s!("/procursus/"),
    ]
}

/// Lowercase substrings of Frida's agent and gadget (`frida.dyld_image`).
fn frida_image_tokens() -> Vec<String> {
    vec![s!("frida-agent"), s!("frida-gadget"), s!("fridagadget")]
}

/// What the scan reads from the device and the process. [`System`] is the real one; unit tests substitute fakes.
trait Probe {
    /// Whether the absolute `path` exists (and the sandbox lets us see it).
    fn path_exists(&self, path: &str) -> bool;
    /// Whether a new file can be created in the directory `dir` (ending in "/"); the file is removed again.
    fn can_create_in(&self, dir: &str) -> bool;
    /// Paths of the images dyld has loaded, at most [`MAX_IMAGES`].
    fn image_names(&self) -> Vec<String>;
    /// Whether the environment variable `name` is set to a non-empty value.
    fn env_set(&self, name: &str) -> bool;
    fn frida_port_open(&self) -> bool;
    /// `P_TRACED` of this process; `None` when it cannot be read reliably.
    fn traced(&self) -> Option<bool>;
    fn simulator(&self) -> bool;
}

/// Runs every check (iOS); the macOS library skips the filesystem probes. See the module documentation.
pub fn scan() -> RiskReport {
    scan_in(&System::new(), FILESYSTEM_PROBES)
}

fn scan_in(probe: &impl Probe, filesystem: bool) -> RiskReport {
    let mut report = RiskReport::default();

    // Root (jailbreak)
    if filesystem {
        if jailbreak_paths().iter().any(|path| probe.path_exists(path)) {
            report.note(Some(Flag::Root), || s!("root.paths"));
        }
        if probe.can_create_in(&write_probe_dir()) {
            report.note(Some(Flag::Root), || s!("root.write"));
        }
    } else {
        report.note(None, || s!("root.unchecked"));
    }

    // Injected libraries
    let images: Vec<String> = probe.image_names().iter().map(|name| name.to_ascii_lowercase()).collect();
    let loaded = |tokens: Vec<String>| images.iter().any(|image| tokens.iter().any(|token| image.contains(token)));
    if loaded(hook_image_tokens()) {
        report.note(Some(Flag::Hook), || s!("hook.dyld_image"));
    }
    if probe.env_set(&s!("DYLD_INSERT_LIBRARIES")) {
        report.note(Some(Flag::Hook), || s!("hook.dyld_env"));
    }

    // Frida
    if loaded(frida_image_tokens()) {
        report.note(Some(Flag::Frida), || s!("frida.dyld_image"));
    }
    if probe.frida_port_open() {
        report.note(Some(Flag::Frida), || s!("frida.port"));
    }

    // Debugger
    match probe.traced() {
        Some(true) => report.note(Some(Flag::Debugger), || s!("debugger.traced")),
        Some(false) => {}
        None => report.note(None, || s!("debugger.unchecked")),
    }

    // Simulator
    if probe.simulator() {
        report.note(Some(Flag::Emulator), || s!("emulator.simulator"));
    }

    report
}

/// The real device and process, through libc and libSystem only (no `std::fs`, no `stat` family: `access` and `open`
/// are not required-reason APIs, file timestamps are).
struct System {
    /// Unit tests only: a directory prepended to every probed path (a fake device root), so the real `access`,
    /// `open` and `unlink` calls run against fake jailbreak files on the host.
    #[cfg(test)]
    root: String,
    /// Unit tests only: leave `access` out of [`Probe::path_exists`], to exercise the `open` probe alone.
    #[cfg(test)]
    skip_access: bool,
    /// Unit tests only: the `root.write` probe's file name instead of a random one.
    #[cfg(test)]
    probe_name: Option<String>,
}

impl System {
    #[cfg(not(test))]
    fn new() -> System {
        System {}
    }

    #[cfg(test)]
    fn new() -> System {
        System { root: String::new(), skip_access: false, probe_name: None }
    }

    /// `path` (absolute) as a C string; `None` for an interior NUL.
    fn c_path(&self, path: &str) -> Option<CString> {
        #[cfg(test)]
        let path = &format!("{}{path}", self.root);
        CString::new(path.as_bytes()).ok()
    }
}

impl Probe for System {
    fn path_exists(&self, path: &str) -> bool {
        let Some(path) = self.c_path(path) else { return false };
        #[cfg(test)]
        let skip_access = self.skip_access;
        #[cfg(not(test))]
        let skip_access = false;
        // SAFETY: path is a NUL-terminated string that outlives the call; access only reads it.
        if !skip_access && unsafe { libc::access(path.as_ptr(), libc::F_OK) } == 0 {
            return true;
        }
        // A second, independent way to see the file (a tweak hiding files must hook both). Read only, never blocks
        // (O_NONBLOCK: FIFOs, devices), never becomes our controlling terminal, closed at once.
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        // SAFETY: path is a NUL-terminated string that outlives the call; without O_CREAT no mode argument is read.
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        if fd < 0 {
            return false;
        }
        // SAFETY: fd was opened just above by this function and is closed exactly once.
        unsafe { libc::close(fd) };
        true
    }

    fn can_create_in(&self, dir: &str) -> bool {
        #[cfg(test)]
        let name = self.probe_name.clone().or_else(probe_file_name);
        #[cfg(not(test))]
        let name = probe_file_name();
        let Some(name) = name else { return false };
        let Some(path) = self.c_path(&format!("{dir}{name}")) else { return false };
        // O_EXCL with O_CREAT: creates a new file or fails; never opens, truncates or follows (a symlink in the last
        // component fails) anything that exists.
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
        // SAFETY: path is a NUL-terminated string that outlives the call; with O_CREAT, open reads one mode argument,
        // passed as the int a C caller's mode_t promotes to.
        let fd = unsafe { libc::open(path.as_ptr(), flags, 0o600 as libc::c_int) };
        if fd < 0 {
            return false;
        }
        // SAFETY: path names the file this call has just created (O_EXCL), so unlinking it removes nothing else; fd
        // was opened just above and is closed exactly once.
        unsafe {
            libc::unlink(path.as_ptr());
            libc::close(fd);
        }
        true
    }

    fn image_names(&self) -> Vec<String> {
        // SAFETY: no preconditions.
        let count = unsafe { _dyld_image_count() };
        // SAFETY: any index is allowed: dyld returns NULL for one out of range (images unloaded since the count;
        // images loaded since are simply not seen). A non-NULL name is a NUL-terminated path owned by dyld, valid while
        // its image stays loaded (images linked at launch and the shared cache never unload; a bundle dlclose'd by
        // another thread during the walk is the one race dyld's API leaves open).
        unsafe { image_names_from(count, |index| _dyld_get_image_name(index)) }
    }

    fn env_set(&self, name: &str) -> bool {
        let Ok(name) = CString::new(name) else { return false };
        // SAFETY: name is NUL-terminated; getenv returns NULL or a NUL-terminated value, of which only the first
        // byte is read, at once.
        unsafe { non_empty(libc::getenv(name.as_ptr())) }
    }

    fn frida_port_open(&self) -> bool {
        port::frida_port_open()
    }

    fn traced(&self) -> Option<bool> {
        // SAFETY: no preconditions.
        let pid = unsafe { libc::getpid() };
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut needed: libc::size_t = 0;
        // SAFETY: a size query: mib holds 4 ints, oldp is NULL, oldlenp points to our size_t, nothing is set.
        let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 4, ptr::null_mut(), &mut needed, ptr::null_mut(), 0) };
        if rc != 0 {
            return None;
        }
        let mut buffer = vec![0u8; kinfo_buffer_len(needed)?];
        let mut len: libc::size_t = buffer.len();
        // SAFETY: buffer has len writable bytes; the kernel copies at most len bytes (ENOMEM when that is too little,
        // no partial write) and stores the length it wrote in len. A byte copy-out: no alignment requirement.
        let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 4, buffer.as_mut_ptr().cast(), &mut len, ptr::null_mut(), 0) };
        if rc != 0 {
            return None;
        }
        traced_from(&buffer[..len.min(buffer.len())], pid)
    }

    fn simulator(&self) -> bool {
        SIMULATOR_BUILD
    }
}

/// The names of the first `count` images (at most [`MAX_IMAGES`]), skipping the NULL ones; each name is read up to
/// [`MAX_IMAGE_NAME`] bytes.
///
/// # Safety
///
/// `name_at` returns NULL or a NUL-terminated string that stays readable until this function returns.
unsafe fn image_names_from(count: u32, name_at: impl Fn(u32) -> *const c_char) -> Vec<String> {
    let count = count.min(MAX_IMAGES);
    let mut names = Vec::with_capacity(count as usize);
    for index in 0..count {
        let name = name_at(index);
        if name.is_null() {
            continue;
        }
        // SAFETY: a non-NULL name is a NUL-terminated string, readable for this call (the caller's contract).
        let bytes = unsafe { c_bytes(name, MAX_IMAGE_NAME) };
        names.push(String::from_utf8_lossy(bytes).into_owned());
    }
    names
}

/// Size of the buffer for the `kinfo_proc` sysctl, from the size the kernel asked for: at least [`KINFO_PROC_SIZE`]
/// (the kernel refuses a smaller one), the kernel's answer when larger (a grown struct), `None` beyond
/// [`MAX_KINFO_BUFFER`].
fn kinfo_buffer_len(needed: usize) -> Option<usize> {
    (needed <= MAX_KINFO_BUFFER).then_some(needed.max(KINFO_PROC_SIZE))
}

/// `P_TRACED` from a `kinfo_proc` the kernel returned for `pid`; `None` unless it is at least [`KINFO_PROC_SIZE`]
/// bytes and holds `pid` at [`P_PID_OFFSET`] (otherwise the layout is not the one we know).
fn traced_from(kinfo: &[u8], pid: libc::pid_t) -> Option<bool> {
    if kinfo.len() < KINFO_PROC_SIZE {
        return None;
    }
    let int_at = |offset: usize| kinfo.get(offset..offset + 4)?.try_into().ok().map(i32::from_ne_bytes);
    let (flag, own_pid) = (int_at(P_FLAG_OFFSET)?, int_at(P_PID_OFFSET)?);
    (own_pid == pid).then_some(flag & P_TRACED != 0)
}

/// A random hidden name for the `root.write` probe ("." and 16 hex digits); `None` when the system RNG fails (the
/// probe is skipped).
fn probe_file_name() -> Option<String> {
    let mut bytes = [0u8; 8];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(format!(".{:016x}", u64::from_be_bytes(bytes)))
}

/// The bytes of the C string at `ptr`, at most `max` of them (no terminator found within `max`: the first `max`).
///
/// # Safety
///
/// `ptr` is non-NULL and points to a NUL-terminated string, or to at least `max` readable bytes, valid for `'a`.
unsafe fn c_bytes<'a>(ptr: *const c_char, max: usize) -> &'a [u8] {
    // SAFETY: by the caller's contract strnlen reads at most max bytes, all readable, and stops at the terminator.
    let len = unsafe { libc::strnlen(ptr, max) };
    // SAFETY: the len bytes just measured are readable for 'a; u8 has no alignment requirement.
    unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }
}

/// Whether a `getenv` result is set and non-empty.
///
/// # Safety
///
/// `value` is NULL or points to a readable byte.
unsafe fn non_empty(value: *const c_char) -> bool {
    // SAFETY: value is not NULL here, and by the caller's contract its first byte is readable.
    !value.is_null() && unsafe { *value } != 0
}

#[cfg(test)]
mod tests;
