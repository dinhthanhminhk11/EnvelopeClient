//! Hook detection (heavy flag `hook`).
//!
//! - `hook.text`: the read-only PT_LOAD segments (.text, .rodata, …) of libdoodleart_core.so in memory differ from the
//!   same bytes in the file it was loaded from (plain .so or `base.apk!/lib/<abi>/…`). The linker never writes those
//!   segments (no TEXTREL on API ≥ 23), so any difference is a patch: inline hook, breakpoint, or edited constants
//!   such as the embedded server keys. File, image offset and load bias all come from the /proc/self/maps entry
//!   holding our code (read with raw syscalls) and the file itself, never from `dladdr`, which lives in the linker
//!   and is trivially hooked to make the check skip. Because the reference is the file, a patch applied before
//!   JNI_OnLoad (spawn-mode Frida in `android_dlopen_ext`'s onLeave) is caught as well.
//! - `hook.prologue`: the first 32 bytes of our JNI entry points changed since JNI_OnLoad (a cheap RAM baseline for
//!   hooks installed after load, when the file comparison cannot run).
//! - `hook.rwx`: a file-backed mapping of a system library or of our own library is writable and executable at the
//!   same time: text patched in place without restoring protections. Anonymous rwx memory is NOT flagged: ART's JIT
//!   on older releases, WebView/V8 and ad SDK runtimes use it legitimately.
//! - `hook.xposed`: Xposed / LSPosed / EdXposed / Riru / SandHook files mapped into the process, or XposedBridge on
//!   the CLASSPATH.
//!
//! libc / libart prologues are deliberately not checked: SDKs bundled with the app (APM, ads) inline-hook libc with
//! the same trampolines Frida uses, so that check would flag real users. Frida itself is covered by `risk::frida`.

use std::sync::OnceLock;

use obfstr::obfstring as s;

use super::elf::{self, LoadSegment, PF_W, PF_X};
use super::maps::MapEntry;
use crate::apk_identity::{self, FileReader, ReadAt};
use crate::sys;

const PROLOGUE_BYTES: usize = 32;
const COMPARE_CHUNK: usize = 64 * 1024;

static PROLOGUE_BASELINE: OnceLock<Vec<(usize, [u8; PROLOGUE_BYTES])>> = OnceLock::new();

fn is_system_library_path(path: &str) -> bool {
    ["/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/odm/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// `hook.rwx`
pub fn rwx_file_mapping(entries: &[MapEntry<'_>], own_map_path: Option<&str>) -> bool {
    entries.iter().any(|entry| {
        entry.read
            && entry.write
            && entry.exec
            && entry.is_file_backed()
            && (is_system_library_path(entry.path) || own_map_path.is_some_and(|own| entry.path == own))
    })
}

/// `hook.xposed`
pub fn xposed_trace(entries: &[MapEntry<'_>], classpath: &str) -> bool {
    let tokens = [
        s!("XposedBridge"),
        s!("liblspd"),
        s!("/lspd/"),
        s!("LSPosed"),
        s!("libriru"),
        s!("/riru/"),
        s!("edxp"),
        s!("libsandhook"),
        s!("libxposed"),
    ];
    let xposed_bridge = s!("XposedBridge");
    classpath.contains(xposed_bridge.as_str())
        || entries.iter().any(|entry| {
            let target = entry.match_target();
            tokens.iter().any(|token| target.contains(token.as_str()))
        })
}

/// Code address of a function: clears the Thumb bit on 32-bit ARM.
pub fn code_address(function: usize) -> usize {
    if cfg!(target_arch = "arm") {
        function & !1
    } else {
        function
    }
}

/// Records the prologues of `functions` (JNI_OnLoad). Later calls are ignored.
pub fn record_prologues(functions: &[usize]) {
    let _ = PROLOGUE_BASELINE.get_or_init(|| {
        functions
            .iter()
            .filter_map(|function| {
                let address = code_address(*function);
                let mut bytes = [0u8; PROLOGUE_BYTES];
                sys::read_own_memory(address, &mut bytes).then_some((address, bytes))
            })
            .collect()
    });
}

/// `hook.prologue`: `None` when no baseline was recorded (host tests, JNI_OnLoad not run).
pub fn prologues_changed() -> Option<bool> {
    let baseline = PROLOGUE_BASELINE.get().filter(|baseline| !baseline.is_empty())?;
    Some(baseline.iter().any(|(address, expected)| {
        let mut now = [0u8; PROLOGUE_BYTES];
        sys::read_own_memory(*address, &mut now) && now != *expected
    }))
}

/// An address inside our own code: the anchor for finding the mapping and image we were loaded from.
fn own_anchor() -> u64 {
    code_address(own_code_changed as fn(&[MapEntry<'_>]) -> Option<bool> as usize) as u64
}

/// The /proc/self/maps path of the mapping that contains `address`.
pub fn map_path_containing<'a>(entries: &[MapEntry<'a>], address: u64) -> Option<&'a str> {
    entries.iter().find(|entry| entry.contains(address)).map(|entry| entry.path).filter(|path| !path.is_empty())
}

/// The /proc/self/maps path backing our own code (the .so, or the APK it is loaded from).
pub fn own_map_path<'a>(entries: &[MapEntry<'a>]) -> Option<&'a str> {
    map_path_containing(entries, own_anchor())
}

/// Load bias of an ELF image whose PT_LOAD `segments` start at `image_offset` in the file mapped by `entry`, located
/// through `anchor`, a code address inside `entry`: the anchor's file offset must fall in an executable segment.
fn load_bias(entry: &MapEntry<'_>, image_offset: u64, segments: &[LoadSegment], anchor: u64) -> Option<u64> {
    if !entry.contains(anchor) {
        return None;
    }
    let anchor_file = entry.offset.checked_add(anchor - entry.start)?.checked_sub(image_offset)?;
    let segment = segments
        .iter()
        .find(|segment| segment.offset <= anchor_file && anchor_file - segment.offset < segment.filesz)?;
    if segment.flags & PF_X == 0 {
        return None;
    }
    anchor.checked_sub(segment.vaddr.checked_add(anchor_file - segment.offset)?)
}

/// `hook.text`: `Some(true)` when a read-only segment of our library differs from its file, `None` when the
/// comparison could not run (code not mapped from a readable file, not ELF, memory not readable).
pub fn own_code_changed(entries: &[MapEntry<'_>]) -> Option<bool> {
    let anchor = own_anchor();
    let entry = entries.iter().find(|entry| entry.contains(anchor)).filter(|entry| entry.is_file_backed())?;
    let reader = FileReader::open(entry.path)?;
    // Inside an APK the image is a stored entry: find it from the mapping's file offset, without trusting names.
    let image_offset =
        if entry.path.ends_with(".apk") { apk_identity::stored_entry_containing(&reader, entry.offset)? } else { 0 };
    let segments = elf::load_segments(&reader, image_offset)?;
    let bias = load_bias(entry, image_offset, &segments, anchor)?;

    let mut memory = vec![0u8; COMPARE_CHUNK];
    let mut file = vec![0u8; COMPARE_CHUNK];
    for segment in segments.iter().filter(|segment| segment.flags & PF_W == 0 && segment.filesz > 0) {
        let mut done = 0u64;
        while done < segment.filesz {
            let length = (segment.filesz - done).min(COMPARE_CHUNK as u64) as usize;
            let address = usize::try_from(bias.checked_add(segment.vaddr + done)?).ok()?;
            if !sys::read_own_memory(address, &mut memory[..length]) {
                return None;
            }
            if !reader.read_at(&mut file[..length], image_offset + segment.offset + done) {
                return None;
            }
            if memory[..length] != file[..length] {
                return Some(true);
            }
            done += length as u64;
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::super::maps;
    use super::*;
    use crate::test_support::fixture_text;

    #[test]
    fn clean_maps_have_no_hook_trace() {
        let text = fixture_text("proc/maps_clean.txt");
        let entries = maps::parse(&text);
        assert!(!rwx_file_mapping(&entries, Some("/data/app/x/base.apk")));
        assert!(!xposed_trace(&entries, "/system/framework/framework.jar"));
    }

    #[test]
    fn hooked_maps_are_found() {
        let text = fixture_text("proc/maps_hooked.txt");
        let entries = maps::parse(&text);
        assert!(rwx_file_mapping(&entries, None));
        assert!(xposed_trace(&entries, ""));
        assert!(xposed_trace(&[], "/data/local/tmp/XposedBridge.jar"));
    }

    #[test]
    fn anonymous_rwx_is_not_a_hook() {
        let text = "7000000000-7000100000 rwxp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n\
                    7100000000-7100100000 rwxp 00000000 00:00 0\n\
                    7200000000-7200100000 rwxp 00000000 00:05 12 /memfd:jit-cache (deleted)\n";
        assert!(!rwx_file_mapping(&maps::parse(text), None));
    }

    #[test]
    fn thumb_bit_cleared_only_on_arm() {
        let expected = if cfg!(target_arch = "arm") { 0x1000 } else { 0x1001 };
        assert_eq!(code_address(0x1001), expected);
    }

    #[test]
    fn host_checks_never_panic() {
        // On the macOS host there is no /proc/self/maps and the image is Mach-O: no verdict, no flag.
        assert_eq!(own_code_changed(&[]), None);
        assert_eq!(prologues_changed(), None);
    }

    /// Bias from the maps entry of a library loaded from split_config.arm64_v8a.apk (fixture maps_clean.txt): image
    /// stored at 0x4000 in the APK, text segment at file/vaddr 0xb8000.
    #[test]
    fn load_bias_from_maps_entry() {
        let text = fixture_text("proc/maps_clean.txt");
        let entries = maps::parse(&text);
        let entry =
            entries.iter().find(|entry| entry.exec && entry.path.ends_with("split_config.arm64_v8a.apk")).unwrap();
        let segments = [
            LoadSegment { vaddr: 0, offset: 0, filesz: 0xb7000, flags: 4 },
            LoadSegment { vaddr: 0xb8000, offset: 0xb8000, filesz: 0x108000, flags: 5 },
            LoadSegment { vaddr: 0x1c4000, offset: 0x1c0000, filesz: 0x14000, flags: 6 },
        ];
        let anchor = entry.start + 0x10;
        let bias = load_bias(entry, 0x4000, &segments, anchor).unwrap();
        assert_eq!(bias, 0x7b_4104_0000, "the first segment lands on the r--p mapping at file offset 0x4000");
        assert_eq!(bias + segments[1].vaddr, entry.start);

        // The anchor's file offset is in a non-executable segment, or in no segment: no bias, no comparison.
        let shifted = [segments[0], LoadSegment { flags: 4, ..segments[1] }, segments[2]];
        assert_eq!(load_bias(entry, 0x4000, &shifted, anchor), None);
        assert_eq!(load_bias(entry, 0x4000, &segments[..1], anchor), None);
        assert_eq!(load_bias(entry, 0x4000, &segments, entry.end), None, "anchor outside the entry");
        assert_eq!(load_bias(entry, entry.offset + 0x11, &segments, anchor), None, "image starts after the anchor");
    }

    #[test]
    fn map_path_lookup() {
        let text = fixture_text("proc/maps_clean.txt");
        let entries = maps::parse(&text);
        assert!(map_path_containing(&entries, 0x7b_5c47_c000).unwrap().ends_with("/libc.so"));
        assert_eq!(map_path_containing(&entries, 0x7b_d0f5_d000), Some("[vdso]"));
        assert_eq!(map_path_containing(&entries, 0x10), None);
    }
}
