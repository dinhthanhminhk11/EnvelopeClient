//! Frida detection (heavy flag `frida`). Each check targets something only an instrumented process has:
//!
//! - `frida.maps`: a mapping named after Frida's agent/gadget/injector (`frida-agent-64.so`, `frida-gadget`,
//!   `re.frida.server`, `linjector`). Matched case-sensitively, and only on the file name for /data/app paths, whose
//!   directories are random base64.
//! - `frida.threads`: Frida's own thread names (`gum-js-loop`, `pool-frida`, `frida-*`), or GLib's `gmain` together
//!   with `gdbus` (the agent's main loop and D-Bus threads; renamed builds usually keep them). Android apps do not
//!   embed GLib, so the pair alone is a strong signal.
//! - `frida.fds`: an open descriptor pointing into the injector's pipes / temp dir (`linjector-*`, `frida-*`). This
//!   replaces ai-car's directory listing of /data/local/tmp, which SELinux denies to apps (dead check).
//! - `frida.port`: something listening on 127.0.0.1:27042, frida-server's default port. No Android component uses it.
//!   Platform-neutral, so it lives in [`super::port`] (the Apple scan uses it too).
//! - `frida.memory`: Frida runtime strings (`frida:rpc`, `LIBFRIDA`, `gum-js-loop`) inside executable or read-only
//!   mappings that are anonymous, memfd-backed, deleted or under /data/local/tmp, i.e. injected code. Read with
//!   pread64 on /proc/self/mem (raw syscall). ai-car mmap'ed /proc/self/mem, which the kernel refuses: that check never
//!   ran. File-backed libraries of the app are not scanned, because security SDKs legitimately embed these strings to
//!   look for Frida themselves; JIT caches are skipped because they are large and never hold native strings.

use obfstr::obfstring as s;

use super::maps::MapEntry;
use crate::sys;

const MEMORY_SCAN_MAX_REGION: u64 = 16 * 1024 * 1024;
const MEMORY_SCAN_BUDGET: u64 = 64 * 1024 * 1024;
const MEMORY_SCAN_CHUNK: usize = 64 * 1024;

fn maps_tokens() -> [String; 4] {
    [s!("frida-agent"), s!("frida-gadget"), s!("re.frida.server"), s!("linjector")]
}

/// `frida.maps`
pub fn maps_trace(entries: &[MapEntry<'_>]) -> bool {
    let tokens = maps_tokens();
    entries.iter().any(|entry| {
        let target = entry.match_target();
        tokens.iter().any(|token| target.contains(token.as_str()))
    })
}

/// `frida.threads`
pub fn threads_trace(names: &[String]) -> bool {
    let specific = [s!("gum-js-loop"), s!("pool-frida"), s!("frida-")];
    if names.iter().any(|name| specific.iter().any(|token| name.contains(token.as_str()))) {
        return true;
    }
    let (gmain, gdbus) = (s!("gmain"), s!("gdbus"));
    names.iter().any(|name| name.trim() == gmain) && names.iter().any(|name| name.trim() == gdbus)
}

/// `frida.fds`
pub fn fds_trace(targets: &[String]) -> bool {
    let tokens = [s!("linjector"), s!("frida-"), s!("re.frida.server")];
    targets.iter().any(|target| tokens.iter().any(|token| target.contains(token.as_str())))
}

/// Mappings that may hold injected code: executable or read-only private memory that is not backed by a regular file
/// on a system or app path. JIT caches (`dalvik-jit-code-cache`, `jit-cache`) and our own library are excluded.
pub fn memory_scan_candidates<'a>(entries: &'a [MapEntry<'a>], own_lib_path: Option<&str>) -> Vec<&'a MapEntry<'a>> {
    let jit = [s!("jit-cache"), s!("jit-code-cache"), s!("dalvik-")];
    let mut budget = MEMORY_SCAN_BUDGET;
    let mut out = Vec::new();
    for entry in entries {
        if !entry.read || entry.write || entry.is_empty() || entry.len() > MEMORY_SCAN_MAX_REGION {
            continue;
        }
        if own_lib_path.is_some_and(|own| entry.path == own)
            || jit.iter().any(|token| entry.path.contains(token.as_str()))
        {
            continue;
        }
        let path = entry.path;
        let injected_like = path.is_empty()
            || path.starts_with("[anon:")
            || path.starts_with("/memfd:")
            || path.ends_with(" (deleted)")
            || path.starts_with("/data/local/tmp/");
        if !injected_like || entry.len() > budget {
            continue;
        }
        // Read-only anonymous data is common and big; only executable ones or named injections are worth the time.
        if !entry.exec && !path.starts_with("/memfd:") && !path.starts_with("/data/local/tmp/") {
            continue;
        }
        budget -= entry.len();
        out.push(entry);
    }
    out
}

pub fn memory_tokens() -> [String; 3] {
    [s!("frida:rpc"), s!("LIBFRIDA"), s!("gum-js-loop")]
}

pub fn contains_any(haystack: &[u8], tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        let needle = token.as_bytes();
        !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
    })
}

/// Scans candidate regions through /proc/self/mem (pread64 via raw syscall).
pub fn memory_trace(candidates: &[&MapEntry<'_>]) -> bool {
    if candidates.is_empty() {
        return false;
    }
    let Some(mem) = sys::open(&s!("/proc/self/mem")) else { return false };
    let tokens = memory_tokens();
    let overlap = tokens.iter().map(String::len).max().unwrap_or(0);
    let mut buf = vec![0u8; MEMORY_SCAN_CHUNK + overlap];
    for entry in candidates {
        let mut address = entry.start;
        let mut carried = 0usize;
        while address < entry.end {
            let want = (entry.end - address).min(MEMORY_SCAN_CHUNK as u64) as usize;
            let Some(read) = mem.pread(&mut buf[carried..carried + want], address) else { break };
            if read == 0 {
                break;
            }
            let filled = carried + read;
            if contains_any(&buf[..filled], &tokens) {
                return true;
            }
            // Keep the tail so a token split across two chunks is still found.
            carried = overlap.min(filled);
            buf.copy_within(filled - carried..filled, 0);
            address += read as u64;
        }
    }
    false
}

/// Comm names of every thread of this process.
pub fn thread_names() -> Vec<String> {
    let task_dir = s!("/proc/self/task");
    let Some(tids) = sys::list_dir(&task_dir) else { return Vec::new() };
    tids.iter()
        .filter(|tid| tid.bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|tid| sys::read_file(&format!("{task_dir}/{tid}/comm"), 64))
        .map(|bytes| String::from_utf8_lossy(&bytes).trim_end().to_owned())
        .collect()
}

/// Link targets of every open descriptor.
pub fn fd_targets() -> Vec<String> {
    let fd_dir = s!("/proc/self/fd");
    let Some(fds) = sys::list_dir(&fd_dir) else { return Vec::new() };
    fds.iter().take(4096).filter_map(|fd| sys::readlink(&format!("{fd_dir}/{fd}"))).collect()
}

#[cfg(test)]
mod tests {
    use super::super::maps;
    use super::*;
    use crate::test_support::fixture_text;

    #[test]
    fn clean_process_has_no_trace() {
        let text = fixture_text("proc/maps_clean.txt");
        let entries = maps::parse(&text);
        assert!(entries.len() > 20);
        assert!(!maps_trace(&entries));
        let names: Vec<String> = fixture_text("proc/threads_clean.txt").lines().map(str::to_owned).collect();
        assert!(!threads_trace(&names));
        let fds: Vec<String> = fixture_text("proc/fds_clean.txt").lines().map(str::to_owned).collect();
        assert!(!fds_trace(&fds));
    }

    #[test]
    fn frida_traces_are_found() {
        let text = fixture_text("proc/maps_frida.txt");
        let entries = maps::parse(&text);
        assert!(maps_trace(&entries));
        let names: Vec<String> = fixture_text("proc/threads_frida.txt").lines().map(str::to_owned).collect();
        assert!(threads_trace(&names));
        assert!(fds_trace(&["/data/local/tmp/frida-6c2b1/linjector-3".to_owned()]));
        // Renamed agent: only gmain + gdbus remain, still a trace; one of them alone is not.
        assert!(threads_trace(&["main".into(), "gmain".into(), "gdbus".into()]));
        assert!(!threads_trace(&["main".into(), "gmain".into()]));
    }

    #[test]
    fn random_app_dir_names_do_not_match() {
        let line = "7000-8000 r--p 0 fd:01 1 /data/app/~~frida-agentAb==/com.x-linjectorQ==/base.apk";
        assert!(!maps_trace(&maps::parse(line)));
    }

    #[test]
    fn memory_candidates_skip_jit_system_and_own_lib() {
        let text = fixture_text("proc/maps_frida.txt");
        let entries = maps::parse(&text);
        let candidates = memory_scan_candidates(
            &entries,
            Some("/data/app/~~Xq3kQ9cPZbVQnT0yUj2w3A==/com.cem.theme.icon.widget-Lr8m1sV2cQhPq0ZbX7dJ_A==/base.apk"),
        );
        assert!(!candidates.is_empty());
        for entry in &candidates {
            assert!(
                !entry.path.contains("jit-cache")
                    && !entry.path.starts_with("/system/")
                    && !entry.path.starts_with("/apex/")
            );
            assert!(!entry.write);
        }
        assert!(candidates.iter().any(|entry| entry.path.starts_with("/memfd:")));
        let clean = fixture_text("proc/maps_clean.txt");
        let clean_entries = maps::parse(&clean);
        assert!(memory_scan_candidates(&clean_entries, None)
            .iter()
            .all(|entry| entry.exec || entry.path.starts_with("/memfd:")));
    }

    #[test]
    fn token_search_handles_boundaries() {
        let tokens = memory_tokens();
        assert!(contains_any(b"xxxxfrida:rpcyyyy", &tokens));
        assert!(!contains_any(b"frida rpc LIBFRID", &tokens));
    }
}
