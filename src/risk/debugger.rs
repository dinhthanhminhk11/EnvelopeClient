//! Debugger detection (heavy flag `debugger`): a non-zero `TracerPid` in /proc/self/status or in the status of any of
//! our threads (a native debugger or strace can attach to a single thread). We never call ptrace on ourselves: that
//! changes process state, can break crash reporters and is the first thing anti-anti-debug tools patch.

use obfstr::obfstring as s;

use crate::sys;

/// `TracerPid:\t<pid>` from a status file; `None` when the line is missing.
pub fn tracer_pid(status: &str) -> Option<u32> {
    let key = s!("TracerPid:");
    status.lines().find_map(|line| line.strip_prefix(key.as_str())).and_then(|value| value.trim().parse().ok())
}

/// `debugger.tracer`
pub fn traced() -> bool {
    let traced = |path: &str| sys::read_text(path).and_then(|text| tracer_pid(&text)).is_some_and(|pid| pid != 0);
    if traced(&s!("/proc/self/status")) {
        return true;
    }
    let task_dir = s!("/proc/self/task");
    sys::list_dir(&task_dir)
        .unwrap_or_default()
        .iter()
        .filter(|tid| tid.bytes().all(|b| b.is_ascii_digit()))
        .take(1024)
        .any(|tid| traced(&format!("{task_dir}/{tid}/status")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture_text;

    #[test]
    fn parses_tracer_pid() {
        assert_eq!(tracer_pid(&fixture_text("proc/status_clean.txt")), Some(0));
        assert_eq!(tracer_pid(&fixture_text("proc/status_traced.txt")), Some(14_221));
        assert_eq!(tracer_pid("Name:\tx\n"), None);
    }
}
