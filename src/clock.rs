//! Time sources.
//!
//! - Wall clock (ms since the Unix epoch) for the handshake `ts`, corrected by the last known server offset.
//! - A monotonic clock that keeps counting during deep sleep for request `ts` (CLOCK_BOOTTIME on Android/Linux,
//!   CLOCK_MONOTONIC on Apple): a session stamps requests with `serverTime + elapsed`, so a user changing the phone's
//!   clock cannot break it, and suspend does not make `ts` lag the server (and leave its 60 s request window).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// serverTime − local wall clock, learned from the last verified handshake (or a server time hint).
static SERVER_OFFSET_MS: AtomicI64 = AtomicI64::new(0);

pub fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0)
}

/// Wall clock shifted by the known server offset; never 0.
pub fn corrected_wall_ms() -> u64 {
    let corrected = wall_ms() as i64 + SERVER_OFFSET_MS.load(Ordering::Relaxed);
    corrected.max(1) as u64
}

/// Records `serverTime − wall` observed at local wall time `wall_at`.
pub fn learn_server_time(server_time: u64, wall_at: u64) {
    let offset = server_time as i64 - wall_at as i64;
    SERVER_OFFSET_MS.store(offset, Ordering::Relaxed);
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn mono_ms() -> u64 {
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime only writes the timespec we own.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) };
    if rc != 0 {
        return fallback_mono_ms();
    }
    (now.tv_sec as u64).saturating_mul(1000) + (now.tv_nsec as u64) / 1_000_000
}

/// Apple platforms (iOS, the Simulator, macOS for host tests). On Darwin CLOCK_MONOTONIC keeps counting while the
/// system is asleep (clock_gettime(3) of the CommandLineTools SDK), unlike Linux's CLOCK_MONOTONIC [đo: on an iPhone,
/// theme-x spec §7.3 #6 (lock the device > 60 s mid-session: the next request is not refused) and #7 (move the clock ±1 day:
/// X-Tx-Ts does not jump)]. Never `Instant`, `mach_absolute_time` or `systemUptime`: they are CLOCK_UPTIME_RAW, which
/// stops during sleep, so after every sleep longer than the server's 60 s window a live session's next request would be
/// refused as a replay.
#[cfg(target_vendor = "apple")]
pub fn mono_ms() -> u64 {
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime only writes the timespec we own.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    let elapsed = if rc != 0 {
        fallback_mono_ms()
    } else {
        (now.tv_sec as u64).saturating_mul(1000) + (now.tv_nsec as u64) / 1_000_000
    };
    elapsed.saturating_add(debug_offset_ms())
}

/// Debug Apple libraries only (C ABI `doodleart_debug_clock_advance_ms`, theme-x spec 2026-11-05 §7.1 "sleep > 60 s"): a forward
/// offset added to [`mono_ms`], so a Swift test can simulate time the device spent asleep. Never part of a release or
/// QA library (tools/c-abi-smoke.sh checks the exported symbols of both build types).
#[cfg(all(target_vendor = "apple", feature = "build-debug"))]
pub mod debug_clock {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Largest single advance: one week.
    pub const MAX_ADVANCE_MS: u64 = 7 * 24 * 3600 * 1000;

    /// Moves [`super::mono_ms`] forward by `ms` (at most [`MAX_ADVANCE_MS`], else `false`) for the rest of the
    /// process. It never goes back: a session sees what a device asleep for that long would show.
    pub fn advance(ms: u64) -> bool {
        if ms > MAX_ADVANCE_MS {
            return false;
        }
        storage::add(ms);
        true
    }

    pub fn offset_ms() -> u64 {
        storage::get()
    }

    /// The offset: a forward-only, saturating sum of every advance. The library keeps one per process; the unit tests
    /// one per thread (below), both through this type, so its arithmetic is tested as the library runs it.
    pub(crate) struct OffsetCell(AtomicU64);

    impl OffsetCell {
        pub(crate) const fn new() -> OffsetCell {
            OffsetCell(AtomicU64::new(0))
        }

        pub(crate) fn add(&self, ms: u64) {
            let _ = self.0.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |now| Some(now.saturating_add(ms)));
        }

        pub(crate) fn get(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[cfg(not(test))]
    mod storage {
        use super::OffsetCell;

        static OFFSET_MS: OffsetCell = OffsetCell::new();

        pub fn add(ms: u64) {
            OFFSET_MS.add(ms);
        }

        pub fn get() -> u64 {
            OFFSET_MS.get()
        }
    }

    /// Per thread in unit tests: they run in parallel in one process, and many of them read the clock.
    #[cfg(test)]
    mod storage {
        use super::OffsetCell;

        thread_local! {
            static OFFSET_MS: OffsetCell = const { OffsetCell::new() };
        }

        pub fn add(ms: u64) {
            OFFSET_MS.with(|offset| offset.add(ms));
        }

        pub fn get() -> u64 {
            OFFSET_MS.with(OffsetCell::get)
        }
    }
}

#[cfg(all(target_vendor = "apple", feature = "build-debug"))]
fn debug_offset_ms() -> u64 {
    debug_clock::offset_ms()
}

#[cfg(all(target_vendor = "apple", not(feature = "build-debug")))]
const fn debug_offset_ms() -> u64 {
    0
}

#[cfg(not(any(target_os = "android", target_os = "linux", target_vendor = "apple")))]
pub fn mono_ms() -> u64 {
    fallback_mono_ms()
}

/// Process-relative monotonic time: the only source on other platforms, and the answer if clock_gettime ever fails.
fn fallback_mono_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The OS clock behind [`mono_ms`] on this target: one that keeps counting while the device sleeps.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    const SLEEP_COUNTING_CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
    #[cfg(target_vendor = "apple")]
    const SLEEP_COUNTING_CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

    #[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
    fn os_clock_ms(clock: libc::clockid_t) -> u64 {
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: clock_gettime only writes the timespec we own.
        assert_eq!(unsafe { libc::clock_gettime(clock, &mut now) }, 0);
        now.tv_sec as u64 * 1000 + now.tv_nsec as u64 / 1_000_000
    }

    /// `mono_ms` is that clock, in ms: bracketed by two direct reads, every time. Rules out the Instant fallback (it
    /// starts near 0 in this process, the OS clock near the uptime) and, on a Mac whose CLOCK_UPTIME_RAW has drifted
    /// from CLOCK_MONOTONIC (sleep, NTP), a regression to `Instant` / mach_absolute_time.
    #[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn mono_ms_reads_the_sleep_counting_clock() {
        for _ in 0..1000 {
            let before = os_clock_ms(SLEEP_COUNTING_CLOCK);
            let mono = mono_ms();
            let after = os_clock_ms(SLEEP_COUNTING_CLOCK);
            assert!(before <= mono && mono <= after, "{before} <= {mono} <= {after}");
        }
    }

    #[test]
    fn mono_ms_is_monotonic_and_follows_real_time() {
        let mut last = mono_ms();
        for _ in 0..10_000 {
            let now = mono_ms();
            assert!(now >= last, "{now} < {last}");
            last = now;
        }
        let start = mono_ms();
        std::thread::sleep(Duration::from_millis(50));
        let elapsed = mono_ms() - start;
        assert!((45..5_000).contains(&elapsed), "slept 50 ms, clock moved {elapsed} ms");
    }

    /// The debug clock hook moves `mono_ms` forward by exactly the advance, never back, and refuses more than a week.
    #[cfg(all(target_vendor = "apple", feature = "build-debug"))]
    #[test]
    fn debug_clock_moves_mono_ms_forward() {
        let before = os_clock_ms(SLEEP_COUNTING_CLOCK);
        assert!(debug_clock::advance(70_000));
        assert!(debug_clock::advance(0));
        assert!(!debug_clock::advance(debug_clock::MAX_ADVANCE_MS + 1));
        assert!(debug_clock::advance(debug_clock::MAX_ADVANCE_MS));
        let advanced = 70_000 + debug_clock::MAX_ADVANCE_MS;
        let mono = mono_ms();
        let after = os_clock_ms(SLEEP_COUNTING_CLOCK);
        assert!(before + advanced <= mono && mono <= after + advanced, "{before} + {advanced} <= {mono} <= {after}");
        assert_eq!(debug_clock::offset_ms(), advanced);
        // Unit tests keep the offset per thread (the hook's own storage is process-wide).
        let other = std::thread::spawn(|| (os_clock_ms(SLEEP_COUNTING_CLOCK), mono_ms())).join().unwrap();
        assert!(other.1 < other.0 + 1_000, "{other:?}");
    }

    /// The storage of the debug clock hook (process-wide in the library): advances add up, never wrap.
    #[cfg(all(target_vendor = "apple", feature = "build-debug"))]
    #[test]
    fn offset_cell_accumulates_and_saturates() {
        let cell = debug_clock::OffsetCell::new();
        assert_eq!(cell.get(), 0);
        cell.add(70_000);
        cell.add(70_000);
        assert_eq!(cell.get(), 140_000);
        cell.add(0);
        assert_eq!(cell.get(), 140_000);
        cell.add(u64::MAX);
        assert_eq!(cell.get(), u64::MAX);
        cell.add(1);
        assert_eq!(cell.get(), u64::MAX);
    }

    #[test]
    fn fallback_is_monotonic_and_follows_real_time() {
        let start = fallback_mono_ms();
        std::thread::sleep(Duration::from_millis(30));
        let elapsed = fallback_mono_ms() - start;
        assert!((25..5_000).contains(&elapsed), "slept 30 ms, fallback moved {elapsed} ms");
    }
}
