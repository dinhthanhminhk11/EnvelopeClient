//! File access for the risk and identity checks through raw syscalls (`svc` / `syscall` via the `syscalls` crate),
//! so libc wrappers patched by Frida or an inline hooking framework (`open`, `read`, `fopen`…) do not see or filter
//! what we read. On the host (macOS tests) it falls back to std, which is only used by unit tests.

use std::ffi::CString;

/// Upper bound for whole-file reads (/proc text files, maps of big processes are well below this).
pub const MAX_TEXT_FILE: usize = 8 * 1024 * 1024;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod imp {
    use std::ffi::CStr;

    use syscalls::{syscall, Sysno};

    const AT_FDCWD: isize = -100;
    const O_RDONLY: usize = 0;
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    const O_CLOEXEC: usize = 0o2000000;
    #[cfg(target_arch = "arm")]
    const O_CLOEXEC: usize = 0o2000000;
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    const O_DIRECTORY: usize = 0o40000;
    #[cfg(target_arch = "x86_64")]
    const O_DIRECTORY: usize = 0o200000;
    const F_OK: usize = 0;

    pub struct Fd(usize);

    impl Fd {
        pub fn open(path: &CStr) -> Option<Fd> {
            Self::open_flags(path, O_RDONLY | O_CLOEXEC)
        }

        pub fn open_dir(path: &CStr) -> Option<Fd> {
            Self::open_flags(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY)
        }

        fn open_flags(path: &CStr, flags: usize) -> Option<Fd> {
            // SAFETY: path is NUL-terminated and outlives the call.
            unsafe { syscall!(Sysno::openat, AT_FDCWD, path.as_ptr(), flags, 0) }.ok().map(Fd)
        }

        pub fn read(&self, buf: &mut [u8]) -> Option<usize> {
            // SAFETY: the kernel writes at most buf.len() bytes into buf.
            unsafe { syscall!(Sysno::read, self.0, buf.as_mut_ptr(), buf.len()) }.ok()
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        pub fn pread(&self, buf: &mut [u8], offset: u64) -> Option<usize> {
            // SAFETY: as read; offset is passed by value.
            unsafe { syscall!(Sysno::pread64, self.0, buf.as_mut_ptr(), buf.len(), offset) }.ok()
        }

        /// ARM EABI passes the 64-bit offset in an aligned register pair (r4:r5) after a padding argument.
        #[cfg(target_arch = "arm")]
        pub fn pread(&self, buf: &mut [u8], offset: u64) -> Option<usize> {
            let (low, high) = (offset as u32 as usize, (offset >> 32) as usize);
            // SAFETY: as read; arguments follow the EABI layout of pread64.
            unsafe { syscall!(Sysno::pread64, self.0, buf.as_mut_ptr(), buf.len(), 0, low, high) }.ok()
        }

        /// Raw `linux_dirent64` records.
        pub fn getdents(&self, buf: &mut [u8]) -> Option<usize> {
            // SAFETY: the kernel writes at most buf.len() bytes into buf.
            unsafe { syscall!(Sysno::getdents64, self.0, buf.as_mut_ptr(), buf.len()) }.ok()
        }
    }

    impl Drop for Fd {
        fn drop(&mut self) {
            // SAFETY: we own this descriptor.
            let _ = unsafe { syscall!(Sysno::close, self.0) };
        }
    }

    pub fn exists(path: &CStr) -> bool {
        // SAFETY: path is NUL-terminated.
        unsafe { syscall!(Sysno::faccessat, AT_FDCWD, path.as_ptr(), F_OK, 0) }.is_ok()
    }

    pub fn readlink(path: &CStr, buf: &mut [u8]) -> Option<usize> {
        // SAFETY: the kernel writes at most buf.len() bytes into buf.
        unsafe { syscall!(Sysno::readlinkat, AT_FDCWD, path.as_ptr(), buf.as_mut_ptr(), buf.len()) }.ok()
    }

    pub fn getpid() -> usize {
        // SAFETY: no arguments, no memory access.
        unsafe { syscall!(Sysno::getpid) }.unwrap_or(0)
    }

    /// Copies `out.len()` bytes at `address` of our own process with `process_vm_readv`, which fails cleanly
    /// (EFAULT) instead of faulting when the page is not readable.
    pub fn read_own_memory(address: usize, out: &mut [u8]) -> bool {
        #[repr(C)]
        struct IoVec {
            base: usize,
            len: usize,
        }
        let local = IoVec { base: out.as_mut_ptr() as usize, len: out.len() };
        let remote = IoVec { base: address, len: out.len() };
        // SAFETY: both iovecs describe valid ranges for the call; the kernel checks the remote one.
        let copied = unsafe {
            syscall!(Sysno::process_vm_readv, getpid(), &local as *const IoVec, 1, &remote as *const IoVec, 1, 0)
        };
        copied == Ok(out.len())
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod imp {
    //! Host fallback for unit tests only.
    use std::ffi::CStr;
    use std::fs::File;
    use std::io::Read;

    pub struct Fd(File);

    impl Fd {
        pub fn open(path: &CStr) -> Option<Fd> {
            File::open(path.to_str().ok()?).ok().map(Fd)
        }

        pub fn open_dir(_path: &CStr) -> Option<Fd> {
            None
        }

        pub fn read(&self, buf: &mut [u8]) -> Option<usize> {
            (&self.0).read(buf).ok()
        }

        pub fn pread(&self, buf: &mut [u8], offset: u64) -> Option<usize> {
            std::os::unix::fs::FileExt::read_at(&self.0, buf, offset).ok()
        }

        pub fn getdents(&self, _buf: &mut [u8]) -> Option<usize> {
            None
        }
    }

    pub fn exists(path: &CStr) -> bool {
        path.to_str().is_ok_and(|path| std::path::Path::new(path).exists())
    }

    pub fn readlink(path: &CStr, buf: &mut [u8]) -> Option<usize> {
        let target = std::fs::read_link(path.to_str().ok()?).ok()?;
        let bytes = target.to_str()?.as_bytes();
        let length = bytes.len().min(buf.len());
        buf[..length].copy_from_slice(&bytes[..length]);
        Some(length)
    }

    pub fn read_own_memory(_address: usize, _out: &mut [u8]) -> bool {
        false
    }
}

pub use imp::Fd;

fn c_path(path: &str) -> Option<CString> {
    CString::new(path).ok()
}

pub fn open(path: &str) -> Option<Fd> {
    Fd::open(&c_path(path)?)
}

/// Whole file (up to `max` bytes) read with raw syscalls; works for /proc files whose size is reported as 0.
pub fn read_file(path: &str, max: usize) -> Option<Vec<u8>> {
    let fd = open(path)?;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = fd.read(&mut chunk)?;
        if read == 0 {
            return Some(out);
        }
        out.extend_from_slice(&chunk[..read]);
        if out.len() >= max {
            out.truncate(max);
            return Some(out);
        }
    }
}

pub fn read_text(path: &str) -> Option<String> {
    read_file(path, MAX_TEXT_FILE).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads exactly `out.len()` bytes at `offset`, retrying short reads.
pub fn pread_exact(fd: &Fd, out: &mut [u8], offset: u64) -> bool {
    let mut done = 0;
    while done < out.len() {
        match fd.pread(&mut out[done..], offset + done as u64) {
            Some(0) | None => return false,
            Some(read) => done += read,
        }
    }
    true
}

/// True only when the path is accessible (faccessat F_OK succeeds); EACCES and ENOENT both read as false.
pub fn exists(path: &str) -> bool {
    c_path(path).is_some_and(|path| imp::exists(&path))
}

pub fn readlink(path: &str) -> Option<String> {
    let path = c_path(path)?;
    let mut buf = vec![0u8; 4096];
    let length = imp::readlink(&path, &mut buf)?;
    Some(String::from_utf8_lossy(&buf[..length]).into_owned())
}

/// Entry names of a directory (without "." and ".."), via getdents64.
pub fn list_dir(path: &str) -> Option<Vec<String>> {
    let fd = Fd::open_dir(&c_path(path)?)?;
    let mut names = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read = fd.getdents(&mut buf)?;
        if read == 0 {
            return Some(names);
        }
        parse_dirents(&buf[..read], &mut names);
        if names.len() > 65_536 {
            return Some(names);
        }
    }
}

/// `struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }`
fn parse_dirents(mut records: &[u8], names: &mut Vec<String>) {
    const NAME_OFFSET: usize = 19;
    while records.len() >= NAME_OFFSET {
        let reclen = usize::from(u16::from_ne_bytes([records[16], records[17]]));
        if reclen < NAME_OFFSET || reclen > records.len() {
            return;
        }
        let raw = &records[NAME_OFFSET..reclen];
        let name = &raw[..raw.iter().position(|b| *b == 0).unwrap_or(raw.len())];
        if name != b"." && name != b".." {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
        records = &records[reclen..];
    }
}

pub use imp::read_own_memory;

/// System property value ("" when unset). `__system_property_get` exists on every API level (the callback API is
/// API 26+, above our minSdk 24); values we read are far below PROP_VALUE_MAX.
#[cfg(target_os = "android")]
pub fn property(name: &str) -> String {
    const PROP_VALUE_MAX: usize = 92;
    extern "C" {
        fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
    }
    let Some(name) = c_path(name) else { return String::new() };
    let mut value = [0u8; PROP_VALUE_MAX + 1];
    // SAFETY: value has room for PROP_VALUE_MAX bytes plus NUL, as the API requires.
    let length = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr().cast()) };
    let length = usize::try_from(length).unwrap_or(0).min(PROP_VALUE_MAX);
    String::from_utf8_lossy(&value[..length]).into_owned()
}

#[cfg(not(target_os = "android"))]
pub fn property(_name: &str) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirent_parsing() {
        let mut records = Vec::new();
        for name in [".", "..", "123", "comm"] {
            let reclen = (19 + name.len() + 1).div_ceil(8) * 8;
            let mut record = vec![0u8; reclen];
            record[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
            record[19..19 + name.len()].copy_from_slice(name.as_bytes());
            records.extend(record);
        }
        let mut names = Vec::new();
        parse_dirents(&records, &mut names);
        assert_eq!(names, vec!["123", "comm"]);
    }

    #[test]
    fn host_file_reads() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let bytes = read_file(path, MAX_TEXT_FILE).unwrap();
        assert!(bytes.starts_with(b"[package]"));
        let fd = open(path).unwrap();
        let mut head = [0u8; 9];
        assert!(pread_exact(&fd, &mut head, 0));
        assert_eq!(&head, b"[package]");
        assert!(exists(path));
        assert!(!exists("/definitely/not/here"));
    }
}
