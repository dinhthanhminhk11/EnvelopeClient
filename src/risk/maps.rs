//! /proc/self/maps parsing.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapEntry<'a> {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub private: bool,
    pub offset: u64,
    /// "" for anonymous mappings; may contain spaces ("[anon:dalvik-main space]", "/memfd:x (deleted)").
    pub path: &'a str,
}

impl MapEntry<'_> {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }

    /// Backed by a real file path (not anonymous, not a kernel pseudo-mapping, not memfd).
    pub fn is_file_backed(&self) -> bool {
        self.path.starts_with('/') && !self.path.starts_with("/memfd:") && !self.path.starts_with("/dev/ashmem")
    }

    /// The part of the path worth matching tokens against: for installed apps only the file name, because the
    /// /data/app/~~<random>==/<pkg>-<random>==/ directories are random base64 and can contain any short token.
    pub fn match_target(&self) -> &str {
        if self.path.starts_with("/data/app/") || self.path.starts_with("/mnt/expand/") {
            self.path.rsplit('/').next().unwrap_or(self.path)
        } else {
            self.path
        }
    }
}

pub fn parse_line(line: &str) -> Option<MapEntry<'_>> {
    let mut rest = line.trim_end();
    let mut fields = [""; 5];
    for field in fields.iter_mut() {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        *field = &rest[..end];
        rest = &rest[end..];
    }
    let [range, perms, offset, _device, _inode] = fields;
    let (start, end) = range.split_once('-')?;
    let perms = perms.as_bytes();
    if perms.len() < 4 {
        return None;
    }
    Some(MapEntry {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        read: perms[0] == b'r',
        write: perms[1] == b'w',
        exec: perms[2] == b'x',
        private: perms[3] == b'p',
        offset: u64::from_str_radix(offset, 16).ok()?,
        path: rest.trim(),
    })
}

pub fn parse(maps: &str) -> Vec<MapEntry<'_>> {
    maps.lines().filter_map(parse_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines() {
        let entry = parse_line("7f9c1e2000-7f9c1e4000 r-xp 0001a000 fd:01 123456   /system/lib64/libc.so").unwrap();
        assert_eq!((entry.start, entry.end, entry.offset), (0x7f9c1e2000, 0x7f9c1e4000, 0x1a000));
        assert!(entry.read && !entry.write && entry.exec && entry.private);
        assert_eq!(entry.path, "/system/lib64/libc.so");

        let anon = parse_line("12c00000-2ac00000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space (region space)]").unwrap();
        assert_eq!(anon.path, "[anon:dalvik-main space (region space)]");
        assert!(!anon.is_file_backed());

        let empty = parse_line("7000000000-7000001000 ---p 00000000 00:00 0").unwrap();
        assert_eq!(empty.path, "");
        let memfd =
            parse_line("7100000000-7100100000 r-xp 00000000 00:05 4242 /memfd:frida-agent-64.so (deleted)").unwrap();
        assert_eq!(memfd.path, "/memfd:frida-agent-64.so (deleted)");
        assert!(!memfd.is_file_backed());
        assert!(parse_line("garbage").is_none());
    }

    #[test]
    fn match_target_hides_random_app_dirs() {
        let entry = parse_line("7000-8000 r--p 0 fd:01 1 /data/app/~~frida==/com.x-abc==/base.apk").unwrap();
        assert_eq!(entry.match_target(), "base.apk");
    }
}
