//! Minimal ELF program-header reader (ELF32 for armeabi-v7a, ELF64 otherwise), enough to map a loaded library's
//! read-only PT_LOAD segments back to file offsets.

use crate::apk_identity::ReadAt;

pub const PT_LOAD: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_X: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub flags: u32,
}

/// PT_LOAD segments of the ELF image starting at `base` in `reader`.
pub fn load_segments<R: ReadAt + ?Sized>(reader: &R, base: u64) -> Option<Vec<LoadSegment>> {
    let mut header = [0u8; 64];
    if !reader.read_at(&mut header[..52], base) {
        return None;
    }
    if &header[..4] != b"\x7fELF" || header[5] != 1 {
        return None; // not ELF or not little-endian
    }
    let is64 = match header[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    if is64 && !reader.read_at(&mut header, base) {
        return None;
    }
    let le16 = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    let le32 = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap_or([0; 4]));
    let le64 = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap_or([0; 8]));
    let (phoff, phentsize, phnum) = if is64 {
        (le64(32), usize::from(le16(54)), usize::from(le16(56)))
    } else {
        (u64::from(le32(28)), usize::from(le16(42)), usize::from(le16(44)))
    };
    let expected_entsize = if is64 { 56 } else { 32 };
    if phentsize != expected_entsize || phnum == 0 || phnum > 64 {
        return None;
    }
    let mut table = vec![0u8; phentsize * phnum];
    if !reader.read_at(&mut table, base.checked_add(phoff)?) {
        return None;
    }
    let mut segments = Vec::new();
    for entry in table.chunks_exact(phentsize) {
        let r32 = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap_or([0; 4]));
        let r64 = |at: usize| u64::from_le_bytes(entry[at..at + 8].try_into().unwrap_or([0; 8]));
        if r32(0) != PT_LOAD {
            continue;
        }
        segments.push(if is64 {
            LoadSegment { flags: r32(4), offset: r64(8), vaddr: r64(16), filesz: r64(32) }
        } else {
            LoadSegment {
                offset: u64::from(r32(4)),
                vaddr: u64::from(r32(8)),
                filesz: u64::from(r32(16)),
                flags: r32(24),
            }
        });
    }
    (!segments.is_empty()).then_some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built ELF64 header with two PT_LOAD entries.
    #[test]
    fn parses_elf64_program_headers() {
        let mut image = vec![0u8; 64 + 2 * 56];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (index, (flags, offset, vaddr, filesz)) in
            [(5u32, 0u64, 0u64, 0x1000u64), (6, 0x4000, 0x8000, 0x200)].into_iter().enumerate()
        {
            let at = 64 + index * 56;
            image[at..at + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            image[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            image[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            image[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
        }
        let segments = load_segments(image.as_slice(), 0).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[1], LoadSegment { vaddr: 0x8000, offset: 0x4000, filesz: 0x200, flags: 6 });
        assert!(load_segments(&b"MZ"[..], 0).is_none());
    }
}
