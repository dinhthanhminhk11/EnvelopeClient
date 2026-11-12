//! gzip (RFC 1952) decoding of sealed responses sent with `X-Tx-Encoding: gzip` (server/docs/app-security.md section
//! 5): the server compresses the plaintext before it seals it and moves the encoding into the authenticated
//! `X-Tx-Encoding`, so HTTP clients never try to gunzip the ciphertext. Only runs on a plaintext that already opened
//! under the session key: the input is the server's own, the output size limit only guards against a bug.

use crate::error::{Error, Result};

const MAGIC: [u8; 2] = [0x1f, 0x8b];
const METHOD_DEFLATE: u8 = 8;
const FLAG_HCRC: u8 = 0x02;
const FLAG_EXTRA: u8 = 0x04;
const FLAG_NAME: u8 = 0x08;
const FLAG_COMMENT: u8 = 0x10;
const FLAG_RESERVED: u8 = 0xe0;
const HEADER_BYTES: usize = 10;
const TRAILER_BYTES: usize = 8;

/// Decodes one gzip member into at most `limit` bytes; the CRC-32 and size of the trailer must match.
pub fn decode(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    if data.len() < HEADER_BYTES + TRAILER_BYTES || data[..2] != MAGIC || data[2] != METHOD_DEFLATE {
        return Err(Error::DecryptFailed);
    }
    let flags = data[3];
    if flags & FLAG_RESERVED != 0 {
        return Err(Error::DecryptFailed);
    }
    let end = data.len() - TRAILER_BYTES;
    let mut at = HEADER_BYTES;
    if flags & FLAG_EXTRA != 0 {
        let length = data.get(at..at + 2).ok_or(Error::DecryptFailed)?;
        at += 2 + usize::from(u16::from_le_bytes([length[0], length[1]]));
    }
    for flag in [FLAG_NAME, FLAG_COMMENT] {
        if flags & flag != 0 {
            let zero =
                data.get(at..end).and_then(|rest| rest.iter().position(|&b| b == 0)).ok_or(Error::DecryptFailed)?;
            at += zero + 1;
        }
    }
    if flags & FLAG_HCRC != 0 {
        at += 2;
    }
    let stream = data.get(at..end).ok_or(Error::DecryptFailed)?;
    let output = miniz_oxide::inflate::decompress_to_vec_with_limit(stream, limit).map_err(|_| Error::DecryptFailed)?;
    let trailer = &data[end..];
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc32(&output) != crc || output.len() as u32 != size {
        return Err(Error::DecryptFailed);
    }
    Ok(output)
}

/// CRC-32 (IEEE 802.3, reflected 0xEDB88320) as gzip uses it.
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
        let mut table = [0u32; 256];
        for (index, entry) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 == 1 { 0xedb8_8320 ^ (value >> 1) } else { value >> 1 };
            }
            *entry = value;
        }
        table
    });
    !data.iter().fold(!0u32, |crc, &byte| TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::hex_decode;

    /// `printf '{"meta":{"code":200}}' | gzip -n` (Go's compress/gzip writes the same header: no name, no extra).
    const SAMPLE: &str = "1f8b0800000000000003ab56ca4d2d4954b2aa564ace4f4955b2323230a8ad050002f298fe15000000";

    #[test]
    fn decodes_gzip_of_the_cli_and_checks_the_trailer() {
        let data = hex_decode(SAMPLE).unwrap();
        assert_eq!(decode(&data, 1 << 20).unwrap(), br#"{"meta":{"code":200}}"#);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let mut bad_crc = data.clone();
        let at = bad_crc.len() - 8;
        bad_crc[at] ^= 1;
        assert_eq!(decode(&bad_crc, 1 << 20), Err(Error::DecryptFailed));
        assert_eq!(decode(&data, 4), Err(Error::DecryptFailed), "over the limit");
        assert_eq!(decode(&data[..10], 1 << 20), Err(Error::DecryptFailed));
        assert_eq!(decode(b"{\"meta\":{\"code\":200}}", 1 << 20), Err(Error::DecryptFailed), "not gzip");
    }
}
