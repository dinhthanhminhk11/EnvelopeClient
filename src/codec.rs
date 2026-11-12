//! Byte encodings shared by every module (theme-x wire format §1).
//!
//! - `frame(f1, f2, …)` = `u32be(len(fi)) ‖ fi` for each field; integers are 8-byte big-endian fields.
//! - Binary values travel as base64url without padding in JSON and headers.

/// Length-prefixed field encoder: the input of every signature, AAD, transcript and requestHash.
#[derive(Default)]
pub struct Frame {
    bytes: Vec<u8>,
}

impl Frame {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { bytes: Vec::with_capacity(capacity) }
    }

    /// Raw bytes field. Fields are bounded by u32; callers validate sizes long before this.
    pub fn bytes(mut self, field: &[u8]) -> Self {
        self.push(field);
        self
    }

    /// UTF-8 text field.
    pub fn text(self, field: &str) -> Self {
        self.bytes(field.as_bytes())
    }

    /// `u64be(value)` as one 8-byte field.
    pub fn u64(self, value: u64) -> Self {
        self.bytes(&value.to_be_bytes())
    }

    pub fn push(&mut self, field: &[u8]) {
        let length = u32::try_from(field.len()).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(field);
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Splits a frame back into its fields; `None` when the lengths do not add up exactly.
pub fn unframe(mut input: &[u8]) -> Option<Vec<&[u8]>> {
    let mut fields = Vec::new();
    while !input.is_empty() {
        let (length, rest) = input.split_first_chunk::<4>()?;
        let length = u32::from_be_bytes(*length) as usize;
        if rest.len() < length {
            return None;
        }
        let (field, rest) = rest.split_at(length);
        fields.push(field);
        input = rest;
    }
    Some(fields)
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding.
pub fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            out.push(B64URL[((n >> (18 - 6 * index)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn b64url_value(symbol: u8) -> Option<u32> {
    Some(match symbol {
        b'A'..=b'Z' => symbol - b'A',
        b'a'..=b'z' => symbol - b'a' + 26,
        b'0'..=b'9' => symbol - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    } as u32)
}

/// Strict base64url decode: no padding, alphabet only, canonical trailing bits (rejects alternative spellings).
pub fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let symbols = input.as_bytes();
    if symbols.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(symbols.len() * 3 / 4);
    for chunk in symbols.chunks(4) {
        let mut n = 0u32;
        for (index, symbol) in chunk.iter().enumerate() {
            n |= b64url_value(*symbol)? << (18 - 6 * index);
        }
        let produced = chunk.len() - 1;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..1 + produced]);
        // Bits below the last full byte must be zero.
        let unused_bits = 24 - 8 * produced;
        if chunk.len() < 4 && n & ((1 << unused_bits) - 1) != 0 {
            return None;
        }
    }
    Some(out)
}

/// Decodes base64url and requires an exact byte length.
pub fn b64url_decode_exact<const N: usize>(input: &str) -> Option<[u8; N]> {
    let bytes = b64url_decode(input)?;
    bytes.try_into().ok()
}

pub fn hex_encode(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
}

/// Lowercase UUID v4 text from 16 random bytes.
pub fn uuid_v4(mut random: [u8; 16]) -> String {
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    let hex = hex_encode(&random);
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` (case-insensitive), as the server checks requestId.
pub fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trip_and_strictness() {
        for length in 0..40 {
            let input: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = b64url_encode(&input);
            assert!(!encoded.contains('='));
            assert_eq!(b64url_decode(&encoded).unwrap(), input);
        }
        assert_eq!(b64url_encode(b"\xfb\xff"), "-_8");
        assert!(b64url_decode("-_8=").is_none());
        assert!(b64url_decode("ab+c").is_none());
        assert!(b64url_decode("a").is_none());
        // "-_9" decodes to the same bytes as "-_8" in lenient decoders: non-canonical, rejected.
        assert!(b64url_decode("-_9").is_none());
    }

    #[test]
    fn unframe_rejects_bad_lengths() {
        let framed = Frame::new().text("ab").u64(7).bytes(&[]).finish();
        let fields = unframe(&framed).unwrap();
        assert_eq!(fields, vec![&b"ab"[..], &7u64.to_be_bytes()[..], &[][..]]);
        assert!(unframe(&framed[..framed.len() - 1]).is_none());
        assert!(unframe(&[0, 0, 0, 5, 1]).is_none());
    }

    #[test]
    fn uuid_shape() {
        let id = uuid_v4([0xff; 16]);
        assert!(is_uuid(&id));
        assert_eq!(&id[14..15], "4");
        assert!(!is_uuid("0f8fad5b-d9cb-469f-a165-70867728950"));
        assert!(is_uuid("0F8FAD5B-D9CB-469F-A165-70867728950E"));
    }
}
