//! Minimal standard base64 (RFC 4648) encode/decode, dependency-free.
//!
//! Session payloads are carried as base64 strings in JSON so that arbitrary
//! bytes survive the wire.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes to a standard base64 string (with `=` padding).
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes canonical padded standard base64.
///
/// Whitespace, omitted padding, padding before the final quartet, trailing
/// data after padding, and non-zero pad bits are rejected. This keeps binary
/// credential and session wire values unambiguous across SDKs.
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 4 != 0 {
        return Err("base64 length must be a multiple of four".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let quartets = input.as_bytes().chunks_exact(4);
    let quartet_count = quartets.len();
    for (index, quartet) in quartets.enumerate() {
        let final_quartet = index + 1 == quartet_count;
        let first = decode_sextet(quartet[0])?;
        let second = decode_sextet(quartet[1])?;
        let third_padding = quartet[2] == b'=';
        let fourth_padding = quartet[3] == b'=';

        if third_padding {
            if !final_quartet || !fourth_padding {
                return Err("base64 padding is only valid at the end".to_string());
            }
            if second & 0x0f != 0 {
                return Err("base64 has non-zero pad bits".to_string());
            }
            out.push((first << 2) | (second >> 4));
            continue;
        }

        let third = decode_sextet(quartet[2])?;
        out.push((first << 2) | (second >> 4));
        out.push((second << 4) | (third >> 2));
        if fourth_padding {
            if !final_quartet {
                return Err("base64 padding is only valid at the end".to_string());
            }
            if third & 0x03 != 0 {
                return Err("base64 has non-zero pad bits".to_string());
            }
        } else {
            let fourth = decode_sextet(quartet[3])?;
            out.push((third << 6) | fourth);
        }
    }
    Ok(out)
}

fn decode_sextet(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        other => Err(format!("invalid base64 byte {other:#x}")),
    }
}
