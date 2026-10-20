// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Standard Base64 and the encoded command text the guard accepts.

use crate::GuardError;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Strict standard base64: full quartets, padding only at the end.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let body = &bytes[..bytes.len() - padding];
    for (i, &b) in body.iter().enumerate() {
        let value = ALPHABET.iter().position(|&a| a == b)? as u32;
        acc = (acc << 6) | value;
        if i % 4 == 3 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
        }
    }
    match padding {
        // Unused trailing bits are ignored, as the reference decoder does.
        1 => { acc <<= 6; out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]); }
        2 => { acc <<= 12; out.push((acc >> 16) as u8); }
        _ => {}
    }
    Some(out)
}

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The command text a `--command-b64` value holds: nonempty UTF-8 with no NUL.
pub fn decode_command(value: &str) -> Result<String, GuardError> {
    let bytes = base64_decode(value).ok_or_else(|| GuardError("--command-b64 is not valid base64".into()))?;
    let command = String::from_utf8(bytes).map_err(|_| GuardError("--command-b64 is not valid UTF-8".into()))?;
    if command.trim().is_empty() || command.contains('\0') {
        return Err(GuardError("command must be nonempty and contain no NUL".into()));
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_and_strictness() {
        for text in ["", "a", "ab", "abc", "abcd", "Write-Output 'guard-ok'"] {
            let encoded = base64_encode(text.as_bytes());
            if !text.is_empty() {
                assert_eq!(base64_decode(&encoded).unwrap(), text.as_bytes());
            }
        }
        assert_eq!(base64_encode(b"Write-Output 'guard-ok'"), "V3JpdGUtT3V0cHV0ICdndWFyZC1vayc=");
        for bad in ["////=", "abc", "ab=c", "a===", "Zm9v!", "Zg=x"] {
            assert!(base64_decode(bad).is_none(), "{}", bad);
        }
    }
}
