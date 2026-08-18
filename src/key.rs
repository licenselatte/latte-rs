//! License-key / AppID normalization and checksum. This is a hand-rolled
//! typo-catching checksum, not a cryptographic primitive, so implementing
//! it here directly (rather than using a crypto library) is correct, not a
//! "hand-rolled crypto" violation.

const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn alphabet_index(c: u8) -> i64 {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|i| i as i64)
        .unwrap_or(-1)
}

pub(crate) fn calculate_checksum(data: &str, length: usize) -> String {
    let mut sum: i64 = 0;
    for (i, c) in data.bytes().enumerate() {
        let mut val = alphabet_index(c);
        if i % 2 == 0 {
            val *= 2;
        }
        sum += val;
    }

    let mut checksum = String::with_capacity(length);
    for i in 0..length {
        let idx = ((sum + (i as i64) * 31).rem_euclid(ALPHABET.len() as i64)) as usize;
        checksum.push(ALPHABET[idx] as char);
    }
    checksum
}

/// Validates that the last `checksum_len` characters of `key` are the
/// correct checksum of the preceding characters.
pub fn validate_key(key: &str, checksum_len: usize) -> bool {
    if key.len() < checksum_len {
        return false;
    }
    let split_at = key.len() - checksum_len;
    let (data_part, provided) = key.split_at(split_at);
    calculate_checksum(data_part, checksum_len) == provided
}

/// Uppercases, strips hyphens/spaces, and folds the visually-ambiguous
/// characters `O -> 0`, `I -> 1`, `L -> 1` (in that order; `I` and `L`
/// both fold to `1`, so a sanitized key can never distinguish an original
/// `L` from an original `I` from an original `1`; this is intentional,
/// not an oversight). This fold is specific to the native key alphabet
/// (which deliberately excludes `O`/`I`/`L`) — use it only where the
/// value is expected to be a native-format key. Use `normalize_key` for
/// anything else.
pub fn sanitize_key(input: &str) -> String {
    let mut s = input.to_uppercase();
    s.retain(|c| c != '-' && c != ' ');
    s.chars()
        .map(|c| match c {
            'O' => '0',
            'I' => '1',
            'L' => '1',
            other => other,
        })
        .collect()
}

/// Uppercases and strips hyphens/spaces, with no other transformation.
/// Unlike `sanitize_key`, this never assumes the input is in the native
/// key alphabet, so it's safe to use on any license key string regardless
/// of which system minted it.
pub fn normalize_key(input: &str) -> String {
    let mut s = input.to_uppercase();
    s.retain(|c| c != '-' && c != ' ');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_folds_ambiguous_chars() {
        assert_eq!(sanitize_key("ab-cd IL o"), "ABCD110");
    }

    #[test]
    fn normalize_strips_separators_without_folding_ambiguous_chars() {
        assert_eq!(normalize_key("ab-cd IL o"), "ABCDILO");
    }

    #[test]
    fn checksum_round_trips() {
        let data = "AHAK85389VQYXYB6S4BW66SKE53TWVT";
        let sum = calculate_checksum(data, 4);
        assert!(validate_key(&format!("{data}{sum}"), 4));
        assert!(!validate_key(&format!("{data}XXXX"), 4));
    }
}
