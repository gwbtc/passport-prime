//! Minimal BIP-39 mnemonic *encoding* (entropy -> words).
//!
//! Groundwire stores the master ticket as a BIP-39 phrase so the secret lives
//! on-device in a standard, portable format — the same format the Passport's
//! own Vault uses.
//!
//! IMPORTANT: Groundwire uses the ticket entropy *directly* as the BIP-32 seed;
//! it does NOT run BIP-39's PBKDF2 stretch. So these words are a standard
//! *encoding of the 128-bit secret*, not a drop-in seed for a stock BIP-39
//! wallet — importing them elsewhere derives different keys. No passphrase.
//! `from_mnemonic` decodes + checksum-verifies the words back to those entropy
//! bytes — used only to verify the backup quiz, never as a foreign import path.

use sha2::{Digest, Sha256};

/// Canonical BIP-39 English wordlist (2048 words). Integrity pinned by its
/// sha256 in the tests below, so a corrupted embed fails the build's test pass.
const WORDLIST: &str = include_str!("bip39_english.txt");

/// Encode entropy (a multiple of 32 bits: 16/20/24/28/32 bytes) as a BIP-39
/// mnemonic. Panics on invalid length — callers pass fixed 16-byte tickets.
pub fn to_mnemonic(entropy: &[u8]) -> String {
    assert!(
        !entropy.is_empty() && entropy.len() % 4 == 0,
        "bip39 entropy must be a non-zero multiple of 4 bytes"
    );
    let ent_bits = entropy.len() * 8;
    let cs_bits = ent_bits / 32; // one checksum bit per 32 entropy bits
    let checksum = Sha256::digest(entropy)[0]; // cs_bits <= 8 for <= 32 bytes

    // Concatenate entropy || checksum bits, then read 11-bit big-endian indices.
    let bit = |i: usize| -> u32 {
        if i < ent_bits {
            ((entropy[i / 8] >> (7 - i % 8)) & 1) as u32
        } else {
            ((checksum >> (7 - (i - ent_bits))) & 1) as u32
        }
    };
    let words: Vec<&str> = WORDLIST.lines().collect();
    let n = (ent_bits + cs_bits) / 11;
    (0..n)
        .map(|w| {
            let idx = (0..11).fold(0u32, |acc, b| (acc << 1) | bit(w * 11 + b));
            words[idx as usize]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The canonical wordlist as a vector, for building quiz decoys.
pub fn wordlist() -> Vec<&'static str> {
    WORDLIST.lines().collect()
}

/// Decode a BIP-39 mnemonic back to its entropy bytes, verifying the checksum.
/// Returns `None` if any word is unknown, the count is unsupported (12/15/18/
/// 21/24), or the checksum is wrong. Inverse of `to_mnemonic`; used to verify
/// the backup-proof quiz (`crate::wizard::confirm_backup`).
pub fn from_mnemonic(mnemonic: &str) -> Option<Vec<u8>> {
    let list = wordlist();
    let idxs: Option<Vec<u32>> = mnemonic
        .split_whitespace()
        .map(|w| list.iter().position(|&x| x == w).map(|p| p as u32))
        .collect();
    let idxs = idxs?;
    let n = idxs.len();
    if !(12..=24).contains(&n) || n % 3 != 0 {
        return None;
    }
    // total = ent + cs bits, with cs = ent/32, so ent = total * 32/33.
    let total_bits = n * 11;
    let ent_bits = total_bits / 33 * 32;
    let cs_bits = total_bits - ent_bits;

    let mut bits = Vec::with_capacity(total_bits);
    for idx in idxs {
        for b in (0..11).rev() {
            bits.push(((idx >> b) & 1) as u8);
        }
    }
    let mut ent = vec![0u8; ent_bits / 8];
    for i in 0..ent_bits {
        ent[i / 8] |= bits[i] << (7 - i % 8);
    }
    let checksum = Sha256::digest(&ent)[0];
    for i in 0..cs_bits {
        if bits[ent_bits + i] != (checksum >> (7 - i)) & 1 {
            return None;
        }
    }
    Some(ent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_integrity() {
        // Canonical bip-0039 english.txt sha256.
        let h = Sha256::digest(WORDLIST.as_bytes());
        assert_eq!(
            format!("{h:x}"),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(WORDLIST.lines().count(), 2048);
    }

    // Official BIP-39 test vectors (128-bit entropy -> 12 words).
    #[test]
    fn known_vectors() {
        assert_eq!(
            to_mnemonic(&[0u8; 16]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            to_mnemonic(&[0x7f; 16]),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
        assert_eq!(
            to_mnemonic(&[0xff; 16]),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }

    #[test]
    fn decode_roundtrip() {
        for e in [[0u8; 16], [0x7f; 16], [0xff; 16], (0u8..16).collect::<Vec<_>>().try_into().unwrap()] {
            assert_eq!(from_mnemonic(&to_mnemonic(&e)).unwrap(), e);
        }
    }

    #[test]
    fn decode_rejects_bad_checksum() {
        // Valid words, wrong checksum (last word swapped for another).
        assert!(from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
        ).is_none());
        // Unknown word.
        assert!(from_mnemonic("notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_none());
        // Wrong count.
        assert!(from_mnemonic("abandon abandon abandon").is_none());
    }
}
