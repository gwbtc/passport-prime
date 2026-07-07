//! Pure logic behind the guided onboarding wizard (docs/onboarding-flow.md §8).
//!
//! Everything here is keyboard-free and deterministic given its salt, so the
//! Slint layer can rebuild the same grid across redraws. The two security-
//! critical gates — the backup proof and the address match — never compare
//! strings the user could rubber-stamp; they re-derive the funding address from
//! the reconstructed secret and compare that (§2 checkpoints 2 & 4).

use crate::{bip39, identity};

/// Deterministic scalar PRNG (SplitMix64) — no `rand`, no OS entropy (the xous
/// device has neither app-facing TRNG nor `getrandom`), reproducible for tests.
fn prng(mut s: u64) -> impl FnMut() -> u64 {
    move || {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Fisher–Yates shuffle driven by `rng`.
fn shuffle<T>(v: &mut [T], rng: &mut impl FnMut() -> u64) {
    for i in (1..v.len()).rev() {
        v.swap(i, (rng() as usize) % (i + 1));
    }
}

/// The correct BIP-39 word at `position` plus 5 decoys from the wordlist,
/// shuffled. Reading only from paper, the user taps the word they wrote; decoys
/// are real dictionary words so recognition-without-paper is no help (§4).
pub fn backup_word_choices(mnemonic: &str, position: usize, salt: u64) -> Vec<String> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let list = bip39::wordlist();
    let mut rng = prng(salt ^ (position as u64).wrapping_mul(0x100_0001));
    let mut out = vec![words.get(position).copied().unwrap_or("").to_string()];
    while out.len() < 6 {
        let w = list[(rng() as usize) % list.len()];
        if !out.iter().any(|c| c == w) {
            out.push(w.to_string());
        }
    }
    shuffle(&mut out, &mut rng);
    out
}

/// Gate for the backup proof: join the tapped words, decode to entropy, re-derive
/// the funding address, and compare to the one shown at generation. Only an
/// exactly-correct transcription passes — a single wrong word changes the
/// address (§2 checkpoint 2). Never reveals *which* word was wrong.
pub fn confirm_backup(words: &[String], expected_address: &str) -> bool {
    let entropy = match bip39::from_mnemonic(&words.join(" ")) {
        Some(e) if e.len() == 16 => e,
        _ => return false,
    };
    identity::derive_funding_address(&entropy) == expected_address
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> (Vec<String>, String) {
        // 16 entropy bytes 00..0f -> BIP-39 words; address is the raw-seed vector
        // pinned in identity.rs::funding_address_vectors.
        let entropy: Vec<u8> = (0u8..16).collect();
        let words = bip39::to_mnemonic(&entropy).split_whitespace().map(String::from).collect();
        (words, "bc1pzh75rtx74l85v2xqfr5uln7mhy40vyqzm68ml4yngcqy9v085tqqmgg72j".to_string())
    }

    #[test]
    fn backup_choices_shape() {
        let (words, _) = known();
        let mn = words.join(" ");
        for pos in 0..12 {
            let c = backup_word_choices(&mn, pos, 42);
            assert_eq!(c.len(), 6);
            assert!(c.contains(&words[pos]), "correct word present at {pos}");
            let uniq: std::collections::HashSet<_> = c.iter().collect();
            assert_eq!(uniq.len(), 6, "no duplicate choices");
        }
        // Deterministic for a given salt.
        assert_eq!(backup_word_choices(&mn, 3, 42), backup_word_choices(&mn, 3, 42));
    }

    #[test]
    fn confirm_backup_gates_on_derivation() {
        let (words, addr) = known();
        assert!(confirm_backup(&words, &addr));
        // One wrong (but valid) word -> different entropy/checksum -> reject.
        let mut bad = words.clone();
        bad[0] = "zoo".into();
        assert!(!confirm_backup(&bad, &addr));
        // Right words, wrong expected address -> reject.
        assert!(!confirm_backup(&words, "bc1pwrong"));
    }

}
