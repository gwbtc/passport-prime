//! User-supplied entropy via dice rolls, conditioned with SHA-256.
//!
//! On-device there is no app-facing TRNG (see docs/trng-spike.md), so a new
//! ticket's entropy comes from the user. Each physical d6 roll is log2(6) ≈
//! 2.585 bits, so >= 50 rolls guarantees a >= 128-bit floor — the same dice
//! method Coldcard / Passport Core use. Raw rolls are biased, so the pool is run
//! through SHA-256 (truncated to 16 bytes) before use; truncating a uniform hash
//! stays uniform. Each tap's arrival timing is folded in as bonus entropy, and
//! callers mix in the OS CSPRNG where one exists (the simulator) as defense in
//! depth. The counted dice alone carry the audited floor.

use sha2::{Digest, Sha256};

/// Rolls needed for a 128-bit ticket: ceil(128 / log2(6)) = ceil(128 / 2.585).
pub const ROLLS_FOR_128: u32 = 50;

#[derive(Default)]
pub struct EntropyPool {
    rolls: u32,
    pool: Vec<u8>,
}

impl EntropyPool {
    pub fn reset(&mut self) {
        use zeroize::Zeroize;
        self.rolls = 0;
        // Wipe the raw dice entropy from the heap, not just drop the length.
        self.pool.zeroize();
        self.pool.clear();
    }

    /// Record a die face (1..=6) plus a timing sample; returns the new roll count.
    pub fn add_roll(&mut self, face: u8, timing_nanos: u128) -> u32 {
        self.rolls += 1;
        self.pool.push(face);
        self.pool.extend_from_slice(&timing_nanos.to_le_bytes());
        self.rolls
    }

    /// True once enough dice have been rolled for a 128-bit floor.
    pub fn ready(&self) -> bool {
        self.rolls >= ROLLS_FOR_128
    }

    /// Condition the accumulated pool (plus any extra system entropy) into the
    /// 16-byte seed, used directly as the BIP-32 seed on-device.
    pub fn finish(&self, extra: &[u8]) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(&self.pool);
        h.update(extra);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h.finalize()[..16]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_is_sha256_truncated() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223...; take the first 16.
        let mut p = EntropyPool::default();
        p.pool.extend_from_slice(b"abc");
        assert_eq!(
            p.finish(&[]),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23
            ]
        );
    }

    #[test]
    fn threshold_and_distinctness() {
        let mut p = EntropyPool::default();
        for i in 0..ROLLS_FOR_128 {
            assert!(!p.ready());
            p.add_roll((i % 6) as u8 + 1, i as u128);
        }
        assert!(p.ready());
        assert_eq!(p.rolls, 50);

        // Different first roll -> different conditioned seed.
        let mut a = EntropyPool::default();
        a.add_roll(1, 0);
        let mut b = EntropyPool::default();
        b.add_roll(2, 0);
        assert_ne!(a.finish(&[]), b.finish(&[]));
    }
}
