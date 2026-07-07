//! On-device suite-C comet miner (port of `comet_miner.c` / Causeway's `mine-c.ts`).
//!
//! Per iteration: random 64-byte seed → SHA-512 ring material → ed25519 pubkey
//! `sPub` → tweak scalar `SHA-256(sPub‖tweak)` → `tweakedSPub = sPub + scalar·G`
//! → comet `@p = shaf("cfig", tweakedSPub)`. Groundwire only sponsors comets
//! under the star `~daplyd` (0x42cd), a 16-bit constraint → ~65k iterations.
//!
//! The `tweak` (see [`super::tweak`]) binds the comet to one precommit satpoint,
//! and the emitted `pass`/`ring` atoms commit to it, so urb-core accepts the @p
//! only for that sat.

use sha2::{Digest, Sha256, Sha512};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use super::encoder::BitWriter;

/// Star all comets must fall under: `~daplyd` = 0x42cd (low 16 bits of the @p).
pub const REQUIRED_STAR: u16 = 0x42cd;

const SALT_CFIG: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = b'c';
    s[1] = b'f';
    s[2] = b'i';
    s[3] = b'g';
    s
};

/// ed25519 public key from a 32-byte private seed (RFC 8032 / noble `getPublicKey`):
/// clamp `SHA-512(seed)[..32]`, multiply the basepoint, compress.
fn ed_pubkey_from_seed(seed32: &[u8; 32]) -> [u8; 32] {
    let h = Sha512::digest(seed32);
    let mut clamp = [0u8; 32];
    clamp.copy_from_slice(&h[..32]);
    clamp[0] &= 248;
    clamp[31] &= 127;
    clamp[31] |= 64;
    // (clamp mod L)·B == clamp·B since B has order L.
    let s = Scalar::from_bytes_mod_order(clamp);
    (ED25519_BASEPOINT_POINT * s).compress().to_bytes()
}

/// `P' = P + s·G`, with `s` the 32-byte scalar read **little-endian** (`byte[0]`
/// is the LSB) and reduced mod L. Matches Causeway `mine-c.ts` `edAddScalarPublic`
/// (`s = Σ b[i]·256^i mod ED_L`) and urcrypt's `urcrypt_ed_add_scalar_public`.
fn ed_add_scalar_public(pub32: &[u8; 32], scalar32: &[u8; 32]) -> [u8; 32] {
    let s = Scalar::from_bytes_mod_order(*scalar32);
    let p = CompressedEdwardsY(*pub32)
        .decompress()
        .expect("valid ed25519 point");
    (p + ED25519_BASEPOINT_POINT * s).compress().to_bytes()
}

/// Hoon `++shas`: `SHA-256(salt ⊕ SHA-256(msg))` with salt-padding rules.
fn shas(salt: &[u8], msg: &[u8]) -> [u8; 32] {
    let mid = Sha256::digest(msg);
    if salt.len() > 32 {
        let mut padded = salt.to_vec();
        for i in 0..32 {
            padded[i] ^= mid[i];
        }
        Sha256::digest(&padded).into()
    } else {
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(&mid);
        for i in 0..salt.len() {
            tmp[i] ^= salt[i];
        }
        Sha256::digest(tmp).into()
    }
}

/// Hoon `++shaf`: 16-byte fuzzy hash = the two halves of `shas` XORed.
fn shaf(salt: &[u8], msg: &[u8]) -> [u8; 16] {
    let h = shas(salt, msg);
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = h[i] ^ h[i + 16];
    }
    out
}

/// On-chain `pass` atom (LE bytes): `[tag='c' ugn=sPub cry=cPub dat=mat(tweak)]`.
pub fn build_pass_atom(s_pub: &[u8; 32], c_pub: &[u8; 32], tweak: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.write_u64(8, 0x63); // 'c'
    w.write_le(256, s_pub);
    w.write_le(256, c_pub);
    w.write_mat_le(tweak);
    w.into_bytes()
}

/// Suite-C `ring` atom bytes: `'C' || ringMaterial || mat(tweak)`.
pub fn build_ring_atom_bytes(ring_material: &[u8; 64], tweak: &[u8]) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.write_u64(8, 0x43); // 'C'
    w.write_le(512, ring_material);
    w.write_mat_le(tweak);
    w.into_bytes()
}

/// A single mining iteration's outcome (before the star gate).
pub struct Candidate {
    pub ring_material: [u8; 64],
    pub s_pub: [u8; 32],
    pub comet: [u8; 16], // raw @p atom, LE
}

impl Candidate {
    /// Low 16 bits of the @p — the star the comet falls under.
    pub fn star(&self) -> u16 {
        self.comet[0] as u16 | ((self.comet[1] as u16) << 8)
    }
}

/// One deterministic mining iteration for a given 64-byte seed and tweak.
pub fn spawn_once(seed64: &[u8; 64], tweak: &[u8]) -> Candidate {
    let ring_material: [u8; 64] = Sha512::digest(seed64).into();
    let mut s_seed = [0u8; 32];
    s_seed.copy_from_slice(&ring_material[..32]);
    let s_pub = ed_pubkey_from_seed(&s_seed);

    let mut tw = Vec::with_capacity(32 + tweak.len());
    tw.extend_from_slice(&s_pub);
    tw.extend_from_slice(tweak);
    let tw_sca: [u8; 32] = Sha256::digest(&tw).into();

    let tweaked = ed_add_scalar_public(&s_pub, &tw_sca);
    let comet = shaf(&SALT_CFIG, &tweaked);
    Candidate { ring_material, s_pub, comet }
}

/// A fully mined comet bound to the tweak.
pub struct Mined {
    pub comet: [u8; 16],   // raw @p atom, LE
    pub pass: Vec<u8>,     // LE atom bytes for the %spawn sotx
    pub ring_atom: Vec<u8>, // suite-C ring atom for the boot feed
}

/// Mine until `accept(star)` holds. `rng` fills a fresh 64-byte seed each try.
/// Returns `None` if `max_tries` is exhausted.
pub(crate) fn mine_until(
    tweak: &[u8],
    mut rng: impl FnMut(&mut [u8; 64]),
    max_tries: u64,
    accept: impl Fn(u16) -> bool,
) -> Option<Mined> {
    let mut seed = [0u8; 64];
    for _ in 0..max_tries {
        rng(&mut seed);
        let cand = spawn_once(&seed, tweak);
        if !accept(cand.star()) {
            continue;
        }
        let mut c_seed = [0u8; 32];
        c_seed.copy_from_slice(&cand.ring_material[32..64]);
        let c_pub = ed_pubkey_from_seed(&c_seed);
        return Some(Mined {
            comet: cand.comet,
            pass: build_pass_atom(&cand.s_pub, &c_pub, tweak),
            ring_atom: build_ring_atom_bytes(&cand.ring_material, tweak),
        });
    }
    None
}

/// Mine a comet under `~daplyd` bound to `tweak`. `rng` must supply CSPRNG bytes.
pub fn mine(tweak: &[u8], rng: impl FnMut(&mut [u8; 64]), max_tries: u64) -> Option<Mined> {
    mine_until(tweak, rng, max_tries, |star| star == REQUIRED_STAR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Counter RNG: deterministic, distinct seeds per call. Not for production.
    fn counter_rng(start: u64) -> impl FnMut(&mut [u8; 64]) {
        let mut n = start;
        move |buf| {
            for chunk in buf.chunks_mut(8) {
                chunk.copy_from_slice(&n.to_le_bytes());
                n = n.wrapping_add(0x9e3779b97f4a7c15);
            }
        }
    }

    // edLuck parity vs Python `cryptography` (getPublicKey semantics).
    #[test]
    fn ed_pubkey_matches_neutral_oracle() {
        let seq: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hex(&ed_pubkey_from_seed(&seq)),
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        );
        assert_eq!(
            hex(&ed_pubkey_from_seed(&[0u8; 32])),
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        );
    }

    // shaf parity vs Python hashlib.
    #[test]
    fn shaf_matches_neutral_oracle() {
        assert_eq!(hex(&shaf(&SALT_CFIG, &[1u8; 32])), "23b73d08b356954b10414ad936c31462");
        let seq: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(hex(&shaf(&SALT_CFIG, &seq)), "0e831415a9b02a9907ffa6ca724f897b");
    }

    // P + s·G is genuine point addition: (k·G) + (s·G) == (k+s)·G.
    #[test]
    fn ed_add_scalar_public_is_point_addition() {
        let k = Scalar::from_bytes_mod_order([7u8; 32]);
        let s_bytes = [9u8; 32];
        let s = Scalar::from_bytes_mod_order(s_bytes);
        let base_pub = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();
        let got = ed_add_scalar_public(&base_pub, &s_bytes);
        let want = (ED25519_BASEPOINT_POINT * (k + s)).compress().to_bytes();
        assert_eq!(got, want);

        // Endianness lock: the scalar is little-endian, so a lone 1 in byte 0 must
        // add exactly 1·G (not 256^31·G). Pins parity with Causeway's byte order —
        // a big-endian misread would silently mine invalid comets.
        let mut one_le = [0u8; 32];
        one_le[0] = 1;
        let p = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();
        let plus_one = ed_add_scalar_public(&p, &one_le);
        let want_plus_one = (ED25519_BASEPOINT_POINT * (k + Scalar::ONE)).compress().to_bytes();
        assert_eq!(plus_one, want_plus_one);
    }

    // Wiring: an independent recompute of the comet from the same primitives
    // reproduces spawn_once's output, and the pass/ring tags are correct.
    #[test]
    fn spawn_once_is_internally_consistent() {
        let seed: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
        let tweak = [0x09u8, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07];
        let cand = spawn_once(&seed, &tweak);

        let rm: [u8; 64] = Sha512::digest(seed).into();
        let mut s_seed = [0u8; 32];
        s_seed.copy_from_slice(&rm[..32]);
        let s_pub = ed_pubkey_from_seed(&s_seed);
        let mut tw = s_pub.to_vec();
        tw.extend_from_slice(&tweak);
        let tw_sca: [u8; 32] = Sha256::digest(&tw).into();
        let tweaked = ed_add_scalar_public(&s_pub, &tw_sca);
        assert_eq!(cand.comet, shaf(&SALT_CFIG, &tweaked));
        assert_eq!(cand.s_pub, s_pub);

        let c_pub = ed_pubkey_from_seed(&[0x55u8; 32]);
        assert_eq!(build_pass_atom(&s_pub, &c_pub, &tweak)[0], 0x63); // 'c'
        assert_eq!(build_ring_atom_bytes(&rm, &tweak)[0], 0x43); // 'C'
    }

    // The mining loop plumbing (accept-first-try predicate — no 65k search).
    #[test]
    fn mine_loop_returns_well_formed_result() {
        let tweak = [0x09u8, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07];
        let mined = mine_until(&tweak, counter_rng(1), 4, |_| true).expect("accepts first try");
        assert_eq!(mined.pass[0], 0x63); // 'c'
        assert_eq!(mined.ring_atom[0], 0x43); // 'C'
        assert!(mined.pass.len() > 64);
        assert_eq!(mined.comet.len(), 16);
    }

    // Real ~daplyd search (~65k iterations). Slow; run explicitly:
    //   cargo test --bins -- --ignored mines_a_real_daplyd_comet
    #[test]
    #[ignore]
    fn mines_a_real_daplyd_comet() {
        let tweak = super::super::tweak::build_tweak_bytes(&"11".repeat(32), 0, 0).unwrap();
        let mined = mine(&tweak, counter_rng(0xDEAD), 2_000_000).expect("finds a comet");
        let star = mined.comet[0] as u16 | ((mined.comet[1] as u16) << 8);
        assert_eq!(star, REQUIRED_STAR);
        assert_eq!(mined.pass[0], 0x63);
    }
}
