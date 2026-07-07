//! Bit-exact port of the `%spawn` arm of `lib/urb-encoder.hoon` (via Causeway's
//! `protocol/encoder.ts`).
//!
//! An sotx (signed ord transaction) is serialized as a Hoon bitstream: fields
//! are written LSB-first into a little-endian byte buffer, with variable-length
//! atoms length-prefixed by `++mat`. The output bytes go verbatim into the
//! `urb`-tagged Taproot leaf.
//!
//! The device only ever emits a bare `%spawn` — management ops (rekey, escape,
//! …) live in Causeway, not on the Passport — so only that op is ported here.
//! Proven against Causeway's three `%spawn` golden vectors (see tests).

/// Little-endian, LSB-first bit sink. Mirrors `protocol/bitwriter.ts`.
pub struct BitWriter {
    buf: Vec<u8>,
    bitpos: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { buf: Vec::new(), bitpos: 0 }
    }

    fn write_bit(&mut self, b: u8) {
        let byte = self.bitpos >> 3;
        if byte >= self.buf.len() {
            self.buf.push(0);
        }
        if b & 1 != 0 {
            self.buf[byte] |= 1 << (self.bitpos & 7);
        }
        self.bitpos += 1;
    }

    /// Write the low `width` bits of `v`, LSB first.
    pub fn write_u64(&mut self, width: usize, v: u64) {
        for i in 0..width {
            self.write_bit(((v >> i) & 1) as u8);
        }
    }

    pub fn write_u128(&mut self, width: usize, v: u128) {
        for i in 0..width {
            self.write_bit(((v >> i) & 1) as u8);
        }
    }

    /// Write `width` bits from a little-endian byte atom, zero-padding beyond `le`.
    pub fn write_le(&mut self, width: usize, le: &[u8]) {
        for i in 0..width {
            let byte = i >> 3;
            let bit = if byte < le.len() { (le[byte] >> (i & 7)) & 1 } else { 0 };
            self.write_bit(bit);
        }
    }

    /// Length-prefixed atom encoding (`++mat`). `le` is the atom in LE bytes.
    pub fn write_mat_le(&mut self, le: &[u8]) {
        let b = sig_bits(le);
        if b == 0 {
            // mat(0) == a single set bit.
            self.write_bit(1);
            return;
        }
        let c = usize_bits(b); // bit-length of the bit-length
        for _ in 0..c {
            self.write_bit(0);
        }
        self.write_bit(1);
        let lowb = if c > 1 { (b as u64) & ((1u64 << (c - 1)) - 1) } else { 0 };
        self.write_u64(c - 1, lowb);
        self.write_le(b, le);
    }

    pub fn write_mat_u64(&mut self, v: u64) {
        self.write_mat_le(&v.to_le_bytes());
    }

    /// Current bit position — the back-reference target for `jam`.
    pub fn bit_len(&self) -> usize {
        self.bitpos
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Significant bit count of a little-endian byte atom (Hoon `(met 0 a)`).
fn sig_bits(le: &[u8]) -> usize {
    for i in (0..le.len()).rev() {
        if le[i] != 0 {
            return i * 8 + (8 - le[i].leading_zeros() as usize);
        }
    }
    0
}

fn usize_bits(mut n: usize) -> usize {
    let mut c = 0;
    while n > 0 {
        c += 1;
        n >>= 1;
    }
    c
}

// ---- %spawn value types (mirror protocol/types.ts) --------------------------

/// A networking endpoint pinned at spawn (`fief`). `%turf` is intentionally
/// unsupported (matches the Hoon `!!`).
pub enum Fief {
    If { ip: u32, port: u16 },
    Is { ip: u128, port: u16 },
}

pub struct SpawnTo {
    pub spkh: [u8; 32], // LE atom bytes
    pub vout: Option<u64>,
    pub off: u64,
    pub tej: u64,
}

pub struct Spawn {
    pub pass: Vec<u8>, // LE atom bytes from the miner
    pub fief: Option<Fief>,
    pub to: SpawnTo,
}

const OP_SPAWN: u64 = 1;

fn encode_fief_inline(w: &mut BitWriter, fief: &Option<Fief>) {
    match fief {
        None => w.write_u64(2, 0),
        Some(Fief::If { ip, port }) => {
            w.write_u64(2, 2);
            w.write_u64(32, *ip as u64);
            w.write_u64(16, *port as u64);
        }
        Some(Fief::Is { ip, port }) => {
            w.write_u64(2, 3);
            w.write_u128(128, *ip);
            w.write_u64(16, *port as u64);
        }
    }
}

/// Encode a bare `%spawn` skim-sotx (what the attestation leaf wraps).
pub fn encode_spawn(s: &Spawn) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.write_u64(7, OP_SPAWN);
    w.write_u64(1, 0);
    w.write_mat_le(&s.pass);
    encode_fief_inline(&mut w, &s.fief);
    w.write_le(256, &s.to.spkh);
    w.write_mat_u64(s.to.off);
    w.write_mat_u64(s.to.tej);
    match s.to.vout {
        None => w.write_u64(2, 0),
        Some(v) => {
            w.write_u64(2, 1);
            w.write_mat_u64(v);
        }
    }
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Decimal string -> little-endian bytes (schoolbook division by 256).
    fn dec_le(s: &str) -> Vec<u8> {
        let mut digits: Vec<u8> = s.bytes().map(|c| c - b'0').collect();
        let mut out = Vec::new();
        while digits.iter().any(|&d| d != 0) {
            let mut rem = 0u32;
            for d in digits.iter_mut() {
                let cur = rem * 10 + *d as u32;
                *d = (cur / 256) as u8;
                rem = cur % 256;
            }
            out.push(rem as u8);
            while digits.len() > 1 && digits[0] == 0 {
                digits.remove(0);
            }
        }
        out
    }

    fn dec_arr32(s: &str) -> [u8; 32] {
        let mut v = dec_le(s);
        v.resize(32, 0);
        v.try_into().unwrap()
    }

    fn dec_u128(s: &str) -> u128 {
        s.parse().unwrap()
    }

    // Causeway's fixed test pass atom + spkh.
    fn pass() -> Vec<u8> {
        dec_le("366213609593416641547364309524750976439928")
    }
    fn spkh() -> [u8; 32] {
        dec_arr32("115520583276441115789036455024003198792587894645174502645738895526012167040478")
    }

    fn check(name: &str, s: Spawn, expected: &str) {
        assert_eq!(hex(&encode_spawn(&s)), expected, "{name}");
    }

    #[test]
    fn golden_spawn_no_fief_no_vout() {
        check(
            "spawn/no-fief/no-vout",
            Spawn {
                pass: pass(),
                fief: None,
                to: SpawnTo { spkh: spkh(), off: 0, tej: 0, vout: None },
            },
            "010017785634120df0fecaefbeadde01ad7f3434c4bbd5f75dd95fd71720426486a8caec0e31537597b9dbfd1f20426486a8caec7f00",
        );
    }

    #[test]
    fn golden_spawn_if_fief_vout() {
        check(
            "spawn/if-fief/vout",
            Spawn {
                pass: pass(),
                fief: Some(Fief::If { ip: 3232235777, port: 8443 }),
                to: SpawnTo { spkh: spkh(), off: 7, tej: 42, vout: Some(3) },
            },
            "010017785634120df0fecaefbeadde01ad7f343434200015781fc4bbd5f75dd95fd71720426486a8caec0e31537597b9dbfd1f20426486a8caec9f8faad1",
        );
    }

    #[test]
    fn golden_spawn_is_fief() {
        check(
            "spawn/is-fief",
            Spawn {
                pass: pass(),
                fief: Some(Fief::Is { ip: dec_u128("42540488161975842760550356425300246529"), port: 9000 }),
                to: SpawnTo { spkh: spkh(), off: 1, tej: 2, vout: None },
            },
            "010017785634120df0fecaefbeadde01ad7f34343c0000000000000000000000000020000465c4bbd5f75dd95fd71720426486a8caec0e31537597b9dbfd1f20426486a8caecdf24",
        );
    }
}
