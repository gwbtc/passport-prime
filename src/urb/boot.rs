//! The comet boot payload: `jam` the feed noun, encode it as `@uw`, and format
//! the `vere -G` one-liner the user runs after the reveal confirms (Causeway's
//! `spawn/mine-c.ts` jam + `spawn/boot-cmd.ts`).

use std::collections::HashMap;

use super::encoder::BitWriter;

/// A Hoon noun: an atom (little-endian bytes) or a cell of two nouns.
pub enum Noun {
    Atom(Vec<u8>),
    Cell(Box<Noun>, Box<Noun>),
}

fn atom(le: Vec<u8>) -> Noun {
    Noun::Atom(le)
}
fn cell(a: Noun, b: Noun) -> Noun {
    Noun::Cell(Box::new(a), Box::new(b))
}

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

// Structural key for back-reference dedup; atoms canonicalized by trimming
// trailing zero bytes so equal integer values share a key.
fn key(n: &Noun) -> String {
    match n {
        Noun::Atom(a) => {
            let mut end = a.len();
            while end > 0 && a[end - 1] == 0 {
                end -= 1;
            }
            let hexs: String = a[..end].iter().map(|b| format!("{b:02x}")).collect();
            format!("a:{hexs}")
        }
        Noun::Cell(x, y) => format!("c:({}|{})", key(x), key(y)),
    }
}

fn encode(w: &mut BitWriter, refs: &mut HashMap<String, usize>, n: &Noun) {
    let start = w.bit_len();
    let k = key(n);
    match n {
        Noun::Cell(x, y) => {
            if let Some(&e) = refs.get(&k) {
                w.write_u64(1, 1);
                w.write_u64(1, 1);
                w.write_mat_u64(e as u64);
            } else {
                refs.insert(k, start);
                w.write_u64(1, 1);
                w.write_u64(1, 0);
                encode(w, refs, x);
                encode(w, refs, y);
            }
        }
        Noun::Atom(a) => {
            if let Some(&e) = refs.get(&k) {
                // Only back-reference if the pointer is not longer than the atom.
                let a_bits = sig_bits(a);
                let r_bits = if e == 0 { 1 } else { usize_bits(e) };
                if a_bits <= r_bits {
                    w.write_u64(1, 0);
                    w.write_mat_le(a);
                } else {
                    w.write_u64(1, 1);
                    w.write_u64(1, 1);
                    w.write_mat_u64(e as u64);
                }
            } else {
                refs.insert(k, start);
                w.write_u64(1, 0);
                w.write_mat_le(a);
            }
        }
    }
}

/// `++jam`: serialize a noun to little-endian bytes with back-references.
pub fn jam(n: &Noun) -> Vec<u8> {
    let mut w = BitWriter::new();
    let mut refs = HashMap::new();
    encode(&mut w, &mut refs, n);
    w.into_bytes()
}

/// Jam the feed noun `[[2 0] comet rift [[life ring] 0]]` for `vere -G`.
pub fn jam_feed(comet: &[u8; 16], rift: u64, life: u64, ring_atom: &[u8]) -> Vec<u8> {
    let feed = cell(
        cell(atom(vec![2]), atom(vec![])),
        cell(
            atom(comet.to_vec()),
            cell(
                atom(rift.to_le_bytes().to_vec()),
                cell(
                    cell(atom(life.to_le_bytes().to_vec()), atom(ring_atom.to_vec())),
                    atom(vec![]),
                ),
            ),
        ),
    );
    jam(&feed)
}

// Urbit @uw base-64 alphabet.
const UW_CHARS: &[u8; 64] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-~";

/// Encode a little-endian byte atom as Urbit `@uw` (base-64, `0v` prefix, dots
/// every 5 chars). Works on arbitrary-length atoms — a jammed feed is hundreds
/// of bits — by dividing the big integer by 64 in place.
pub fn atom_to_uw(le: &[u8]) -> String {
    // Big-endian working copy, trailing (high) zero bytes trimmed.
    let mut num: Vec<u8> = le.iter().rev().skip_while(|&&b| b == 0).copied().collect();
    if num.is_empty() {
        return "0v0".to_string();
    }
    let mut digits = Vec::new();
    while num.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        for byte in num.iter_mut() {
            let cur = (rem << 8) | *byte as u32;
            *byte = (cur / 64) as u8;
            rem = cur % 64;
        }
        digits.push(UW_CHARS[rem as usize]);
    }
    digits.reverse();
    // Group every 5 chars from the right with '.'.
    let mut groups: Vec<String> = Vec::new();
    let mut i = digits.len();
    while i > 0 {
        let lo = i.saturating_sub(5);
        groups.insert(0, String::from_utf8(digits[lo..i].to_vec()).unwrap());
        i = lo;
    }
    format!("0v{}", groups.join("."))
}

/// The copy-paste one-liner that installs the runtime and boots the comet.
pub fn format_boot_command(comet_patp: &str, feed: &[u8], boot_script_url: &str, port: Option<u16>) -> String {
    let feed_uw = atom_to_uw(feed);
    let port_arg = match port {
        Some(p) if p != 8080 => format!(" --port {p}"),
        _ => String::new(),
    };
    format!("curl -fsSL {boot_script_url} | bash -s -- --comet {comet_patp} --feed {feed_uw}{port_arg}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Decimal string -> little-endian bytes.
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
    fn a(dec: &str) -> Noun {
        atom(dec_le(dec))
    }

    // All 14 of Causeway's jam golden vectors, incl. atom/cell back-references.
    #[test]
    fn jam_golden_vectors() {
        let cases: Vec<(Noun, &str)> = vec![
            (a("0"), "02"),
            (a("1"), "0c"),
            (a("42"), "5015"),
            (a("295990755076957304698161171062762229231"), "0002de9b5713cf8a46027c75fd95df7d5bbd01"),
            (cell(a("0"), a("0")), "29"),
            (cell(a("1"), a("2")), "3112"),
            (cell(cell(a("1"), a("2")), a("3")), "c54834"),
            (cell(a("1"), cell(a("2"), cell(a("3"), a("4")))), "71c8d098"),
            (
                cell(cell(a("1"), a("2")), cell(cell(a("3"), cell(a("4"), a("5"))), a("6"))),
                "c5c84287898b0d",
            ),
            (
                cell(
                    a("1512366075204170947332355369683137040"),
                    a("1512366075204170947332355369683137040"),
                ),
                "01cc2164a8ec3075b9fddf9b5713cf8a464e02",
            ),
            (cell(cell(a("42"), a("99")), cell(a("42"), a("99"))), "0555e1e349"),
            (cell(a("1"), cell(a("2"), cell(a("3"), a("0")))), "71c8d002"),
            (cell(a("0"), cell(a("5"), a("7"))), "192e3e"),
            (
                cell(cell(a("1"), a("100")), cell(cell(a("2"), a("200")), a("0"))),
                "c570722141200b",
            ),
        ];
        for (noun, expected) in cases {
            assert_eq!(hex(&jam(&noun)), expected);
        }
    }

    #[test]
    fn jam_feed_is_nonempty_and_deterministic() {
        let comet = [0x11u8; 16];
        let ring = {
            let mut v = vec![0x43u8];
            v.extend_from_slice(&[0u8; 64]);
            v.push(0x01);
            v
        };
        let f = jam_feed(&comet, 0, 1, &ring);
        assert!(!f.is_empty());
        assert_eq!(f, jam_feed(&comet, 0, 1, &ring));
    }

    #[test]
    fn uw_encoding() {
        assert_eq!(atom_to_uw(&[]), "0v0");
        assert_eq!(atom_to_uw(&[0, 0]), "0v0");
        assert_eq!(atom_to_uw(&[63]), "0v~");
        assert_eq!(atom_to_uw(&[64]), "0v10");
        // 64^5 = 2^30: six base-64 digits → one dot group boundary.
        assert_eq!(atom_to_uw(&1_073_741_824u64.to_le_bytes()), "0v1.00000");
        // 2^184 = 64^30 · 16 — wider than u128, must not truncate: top digit is
        // 16 ('g') followed by thirty '0's, grouped in fives.
        let mut wide = vec![0u8; 24];
        wide[23] = 0x01;
        assert_eq!(atom_to_uw(&wide), "0vg.00000.00000.00000.00000.00000.00000");
    }

    #[test]
    fn boot_command_format() {
        let feed = vec![0x01, 0x00, 0x00, 0x00]; // atom = 1
        let cmd = format_boot_command("~sampel-palnet", &feed, "https://groundwire.io/causeway/boot.sh", None);
        assert_eq!(
            cmd,
            "curl -fsSL https://groundwire.io/causeway/boot.sh | bash -s -- --comet ~sampel-palnet --feed 0v1",
        );
        let cmd_port = format_boot_command("~sampel-palnet", &feed, "u", Some(9000));
        assert!(cmd_port.ends_with("--feed 0v1 --port 9000"));
    }
}
