//! The tweak atom urb-core uses to validate a %spawn's networking key
//! (`lib/urb-core.hoon:363-375`, via Causeway's `spawn/tweak.ts`).
//!
//! `(rap 3 ~[%9 ~tyr %urb-watcher %btc %gw %9 txid vout off])` — each atom's
//! minimal little-endian bytes concatenated. Zero-valued atoms contribute
//! nothing; `txid` is the full 32-byte LE atom. The mined comet's `pass`
//! commits to this, binding the new @p to one precommit satpoint.

/// Minimal LE bytes of a non-negative integer (empty for 0, matching `(met 3 0)`).
fn min_le(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out
}

/// Build the tweak bytes from a display-order (explorer) txid hex plus vout/off.
pub fn build_tweak_bytes(txid_display_hex: &str, vout: u64, off: u64) -> Result<Vec<u8>, String> {
    let clean = txid_display_hex.strip_prefix("0x").unwrap_or(txid_display_hex).to_ascii_lowercase();
    if clean.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", clean.len()));
    }
    let mut display = [0u8; 32];
    for i in 0..32 {
        display[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }

    let mut out = vec![0x09, 0x99]; // %9, ~tyr (galaxy 153)
    out.extend_from_slice(b"urb-watcher");
    out.extend_from_slice(b"btc");
    out.extend_from_slice(b"gw");
    out.push(0x09); // fixed sotx-set version
    // txid: display hex reversed -> LE atom bytes (full 32).
    for i in (0..32).rev() {
        out.push(display[i]);
    }
    out.extend(min_le(vout));
    out.extend(min_le(off));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn golden_txid_1_vout_0_off_0() {
        let r = build_tweak_bytes(&("00".repeat(31) + "01"), 0, 0).unwrap();
        assert_eq!(
            hex(&r),
            "09997572622d776174636865726274636777090100000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn golden_txid_pattern_vout_258_off_1() {
        let r = build_tweak_bytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            258,
            1,
        )
        .unwrap();
        assert_eq!(
            hex(&r),
            "09997572622d77617463686572627463677709efcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301020101",
        );
    }

    #[test]
    fn golden_txid_ff_vout_5_off_1000() {
        let r = build_tweak_bytes(&"ff".repeat(32), 5, 1000).unwrap();
        assert_eq!(
            hex(&r),
            "09997572622d77617463686572627463677709ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff05e803",
        );
    }

    #[test]
    fn omits_zero_vout_off_and_reverses_txid() {
        let r = build_tweak_bytes(&"00".repeat(32), 0, 0).unwrap();
        assert_eq!(r.len(), 1 + 1 + 11 + 3 + 2 + 1 + 32);
        // txid LE atom starts after the 19-byte prefix.
        let tail = build_tweak_bytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            hex(&tail[19..19 + 32]),
            "efcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301",
        );
    }

    #[test]
    fn rejects_bad_length() {
        assert!(build_tweak_bytes("0123", 0, 0).is_err());
        assert!(build_tweak_bytes(&"00".repeat(33), 0, 0).is_err());
    }
}
