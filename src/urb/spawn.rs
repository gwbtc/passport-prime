//! End-to-end on-device spawn: given the app's seed and the funding UTXO, mine
//! the comet, encode the `%spawn` attestation, build and sign the commit+reveal
//! transactions, and format the boot command. This is the whole of Architecture
//! B's happy path, tying together [`mine`], [`encoder`], [`tweak`], [`tx`], and
//! [`boot`] with the device's own taproot keys.

use sha2::{Digest, Sha256};

use crate::identity::{taproot_keypath, to_patp};

use super::{boot, encoder, mine, tweak, tx};

/// The funding UTXO the user paid into the app's funding address, as learned
/// from a block explorer (scanned QR or typed).
pub struct FundingInput {
    pub txid_display_hex: String, // explorer/display byte order
    pub vout: u32,
    pub value: u64,
}

/// Parse `txid:vout:sats` (explorer QR payload or manual entry).
pub fn parse_funding(s: &str) -> Result<FundingInput, String> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 3 {
        return Err("expected txid:vout:sats".into());
    }
    let txid = parts[0].trim().to_ascii_lowercase();
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("txid must be 64 hex chars".into());
    }
    let vout: u32 = parts[1].trim().parse().map_err(|_| "vout must be a number")?;
    let value: u64 = parts[2].trim().parse().map_err(|_| "sats must be a number")?;
    if value == 0 {
        return Err("sats must be greater than 0".into());
    }
    Ok(FundingInput { txid_display_hex: txid, vout, value })
}

/// `spkh = sha256(scriptPubKey || u64le(value))` — the sat identity urb-core
/// binds the comet to (matches `boot.hoon`'s extract-spawn-fields).
///
/// Verified against Causeway `spawn/assemble.ts`: the hash is over the
/// **precommit/funding** UTXO's spk and value (the input being spent), NOT the
/// reveal destination. `assemble_spawn` accordingly feeds `funding.value` and
/// `funding.vout` — do not "correct" these to the reveal output's value.
fn compute_spkh(spk: &[u8], value: u64) -> [u8; 32] {
    let mut buf = spk.to_vec();
    buf.extend_from_slice(&value.to_le_bytes());
    Sha256::digest(&buf).into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn display_hex_to_wire(display_hex: &str) -> Result<[u8; 32], String> {
    if display_hex.len() != 64 {
        return Err("txid must be 64 hex chars".into());
    }
    let mut wire = [0u8; 32];
    for i in 0..32 {
        let b = u8::from_str_radix(&display_hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        wire[31 - i] = b; // display is wire reversed
    }
    Ok(wire)
}

fn wire_to_display(wire: &[u8; 32]) -> String {
    let mut d = *wire;
    d.reverse();
    hex(&d)
}

/// Everything the wizard shows after a successful on-device spawn.
pub struct SpawnResult {
    pub comet_patp: String,
    pub comet_atom: [u8; 16],
    pub commit_raw_hex: String,
    pub commit_txid_display: String,
    pub reveal_raw_hex: String,
    pub reveal_txid_display: String,
    pub boot_command: String,
}

/// The p2tr scriptPubKey of the app's own funding address.
fn funding_spk(output_x: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(output_x);
    v
}

/// Build the attestation + signed transactions + boot command for an already
/// mined comet. Split from [`spawn_identity`] so it can be exercised without the
/// slow star search.
pub fn assemble_spawn(
    seed: &[u8],
    funding: &FundingInput,
    mined: &mine::Mined,
    fee_rate: u64,
    aux_rand: &[u8; 32],
    boot_script_url: &str,
) -> Result<SpawnResult, String> {
    let kp = taproot_keypath(seed);
    let spk = funding_spk(&kp.output_x);
    let spkh = compute_spkh(&spk, funding.value);

    let attestation = encoder::encode_spawn(&encoder::Spawn {
        pass: mined.pass.clone(),
        fief: None,
        to: encoder::SpawnTo {
            spkh,
            off: 0,
            tej: 0,
            vout: if funding.vout == 0 { None } else { Some(funding.vout as u64) },
        },
    });

    let txs = tx::build_and_sign_spawn(
        seed,
        &tx::FundingUtxo {
            txid: display_hex_to_wire(&funding.txid_display_hex)?,
            vout: funding.vout,
            value: funding.value,
        },
        &attestation,
        fee_rate,
        aux_rand,
    )?;

    let feed = boot::jam_feed(&mined.comet, 0, 1, &mined.ring_atom);
    let comet_patp = to_patp(&mined.comet);
    let boot_command = boot::format_boot_command(&comet_patp, &feed, boot_script_url, None);

    Ok(SpawnResult {
        comet_patp,
        comet_atom: mined.comet,
        commit_raw_hex: hex(&txs.commit_raw),
        commit_txid_display: wire_to_display(&txs.commit_txid),
        reveal_raw_hex: hex(&txs.reveal_raw),
        reveal_txid_display: wire_to_display(&txs.reveal_txid),
        boot_command,
    })
}

/// A resumable spawn: the slow star search split into bounded batches so the UI
/// can mine a chunk per frame and stay responsive (mining ~65k iterations blocks
/// for minutes on-device if run in one shot). [`SpawnJob::step`] mines up to
/// `batch` iterations and, once a `~daplyd` comet lands, assembles the signed
/// commit+reveal in the same call.
pub struct SpawnJob {
    seed: Vec<u8>,
    funding: FundingInput,
    tweak: Vec<u8>,
    rng: Box<dyn FnMut(&mut [u8; 64])>,
    fee_rate: u64,
    aux_rand: [u8; 32],
    boot_script_url: String,
    /// Iterations mined so far — for the progress readout.
    pub tries: u64,
    budget: u64,
}

/// One `step` outcome.
pub enum SpawnStep {
    /// Still searching; `tries` on the job has advanced.
    Working,
    /// Found and fully signed.
    Done(Box<SpawnResult>),
    /// Terminal error: budget exhausted, or the funding UTXO was too small to
    /// cover the commit+reveal fees.
    Failed(String),
}

impl SpawnJob {
    /// Set up a spawn (compute the tweak); mining happens in [`step`](Self::step).
    pub fn new(
        seed: &[u8],
        funding: FundingInput,
        fee_rate: u64,
        rng: impl FnMut(&mut [u8; 64]) + 'static,
        aux_rand: [u8; 32],
        boot_script_url: &str,
    ) -> Result<SpawnJob, String> {
        let tweak = tweak::build_tweak_bytes(&funding.txid_display_hex, funding.vout as u64, 0)?;
        Ok(SpawnJob {
            seed: seed.to_vec(),
            funding,
            tweak,
            rng: Box::new(rng),
            fee_rate,
            aux_rand,
            boot_script_url: boot_script_url.to_string(),
            tries: 0,
            budget: 5_000_000,
        })
    }

    /// Mine up to `batch` iterations. On a hit, assembles and returns the signed
    /// transactions; otherwise reports progress so the caller can call again.
    pub fn step(&mut self, batch: u64) -> SpawnStep {
        let hit = mine::mine_until(&self.tweak, &mut *self.rng, batch, |s| s == mine::REQUIRED_STAR);
        match hit {
            Some(mined) => match assemble_spawn(
                &self.seed,
                &self.funding,
                &mined,
                self.fee_rate,
                &self.aux_rand,
                &self.boot_script_url,
            ) {
                Ok(r) => SpawnStep::Done(Box::new(r)),
                Err(e) => SpawnStep::Failed(e), // assembly only fails on a too-small UTXO
            },
            None => {
                self.tries += batch;
                if self.tries >= self.budget {
                    SpawnStep::Failed("mining exhausted its budget".into())
                } else {
                    SpawnStep::Working
                }
            }
        }
    }
}

/// Mine a `~daplyd` comet bound to the funding sat, then assemble everything.
/// `rng` must supply CSPRNG bytes; mining is the slow step (~65k iterations).
pub fn spawn_identity(
    seed: &[u8],
    funding: &FundingInput,
    fee_rate: u64,
    rng: impl FnMut(&mut [u8; 64]),
    aux_rand: &[u8; 32],
    boot_script_url: &str,
) -> Result<SpawnResult, String> {
    let tw = tweak::build_tweak_bytes(&funding.txid_display_hex, funding.vout as u64, 0)?;
    let mined = mine::mine(&tw, rng, 5_000_000).ok_or("mining exhausted its budget")?;
    assemble_spawn(seed, funding, &mined, fee_rate, aux_rand, boot_script_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_funding_accepts_and_rejects() {
        let f = parse_funding(&format!("  {}:2:100000 ", "AB".repeat(32))).unwrap();
        assert_eq!(f.txid_display_hex.len(), 64);
        assert_eq!(f.txid_display_hex, "ab".repeat(32)); // lowercased
        assert_eq!(f.vout, 2);
        assert_eq!(f.value, 100_000);
        assert!(parse_funding("deadbeef:0:1").is_err()); // short txid
        assert!(parse_funding(&format!("{}:0", "aa".repeat(32))).is_err()); // missing field
        assert!(parse_funding(&format!("{}:x:1", "aa".repeat(32))).is_err()); // bad vout
        assert!(parse_funding(&format!("{}:0:0", "aa".repeat(32))).is_err()); // zero value
    }

    #[test]
    fn display_wire_roundtrip() {
        let d = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(wire_to_display(&display_hex_to_wire(d).unwrap()), d);
    }

    // Full assembly over an accept-first-try "mine" — deterministic and fast.
    // Proves the whole B pipeline wires together end to end; the crypto inside
    // is pinned by the encoder/tx/boot vector tests.
    #[test]
    fn assemble_produces_a_coherent_spawn() {
        // Deterministic counter RNG (test-only).
        let mut n = 1u64;
        let rng = move |buf: &mut [u8; 64]| {
            for c in buf.chunks_mut(8) {
                c.copy_from_slice(&n.to_le_bytes());
                n = n.wrapping_add(0x9e3779b97f4a7c15);
            }
        };
        let tw = tweak::build_tweak_bytes(&"11".repeat(32), 0, 0).unwrap();
        let mined = mine::mine_until(&tw, rng, 4, |_| true).unwrap();

        let seed = (0u8..16).collect::<Vec<u8>>();
        let funding = FundingInput { txid_display_hex: "11".repeat(32), vout: 0, value: 100_000 };
        let r = assemble_spawn(&seed, &funding, &mined, 2, &[0u8; 32], "https://groundwire.io/causeway/boot.sh").unwrap();

        assert!(r.comet_patp.starts_with('~'));
        assert!(!r.commit_raw_hex.is_empty() && r.commit_raw_hex.len() % 2 == 0);
        assert!(!r.reveal_raw_hex.is_empty());
        assert_eq!(r.commit_txid_display.len(), 64);
        assert!(r.boot_command.contains(&r.comet_patp));
        assert!(r.boot_command.contains("--feed 0v"));
        // Segwit marker present in the finalized commit tx (version 02000000, 00 01).
        assert!(r.commit_raw_hex.starts_with("020000000001"));
    }
}
