//! Taproot transaction construction, BIP-341/342 sighash, and on-device signing
//! for the commit+reveal attestation pattern (Causeway's `chain/` + `signing/`).
//!
//! The device holds the key, so there is no PSBT: it builds the unsigned commit
//! and reveal transactions, computes their taproot sighashes, signs on-device,
//! and emits finalized raw transactions ready to broadcast.
//!
//! The consensus-critical pieces (output-key tweak, tapleaf hash, control block,
//! and the sighash algorithm) are pinned to the canonical BIP-341 wallet test
//! vectors (see tests).

use sha2::{Digest, Sha256};

use crate::identity::{scalar_from, tagged_hash};

// ---- hashing + varint --------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Bitcoin compact-size (varint) encoding.
fn var_int(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn var_slice(data: &[u8]) -> Vec<u8> {
    let mut v = var_int(data.len() as u64);
    v.extend_from_slice(data);
    v
}

// ---- taproot key math (secp256k1 via k256) -----------------------------------

const LEAF_VERSION: u8 = 0xc0;

/// Lift an x-only key to the affine point with even Y (BIP-340 `lift_x`).
fn lift_x_even(x: &[u8; 32]) -> k256::AffinePoint {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let mut enc = [0u8; 33];
    enc[0] = 0x02;
    enc[1..].copy_from_slice(x);
    let ep = k256::EncodedPoint::from_bytes(enc).expect("valid compressed point");
    Option::from(k256::AffinePoint::from_encoded_point(&ep)).expect("x on curve")
}

/// Taproot output key `Q = lift_x(internal) + t·G`, `t = H_TapTweak(internal‖root)`.
/// Returns the x-only output key and whether Q's Y is odd (the control-block parity).
fn taproot_output(internal_x: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> ([u8; 32], bool) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let mut msg = internal_x.to_vec();
    if let Some(r) = merkle_root {
        msg.extend_from_slice(r);
    }
    let t = scalar_from(&tagged_hash("TapTweak", &msg));
    let p = k256::ProjectivePoint::from(lift_x_even(internal_x));
    let q = (p + k256::ProjectivePoint::GENERATOR * t).to_affine();
    let enc = q.to_encoded_point(true);
    let out_x: [u8; 32] = enc.as_bytes()[1..33].try_into().expect("32-byte x");
    (out_x, enc.as_bytes()[0] == 0x03)
}

/// TapLeaf hash of a tapscript at the default leaf version (== merkle root for a
/// single-leaf tree).
fn tapleaf_hash(script: &[u8]) -> [u8; 32] {
    let mut msg = vec![LEAF_VERSION];
    msg.extend_from_slice(&var_slice(script));
    tagged_hash("TapLeaf", &msg)
}

/// Control block for a single-leaf script-path spend: `[leaf_ver|parity] ‖ internal`.
fn control_block(internal_x: &[u8; 32], output_parity_odd: bool) -> Vec<u8> {
    let mut v = vec![LEAF_VERSION | output_parity_odd as u8];
    v.extend_from_slice(internal_x);
    v
}

/// P2TR scriptPubKey: `OP_1 <32-byte output key>`.
fn p2tr_spk(output_x: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(output_x);
    v
}

// ---- the urb attestation leaf (Causeway chain/tapscript.ts) -------------------

fn push_data(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut o = Vec::with_capacity(n + 5);
    if n < 0x4c {
        o.push(n as u8);
    } else if n <= 0xff {
        o.push(0x4c);
        o.push(n as u8);
    } else if n <= 0xffff {
        o.push(0x4d);
        o.push((n & 0xff) as u8);
        o.push((n >> 8) as u8);
    } else {
        o.push(0x4e);
        o.extend_from_slice(&(n as u32).to_le_bytes());
    }
    o.extend_from_slice(data);
    o
}

/// `OP_0 OP_IF "urb" <dat…> OP_ENDIF <xonly> OP_CHECKSIG` (`++unv-to-script`).
pub fn urb_leaf_script(dat: &[u8], xonly: &[u8; 32]) -> Vec<u8> {
    let mut o = vec![0x00, 0x63]; // OP_0 OP_IF
    o.extend_from_slice(&push_data(b"urb"));
    for chunk in dat.chunks(520) {
        o.extend_from_slice(&push_data(chunk));
    }
    o.push(0x68); // OP_ENDIF
    o.extend_from_slice(&push_data(xonly));
    o.push(0xac); // OP_CHECKSIG
    o
}

// ---- transaction model + serialization ---------------------------------------

#[derive(Clone)]
pub struct OutPoint {
    pub txid: [u8; 32], // internal (wire) byte order
    pub vout: u32,
}

#[derive(Clone)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct TxOut {
    pub value: u64,
    pub spk: Vec<u8>,
}

#[derive(Clone)]
pub struct Tx {
    pub version: u32,
    pub ins: Vec<TxIn>,
    pub outs: Vec<TxOut>,
    pub locktime: u32,
}

impl Tx {
    /// Legacy (no-witness) serialization — the preimage for the txid.
    fn serialize_no_witness(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&var_int(self.ins.len() as u64));
        for i in &self.ins {
            v.extend_from_slice(&i.prevout.txid);
            v.extend_from_slice(&i.prevout.vout.to_le_bytes());
            v.push(0x00); // empty scriptSig
            v.extend_from_slice(&i.sequence.to_le_bytes());
        }
        v.extend_from_slice(&var_int(self.outs.len() as u64));
        for o in &self.outs {
            v.extend_from_slice(&o.value.to_le_bytes());
            v.extend_from_slice(&var_slice(&o.spk));
        }
        v.extend_from_slice(&self.locktime.to_le_bytes());
        v
    }

    /// Segwit serialization including the witness — the broadcast wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.version.to_le_bytes());
        v.push(0x00); // marker
        v.push(0x01); // flag
        v.extend_from_slice(&var_int(self.ins.len() as u64));
        for i in &self.ins {
            v.extend_from_slice(&i.prevout.txid);
            v.extend_from_slice(&i.prevout.vout.to_le_bytes());
            v.push(0x00);
            v.extend_from_slice(&i.sequence.to_le_bytes());
        }
        v.extend_from_slice(&var_int(self.outs.len() as u64));
        for o in &self.outs {
            v.extend_from_slice(&o.value.to_le_bytes());
            v.extend_from_slice(&var_slice(&o.spk));
        }
        for i in &self.ins {
            v.extend_from_slice(&var_int(i.witness.len() as u64));
            for item in &i.witness {
                v.extend_from_slice(&var_slice(item));
            }
        }
        v.extend_from_slice(&self.locktime.to_le_bytes());
        v
    }

    /// txid in internal (wire) byte order; reverse for display hex.
    pub fn txid(&self) -> [u8; 32] {
        dsha256(&self.serialize_no_witness())
    }
}

/// A prevout the sighash commits to (value + scriptPubKey).
pub struct Prevout {
    pub value: u64,
    pub spk: Vec<u8>,
}

/// Which spend path a sighash is for.
pub enum SpendPath {
    /// BIP-341 key-path spend.
    Key,
    /// BIP-342 tapscript spend of the given leaf.
    Script { leaf_hash: [u8; 32] },
}

/// BIP-341/342 sighash for SIGHASH_DEFAULT over a single input.
pub fn sighash(tx: &Tx, input_index: usize, prevouts: &[Prevout], path: SpendPath) -> [u8; 32] {
    let mut prevouts_pre = Vec::new();
    let mut amounts_pre = Vec::new();
    let mut spks_pre = Vec::new();
    let mut seqs_pre = Vec::new();
    for (i, inp) in tx.ins.iter().enumerate() {
        prevouts_pre.extend_from_slice(&inp.prevout.txid);
        prevouts_pre.extend_from_slice(&inp.prevout.vout.to_le_bytes());
        amounts_pre.extend_from_slice(&prevouts[i].value.to_le_bytes());
        spks_pre.extend_from_slice(&var_slice(&prevouts[i].spk));
        seqs_pre.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    let mut outs_pre = Vec::new();
    for o in &tx.outs {
        outs_pre.extend_from_slice(&o.value.to_le_bytes());
        outs_pre.extend_from_slice(&var_slice(&o.spk));
    }

    let mut m = Vec::new();
    m.push(0x00); // hash_type = SIGHASH_DEFAULT
    m.extend_from_slice(&tx.version.to_le_bytes());
    m.extend_from_slice(&tx.locktime.to_le_bytes());
    m.extend_from_slice(&sha256(&prevouts_pre));
    m.extend_from_slice(&sha256(&amounts_pre));
    m.extend_from_slice(&sha256(&spks_pre));
    m.extend_from_slice(&sha256(&seqs_pre));
    m.extend_from_slice(&sha256(&outs_pre));

    let ext_flag: u8 = match path {
        SpendPath::Key => 0,
        SpendPath::Script { .. } => 1,
    };
    m.push(2 * ext_flag); // spend_type (annex absent)
    m.extend_from_slice(&(input_index as u32).to_le_bytes());

    if let SpendPath::Script { leaf_hash } = path {
        m.extend_from_slice(&leaf_hash);
        m.push(0x00); // key_version
        m.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // codesep_pos
    }

    // Epoch byte 0x00 precedes SigMsg inside the tagged hash.
    let mut msg = vec![0x00];
    msg.extend_from_slice(&m);
    tagged_hash("TapSighash", &msg)
}

// ---- commit + reveal assembly + signing --------------------------------------

/// The funding UTXO the user paid into the app's funding address.
pub struct FundingUtxo {
    pub txid: [u8; 32], // internal (wire) byte order
    pub vout: u32,
    pub value: u64,
}

/// Finalized, broadcast-ready spawn transactions.
pub struct SpawnTxs {
    pub commit_raw: Vec<u8>,
    pub commit_txid: [u8; 32], // internal order
    pub reveal_raw: Vec<u8>,
    pub reveal_txid: [u8; 32],
    pub commit_value: u64,
    pub reveal_value: u64,
}

/// Build and sign the commit+reveal pair that inscribes `attestation` on the
/// funding sat. Everything is signed on-device with the seed's taproot keys;
/// `aux_rand` is BIP-340 auxiliary randomness (zeros acceptable on the device).
pub fn build_and_sign_spawn(
    seed: &[u8],
    funding: &FundingUtxo,
    attestation: &[u8],
    fee_rate: u64,
    aux_rand: &[u8; 32],
) -> Result<SpawnTxs, String> {
    use crate::identity::{taproot_keypath, taproot_keypath_sign, taproot_scriptpath_sign};

    let kp = taproot_keypath(seed);
    let leaf = urb_leaf_script(attestation, &kp.internal_x);
    let merkle = tapleaf_hash(&leaf);
    let (commit_out_x, commit_parity) = taproot_output(&kp.internal_x, Some(&merkle));
    let commit_spk = p2tr_spk(&commit_out_x);
    let funding_spk = p2tr_spk(&kp.output_x); // the funding address the user paid

    // Commit: spend the funding UTXO (key-path) into the P2TR script-tree output.
    let commit_fee = (11 + 58 + 43) * fee_rate;
    let commit_value = funding
        .value
        .checked_sub(commit_fee)
        .filter(|v| *v > 0)
        .ok_or("funding UTXO too small for commit")?;

    let mut commit = Tx {
        version: 2,
        ins: vec![TxIn {
            prevout: OutPoint { txid: funding.txid, vout: funding.vout },
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outs: vec![TxOut { value: commit_value, spk: commit_spk.clone() }],
        locktime: 0,
    };
    let commit_sighash = sighash(
        &commit,
        0,
        &[Prevout { value: funding.value, spk: funding_spk }],
        SpendPath::Key,
    );
    let commit_sig = taproot_keypath_sign(seed, &commit_sighash, aux_rand);
    commit.ins[0].witness = vec![commit_sig.to_vec()];
    let commit_txid = commit.txid();

    // Reveal: spend the commit output (script-path) exposing the urb leaf.
    let input_weight = 265 + leaf.len() as u64;
    let input_vb = input_weight.div_ceil(4);
    let reveal_vbytes = 11 + input_vb + 43;
    let reveal_fee = reveal_vbytes * fee_rate;
    let reveal_value = commit_value
        .checked_sub(reveal_fee)
        .filter(|v| *v >= 330)
        .ok_or("commit output too small for reveal")?;
    let dest_spk = p2tr_spk(&kp.output_x); // sat returns to the funding address

    let mut reveal = Tx {
        version: 2,
        ins: vec![TxIn {
            prevout: OutPoint { txid: commit_txid, vout: 0 },
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outs: vec![TxOut { value: reveal_value, spk: dest_spk }],
        locktime: 0,
    };
    let reveal_sighash = sighash(
        &reveal,
        0,
        &[Prevout { value: commit_value, spk: commit_spk }],
        SpendPath::Script { leaf_hash: merkle },
    );
    let reveal_sig = taproot_scriptpath_sign(seed, &reveal_sighash, aux_rand);
    reveal.ins[0].witness = vec![reveal_sig.to_vec(), leaf, control_block(&kp.internal_x, commit_parity)];
    let reveal_txid = reveal.txid();

    Ok(SpawnTxs {
        commit_raw: commit.serialize(),
        commit_txid,
        reveal_raw: reveal.serialize(),
        reveal_txid,
        commit_value,
        reveal_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Minimal no-witness tx parser, for feeding the BIP-341 rawUnsignedTx vector.
    fn parse_no_witness(raw: &[u8]) -> Tx {
        let mut p = 0usize;
        let adv = |p: &mut usize, n: usize| {
            let s = raw[*p..*p + n].to_vec();
            *p += n;
            s
        };
        let read_vi = |p: &mut usize| -> u64 {
            let first = raw[*p];
            *p += 1;
            match first {
                0xfd => { let v = u16::from_le_bytes(raw[*p..*p + 2].try_into().unwrap()) as u64; *p += 2; v }
                0xfe => { let v = u32::from_le_bytes(raw[*p..*p + 4].try_into().unwrap()) as u64; *p += 4; v }
                0xff => { let v = u64::from_le_bytes(raw[*p..*p + 8].try_into().unwrap()); *p += 8; v }
                n => n as u64,
            }
        };
        let version = u32::from_le_bytes(adv(&mut p, 4).try_into().unwrap());
        let nin = read_vi(&mut p);
        let mut ins = Vec::new();
        for _ in 0..nin {
            let txid: [u8; 32] = adv(&mut p, 32).try_into().unwrap();
            let vout = u32::from_le_bytes(adv(&mut p, 4).try_into().unwrap());
            let slen = read_vi(&mut p) as usize;
            let _script = adv(&mut p, slen);
            let sequence = u32::from_le_bytes(adv(&mut p, 4).try_into().unwrap());
            ins.push(TxIn { prevout: OutPoint { txid, vout }, sequence, witness: vec![] });
        }
        let nout = read_vi(&mut p);
        let mut outs = Vec::new();
        for _ in 0..nout {
            let value = u64::from_le_bytes(adv(&mut p, 8).try_into().unwrap());
            let slen = read_vi(&mut p) as usize;
            let spk = adv(&mut p, slen);
            outs.push(TxOut { value, spk });
        }
        let locktime = u32::from_le_bytes(adv(&mut p, 4).try_into().unwrap());
        Tx { version, ins, outs, locktime }
    }

    // BIP-341 scriptPubKey[1]: a single-leaf tree — pins tapleaf hash, TapTweak,
    // output key, scriptPubKey, and control-block parity all at once.
    #[test]
    fn bip341_single_leaf_output_and_control_block() {
        let internal = arr32("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        let leaf = unhex("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac");
        let merkle = tapleaf_hash(&leaf);
        assert_eq!(hex(&merkle), "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21");
        let (out_x, parity_odd) = taproot_output(&internal, Some(&merkle));
        assert_eq!(hex(&out_x), "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3");
        assert_eq!(hex(&p2tr_spk(&out_x)), "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3");
        assert!(parity_odd); // control block byte is 0xc1
        assert_eq!(
            hex(&control_block(&internal, parity_odd)),
            "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
        );
    }

    // BIP-341 scriptPubKey[0]: BIP-86 (no script tree) output key tweak.
    #[test]
    fn bip341_keypath_only_output() {
        let internal = arr32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        let (out_x, _) = taproot_output(&internal, None);
        assert_eq!(hex(&out_x), "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
    }

    // BIP-341 keyPathSpending[0], input 4 (SIGHASH_DEFAULT): pins the full sighash
    // algorithm and every intermediary hash.
    #[test]
    fn bip341_keypath_sighash() {
        let raw = unhex("02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d");
        let tx = parse_no_witness(&raw);

        // Nine spent outputs, in input order.
        let spent: [(&str, u64); 9] = [
            ("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420000000),
            ("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462000000),
            ("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294000000),
            ("5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504000000),
            ("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630000000),
            ("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378000000),
            ("512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672000000),
            ("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546000000),
            ("512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588000000),
        ];
        let prevs: Vec<Prevout> = spent
            .iter()
            .map(|(s, v)| Prevout { value: *v, spk: unhex(s) })
            .collect();

        let sh = sighash(&tx, 4, &prevs, SpendPath::Key);
        assert_eq!(hex(&sh), "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef");
    }

    // The full assembly is internally coherent: each signature verifies under the
    // exact key its spend path uses, over the sighash proven correct above.
    #[test]
    fn spawn_txs_sign_under_the_right_keys() {
        use crate::identity::taproot_keypath;
        use k256::schnorr::{Signature, VerifyingKey};

        let seed = (0u8..16).collect::<Vec<u8>>();
        let kp = taproot_keypath(&seed);
        let attestation = crate::urb::encoder::encode_spawn(&crate::urb::encoder::Spawn {
            pass: vec![0x63, 0x01],
            fief: None,
            to: crate::urb::encoder::SpawnTo { spkh: [0x11; 32], off: 0, tej: 0, vout: None },
        });
        let funding = FundingUtxo { txid: [0x11; 32], vout: 1, value: 100_000 };
        let txs = build_and_sign_spawn(&seed, &funding, &attestation, 2, &[0u8; 32]).unwrap();

        assert!(txs.commit_value < funding.value);
        assert!(txs.reveal_value < txs.commit_value);

        // Reconstruct the commit input's sighash and verify the key-path signature
        // under the funding address key.
        let leaf = urb_leaf_script(&attestation, &kp.internal_x);
        let merkle = tapleaf_hash(&leaf);
        let (commit_out_x, commit_parity) = taproot_output(&kp.internal_x, Some(&merkle));
        let commit = Tx {
            version: 2,
            ins: vec![TxIn {
                prevout: OutPoint { txid: funding.txid, vout: funding.vout },
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outs: vec![TxOut { value: txs.commit_value, spk: p2tr_spk(&commit_out_x) }],
            locktime: 0,
        };
        let commit_sh = sighash(
            &commit,
            0,
            &[Prevout { value: funding.value, spk: p2tr_spk(&kp.output_x) }],
            SpendPath::Key,
        );
        // Witness item 0 of the finalized commit is the signature.
        let finalized = parse_witness_first_item(&txs.commit_raw);
        let vk = VerifyingKey::from_bytes(&kp.output_x).unwrap();
        vk.verify_raw(&commit_sh, &Signature::try_from(&finalized[..]).unwrap())
            .expect("commit key-path sig valid under funding key");

        // Reveal script-path signature verifies under the internal (leaf) key.
        let reveal = Tx {
            version: 2,
            ins: vec![TxIn {
                prevout: OutPoint { txid: txs.commit_txid, vout: 0 },
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outs: vec![TxOut { value: txs.reveal_value, spk: p2tr_spk(&kp.output_x) }],
            locktime: 0,
        };
        let reveal_sh = sighash(
            &reveal,
            0,
            &[Prevout { value: txs.commit_value, spk: p2tr_spk(&commit_out_x) }],
            SpendPath::Script { leaf_hash: merkle },
        );
        let reveal_sig = parse_witness_first_item(&txs.reveal_raw);
        let vk_internal = VerifyingKey::from_bytes(&kp.internal_x).unwrap();
        vk_internal
            .verify_raw(&reveal_sh, &Signature::try_from(&reveal_sig[..]).unwrap())
            .expect("reveal script-path sig valid under internal key");

        // Control block parity matches the commit output.
        assert_eq!(control_block(&kp.internal_x, commit_parity)[0], 0xc0 | commit_parity as u8);
    }

    // Pull witness item 0 of input 0 from a finalized segwit tx (test helper).
    fn parse_witness_first_item(raw: &[u8]) -> Vec<u8> {
        // version(4) marker(1) flag(1)
        let mut p = 6usize;
        let read_vi = |raw: &[u8], p: &mut usize| -> u64 {
            let f = raw[*p];
            *p += 1;
            match f {
                0xfd => { let v = u16::from_le_bytes(raw[*p..*p+2].try_into().unwrap()) as u64; *p+=2; v }
                0xfe => { let v = u32::from_le_bytes(raw[*p..*p+4].try_into().unwrap()) as u64; *p+=4; v }
                0xff => { let v = u64::from_le_bytes(raw[*p..*p+8].try_into().unwrap()); *p+=8; v }
                n => n as u64,
            }
        };
        let nin = read_vi(raw, &mut p);
        for _ in 0..nin {
            p += 36; // outpoint
            let sl = read_vi(raw, &mut p) as usize;
            p += sl + 4; // scriptSig + sequence
        }
        let nout = read_vi(raw, &mut p);
        for _ in 0..nout {
            p += 8;
            let sl = read_vi(raw, &mut p) as usize;
            p += sl;
        }
        // witness of input 0
        let items = read_vi(raw, &mut p);
        assert!(items >= 1);
        let ilen = read_vi(raw, &mut p) as usize;
        raw[p..p + ilen].to_vec()
    }
}
