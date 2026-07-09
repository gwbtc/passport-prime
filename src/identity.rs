//! Groundwire identity derivation — the device-side half of `gw-onboard`.
//!
//! The master ticket is a random `@q` value used *directly* as the BIP-32 seed
//! (no BIP-39 mnemonic / PBKDF2 step). From it `gw-onboard` derives:
//!   - the Bitcoin funding/attestation key at taproot path `m/86'/1'/0'/0/0`
//!   - the ship's ed25519 networking keypair (Suite C, from the seed atom)
//!
//! This module currently implements only the parts that need no external crypto
//! crate: random-ticket generation and `@q` rendering. The BIP-32 / taproot /
//! ed25519 derivation is specified in `docs/identity-derivation.md` and is wired
//! up in the implementation phase behind the byte-exact test vectors there.
//!
//! ponytail: the authoritative encoding is pinned by cross-impl test vectors in
//! docs/identity-derivation.md; this file must match gw-onboard, not the reverse.

/// Urbit `@q`/`@p` syllable tables (public constants from urbit-ob `co.js`).
/// 256 three-letter prefixes and 256 suffixes.
const PRE: &str = "dozmarbinwansamlitsighidfidlissogdirwacsabwissibrigsoldopmodfoglidhopdardorlorhodfolrintogsilmirholpaslacrovlivdalsatlibtabhanticpidtorbolfosdotlosdilforpilramtirwintadbicdifrocwidbisdasmidloprilnardapmolsanlocnovsitnidtipsicropwitnatpanminritpodmottamtolsavposnapnopsomfinfonbanmorworsipronnorbotwicsocwatdolmagpicdavbidbaltimtasmalligsivtagpadsaldivdactansidfabtarmonranniswolmispallasdismaprabtobrollatlonnodnavfignomnibpagsopralbilhaddocridmocpacravripfaltodtiltinhapmicfanpattaclabmogsimsonpinlomrictapfirhasbosbatpochactidhavsaplindibhosdabbitbarracparloddosbortochilmactomdigfilfasmithobharmighinradmashalraglagfadtopmophabnilnosmilfopfamdatnoldinhatnacrisfotribhocnimlarfitwalrapsarnalmoslandondanladdovrivbacpollaptalpitnambonrostonfodponsovnocsorlavmatmipfip";
const SUF: &str = "zodnecbudwessevpersutletfulpensytdurwepserwylsunrypsyxdyrnuphebpeglupdepdysputlughecryttyvsydnexlunmeplutseppesdelsulpedtemledtulmetwenbynhexfebpyldulhetmevruttylwydtepbesdexsefwycburderneppurrysrebdennutsubpetrulsynregtydsupsemwynrecmegnetsecmulnymtevwebsummutnyxrextebfushepbenmuswyxsymselrucdecwexsyrwetdylmynmesdetbetbeltuxtugmyrpelsyptermebsetdutdegtexsurfeltudnuxruxrenwytnubmedlytdusnebrumtynseglyxpunresredfunrevrefmectedrusbexlebduxrynnumpyxrygryxfeptyrtustyclegnemfermertenlusnussyltecmexpubrymtucfyllepdebbermughuttunbylsudpemdevlurdefbusbeprunmelpexdytbyttyplevmylwedducfurfexnulluclennerlexrupnedlecrydlydfenwelnydhusrelrudneshesfetdesretdunlernyrsebhulrylludremlysfynwerrycsugnysnyllyndyndemluxfedsedbecmunlyrtesmudnytbyrsenwegfyrmurtelreptegpecnelnevfes";

fn syl(table: &str, i: u8) -> &str {
    let i = i as usize * 3;
    &table[i..i + 3]
}

/// Render an atom (little-endian bytes) as an Urbit `@p` name — for a mined
/// comet and its boot command.
///
/// ponytail: the `ob` obfuscation cipher (`fein`) is the **identity** for atoms
/// ≥ 2⁶⁴ — its recursion bands top out at 64 bits (urbit-ob `ob.js`). A mined
/// comet is 128-bit, so `@p` is just the raw syllable rendering with `@p`
/// separators; no murmur3/Feistel is needed. Planets/moons (2¹⁶‥2⁶⁴) *would*
/// need the scramble, but a comet never lands there — hence the debug guard.
pub fn to_patp(atom_le: &[u8]) -> String {
    let mut sig = atom_le.len();
    while sig > 0 && atom_le[sig - 1] == 0 {
        sig -= 1;
    }
    if sig == 0 {
        return "~zod".to_string();
    }
    if sig <= 1 {
        return format!("~{}", syl(SUF, atom_le[0])); // galaxy
    }
    debug_assert!(sig <= 2 || sig >= 9, "to_patp is comet-scoped; the 2¹⁶‥2⁶⁴ range needs the ob scramble");

    // Significant 16-bit words = ceil(sig_bytes / 2); render most-significant
    // first with `--` every fourth word boundary, `-` otherwise.
    let dyy = sig.div_ceil(2);
    let mut acc = String::new();
    for timp in 0..dyy {
        let lo = atom_le.get(2 * timp).copied().unwrap_or(0); // suffix byte
        let hi = atom_le.get(2 * timp + 1).copied().unwrap_or(0); // prefix byte
        let etc = if timp % 4 == 0 {
            if timp == 0 { "" } else { "--" }
        } else {
            "-"
        };
        acc = format!("{}{}{}{}", syl(PRE, hi), syl(SUF, lo), etc, acc);
    }
    format!("~{acc}")
}

/// A freshly generated identity, ready to show on the create screen.
pub struct IdentityDraft {
    /// The taproot funding address the user pays into.
    pub funding_address: String,
    /// The 128-bit seed as a BIP-39 mnemonic — the user's backup (see `crate::bip39`).
    pub mnemonic: String,
}

/// Generate a new 128-bit identity: its funding address and mnemonic backup.
/// `entropy` is the 16-byte seed (dice pool, see `EntropyPool`), used directly
/// as the BIP-32 seed on-device.
pub fn new_identity(entropy: [u8; 16]) -> IdentityDraft {
    IdentityDraft {
        funding_address: derive_funding_address(&entropy),
        mnemonic: crate::bip39::to_mnemonic(&entropy),
    }
}

/// Derive the BIP-86 taproot funding address at `m/86'/1'/0'/0/0`, mainnet
/// bech32m. Matches gw-onboard `derive_taproot_address` (embit `script.p2tr`).
/// See `docs/identity-derivation.md`. This is the money path — the tests below
/// pin it to three vectors captured from the real gw-onboard binary.
pub fn derive_funding_address(seed: &[u8]) -> String {
    let kp = taproot_keypath(seed);
    bech32::segwit::encode(
        bech32::hrp::Hrp::parse("bc").unwrap(),
        bech32::Fe32::P, // witness version 1
        &kp.output_x,
    )
    .expect("valid taproot witness program")
}

/// The BIP-341 key material for `m/86'/1'/0'/0/0`, in both roles the on-device
/// spawner needs: the *internal* key (even-Y secret + x-only) that the commit's
/// taproot script tree and reveal's script-path CHECKSIG use, and the *output*
/// key (empty-tweak secret + x-only) that is the funding address and signs the
/// commit's key-path input.
pub(crate) struct KeyPath {
    pub d_internal: k256::Scalar,
    pub internal_x: [u8; 32],
    pub d_output: k256::Scalar,
    pub output_x: [u8; 32],
}

/// Derive [`KeyPath`] for `m/86'/1'/0'/0/0`. One computation feeds every role, so
/// the address, the leaf's committed key, and both signatures stay consistent.
pub(crate) fn taproot_keypath(seed: &[u8]) -> KeyPath {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ProjectivePoint;

    // BIP-32 master from seed, then m/86'/1'/0'/0/0.
    let i = hmac_sha512(b"Bitcoin seed", seed);
    let mut k = scalar_from(&i[..32]);
    let mut chain = to_arr32(&i[32..]);
    const H: u32 = 0x8000_0000;
    for &index in &[86 | H, 1 | H, H, 0, 0] {
        let mut data = [0u8; 37];
        if index & H != 0 {
            // hardened: 0x00 || ser256(k_par)
            data[1..33].copy_from_slice(&k.to_bytes());
        } else {
            // normal: serP(point(k_par)) — 33-byte compressed pubkey
            let pt = (ProjectivePoint::GENERATOR * k).to_affine();
            data[..33].copy_from_slice(pt.to_encoded_point(true).as_bytes());
        }
        data[33..].copy_from_slice(&index.to_be_bytes());
        let ii = hmac_sha512(&chain, &data);
        k = scalar_from(&ii[..32]) + k;
        chain = to_arr32(&ii[32..]);
    }

    // Even-Y convention: negate the secret when the internal point has odd Y, so
    // the x-only key we commit to is the even-Y lift. t = H_TapTweak(x); the
    // output key (no script tree) is d_internal + t.
    let internal = (ProjectivePoint::GENERATOR * k).to_affine();
    let enc = internal.to_encoded_point(true);
    let internal_x: [u8; 32] = enc.as_bytes()[1..33].try_into().expect("32-byte x");
    let d_internal = if enc.as_bytes()[0] == 0x03 { -k } else { k };
    let t = scalar_from(&tagged_hash("TapTweak", &internal_x));
    let d_output = d_internal + t;
    let output = (ProjectivePoint::GENERATOR * d_output).to_affine();
    let output_x: [u8; 32] = output.to_encoded_point(true).as_bytes()[1..33]
        .try_into()
        .expect("32-byte x coordinate");
    KeyPath { d_internal, internal_x, d_output, output_x }
}

/// Sign a BIP-341 key-path spend: a BIP-340 Schnorr signature over `sighash` (the
/// 32-byte TapSighash of the unsigned self-spend) with this seed's taproot-tweaked
/// funding key. The private key is derived and used **entirely on-device**; only
/// the 64-byte signature leaves. This is the model-(b) core — the host builds the
/// unsigned transaction and never sees the key.
///
/// `aux_rand` is BIP-340 auxiliary randomness — pass fresh CSPRNG bytes on the
/// host/sim; the xous device (no app TRNG, docs/trng-spike.md) may pass zeros, at
/// the cost of the nonce side-channel hardening aux_rand would add.
pub fn taproot_keypath_sign(seed: &[u8], sighash: &[u8; 32], aux_rand: &[u8; 32]) -> [u8; 64] {
    schnorr_sign(&taproot_keypath(seed).d_output, sighash, aux_rand)
}

/// Sign a BIP-342 tapscript (script-path) spend: a BIP-340 Schnorr signature over
/// the tapscript `sighash` with this seed's *internal* key — the key the reveal
/// leaf's `<xonly> OP_CHECKSIG` verifies against. Used to spend the commit output
/// and expose the urb attestation. Key stays on-device; only the signature leaves.
pub(crate) fn taproot_scriptpath_sign(seed: &[u8], sighash: &[u8; 32], aux_rand: &[u8; 32]) -> [u8; 64] {
    schnorr_sign(&taproot_keypath(seed).d_internal, sighash, aux_rand)
}

fn schnorr_sign(secret: &k256::Scalar, sighash: &[u8; 32], aux_rand: &[u8; 32]) -> [u8; 64] {
    // from_bytes normalizes the key's Y parity per BIP-340 internally.
    let sk = k256::schnorr::SigningKey::from_bytes(&secret.to_bytes())
        .expect("non-zero signing key");
    sk.sign_raw(sighash, aux_rand).expect("schnorr sign").to_bytes()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use hmac::{Mac, SimpleHmac};
    let mut m = <SimpleHmac<sha2::Sha512>>::new_from_slice(key).expect("hmac key");
    m.update(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

pub(crate) fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let th = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(th);
    h.update(th);
    h.update(msg);
    to_arr32(&h.finalize())
}

pub(crate) fn scalar_from(bytes: &[u8]) -> k256::Scalar {
    use k256::elliptic_curve::ops::Reduce;
    // BIP-32/BIP-341 treat a >= n scalar as invalid (skip index / abort); that
    // has ~2^-128 probability. Rather than panic the app on that unreachable
    // event, reduce mod n — total, and byte-identical to from_repr for every
    // value < n (i.e. all of them in practice, so the pinned vectors are unchanged).
    // Scalar: Reduce<U256> and Reduce<U512>, so pin the U256 impl.
    <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&k256::FieldBytes::from(to_arr32(bytes)))
}

fn to_arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical urbit-ob @p anchors. Galaxies/stars are below the scramble band
    // and the 38-byte value is above it, so all render without the ob cipher —
    // exactly the ranges a 128-bit comet renderer touches.
    #[test]
    fn patp_known_vectors() {
        assert_eq!(to_patp(&[]), "~zod");
        assert_eq!(to_patp(&200u16.to_le_bytes()[..1]), "~lex"); // galaxy 200
        assert_eq!(to_patp(&512u16.to_le_bytes()), "~binzod");
        assert_eq!(to_patp(&1024u16.to_le_bytes()), "~samzod");
        // hex2patp("7468...7079") — big-endian; reverse to little-endian bytes.
        let be = hex16("7468697320697320736f6d6520766572792068696768207175616c69747920656e74726f7079");
        let le: Vec<u8> = be.into_iter().rev().collect();
        assert_eq!(
            to_patp(&le),
            "~divmes-davset-holdet--sallun-salpel-taswet-holtex--watmeb-tarlun-picdet-magmes--holter-dacruc-timdet-divtud--holwet-maldut-padpel-sivtud",
        );
    }

    // Vectors captured from the real gw-onboard binary (see docs/identity-derivation.md).
    #[test]
    fn funding_address_vectors() {
        // Fresh path: 16 entropy bytes used directly.
        assert_eq!(
            derive_funding_address(&(0u8..16).collect::<Vec<_>>()),
            "bc1pzh75rtx74l85v2xqfr5uln7mhy40vyqzm68ml4yngcqy9v085tqqmgg72j"
        );
        assert_eq!(
            derive_funding_address(&hex16("deadbeef00112233445566778899aabb")),
            "bc1pft80yrj8lw8ewmm75s9m04qygt73k4z70jqmes9d8u47te38c9cqxpj5gl"
        );
    }

    // Model-(b) signer self-check: the funding key signs, and the signature
    // verifies under the x-only output key taken from the funding ADDRESS. If the
    // taproot tweak or the even-Y handling were wrong, the signing key would not
    // match the address key and verification would fail. (Cross-impl parity with
    // gw-onboard still needs a reference signature vector — tracked separately.)
    #[test]
    fn keypath_sign_verifies_under_the_address_key() {
        use k256::schnorr::{Signature, VerifyingKey};
        for seed in [(0u8..16).collect::<Vec<u8>>(), hex16("deadbeef00112233445566778899aabb")] {
            let out_x = taproot_keypath(&seed).output_x;
            // The signer's output key is exactly the address's witness program.
            let (_hrp, _ver, program) = bech32::segwit::decode(&derive_funding_address(&seed)).unwrap();
            assert_eq!(&out_x[..], program.as_slice(), "output key == address program");

            // Sign a sample TapSighash on-device; verify with the address's key.
            let sighash = [0x42u8; 32];
            let sig = taproot_keypath_sign(&seed, &sighash, &[0u8; 32]);
            let vk = VerifyingKey::from_bytes(&out_x).unwrap();
            vk.verify_raw(&sighash, &Signature::try_from(&sig[..]).unwrap())
                .expect("signature valid under the funding address's key");
        }
    }

    fn hex16(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
