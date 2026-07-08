//! WASM spike: the Passport's `urb/` protocol core, compiled to `wasm32` and
//! shown to reproduce the native golden vectors in a browser. These are the
//! *same source files* the device app builds (pulled in verbatim via `#[path]`),
//! proving the protocol engine is platform-free — the only device coupling lives
//! in `main.rs`/`store.rs`/`theme.rs`, none of which are here.
#![allow(dead_code, unused_imports)]

#[path = "../../src/bip39.rs"]
mod bip39;
#[path = "../../src/identity.rs"]
mod identity;
#[path = "../../src/urb/mod.rs"]
mod urb;

use identity::to_patp;
use urb::{boot, encoder, mine, spawn, tweak};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// Decimal string -> little-endian bytes (same helper the source tests use).
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

fn line(out: &mut String, pass: &mut u32, total: &mut u32, name: &str, ok: bool, detail: &str) {
    *total += 1;
    if ok {
        *pass += 1;
    }
    out.push_str(&format!("[{}] {name}\n", if ok { "PASS" } else { "FAIL" }));
    if !detail.is_empty() {
        out.push_str(&format!("       {detail}\n"));
    }
}

/// Re-run a representative slice of the device's golden vectors and report which
/// ones reproduce byte-for-byte. Called from both the wasm ABI and the native bin.
pub fn run_report() -> String {
    let mut out = String::new();
    let (mut pass, mut total) = (0u32, 0u32);

    // 1. %spawn encoder — the bit-exact sotx serialization (Causeway golden).
    let enc = encoder::encode_spawn(&encoder::Spawn {
        pass: dec_le("366213609593416641547364309524750976439928"),
        fief: None,
        to: encoder::SpawnTo {
            spkh: dec_arr32(
                "115520583276441115789036455024003198792587894645174502645738895526012167040478",
            ),
            off: 0,
            tej: 0,
            vout: None,
        },
    });
    let want1 = "010017785634120df0fecaefbeadde01ad7f3434c4bbd5f75dd95fd71720426486a8caec0e31537597b9dbfd1f20426486a8caec7f00";
    line(&mut out, &mut pass, &mut total, "encode_spawn (no-fief/no-vout)", hex(&enc) == want1, "");

    // 2. tweak atom binding the comet to the precommit satpoint.
    let tw = tweak::build_tweak_bytes(&("00".repeat(31) + "01"), 0, 0).unwrap();
    let want2 = "09997572622d776174636865726274636777090100000000000000000000000000000000000000000000000000000000000000";
    line(&mut out, &mut pass, &mut total, "build_tweak_bytes (txid=1)", hex(&tw) == want2, "");

    // 3. @p rendering (comet range, no ob scramble).
    let p = to_patp(&512u16.to_le_bytes());
    line(&mut out, &mut pass, &mut total, "to_patp (512 -> ~binzod)", p == "~binzod", &p);

    // 4. @uw boot-feed encoding across the u128 boundary.
    let mut wide = [0u8; 24];
    wide[23] = 0x01; // 2^184
    let uw = boot::atom_to_uw(&wide);
    line(&mut out, &mut pass, &mut total, "atom_to_uw (2^184)", uw == "0vg.00000.00000.00000.00000.00000.00000", &uw);

    // 5. The whole pipeline in one shot: ed25519 comet mine + BIP-341 taproot
    //    commit/reveal signing, entirely in wasm. Deterministic accept-first mine.
    let mut n = 1u64;
    let rng = move |buf: &mut [u8; 64]| {
        for c in buf.chunks_mut(8) {
            c.copy_from_slice(&n.to_le_bytes());
            n = n.wrapping_add(0x9e3779b97f4a7c15);
        }
    };
    let tw2 = tweak::build_tweak_bytes(&"11".repeat(32), 0, 0).unwrap();
    let mined = mine::mine_until(&tw2, rng, 4, |_| true).unwrap();
    let funding = spawn::FundingInput { txid_display_hex: "11".repeat(32), vout: 0, value: 100_000 };
    let seed = (0u8..16).collect::<Vec<u8>>();
    let r = spawn::assemble_spawn(&seed, &funding, &mined, 2, &[0u8; 32], "https://groundwire.io/causeway/boot.sh").unwrap();
    let ok5 = r.comet_patp.starts_with('~')
        && r.commit_raw_hex.starts_with("020000000001")
        && !r.reveal_raw_hex.is_empty();
    line(
        &mut out,
        &mut pass,
        &mut total,
        "full spawn pipeline (ed25519 mine + taproot sign)",
        ok5,
        &format!("comet {}  commit {}…", r.comet_patp, &r.commit_raw_hex[..40.min(r.commit_raw_hex.len())]),
    );

    out.push_str(&format!("\n{pass}/{total} vectors reproduced in wasm\n"));
    out
}

// ---- raw wasm ABI (no wasm-bindgen) -----------------------------------------
// Convention: byte buffers cross the boundary as a packed `u64` = (ptr<<32)|len
// into the module's exported linear `memory`. Callers allocate inputs with
// `__alloc`, and free every returned buffer with `__dealloc(ptr,len)`. A thin
// hand-written JS/TS wrapper (see causeway) hides all of this.

/// Allocate `len` bytes in wasm memory; returns the pointer. JS writes the input
/// there before calling a function.
#[no_mangle]
pub extern "C" fn __alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// Free a buffer previously returned to JS (input or output).
///
/// # Safety
/// `ptr`/`len` must be a buffer this module handed out and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn __dealloc(ptr: *mut u8, len: usize) {
    drop(Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)));
}

fn pack(bytes: Vec<u8>) -> u64 {
    let b = bytes.into_boxed_slice();
    let (ptr, len) = (b.as_ptr() as u64, b.len() as u64);
    core::mem::forget(b);
    (ptr << 32) | len
}

/// # Safety: `ptr`/`len` must describe a valid input buffer in wasm memory.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    core::slice::from_raw_parts(ptr, len)
}

/// `build_tweak_bytes(txid_display_hex, vout, off)` — the satpoint-binding tweak.
/// Input: UTF-8 hex txid. Output: raw tweak bytes (empty on a bad txid).
///
/// # Safety: `txid_ptr`/`txid_len` must be a valid UTF-8 buffer in wasm memory.
#[no_mangle]
pub unsafe extern "C" fn tweak(txid_ptr: *const u8, txid_len: usize, vout: u64, off: u64) -> u64 {
    let txid = core::str::from_utf8(input(txid_ptr, txid_len)).unwrap_or("");
    pack(tweak::build_tweak_bytes(txid, vout, off).unwrap_or_default())
}

/// `to_patp(atom_le)` — the comet @p. Input: raw little-endian atom bytes.
/// Output: the UTF-8 `~name`.
///
/// # Safety: `atom_ptr`/`atom_len` must be a valid buffer in wasm memory.
#[no_mangle]
pub unsafe extern "C" fn patp(atom_ptr: *const u8, atom_len: usize) -> u64 {
    pack(to_patp(input(atom_ptr, atom_len)).into_bytes())
}

/// `atom_to_uw(le)` — the `@uw` boot-feed rendering. Input: raw LE atom bytes.
/// Output: the UTF-8 `0v…` string.
///
/// # Safety: `atom_ptr`/`atom_len` must be a valid buffer in wasm memory.
#[no_mangle]
pub unsafe extern "C" fn uw(atom_ptr: *const u8, atom_len: usize) -> u64 {
    pack(boot::atom_to_uw(input(atom_ptr, atom_len)).into_bytes())
}

/// `encode_spawn(..)` — the bit-exact `%spawn` sotx serialization.
///
/// Args: `pass` (LE atom bytes), `spkh` (32 LE bytes), `off`, `tej`, `vout`
/// (`< 0` ⇒ absent), and the fief: `fief_kind` `0`=none `2`=If `3`=Is, with the
/// IP as LE integer bytes (4 for If, 16 for Is) and `port`. Output: raw sotx
/// bytes. Matches Causeway `protocol/encoder.ts`.
///
/// # Safety: all `*_ptr`/`*_len` pairs must be valid buffers in wasm memory.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn encode_spawn(
    pass_ptr: *const u8,
    pass_len: usize,
    spkh_ptr: *const u8,
    spkh_len: usize,
    off: u64,
    tej: u64,
    vout: i64,
    fief_kind: i32,
    ip_ptr: *const u8,
    ip_len: usize,
    port: i32,
) -> u64 {
    let pass = input(pass_ptr, pass_len).to_vec();
    let mut spkh = [0u8; 32];
    let s = input(spkh_ptr, spkh_len);
    spkh[..s.len().min(32)].copy_from_slice(&s[..s.len().min(32)]);
    let ip = input(ip_ptr, ip_len);
    let fief = match fief_kind {
        2 => {
            let mut b = [0u8; 4];
            b[..ip.len().min(4)].copy_from_slice(&ip[..ip.len().min(4)]);
            Some(encoder::Fief::If { ip: u32::from_le_bytes(b), port: port as u16 })
        }
        3 => {
            let mut b = [0u8; 16];
            b[..ip.len().min(16)].copy_from_slice(&ip[..ip.len().min(16)]);
            Some(encoder::Fief::Is { ip: u128::from_le_bytes(b), port: port as u16 })
        }
        _ => None,
    };
    let to = encoder::SpawnTo { spkh, off, tej, vout: if vout < 0 { None } else { Some(vout as u64) } };
    pack(encoder::encode_spawn(&encoder::Spawn { pass, fief, to }))
}

/// Self-check: runs [`run_report`] and returns the UTF-8 report (packed ptr/len).
#[no_mangle]
pub extern "C" fn self_test() -> u64 {
    pack(run_report().into_bytes())
}
