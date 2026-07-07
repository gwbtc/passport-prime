# Groundwire identity derivation — shared spec

This is the **contract** between the Passport Prime app (`src/identity.rs`) and
host `gw-onboard`. Both must derive identical values from the same master
ticket, or a device-created identity won't match the comet the host mines and
funds. Reverse-engineered from `gw-onboard` (release
`groundwire-daily-2026.7.6`); treat the **test vectors** at the bottom as the
authority — implement to pass them, don't trust this prose over a failing test.

## Master ticket

- A random **`@q`** value. The app uses **128 bits (16 bytes)**; confirm this
  matches `gw-onboard`'s length before shipping (vector TV-3).
- Rendered with the Urbit **patq** syllable encoding (see below). It is the
  ship login *and* the HD wallet seed — one secret, everything derives from it.

### `@q` (patq) encoding — implemented, tested

Tables: the public urbit-ob 256-prefix / 256-suffix syllable sets (embedded in
`src/identity.rs`, sourced from urbit-ob `co.js`). Rendering:

- Pair the seed bytes high-to-low; if odd length, pad **one leading zero byte**.
- Each pair `(hi, lo)` → `prefix[hi] + suffix[lo]` (a 6-letter word).
- Join words with `-`, prepend `~`. Leading zero bytes are **preserved**
  (unlike `@p`), so 16 bytes always render as exactly 8 dashed words.

## Seed → BIP-32 (IMPLEMENTED — `src/identity.rs`)

Decompiled from `gw-onboard` (`main`, `decode_q`), verified by running the real
binary. Two paths that can disagree:

**Fresh generation:**
```
seed_bytes = secrets.token_bytes(16)      # the 16 bytes ARE the BIP-32 seed
master_ticket = encode_q(int.from_bytes(seed_bytes, 'little'))   # display only
```
So on the create path, the 16 TRNG bytes are the seed directly; the `@q` is just
their backup encoding. `src/identity.rs::new_identity` does exactly this.

**Resume (typed-in ticket):**
```
seed_int   = decode_q(ticket)             # int.from_bytes(syllable_bytes, 'little')
n_bytes    = (seed_int.bit_length() + 7) // 8      # MINIMAL width
seed_bytes = seed_int.to_bytes(n_bytes, 'little')  # drops leading-zero high bytes
```
⚠️ **The minimal-width step means resume can differ from fresh** when the seed's
high byte is zero (≈1/256): fresh derives from 16 bytes, resume from fewer, so
the funding address differs. `src/identity.rs::funding_address_for_ticket`
replicates the resume path; matching each app path to the corresponding
gw-onboard path is the correct behavior. No BIP-39, no PBKDF2, no salt.

## Bitcoin funding / attestation key (IMPLEMENTED)

- Path **`m/86'/1'/0'/0/0`** — BIP-86 keypath taproot. Coin type is **1'**, but
  the address is rendered on **mainnet** (`bc1p…`, embit `NETWORKS['main']`).
  Confirmed against the real binary — the "testnet coin type" does not make it a
  testnet address.
- Address: plain **BIP-86 keypath** p2tr, bech32m — embit `script.p2tr(child.key)`.
  (The "single-leaf script tree" docstrings belong to `tapscript_address`, a
  *different* function used elsewhere, not to the funding address.)
- Rust: `derive_funding_address` in `src/identity.rs` — HMAC-SHA512 BIP-32 via
  `k256`, BIP-341 even-Y keypath tweak, `bech32` v1. Builds for
  `armv7a-unknown-xous-elf`.
- This key funds the address **and signs the attestation** (commit + reveal tx
  pair — `gw-onboard` builds both and returns `(commit_txid, reveal_txid)`).
- **This is the key that must move to the Passport.** On device: parse the
  unsigned PSBT, verify the committed tweak matches this ID's derived comet
  (below) *before* showing the confirm screen, sign on user confirmation.

## Networking keypair — Suite C (NOT YET IMPLEMENTED)

Urbit ed25519, from the seed atom. `gw-onboard` docstrings:

> Hoon `luck:ed`: derive ed25519 keypair from seed atom.
> `h = SHA-512(first 32 bytes of seed)`; `a = scalarmult-base`(clamped h).
> Derive the Suite C pass (public networking key) from a ring.

Suite C ring format: tag byte `'C'` (0x43) then key material; `ring_byte_len`
and `derive_pass_from_ring` replicate Hoon's `pub:ex:(nol:nu:cric:crypto ring)`.
Uses `crypto_scalarmult_ed25519_base_noclamp` (libsodium). Match `luck:ed` and
the Suite C ring layout exactly — pin with TV-6.

## Comet tweak / attestation binding

The comet is bound to the Bitcoin tx via `comet_miner --tweak <hoon-expr>`:

> Tweak format **v9**: `(rap 3 ~[%9 ~tyr %urb-watcher %btc %gw %9 txid vout off])`

Because the tweak includes **txid + vout**, mining happens **after** the funding
tx exists. Consequence for the device design: the mining seed / nonce scheme in
the proposal must account for the txid being an input to the tweak — the device
confirms the derived comet against the tweak that commits its own funding txid.

## Division of labor (see integration proposal)

| Value | Derived where | Notes |
|---|---|---|
| Master ticket (`@q`) | **Device** | never leaves Passport |
| Taproot funding key `m/86'/1'/0'/0/0` | **Device** | address exported watch-only; signs attestation |
| ed25519 networking keypair (Suite C) | **Device** | exported as keyfile (hot key) |
| Comet mining | Host (`comet_miner`) | 8 GB loom; tweak commits funding txid |

## Test vectors — THE AUTHORITY

Addresses below were captured from the **real gw-onboard binary**
(`groundwire-daily-2026.7.6`, `--master-ticket <T> --skip-boot --skip-attestation`)
and are asserted in `src/identity.rs` tests (all passing).

| ID | Input | Expected | Status |
|----|-------|----------|--------|
| TV-1 | patq(`[0x00,0x00]`) | `~dozzod` | ✅ |
| TV-2 | patq(`[0x00,0x01]`) | `~doznec` | ✅ |
| TV-3 | patq(`00..0f` 16B) | `~doznec-binwes-samper-siglet-fidpen-sogdur-wacser-wissun` | ✅ |
| TV-4 | funding addr, seed = `00..0f` (16B, fresh path) | `bc1pzh75rtx74l85v2xqfr5uln7mhy40vyqzm68ml4yngcqy9v085tqqmgg72j` | ✅ |
| TV-5 | funding addr, seed = `deadbeef00112233445566778899aabb` | `bc1pft80yrj8lw8ewmm75s9m04qygt73k4z70jqmes9d8u47te38c9cqxpj5gl` | ✅ |
| TV-6 | funding addr, resume of all-zeros ticket (empty seed) | `bc1pl4lmgvwphzjllhl5tsrst3mqp588zpmyxtyszh2wk68wjfenm47s5c8t5m` | ✅ |
| TV-7 | Suite C networking pubkey, seed = TV-4 | (capture when keyfile export is built) | ⬜ TODO |

To capture a new vector: `env -i PATH=/usr/bin:/bin ./gw-onboard --master-ticket
'<@q>' --rpc-url http://127.0.0.1:1 --skip-boot --skip-attestation` and read the
`Address:` line. The Python cross-check in `scratchpad/reref2.py` reproduces all
of the above with `embit`.
