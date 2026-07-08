# groundwire

A KeyOS / Passport Prime (Foundation Devices) app that creates **Groundwire
identities** — Bitcoin-attested Urbit comets — **entirely on-device**. The
Passport mines the comet, encodes the attestation, and builds *and signs* the
commit + reveal transactions itself, then shows them as broadcast QRs. No host
signer, no PSBT round-trip, no private key leaves the device — except the
comet's own networking key, which is delivered once in the boot command because
it has to boot the ship on your computer.

This is **Architecture B**: the device does the whole spawn. The reference
host implementation (PSBT + UR2.0 QR, plus the management ops — rekey, escape,
etc.) lives separately in Causeway; groundwire is spawn-only.

## What it does

- Generates a 128-bit seed from user-supplied **dice rolls** (the dice, not the
  device, are the randomness — SDK 0.4.0 exposes no app-facing TRNG on hardware;
  see `docs/trng-spike.md`). On the hosted sim it also mixes the OS CSPRNG.
- Renders the seed as a **BIP-39 phrase** — the single human backup. The same
  16 bytes are used *directly* as the BIP-32 seed (no PBKDF2).
- Derives the **BIP-86 taproot funding address** (`m/86'/1'/0'/0/0`) on-device,
  byte-for-byte matching `gw-onboard` (`docs/identity-derivation.md`).
- **Mines** a `~daplyd` comet (suite-C ed25519) whose `pass`/`ring` commit to
  the funding satpoint, and renders its `@p`.
- **Encodes** the `%spawn` attestation (a bit-exact port of `urb-encoder.hoon`)
  and wraps it in a `urb`-tagged Taproot leaf.
- **Builds and signs** the commit + reveal transactions on-device (BIP-341
  output tweak, BIP-342 tapscript sighash, BIP-340 Schnorr), and emits the
  finalized **raw transactions as broadcast QRs**.
- Produces the `vere -G` **boot command** (jam → `@uw` feed) behind a
  press-and-hold reveal, since the feed embeds the comet's private networking key.
- Persists identities in the per-app encrypted `identities.json`
  (`Location::AppData`), and zeroizes seed/mnemonic from memory when the wizard
  leaves or regenerates.

Every consensus- and protocol-critical byte is pinned to an independent oracle:
the canonical **BIP-341** wallet test vectors, Causeway's **encoder + jam**
golden vectors, urbit-ob `@p` anchors, and a neutral **ed25519** oracle.

## The onboarding wizard

One `CreatePagePage` component (a `step` state machine) in
`ui/pages/create/page.slint`:

```
dice → write-down → prove-quiz → fund → enter-UTXO → mine & sign → broadcast → boot
```

- **prove-quiz** re-derives the funding address from the tapped backup words and
  compares; no Bitcoin is touched until the paper copy is proven correct.
- **enter-UTXO** takes the funding output as `txid:vout:sats` — typed by hand
  (the common case), with QR scan as a secondary option.
- **mine & sign** runs the ~65k-iteration star search in **bounded batches
  driven by a Slint `Timer`**, so mining (minutes on-device) never freezes the
  UI; a live tries counter and a Cancel button stay responsive throughout.
- **broadcast** shows the commit and reveal raw-tx QRs (commit first, wait for
  confirmation, then reveal).

The device only ever signs a **self-spend of its own funding UTXO back to its
own funding address**, and Taproot commits to the input amount — so a scanned
funding QR can never redirect funds. Design and rationale: `docs/onboarding-flow.md`.

### Lifecycle

The main page lists identities with their onboarding **stage** (backed-up →
funded → attested → live) and the comet `@p` once attested. An unfinished
identity can be **resumed** (rebuilds the seed from its stored mnemonic and
re-enters the wizard at the right step) or **deleted** behind an inline confirm.

## Layout

```
src/
  main.rs       app entry + GwBridge callback wiring (Slint <-> Rust)
  entropy.rs    dice entropy pool, SHA-256 conditioning
  bip39.rs      BIP-39 encode/decode (no PBKDF2 — raw entropy is the seed)
  identity.rs   @p rendering + BIP-86 taproot derivation + on-device signing
  wizard.rs     backup-quiz choices + address-match gate
  store.rs      identities.json persistence + onboarding stage constants
  urb/          the on-device attestation engine:
    encoder.rs    bit-exact %spawn encoder (urb-encoder.hoon)
    tweak.rs      the satpoint tweak the comet's pass commits to
    mine.rs       suite-C ed25519 comet miner
    tx.rs         Taproot tx build + BIP-341/342 sighash + Schnorr signing
    boot.rs       jam + @uw boot-command feed
    spawn.rs      end-to-end spawn: mine → encode → sign (chunked SpawnJob)
ui/
  gw-bridge.slint   the Slint <-> Rust interface
  pages/            main list + the create wizard
docs/             derivation, onboarding-flow, TRNG, and vault design notes
```

## Build & run

Requires the [Foundation SDK](https://foundation.xyz) (0.4.0, Nix-based) and its
pinned nightly toolchain. The SDK crates are referenced through a **sibling
symlink** `../foundation-sdk`; create it once per machine:

```sh
ln -sfn "$HOME/.foundation/sdk/current" ../foundation-sdk
```

Then:

```sh
# Unit tests (encoder/jam/BIP-341/tweak/miner/boot vectors + wizard gates)
cargo test --bins

# Launch the hosted simulator (needs a display server)
./sim
```

`./sim` runs `foundation sim` inside a memory-capped systemd scope
(`SIM_MEM_MAX`, default 12G) to keep the emulator from OOM-ing the host.

> **Simulator + Wayland (non-NixOS hosts).** The SDK's `gui-server` is built
> with a Nix glibc loader that doesn't read the system `ld.so.cache`, so its
> runtime `dlopen("libwayland-client.so.0")` fails with `NoWaylandLib` even
> though the lib is installed. Expose the wayland libs to just that loader —
> e.g. symlink `libwayland-{client,cursor,egl}`, `libxkbcommon`, and `libffi`
> into a dir and launch with `LD_LIBRARY_PATH=<that dir>`. A blanket
> `LD_LIBRARY_PATH=/usr/lib` segfaults the kernel, so keep the shim minimal.

## Continuous integration

`.github/workflows/ci.yml` runs on GitHub Actions:

- **`test`** — on every PR to `main` (and on push): installs Nix + the
  Foundation SDK, links `../foundation-sdk`, and runs `cargo test --bins` in the
  SDK's Nix dev shell.
- **`release build`** — on push to `main`: `foundation build --release` and
  uploads the optimized app as a build artifact.

The SDK installer is read from the repo variable `FOUNDATION_SDK_INSTALL`. To
make tests a **required** check, enable branch protection on `main`.

## Security model & scope

- The seed is **both the ship login and the Bitcoin wallet — one secret.** One
  12-word backup restores both; lose it and the identity and its coins are gone.
- The comet's **networking key is intrinsically exportable** — it rides in the
  boot command's `@uw` feed to boot the ship on your computer. That is the one
  secret that must leave the device; treat the boot command accordingly.
- Everything else stays on-device: the seed is used *directly* as the BIP-32
  seed, and every signature is produced on the Passport. The device signs only a
  self-spend of its own funding UTXO; **broadcasting** the resulting raw txs is
  done by you (scan the QR into a broadcaster) — the Passport never touches the
  network or the chain.
