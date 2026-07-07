# groundwire

A KeyOS / Passport Prime (Foundation Devices) app for creating and managing
**Groundwire identities** — Bitcoin-attested Urbit comets. The Passport is an
offline generator and relay-verifier: it mints the master ticket from dice
entropy, guides the user through a foolproof onboarding flow, and stores the
secret at rest. All money and host work is done by `gw-onboard` on the user's
computer — the Passport never touches the network or the chain.

## What it does

- Generates a 128-bit **master ticket** from user-supplied dice rolls (the
  dice, not the device, are the randomness — there is no app-facing TRNG on
  the device; see `docs/trng-spike.md`).
- Renders the ticket as a **BIP-39 phrase** (the human-facing backup) while
  keeping the `@q` form internal. Both encode the same 16 entropy bytes.
- Derives the **BIP-86 taproot funding address** (`m/86'/1'/0'/0/0`, mainnet)
  on-device, byte-for-byte matching `gw-onboard` (`docs/identity-derivation.md`).
- Runs a guided onboarding **wizard** that will not let the user spend Bitcoin
  until the paper backup and the host-derived address are both cryptographically
  confirmed.
- Stores identities in the per-app encrypted `identities.json`
  (`Location::AppData`), and wipes ticket/mnemonic/entropy from memory
  (`zeroize`) when the wizard leaves or regenerates.

## The onboarding wizard

One `CreatePagePage` component (a `step` state machine) in
`ui/pages/create/page.slint`, driving these screens:

`mode → dice → write-down → prove-quiz → handoff → address-match → fund → attest → boot`

Its central safety property: **no funding command is revealed until (a) the
tapped backup words re-derive the exact stored address, and (b) the user
confirms the address `gw-onboard` printed matches the app's.** Because the
Passport has no IPC to the host, every host confirmation is a human-relayed
discriminating tap (match the address group, tap the txid tail), never a
rubber-stampable yes/no. The full design and rationale are in
`docs/onboarding-flow.md`.

## Layout

```
src/
  main.rs       app entry + GwBridge callback wiring (Slint <-> Rust)
  entropy.rs    dice entropy pool, SHA-256 conditioning, top-byte guard
  bip39.rs      BIP-39 encode/decode (no PBKDF2 — raw entropy is the seed)
  identity.rs   @q rendering + BIP-86 taproot derivation (pinned to vectors)
  wizard.rs     backup-quiz choices, address-match gate, handoff commands
  store.rs      identities.json persistence + onboarding stage constants
ui/
  gw-bridge.slint   the Slint <-> Rust interface
  pages/create/     the wizard
docs/             derivation, onboarding-flow, TRNG, and vault design notes
```

## Build & run

Requires the [Foundation SDK](https://foundation.xyz) (0.4.0, Nix-based) and the
pinned nightly toolchain.

The SDK crates are referenced through a **sibling symlink** `../foundation-sdk`
(so `Cargo.toml` carries no absolute paths and the SDK crates stay out of this
project's Cargo workspace). Create it once per machine, pointing at your
installed SDK:

```sh
ln -sfn "$HOME/.foundation/sdk/current" ../foundation-sdk
```

Then:

```sh
# Unit tests (logic: entropy, bip39, identity vectors, wizard gates)
cargo test --bins

# Launch the hosted simulator (needs a display server)
./sim
```

`./sim` runs `foundation sim` inside a memory-capped systemd scope
(`SIM_MEM_MAX`, default 12G) to keep the emulator from OOM-ing the host; set
`SIM_MEM_MAX` to override.

> Toolchain note: the pinned nightly's `rustc` can SIGSEGV/ICE while compiling
> some dependency proc-macros. Building with `RUST_MIN_STACK=67108864 -j2`
> gets through; retries make forward progress as crates cache.

## Continuous integration

`.github/workflows/ci.yml` runs on GitHub Actions:

- **`test`** — on every PR to `master` (and on push): installs Nix + the
  Foundation SDK, links `../foundation-sdk`, and runs `cargo test --bins` in the
  SDK's Nix dev shell.
- **`release build`** — on push to `master`: `foundation build --release` and
  uploads the optimized app as a build artifact.

The SDK installer is read from the repo variable `FOUNDATION_SDK_INSTALL`
(defaults to the public `curl … | bash`); during early access, set it to your
gated installer. To make tests a **required** check, enable branch protection on
`master`:

```sh
gh api -X PUT repos/:owner/:repo/branches/master/protection \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=test' \
  -F 'enforce_admins=true' \
  -F 'required_pull_request_reviews=null' \
  -F 'restrictions=null'
```

## Security model & scope

- The master ticket is **both the ship login and the Bitcoin wallet — one
  secret.** Lose it and the identity and its coins are unrecoverable.
- Derivation currently uses the entropy **directly** as the BIP-32 seed, to
  match live `gw-onboard`. A proposed change moves both sides to BIP-39 PBKDF2
  output; the app flips its internal seed step when that lands.
- The app derives and verifies; it does not broadcast, fund, or mine. Two
  mainnet-blocking host-side preconditions (no-fund dry run, seed off `argv`)
  are `gw-onboard` changes, tracked in `docs/onboarding-flow.md` §1.
