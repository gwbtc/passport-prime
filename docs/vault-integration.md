# Can Groundwire store its ticket in the first-party Vault app?

**Short answer: not programmatically, in SDK 0.4.0.** The Vault is a
self-contained GUI app with no app-callable interface, and its data model
doesn't fit a Groundwire `@q` ticket anyway. Details and the upstream asks below.

## What the Vault actually is

`gui-app-seed-vault` — a **GUI app, not a system service**. Evidence from the
shipped binary (`simulator/bin/gui-app-seed-vault`) and the SDK tree:

- Stores to its **own** `seed_vault_database_v2.json` in **its** `AppData`.
  `AppData` is scoped per app-id, so Groundwire cannot read or write the Vault's
  database — OS isolation, by design.
- It does **not register an IPC server**. There is no `os/vault` / `os/seed-vault`
  server name, no vault API crate under `lib/keyos/api/`, and **no gui-server
  navigation flow** for it. Compare the flows that *are* app-callable:
  `alerts`, `bitcoin` (scan-only), `filepicker`, `lockscreen`, `qrscanner`,
  `securitykeys`. There is deliberately no `vault` among them.
- Its export features — Standard/Compact **SeedQR**, "Save to File", "Export
  Nostr Key" — are **user-driven, screen-only**. They are not an API another app
  can invoke.

## Data-model mismatch

The Vault stores **BIP-39 mnemonics** (12/15/18/21/24 words from the English
wordlist) and derives keys via BIP-39 → "Bitcoin seed". A Groundwire master
ticket is an **`@q` phrase used as a *raw* BIP-32 seed — no BIP-39, no PBKDF2**
(see `identity-derivation.md`). So the Vault can't represent a ticket as a
"seed": the syllables aren't BIP-39 words, and even if coerced, the Vault would
derive different keys. The only fit is a Vault "password" item — arbitrary
encrypted string, no derivation — which is clunky and manual.

## What the Vault would actually buy us

Not a different storage medium — Groundwire already stores its ticket in
per-app **AppData that is encrypted at rest**, the same tier the Vault uses. The
Vault's real advantages are **PIN-gated per-item unlock** ("Enter PIN to
unlock") and **securam** (secure-element/secure-RAM) backing via `os/security`,
plus centralized backup/recovery UX. Those are custody upgrades Groundwire's
plain AppData does not have.

Note `os/security` is **also not an app-callable API crate** in this SDK, so
Groundwire can't get securam-backed storage directly either — only the
first-party apps can.

## Paths forward (all upstream)

1. **Ask Foundation for a secret-storage / vault IPC API** — the clean fix. They
   already ship navigation flows for `securitykeys` and `qrscanner`; a
   `vault`/`secret` flow (store an item, retrieve with user-presence + PIN)
   would let Groundwire delegate ticket custody to securam. Best long-term.
2. **Ask for raw-seed / `@q` support in the Vault**, so a ticket can be stored as
   a first-class seed. Narrower, and still needs #1 to be programmatic.
3. **Ask for an `os/security` app API** — lower-level; lets any app get
   securam-backed, PIN-gated storage without going through the Vault UI.

## Interim (what we do now)

Keep storing the ticket in Groundwire's own encrypted `AppData`
(`src/store.rs`). It is encrypted at rest and app-isolated — the platform's best
available custody for a third-party app today. Track the asks above; if #1 or #3
ships, migrate `store.rs` behind it (the store is a thin module precisely so this
swap is small). This is the same "watch the SDK" item flagged in the integration
proposal under key custody.
