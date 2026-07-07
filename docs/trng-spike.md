# TRNG access spike — how a KeyOS app gets random bytes

**Question:** where does the Groundwire app get the 16 bytes of entropy for a
master ticket, in the simulator and on real Passport Prime hardware?

**Status:** simulator path solved; **hardware path is blocked** on an SDK gap.
This gates on-device ID creation and needs a decision from Foundation.

## What the SDK actually ships

Verified against SDK 0.4.0 (`~/.foundation/sdk/current`):

- **No `os/trng` client API crate.** The shipped app-callable API crates are
  app-manager, bt, crypto, fs, gui-server, haptics, quantum-link, rgb-led,
  settings (`lib/keyos/api/`). There is a `trng` **server** (it boots as PID 6
  in the simulator, `simulator/bin/trng`, source `xous/trng/src/main.rs`) but
  no crate exposes its server name or message types to an app.
- **The crypto server has no RNG.** `os/crypto` is AES/SHA-2/HMAC/Shamir only —
  no key generation, no `GetRandom` (see `docs/identity-derivation.md`).
- **The kernel TRNG is not app-reachable for bulk bytes.** `SysCall::CreateServerId`
  pulls from the "kernel-exclusive TRNG" (`xous-rs/src/syscall.rs:1408`) but only
  to mint 128-bit server IDs — it is not a general entropy API.
- **`getrandom` and `rand` are already in the dependency tree** (getrandom
  0.2/0.3/0.4, rand 0.8/0.9 in `Cargo.lock`), pulled in transitively.

## Simulator (hosted) — works today

In hosted mode the process is a normal Linux binary, so `std`-based entropy and
`getrandom` both resolve to the OS (`library/std/src/sys/random/linux.rs`).

⚠️ **The `trng` server itself is a deterministic PRNG in hosted mode** — its own
string says so: *"hosted mode TRNG is \*not\* random, it is a deterministic PRNG"*
(`xous/trng/src/platform/hosted/mod.rs`). So do **not** validate randomness
quality against the simulator, and don't route sim entropy through that server
expecting unpredictability.

What the app does now: `sim_entropy()` in `src/main.rs` — SplitMix64 seeded from
`SystemTime` + a stack address. Dependency-free, good enough to exercise the
create screen with distinct tickets per press. Marked sim-only.

## Hardware (armv7a-unknown-xous-elf) — BLOCKED

On device there is no OS-provided `getrandom` fallback; entropy must come from
the `os/trng` server, and **the client API for it is not in the shipped SDK.**
Three ways forward, cheapest first:

1. **Confirm `getrandom` has a xous backend wired to `os/trng`.** getrandom is
   already in the tree; if its xous target feature routes to the trng server,
   `rand`/`getrandom` "just work" on device. **Test:** add a one-call `getrandom`
   probe to the app, `foundation build` for the device target, side-load, and
   check it returns non-zero, non-repeating bytes. ~1 afternoon.
2. **Ask Foundation to ship the `trng` API crate** (add it to `keyos_api_interfaces`
   in `sdk-build.toml`, alongside crypto/fs/…). Then call it like any other
   service with a `use_api!` permission block. Cleanest long-term; needs an SDK
   release.
3. **Vendor the trng message definitions** from the server's IPC enum and connect
   by server name directly. Works without an SDK change but couples us to an
   unstable private interface — last resort.

## Recommendation

Do option 1 first (it may already work and costs almost nothing). If it fails,
file option 2 with Foundation and track it — this is the same blocker noted in
the integration proposal, now with a concrete cause: **no app-facing TRNG client
in SDK 0.4.0.** Until it's resolved, ID creation runs only in the simulator.

A `permission_templates.toml` entry will be needed once the interface exists,
e.g. `"os/trng" = ["FillTrng"]` (exact message name TBD from the shipped crate).
