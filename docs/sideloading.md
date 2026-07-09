# Side-loading groundwire onto a physical Passport Prime

The simulator (`./sim`) covers everything except the two things that only exist
on real hardware: **actual mining speed** (the device is a single-core SAMA5D2 —
a debug build's curve25519 is 10–30× slower than release, see `Cargo.toml`) and
the **Airlock USB boot-key export** (the go-live step; the sim stubs it). To
exercise those you sideload the real app.

One command does the whole loop:

```sh
foundation sideload            # build (debug) → sign → copy to device → launch
foundation sideload --release  # optimized build — use this to judge mining speed
```

`foundation sideload` builds and signs the app, copies the bundle to a connected
Passport Prime over its USB mass-storage volume (the airlock), and launches it
over the USB debug channel. Everything below is the one-time setup around that.

## 1. Toolchain (once per machine)

All `foundation` commands run inside the SDK's Nix shell.

```sh
ln -sfn "$HOME/.foundation/sdk/current" ../foundation-sdk   # sibling symlink the crates expect
foundation develop            # enter the Nix dev shell
foundation doctor             # verify tools, targets, and device prerequisites
```

`foundation doctor` is the first thing to run when anything below misbehaves — it
checks the toolchain, the target triple (`atsama5d27-keyos`), and whether a
device is reachable.

## 2. Signing key (once per publisher)

Sideloaded apps must be signed, and the device must trust the signer. This repo's
key already exists at `~/.foundation/signing/Groundwire Foundation/`
(`private.pem`, `certificate.crt`, `cosign2.toml`; cosign target
`atsama5d27-keyos`). `foundation sideload` picks it up automatically.

If you need to (re)generate it on a fresh machine:

```sh
foundation cert gen "Groundwire Foundation" \
  --publisher-name "Groundwire Foundation" \
  --contact-email  "jackson@groundwire.io" \
  --support-url    "https://groundwire.io"

foundation cert print         # inspect the X.509 publisher certificate
```

This generates a secp256k1 keypair, a self-signed X.509 code-signing
certificate, and the `cosign2` config used at sign time. Keep `private.pem`
secret — it is the identity every sideloaded build is signed under.

**Trust the key on the device (once).** The Passport only installs apps signed by
a publisher key it trusts. The *first* time you sideload, the device prompts to
install the app and to trust this publisher's public key — approve both on the
Passport. After that, any build signed with the same key installs without the
trust prompt. (If an install is rejected as an untrusted publisher, this
enrollment step hasn't been completed.)

## 3. Connect the device

- Plug the Passport Prime into the computer over USB and unlock it.
- It exposes two things the CLI needs: a **PRIME mass-storage volume** (where the
  signed bundle is dropped) and a **USB serial/debug channel** (where the app is
  launched and logs stream). Both are auto-detected.
- If auto-detection picks the wrong device, override explicitly:

  ```sh
  foundation sideload --mount-path /run/media/$USER/PRIME --serial-port /dev/ttyACM0
  ```

## 4. Install / update behavior

- **First install:** the Passport prompts to install groundwire (App ID
  `0x8293f5297acdbf185ed039edee7e0013`, from `app-config.toml`); approve it.
- **Updates:** re-running `foundation sideload` with the same App ID replaces the
  installed app automatically, with a toast on the device — no re-approval.
- `--no-run` copies and installs the bundle but doesn't launch it (useful when
  you want to start it from the launcher yourself).

## 5. Watch logs

```sh
foundation logs               # attach the KeyOS log viewer to the device over USB
```

This streams the app's `log`/panic output — the practical way to watch the miner
tries counter, catch a panic, or confirm the Airlock export path on real
hardware. `-t <seconds>` sets the USB reconnect timeout.

## 6. Iterate

Edit → `foundation sideload` → the device auto-replaces the running app. Use
`--release` whenever you're measuring mining time; the debug build's unoptimized
curve25519 makes the ~65k-iteration star search far slower than it is in
production.

## What to actually test on hardware

The sim can't, so verify these on the device specifically:

- **Mining throughput** on the single core (release build) — the `~daplyd` star
  search real-world duration and that the batched `SpawnJob` keeps the UI
  responsive with a live tries counter.
- **Dice entropy** — hardware exposes no app-facing TRNG (`docs/trng-spike.md`),
  so onboarding genuinely depends on the dice-roll pool; the sim's OS-CSPRNG mix
  isn't present here.
- **Go-live over USB** — the boot key export writes `comet.feed` + `boot-comet.sh`
  to `Location::Airlock` and mounts it as a USB drive for your computer. This is
  gated on the `os/fs` Airlock permissions in `app-config.toml`
  (`GetAirlockWriteAccess`, `MountAirlock`, `FormatAirlock`) and only runs on
  device — the sim returns success without touching hardware.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Device not found | Unlock the Passport, reseat the cable, re-run `foundation doctor`. Override with `--mount-path` / `--serial-port`. |
| "Untrusted publisher" / install rejected | Complete the one-time key-trust prompt (§2); confirm the cert with `foundation cert print`. |
| App won't launch after copy | Try `--no-run`, start it from the launcher, and read `foundation logs`. |
| `min-keyos-version` mismatch | `app-config.toml` requires KeyOS ≥ 1.0.0; update the device firmware. |
| Mining feels impossibly slow | You're on a debug build — rebuild with `foundation sideload --release`. |
