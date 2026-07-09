# urb-wasm

The Passport's `src/urb/` protocol core, compiled to `wasm32` so the **same
audited Rust** — encoder, tweak, ed25519 comet miner, BIP-341/342 taproot
tx-builder+signer, jam/`@uw`, `@p` — runs in a browser instead of being
re-implemented. The device coupling (`main.rs`, `store.rs`, `theme.rs`) is left
behind; this crate pulls in the portable modules verbatim via `#[path]`, so it
tracks the device code with no fork.

Intended use: a shared, vector-pinned protocol engine (e.g. to retire
Causeway's separate TypeScript port), **not** an in-browser signer for real
funds — the security model still says keys stay on the device.

## Build

```sh
cargo +stable build --release --lib --target wasm32-unknown-unknown
# -> target/wasm32-unknown-unknown/release/urb_wasm.wasm  (~200 KB)
```

## Run the parity self-check

```sh
cargo +stable run --bin selftest                 # native reference
deno run --allow-read run_wasm.mjs               # same report, from wasm
python3 -m http.server                           # then open index.html
```

Both paths reproduce the device's golden vectors byte-for-byte, including a full
ed25519 mine + taproot commit/reveal sign.

## ABI

No `wasm-bindgen`. Byte buffers cross as a packed `u64` = `(ptr<<32)|len` into
the exported `memory`; callers `__alloc` inputs and `__dealloc` every returned
buffer. Exports: `tweak`, `patp`, `nym`, `uw`, `encode_spawn`, `self_test`. A ~40-line
JS/TS wrapper hides the marshalling (see `index.html` / the Causeway binding).
