// Load the wasm module and print its golden-vector self-check report.
//   deno run --allow-read run_wasm.mjs
import { readFile } from "node:fs/promises";
const buf = await readFile("./target/wasm32-unknown-unknown/release/urb_wasm.wasm");
const { instance } = await WebAssembly.instantiate(buf, {});
const packed = instance.exports.self_test(); // u64 -> BigInt
const ptr = Number(packed >> 32n), len = Number(packed & 0xffffffffn);
const view = new Uint8Array(instance.exports.memory.buffer, ptr, len);
process.stdout.write(new TextDecoder().decode(view));
