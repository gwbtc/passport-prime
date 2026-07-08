//! Native runner for the same `run_report()` the wasm ABI calls — so `cargo run`
//! (x86) and the browser (wasm) exercise identical code and must agree.
fn main() {
    print!("{}", urb_wasm::run_report());
}
