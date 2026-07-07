//! On-device port of the Groundwire attestation protocol (Causeway's `src/`).
//! The device mines, encodes, builds, and signs the spawn attestation itself —
//! no PSBT round-trip, because it holds the key.
#![allow(dead_code)] // op variants/helpers land as later slices wire them in

pub mod boot;
pub mod encoder;
pub mod mine;
pub mod spawn;
pub mod tweak;
pub mod tx;
