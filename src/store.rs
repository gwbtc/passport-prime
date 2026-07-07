//! Persistence for Groundwire identities.
//!
//! One JSON file, `identities.json`, in `Location::AppData` — the per-app
//! encrypted-at-rest store, which needs no extra fs access grant. The 12-word
//! mnemonic (the wallet seed) lives here; that is the platform's intended
//! custody for app secrets (see the integration proposal). ponytail: single
//! file + full rewrite on every change — fine for the handful of identities a
//! user holds; revisit only if that count ever gets large.

use serde::{Deserialize, Serialize};
use std::io::Read;

fs::use_api!();

use fs::{Location, OpenFlags};

const FILE: &str = "identities.json";

/// Onboarding progress, persisted as `Identity::stage` (docs/onboarding-flow.md
/// §7). Full sequence: 1 backed-up · 2 verified · 3 funding · 4 mining ·
/// 5 attested · 6 live. The wizard advances the intermediate stages as integer
/// literals in Slint, so only the two Rust touches are named here.
pub mod stage {
    pub const BACKED_UP: u8 = 1; // paper proven by the quiz; persisted here
    pub const ATTESTED: u8 = 5; // commit+reveal on-chain — never re-run
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Identity {
    pub label: String,
    /// BIP-39 encoding of the seed entropy — the single stored backup form (the
    /// @q ticket rendering is not persisted; recovery is by these 12 words).
    #[serde(default)]
    pub mnemonic: String,
    pub address: String,
    pub created_unix: u64,
    /// Onboarding stage; see [`stage`].
    #[serde(default)]
    pub stage: u8,
    /// Comet name (@p), recorded at attestation. Provisional until `stage >= ATTESTED`.
    #[serde(default)]
    pub comet: String,
    #[serde(default)]
    pub commit_txid: String,
    #[serde(default)]
    pub reveal_txid: String,
}

/// Load all stored identities. Returns empty on first run or any read error —
/// a corrupt/absent store must never crash the app.
pub fn load() -> Vec<Identity> {
    let fs = FileSystem::default();
    let Ok(mut f) = fs.open_file(FILE, Location::AppData, OpenFlags::READ_ONLY) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    serde_json::from_slice(&buf).unwrap_or_default()
}

/// Persist the full identity list, replacing the file's contents.
pub fn save(items: &[Identity]) -> Result<(), fs::Error> {
    let fs = FileSystem::default();
    let mut f = fs.open_file(FILE, Location::AppData, OpenFlags::CREATE)?;
    let json = serde_json::to_vec(items).expect("identities serialize");
    f.overwrite(&json)
}
