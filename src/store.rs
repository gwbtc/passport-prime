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
    pub const FUNDED: u8 = 2; // funding UTXO entered; ready to mine + sign
    pub const ATTESTED: u8 = 5; // commit+reveal on-chain — never re-run
    pub const LIVE: u8 = 6; // comet booted

    /// An identity still mid-onboarding (can be resumed or deleted).
    pub fn in_progress(s: u8) -> bool {
        s < ATTESTED
    }
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
    /// The scanned/typed funding UTXO (`txid:vout:sats`), persisted so a paused
    /// onboarding can resume straight to the mine step. Empty until funded.
    #[serde(default)]
    pub funding: String,
    /// Comet name (@p), recorded at attestation. Provisional until `stage >= ATTESTED`.
    #[serde(default)]
    pub comet: String,
    #[serde(default)]
    pub commit_txid: String,
    #[serde(default)]
    pub reveal_txid: String,
}

impl Drop for Identity {
    /// The mnemonic is the whole secret (wallet + ship). Scrub it from the heap
    /// when an Identity is dropped — on delete, on list reload, and at exit — so
    /// a used seed isn't left in freed memory. (address/txids/comet are public.)
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.mnemonic.zeroize();
    }
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

/// Write the comet boot key file and a runnable boot script to the Airlock
/// partition and expose them to a connected computer as a USB drive. The user
/// either runs the script or copies the key file and runs the shown command
/// (see [`crate::urb::boot::format_boot_command_keyfile`] / `format_boot_script`).
///
/// Airlock is a real block device that only exists on the Passport; the simulator
/// has none, so there this returns Ok without touching hardware — the go-live flow
/// stays testable, and the transfer is verified on device. The airlock calls are
/// compiled (and type-checked) on both targets; only the runtime call is skipped.
pub fn export_boot_key(feed_uw: &str, boot_script: &str) -> Result<(), String> {
    if !cfg!(target_os = "xous") {
        return Ok(()); // simulator: no Airlock hardware
    }
    use crate::urb::boot::{KEYFILE_NAME, SCRIPT_NAME};
    let mut fs = FileSystem::default();
    fs.format_airlock().map_err(|e| format!("{e:?}"))?;
    for (name, bytes) in [(KEYFILE_NAME, feed_uw.as_bytes()), (SCRIPT_NAME, boot_script.as_bytes())] {
        let mut f = fs
            .open_file(name, Location::Airlock, OpenFlags::CREATE)
            .map_err(|e| format!("{e:?}"))?;
        f.overwrite(bytes).map_err(|e| format!("{e:?}"))?;
    }
    fs.mount_airlock().map_err(|e| format!("{e:?}"))
}

/// Unmount and wipe the Airlock so the boot key no longer sits on the USB drive.
/// Device-only; a no-op on the simulator (see [`export_boot_key`]).
pub fn wipe_airlock() -> Result<(), String> {
    if !cfg!(target_os = "xous") {
        return Ok(());
    }
    let mut fs = FileSystem::default();
    let _ = fs.unmount_airlock(); // reclaim from host; ignore if not mounted
    fs.format_airlock().map_err(|e| format!("{e:?}"))
}
