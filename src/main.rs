mod bip39;
mod entropy;
mod identity;
mod store;
mod theme;
mod urb;
mod wizard;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use slint_keyos_platform::slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use slint_keyos_platform::{app_ui, qrcode};

/// The boot script the comet's `vere -G` one-liner downloads.
const BOOT_URL: &str = "https://groundwire.io/causeway/boot.sh";
/// Fee rate for the commit+reveal transactions (sat/vB). Causeway's default.
const FEE_RATE: u64 = 2;

/// The current in-progress identity, held in Rust between wizard steps so the
/// secret isn't round-tripped through Slint on every screen. Populated by
/// `generate-identity`; consumed by the backup gate and the on-device spawn.
#[derive(Default)]
struct DraftState {
    /// The 16-byte ticket entropy — the BIP-32 seed used to mine/sign on-device.
    entropy: Vec<u8>,
    mnemonic: String,
    address: String,
    /// Shuffle salt for this draft's quiz grid — stable across redraws.
    salt: u64,
    /// Words tapped so far in the backup-proof quiz, in order.
    quiz: Vec<String>,
    /// Funding UTXO scanned/entered from a block explorer.
    funding: Option<urb::spawn::FundingInput>,
    /// Finalized raw commit/reveal transactions (hex) from the last spawn, held
    /// for the broadcast QRs.
    commit_hex: String,
    reveal_hex: String,
    /// The comet's Urbit `@p` — used only for the boot script's `--comet` arg.
    /// The user-facing name is the mnemonym (shown via `SpawnProgress.comet`).
    comet: String,
    /// The `0v…` boot feed (embeds the comet's private key) for the USB key file.
    feed_uw: String,
}

impl DraftState {
    /// Scrub the seed and secrets from the heap. Called when the wizard leaves or
    /// regenerates so a used secret doesn't linger in freed memory.
    fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.entropy.zeroize();
        self.entropy.clear();
        self.mnemonic.zeroize();
        self.address.zeroize();
        for w in &mut self.quiz {
            w.zeroize();
        }
        self.quiz.clear();
        self.salt = 0;
        self.funding = None;
        self.commit_hex.clear();
        self.reveal_hex.clear();
        self.comet.clear();
        self.feed_uw.zeroize();
    }
}

impl Drop for DraftState {
    /// Wipe on drop, so replacing the draft (regenerate / resume a different
    /// identity) or tearing down the app scrubs the previous seed automatically.
    fn drop(&mut self) {
        self.wipe();
    }
}

app_ui!("groundwire");

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    // In-memory identity list, backed by the AppData store.
    let identities = Rc::new(RefCell::new(store::load()));
    let model = Rc::new(VecModel::from(summaries(&identities.borrow())));
    ui.global::<GwBridge>().set_identities(ModelRc::from(model.clone()));

    // User-supplied dice entropy, accumulated across taps on the create screen.
    let pool = Rc::new(RefCell::new(entropy::EntropyPool::default()));
    // The in-progress identity, shared across the wizard's steps.
    let draft = Rc::new(RefCell::new(DraftState::default()));
    // Shared state for the worker-thread miner: the UI polls `tries`/`done` from
    // the main thread while the worker updates them. `cancel` stops the worker.
    let mine: Arc<Mutex<MineShared>> = Arc::new(Mutex::new(MineShared::default()));

    let p = pool.clone();
    ui.global::<GwBridge>().on_add_roll(move |face| p.borrow_mut().add_roll(face as u8, now_nanos()) as i32);

    let p = pool.clone();
    let dr = draft.clone();
    ui.global::<GwBridge>().on_reset_entropy(move || {
        p.borrow_mut().reset();
        dr.borrow_mut().wipe();
    });

    let p = pool.clone();
    let dr = draft.clone();
    ui.global::<GwBridge>().on_generate_identity(move || {
        // Fail closed: the UI disables generate until the 128-bit floor, but never
        // mint a ticket under-rolled if that gate is ever bypassed.
        assert!(p.borrow().ready(), "generate-identity called before the 128-bit dice floor");
        // Dice carry the audited floor; mix in the OS CSPRNG where one exists.
        let ent = p.borrow().finish(&system_entropy());
        let d = identity::new_identity(ent);
        *dr.borrow_mut() = DraftState {
            entropy: ent.to_vec(),
            salt: salt_from(&d.funding_address),
            mnemonic: d.mnemonic.clone(),
            address: d.funding_address.clone(),
            quiz: Vec::new(),
            funding: None,
            commit_hex: String::new(),
            reveal_hex: String::new(),
            comet: String::new(),
            feed_uw: String::new(),
        };
        IdentityDraft {
            funding_address: d.funding_address.into(),
            mnemonic: d.mnemonic.into(),
        }
    });

    // The draft's 12 words, for the write-down grid.
    let dr = draft.clone();
    ui.global::<GwBridge>().on_mnemonic_words(move || {
        string_model(dr.borrow().mnemonic.split_whitespace().map(String::from).collect())
    });

    // Backup proof: 6 shuffled word choices for one mnemonic position.
    let dr = draft.clone();
    ui.global::<GwBridge>().on_backup_word_choices(move |pos| {
        let d = dr.borrow();
        string_model(wizard::backup_word_choices(&d.mnemonic, pos.max(0) as usize, d.salt))
    });

    // Record one tapped quiz word (in order).
    let dr = draft.clone();
    ui.global::<GwBridge>().on_backup_tap(move |word| {
        let mut d = dr.borrow_mut();
        d.quiz.push(word.to_string());
        d.quiz.len() as i32
    });

    let dr = draft.clone();
    ui.global::<GwBridge>().on_backup_reset(move || dr.borrow_mut().quiz.clear());

    // Backup gate: re-derive from the tapped words; persist on match.
    let dr = draft.clone();
    let ids = identities.clone();
    let m = model.clone();
    ui.global::<GwBridge>().on_confirm_backup(move || {
        let mut d = dr.borrow_mut();
        if !wizard::confirm_backup(&d.quiz, &d.address) {
            d.quiz.clear();
            return false;
        }
        // Idempotent: the quiz is reachable again via the funding step's Back
        // button, so re-passing it must not append a second copy of an identity
        // we already saved. Match on address (unique per draft).
        {
            let mut list = ids.borrow_mut();
            if !list.iter().any(|it| it.address == d.address) {
                // Explicit fields (no `..Default::default()`): Identity impls Drop
                // for zeroization, so struct-update can't move out of a default.
                list.push(store::Identity {
                    label: label_from_address(&d.address),
                    mnemonic: d.mnemonic.clone(),
                    address: d.address.clone(),
                    created_unix: now_unix(),
                    stage: store::stage::BACKED_UP,
                    funding: String::new(),
                    comet: String::new(),
                    commit_txid: String::new(),
                    reveal_txid: String::new(),
                });
            }
        }
        persist_and_refresh(&ids.borrow(), &m);
        d.quiz.clear();
        true
    });

    // QR codes: black-on-white for scanner contrast regardless of app theme.
    use slint_keyos_platform::slint::Color;
    let black = Color::from_rgb_u8(0, 0, 0);
    let white = Color::from_rgb_u8(255, 255, 255);

    let dr = draft.clone();
    ui.global::<GwBridge>().on_address_qr(move || qrcode::render(dr.borrow().address.clone(), black, white));

    // Funding UTXO: scan a "txid:vout:sats" QR from a block explorer.
    let dr = draft.clone();
    ui.global::<GwBridge>().on_scan_funding(move || scan_funding(&dr).into());

    // Manual fallback: the same "txid:vout:sats" string, entered by hand.
    let dr = draft.clone();
    ui.global::<GwBridge>().on_set_funding(move |s| match urb::spawn::parse_funding(&s) {
        Ok(f) => {
            dr.borrow_mut().funding = Some(f);
            SharedString::new()
        }
        Err(e) => e.into(),
    });

    // On-device spawn: `begin` kicks off mining on a worker thread so the UI
    // thread stays free (smooth animation); the UI Timer `poll`s progress and,
    // on completion, the signed result. `cancel` stops the worker.
    let dr = draft.clone();
    let mn = mine.clone();
    ui.global::<GwBridge>().on_spawn_begin(move || spawn_begin(&dr, &mn).into());

    let dr = draft.clone();
    let mn = mine.clone();
    ui.global::<GwBridge>().on_spawn_poll(move || spawn_poll(&mn, &dr));

    let mn = mine.clone();
    ui.global::<GwBridge>().on_spawn_cancel(move || {
        mn.lock().unwrap().cancel = true;
    });

    // Persist the funding UTXO onto the in-progress identity (stage = funded).
    let dr = draft.clone();
    let ids = identities.clone();
    let m = model.clone();
    ui.global::<GwBridge>().on_record_funding(move |index| {
        if index < 0 {
            return;
        }
        let funding_str = dr
            .borrow()
            .funding
            .as_ref()
            .map(|f| format!("{}:{}:{}", f.txid_display_hex, f.vout, f.value));
        let Some(fs) = funding_str else { return };
        if let Some(it) = ids.borrow_mut().get_mut(index as usize) {
            it.funding = fs;
            if it.stage < store::stage::FUNDED {
                it.stage = store::stage::FUNDED;
            }
        }
        persist_and_refresh(&ids.borrow(), &m);
    });

    // Resume a paused onboarding: rebuild the draft and report where to re-enter.
    let dr = draft.clone();
    let ids = identities.clone();
    ui.global::<GwBridge>().on_load_identity(move |index| load_identity(&dr, &ids, index));

    // Broadcast QRs: the finalized raw commit / reveal transactions.
    let dr = draft.clone();
    ui.global::<GwBridge>().on_commit_qr(move || qrcode::render(dr.borrow().commit_hex.clone(), black, white));
    let dr = draft.clone();
    ui.global::<GwBridge>().on_reveal_qr(move || qrcode::render(dr.borrow().reveal_hex.clone(), black, white));

    // Go-live: write the boot key to the Airlock and expose it over USB; wipe it
    // once the user is done. Both return "" on success or a human-readable error.
    let dr = draft.clone();
    ui.global::<GwBridge>().on_export_boot_key(move || {
        let (feed, script) = {
            let d = dr.borrow();
            (d.feed_uw.clone(), urb::boot::format_boot_script(&d.comet, BOOT_URL, None))
        };
        match store::export_boot_key(&feed, &script) {
            Ok(()) => SharedString::new(),
            Err(e) => e.into(),
        }
    });
    ui.global::<GwBridge>().on_wipe_usb(move || match store::wipe_airlock() {
        Ok(()) => SharedString::new(),
        Err(e) => e.into(),
    });

    // Advance a persisted identity's stage.
    let ids = identities.clone();
    let m = model.clone();
    ui.global::<GwBridge>().on_set_stage(move |index, stage| {
        // `index as usize` (not `.max(0)`): a stray -1 becomes usize::MAX → no
        // match, rather than silently mutating identity[0].
        if index >= 0 {
            if let Some(it) = ids.borrow_mut().get_mut(index as usize) {
                it.stage = stage as u8;
            }
            persist_and_refresh(&ids.borrow(), &m);
        }
    });

    // Record the on-chain attestation — the point of no return.
    let ids = identities.clone();
    let m = model.clone();
    ui.global::<GwBridge>().on_record_attestation(move |index, comet, commit, reveal| {
        // Guard the sentinel -1 so a lost selection can't stamp the wrong identity
        // as ATTESTED with this comet's txids.
        if index >= 0 {
            if let Some(it) = ids.borrow_mut().get_mut(index as usize) {
                it.comet = comet.to_string();
                it.commit_txid = commit.to_string();
                it.reveal_txid = reveal.to_string();
                it.stage = store::stage::ATTESTED;
            }
            persist_and_refresh(&ids.borrow(), &m);
        }
    });

    let ids = identities.clone();
    let m = model.clone();
    ui.global::<GwBridge>().on_delete_identity(move |index| {
        let i = index as usize;
        if i < ids.borrow().len() {
            ids.borrow_mut().remove(i);
            persist_and_refresh(&ids.borrow(), &m);
        }
    });

    ui.run().expect("UI running");
}

/// Open the camera, scan a "txid:vout:sats" QR, and store the parsed funding
/// UTXO on the draft. Returns "" on success or a human-readable error.
fn scan_funding(draft: &Rc<RefCell<DraftState>>) -> String {
    use slint_keyos_platform::gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult};
    use slint_keyos_platform::navigation::open_qr_scanner;

    let opts = ScanQrOptions {
        header_title: String::from("Scan funding UTXO"),
        message: String::from("Scan a txid:vout:sats QR from your block explorer."),
        ..ScanQrOptions::default()
    };
    match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
        Ok(Some(ScanQrResult::Qr(bytes))) => {
            let s = String::from_utf8_lossy(&bytes);
            match urb::spawn::parse_funding(&s) {
                Ok(f) => {
                    draft.borrow_mut().funding = Some(f);
                    String::new()
                }
                Err(e) => e,
            }
        }
        Ok(Some(ScanQrResult::Ur2(..))) => "Expected a plain txid:vout:sats QR, not a UR.".into(),
        Ok(Some(_)) | Ok(None) => "Scan cancelled.".into(),
        Err(_) => "Scanner unavailable.".into(),
    }
}

/// Live state of the worker-thread mine, shared between the worker (writer) and
/// the UI poll on the main thread (reader). The seed never lives here — it stays
/// inside the `SpawnJob` moved onto the worker (zeroized when that job drops).
#[derive(Default)]
struct MineShared {
    /// Iterations mined so far, for the progress readout.
    tries: u64,
    /// Set by the UI's Cancel; the worker checks it each batch and stops.
    cancel: bool,
    /// Populated once mining finishes: the signed result, or a terminal error.
    done: Option<Result<Box<urb::spawn::SpawnResult>, String>>,
}

/// Iterations mined per batch between cancel checks / progress updates. Small
/// enough that Cancel and the tries readout stay responsive on the slow device.
const BATCH: u64 = 500;

/// Start mining on a worker thread from the draft's seed + funding UTXO. Returns
/// "" on success or a human-readable error. Mining runs off the UI thread so the
/// animation stays smooth; progress lands in `mine` for [`spawn_poll`] to read.
fn spawn_begin(draft: &Rc<RefCell<DraftState>>, mine: &Arc<Mutex<MineShared>>) -> String {
    let (mut seed, funding) = {
        let d = draft.borrow();
        if d.entropy.len() != 16 {
            return "No ticket in progress.".into();
        }
        let Some(f) = &d.funding else {
            return "Enter the funding UTXO first.".into();
        };
        (
            d.entropy.clone(),
            urb::spawn::FundingInput {
                txid_display_hex: f.txid_display_hex.clone(),
                vout: f.vout,
                value: f.value,
            },
        )
    };
    let aux = aux_rand();
    let job = match urb::spawn::SpawnJob::new(&seed, funding, FEE_RATE, spawn_rng(&seed), aux, BOOT_URL) {
        Ok(j) => j,
        Err(e) => {
            zeroize::Zeroize::zeroize(&mut seed);
            return e;
        }
    };
    // Scrub this local copy of the seed; SpawnJob keeps its own (zeroized on drop).
    zeroize::Zeroize::zeroize(&mut seed);

    *mine.lock().unwrap() = MineShared::default();
    let shared = mine.clone();
    // A raw OS thread, not spawn_worker: the platform's cooperative async executor
    // stalls a long CPU grind (a self-waking task stops being re-polled; its async
    // sleep wedges the UI thread). xous preempts threads, so a plain blocking loop
    // here runs concurrently with the UI. std::thread::sleep(1ms) per batch hands
    // the single core to the UI thread for a smooth animation; cancel is polled per
    // batch. The detached handle ends when the loop breaks (job drops -> seed wiped).
    std::thread::spawn(move || {
        let mut job = job;
        loop {
            if shared.lock().unwrap().cancel {
                break;
            }
            let step = job.step(BATCH);
            {
                let mut m = shared.lock().unwrap();
                m.tries = job.tries;
                match step {
                    urb::spawn::SpawnStep::Working => {}
                    urb::spawn::SpawnStep::Done(r) => {
                        m.done = Some(Ok(r));
                        break;
                    }
                    urb::spawn::SpawnStep::Failed(e) => {
                        m.done = Some(Err(e));
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    String::new()
}

fn progress_err(e: &str, tries: u64) -> SpawnProgress {
    SpawnProgress {
        done: true,
        ok: false,
        error: e.into(),
        tries: tries as i32,
        comet: SharedString::new(),
        commit_txid: SharedString::new(),
        reveal_txid: SharedString::new(),
        boot_command: SharedString::new(),
    }
}

/// Read the worker-thread mine's progress (called from the UI Timer, main thread).
/// While searching, reports the live `tries`. Once finished, stashes the raw txs
/// on the draft for the broadcast QRs and reports the outcome.
fn spawn_poll(mine: &Arc<Mutex<MineShared>>, draft: &Rc<RefCell<DraftState>>) -> SpawnProgress {
    let mut m = mine.lock().unwrap();
    let tries = m.tries;
    match m.done.take() {
        None => SpawnProgress {
            done: false,
            ok: false,
            error: SharedString::new(),
            tries: tries as i32,
            comet: SharedString::new(),
            commit_txid: SharedString::new(),
            reveal_txid: SharedString::new(),
            boot_command: SharedString::new(),
        },
        Some(Ok(r)) => {
            {
                let mut d = draft.borrow_mut();
                d.commit_hex = r.commit_raw_hex.clone();
                d.reveal_hex = r.reveal_raw_hex.clone();
                // Keep the @p in the draft: the boot script's `--comet` needs it.
                d.comet = r.comet_patp.clone();
                d.feed_uw = r.feed_uw.clone();
            }
            SpawnProgress {
                done: true,
                ok: true,
                error: SharedString::new(),
                tries: tries as i32,
                // The user sees the mnemonym; the boot command/script keep the @p.
                comet: r.comet_nym.into(),
                commit_txid: r.commit_txid_display.into(),
                reveal_txid: r.reveal_txid_display.into(),
                boot_command: r.boot_command.into(),
            }
        }
        Some(Err(e)) => progress_err(&e, tries),
    }
}

/// Rebuild the draft for a paused identity (decode its mnemonic back to the seed,
/// reload any funding UTXO) and report where the wizard should resume.
fn load_identity(
    draft: &Rc<RefCell<DraftState>>,
    ids: &Rc<RefCell<Vec<store::Identity>>>,
    index: i32,
) -> ResumeInfo {
    let none = || ResumeInfo {
        ok: false,
        step: 0,
        index: -1,
        draft: IdentityDraft { funding_address: SharedString::new(), mnemonic: SharedString::new() },
    };
    if index < 0 {
        return none();
    }
    let idl = ids.borrow();
    let Some(it) = idl.get(index as usize) else { return none() };
    let Some(entropy) = bip39::from_mnemonic(&it.mnemonic).filter(|e| e.len() == 16) else {
        return none();
    };
    let funding = if it.funding.is_empty() {
        None
    } else {
        urb::spawn::parse_funding(&it.funding).ok()
    };
    // stage 2 (funded) resumes at the mine step; anything earlier at fund.
    let step = if it.stage >= store::stage::FUNDED && funding.is_some() { 6 } else { 4 };
    let (address, mnemonic) = (it.address.clone(), it.mnemonic.clone());
    *draft.borrow_mut() = DraftState {
        entropy,
        salt: salt_from(&address),
        mnemonic: mnemonic.clone(),
        address: address.clone(),
        funding,
        quiz: Vec::new(),
        commit_hex: String::new(),
        reveal_hex: String::new(),
        comet: String::new(),
        feed_uw: String::new(),
    };
    ResumeInfo {
        ok: true,
        step,
        index,
        draft: IdentityDraft { funding_address: address.into(), mnemonic: mnemonic.into() },
    }
}

/// Wrap a list of strings as a Slint `[string]` model.
fn string_model(items: Vec<String>) -> ModelRc<SharedString> {
    let v: Vec<SharedString> = items.into_iter().map(Into::into).collect();
    ModelRc::from(Rc::new(VecModel::from(v)))
}

/// A stable, non-secret shuffle salt for a draft's decoy grids. `DefaultHasher`
/// has fixed keys, so this is deterministic; the salt is never persisted.
fn salt_from(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn summaries(items: &[store::Identity]) -> Vec<IdentitySummary> {
    items
        .iter()
        .map(|it| IdentitySummary {
            label: it.label.clone().into(),
            address: it.address.clone().into(),
            stage: it.stage as i32,
            comet: it.comet.clone().into(),
        })
        .collect()
}

fn persist_and_refresh(items: &[store::Identity], model: &Rc<VecModel<IdentitySummary>>) {
    if let Err(e) = store::save(items) {
        log::error!("failed to persist identities: {e:?}");
    }
    model.set_vec(summaries(items));
}

/// Label an identity by its funding-address last-4 — collision-resistant, unlike
/// the first two `@q` words (docs/onboarding-flow.md §7).
fn label_from_address(address: &str) -> String {
    format!("…{}", &address[address.len().saturating_sub(4)..])
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn now_nanos() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

/// Optional system entropy mixed into the dice pool (defense in depth). The
/// hosted/simulator target has the OS CSPRNG; the xous device has no app-facing
/// TRNG (docs/trng-spike.md), so there the dice are the sole source — which is
/// exactly what the counted 50-roll floor guarantees.
#[cfg(not(target_os = "xous"))]
fn system_entropy() -> Vec<u8> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("OS CSPRNG must provide entropy");
    b.to_vec()
}

#[cfg(target_os = "xous")]
fn system_entropy() -> Vec<u8> {
    Vec::new()
}

/// BIP-340 auxiliary randomness for signing. Zeros are acceptable per BIP-340;
/// the device has no app TRNG, so it forgoes the nonce side-channel hardening.
#[cfg(not(target_os = "xous"))]
fn aux_rand() -> [u8; 32] {
    let mut a = [0u8; 32];
    getrandom::getrandom(&mut a).expect("OS CSPRNG must provide entropy");
    a
}

#[cfg(target_os = "xous")]
fn aux_rand() -> [u8; 32] {
    [0u8; 32]
}

/// CSPRNG for the comet miner (a fresh 64-byte seed per iteration). The
/// hosted/simulator target uses the OS CSPRNG; the xous device has no app TRNG,
/// so it derives a deterministic SHA-512 stream from the ticket seed — which also
/// makes the comet networking key recoverable from the ticket.
#[cfg(not(target_os = "xous"))]
fn spawn_rng(_seed: &[u8]) -> impl FnMut(&mut [u8; 64]) {
    |buf: &mut [u8; 64]| getrandom::getrandom(buf).expect("OS CSPRNG must provide entropy")
}

#[cfg(target_os = "xous")]
fn spawn_rng(seed: &[u8]) -> impl FnMut(&mut [u8; 64]) {
    let base = seed.to_vec();
    let mut ctr = 0u64;
    move |buf: &mut [u8; 64]| {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(&base);
        h.update(ctr.to_le_bytes());
        ctr += 1;
        buf.copy_from_slice(&h.finalize());
    }
}
