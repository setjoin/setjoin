//! MAM (Mobile Application Management) device-trust lifecycle — the single
//! owner of device checkin, policy caching, remote wipe, and screenshot
//! blocking for the SetJoin shell.
//!
//! This module is the platform bridge half of the device-trust split: it owns
//! the **HTTP** (checkin / policy fetch against the authserver `/device/*`
//! endpoints, signed with the per-device HMAC) and the **enforcement**
//! (screenshot block, wipe). `guard-core` owns only the cached **values** —
//! `store_device_id` / `store_mam_policy` / `get_mam_policy` / `mark_wiped` /
//! `is_wiped`. This file is the sole consumer of those guard-core setters
//! (the acceptance criterion of C2 Task 5): without it they would be
//! permanently-dead kept methods.
//!
//! ## Lifecycle
//! - **Checkin** (`mam_checkin`, callable by the future Connectivity E4
//!   start/resume composition owner; no production owner is wired yet): POST
//!   `{server}/device/checkin` with `X-Device-HMAC` + `X-Device-Timestamp`
//!   over the canonical challenge `"{device_id}:{timestamp}"`. The response
//!   carries the device's resolved policy (only when its version changed) and
//!   the wipe flag. On success the device id + policy are cached into
//!   guard-core; on `wipe_requested` we latch the wipe and clear webview
//!   storage.
//! - **Policy read** (`mam_get_policy`, `mam_is_wiped`): enforcement code reads
//!   the cached snapshot via guard-core `get_mam_policy` / `is_wiped`.
//! - **Remote wipe**: the pure reducer emits `LatchWipe` before
//!   `ClearWebStorage`; this adapter executes both in order. Once wiped,
//!   `is_wiped()` gates access until re-enrolment.
//! - **Screenshot block** (`apply_screen_capture_policy`): platform-specific —
//!   Android `FLAG_SECURE`, iOS secure-flag/blur-on-background, desktop no-op.
//!
//! The host build (desktop target) compiles the whole lifecycle: HTTP +
//! caching + wipe + policy are platform-agnostic; only the screenshot-block
//! body is `cfg`-gated per OS with a desktop no-op fallback.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_core::{GuardCore, MamPolicy};
use tauri::{AppHandle, Manager, State};

use crate::bridge::CapabilityState;
use crate::mam_lifecycle::{
    build_checkin_request, checkin_requires_flag_secure_retry, classify_surface, device_hmac,
    flag_secure_status, reduce_checkin_response, CheckinOutcome, CheckinResponse, EffectIntent,
    FlagSecureApply, FlagSecureDispatch, FlagSecureTracker, LateFlagSecureAck,
    SurfaceSensitivity,
};

/// Secure-store keys under which the device enrolment credentials are kept in
/// the guard-core vault (so they survive restarts and are AES-encrypted at
/// rest). Registration (which mints these) is the user-authenticated bootstrap;
/// this lifecycle consumes them for the per-device HMAC.
const SS_DEVICE_ID: &str = "mam:device_id";
const SS_HMAC_SECRET: &str = "mam:hmac_secret";
const SS_SERVER_URL: &str = "mam:server_url";

/// Tauri-managed MAM state. Holds the last-seen policy version (for the
/// server's `policy_version` short-circuit) so we only pull the full policy
/// body when it actually changed.
#[derive(Default)]
pub struct MamState {
    inner: Mutex<MamInner>,
}

#[derive(Default)]
struct MamInner {
    /// Client's currently-known policy version, echoed back on checkin so the
    /// server can omit the policy body when nothing changed.
    policy_version: i64,
    /// Whether the last enforced MAM policy blocks screen capture. Sourced from
    /// the reducer's `EnforcePolicy` intent — not re-read from the vault on
    /// every decision — so a locked vault mid-session cannot make a live
    /// `screen_capture=block` look unenforced (fail-secure, not fail-open).
    policy_blocks_capture: bool,
    /// The webmail surface the shell last reported (`mam_set_surface_route`).
    /// `Default` is non-sensitive — an unknown screen never claims protection.
    surface: SurfaceSensitivity,
    /// FLAG_SECURE decision tracker (DESKTOP-007): dedupes platform dispatches
    /// to state transitions so repeated checkins / same-surface navigations
    /// never flap the window flag. r2: `applied` flips only on an
    /// acknowledged JNI success; failed applications stay pending and retry
    /// on the next eligible tick. r3: dispatches carry op identities so a
    /// stale acknowledgment can never flip `applied` (dispatch and ack
    /// recording are independently ordered), and the pending retry is
    /// re-driven on EVERY checkin tick — including the 304 short-circuit.
    /// r4: a timed-out dispatch's LATE platform outcome is persisted in
    /// `flag_secure_late_acks` and drained through the tracker's op-id rules
    /// on the next drive, so the queued clear converges the state truthfully.
    flag_secure: FlagSecureTracker,
    /// Shared sink for FLAG_SECURE outcomes that completed after their
    /// dispatch's bounded wait had already timed out (DESKTOP-007 r4). r5:
    /// every completion is persisted here by the platform closure BEFORE the
    /// channel signal (lossless handoff), and the driver consumes an op's
    /// record when the signal was received through the channel, so the drain
    /// sees only genuinely unreceived outcomes.
    flag_secure_late_acks: FlagSecureLateAcks,
}

/// Shared sink for FLAG_SECURE outcomes that complete after their dispatch's
/// bounded wait already gave up (DESKTOP-007 r4), made lossless in r5: the
/// activity-thread closure persists EVERY completion here BEFORE attempting
/// the channel signal, so a completion landing in the post-timeout/pre-drop
/// window is durable even though its (successful) channel send dies with the
/// dropped receiver. Consumption is deduplicated by op id: the driver
/// consumes an op's record when its outcome arrived through the channel, and
/// the next drive drains only genuinely unreceived outcomes UNDER the state
/// lock, feeding each through the tracker's op-id-verified `acknowledge`. The
/// main thread must never take the MamState mutex (it would freeze behind an
/// in-flight dispatch), which is exactly why this indirection exists: the
/// late outcome survives in a lock the main thread can take briefly, and the
/// tracker only ever sees it on the driver's side, serialized with every
/// other decision.
#[derive(Default, Clone)]
pub(crate) struct FlagSecureLateAcks(Arc<Mutex<Vec<LateFlagSecureAck>>>);

impl FlagSecureLateAcks {
    /// Record a platform outcome (activity-thread side, r5: for EVERY
    /// completion, before the channel signal). Best-effort: a poisoned sink
    /// lock drops the record — the pending dispatch stays pending and the
    /// next tick re-drives it, so this can never report protection falsely.
    // Called only by the android-cfg'd closure in
    // `mam_android::set_flag_secure`; the host/iOS seams cannot produce late
    // outcomes (the android-target check compiles that caller).
    #[allow(
        dead_code,
        reason = "android-only caller: mam_android::set_flag_secure's activity-thread closure"
    )]
    pub(crate) fn record(&self, ack: LateFlagSecureAck) {
        if let Ok(mut acks) = self.0.lock() {
            acks.push(ack);
        }
    }

    /// Remove every recorded acknowledgment for `op` (driver side only).
    /// Called when the driver received this op's outcome through the
    /// acknowledgment channel: the closure's sink-first record (r5) for that
    /// same execution must not be acknowledged a second time by a later
    /// drain — channel receipt OR sink drain, never both. Records for other
    /// ops are untouched.
    fn consume(&self, op: u64) {
        if let Ok(mut acks) = self.0.lock() {
            acks.retain(|ack| ack.op != op);
        }
    }

    /// Take every recorded late acknowledgment (driver side only).
    fn drain(&self) -> Vec<LateFlagSecureAck> {
        self.0
            .lock()
            .map(|mut acks| std::mem::take(&mut *acks))
            .unwrap_or_default()
    }
}

// ── Server wire types (mirror authserver/internal/device/checkin.go) ────────

// ── Policy mapping ──────────────────────────────────────────────────────────

// ── HMAC proof ──────────────────────────────────────────────────────────────

/// Current unix-seconds timestamp as a string. The server's
/// `parseDeviceTimestamp` accepts unix seconds (or RFC 3339); unix seconds
/// avoids a date-formatting dependency.
fn unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

// ── Enrolment credential access (via the guard-core secure store) ───────────

/// Enrolment credentials needed to sign a device request.
struct Enrolment {
    server_url: String,
    device_id: i64,
    hmac_secret: String,
}

/// Load the device enrolment from the unlocked guard-core vault. Returns `None`
/// when the vault is locked or the device has not been enrolled yet (no
/// registration has stored the credentials).
fn load_enrolment(core: &Arc<GuardCore>) -> Option<Enrolment> {
    let server_url = core.meta_get(SS_SERVER_URL.into()).ok().flatten()?;
    let device_id_s = core.meta_get(SS_DEVICE_ID.into()).ok().flatten()?;
    let hmac_secret = core.meta_get(SS_HMAC_SECRET.into()).ok().flatten()?;
    let device_id = device_id_s.parse::<i64>().ok()?;
    Some(Enrolment {
        server_url,
        device_id,
        hmac_secret,
    })
}

// ── Commands ────────────────────────────────────────────────────────────────

/// Persist the device enrolment credentials into the vault. Called once after
/// `POST /device/register` returns `{device_id, hmac_secret}` (the registration
/// HTTP itself is the user-authenticated bootstrap; this caches its result so
/// subsequent checkins can sign with the per-device HMAC). Requires an unlocked
/// vault.
#[tauri::command]
pub fn mam_enroll(
    vault: State<'_, CapabilityState>,
    server_url: String,
    device_id: i64,
    hmac_secret: String,
) -> Result<(), String> {
    let core = vault.guard_if_unlocked().ok_or("vault locked")?;
    core.meta_set(SS_SERVER_URL.into(), server_url)
        .map_err(|e| e.to_string())?;
    core.meta_set(SS_DEVICE_ID.into(), device_id.to_string())
        .map_err(|e| e.to_string())?;
    core.meta_set(SS_HMAC_SECRET.into(), hmac_secret)
        .map_err(|e| e.to_string())?;
    // A successful (user-authenticated) enrolment re-arms the device: clear any
    // durable remote-wipe latch so a recovered device is usable again.
    core.clear_wiped().map_err(|e| e.to_string())?;
    // Cache the device id immediately so enforcement reads have it before the
    // first checkin completes.
    core.store_device_id(device_id.to_string());
    Ok(())
}

/// Run a device checkin against the authserver. POSTs the signed request,
/// caches the resolved device id + policy into guard-core, and latches a remote
/// wipe (clearing webview storage) when the server requests one.
///
/// No-ops (returns `ran: false`) when the vault is locked or the device is not
/// enrolled — the lifecycle is inert until the user has logged in and the
/// device is registered.
#[tauri::command]
pub async fn mam_checkin(
    app: AppHandle,
    vault: State<'_, CapabilityState>,
    state: State<'_, MamState>,
) -> Result<CheckinOutcome, String> {
    let Some(core) = vault.guard_if_unlocked() else {
        return Ok(CheckinOutcome::default());
    };
    // Already wiped — do not phone home; access stays gated.
    if core.is_wiped() {
        return Ok(CheckinOutcome {
            ran: false,
            policy_version: 0,
            wiped: true,
        });
    }
    let Some(enr) = load_enrolment(&core) else {
        return Ok(CheckinOutcome::default());
    };

    let known_version = state
        .inner
        .lock()
        .map_err(|e| e.to_string())?
        .policy_version;
    let timestamp = unix_timestamp();
    let request = build_checkin_request(
        &enr.server_url,
        enr.device_id,
        &enr.hmac_secret,
        &timestamp,
        known_version,
    );

    let resp = reqwest::Client::new()
        .post(&request.url)
        .header("X-Device-HMAC", &request.hmac)
        .header("X-Device-Timestamp", &request.timestamp)
        .header("If-None-Match", &request.if_none_match)
        .json(&request.body)
        .send()
        .await
        .map_err(|e| format!("mam checkin request failed: {e}"))?;

    let status = resp.status().as_u16();
    let parsed = if status == 304 || !(200..300).contains(&status) {
        None
    } else {
        Some(
            resp.json::<CheckinResponse>()
                .await
                .map_err(|e| format!("mam checkin: bad response: {e}"))?,
        )
    };
    let transition = reduce_checkin_response(status, known_version, enr.device_id, parsed)?;
    // DESKTOP-007 r3: required when the transition carried no EnforcePolicy
    // of its own (the 304 Not-Modified short-circuit is the motivating case).
    // Computed before the effects loop consumes `transition.effects`.
    let needs_retry_tick = checkin_requires_flag_secure_retry(&transition);
    // DESKTOP-007 r2: set when a required FLAG_SECURE application was not
    // acknowledged. The checkin effects before enforcement (wipe latch,
    // storage clear, device/policy caching) still run and stay cached, but the
    // client's known policy version is NOT advanced — so the next checkin's
    // `If-None-Match` no longer short-circuits to 304, the server re-pulls the
    // full policy, and `EnforcePolicy` retries. Returning `Err` also keeps the
    // caller (lifecycle owner / future Connectivity E4 composition) honestly
    // informed instead of reporting a clean checkin.
    let mut enforcement_error: Option<String> = None;
    for effect in transition.effects {
        match effect {
            EffectIntent::LatchWipe => {
                if let Err(error) = core.mark_wiped() {
                    eprintln!("mam: remote vault wipe failed: {error}");
                }
            }
            EffectIntent::ClearWebStorage => clear_web_storage(&app),
            EffectIntent::CacheDevice { device_id } => core.store_device_id(device_id),
            EffectIntent::CachePolicy { policy } => core.store_mam_policy(policy),
            EffectIntent::EnforcePolicy { policy } => {
                if let Err(error) = apply_screen_capture_policy(&app, &state, &policy) {
                    eprintln!("mam: screen-capture enforcement failed (will retry next tick): {error}");
                    enforcement_error = Some(error);
                }
            }
        }
    }

    // DESKTOP-007 r3: a checkin whose outcome produced no enforcement of its
    // own (304, or any effect list without EnforcePolicy) must STILL re-drive
    // a pending FLAG_SECURE dispatch. Without this, a failed route-report
    // application stays pending forever while the already-accepted policy
    // version 304s on every future checkin — the surface remains capturable.
    if needs_retry_tick {
        if let Err(error) = drive_flag_secure(&app, &state, FlagSecureTrigger::Tick) {
            eprintln!("mam: pending FLAG_SECURE retry failed (will retry next tick): {error}");
            enforcement_error = Some(error);
        }
    }

    if !transition.outcome.wiped && enforcement_error.is_none() {
        state
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .policy_version = transition.outcome.policy_version;
    }

    match enforcement_error {
        Some(error) => Err(format!(
            "mam checkin ran but screen-capture enforcement did not take \
             (policy version held back for re-enforcement): {error}"
        )),
        None => Ok(transition.outcome),
    }
}

/// Read the cached MAM policy snapshot (guard-core `get_mam_policy`). Returns
/// the typed fields the webmail/enforcement needs; `None` when no policy has
/// been fetched yet or the vault is locked.
#[tauri::command]
pub fn mam_get_policy(vault: State<'_, CapabilityState>) -> Result<Option<MamPolicyDto>, String> {
    let Some(core) = vault.guard_if_unlocked() else {
        return Ok(None);
    };
    Ok(core.get_mam_policy().map(MamPolicyDto::from))
}

/// Whether a remote wipe has been latched (guard-core `is_wiped`). The webmail
/// uses this to gate access (force a re-enrol / logged-out screen).
#[tauri::command]
pub fn mam_is_wiped(vault: State<'_, CapabilityState>) -> Result<bool, String> {
    Ok(vault
        .guard_if_unlocked()
        .map(|c| c.is_wiped())
        .unwrap_or(false))
}

/// The bridge-visible device-proof payload: only the HMAC hex, never the secret.
#[derive(serde::Serialize)]
pub struct DeviceProof {
    pub hmac: String,
}

/// Compute the device-proof HMAC for `device_id` and `timestamp` using the
/// per-device HMAC secret stored in the vault. The secret is never returned to
/// JS — only the computed proof is surfaced (analogous to the SQLCipher key).
///
/// Returns `None` when the vault is locked or the device is not enrolled (no
/// `mam_enroll` has stored credentials yet). The JS `attachDeviceProofHeaders`
/// gates on `hasCapability('deviceProof')` + a non-empty deviceId before
/// calling this, so `None` is a graceful no-op path.
#[tauri::command]
pub fn device_proof(
    vault: State<'_, CapabilityState>,
    device_id: String,
    timestamp: String,
) -> Result<Option<DeviceProof>, String> {
    let Some(core) = vault.guard_if_unlocked() else {
        return Ok(None);
    };
    let Some(hmac_secret) = core
        .meta_get(SS_HMAC_SECRET.into())
        .map_err(|e| e.to_string())?
    else {
        return Ok(None); // not enrolled
    };
    // parse to i64 so the challenge string matches the server contract
    // (device_id is stored as i64.to_string() by mam_enroll).
    let device_id_num: i64 = device_id
        .parse()
        .map_err(|_| format!("device_proof: invalid device_id: {device_id}"))?;
    Ok(Some(DeviceProof {
        hmac: device_hmac(&hmac_secret, device_id_num, &timestamp),
    }))
}

/// Serializable projection of [`MamPolicy`] for the bridge (the guard-core
/// type is not `Serialize`, and is owned by the crate).
#[derive(serde::Serialize)]
pub struct MamPolicyDto {
    pub policy_version: i64,
    pub copy_paste: String,
    pub screen_capture: String,
    pub encryption: String,
    pub watermark: bool,
    pub notification_profile: String,
    pub max_offline_days: i32,
}

impl From<MamPolicy> for MamPolicyDto {
    fn from(p: MamPolicy) -> Self {
        MamPolicyDto {
            policy_version: p.policy_version,
            copy_paste: p.copy_paste,
            screen_capture: p.screen_capture,
            encryption: p.encryption,
            watermark: p.watermark,
            notification_profile: p.notification_profile,
            max_offline_days: p.max_offline_days,
        }
    }
}

// ── Remote wipe ─────────────────────────────────────────────────────────────

/// Latch the wipe in guard-core and clear the webview's local storage so no
/// mail/session data survives. After this, `is_wiped()` gates access until the
/// device is re-enrolled.
fn clear_web_storage(app: &AppHandle) {
    // Clear all client-side storage in the webview (localStorage, sessionStorage,
    // IndexedDB, caches). Best-effort: a failed eval must not block the wipe latch.
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.eval(
            r#"
            try {
              localStorage.clear();
              sessionStorage.clear();
              if (window.indexedDB && indexedDB.databases) {
                indexedDB.databases().then(dbs =>
                  dbs.forEach(d => d.name && indexedDB.deleteDatabase(d.name))
                ).catch(() => {});
              }
              if (window.caches && caches.keys) {
                caches.keys().then(ks => ks.forEach(k => caches.delete(k))).catch(() => {});
              }
              window.dispatchEvent(new Event('setjoin-mam-wiped'));
            } catch (_e) {}
            "#,
        );
    }
}

// ── Screenshot block (platform-specific) ────────────────────────────────────
//
// Android: window FLAG_SECURE. iOS: secure-flag/blur-on-background. Desktop:
// no platform screen-capture-block API, so a no-op fallback keeps the lifecycle
// compiling and running on host.
//
// DESKTOP-007: the flag decision is pure (`mam_lifecycle`) and deduped through
// `FlagSecureTracker`, so both drivers below — the MAM policy refresh and the
// shell's surface reports — converge on one dispatch stream that only crosses
// the platform boundary on transitions.
//
// DESKTOP-007 r2: application is ACKNOWLEDGED, never assumed. The driver below
// computes the action, executes it on the platform, and feeds the outcome back
// through `FlagSecureTracker::acknowledge`. A failed application keeps the
// desired state pending (the next eligible lifecycle tick — route report,
// policy enforcement, or the per-checkin retry tick — retries) and is surfaced
// as `Err` to the caller, so a required FLAG_SECURE can never be reported (or
// treated) as active while the platform refused it.
//
// DESKTOP-007 r3: decision → dispatch → acknowledgment run under ONE lock
// hold (see `drive_flag_secure`). r2 released the state lock across the
// dispatch and wrote a pre-dispatch surface snapshot back afterwards, which
// let an allowing-policy refresh overwrite a newer sensitive-surface report
// and CLEAR protection; and two interleaved drives could record a stale
// success after a newer dispatch, falsely reporting protection.
//
// DESKTOP-007 r4: an acknowledgment that TIMES OUT is not a failure — the
// closure is still queued on the activity thread and may execute late, so
// the window state is unknown. (1) The platform seam reports its conclusion
// as a `FlagSecureApply` (completed / refused / ambiguous) and the status
// mapping (`mam_lifecycle::flag_secure_status`) reports every CLEAR that did
// not conclude successfully as `Err` — never `Ok(true)` from the historical
// `applied` (r5 widened this from ambiguous-only: a failed/refused clear is
// equally unconfirmed, because a superseded dispatch may have executed in
// its place). (2) The late outcome is not lost: the closure records it in a
// shared sink and the next drive drains it under the state lock, feeding it
// through the tracker's op-id rules — a still-matching pending dispatch
// settles truthfully, a superseded late ack is filtered, and until then the
// pending dispatch guarantees every status answer comes from a fresh
// platform outcome.
//
// DESKTOP-007 r5: the sink handoff is lossless and deduplicated. The
// closure persists EVERY completion into the sink BEFORE the channel signal,
// so a completion landing after `recv_timeout` gave up but before the driver
// dropped the (still-alive) receiver — the pre-r5 loss window: the send
// succeeded, no record existed, and the outcome died with the dropped
// receiver — is durable. The driver consumes an op's sink record when its
// outcome arrived through the channel, so channel receipt OR sink drain
// acknowledges an execution exactly once.

/// The lifecycle event that triggered a FLAG_SECURE re-evaluation. The
/// trigger's own input is installed under the state lock, and the decision is
/// made against the CURRENT `(policy_blocks_capture, surface)` pair — never
/// against a snapshot taken before the lock release.
enum FlagSecureTrigger {
    /// The shell reported a route transition: install the reported surface.
    Route(SurfaceSensitivity),
    /// An enforced policy arrived: install its capture decision.
    Policy(bool),
    /// A retry tick (periodic checkin with no policy body of its own): change
    /// nothing and re-evaluate against the current cached state, so a pending
    /// failed dispatch re-dispatches even when nothing else would.
    Tick,
}

/// Execute a FLAG_SECURE dispatch on the platform and acknowledge the outcome
/// in the tracker. `Ok(true)` means the platform acknowledged `FLAG_SECURE`
/// ON (protection active); `Ok(false)` means the acknowledged state is
/// honestly not-protecting. `Err` means the outcome does not support a
/// protection claim: a REQUIRED (`desired = true`) application was not
/// acknowledged (r2/r3), or a clear did not conclude successfully — its ack
/// timed out (r4: the queued clear may still execute late) or it
/// failed/refused while a SUPERSEDED dispatch may have executed in its place
/// (r5: the historical `applied` is not a live fact across a retry queue). In
/// every `Err` case the tracker holds the desired state pending for the next
/// tick, so no later status can be answered from the stale historical
/// `applied`.
fn drive_flag_secure(
    app: &AppHandle,
    state: &State<'_, MamState>,
    trigger: FlagSecureTrigger,
) -> Result<bool, String> {
    // DESKTOP-007 r3: ONE lock hold across decision, platform dispatch and
    // acknowledgment.
    //
    // Why hold it across the dispatch (r2 released it): the trigger input and
    // the `next_action` decision are made against state that cannot change
    // until the acknowledgment is recorded — there is no pre-dispatch snapshot
    // to write back (the finding-2 race: an allowing-policy refresh snapshot
    // of NonSensitive overwriting a newer /inbox protection), and dispatches
    // cannot interleave, so decision order == platform execution order ==
    // acknowledgment order (the finding-3 race: a stale true-ack recorded
    // after a newer false-dispatch reporting protection on a capturable
    // window). `Tracker::acknowledge` additionally refuses any op that is not
    // the latest dispatched one, so the state machine stays correct even if a
    // future driver releases the lock again.
    //
    // The hold cannot deadlock: the activity thread that must acknowledge
    // (wry main pipe → JNI shim → channel send) never takes this mutex, no
    // await happens inside, and the dispatch's wait is bounded by
    // FLAG_SECURE_ACK_TIMEOUT (3s). Concurrent drives queue on the mutex and
    // each re-decides against the post-acknowledgment state.
    let mut inner = state.inner.lock().expect("MAM state lock");
    match trigger {
        FlagSecureTrigger::Route(surface) => inner.surface = surface,
        FlagSecureTrigger::Policy(block) => inner.policy_blocks_capture = block,
        FlagSecureTrigger::Tick => {}
    }
    // DESKTOP-007 r4/r5: drain unreceived platform acknowledgments FIRST, so
    // a dispatch that executed after its bounded wait settles the tracker
    // before the decision. (The sink holds only outcomes whose channel
    // signal was never received — a received outcome's sink-first record was
    // already consumed by op id.) Each record flows through the same
    // op-id-verified `acknowledge`: a late ack whose dispatch is still the
    // pending one converges `applied` to the window's real state; a late ack
    // a newer dispatch has superseded is filtered and moves nothing.
    for ack in inner.flag_secure_late_acks.drain() {
        inner.flag_secure.acknowledge(ack.op, ack.desired, ack.succeeded);
    }
    let action = {
        // Locals stay inside this same critical section — still one coherent
        // (policy, surface) pair, read after the trigger was installed.
        let (blocks, surface) = (inner.policy_blocks_capture, inner.surface);
        inner.flag_secure.next_action(blocks, surface)
    };
    match action {
        FlagSecureDispatch::Settled => Ok(inner.flag_secure.applied() == Some(true)),
        FlagSecureDispatch::Dispatch { op, blocked } => {
            // Execute on the platform, then acknowledge the op we dispatched.
            // A completed success flips `applied`; anything else keeps the
            // desired state pending so the next tick retries — including an
            // ambiguous outcome, whose LATE acknowledgment (sink above) will
            // later match this still-pending op and settle it truthfully, or
            // be filtered if a newer dispatch supersedes it first.
            let late_acks = inner.flag_secure_late_acks.clone();
            let outcome = set_screen_capture_blocked(app, blocked, op, &late_acks);
            // DESKTOP-007 r5: the platform closure persists every completion
            // into the sink BEFORE signaling the channel (lossless handoff).
            // A conclusion delivered through the channel has therefore ALSO
            // left a sink record for this execution; consume it by op id so
            // the next drive's drain cannot acknowledge the same execution
            // twice. Ambiguous/Refused conclusions were NOT received here —
            // a record the closure still produces stays in the sink for the
            // next drain.
            if matches!(outcome, FlagSecureApply::Completed(_)) {
                inner.flag_secure_late_acks.consume(op);
            }
            let acknowledged = matches!(&outcome, FlagSecureApply::Completed(Ok(())));
            inner.flag_secure.acknowledge(op, blocked, acknowledged);
            // The status mapping owns the honesty contract (r4/r5): any
            // non-conclusive clear reports `Err` — never `Ok(true)` from the
            // historical `applied` — and every failure keeps the dispatch
            // pending for the next eligible tick.
            let status = flag_secure_status(&outcome, blocked);
            if let Err(report) = &status {
                eprintln!("{report}");
            }
            status
        }
    }
}

/// Record an enforced policy's capture decision and drive the FLAG_SECURE
/// dispatch against the surface the shell last reported. The policy decision
/// is cached even when the dispatch fails (fail-secure: a locked vault or a
/// wedged activity thread cannot make an enforced `screen_capture=block` look
/// unenforced to later surface reports).
fn enforce_policy_capture_block(
    app: &AppHandle,
    state: &State<'_, MamState>,
    block: bool,
) -> Result<bool, String> {
    drive_flag_secure(app, state, FlagSecureTrigger::Policy(block))
}

/// Apply (or clear) the platform screen-capture block according to the policy's
/// `screen_capture` field (`"block"` vs `"allow"`), combined with the surface
/// the shell last reported. Only transitions dispatch (see
/// [`enforce_policy_capture_block`]). The policy path dispatches on every
/// mobile target: Android toggles `FLAG_SECURE`, iOS installs/removes the
/// secure overlay, desktop is a no-op.
///
/// DESKTOP-007 r2: returns `Err` when a required application was not
/// acknowledged — [`mam_checkin`] propagates it (and holds back the policy
/// version) so the next checkin re-pulls the policy and re-enforces.
/// DESKTOP-007 r4: `Err` additionally covers an AMBIGUOUS outcome (a timed-out
/// clear whose queued dispatch may still execute late): the honest checkin
/// error forces the re-pull + re-enforcement that converges the window state
/// instead of letting the tick report a clean run from an unknown state.
fn apply_screen_capture_policy(
    app: &AppHandle,
    state: &State<'_, MamState>,
    policy: &MamPolicy,
) -> Result<(), String> {
    let block = policy.screen_capture == "block";
    enforce_policy_capture_block(app, state, block).map(|_| ())
}

/// DESKTOP-007 — the shell reports every webmail route transition (injected
/// watcher in `bridge_js`, Android build) so the activity window carries
/// `FLAG_SECURE` exactly while message content is on screen: chat
/// conversations, email bodies, quarantined message previews force it on;
/// non-sensitive screens clear it unless the MAM policy blocks capture. The
/// route is classified in Rust (`mam_lifecycle::classify_surface`, unit-tested)
/// — the JS side only forwards `location.pathname`. The policy input is the
/// last enforcement cached by [`apply_screen_capture_policy`] — a locked vault
/// cannot make an enforced block look unenforced.
///
/// Honest status contract (DESKTOP-007 r2, r4, r5):
/// - `Ok(true)` — the platform ACKNOWLEDGED `FLAG_SECURE` ON; the surface is
///   protected.
/// - `Ok(false)` — the acknowledged state is honestly not protecting (cleared
///   on a non-sensitive screen, or not yet successfully applied anywhere).
/// - `Err(..)` — the outcome does not support a protection claim: either the
///   REQUIRED (desired-on) application was NOT acknowledged (the surface is
///   NOT protected; r2), or a clear did not conclude successfully — its ack
///   timed out (the queued clear may still execute late, r4) or it
///   failed/refused while a superseded dispatch may have executed in its
///   place, so the protection state is UNKNOWN and is never answered from the
///   historical `applied` (r5). In both cases the desired state stays pending
///   in the tracker and is retried on the next eligible tick; the late
///   acknowledgment converges the tracker through the op-id rules, and the
///   Android route watcher resets its same-path dedupe on any rejection so
///   the surface re-drives.
///
/// Enforcement is Android-only; on other targets the decision is computed and
/// tracked but [`set_screen_capture_blocked`] is a documented no-op that
/// cannot fail.
#[tauri::command]
pub fn mam_set_surface_route(
    app: AppHandle,
    state: State<'_, MamState>,
    route: String,
) -> Result<bool, String> {
    let surface = classify_surface(&route);
    drive_flag_secure(&app, &state, FlagSecureTrigger::Route(surface))
}

/// Desktop fallback — no platform screen-capture-block API. No-op so the
/// lifecycle compiles and runs on host (`cargo build -p setjoin-desktop`).
///
/// C2 cfg(mobile) — target-checked post-init: the Android/iOS bodies below are
/// only compiled for those targets; the orchestrator compile-checks them after
/// `tauri ios/android init`.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn set_screen_capture_blocked(
    _app: &AppHandle,
    _blocked: bool,
    _op: u64,
    _late_acks: &FlagSecureLateAcks,
) -> FlagSecureApply {
    // No desktop screen-capture-block API; intentionally a no-op that cannot
    // fail (nothing is claimed to be enforced here).
    FlagSecureApply::Completed(Ok(()))
}

/// Android — toggle `WindowManager.LayoutParams.FLAG_SECURE` on the activity
/// window so the OS excludes the app from screenshots and the recents preview.
///
/// C2 cfg(mobile) — target-checked post-init.
///
/// DESKTOP-007 r2: returns the JNI outcome so the tracker only records
/// acknowledged application. Deliberately NOT wrapped in
/// `run_on_main_thread`: wry's `dispatch` already serializes the closure onto
/// the activity's thread, and `set_flag_secure` blocks on the acknowledgment
/// channel — waiting for the main loop from INSIDE a main-thread closure would
/// deadlock until the timeout on every toggle.
#[cfg(target_os = "android")]
fn set_screen_capture_blocked(
    _app: &AppHandle,
    blocked: bool,
    op: u64,
    late_acks: &FlagSecureLateAcks,
) -> FlagSecureApply {
    // FLAG_SECURE = 0x2000. Set/clear it on the activity's window via JNI
    // (mam_android dispatches through wry's main pipe and invokes the tracked
    // android-integration shim's `setFlagSecure`, injected into the generated
    // MainActivity). The op identity + late-ack sink travel with the dispatch:
    // a timed-out acknowledgment may still execute late, and its outcome is
    // recorded for the next drive's drain instead of being lost (r4).
    crate::mam_android::set_flag_secure(blocked, op, late_acks)
}

/// iOS — block screen capture via a secure overlay and blur-on-background.
/// UIKit has no public "disable screenshot" API; the platform-accepted
/// approach is a secure `UITextField` overlay (its `isSecureTextEntry` layer is
/// excluded from screen recording/AirPlay) plus blurring the key window when the
/// app resigns active.
///
/// C2 cfg(mobile) — target-checked post-init.
///
/// Honest-status seam (DESKTOP-007 r2): iOS reports `Completed` after the objc
/// dispatch is SCHEDULED — the objc shim has no synchronous acknowledgment, so
/// iOS keeps the pre-r2 best-effort semantics (documented; the acknowledged-
/// application guarantee of this package is scoped to the Android JNI path). A
/// scheduling failure is definitive (nothing was queued).
#[cfg(target_os = "ios")]
fn set_screen_capture_blocked(
    app: &AppHandle,
    blocked: bool,
    _op: u64,
    _late_acks: &FlagSecureLateAcks,
) -> FlagSecureApply {
    // Delegated to the generated Swift glue (gen/apple) which installs/removes a
    // secure-field overlay on the key window and a blur snapshot on
    // `applicationWillResignActive`. Bridged here through an objc shim.
    app.run_on_main_thread(move || {
        crate::mam_ios::set_secure_overlay(blocked);
    })
    .map(|()| FlagSecureApply::Completed(Ok(())))
    .unwrap_or_else(|error| {
        FlagSecureApply::Completed(Err(format!(
            "mam_ios: scheduling secure overlay({blocked}) failed: {error}"
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DESKTOP-007 r4/r5: the sink persists platform outcomes (r5: EVERY
    /// completion, recorded before the channel signal), drains exactly once
    /// in completion order, and is shareable (the activity-thread closure
    /// holds a clone while the driver drains the original under the state
    /// lock).
    #[test]
    fn flag_secure_late_acks_drain_records_exactly_once() {
        let sink = FlagSecureLateAcks::default();
        assert!(sink.drain().is_empty(), "a fresh sink is empty");
        // The closure's clone records every completion sink-first (r5).
        let closure_handle = sink.clone();
        closure_handle.record(LateFlagSecureAck {
            op: 7,
            desired: false,
            succeeded: true,
        });
        closure_handle.record(LateFlagSecureAck {
            op: 8,
            desired: true,
            succeeded: false,
        });
        let drained = sink.drain();
        assert_eq!(
            drained,
            vec![
                LateFlagSecureAck {
                    op: 7,
                    desired: false,
                    succeeded: true
                },
                LateFlagSecureAck {
                    op: 8,
                    desired: true,
                    succeeded: false
                },
            ]
        );
        // Exactly once: the next drive's drain sees nothing.
        assert!(sink.drain().is_empty());
    }

    /// DESKTOP-007 r5 (P2) — the timeout → send → drop boundary. The android
    /// closure persists EVERY completion into the sink BEFORE signaling the
    /// channel, so a completion landing after `recv_timeout` gave up but
    /// before the driver dropped the (still-alive) receiver cannot vanish
    /// with the doomed channel: the pre-r5 code recorded nothing in that
    /// window (the send SUCCEEDED), and the outcome was lost when the dropped
    /// receiver destroyed the channel. Here the boundary is modeled
    /// deterministically on the host: the record + a SUCCESSFUL channel send
    /// happen in the window, the driver never receives (it already answered
    /// Ambiguous) and drops the receiver, and the completion still reaches
    /// the tracker via the next drive's sink drain — whose op-id rules settle
    /// the still-pending dispatch truthfully.
    #[test]
    fn flag_secure_completion_survives_timeout_send_drop_boundary() {
        let sink = FlagSecureLateAcks::default();
        let mut tracker = FlagSecureTracker::default();
        // Drive 0: required-on application acknowledged.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        tracker.acknowledge(0, true, true);
        assert_eq!(tracker.applied(), Some(true));
        // Drive 1 dispatches the clear; its bounded wait TIMES OUT
        // (acknowledge records no success; the dispatch stays pending).
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: false }
        );
        tracker.acknowledge(1, false, false);
        assert_eq!(tracker.pending(), Some(false));
        // The closure executes in the post-timeout/pre-drop window:
        // sink-first record, then a send that SUCCEEDS because the receiver
        // is still alive (exactly the record the pre-r5 code never wrote).
        let (ack_tx, ack_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        sink.record(LateFlagSecureAck {
            op: 1,
            desired: false,
            succeeded: true,
        });
        ack_tx
            .send(Ok(()))
            .expect("receiver is alive in the timeout→drop window");
        // The driver never consumes the channel value (it already returned
        // Ambiguous) and the receiver is dropped — the sent outcome dies with
        // the channel, but the sink record is durable.
        drop(ack_rx);
        drop(ack_tx);
        // Next drive: the drain feeds the record through the op-id rules; op
        // 1 is still the pending dispatch, so the late completion settles it
        // truthfully at the window's real (cleared) state.
        for ack in sink.drain() {
            tracker.acknowledge(ack.op, ack.desired, ack.succeeded);
        }
        assert_eq!(tracker.applied(), Some(false));
        assert_eq!(tracker.pending(), None);
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Settled
        );
    }

    /// DESKTOP-007 r5 (P2) — consumption is deduplicated by op id. When the
    /// driver received an execution's outcome through the channel
    /// (`Completed`), it consumes that op's sink-first record, so the next
    /// drive's drain cannot acknowledge the same execution twice; records for
    /// other (still-unreceived) ops survive the consume untouched.
    #[test]
    fn flag_secure_channel_receipt_consumes_sink_record_by_op() {
        let sink = FlagSecureLateAcks::default();
        // The closure persists every completion sink-first...
        sink.record(LateFlagSecureAck {
            op: 3,
            desired: true,
            succeeded: true,
        });
        // ...and an UNRELATED late completion is also in the sink (its
        // channel send failed — driver already gone).
        sink.record(LateFlagSecureAck {
            op: 4,
            desired: false,
            succeeded: true,
        });
        // The driver receives op 3 through the channel (the send landed
        // before the receiver was dropped) and consumes it by op id — the
        // `Completed` path in drive_flag_secure.
        sink.consume(3);
        let drained = sink.drain();
        assert_eq!(
            drained,
            vec![LateFlagSecureAck {
                op: 4,
                desired: false,
                succeeded: true,
            }],
            "the received op's record is consumed; unreceived ops drain normally"
        );
        // Idempotent: consuming a drained/unknown op is a no-op.
        sink.consume(3);
        assert!(sink.drain().is_empty());
    }
}
