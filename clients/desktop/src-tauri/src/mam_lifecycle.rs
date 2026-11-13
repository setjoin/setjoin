//! Pure MAM check-in request construction and response reduction.
//!
//! The adjacent `mam` module owns HTTP, secure state, web-storage clearing and
//! platform enforcement. Keeping those effects out of this module lets every
//! shell prove the same versioned transition corpus without cross-language FFI.

use std::collections::HashMap;

use guard_core::MamPolicy;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, serde::Serialize)]
pub struct CheckinRequestBody {
    pub device_id: i64,
    pub policy_version: i64,
}

#[derive(Debug)]
pub struct CheckinRequest {
    pub url: String,
    pub hmac: String,
    pub timestamp: String,
    pub if_none_match: String,
    pub body: CheckinRequestBody,
}

#[derive(Debug, Deserialize, Default)]
pub struct CheckinResponse {
    #[serde(default)]
    pub policy_version: i64,
    #[serde(default)]
    pub policy: HashMap<String, String>,
    #[serde(default)]
    pub wipe_requested: bool,
}

#[derive(Debug, serde::Serialize, Default, PartialEq)]
pub struct CheckinOutcome {
    pub ran: bool,
    pub policy_version: i64,
    pub wiped: bool,
}

#[derive(Debug)]
pub enum EffectIntent {
    LatchWipe,
    ClearWebStorage,
    CacheDevice { device_id: String },
    CachePolicy { policy: MamPolicy },
    EnforcePolicy { policy: MamPolicy },
}

impl EffectIntent {
    #[cfg(test)]
    fn name(&self) -> &'static str {
        match self {
            EffectIntent::LatchWipe => "latch_wipe",
            EffectIntent::ClearWebStorage => "clear_web_storage",
            EffectIntent::CacheDevice { .. } => "cache_device",
            EffectIntent::CachePolicy { .. } => "cache_policy",
            EffectIntent::EnforcePolicy { .. } => "enforce_policy",
        }
    }
}

#[derive(Debug)]
pub struct CheckinTransition {
    pub outcome: CheckinOutcome,
    pub effects: Vec<EffectIntent>,
}

pub fn device_hmac(secret: &str, device_id: i64, timestamp: &str) -> String {
    let challenge = format!("{device_id}:{timestamp}");
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn build_checkin_request(
    server_url: &str,
    device_id: i64,
    secret: &str,
    timestamp: &str,
    known_version: i64,
) -> CheckinRequest {
    CheckinRequest {
        url: format!("{}/device/checkin", server_url.trim_end_matches('/')),
        hmac: device_hmac(secret, device_id, timestamp),
        timestamp: timestamp.to_owned(),
        if_none_match: known_version.to_string(),
        body: CheckinRequestBody {
            device_id,
            policy_version: known_version,
        },
    }
}

pub fn reduce_checkin_response(
    status: u16,
    known_version: i64,
    device_id: i64,
    response: Option<CheckinResponse>,
) -> Result<CheckinTransition, String> {
    if status == 304 {
        return Ok(CheckinTransition {
            outcome: CheckinOutcome {
                ran: true,
                policy_version: known_version,
                wiped: false,
            },
            effects: Vec::new(),
        });
    }
    if !(200..300).contains(&status) {
        return Err(format!("mam checkin: server returned {status}"));
    }
    let response = response.ok_or_else(|| "mam checkin: bad response".to_string())?;
    if response.wipe_requested {
        return Ok(CheckinTransition {
            outcome: CheckinOutcome {
                ran: true,
                policy_version: response.policy_version,
                wiped: true,
            },
            effects: vec![EffectIntent::LatchWipe, EffectIntent::ClearWebStorage],
        });
    }

    let policy = policy_from_map(response.policy_version, &response.policy);
    Ok(CheckinTransition {
        outcome: CheckinOutcome {
            ran: true,
            policy_version: response.policy_version,
            wiped: false,
        },
        effects: vec![
            EffectIntent::CacheDevice {
                device_id: device_id.to_string(),
            },
            EffectIntent::CachePolicy {
                policy: policy.clone(),
            },
            EffectIntent::EnforcePolicy { policy },
        ],
    })
}

/// DESKTOP-007 r3: whether a completed checkin must ALSO re-drive a pending
/// FLAG_SECURE dispatch. Required exactly when the transition carried no
/// `EnforcePolicy` effect of its own and the device was not wiped. The
/// motivating case is the `304 Not Modified` short-circuit (empty effects,
/// policy version unchanged): with an already-accepted policy version the r2
/// hold-back of `policy_version` cannot help — every future checkin 304s — so
/// without this tick a failed route-report application would stay pending
/// forever while the surface is capturable. A transition that DOES carry
/// `EnforcePolicy` needs no extra tick (its own enforcement pass re-drives);
/// a wiped device is locked down regardless.
pub fn checkin_requires_flag_secure_retry(transition: &CheckinTransition) -> bool {
    !transition.outcome.wiped
        && !transition
            .effects
            .iter()
            .any(|effect| matches!(effect, EffectIntent::EnforcePolicy { .. }))
}

// ── FLAG_SECURE decision (DESKTOP-007) ──────────────────────────────────────
//
// Pure toggle logic for the Android screen-capture block. The platform JNI
// side (`mam_android`) consumes these decisions; keeping the decision here
// (no FFI, no threads) lets every shell unit-test the exact rules that decide
// when the window must exclude itself from screenshots/recording.

/// The first path segment of the webmail routes that render message content
/// (chat conversations, email bodies, quarantined message previews). Matching
/// is whole-segment: `/chat` is sensitive, `/chatx` is not.
pub const SENSITIVE_ROUTE_SEGMENTS: &[&str] = &["chat", "inbox", "quarantine"];

/// Whether the surface currently shown in the webview renders sensitive
/// content. `Default` is [`SurfaceSensitivity::NonSensitive`] — an unknown or
/// not-yet-reported screen never claims protection it has not justified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SurfaceSensitivity {
    /// Chat conversations, email bodies, quarantined message previews.
    Sensitive,
    /// Settings, admin, calendars, lists without message content, login, ...
    #[default]
    NonSensitive,
}

/// Classify a webmail route path by its first path segment. Unknown or empty
/// routes are non-sensitive (fail-open for the *flag*, never for the policy:
/// an enforced MAM `screen_capture=block` keeps the flag on regardless — see
/// [`desired_flag_secure`]).
pub fn classify_surface(route: &str) -> SurfaceSensitivity {
    let segment = route
        .split('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("");
    if SENSITIVE_ROUTE_SEGMENTS.contains(&segment) {
        SurfaceSensitivity::Sensitive
    } else {
        SurfaceSensitivity::NonSensitive
    }
}

/// The desired `FLAG_SECURE` state for the activity window: on when the MAM
/// policy blocks screen capture (whole-device enforcement), or when the
/// currently shown surface renders sensitive content; off only when the
/// policy allows AND the screen is non-sensitive.
pub fn desired_flag_secure(
    policy_blocks_capture: bool,
    surface: SurfaceSensitivity,
) -> bool {
    policy_blocks_capture || surface == SurfaceSensitivity::Sensitive
}

/// The action [`FlagSecureTracker::next_action`] hands the platform driver.
///
/// The tracker owns *decision* only; the driver (mam.rs) executes the dispatch
/// against the platform and reports the outcome back through
/// [`FlagSecureTracker::acknowledge`]. DESKTOP-007 r2: application is
/// acknowledged, never assumed — `applied` flips only on a platform success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagSecureDispatch {
    /// The desired state is already the platform-*acknowledged* state; no JNI
    /// dispatch is needed.
    Settled,
    /// Dispatch this desired state to the platform — first application, a
    /// genuine transition, or a retry of a previously failed application.
    /// `op` is the dispatch's operation identity (DESKTOP-007 r3): the
    /// acknowledgment fed back through [`FlagSecureTracker::acknowledge`] must
    /// carry it, and only the acknowledgment of the LATEST dispatched `op`
    /// may move the tracker's state.
    Dispatch {
        op: u64,
        blocked: bool,
    },
}

/// A dispatch handed to the platform but not (yet) acknowledged: its
/// operation identity and the desired state it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingDispatch {
    op: u64,
    desired: bool,
}

/// Deduplicates the JNI dispatches that apply [`desired_flag_secure`] to the
/// activity window, and tracks application *honestly*: a desired state is only
/// `applied` once the platform acknowledged it. Every policy refresh and route
/// change recomputes the desired state; only *transitions* (or retries of a
/// failed application) cross the JNI boundary so repeated checkins /
/// same-surface navigations never flap the window flag (Android rebuilds the
/// recents/task-switcher preview when it changes).
///
/// State model (DESKTOP-007 r2):
/// - `applied`: the desired state last acknowledged by the platform (JNI
///   success). This is the only state a caller may report as "protected".
/// - `pending`: the dispatch handed to the platform that has not (yet) been
///   acknowledged. A failed dispatch KEEPS `pending`, so the next eligible
///   lifecycle tick (route report, policy enforcement, or the per-checkin
///   retry tick — DESKTOP-007 r3) returns
///   [`FlagSecureDispatch::Dispatch`] again and retries.
///
/// DESKTOP-007 r3: every dispatch carries a monotonically increasing `op`
/// identity, and [`FlagSecureTracker::acknowledge`] updates state ONLY for the
/// op currently pending — a stale success recorded after a newer dispatch can
/// otherwise report `applied = true` while the window was actually cleared
/// (a false-protection report while the surface is capturable).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlagSecureTracker {
    /// Identity of the next dispatch (`PendingDispatch::op`).
    next_op: u64,
    /// Dispatch handed to the platform but not yet acknowledged; `None` when
    /// nothing is in flight or failing. A newer dispatch REPLACES it (the
    /// superseded op's acknowledgment, if it ever arrives, is stale and
    /// updates nothing).
    pending: Option<PendingDispatch>,
    /// The desired state last acknowledged applied by the platform, `None`
    /// until the first JNI success.
    applied: Option<bool>,
}

impl FlagSecureTracker {
    /// Compute the next platform action for `(policy_blocks_capture, surface)`.
    /// Returns [`FlagSecureDispatch::Settled`] exactly when the desired state
    /// equals the acknowledged state and nothing is pending. The first call
    /// always dispatches an explicit state — including a deliberate
    /// `clearFlags` (a harmless no-op on a fresh window that defends against a
    /// stale `FLAG_SECURE` on a recycled activity instance). A dispatch that
    /// was never acknowledged (failure) is re-returned on every subsequent
    /// tick until it succeeds or the desired state changes; each re-issue (and
    /// every new transition) carries a FRESH operation identity so a late
    /// acknowledgment of a superseded dispatch can never be mistaken for the
    /// current one.
    pub fn next_action(
        &mut self,
        policy_blocks_capture: bool,
        surface: SurfaceSensitivity,
    ) -> FlagSecureDispatch {
        let desired = desired_flag_secure(policy_blocks_capture, surface);
        if self.applied == Some(desired) && self.pending.is_none() {
            return FlagSecureDispatch::Settled;
        }
        let op = self.next_op;
        self.next_op += 1;
        self.pending = Some(PendingDispatch { op, desired });
        FlagSecureDispatch::Dispatch { op, blocked: desired }
    }

    /// Record the platform's acknowledgment for the dispatch identified by
    /// `op` (as returned by [`FlagSecureTracker::next_action`]).
    ///
    /// DESKTOP-007 r3: ONLY the acknowledgment of the LATEST dispatched op may
    /// move state. A success for the pending op flips `applied` (and clears
    /// the pending dispatch); failure leaves `pending` in place — the state
    /// machine deliberately stays un-acknowledged so the next tick retries.
    /// A stale/superseded acknowledgment (dispatch and acknowledgment are
    /// independently ordered) updates NOTHING: recording its desired state
    /// could report protection the window no longer carries.
    pub fn acknowledge(&mut self, op: u64, desired: bool, succeeded: bool) {
        // Only a SUCCESS acknowledgment for the op currently pending may move
        // state. Anything else — a stale/superseded op (dispatch and
        // acknowledgment recording are independently ordered), an unknown op,
        // or a failure (the pending dispatch stays in place so the next tick
        // retries) — updates nothing.
        let matches_latest_pending = match self.pending {
            Some(pending) => pending.op == op && pending.desired == desired && succeeded,
            None => false,
        };
        if !matches_latest_pending {
            return;
        }
        self.applied = Some(desired);
        self.pending = None;
    }

    /// The desired state last acknowledged by the platform (`None` until the
    /// first JNI success). Report "protection active" ONLY from
    /// `Some(true)` — a dispatched-but-unacknowledged `true` must never count.
    pub fn applied(&self) -> Option<bool> {
        self.applied
    }

    /// The desired state currently dispatched-but-unacknowledged (`None` when
    /// fully settled). Production reporting goes through [`Self::applied`]
    /// only; this accessor exists for the state-machine tests' intermediate
    /// assertions (same pattern as [`EffectIntent::name`]).
    #[cfg(test)]
    pub fn pending(&self) -> Option<bool> {
        self.pending.map(|pending| pending.desired)
    }
}

/// How a platform FLAG_SECURE dispatch concluded (DESKTOP-007 r4). The bare
/// `Result<(), String>` this replaces could not distinguish a dispatch whose
/// outcome is *definitive* (the window was or was not touched, nothing is left
/// queued) from one whose acknowledgment merely *timed out* — the closure is
/// still queued on the activity thread and may execute late, so the window
/// state is UNKNOWN. DESKTOP-007 r5: only `Completed(Ok)` is an authoritative
/// STATUS answer — the driver calls [`flag_secure_status`] with the outcome of
/// the dispatch it just made for the op currently pending, so a definitive
/// success is the one conclusion that describes the live window. Every other
/// conclusion is unconfirmed (see [`flag_secure_status`]): even a refused
/// dispatch says nothing about a SUPERSEDED one, which may have executed in
/// between.
// `Refused`/`Ambiguous` are constructed only by the android-cfg'd
// `mam_android::set_flag_secure` — the host/iOS seams cannot produce them, so
// the host build sees the variants as dead (the android-target check compiles
// those constructors).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "android-only constructors: mam_android::set_flag_secure"
)]
pub enum FlagSecureApply {
    /// The platform call completed and reported its JNI outcome: `Ok(())` when
    /// it succeeded, `Err` when it definitively failed. Nothing is left queued
    /// on the activity thread in either case.
    Completed(Result<(), String>),
    /// The dispatch was refused before anything was queued (e.g. no activity
    /// registered with wry yet): nothing can execute late, the window is
    /// untouched.
    Refused(String),
    /// The acknowledgment did not arrive within the bounded wait: the closure
    /// is STILL queued on the activity thread and may execute late. The window
    /// state is unknown until the late outcome is observed and recorded into
    /// the late-ack sink (see [`LateFlagSecureAck`]).
    Ambiguous(String),
}

/// A platform FLAG_SECURE outcome that arrived after its dispatch's bounded
/// wait had already timed out (DESKTOP-007 r4): the dispatch's operation
/// identity, the desired state it carried, and whether the late execution
/// succeeded. The activity-thread closure records this into the driver's
/// late-ack sink instead of letting the outcome die with the dropped channel;
/// the next drive drains the sink and feeds each record through
/// [`FlagSecureTracker::acknowledge`], whose op-id rules settle a still-matching
/// pending dispatch truthfully and filter any late ack a newer dispatch has
/// already superseded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateFlagSecureAck {
    pub op: u64,
    pub desired: bool,
    pub succeeded: bool,
}

/// The honest command status for a finished FLAG_SECURE dispatch (DESKTOP-007
/// r4, r5) — the `bool` a driver reports as "the surface is protected".
///
/// - A completed success is the ONLY authoritative answer: `Ok(blocked)`. The
///   driver calls this with the outcome of the dispatch it just made for the
///   op currently pending, so `Completed(Ok)` describes the live window.
/// - EVERY other conclusion answers `Err` — it does not support a protection
///   claim:
///   - a failed/refused REQUIRED (desired-on) application leaves the surface
///     NOT protected — loud `Err`, pending retry (r2/r3, unchanged);
///   - an AMBIGUOUS outcome (ack timed out) leaves the window state UNKNOWN —
///     the closure is still queued and may execute late (r4);
///   - r5: a failed/refused CLEAR is UNCONFIRMED and is never answered from
///     the tracker's historical `applied`. Historical state is not a live
///     fact across a retry queue: an earlier SUPERSEDED dispatch (e.g. clear
///     op1 whose ack timed out, with clear op2 re-driven on the next tick) may
///     have executed in between, so `applied = Some(true)` can be stale in
///     BOTH directions — reporting `Ok(true)` there would resurrect
///     protection op1 already removed (and let a checkin advance the policy
///     version on that lie). The dispatch deliberately stays pending after any
///     non-success, which structurally forces the next status answer to come
///     from a fresh platform outcome; the late acknowledgment converges the
///     tracker through the op-id rules.
pub fn flag_secure_status(outcome: &FlagSecureApply, blocked: bool) -> Result<bool, String> {
    match outcome {
        FlagSecureApply::Completed(Ok(())) => Ok(blocked),
        FlagSecureApply::Completed(Err(error)) | FlagSecureApply::Refused(error) if blocked => Err(
            format!(
                "mam: FLAG_SECURE application failed — surface is NOT protected \
                 (desired on, pending retry): {error}"
            ),
        ),
        FlagSecureApply::Completed(Err(error)) | FlagSecureApply::Refused(error) => Err(format!(
            "mam: FLAG_SECURE clear unconfirmed — protection state UNKNOWN \
             (the clear did not conclude successfully, and a superseded \
             dispatch may have executed in its place; pending retry): {error}"
        )),
        FlagSecureApply::Ambiguous(error) if !blocked => Err(format!(
            "mam: FLAG_SECURE clear unconfirmed — protection state UNKNOWN \
             (ack timed out; the queued clear may still execute late, \
             pending retry): {error}"
        )),
        FlagSecureApply::Ambiguous(error) => Err(format!(
            "mam: FLAG_SECURE application unconfirmed — surface is NOT protected \
             (desired on, ack timed out, pending retry): {error}"
        )),
    }
}

fn policy_from_map(version: i64, map: &HashMap<String, String>) -> MamPolicy {
    let mut policy = MamPolicy {
        policy_version: version,
        ..Default::default()
    };
    if let Some(value) = map.get("copy_paste") {
        policy.copy_paste = value.clone();
    }
    if let Some(value) = map.get("screen_capture") {
        policy.screen_capture = value.clone();
    }
    if let Some(value) = map.get("encryption") {
        policy.encryption = value.clone();
    }
    if let Some(value) = map.get("watermark") {
        policy.watermark = value == "true";
    }
    if let Some(value) = map.get("notification_profile") {
        policy.notification_profile = value.clone();
    }
    if let Some(value) = map.get("max_offline_days") {
        if let Ok(days) = value.parse::<i32>() {
            policy.max_offline_days = days;
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../mam/conformance/v1/lifecycle.json"))
            .expect("MAM conformance corpus v1 must be valid JSON")
    }

    fn policy_json(policy: &MamPolicy) -> serde_json::Value {
        serde_json::json!({
            "policy_version": policy.policy_version,
            "copy_paste": policy.copy_paste,
            "screen_capture": policy.screen_capture,
            "encryption": policy.encryption,
            "watermark": policy.watermark,
            "notification_profile": policy.notification_profile,
            "max_offline_days": policy.max_offline_days,
        })
    }

    #[test]
    fn versioned_cross_shell_conformance_corpus() {
        let corpus = corpus();
        assert_eq!(corpus["contract"], "setjoin.mam.lifecycle");
        assert_eq!(corpus["version"], 1);

        for vector in corpus["signing_vectors"].as_array().unwrap() {
            assert_eq!(
                device_hmac(
                    vector["secret"].as_str().unwrap(),
                    vector["device_id"].as_i64().unwrap(),
                    vector["timestamp"].as_str().unwrap(),
                ),
                vector["hmac_sha256_hex"].as_str().unwrap(),
                "{}",
                vector["name"].as_str().unwrap()
            );
        }

        for vector in corpus["request_vectors"].as_array().unwrap() {
            let request = build_checkin_request(
                vector["server_url"].as_str().unwrap(),
                vector["device_id"].as_i64().unwrap(),
                vector["secret"].as_str().unwrap(),
                vector["timestamp"].as_str().unwrap(),
                vector["known_policy_version"].as_i64().unwrap(),
            );
            assert_eq!(request.url, vector["expected_url"]);
            assert_eq!(request.hmac, vector["expected_headers"]["X-Device-HMAC"]);
            assert_eq!(
                request.timestamp,
                vector["expected_headers"]["X-Device-Timestamp"]
            );
            assert_eq!(
                request.if_none_match,
                vector["expected_headers"]["If-None-Match"]
            );
            assert_eq!(
                serde_json::to_value(request.body).unwrap(),
                vector["expected_body"]
            );
        }

        for vector in corpus["response_vectors"].as_array().unwrap() {
            let response = if vector["body"].is_null() {
                None
            } else {
                Some(serde_json::from_value(vector["body"].clone()).unwrap())
            };
            let transition = reduce_checkin_response(
                vector["status"].as_u64().unwrap() as u16,
                vector["known_policy_version"].as_i64().unwrap(),
                42,
                response,
            )
            .unwrap();
            assert_eq!(
                transition.outcome.policy_version,
                vector["expected"]["policy_version"]
            );
            assert_eq!(transition.outcome.wiped, vector["expected"]["wiped"]);
            let names: Vec<_> = transition.effects.iter().map(EffectIntent::name).collect();
            assert_eq!(
                serde_json::json!(names),
                vector["expected"]["effect_intents"]
            );
            if let Some(policy) = transition.effects.iter().find_map(|effect| match effect {
                EffectIntent::CachePolicy { policy } => Some(policy),
                _ => None,
            }) {
                assert_eq!(policy_json(policy), vector["expected"]["normalized_policy"]);
            }
        }
    }

    // ── FLAG_SECURE toggle logic (DESKTOP-007) — pure, host-runnable ─────────

    #[test]
    fn classify_surface_marks_message_content_sensitive() {
        for route in ["/chat", "/chat/", "/chat/room/9", "/inbox", "/inbox/42"] {
            assert_eq!(
                classify_surface(route),
                SurfaceSensitivity::Sensitive,
                "{route} renders message content and must be sensitive"
            );
        }
    }

    #[test]
    fn classify_surface_marks_unknown_routes_non_sensitive() {
        for route in [
            "/", "", "/settings", "/settings/security", "/admin", "/calendar", "/directory",
            "/apps",
        ] {
            assert_eq!(
                classify_surface(route),
                SurfaceSensitivity::NonSensitive,
                "{route} must default to non-sensitive"
            );
        }
    }

    /// Segment matching, not substring matching: a hypothetical `/chatx` route
    /// must never inherit `/chat`'s sensitivity.
    #[test]
    fn classify_surface_matches_whole_segments_only() {
        for route in ["/chatx", "/inbox-help", "/quarantined", "/admin/chat-compliance"] {
            assert_eq!(
                classify_surface(route),
                SurfaceSensitivity::NonSensitive,
                "{route} is a different segment; prefix leakage would over-block"
            );
        }
    }

    /// The full truth table: the flag is on when EITHER the policy blocks or
    /// the surface is sensitive; it clears only when the policy allows AND the
    /// screen is non-sensitive.
    #[test]
    fn desired_flag_secure_truth_table() {
        assert!(desired_flag_secure(true, SurfaceSensitivity::Sensitive));
        assert!(desired_flag_secure(true, SurfaceSensitivity::NonSensitive));
        assert!(desired_flag_secure(false, SurfaceSensitivity::Sensitive));
        assert!(!desired_flag_secure(
            false,
            SurfaceSensitivity::NonSensitive
        ));
    }

    #[test]
    fn flag_secure_tracker_defaults_to_unapplied() {
        let tracker = FlagSecureTracker::default();
        assert_eq!(tracker.applied(), None);
        assert_eq!(tracker.pending(), None);
    }

    /// Every state transition dispatches exactly one action — including into
    /// the cleared state, otherwise a sensitive→non-sensitive navigation would
    /// leave the window permanently excluded from the recents preview — and a
    /// dispatch only stops being re-issued once the platform ACKNOWLEDGED it.
    /// Each dispatch carries a fresh, monotonically increasing op identity.
    #[test]
    fn flag_secure_tracker_dispatches_only_on_transitions() {
        let mut tracker = FlagSecureTracker::default();
        // First call always dispatches an explicit state (defends against a
        // stale FLAG_SECURE on a recycled activity instance).
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: false }
        );
        // Same state recomputes (policy refresh, same-surface navigation)
        // before any acknowledgment: still unapplied, so it re-dispatches —
        // an application the platform never acknowledged is not settled. The
        // re-issue carries a NEW op identity (the old dispatch is superseded).
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: false }
        );
        // The platform acknowledges the clear: now the same state settles.
        tracker.acknowledge(1, false, true);
        assert_eq!(tracker.applied(), Some(false));
        assert_eq!(tracker.pending(), None);
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Settled
        );
        // Sensitive surface forces the flag on.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 2, blocked: true }
        );
        tracker.acknowledge(2, true, true);
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Settled
        );
        // Back to a non-sensitive screen: the clear must dispatch.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 3, blocked: false }
        );
        tracker.acknowledge(3, false, true);
        assert_eq!(tracker.applied(), Some(false));
    }

    /// DESKTOP-007 r2 (a): `applied` flips ONLY on an acknowledged success. A
    /// dispatch the platform refused never counts as protection — the report
    /// path (`applied()`) stays honest while the state is in flight/failing.
    #[test]
    fn flag_secure_tracker_applies_only_on_acknowledged_success() {
        let mut tracker = FlagSecureTracker::default();
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        // Failure: nothing applied, desired stays pending.
        tracker.acknowledge(0, true, false);
        assert_eq!(tracker.applied(), None);
        assert_eq!(tracker.pending(), Some(true));
        // The retry carries a fresh op id; its success acknowledgment is what
        // flips applied.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: true }
        );
        tracker.acknowledge(1, true, true);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), None);
        // A failed LATER dispatch (a transition to cleared) must not corrupt
        // the acknowledged state either: applied stays Some(true) — the flag
        // really is still on — while the clear is pending.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 2, blocked: false }
        );
        tracker.acknowledge(2, false, false);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), Some(false));
    }

    /// DESKTOP-007 r2 (b): a failed application stays pending so the NEXT
    /// eligible lifecycle tick re-dispatches it, and it converges once the
    /// platform finally acknowledges.
    #[test]
    fn flag_secure_tracker_retries_failed_application_on_next_tick() {
        let mut tracker = FlagSecureTracker::default();
        // Tick 1: dispatch, platform refuses.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        tracker.acknowledge(0, true, false);
        // Tick 2 (identical inputs — e.g. a periodic checkin): must retry.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: true }
        );
        tracker.acknowledge(1, true, false);
        // Tick 3 (surface changed but desired state identical): still retries.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 2, blocked: true }
        );
        // Tick 4: the platform finally acknowledges — retried to convergence.
        tracker.acknowledge(2, true, true);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), None);
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Settled
        );
    }

    /// While the MAM policy blocks capture, surface navigation must not flap
    /// the flag: applied stays true across sensitive/non-sensitive changes and
    /// no JNI dispatch churns the window.
    #[test]
    fn flag_secure_tracker_holds_steady_under_enforced_policy() {
        let mut tracker = FlagSecureTracker::default();
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        tracker.acknowledge(0, true, true);
        for (blocks, surface) in [
            (true, SurfaceSensitivity::NonSensitive),
            (true, SurfaceSensitivity::Sensitive),
            (true, SurfaceSensitivity::NonSensitive),
        ] {
            assert_eq!(
                tracker.next_action(blocks, surface),
                FlagSecureDispatch::Settled,
                "policy-enforced flag must not flap with surface changes"
            );
        }
        // Policy relaxes to allow while a sensitive surface is showing: the
        // flag must stay on (the surface keeps it), without a dispatch.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Settled
        );
        // ...and only clears once the user leaves the sensitive surface.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: false }
        );
        tracker.acknowledge(1, false, true);
        assert_eq!(tracker.applied(), Some(false));
    }

    /// DESKTOP-007 r3 — the ordered-acknowledgment contract: dispatch and
    /// acknowledgment recording are independently ordered, so only the ack of
    /// the LATEST dispatched op may move the tracker. The exact reported
    /// interleaving: `dispatch(true)`, `dispatch(false)`, then a stale
    /// `ack(true)` from the OLD op must NOT report protected, and the ack of
    /// the latest op does flip `applied` honestly.
    #[test]
    fn flag_secure_tracker_stale_true_ack_does_not_report_protection() {
        let mut tracker = FlagSecureTracker::default();
        // Op 0: sensitive surface demands FLAG_SECURE on.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        // Op 1 (newer): before op 0 was acknowledged, the surface reports
        // non-sensitive under an allowing policy — a CLEAR is dispatched and
        // supersedes op 0's pending dispatch.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: false }
        );
        // The window is being cleared — but op 0's (stale) success arrives
        // NOW. Recording it would report protection while the window is
        // capturable: it must update nothing.
        tracker.acknowledge(0, true, true);
        assert_ne!(
            tracker.applied(),
            Some(true),
            "a stale true-ack must never report protection"
        );
        assert_eq!(tracker.applied(), None);
        // The ack of the LATEST op does move state (honestly, to cleared).
        tracker.acknowledge(1, false, true);
        assert_eq!(tracker.applied(), Some(false));
        // ...and a fresh protected dispatch is only settled by ITS OWN ack.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 2, blocked: true }
        );
        tracker.acknowledge(2, true, true);
        assert_eq!(tracker.applied(), Some(true));
    }

    /// DESKTOP-007 r3: a stale success for a SUPERSEDED op is not recorded as
    /// a platform fact at all (r2 recorded it) — with independently ordered
    /// dispatches its "fact" may already have been overwritten on the window.
    /// The newer pending state survives and is re-issued with its own op id.
    #[test]
    fn flag_secure_tracker_stale_acknowledgment_keeps_newer_pending() {
        let mut tracker = FlagSecureTracker::default();
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: false }
        );
        // Surface goes sensitive before the clear was acknowledged.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: true }
        );
        // The stale clear succeeds: under r3 ordering it updates NOTHING —
        // applied stays unacknowledged — while the flag-on dispatch stays
        // pending and is re-issued next tick.
        tracker.acknowledge(0, false, true);
        assert_eq!(tracker.applied(), None);
        assert_eq!(tracker.pending(), Some(true));
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 2, blocked: true }
        );
        tracker.acknowledge(2, true, true);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), None);
    }

    /// DESKTOP-007 r3: the per-checkin retry tick is required exactly when the
    /// transition carries no `EnforcePolicy` of its own and the device was not
    /// wiped — a 304 (empty effects) must re-drive a pending failed
    /// application even though nothing else in the checkin would.
    #[test]
    fn checkin_retry_tick_required_exactly_without_enforcement() {
        let known_version = 7;
        // 304 Not Modified: empty effects — the retry tick is the only thing
        // that re-drives a pending FLAG_SECURE on this outcome.
        let not_modified =
            reduce_checkin_response(304, known_version, 42, None).unwrap();
        assert!(not_modified.effects.is_empty());
        assert!(checkin_requires_flag_secure_retry(&not_modified));
        // 200 with a policy body: EnforcePolicy itself re-drives; no extra
        // tick needed.
        let enforced = reduce_checkin_response(
            200,
            known_version,
            42,
            Some(serde_json::from_value(serde_json::json!({
                "policy_version": 8,
                "policy": { "screen_capture": "block" }
            })).unwrap()),
        )
        .unwrap();
        assert!(enforced
            .effects
            .iter()
            .any(|effect| matches!(effect, EffectIntent::EnforcePolicy { .. })));
        assert!(!checkin_requires_flag_secure_retry(&enforced));
        // A wipe latches the lockdown; enforcement is moot afterwards.
        let wiped = reduce_checkin_response(
            200,
            known_version,
            42,
            Some(serde_json::from_value(serde_json::json!({
                "policy_version": 8,
                "wipe_requested": true
            })).unwrap()),
        )
        .unwrap();
        assert!(wiped.outcome.wiped);
        assert!(!checkin_requires_flag_secure_retry(&wiped));
    }

    // ── DESKTOP-007 r4: ambiguous clear acknowledgments ──────────────────────

    /// (r4 P2) The exact reported hole: a timed-out CLEAR must never answer
    /// `Ok(true)` from the tracker's historical `applied = Some(true)` — the
    /// queued clear may still execute late, so the window state is unknown and
    /// the status path reports the ambiguity as `Err`. An ambiguous
    /// desired-on application keeps the r2/r3 honesty on every input too.
    #[test]
    fn flag_secure_status_ambiguous_clear_is_never_protected() {
        let ambiguous = FlagSecureApply::Ambiguous("ack timed out after 3000ms".to_string());
        assert!(
            flag_secure_status(&ambiguous, false).is_err(),
            "an ambiguous clear must not report protection \
             (the late clear may already have run)"
        );
        assert!(
            flag_secure_status(&ambiguous, true).is_err(),
            "an ambiguous required application must be Err on every input"
        );
    }

    /// The definitive outcomes keep the honest contract, tightened by r5: a
    /// completed application reports itself; every non-success is `Err`. A
    /// definitively failed/refused CLEAR no longer reports the historical
    /// acknowledged state (the r4 reading) — a SUPERSEDED dispatch may have
    /// executed in between, so that state is not a live fact (see
    /// [`flag_secure_failed_clear_retry_reports_unconfirmed_not_stale_protection`]
    /// for the exact FIFO sequence). A failed REQUIRED application stays the
    /// r2/r3 fail-open hole — loud Err.
    #[test]
    fn flag_secure_status_definitive_outcomes_truth_table() {
        assert_eq!(
            flag_secure_status(&FlagSecureApply::Completed(Ok(())), true),
            Ok(true)
        );
        assert_eq!(
            flag_secure_status(&FlagSecureApply::Completed(Ok(())), false),
            Ok(false)
        );
        // A clear that definitively failed/refused: unconfirmed — the
        // pre-r5 `Ok(applied == Some(true))` answers are gone. Only
        // Completed(Ok) for the currently-pending op may answer.
        let refused = FlagSecureApply::Refused("no activity yet".to_string());
        assert!(flag_secure_status(&refused, false).is_err());
        assert!(flag_secure_status(&refused, true).is_err());
        let jni_failed = FlagSecureApply::Completed(Err("JNI failed".to_string()));
        assert!(flag_secure_status(&jni_failed, false).is_err());
        assert!(flag_secure_status(&jni_failed, true).is_err());
    }

    /// (r4 P2) The pinned late-execution sequence: enable acked → clear
    /// dispatched → clear ack TIMES OUT → late clear ack arrives. The in-between
    /// status query must not claim protection (a pending dispatch forces a
    /// re-dispatch, so no answer can come from the historical applied), and the
    /// late ack of the still-pending op settles the tracker truthfully at
    /// `Some(false)`.
    #[test]
    fn flag_secure_tracker_late_clear_ack_after_timeout_converges() {
        let mut tracker = FlagSecureTracker::default();
        // Enable acked: protection is a confirmed fact.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        tracker.acknowledge(0, true, true);
        assert_eq!(tracker.applied(), Some(true));
        // Clear dispatched (policy allows, surface non-sensitive).
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: false }
        );
        // The clear's ack TIMES OUT: the drive records a non-success (updates
        // nothing) — applied stays the last confirmed fact, but the dispatch
        // stays PENDING.
        tracker.acknowledge(1, false, false);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), Some(false));
        // A status query in between cannot answer from the stale fact: with a
        // pending dispatch `next_action` re-dispatches (never settles), so the
        // returned status is always built from a fresh platform outcome —
        // which is `Err` while the outcome is ambiguous (pinned by
        // flag_secure_status_ambiguous_clear_is_never_protected). Probed on a
        // clone so the pinned late ack below still matches op 1.
        let mut probe = tracker.clone();
        assert!(matches!(
            probe.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { blocked: false, .. }
        ));
        // The queued clear executes LATE and its success ack arrives via the
        // late-ack sink: same op, still the pending dispatch → lands and
        // converges the tracker to the window's real (cleared) state.
        tracker.acknowledge(1, false, true);
        assert_eq!(tracker.applied(), Some(false));
        assert_eq!(tracker.pending(), None);
        // (r4 c) The subsequent Tick re-drive now settles truthfully at
        // "not protected" — no re-dispatch, no false protection.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Settled
        );
    }

    /// (r4 b, reworked by r5) DESKTOP-007 r5's exact reviewer FIFO sequence —
    /// the r4 version of this test assumed the re-driven clear simply
    /// succeeded, which hid the stale-protection resurrection: enable acked →
    /// clear op1's ack TIMES OUT (ambiguous) → the next drive re-drives the
    /// clear as op2 → op1 executes LATE and its success record reaches the
    /// sink only after op2 was dispatched → op2 DEFINITIVELY fails. The status
    /// answered at that point must be `Err` (unconfirmed) — never `Ok(true)`
    /// from the historical `applied = Some(true)`, because op1 really ran and
    /// the window IS cleared. The superseded late ack is then filtered by the
    /// op-id rules at the next drive's drain, the clear re-drives, and ITS own
    /// success settles the tracker honestly at `Some(false)`. A Policy
    /// re-drive over the ambiguity likewise restores truth only through its
    /// own ack.
    #[test]
    fn flag_secure_failed_clear_retry_reports_unconfirmed_not_stale_protection() {
        let mut tracker = FlagSecureTracker::default();
        // ON acked: protection is a confirmed fact.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 0, blocked: true }
        );
        tracker.acknowledge(0, true, true);
        assert_eq!(tracker.applied(), Some(true));
        // Drive A: clear dispatched (policy allows, surface non-sensitive);
        // its ack TIMES OUT — ambiguous, the closure is still queued and may
        // execute late. The status is Err (unconfirmed), never the stale
        // protection fact.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 1, blocked: false }
        );
        tracker.acknowledge(1, false, false);
        assert!(flag_secure_status(
            &FlagSecureApply::Ambiguous("ack timed out after 3000ms".to_string()),
            false
        )
        .is_err());
        // Drive B: the sink is still empty (op1 has not executed yet), so the
        // drive re-issues the clear with a FRESH op identity.
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 2, blocked: false }
        );
        // op1 now executes LATE; its success record lands in the sink only
        // after op2 was dispatched (the next drive's drain will see it — this
        // drive cannot). The `LateFlagSecureAck` the closure persisted:
        let late_op1 = LateFlagSecureAck {
            op: 1,
            desired: false,
            succeeded: true,
        };
        // op2 DEFINITIVELY fails. The pre-r5 driver answered
        // `Ok(applied == Some(true))` here — resurrecting stale protection
        // although op1's late execution really cleared the window. Uncertainty
        // must survive the failed retry: Err, and the dispatch stays pending
        // so no later status can be answered from the stale fact either.
        tracker.acknowledge(2, false, false);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), Some(false));
        assert!(
            flag_secure_status(
                &FlagSecureApply::Completed(Err("JNI clear failed".to_string())),
                false
            )
            .is_err(),
            "a failed clear retry must not answer Ok(true) from the stale applied"
        );
        // Drive C: the sink drains FIRST — op1's late success is superseded
        // by the still-pending op2 and is filtered by the op-id rules (it
        // moves nothing); the drive then re-issues the clear once more.
        tracker.acknowledge(late_op1.op, late_op1.desired, late_op1.succeeded);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(tracker.pending(), Some(false));
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Dispatch { op: 3, blocked: false }
        );
        // The re-driven clear's own success settles the tracker honestly —
        // and only NOW is there an authoritative status answer, from a
        // definitive Completed(Ok) for the op that was pending: the window
        // really is cleared, so Ok(false), not Ok(true).
        tracker.acknowledge(3, false, true);
        assert_eq!(tracker.applied(), Some(false));
        assert_eq!(tracker.pending(), None);
        assert_eq!(
            flag_secure_status(&FlagSecureApply::Completed(Ok(())), false),
            Ok(false)
        );
        assert_eq!(
            tracker.next_action(false, SurfaceSensitivity::NonSensitive),
            FlagSecureDispatch::Settled
        );
        // (r4 c) A Policy re-drive over the same ambiguity: the desired-on
        // dispatch reports protection only once ITS OWN ack lands.
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Dispatch { op: 4, blocked: true }
        );
        tracker.acknowledge(4, false, false); // wrong-op/noise must not move state
        tracker.acknowledge(4, true, true);
        assert_eq!(tracker.applied(), Some(true));
        assert_eq!(
            tracker.next_action(true, SurfaceSensitivity::Sensitive),
            FlagSecureDispatch::Settled
        );
    }
}
