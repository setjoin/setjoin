//! Live policy metadata and scope caches. Revocation-sensitive runtime decisions
//! are never cached; only the raw, unfiltered policy set is shared across users.
use super::{
    eval::{evaluate, text, Context, Result, Snapshot},
    store,
};
use setjoin_pg::ScopedExecutor;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Default)]
struct State {
    initialized: bool,
    open: bool,
    break_glass: Vec<i64>,
    loaded: bool,
    cache: Option<(Instant, Snapshot)>,
    scopes: HashMap<i64, (Instant, Vec<i64>, Vec<i64>)>,
}
pub struct Engine {
    exec: ScopedExecutor,
    state: Mutex<State>,
}
impl Engine {
    pub fn new(exec: ScopedExecutor) -> Self {
        Self {
            exec,
            state: Mutex::new(State::default()),
        }
    }
    async fn initialize_state(&self, s: &mut State) {
        if s.initialized {
            return;
        }
        // The deprecated CONDITIONAL_ACCESS_FAIL_CLOSED constructor argument
        // maps to closed; ca_fail_mode is Go's sole effective startup posture.
        s.open = self
            .exec
            .read(
                "SELECT value::text FROM system_config WHERE key='ca_fail_mode'",
                &[],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().map(|r| r.get::<_, String>(0)))
            .is_some_and(|v| v.trim().trim_matches('"') == "open");
        if let Ok(ids) = store::break_glass(&self.exec).await {
            s.break_glass = ids;
        }
        s.initialized = true;
    }
    pub async fn initialize(&self) {
        let mut s = self.state.lock().await;
        self.initialize_state(&mut s).await;
    }
    /// NOTIFY invalidates policy/location/strength metadata but deliberately
    /// retains the independent 60 s membership cache and last break-glass on error.
    pub async fn invalidate(&self) {
        let mut s = self.state.lock().await;
        self.initialize_state(&mut s).await;
        s.cache = None;
        // Owner-approved security fix 2026-11-05 (#499): an invalidation also
        // clears `loaded`, so a failed reload fails closed ("cache never loaded")
        // instead of judging by the stale classification.
        if !setjoin_contracts::mutants::on("policy-invalidate-keeps-loaded") {
            s.loaded = false;
        }
        if let Ok(ids) = store::break_glass(&self.exec).await {
            s.break_glass = ids;
        }
    }
    /// Authserver's reconnect contract clears stale exclusions on read errors.
    /// Gateway's `invalidate` deliberately retains its historical posture.
    pub async fn invalidate_auth(&self) -> std::result::Result<(), setjoin_pg::StatementFailure> {
        let mut s = self.state.lock().await;
        self.initialize_state(&mut s).await;
        s.cache = None;
        if !setjoin_contracts::mutants::on("policy-invalidate-keeps-loaded") {
            s.loaded = false;
        }
        match store::break_glass(&self.exec).await {
            Ok(ids) => { s.break_glass = ids; Ok(()) },
            Err(error) => { s.break_glass.clear(); Err(error) }
        }
    }
    pub async fn evaluate(&self, mut c: Context) -> Result {
        let mut s = self.state.lock().await;
        self.initialize_state(&mut s).await;
        // This must precede every policy/scope/error branch.
        if s.break_glass.contains(&c.user_id) {
            return Result {
                reason: "break-glass exempt".into(),
                ..Default::default()
            };
        }
        if s.cache
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(30))
        {
            let policies = match store::policies(&self.exec).await {
                Ok(p) => p,
                Err(_) => return failure(&s),
            };
            let locations = store::locations(&self.exec)
                .await
                .ok()
                .or_else(|| s.cache.as_ref().and_then(|(_, v)| v.locations.clone()));
            let strengths = store::strengths(&self.exec).await.unwrap_or_else(|_| {
                s.cache
                    .as_ref()
                    .map_or_else(Vec::new, |(_, v)| v.strengths.clone())
            });
            let snapshot = Snapshot {
                policies,
                locations,
                strengths,
                break_glass: s.break_glass.clone(),
            };
            s.cache = Some((Instant::now(), snapshot));
            s.loaded = true;
        }
        if c.user_id > 0 {
            if s.scopes
                .get(&c.user_id)
                .is_none_or(|(at, _, _)| at.elapsed() >= Duration::from_secs(60))
            {
                match store::resolve_scope(&self.exec, c.user_id).await {
                    Ok((groups, roles)) => {
                        s.scopes.insert(c.user_id, (Instant::now(), groups, roles));
                    }
                    Err(_) => return failure(&s),
                }
            }
            let (_, groups, roles) = s.scopes.get(&c.user_id).expect("successful scope load");
            c.group_ids = groups.clone();
            c.role_group_ids = roles.clone();
        }
        let snapshot = &s.cache.as_ref().expect("loaded policy snapshot").1;
        if snapshot.locations.is_none()
            && snapshot.policies.iter().any(|p| {
                ["location_in", "location_trusted"].iter().any(|k| {
                    // Go tests key presence before matching or scope filtering.
                    p.0["conditions"].get(*k).is_some()
                })
            })
        {
            return failure(&s);
        }
        if c.trust_tier.is_empty() {
            c.trust_tier = store::resolve_trust(&self.exec, &c).await;
        }
        // Owner-approved security fix 2026-11-05 (#499): a geo lookup error takes
        // the checked failure path; Go turned it into a low-risk result.
        c.geo_tier = match store::resolve_geo(&self.exec, &c.country).await {
            Ok(tier) => tier,
            Err(_) if setjoin_contracts::mutants::on("geo-error-is-low-risk") => "low".into(),
            Err(_) => return failure(&s),
        };
        c.score_band = risk_score(&c.geo_tier, c.feed_hits, c.vpn_score).1.into();
        evaluate(snapshot, &c)
    }
}
fn enforcing(actions: &serde_json::Value) -> bool {
    // Owner-approved security fix 2026-11-05 (#499): legacy `step_up` enforces.
    let step_up = !setjoin_contracts::mutants::on("step-up-not-enforcing");
    let is = |kind: &str| {
        (step_up && kind == "step_up")
            || matches!(
            kind,
            "block"
                | "require_acr"
                | "require_strength"
                | "require_terms"
                | "require_risk_remediation"
        )
    };
    if actions["require_compliant_device"] == true || is(text(actions, "action")) {
        return true;
    }
    if let Some(value) = actions.get("grants") {
        let Some(array) = value.as_array() else {
            return true;
        };
        if array.is_empty() {
            return true;
        }
        for value in array {
            let Some(map) = value.as_object() else {
                return true;
            };
            let (t, invalid) = super::grant_discriminator(map);
            if invalid
                || t.is_empty()
                || !super::allowed_action_names().contains(&t.as_str())
                || is(&t)
            {
                return true;
            }
        }
    }
    false
}
fn failure(s: &State) -> Result {
    let (decision, reason) = if s.open {
        ("allow", "eval error (fail open)")
    } else if !s.loaded {
        ("block", "eval error (fail closed — cache never loaded)")
    } else if s.cache.as_ref().is_some_and(|(_, v)| {
        v.policies.iter().any(|p| {
            !matches!(text(&p.0, "state"), "off" | "report_only") && enforcing(&p.0["actions"])
        })
    }) {
        ("block", "eval error (fail closed)")
    } else {
        ("allow", "eval error (fail open — no enforcing policy)")
    };
    Result {
        decision: decision.into(),
        reason: reason.into(),
        ..Default::default()
    }
}
/// Immutable request-scoped Go IPRiskScorer inputs; HTTP runtime supplies no
/// feed/VPN inputs in frozen Go. Other callers may supply their collected signals.
pub fn risk_score(tier: &str, feed_hits: i32, vpn: i32) -> (i32, &'static str) {
    let feed = if feed_hits >= 2 {
        40
    } else if feed_hits == 1 {
        20
    } else {
        0
    };
    let geo = match tier {
        "low" => 0,
        "medium" => 15,
        "high" => 30,
        "critical" => 40,
        _ => 10,
    };
    let score = (feed + geo + vpn.clamp(0, 20)).clamp(0, 100);
    (
        score,
        if score <= 20 {
            "low"
        } else if score <= 50 {
            "medium"
        } else if score <= 80 {
            "high"
        } else {
            "critical"
        },
    )
}
