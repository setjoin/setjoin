//! Frozen shared/threat non-HTTP pipeline. No protocol owns a second policy engine.
use crate::Error;
use futures_util::future::BoxFuture;
use setjoin_authz::{
    geoip::CountryDb,
    policy::eval::{Context, Engine},
};
use setjoin_pg::{ScopedExecutor, Type};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
#[derive(Clone, Debug, Default)]
pub struct ConnectionMeta {
    pub source_ip: String,
    pub username: String,
    pub app_password: bool,
    pub user_id: i64,
    pub device_bound: bool,
    pub protocol: String,
    pub user_agent: String,
    pub country: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatAction {
    Allow,
    Reject,
    Tarpitted,
    RateLimited,
}
pub trait ThreatGate: Send + Sync {
    fn intercept<'a>(&'a self, meta: &'a ConnectionMeta)
        -> BoxFuture<'a, (ThreatAction, Duration)>;
    fn record_result<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
        success: bool,
        user_id: i64,
    ) -> BoxFuture<'a, ()>;
    fn evaluate_post_auth<'a>(
        &'a self,
        meta: &'a mut ConnectionMeta,
    ) -> BoxFuture<'a, (ThreatAction, String)>;
}
#[derive(Clone)]
pub struct Config {
    pub overrides: HashMap<String, bool>,
    pub block_countries: Vec<String>,
    pub spray_window_secs: i32,
    pub spray_max_users: i32,
    pub spray_lockout_mins: i32,
    pub rate_limit_per_min: i32,
    pub captcha_window_mins: i32,
    pub captcha_threshold: i32,
    pub tarpit_window_mins: i32,
    pub tarpit_threshold: i32,
    pub captcha_secret: Vec<u8>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            overrides: HashMap::new(),
            block_countries: vec![],
            spray_window_secs: 300,
            spray_max_users: 5,
            spray_lockout_mins: 30,
            rate_limit_per_min: 20,
            captcha_window_mins: 5,
            captcha_threshold: 3,
            tarpit_window_mins: 15,
            tarpit_threshold: 3,
            captcha_secret: vec![],
        }
    }
}
/// How the captcha/tarpit step runs (#349).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptchaStep {
    /// Protocol listeners (Go `skipCaptcha=true`): neither captcha nor tarpit.
    Skip,
    /// HTTP without a captcha token: captcha threshold, then tarpit.
    Full,
    /// HTTP with a captcha token that failed verification or its single-use claim:
    /// tarpit and every later step, no captcha threshold (#349 divergence
    /// failed-captcha-runs-pipeline). A verified, claimed token runs `Skip`, as in Go.
    TarpitOnly,
}
/// Pre-auth worker-credential connections (#367): lockout_check, detect_spray
/// and the spray side effects. A full pool waits `Timeouts::pool_wait`, then
/// the check fails closed.
pub const WORKER_POOL_SIZE: usize = 8;
/// Reserved connections for lockout_clear/lockout_escalate after a real
/// credential verification, so pre-auth floods cannot starve failure accounting.
pub const RECORD_POOL_SIZE: usize = 2;

/// The two bounded worker-credential pools a [`Gate`] uses (#367).
#[derive(Clone)]
pub struct WorkerPools {
    pub check: ScopedExecutor,
    pub record: ScopedExecutor,
}

impl WorkerPools {
    /// `DB_WORKER_DSN` when set, otherwise Go's request-DSN fallback.
    pub fn from_dsns(request_dsn: &str, worker_dsn: Option<&str>) -> Result<Self, Error> {
        Self::from_dsn(worker_dsn.filter(|s| !s.is_empty()).unwrap_or(request_dsn))
    }

    /// Both pools on one worker DSN, with `Timeouts::resolved()`.
    pub fn from_dsn(dsn: &str) -> Result<Self, Error> {
        Ok(Self {
            check: ScopedExecutor::from_dsn(dsn, WORKER_POOL_SIZE).map_err(|e| e.0)?,
            record: ScopedExecutor::from_dsn(dsn, RECORD_POOL_SIZE).map_err(|e| e.0)?,
        })
    }
}

pub struct Gate {
    pub(crate) exec: ScopedExecutor,
    pub(crate) worker: WorkerPools,
    pub(crate) config: Config,
    pub(crate) flags: RwLock<HashMap<String, bool>>,
    pub(crate) engine: Engine,
    geo: Option<CountryDb>,
}
#[derive(Debug)]
pub struct Decision {
    pub action: ThreatAction,
    pub reason: String,
    pub delay: Duration,
}
impl Decision {
    fn new(action: ThreatAction, reason: &str, delay: Duration) -> Self {
        Self {
            action,
            reason: reason.into(),
            delay,
        }
    }
    fn allow() -> Self {
        Self::new(ThreatAction::Allow, "", Duration::ZERO)
    }
    fn reject(reason: &str) -> Self {
        Self::new(ThreatAction::Reject, reason, Duration::ZERO)
    }
}
impl Gate {
    pub async fn load(
        exec: ScopedExecutor,
        worker: WorkerPools,
        config: Config,
        geo: Option<CountryDb>,
    ) -> Result<Arc<Self>, Error> {
        let gate = Arc::new(Self {
            engine: Engine::new(exec.clone()),
            exec,
            worker,
            config,
            flags: Default::default(),
            geo,
        });
        gate.reload_flags().await?;
        // Go's startup drift tripwire: an explicit environment override counts
        // as a value, but a missing seeded security control must refuse boot.
        let flags = gate.flags.read().unwrap();
        let missing: Vec<_> = [
            "feature.conditional_access",
            "feature.device_trust_enforcement",
            "feature.device_lockdown",
            "dengbao.sod_mode",
            "feature.cae_runtime",
            "feature.token_binding",
            "feature.user_risk",
            "feature.smime_verify",
        ]
        .into_iter()
        .filter(|key| !gate.config.overrides.contains_key(*key) && !flags.contains_key(*key))
        .collect();
        drop(flags);
        if !missing.is_empty() {
            return Err(format!("feature_toggles rows missing for security toggles {missing:?}; restore the seeded baseline").into());
        }
        gate.probe_worker().await?;
        gate.engine.initialize().await;
        Ok(gate)
    }
    pub async fn reload_flags(&self) -> Result<(), Error> {
        let snapshot: Result<HashMap<String, bool>, Error> = async {
            let rows = self.exec.read(
                "SELECT ft.key,ft.enabled,s.mode::text FROM feature_toggle_registry_state s LEFT JOIN feature_toggles ft ON true WHERE s.singleton",
                &[],
            ).await.map_err(|e| -> Error { e.message.into() })?;
            let first = rows.first().ok_or("feature toggle registry state row is missing")?;
            let mode: String = first.get(2);
            if !matches!(mode.as_str(), "observe" | "enforce") {
                return Err(format!("feature toggle registry mode {mode:?} is invalid").into());
            }
            Ok(rows.iter().filter_map(|row| {
                let key: Option<String> = row.get(0);
                let enabled: Option<bool> = row.get(1);
                key.zip(enabled)
            }).collect())
        }.await;
        match snapshot {
            Ok(flags) => {
                *self.flags.write().unwrap() = flags;
                Ok(())
            }
            Err(e) => {
                // Go's conservative security defaults on failed authoritative reload.
                let mut flags = self.flags.write().unwrap();
                for k in [
                    "threat_feed",
                    "geo_block",
                    "spray_detect",
                    "captcha",
                    "tarpit",
                    "rate_limit",
                ] {
                    flags.insert(format!("feature.{k}"), true);
                }
                Err(e)
            }
        }
    }
    pub fn enabled(&self, name: &str) -> bool {
        self.config
            .overrides
            .get(name)
            .copied()
            .or_else(|| self.flags.read().unwrap().get(name).copied())
            .unwrap_or(!matches!(name, "feature.conditional_access"))
    }
    fn country(&self, meta: &ConnectionMeta) -> String {
        if !meta.country.is_empty() {
            return meta.country.clone();
        }
        meta.source_ip
            .parse()
            .ok()
            .and_then(|ip| self.geo.as_ref().map(|g| g.country(ip)))
            .unwrap_or_default()
    }
    fn protocol<'a>(&self, meta: &'a ConnectionMeta) -> &'a str {
        if meta.protocol.is_empty() {
            "imap"
        } else {
            &meta.protocol
        }
    }
    fn keys(&self, meta: &ConnectionMeta) -> Vec<String> {
        let name = setjoin_authz::address::lower(&meta.username);
        vec![
            format!("ip:{}", meta.source_ip),
            format!("user:{name}"),
            format!("ip_user:{}:{name}", meta.source_ip),
        ]
    }
    /// Keys `lockout_check` reads: all three, or only `ip:` without a username.
    fn check_keys(&self, meta: &ConnectionMeta) -> Vec<String> {
        if meta.username.is_empty() {
            vec![format!("ip:{}", meta.source_ip)]
        } else {
            self.keys(meta)
        }
    }
    /// Boot check (#367): a worker credential that may not run the lockout
    /// accessors would make every login a fail-closed rejection. Refuse boot on
    /// SQLSTATE 42501 or a denied privilege only; an unreachable database still
    /// boots and fails closed per request.
    async fn probe_worker(&self) -> Result<(), Error> {
        let mut probes: Vec<(&ScopedExecutor, &'static str)> = vec![
            (&self.worker.check, "SELECT locked FROM lockout_check('{}'::text[])"),
            (&self.worker.record, "SELECT lockout_clear('{}'::text[])"),
            (
                &self.worker.record,
                "SELECT has_function_privilege('lockout_escalate(text,integer)','EXECUTE') AND has_function_privilege('lockout_arm(text,integer)','EXECUTE')",
            ),
        ];
        if self.enabled("feature.spray_detect") {
            probes.push((
                &self.worker.check,
                "SELECT detect_spray('192.0.2.1'::inet,1,1)",
            ));
        }
        for (pool, sql) in probes {
            let denied = match pool.protocol_query(sql, &[]).await {
                Err(e) => e.sqlstate.as_deref() == Some("42501"),
                Ok(rows) => {
                    sql.contains("has_function_privilege")
                        && rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()) == Some(false)
                }
            };
            if denied {
                return Err(format!(
                    "threat worker credential may not run the lockout accessors ({sql}); set DB_WORKER_DSN to setjoin_worker"
                )
                .into());
            }
        }
        Ok(())
    }

    /// `Ok(Some(seconds))` when locked; `Err` means no answer, so fail closed.
    async fn lockout_state(&self, meta: &ConnectionMeta) -> Result<Option<f64>, ()> {
        let rows = self
            .worker
            .check
            .protocol_query(
                "SELECT locked, remaining_seconds FROM lockout_check($1)",
                &[(&self.check_keys(meta), Type::TEXT_ARRAY)],
            )
            .await
            .map_err(|_| ())?;
        let row = match rows.first() {
            None => None,
            Some(row) => Some((
                row.try_get::<_, Option<bool>>(0).map_err(|_| ())?,
                row.try_get::<_, Option<f64>>(1).ok().flatten(),
            )),
        };
        lockout_from(row)
    }

    pub async fn decide(&self, meta: &ConnectionMeta, skip_captcha: bool) -> Decision {
        let step = if skip_captcha {
            CaptchaStep::Skip
        } else {
            CaptchaStep::Full
        };
        self.decide_with(meta, step).await
    }
    pub async fn decide_with(&self, meta: &ConnectionMeta, step: CaptchaStep) -> Decision {
        let country = self.country(meta);
        let mut hits = 0_i64;
        if self.enabled("feature.threat_feed") {
            // Go parity (interceptor.go:619-624): a failed feed lookup scores 0 hits; see DOX (#367).
            hits=tokio::time::timeout(Duration::from_secs(3),self.exec.read("SELECT COUNT(*) FROM (SELECT 1 FROM threat_feed_blocks WHERE cidr >>= $1::inet LIMIT 2) AS hits",&[(&meta.source_ip,Type::TEXT)])).await.ok().and_then(Result::ok).and_then(|r|r.first().map(|r|r.get(0))).unwrap_or(0);
        }
        match ip_rule_blocked(&self.exec, &meta.source_ip).await {
            Ok(false) => {}
            Ok(true) => return Decision::reject("ip_blocked"),
            Err(()) => {
                // Divergence (#367): Go proceeds (interceptor.go:668).
                eprintln!("threat gate: ip rule check unavailable; failing closed");
                return Decision::reject("ip_rules_unavailable");
            }
        }
        if self.enabled("feature.geo_block")
            && !country.is_empty()
            && self.config.block_countries.contains(&country)
        {
            return Decision::reject("geo_blocked");
        }
        // #349 divergence lockout-ip-key-without-username: HTTP answers to its
        // `ip:` lock (spray-armed included) even without a username.
        if !meta.username.is_empty() || self.protocol(meta) == "http" {
            match self.lockout_state(meta).await {
                Ok(None) => {}
                Ok(Some(secs)) => {
                    return Decision::new(ThreatAction::Reject, "lockout", lockout_delay(secs));
                }
                Err(()) => {
                    // Divergence (#367): Go fails open (shared/threat/lockout.go:46-50).
                    eprintln!("threat gate: lockout check unavailable; failing closed");
                    return Decision::reject("lockout_unavailable");
                }
            }
        }
        if self.enabled("feature.spray_detect") {
            let detected = self
                .worker
                .check
                .protocol_query(
                    "SELECT detect_spray($1::inet,$2,$3)",
                    &[
                        (&meta.source_ip, Type::TEXT),
                        (&self.config.spray_window_secs, Type::INT4),
                        (&self.config.spray_max_users, Type::INT4),
                    ],
                )
                .await
                .ok()
                .and_then(|rows| rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()));
            match detected {
                Some(false) => {}
                Some(true) => {
                    // Go's best-effort side effects, in order, one checkout each.
                    let _ = self
                        .worker
                        .check
                        .protocol_statement(
                            "SELECT lockout_arm($1,$2)",
                            &[
                                (&format!("ip:{}", meta.source_ip), Type::TEXT),
                                (&self.config.spray_lockout_mins, Type::INT4),
                            ],
                        )
                        .await;
                    let metadata = serde_json::json!({
                        "unique_usernames": self.config.spray_max_users,
                        "window": self.config.spray_window_secs,
                    })
                    .to_string();
                    let _ = self
                        .worker
                        .check
                        .protocol_statement(
                            "INSERT INTO audit_log(source_ip,event_type,metadata) VALUES($1::inet,'spray_detected',$2::jsonb)",
                            &[(&meta.source_ip, Type::TEXT), (&metadata, Type::TEXT)],
                        )
                        .await;
                    let _ = self
                        .worker
                        .check
                        .protocol_statement(
                            "SELECT pg_notify('alert:spray',$1)",
                            &[(&meta.source_ip, Type::TEXT)],
                        )
                        .await;
                    return Decision::reject("spray_detected");
                }
                None => {
                    // Divergence (#367): Go fails open (shared/threat/spray.go:31-37).
                    eprintln!("threat gate: spray check unavailable; failing closed");
                    return Decision::reject("spray_unavailable");
                }
            }
        }
        if step != CaptchaStep::Skip && (self.enabled("feature.captcha") || self.enabled("feature.tarpit")) {
            let counts=self.exec.read("SELECT COUNT(*) FILTER (WHERE outcome='failure' AND occurred_at>now()-make_interval(mins=>$2)),COUNT(*) FILTER (WHERE outcome IN ('failure','captcha_needed') AND occurred_at>now()-make_interval(mins=>$3)) FROM auth_attempts WHERE source_ip=$1::inet",&[(&meta.source_ip,Type::TEXT),(&self.config.captcha_window_mins,Type::INT4),(&self.config.tarpit_window_mins,Type::INT4)]).await;
            let counts = counts.ok().and_then(|rows| {
                let row = rows.first()?;
                Some((row.try_get::<_, i64>(0).ok()?, row.try_get::<_, i64>(1).ok()?))
            });
            let Some((fails, tarpit)) = counts else {
                // Divergence (#367): Go scores 0 (interceptor.go:731-733).
                eprintln!("threat gate: captcha/tarpit count unavailable; failing closed");
                return Decision::reject("captcha_unavailable");
            };
            if step == CaptchaStep::Full
                && self.enabled("feature.captcha")
                && fails >= i64::from(self.config.captcha_threshold)
            {
                return Decision::reject("captcha_needed");
            }
            if self.enabled("feature.tarpit")
                && (tarpit >= i64::from(self.config.tarpit_threshold)
                    || (!country.is_empty() && self.config.block_countries.contains(&country)))
            {
                return Decision::new(
                    ThreatAction::Tarpitted,
                    "tarpit_applied",
                    Duration::from_millis(((500 * tarpit + 500).max(0) as u64).min(15000)),
                );
            }
        }
        if self.enabled("feature.rate_limit") {
            let key = format!("auth:{}:{}", self.protocol(meta), meta.source_ip);
            let rows=self.exec.protocol_query("INSERT INTO rate_limit_counters(key,count,window_start) VALUES($1,1,now()) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN rate_limit_counters.window_start+INTERVAL '1 minute'<now() THEN 1 ELSE rate_limit_counters.count+1 END, window_start=CASE WHEN rate_limit_counters.window_start+INTERVAL '1 minute'<now() THEN now() ELSE rate_limit_counters.window_start END RETURNING count",&[(&key,Type::TEXT)]).await;
            match rows
                .ok()
                .and_then(|r| r.first().and_then(|row| row.try_get::<_, i32>(0).ok()))
            {
                Some(count) if count > self.config.rate_limit_per_min => {
                    return Decision::new(ThreatAction::RateLimited, "rate_limited", Duration::ZERO);
                }
                Some(_) => {}
                None => {
                    // Divergence (#367): Go fails open (shared/threat/ratelimit.go:25-29).
                    eprintln!("threat gate: rate limit unavailable; failing closed");
                    return Decision::reject("rate_limit_unavailable");
                }
            }
        }
        if self.enabled("feature.conditional_access") {
            let result = self
                .engine
                .evaluate(Context {
                    feed_hits: hits as i32,
                    source_ip: meta.source_ip.clone(),
                    country,
                    protocol: self.protocol(meta).into(),
                    client_type: client_type(self.protocol(meta), &meta.user_agent, false).into(),
                    user_agent: meta.user_agent.clone(),
                    ..Default::default()
                })
                .await;
            if result.decision == "block" {
                return Decision::reject("conditional_access_blocked");
            }
            if result.decision == "step_up" && self.protocol(meta) != "http" {
                return Decision::reject("conditional_access_step_up_unavailable");
            }
        }
        if hits > 0 {
            return Decision::reject("threat_blocked");
        }
        Decision::allow()
    }
    pub async fn record(&self, meta: &ConnectionMeta, success: bool, user: i64) {
        self.attempt(meta, if success { "success" } else { "failure" })
            .await;
        let protocol = self.protocol(meta);
        let country = self.country(meta);
        if matches!(protocol, "imap" | "smtp" | "caldav" | "carddav") {
            let method = if meta.app_password {
                "app_password"
            } else {
                "password"
            };
            let _ = self
                .exec
                .protocol_statement(
                    "SELECT rust_threat_signin($1,$2,$3,$4,$5,$6)",
                    &[
                        (&user, Type::INT8),
                        (&success, Type::BOOL),
                        (&protocol, Type::TEXT),
                        (&method, Type::TEXT),
                        (&meta.source_ip, Type::TEXT),
                        (&country, Type::TEXT),
                    ],
                )
                .await;
        }
        if !meta.username.is_empty() {
            // Reserved record pool (#367). Keep ONE statement per key (Go
            // lockout.go:61-63): a failing `user:` key (NUL, oversized index
            // entry) must not roll back the `ip:` key. Never fold into unnest.
            let keys = self.keys(meta);
            if success {
                if self
                    .worker
                    .record
                    .protocol_statement("SELECT lockout_clear($1)", &[(&keys, Type::TEXT_ARRAY)])
                    .await
                    .is_err()
                {
                    eprintln!("threat gate: lockout clear failed");
                }
            } else {
                for key in &keys {
                    if self
                        .worker
                        .record
                        .protocol_statement("SELECT lockout_escalate($1)", &[(key, Type::TEXT)])
                        .await
                        .is_err()
                    {
                        eprintln!("threat gate: lockout escalate failed");
                    }
                }
            }
        }
        if success && user > 0 {
            let fp = fingerprint(&meta.user_agent, &meta.source_ip);
            let hash = format!("{:x}", Sha256::digest(fp.as_bytes()));
            if let Ok(rows) = self
                .exec
                .protocol_query(
                    "SELECT rust_threat_device($1,$2,$3,$4,$5)::text",
                    &[
                        (&user, Type::INT8),
                        (&hash, Type::TEXT),
                        (&meta.user_agent, Type::TEXT),
                        (&mask_ip(&meta.source_ip), Type::TEXT),
                        (&country, Type::TEXT),
                    ],
                )
                .await
            {
                let state: serde_json::Value =
                    serde_json::from_str(&rows[0].get::<_, String>(0)).unwrap_or_default();
                let new = state["new"] == true;
                let changed = state["changed"] == true;
                if new || changed {
                    let mut metadata = serde_json::json!({"device_hash":hash});
                    if changed {
                        metadata["from"] = state["from"].clone();
                        metadata["to"] = serde_json::json!(country)
                    }
                    let event = if changed {
                        "device_country_changed"
                    } else {
                        "device_new"
                    };
                    let _=self.exec.protocol_statement("INSERT INTO audit_log(user_id,source_ip,event_type,metadata) VALUES($1,$2::inet,$3,$4::jsonb)",&[(&user,Type::INT8),(&meta.source_ip,Type::TEXT),(&event,Type::TEXT),(&metadata.to_string(),Type::TEXT)]).await;
                }
            }
        }
    }
    pub async fn attempt(&self, meta: &ConnectionMeta, outcome: &str) {
        let _=self.exec.protocol_statement("INSERT INTO auth_attempts(source_ip,target_username,protocol,outcome,geo_country,device_fingerprint) VALUES($1::inet,$2,$3,$4,$5,$6)",&[(&meta.source_ip,Type::TEXT),(&meta.username,Type::TEXT),(&self.protocol(meta),Type::TEXT),(&outcome,Type::TEXT),(&self.country(meta),Type::TEXT),(&fingerprint(&meta.user_agent,&meta.source_ip),Type::TEXT)]).await;
    }
    pub async fn post_auth(&self, meta: &ConnectionMeta) -> (ThreatAction, String) {
        if meta.user_id <= 0 || !self.enabled("feature.conditional_access") {
            return (ThreatAction::Allow, String::new());
        }
        let protocol = self.protocol(meta);
        let client = client_type(protocol, &meta.user_agent, true);
        let result = self
            .engine
            .evaluate(Context {
                user_id: meta.user_id,
                source_ip: meta.source_ip.clone(),
                country: self.country(meta),
                protocol: protocol.into(),
                client_type: client.into(),
                device_bound: meta.device_bound,
                user_agent: meta.user_agent.clone(),
                ..Default::default()
            })
            .await;
        match result.decision.as_str() {
            "block" => (ThreatAction::Reject, "conditional_access_blocked".into()),
            "step_up" if protocol != "http" => (
                ThreatAction::Reject,
                "conditional_access_step_up_unavailable".into(),
            ),
            _ => (ThreatAction::Allow, String::new()),
        }
    }
}
impl ThreatGate for Gate {
    fn intercept<'a>(&'a self, m: &'a ConnectionMeta) -> BoxFuture<'a, (ThreatAction, Duration)> {
        Box::pin(async move {
            let d = self.decide(m, true).await;
            (d.action, d.delay)
        })
    }
    fn record_result<'a>(&'a self, m: &'a ConnectionMeta, ok: bool, u: i64) -> BoxFuture<'a, ()> {
        Box::pin(self.record(m, ok, u))
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        m: &'a mut ConnectionMeta,
    ) -> BoxFuture<'a, (ThreatAction, String)> {
        Box::pin(self.post_auth(m))
    }
}
/// Decode one `lockout_check` row (#367). No row or a NULL `locked` is an
/// error (fail closed); locked with an unreadable remainder stays locked
/// (Go lockout.go:38-44).
fn lockout_from(row: Option<(Option<bool>, Option<f64>)>) -> Result<Option<f64>, ()> {
    match row {
        None | Some((None, _)) => Err(()),
        Some((Some(false), _)) => Ok(None),
        Some((Some(true), remaining)) => Ok(Some(remaining.unwrap_or(0.).max(0.))),
    }
}

/// Go's tarpit-convention bound on the lockout response delay (15 s).
fn lockout_delay(secs: f64) -> Duration {
    Duration::from_secs((secs.max(0.) as u64).min(15))
}

/// Go stepIPRules (shared/threat/interceptor.go:652): first rule by action, 3 s
/// bound; `expires_at` is ignored exactly as Go does. An "allow" rule continues
/// the pipeline (Go's runPipeline stops only on a non-proceed result). `Err` means
/// no answer (timeout, error or unreadable row): every caller fails closed
/// (#367 divergence `ip-rules-fail-closed`). Shared by the protocol gate and the
/// auth guest-invite ingress (#342); auth admission reaches it via `decide` (#349).
pub async fn ip_rule_blocked(exec: &ScopedExecutor, source_ip: &str) -> Result<bool, ()> {
    let rows = tokio::time::timeout(
        Duration::from_secs(3),
        exec.read(
            "SELECT action FROM ip_rules WHERE cidr >>= $1::inet ORDER BY action ASC LIMIT 1",
            &[(&source_ip, Type::TEXT)],
        ),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    match rows.first() {
        None => Ok(false),
        Some(row) => row
            .try_get::<_, String>(0)
            .map(|action| action == "block")
            .map_err(|_| ()),
    }
}

pub fn mask_ip(ip: &str) -> String {
    let ip = ip
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_canonical().to_string())
        .unwrap_or_else(|_| ip.into());
    let parts: Vec<_> = ip.split('.').collect();
    if parts.len() == 4 {
        return format!("{}.{}.{}.0", parts[0], parts[1], parts[2]);
    }
    let parts: Vec<_> = ip.split(':').collect();
    if parts.len() > 3 {
        return format!("{}::", parts[..3].join(":"));
    }
    ip
}
pub fn fingerprint(agent: &str, ip: &str) -> String {
    format!("{agent}|{}", mask_ip(ip))
}

impl Config {
    /// Frozen boot knobs; environment/YAML precedence belongs to each binary.
    pub fn from_lookup(get: &dyn Fn(&str, &str) -> Option<String>) -> Result<Self, String> {
        let mut c = Self::default();
        for (env, path, key) in [
            ("THREAT_FEED_ENABLED", "threat_feed.enabled", "threat_feed"),
            ("GEO_BLOCK_ENABLED", "geo_block.enabled", "geo_block"),
            (
                "SPRAY_DETECT_ENABLED",
                "spray_detect.enabled",
                "spray_detect",
            ),
            ("CAPTCHA_ENABLED", "captcha.enabled", "captcha"),
            ("TARPIT_ENABLED", "tarpit.enabled", "tarpit"),
        ] {
            let enabled = get(env, path).map_or(true, |v| {
                matches!(v.as_str(), "1" | "t" | "T" | "true" | "TRUE" | "True")
            });
            c.overrides.insert(format!("feature.{key}"), enabled);
        }
        let number = |env: &str, path: &str, default: i32, max: i32| -> Result<i32, String> {
            let n = get(env, path).map_or(Ok(default), |v| {
                v.parse().map_err(|_| format!("invalid {env}"))
            })?;
            if n <= 0 || n > max {
                return Err(format!("invalid {env}"));
            }
            Ok(n)
        };
        c.spray_window_secs = number(
            "THREAT_SPRAY_WINDOW_SECS",
            "threat.spray_window_secs",
            300,
            2592000,
        )?;
        c.spray_max_users = number(
            "THREAT_SPRAY_MAX_USERS",
            "threat.spray_max_users",
            5,
            1000000,
        )?;
        c.spray_lockout_mins = number(
            "THREAT_SPRAY_LOCKOUT_MINS",
            "threat.spray_lockout_mins",
            30,
            43200,
        )?;
        c.captcha_window_mins = number(
            "THREAT_CAPTCHA_WINDOW_MINS",
            "threat.captcha_window_mins",
            5,
            43200,
        )?;
        c.captcha_threshold = number(
            "THREAT_CAPTCHA_THRESHOLD",
            "threat.captcha_threshold",
            3,
            100000,
        )?;
        c.tarpit_window_mins = number(
            "THREAT_TARPIT_WINDOW_MINS",
            "threat.tarpit_window_mins",
            15,
            43200,
        )?;
        c.tarpit_threshold = number(
            "THREAT_TARPIT_THRESHOLD",
            "threat.tarpit_threshold",
            3,
            100000,
        )?;
        c.rate_limit_per_min = number(
            "THREAT_RATE_LIMIT_PER_MIN",
            "threat.rate_limit_per_min",
            20,
            1000000,
        )?;
        c.block_countries = get("GEO_BLOCK_COUNTRIES", "geo.block_countries")
            .unwrap_or_default()
            .split(',')
            .map(|v| v.trim().to_uppercase())
            .filter(|v| !v.is_empty())
            .collect();
        c.captcha_secret = get("CAPTCHA_SECRET", "captcha.secret")
            .unwrap_or_default()
            .into_bytes();
        Ok(c)
    }
}

fn client_type<'a>(protocol: &'a str, agent: &str, post: bool) -> &'a str {
    match protocol {
        "imap" | "smtp" if post => "legacy",
        "imap" | "smtp" | "caldav" => protocol,
        "carddav" => "caldav",
        "http" => {
            let agent = agent.to_lowercase();
            if agent.contains("mozilla")
                && ["mobile", "iphone", "android"]
                    .iter()
                    .any(|v| agent.contains(v))
            {
                "mobile"
            } else {
                "web"
            }
        }
        _ => "web",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_row_decoding_fails_closed() {
        assert_eq!(lockout_from(None), Err(()));
        assert_eq!(lockout_from(Some((None, Some(5.)))), Err(()));
        assert_eq!(lockout_from(Some((Some(false), Some(5.)))), Ok(None));
        assert_eq!(lockout_from(Some((Some(true), None))), Ok(Some(0.)));
        assert_eq!(lockout_from(Some((Some(true), Some(-3.)))), Ok(Some(0.)));
        assert_eq!(lockout_from(Some((Some(true), Some(90.)))), Ok(Some(90.)));
    }

    #[test]
    fn lockout_delay_keeps_go_bound() {
        assert_eq!(lockout_delay(0.), Duration::ZERO);
        assert_eq!(lockout_delay(3.9), Duration::from_secs(3));
        assert_eq!(lockout_delay(900.), Duration::from_secs(15));
        assert_eq!(lockout_delay(-1.), Duration::ZERO);
        assert_eq!(lockout_delay(f64::NAN), Duration::ZERO);
    }

    /// Port 1 refuses at once: these paths need no database.
    fn unreachable() -> ScopedExecutor {
        ScopedExecutor::from_dsn_with(
            "host=127.0.0.1 port=1 user=gate dbname=gate",
            1,
            setjoin_pg::Timeouts {
                pool_wait: Duration::from_millis(100),
                create: Duration::from_millis(500),
                statement: Duration::from_millis(500),
            },
        )
        .unwrap()
    }

    /// Built without `load`, so the boot probe is not involved; all toggles off.
    fn gate() -> Gate {
        let mut config = Config::default();
        for key in [
            "threat_feed",
            "geo_block",
            "spray_detect",
            "captcha",
            "tarpit",
            "rate_limit",
            "conditional_access",
        ] {
            config.overrides.insert(format!("feature.{key}"), false);
        }
        let exec = unreachable();
        Gate {
            engine: Engine::new(exec.clone()),
            exec,
            worker: WorkerPools {
                check: unreachable(),
                record: unreachable(),
            },
            config,
            flags: Default::default(),
            geo: None,
        }
    }

    fn meta(username: &str) -> ConnectionMeta {
        ConnectionMeta {
            source_ip: "198.51.100.7".into(),
            username: username.into(),
            protocol: "ldap".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn unavailable_request_pool_rejects_instead_of_skipping_ip_rules() {
        for user in ["", "alice@example.test"] {
            let decision = tokio::time::timeout(Duration::from_secs(5), gate().decide(&meta(user), true))
                .await
                .expect("ip rule check is bounded");
            assert_eq!(decision.action, ThreatAction::Reject);
            assert_eq!(decision.reason, "ip_rules_unavailable");
        }
    }

    #[tokio::test]
    async fn record_with_unavailable_pools_is_bounded_best_effort() {
        let gate = gate();
        for success in [false, true] {
            tokio::time::timeout(
                Duration::from_secs(5),
                gate.record(&meta("alice@example.test"), success, 0),
            )
            .await
            .expect("record stays bounded");
        }
    }

    #[tokio::test]
    async fn shared_ip_rule_helper_reports_unanswered_lookups() {
        let answer = tokio::time::timeout(
            Duration::from_secs(5),
            ip_rule_blocked(&unreachable(), "198.51.100.7"),
        )
        .await
        .expect("ip rule lookup is bounded");
        assert_eq!(answer, Err(()));
    }

    /// #349: auth's dynamic credential mount reads these six; a failed
    /// authoritative reload must switch HTTP admission on, never leave it off.
    #[tokio::test]
    async fn failed_reload_turns_every_http_admission_control_on() {
        let mut gate = gate();
        gate.config.overrides.clear();
        assert!(gate.reload_flags().await.is_err());
        for key in ["threat_feed", "geo_block", "spray_detect", "captcha", "tarpit", "rate_limit"] {
            assert!(gate.enabled(&format!("feature.{key}")), "{key}");
        }
    }

    #[test]
    fn lockout_check_keys_fall_back_to_the_ip_key() {
        let gate = gate();
        assert_eq!(gate.check_keys(&meta("")), vec!["ip:198.51.100.7".to_owned()]);
        assert_eq!(gate.check_keys(&meta("a@example.test")).len(), 3);
    }

    /// An HTTP request without a username still pays the lockout check (#349),
    /// so an unreachable worker pool rejects it; protocol listeners keep Go's skip.
    #[tokio::test]
    async fn http_without_username_still_checks_the_ip_lock() {
        let mut http = meta("");
        http.protocol = "http".into();
        let gate = Gate {
            exec: ScopedExecutor::from_dsn(
                &std::env::var("TEST_DB_DSN").unwrap_or_else(|_| "host=127.0.0.1 port=1 user=gate dbname=gate".into()),
                1,
            )
            .unwrap(),
            ..gate()
        };
        let decision = tokio::time::timeout(Duration::from_secs(10), gate.decide(&http, true))
            .await
            .expect("bounded");
        assert_eq!(decision.action, ThreatAction::Reject);
        assert!(
            matches!(decision.reason.as_str(), "lockout_unavailable" | "ip_rules_unavailable"),
            "{}",
            decision.reason
        );
    }
}
