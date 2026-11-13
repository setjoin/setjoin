//! `mailserver/internal/metrics` and `middleware.MetricsAuth`: the
//! Prometheus text exposition of `GET /metrics`.
//!
//! The metric names, help strings and order are Go's. Process counters come
//! from the front door instead of Go's `RecordRequest` hooks; Go's TCP, TLS
//! and per-method families only exist while Go mail protocols record into
//! them, so they are omitted (the SMTP queue depth gauge is never set in Go
//! and stays 0).
use setjoin_pg::ScopedExecutor;

/// `MetricsAuth`'s decision from `METRICS_TOKEN` / `METRICS_ALLOW_UNAUTHENTICATED`.
#[derive(Clone, Debug)]
pub struct MetricsAuth {
    token: String,
    open: bool,
}

impl MetricsAuth {
    pub fn from_values(token: &str, allow_unauthenticated: &str) -> Self {
        Self {
            token: token.to_owned(),
            open: token.is_empty() && matches!(allow_unauthenticated, "1" | "true"),
        }
    }

    /// Whether the request may scrape. `authorization` is the raw header.
    pub fn admits(&self, authorization: Option<&str>) -> bool {
        if self.token.is_empty() {
            return self.open;
        }
        authorization
            .and_then(|a| a.strip_prefix("Bearer "))
            .is_some_and(|presented| constant_time_eq(presented.as_bytes(), self.token.as_bytes()))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The identity-health gauges Go's collector publishes (20 values).
#[derive(Clone, Copy, Default, Debug)]
pub struct Identity {
    pub success: i64,
    pub critical: i64,
    pub sources: i64,
    pub inbox: i64,
    pub quarantined: i64,
    pub conflicts: i64,
    pub transitions: i64,
    pub effects: i64,
    pub cohort: i64,
    pub sync_runs: i64,
    pub sync_duration: i64,
    pub cursor_age: i64,
    pub generation_rejects: i64,
    pub transition_age: i64,
    pub approval_age: i64,
    pub approvals_pending: i64,
    pub approval_expiry: i64,
    pub effect_age: i64,
    pub effect_retries: i64,
    pub auth_resolutions: i64,
    pub grant_changes: i64,
}

const IDENTITY_SQL: &str = "SELECT
 (SELECT count(*) FROM identity_shadow_divergences WHERE state='open' AND divergence_class<>'expected_legacy_ambiguity'),
 (SELECT count(*) FROM identity_sources WHERE state IN ('error','paused') OR last_error_code IS NOT NULL),
 (SELECT count(*) FROM identity_source_inbox WHERE state IN ('pending','quarantined')),
 (SELECT count(*) FROM identity_source_inbox WHERE state='quarantined'),
 (SELECT count(*) FROM identity_match_candidates WHERE status IN ('pending','deferred')),
 (SELECT count(*) FROM identity_transitions WHERE state NOT IN ('completed','rolled_back')),
 (SELECT count(*) FROM identity_transition_effects WHERE state<>'completed'),
 (SELECT count(*) FROM identity_read_cohort),
 (SELECT count(*) FROM identity_sync_log WHERE source_id IS NOT NULL),
 COALESCE((SELECT max(duration_ms)/1000 FROM identity_sync_log WHERE source_id IS NOT NULL),0),
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-last_success_at))::bigint FROM identity_sources WHERE last_success_at IS NOT NULL),0),
 (SELECT count(*) FROM identity_source_inbox WHERE last_error_code='BZ229'),
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-created_at))::bigint FROM identity_transitions WHERE state NOT IN ('completed','rolled_back','cancelled','expired')),0),
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-created_at))::bigint FROM approval_requests WHERE consumer_type='identity.transition' AND status='pending'),0),
 (SELECT count(*) FROM approval_requests WHERE consumer_type='identity.transition' AND status='pending'),
 COALESCE((SELECT greatest(0,min(extract(epoch FROM expires_at-statement_timestamp())))::bigint FROM approval_requests WHERE consumer_type='identity.transition' AND status='pending'),0),
 COALESCE((SELECT max(extract(epoch FROM statement_timestamp()-updated_at))::bigint FROM identity_transition_effects WHERE state<>'completed'),0),
 COALESCE((SELECT sum(attempt_count)::bigint FROM identity_transition_effects),0),
 (SELECT count(*) FROM identity_link_events WHERE action IN ('auth_jit_created','auth_linked','auth_resolved')),
 (SELECT count(*) FROM identity_link_events WHERE action IN ('entitlements_reconciled','authority_changed','transition_committed'))";

/// One collection round; `success = 0` with zeroed values when it fails, as
/// Go's collector publishes on a failed query.
pub async fn collect_identity(exec: &ScopedExecutor) -> Identity {
    let Ok(rows) = exec.read(IDENTITY_SQL, &[]).await else {
        return Identity::default();
    };
    let Some(row) = rows.first() else {
        return Identity::default();
    };
    let n = |i: usize| {
        row.try_get::<_, i64>(i)
            .or_else(|_| row.try_get::<_, i32>(i).map(i64::from))
            .unwrap_or(0)
    };
    Identity {
        success: 1,
        critical: n(0),
        sources: n(1),
        inbox: n(2),
        quarantined: n(3),
        conflicts: n(4),
        transitions: n(5),
        effects: n(6),
        cohort: n(7),
        sync_runs: n(8),
        sync_duration: n(9),
        cursor_age: n(10),
        generation_rejects: n(11),
        transition_age: n(12),
        approval_age: n(13),
        approvals_pending: n(14),
        approval_expiry: n(15),
        effect_age: n(16),
        effect_retries: n(17),
        auth_resolutions: n(18),
        grant_changes: n(19),
    }
}

/// Process-level values the front door supplies.
#[derive(Clone, Copy, Default, Debug)]
pub struct Process {
    pub requests: u64,
    pub errors: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub duration_ms: u64,
    pub active_connections: i64,
    pub memory_bytes: u64,
    pub tasks: u64,
}

pub fn render(process: &Process, identity: &Identity) -> String {
    let mut out = String::new();
    let mut family = |name: &str, help: &str, kind: &str, value: String| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    family(
        "gateway_requests_total",
        "Total HTTP requests",
        "counter",
        process.requests.to_string(),
    );
    family(
        "gateway_request_errors_total",
        "Total HTTP request errors",
        "counter",
        process.errors.to_string(),
    );
    family(
        "gateway_request_4xx_total",
        "HTTP 4xx responses",
        "counter",
        process.status_4xx.to_string(),
    );
    family(
        "gateway_request_5xx_total",
        "HTTP 5xx responses",
        "counter",
        process.status_5xx.to_string(),
    );
    family(
        "gateway_request_duration_ms_total",
        "Cumulative request duration",
        "counter",
        process.duration_ms.to_string(),
    );
    family(
        "gateway_active_connections",
        "Current active connections",
        "gauge",
        process.active_connections.to_string(),
    );
    family(
        "gateway_memory_alloc_bytes",
        "Allocated memory",
        "gauge",
        process.memory_bytes.to_string(),
    );
    family(
        "gateway_goroutines_total",
        "Current goroutines",
        "gauge",
        process.tasks.to_string(),
    );
    family(
        "gateway_smtp_queue_depth",
        "Current outbound SMTP queue depth",
        "gauge",
        "0".into(),
    );
    let i = identity;
    let identity_rows: &[(&str, &str, &str, i64)] = &[
        (
            "gateway_identity_shadow_critical",
            "Open unexplained critical identity divergences",
            "gauge",
            i.critical,
        ),
        (
            "gateway_identity_sources_attention",
            "Identity sources requiring operator attention",
            "gauge",
            i.sources,
        ),
        (
            "gateway_identity_inbox_pending",
            "Pending or quarantined identity source entries",
            "gauge",
            i.inbox,
        ),
        (
            "gateway_identity_inbox_quarantined",
            "Quarantined identity source entries",
            "gauge",
            i.quarantined,
        ),
        (
            "gateway_identity_conflicts_pending",
            "Pending or deferred identity match conflicts",
            "gauge",
            i.conflicts,
        ),
        (
            "gateway_identity_transitions_pending",
            "Identity transitions not in a terminal state",
            "gauge",
            i.transitions,
        ),
        (
            "gateway_identity_effects_pending",
            "Identity transition effects not completed",
            "gauge",
            i.effects,
        ),
        (
            "gateway_identity_canary_members",
            "Users in normalized identity read canary cohorts",
            "gauge",
            i.cohort,
        ),
        (
            "gateway_identity_collector_success",
            "Whether the last identity metrics collection succeeded",
            "gauge",
            i.success,
        ),
        (
            "setjoin_identity_sync_runs_total",
            "Retained normalized identity sync runs",
            "counter",
            i.sync_runs,
        ),
        (
            "setjoin_identity_sync_duration_seconds",
            "Longest retained normalized identity sync duration",
            "gauge",
            i.sync_duration,
        ),
        (
            "setjoin_identity_cursor_age_seconds",
            "Oldest observed successful identity source cursor age",
            "gauge",
            i.cursor_age,
        ),
        (
            "setjoin_identity_inbox_rows",
            "Pending or quarantined identity source inbox rows",
            "gauge",
            i.inbox,
        ),
        (
            "setjoin_identity_generation_rejects_total",
            "Retained stale-generation connector rejects",
            "counter",
            i.generation_rejects,
        ),
        (
            "setjoin_identity_candidates",
            "Pending or deferred identity match candidates",
            "gauge",
            i.conflicts,
        ),
        (
            "setjoin_identity_conflicts",
            "Pending or deferred identity conflicts",
            "gauge",
            i.conflicts,
        ),
        (
            "setjoin_identity_shadow_divergences",
            "Open unexplained critical identity divergences",
            "gauge",
            i.critical,
        ),
        (
            "setjoin_identity_transitions",
            "Nonterminal identity transitions",
            "gauge",
            i.transitions,
        ),
        (
            "setjoin_identity_transition_age_seconds",
            "Age of the oldest nonterminal identity transition",
            "gauge",
            i.transition_age,
        ),
        (
            "setjoin_identity_approval_age_seconds",
            "Age of the oldest pending identity transition approval",
            "gauge",
            i.approval_age,
        ),
        (
            "gateway_identity_approvals_pending",
            "Pending identity transition approvals",
            "gauge",
            i.approvals_pending,
        ),
        (
            "gateway_identity_approval_expiry_seconds",
            "Seconds until the earliest pending identity transition approval expires",
            "gauge",
            i.approval_expiry,
        ),
        (
            "setjoin_identity_effect_intents",
            "Incomplete identity transition effects",
            "gauge",
            i.effects,
        ),
        (
            "setjoin_identity_effect_oldest_age_seconds",
            "Age of the oldest incomplete identity transition effect",
            "gauge",
            i.effect_age,
        ),
        (
            "setjoin_identity_effect_retries_total",
            "Retained identity effect attempts",
            "counter",
            i.effect_retries,
        ),
        (
            "setjoin_identity_auth_resolution_total",
            "Retained normalized authentication resolution events",
            "counter",
            i.auth_resolutions,
        ),
    ];
    for (name, help, kind, value) in identity_rows {
        family(name, help, kind, value.to_string());
    }
    family(
        "setjoin_identity_grant_changes_total",
        "Retained normalized authority or grant change events",
        "counter",
        i.grant_changes.to_string(),
    );
    out
}
