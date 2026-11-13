//! Slice `spam` (#322): the ML spam dashboard and per-user model switches (admin), the
//! per-user sender lists, trusted (image-allow) senders, external-sender warning, the
//! message-bound sender-control center and the user spam/phishing report.
//!
//! Every statement names the verified user in its own WHERE (R1-R3); ids in paths, queries
//! and bodies only name targets. Writes are receipted: one statement where Go's transaction
//! is one statement (trusted senders, external-sender toggle, the admin model switches with
//! their reach check folded in), a reducer otherwise (`rust_mailsec_sender_list_replace`,
//! `rust_mailsec_sender_never_block`, `rust_mailsec_report`, and the existing
//! `sender_list_replace` / `sender_control_action` reducers Go already calls).
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};

/// `feature.sender_control_center` as Go's toggle store resolves it (default OFF).
pub async fn sender_control_on(worker: &ScopedExecutor) -> Result<bool, StatementFailure> {
    let rows = worker
        .read(
            "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.sender_control_center'),false)",
            &[],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

fn flag(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// Go's `strconv.FormatFloat(f, 'f'|'e', -1, 64)` as `encoding/json` picks it.
pub fn go_float(f: f64) -> String {
    if f == 0.0 {
        return "0".into();
    }
    let a = f.abs();
    if !(1e-6..1e21).contains(&a) {
        // Rust's `{:e}` is Go's 'e' form with a one-digit-minimum exponent, which is what
        // encoding/json produces after cleaning "e-07" to "e-7".
        return format!("{f:e}");
    }
    format!("{f}")
}

// ---- admin: dashboard and model switches ----

async fn count(worker: &ScopedExecutor, sql: &str) -> i64 {
    match worker.read(sql, &[]).await {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// `GET /admin/spam`: Go ignores every scan error (the field keeps its zero value), so each
/// aggregate degrades to 0 on its own. The batch-load gauges are the Go delivery path's
/// process-local counters; standalone F06 callers default to an idle store.
pub async fn dashboard(worker: &ScopedExecutor) -> String {
    dashboard_with_stats(worker, Default::default()).await
}

pub async fn dashboard_with_stats(worker: &ScopedExecutor, stats: setjoin_spam::BatchStats) -> String {
    let (batch_models, batch_bytes, batch_loads, batch_hits) = (stats.resident_models,stats.resident_bytes,stats.loads,stats.hits);
    let enabled = match worker
        .read(
            "SELECT enabled FROM feature_toggles WHERE key = 'feature.ml_spam'",
            &[],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false),
        Err(_) => false,
    };
    // One statement per Go query: a failing one only zeroes its own fields.
    let (models, samples): (i64, i64) = match worker
        .read(
            "SELECT COALESCE(COUNT(*), 0)::bigint, COALESCE(SUM(sample_count), 0)::bigint FROM user_spam_model",
            &[],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .map(|r| (r.get::<_, i64>(0), r.get::<_, i64>(1)))
            .unwrap_or_default(),
        Err(_) => (0, 0),
    };
    let average: f64 = match worker
        .read(
            "SELECT COALESCE(AVG(sample_count), 0)::text FROM user_spam_model",
            &[],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .and_then(|t| t.parse().ok())
            .unwrap_or(0.0),
        Err(_) => 0.0,
    };
    let disabled = count(
        worker,
        "SELECT COALESCE(COUNT(*), 0)::bigint FROM user_spam_model WHERE disabled = TRUE",
    )
    .await;
    let active = count(
        worker,
        "SELECT COALESCE(COUNT(*), 0)::bigint FROM user_spam_model WHERE trained_at > now() - INTERVAL '7 days'",
    )
    .await;
    let (fp, fneg, classified): (i64, i64, i64) = match worker
        .read(
            "SELECT COALESCE(SUM(fp_count), 0)::bigint, COALESCE(SUM(fn_count), 0)::bigint, COALESCE(SUM(classified_count), 0)::bigint FROM user_spam_model",
            &[],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .unwrap_or_default(),
        Err(_) => (0, 0, 0),
    };
    let rate = if classified > 0 {
        fp as f64 / classified as f64
    } else {
        0.0
    };
    let mut top = vec![];
    if let Ok(rows) = worker
        .read(
            "SELECT m.user_id, COALESCE(u.email, 'unknown'), m.sample_count, \
             to_char(m.trained_at, 'YYYY-MM-DD HH24:MI') AS trained, \
             (octet_length(m.model_bytes) / 1024)::int4 AS size_kb, m.disabled \
             FROM user_spam_model m LEFT JOIN users u ON u.id = m.user_id \
             ORDER BY m.sample_count DESC LIMIT 10",
            &[],
        )
        .await
    {
        for r in &rows {
            // A row whose Scan fails is skipped, as Go's.
            let (Ok(id), Ok(email), Ok(n), Ok(at), Ok(kb), Ok(off)) = (
                r.try_get::<_, i64>(0),
                r.try_get::<_, String>(1),
                r.try_get::<_, i32>(2),
                r.try_get::<_, String>(3),
                r.try_get::<_, i32>(4),
                r.try_get::<_, bool>(5),
            ) else {
                continue;
            };
            top.push(format!(
                "{{\"user_id\":{id},\"email\":{},\"sample_count\":{n},\"trained_at\":{},\"model_size_kb\":{kb},\"disabled\":{off}}}",
                s(&email),
                s(&at)
            ));
        }
    }
    done(format!(
        "{{\"enabled\":{enabled},\"total_models\":{models},\"total_samples\":{samples},\"avg_samples\":{},\"active_week\":{active},\"disabled_users\":{disabled},\"total_fp\":{fp},\"total_fn\":{fneg},\"total_classified\":{classified},\"fp_rate\":{},\"top_users\":[{}],\"feature_size\":1048576,\"min_samples\":50,\"batch_load_resident_models\":{batch_models},\"batch_load_resident_bytes\":{batch_bytes},\"batch_load_loads\":{batch_loads},\"batch_load_hits\":{batch_hits}}}",
        go_float(average),
        go_float(rate),
        top.join(",")
    ))
}

/// Which model switch an admin asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    Reset,
    Disable,
    Enable,
}

/// Go's reach check plus the write, in one statement so the check cannot go stale before
/// the write (R3). `Committed(false)` is Go's 403 "target user not within your
/// administrative scope"; a statement error is its 500 "database error".
pub async fn switch_model(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    what: Switch,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let (name, sql) = match what {
        Switch::Reset => (
            "spam.model.reset",
            "WITH r AS (SELECT admin_can_reach($2, $4) AS ok), \
             d AS (DELETE FROM user_spam_model WHERE user_id = $4 AND (SELECT ok FROM r) RETURNING 1) \
             SELECT ok FROM r WHERE $1::bigint > 0 AND $3::text <> ''",
        ),
        Switch::Disable => (
            "spam.model.disable",
            "WITH r AS (SELECT admin_can_reach($2, $4) AS ok), \
             i AS (INSERT INTO user_spam_model (user_id, model_bytes, sample_count, disabled) \
                   SELECT $4, '\\x'::bytea, 0, TRUE FROM r WHERE ok \
                   ON CONFLICT (user_id) DO UPDATE SET disabled = TRUE RETURNING 1) \
             SELECT ok FROM r WHERE $1::bigint > 0 AND $3::text <> ''",
        ),
        Switch::Enable => (
            "spam.model.enable",
            "WITH r AS (SELECT admin_can_reach($2, $4) AS ok), \
             u AS (UPDATE user_spam_model SET disabled = FALSE WHERE user_id = $4 AND (SELECT ok FROM r) RETURNING 1) \
             SELECT ok FROM r WHERE $1::bigint > 0 AND $3::text <> ''",
        ),
    };
    setjoin_pg::run_receipted_command(
        worker,
        command(name),
        &envelope(&auth, operation, &format!("{name}:{target}")),
        &auth,
        deadline(),
        sql,
        &[(&target, Type::INT8)],
        flag,
    )
    .await
}

// ---- user: sender lists ----

/// `GET /settings/senders` with the sender-control center OFF. A scan failure skips the
/// row and the deferred row error is never read (Go), so only a failed query is an error.
pub async fn senders_legacy(
    worker: &ScopedExecutor,
    user: i64,
) -> Result<String, StatementFailure> {
    let rows = worker
        .read_iterated(
            "SELECT sender, list_type FROM user_sender_list WHERE user_id = $1 ORDER BY list_type, sender",
            &[(&user, Type::INT8)],
        )
        .await?;
    let (mut safe, mut blocked) = (vec![], vec![]);
    for r in &rows {
        let (Ok(sender), Ok(kind)) = (r.try_get::<_, String>(0), r.try_get::<_, String>(1)) else {
            continue;
        };
        if kind == "safe" {
            safe.push(s(&sender));
        } else {
            blocked.push(s(&sender));
        }
    }
    Ok(done(format!(
        "{{\"blocked\":[{}],\"safe\":[{}]}}",
        blocked.join(","),
        safe.join(",")
    )))
}

/// A reducer's jsonb answer, as the `::text` Postgres prints, and its `generation` field.
pub struct Raw {
    pub body: String,
    pub generation: String,
}
impl Raw {
    fn from(rows: &[Row]) -> Result<Raw, StatementFailure> {
        let body: String = rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .ok_or_else(invalid)?;
        // `json.Unmarshal` into a string field leaves "" for null or a non-string.
        let generation = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["generation"].as_str().map(str::to_owned))
            .unwrap_or_default();
        Ok(Raw { body, generation })
    }
}

/// `GET /settings/senders` with the center ON: `sender_list_read`.
pub async fn sender_list_read(worker: &ScopedExecutor, user: i64) -> Result<Raw, StatementFailure> {
    Raw::from(
        &worker
            .read("SELECT sender_list_read($1)::text", &[(&user, Type::INT8)])
            .await?,
    )
}

/// `PUT /settings/senders` with the center OFF: delete-all plus re-insert, one transaction.
pub async fn sender_list_replace_legacy(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    safe: &[String],
    blocked: &[String],
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let (safe, blocked) = (safe.to_vec(), blocked.to_vec());
    setjoin_pg::run_receipted_command(
        worker,
        command("senders.replace"),
        &envelope(
            &auth,
            operation,
            &format!("senders.replace:{}:{}", safe.len(), blocked.len()),
        ),
        &auth,
        deadline(),
        "SELECT rust_mailsec_sender_list_replace($2, $4, $5) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&safe, Type::TEXT_ARRAY), (&blocked, Type::TEXT_ARRAY)],
        flag,
    )
    .await
}

/// `PUT /settings/senders` with the center ON: the existing `sender_list_replace` reducer,
/// called with exactly Go's arguments (its own idempotency record replaces our receipt's
/// role for replays).
#[allow(clippy::too_many_arguments)]
pub async fn sender_list_replace(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    operation_id: &str,
    generation: i64,
    digest: &str,
    safe: &Option<Vec<String>>,
    blocked: &Option<Vec<String>>,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("senders.replace.generation"),
        &envelope(&auth, operation, &format!("senders.replace.generation:{operation_id}")),
        &auth,
        deadline(),
        "SELECT sender_list_replace($2, $4::text::uuid, $5, $6, $7, $8)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&operation_id, Type::TEXT),
            (&generation, Type::INT8),
            (&digest, Type::TEXT),
            (safe, Type::TEXT_ARRAY),
            (blocked, Type::TEXT_ARRAY),
        ],
        Raw::from,
    )
    .await
}

/// `POST /settings/senders/never-block` with the center OFF.
pub async fn never_block(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    sender: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("senders.never_block"),
        &envelope(&auth, operation, "senders.never_block"),
        &auth,
        deadline(),
        "SELECT rust_mailsec_sender_never_block($2, $4) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&sender, Type::TEXT)],
        flag,
    )
    .await
}

// ---- user: sender-control center ----

/// `GET /settings/sender-control`.
pub async fn sender_control_read(
    worker: &ScopedExecutor,
    user: i64,
    mailbox: i64,
    message: i64,
    received_at: &str,
) -> Result<Raw, StatementFailure> {
    Raw::from(
        &worker
            .read(
                "SELECT sender_control_read($1, $2, $3, $4::text::timestamptz)::text",
                &[
                    (&user, Type::INT8),
                    (&mailbox, Type::INT8),
                    (&message, Type::INT8),
                    (&received_at, Type::TEXT),
                ],
            )
            .await?,
    )
}

/// The decoded, validated `POST /settings/sender-control/actions` target and operation.
pub struct ControlAction<'a> {
    pub mailbox: i64,
    pub message: i64,
    pub received_at: &'a str,
    pub operation_id: &'a str,
    pub action: &'a str,
    pub generation: i64,
    pub digest: &'a str,
    pub target_operation: Option<&'a str>,
}

pub async fn sender_control_action(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    a: &ControlAction<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("sender_control.action"),
        &envelope(
            &auth,
            operation,
            &format!("sender_control.action:{}", a.operation_id),
        ),
        &auth,
        deadline(),
        "SELECT sender_control_action($2, $4, $5, $6::text::timestamptz, $7::text::uuid, $8, $9, $10, $11::text::uuid)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&a.mailbox, Type::INT8),
            (&a.message, Type::INT8),
            (&a.received_at, Type::TEXT),
            (&a.operation_id, Type::TEXT),
            (&a.action, Type::TEXT),
            (&a.generation, Type::INT8),
            (&a.digest, Type::TEXT),
            (&a.target_operation, Type::TEXT),
        ],
        Raw::from,
    )
    .await
}

// ---- user: trusted (image-allow) senders ----

/// `GET /settings/trusted-senders`: Go checks `rows.Err()` here, so any failure is a 500.
pub async fn trusted_list(worker: &ScopedExecutor, user: i64) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT sender, to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
             FROM user_image_allow WHERE user_id = $1 ORDER BY created_at DESC, sender",
            &[(&user, Type::INT8)],
        )
        .await?;
    let mut items = vec![];
    for r in &rows {
        items.push(format!(
            "{{\"sender\":{},\"createdAt\":{}}}",
            s(&r.try_get::<_, String>(0).map_err(|_| invalid())?),
            s(&r.try_get::<_, String>(1).map_err(|_| invalid())?)
        ));
    }
    Ok(done(format!("{{\"senders\":[{}]}}", items.join(","))))
}

/// `POST /settings/trusted-senders` (upsert) or `DELETE /settings/trusted-senders/{sender}`:
/// one statement each, the verified user in the same WHERE or VALUES.
pub async fn trusted_write(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    sender: &str,
    add: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let (name, sql) = if add {
        (
            "trusted_senders.add",
            "INSERT INTO user_image_allow (user_id, sender) SELECT $2, $4 \
             WHERE $1::bigint > 0 AND $3::text <> '' \
             ON CONFLICT (user_id, sender) DO NOTHING RETURNING true",
        )
    } else {
        (
            "trusted_senders.remove",
            "DELETE FROM user_image_allow WHERE user_id = $2 AND sender = $4 \
             AND $1::bigint > 0 AND $3::text <> '' RETURNING true",
        )
    };
    setjoin_pg::run_receipted_command(
        worker,
        command(name),
        &envelope(&auth, operation, name),
        &auth,
        deadline(),
        sql,
        &[(&sender, Type::TEXT)],
        |_| Ok(true),
    )
    .await
}

// ---- user: external-sender warning ----

fn json_bool(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

/// `GET /settings/external-sender`: each of Go's three reads degrades on error.
pub async fn external_get(worker: &ScopedExecutor, user: i64) -> String {
    let (user_enabled, email) = match worker
        .read(
            "SELECT COALESCE(external_sender_warning, TRUE), email FROM users WHERE id = $1",
            &[(&user, Type::INT8)],
        )
        .await
    {
        Ok(rows) => match rows.first() {
            Some(r) => match (r.try_get::<_, bool>(0), r.try_get::<_, String>(1)) {
                (Ok(a), Ok(b)) => (a, b),
                _ => (true, String::new()),
            },
            None => (true, String::new()),
        },
        Err(_) => (true, String::new()),
    };
    let domain = email.rsplit_once('@').map_or("", |(_, d)| d).to_owned();
    let mut domain_part = String::new();
    if !email.is_empty() && !domain.is_empty() {
        if let Ok(rows) = worker
            .read(
                "SELECT esc.enabled, esc.warn_text, esc.warn_color FROM domains d \
                 JOIN external_sender_config esc ON esc.domain_id = d.id \
                 WHERE lower(d.name) = lower($1) AND d.is_local = TRUE",
                &[(&domain, Type::TEXT)],
            )
            .await
        {
            // Go scans warn_color into a plain string: a NULL fails the whole Scan.
            if let Some(r) = rows.first() {
                if let (Ok(enabled), Ok(text), Ok(color)) = (
                    r.try_get::<_, bool>(0),
                    r.try_get::<_, Option<String>>(1),
                    r.try_get::<_, String>(2),
                ) {
                    domain_part = format!(
                        "\"domainEnabled\":{},\"domainWarnColor\":{},",
                        json_bool(enabled),
                        s(&color)
                    );
                    if let Some(text) = text {
                        domain_part.push_str(&format!("\"domainWarnText\":{},", s(&text)));
                    }
                }
            }
        }
    }
    let global = match worker
        .read(
            "SELECT value::text FROM system_config WHERE key = 'external_sender.enabled'",
            &[],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .is_none_or(|v| v != "false"),
        Err(_) => true,
    };
    done(format!(
        "{{{domain_part}\"globalEnabled\":{},\"userEnabled\":{}}}",
        json_bool(global),
        json_bool(user_enabled)
    ))
}

/// `PUT /settings/external-sender`: one UPDATE on the verified user.
pub async fn external_put(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    enabled: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("external_sender.set"),
        &envelope(&auth, operation, "external_sender.set"),
        &auth,
        deadline(),
        "UPDATE users SET external_sender_warning = $4 WHERE id = $2 \
         AND $1::bigint > 0 AND $3::text <> '' RETURNING true",
        &[(&enabled, Type::BOOL)],
        |_| Ok(true),
    )
    .await
}

// ---- user: report ----

/// `POST /report` with the center OFF. `Committed(false)` is Go's 404 "message not found".
pub async fn report(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    message: i64,
    kind: &str,
    note: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("report"),
        &envelope(&auth, operation, &format!("report:{message}:{kind}")),
        &auth,
        deadline(),
        "SELECT rust_mailsec_report($2, $4, $5, $6) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&message, Type::INT8),
            (&kind, Type::TEXT),
            (&note, Type::TEXT),
        ],
        flag,
    )
    .await
}
