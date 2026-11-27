//! Slice `spam` (#322): the ML spam dashboard and per-user model switches (admin), the
//! per-user sender lists, trusted (image-allow) senders, external-sender warning, the
//! message-bound sender-control center and the user spam/phishing report.
//!
//! Every statement names the verified user in its own WHERE (R1-R3); ids in paths, queries
//! and bodies only name targets. User self-service writes run via `UserTx` / `MailboxTx`,
//! including `rust_user_external_sender_warning_set` (retiring the legacy
//! direct `UPDATE users`). Admin dashboard reads run via `AdminReadTx`; admin model switches
//! execute `SPAM_MODEL_*` (`WorkerBypass` over `user_spam_model` with FORCE RLS `V287`)
//! through the gateway composition root so no extra `admin_audit_log` row breaks Go parity.
use super::{command, deadline, done, envelope, invalid, mailbox_envelope, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, MutateCapability, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Row, StatementFailure};

/// `feature.sender_control_center` as Go's toggle store resolves it (default OFF).
pub async fn sender_control_on(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::SPAM_SENDER_CONTROL_ON, &[])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

fn flag(rows: Vec<Row>) -> Result<bool, StatementFailure> {
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

async fn count(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    contract: &'static setjoin_sql_catalog::SqlContract,
) -> i64 {
    match factory.run_admin_read_contract(admin, contract, &[]).await {
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
pub async fn dashboard(factory: &TxFactory, admin: &AdminPermissionProof) -> String {
    dashboard_with_stats(factory, admin, Default::default()).await
}

pub async fn dashboard_with_stats(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    stats: setjoin_spam::BatchStats,
) -> String {
    let (batch_models, batch_bytes, batch_loads, batch_hits) = (
        stats.resident_models,
        stats.resident_bytes,
        stats.loads,
        stats.hits,
    );
    let enabled = match factory
        .run_admin_read_contract(admin, &sql::SPAM_DASHBOARD_ENABLED, &[])
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false),
        Err(_) => false,
    };
    // One statement per Go query: a failing one only zeroes its own fields.
    let (models, samples): (i64, i64) = match factory
        .run_admin_read_contract(admin, &sql::SPAM_DASHBOARD_TOTALS, &[])
        .await
    {
        Ok(rows) => rows
            .first()
            .map(|r| (r.get::<_, i64>(0), r.get::<_, i64>(1)))
            .unwrap_or_default(),
        Err(_) => (0, 0),
    };
    let average: f64 = match factory
        .run_admin_read_contract(admin, &sql::SPAM_DASHBOARD_AVG, &[])
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .and_then(|t| t.parse().ok())
            .unwrap_or(0.0),
        Err(_) => 0.0,
    };
    let disabled = count(factory, admin, &sql::SPAM_DASHBOARD_DISABLED).await;
    let active = count(factory, admin, &sql::SPAM_DASHBOARD_ACTIVE).await;
    let (fp, fneg, classified): (i64, i64, i64) = match factory
        .run_admin_read_contract(admin, &sql::SPAM_DASHBOARD_COUNTS, &[])
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
    if let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::SPAM_DASHBOARD_TOP, &[])
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

// ---- user: sender lists ----

/// `GET /settings/senders` with the sender-control center OFF. A scan failure skips the
/// row and the deferred row error is never read (Go), so only a failed query is an error.
pub async fn senders_legacy(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let mut tx = factory.begin_user_read(user).await?;
    let rows = tx
        .query_iterated_contract(&sql::SPAM_SENDERS_LEGACY, &[&uid])
        .await?;
    tx.finish().await?;
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
    fn from(rows: Vec<Row>) -> Result<Raw, StatementFailure> {
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
pub async fn sender_list_read(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Raw, StatementFailure> {
    let uid = user.user().get();
    Raw::from(
        factory
            .run_user_read_contract(user, &sql::SPAM_SENDER_LIST_READ, &[&uid])
            .await?,
    )
}

/// `PUT /settings/senders` with the center OFF: delete-all plus re-insert, one transaction.
pub async fn sender_list_replace_legacy(
    factory: &TxFactory,
    user: &UserPrincipal,
    safe: &[String],
    blocked: &[String],
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let (safe, blocked) = (safe.to_vec(), blocked.to_vec());
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("senders.replace:{}:{}", safe.len(), blocked.len()),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SPAM_SENDER_LIST_REPLACE_LEGACY,
            &[&uid, &safe, &blocked],
            Some(command("senders.replace")),
            flag,
        )
        .await
}

/// `PUT /settings/senders` with the center ON: the existing `sender_list_replace` reducer,
/// called with exactly Go's arguments (its own idempotency record replaces our receipt's
/// role for replays).
#[allow(clippy::too_many_arguments)]
pub async fn sender_list_replace(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation_id: &str,
    generation: i64,
    digest: &str,
    safe: &Option<Vec<String>>,
    blocked: &Option<Vec<String>>,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("senders.replace.generation:{operation_id}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SPAM_SENDER_LIST_REPLACE,
            &[&uid, &operation_id, &generation, &digest, safe, blocked],
            Some(command("senders.replace.generation")),
            Raw::from,
        )
        .await
}

/// `POST /settings/senders/never-block` with the center OFF.
pub async fn never_block(
    factory: &TxFactory,
    user: &UserPrincipal,
    sender: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        "senders.never_block",
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SPAM_NEVER_BLOCK,
            &[&uid, &sender],
            Some(command("senders.never_block")),
            flag,
        )
        .await
}

// ---- user: sender-control center ----

/// `GET /settings/sender-control`.
pub async fn sender_control_read(
    factory: &TxFactory,
    user: &UserPrincipal,
    mailbox: i64,
    message: i64,
    received_at: &str,
) -> Result<Raw, StatementFailure> {
    let uid = user.user().get();
    Raw::from(
        factory
            .run_user_read_contract(
                user,
                &sql::SPAM_SENDER_CONTROL_READ,
                &[&uid, &mailbox, &message, &received_at],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    a: &ControlAction<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("sender_control.action:{}", a.operation_id),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SPAM_SENDER_CONTROL_ACTION,
            &[
                &uid,
                &a.mailbox,
                &a.message,
                &a.received_at,
                &a.operation_id,
                &a.action,
                &a.generation,
                &a.digest,
                &a.target_operation,
            ],
            Some(command("sender_control.action")),
            Raw::from,
        )
        .await
}

// ---- user: trusted (image-allow) senders ----

/// `GET /settings/trusted-senders`: Go checks `rows.Err()` here, so any failure is a 500.
pub async fn trusted_list(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::SPAM_TRUSTED_LIST, &[&uid])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    sender: &str,
    add: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let (name, contract) = if add {
        ("trusted_senders.add", &sql::SPAM_TRUSTED_ADD)
    } else {
        ("trusted_senders.remove", &sql::SPAM_TRUSTED_REMOVE)
    };
    let env = envelope(user.user(), user.generation(), operation, name);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            &[&uid, &sender],
            Some(command(name)),
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
pub async fn external_get(factory: &TxFactory, user: &UserPrincipal) -> String {
    let uid = user.user().get();
    let (user_enabled, email) = match factory
        .run_user_read_contract(user, &sql::SPAM_EXTERNAL_USER, &[&uid])
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
        if let Ok(rows) = factory
            .run_user_read_contract(user, &sql::SPAM_EXTERNAL_DOMAIN, &[&domain])
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
    let global = match factory
        .run_user_read_contract(user, &sql::SPAM_EXTERNAL_GLOBAL, &[])
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

/// `PUT /settings/external-sender`: update via `rust_user_external_sender_warning_set`.
pub async fn external_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    enabled: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        "external_sender.set",
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SPAM_EXTERNAL_PUT,
            &[&uid, &enabled],
            Some(command("external_sender.set")),
            |_| Ok(true),
        )
        .await
}

// ---- user: report ----

/// `POST /report` with the center OFF. `Committed(false)` is Go's 404 "message not found".
pub async fn report(
    factory: &TxFactory,
    cap: &MutateCapability,
    message: i64,
    kind: &str,
    note: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = cap.actor().get();
    let env = mailbox_envelope(
        cap.actor(),
        cap.mailbox(),
        operation,
        &format!("report:{message}:{kind}"),
    );
    factory
        .run_mailbox_write_contract_pipelined(
            cap,
            &env,
            deadline(),
            &sql::SPAM_REPORT,
            &[&uid, &message, &kind, &note],
            Some(command("report")),
            flag,
        )
        .await
}
