//! Rules and templates (F09). Frozen Go is authoritative; see DOX.md.
#![forbid(unsafe_code)]
use setjoin_authz::AuthContext;
use setjoin_pg::{Row, ScopedExecutor, StatementFailure, Type};
fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid rules result".into(),
    }
}
fn s(v: &str) -> String {
    serde_json::to_string(v).expect("string")
}
fn done(v: String) -> String {
    v.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        + "\n"
}
fn nano(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'")
}
fn columns() -> String {
    format!("id,mailbox_id,name,enabled,priority,run_on,is_transport_rule,conditions::text,actions::text,stop_processing,{},{}",nano("created_at"),nano("updated_at"))
}
fn rule(r: &Row) -> Result<String, StatementFailure> {
    let id: i64 = r.try_get(0).map_err(|_| invalid())?;
    let mb: Option<i64> = r.try_get(1).map_err(|_| invalid())?;
    let mailbox = mb
        .map(|m| format!(",\"mailboxId\":{m}"))
        .unwrap_or_default();
    Ok(format!("{{\"id\":{id}{mailbox},\"name\":{},\"enabled\":{},\"priority\":{},\"runOn\":{},\"isTransportRule\":{},\"conditions\":{},\"actions\":{},\"stopProcessing\":{},\"createdAt\":{},\"updatedAt\":{}}}",s(r.try_get(2).map_err(|_|invalid())?),r.try_get::<_,bool>(3).map_err(|_|invalid())?,r.try_get::<_,i32>(4).map_err(|_|invalid())?,s(r.try_get(5).map_err(|_|invalid())?),r.try_get::<_,bool>(6).map_err(|_|invalid())?,templates::raw(r.try_get(7).map_err(|_|invalid())?),templates::raw(r.try_get(8).map_err(|_|invalid())?),r.try_get::<_,bool>(9).map_err(|_|invalid())?,s(r.try_get(10).map_err(|_|invalid())?),s(r.try_get(11).map_err(|_|invalid())?)))
}
pub async fn personal_list(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read_iterated(&format!("SELECT {} FROM rules WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$1) AND is_transport_rule=FALSE ORDER BY priority,id",columns()),&[(&user,Type::INT8)]).await?;
    Ok(done(format!(
        "[{}]",
        rows.iter()
            .filter_map(|r| rule(r).ok())
            .collect::<Vec<_>>()
            .join(",")
    )))
}

pub mod input;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Param, ReceiptCommand};
use sha2::{Digest as _, Sha256};
fn scope(a: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(a.user_id()).expect("actor"),
        MailboxId::new(a.mailbox_id()).expect("mailbox"),
        Generation(1),
    )
}
pub async fn write(
    exec: &ScopedExecutor,
    a: &AuthContext,
    op: [u8; 16],
    name: &'static str,
    sql: &str,
    params: &[Param<'_>],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(a);
    let envelope = CommandEnvelope {
        operation: OperationId(op),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!("{name}:{sql}:{params:?}").as_bytes()).into(),
        ),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F09",
            command: name,
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        sql,
        params,
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, String>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
pub async fn personal_count(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<i64, StatementFailure> {
    let mb = actor.mailbox_id();
    exec.read(
        "SELECT count(*) FROM rules WHERE mailbox_id=$1",
        &[(&mb, Type::INT8)],
    )
    .await?
    .first()
    .and_then(|r| r.try_get(0).ok())
    .ok_or_else(invalid)
}
pub const PERSONAL_RULE_CAP: i64 = 100;
pub const ACTIVE_SWEEP_CAP: i64 = 3;
/// A command capped per mailbox: the mailbox row is locked and the count and the
/// write are separate statements of one transaction (`run_receipted_command_capped`),
/// so concurrent requests on any replica cannot both pass the cap.
async fn write_capped(
    exec: &ScopedExecutor,
    a: &AuthContext,
    op: [u8; 16],
    name: &'static str,
    count_sql: &str,
    cap: i64,
    sql: &str,
    params: &[Param<'_>],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(a);
    let envelope = CommandEnvelope {
        operation: OperationId(op),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!("{name}:{sql}:{params:?}").as_bytes()).into(),
        ),
        command: (),
    };
    setjoin_pg::run_receipted_command_capped(
        exec,
        ReceiptCommand {
            family: "F09",
            command: name,
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        count_sql,
        cap,
        sql,
        params,
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, String>(0).ok())
                .ok_or_else(invalid)
        },
        || "cap".to_owned(),
    )
    .await
}
/// `Committed("cap")` means the mailbox is at its personal-rule cap and nothing was
/// written. Owner-approved security fix 2026-11-05 (#484): the cap is enforced in the
/// database under a mailbox row lock (Go counted in a separate, unlocked statement).
pub async fn personal_create(
    exec: &ScopedExecutor,
    a: &AuthContext,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let cap = if setjoin_contracts::mutants::on("rules-cap-count-then-insert") {
        i64::MAX
    } else {
        PERSONAL_RULE_CAP
    };
    write_capped(exec,a,op,"personal.create","SELECT count(*) FROM rules WHERE mailbox_id=$1",cap,"INSERT INTO rules(mailbox_id,name,enabled,priority,run_on,is_transport_rule,conditions,actions,stop_processing) SELECT $1,$4,$5,$6::bigint::int,$7,FALSE,$8::text::jsonb,$9::text::jsonb,$10 WHERE $2::bigint>0 AND $3::text<>'' RETURNING id::text",&[(&r.name,Type::TEXT),(&r.enabled,Type::BOOL),(&r.priority,Type::INT8),(&r.run_on,Type::TEXT),(&r.conditions.0,Type::TEXT),(&r.actions.0,Type::TEXT),(&r.stop,Type::BOOL)]).await
}
pub async fn personal_update(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    write(exec,a,op,"personal.update","WITH changed AS(UPDATE rules SET name=COALESCE(NULLIF($5,''),name),enabled=$6,priority=$7::bigint::int,run_on=$8,conditions=COALESCE($9::text::jsonb,conditions),actions=COALESCE($10::text::jsonb,actions),stop_processing=$11,updated_at=now() WHERE id=$4 AND mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$2) AND is_transport_rule=FALSE AND $1::bigint>0 AND $3::text<>'' RETURNING id) SELECT EXISTS(SELECT 1 FROM changed)::text",&[(&id,Type::INT8),(&r.name,Type::TEXT),(&r.enabled,Type::BOOL),(&r.priority,Type::INT8),(&r.run_on,Type::TEXT),(&r.conditions.0,Type::TEXT),(&r.actions.0,Type::TEXT),(&r.stop,Type::BOOL)]).await
}
pub async fn personal_delete(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    write(exec,a,op,"personal.delete","WITH changed AS(DELETE FROM rules WHERE id=$4 AND mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$2) AND is_transport_rule=FALSE AND $1::bigint>0 AND $3::text<>'' RETURNING id) SELECT EXISTS(SELECT 1 FROM changed)::text",&[(&id,Type::INT8)]).await
}
pub async fn active_sweeps(
    exec: &ScopedExecutor,
    a: &AuthContext,
) -> Result<i64, StatementFailure> {
    let mb = a.mailbox_id();
    exec.read("SELECT count(*) FROM scheduled_actions WHERE mailbox_id=$1 AND action_kind='rules_retro' AND status IN('pending','processing')",&[(&mb,Type::INT8)]).await?.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)
}
/// `Committed("cap")` means the mailbox already has [`ACTIVE_SWEEP_CAP`] sweeps in
/// progress and nothing was enqueued (security fix 2026-11-05, #484: counted under the
/// mailbox row lock in the same transaction as the enqueue).
pub async fn apply(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    window: &str,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let cap = if setjoin_contracts::mutants::on("rules-cap-count-then-insert") {
        i64::MAX
    } else {
        ACTIVE_SWEEP_CAP
    };
    write_capped(
        exec,
        a,
        op,
        "personal.apply",
        "SELECT count(*) FROM scheduled_actions WHERE mailbox_id=$1 AND action_kind='rules_retro' AND status IN('pending','processing')",
        cap,
        "SELECT rules_apply_retroactive($1,$4,$5)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&window, Type::TEXT)],
    )
    .await
}
pub async fn apply_status(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: &str,
) -> Result<Option<String>, StatementFailure> {
    let user = a.user_id();
    let rows=exec.read("SELECT status,(payload->>'processed')::bigint,(payload->>'truncated')::boolean FROM scheduled_actions WHERE id=$1::text::uuid AND action_kind='rules_retro' AND mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$2)",&[(&id,Type::TEXT),(&user,Type::INT8)]).await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let mut out = serde_json::json!({"status":row.try_get::<_,String>(0).map_err(|_|invalid())?});
    if let Some(v) = row.try_get::<_, Option<i64>>(1).map_err(|_| invalid())? {
        out["processed"] = serde_json::json!(v)
    }
    if let Some(v) = row.try_get::<_, Option<bool>>(2).map_err(|_| invalid())? {
        out["truncated"] = serde_json::json!(v)
    }
    Ok(Some(done(out.to_string())))
}

pub mod authority;
pub async fn admin_list(
    exec: &ScopedExecutor,
    mailbox: Option<i64>,
) -> Result<String, StatementFailure> {
    let rows = if let Some(mb) = mailbox {
        exec.read_iterated(
            &format!(
                "SELECT {} FROM rules WHERE mailbox_id=$1 ORDER BY priority,id",
                columns()
            ),
            &[(&mb, Type::INT8)],
        )
        .await?
    } else {
        exec.read_iterated(
            &format!(
                "SELECT {} FROM rules ORDER BY is_transport_rule DESC,priority,id",
                columns()
            ),
            &[],
        )
        .await?
    };
    Ok(done(format!(
        "[{}]",
        rows.iter()
            .filter_map(|r| rule(r).ok())
            .collect::<Vec<_>>()
            .join(",")
    )))
}
pub async fn admin_get(exec: &ScopedExecutor, id: i64) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            &format!("SELECT {} FROM rules WHERE id=$1", columns()),
            &[(&id, Type::INT8)],
        )
        .await?;
    rows.first().map(|r| rule(r).map(done)).transpose()
}
pub async fn mailbox_exists(exec: &ScopedExecutor, id: i64) -> bool {
    exec.read(
        "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id=$1)",
        &[(&id, Type::INT8)],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}
pub async fn admin_create(
    exec: &ScopedExecutor,
    a: &AuthContext,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    write(exec,a,op,"admin.create","SELECT rule_config_create($2,$4,$5,$6,$7::bigint::int,$8,$9,$10::text::jsonb,$11::text::jsonb,$12)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&r.mailbox_id,Type::INT8),(&r.name,Type::TEXT),(&r.enabled,Type::BOOL),(&r.priority,Type::INT8),(&r.run_on,Type::TEXT),(&r.transport,Type::BOOL),(&r.conditions.0,Type::TEXT),(&r.actions.0,Type::TEXT),(&r.stop,Type::BOOL)]).await
}
pub async fn admin_update(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    write(exec,a,op,"admin.update","SELECT rule_config_update($2,$4,$5,$6,$7,$8::bigint::int,$9,$10,$11::text::jsonb,$12::text::jsonb,$13)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&id,Type::INT8),(&r.mailbox_id,Type::INT8),(&r.name,Type::TEXT),(&r.enabled,Type::BOOL),(&r.priority,Type::INT8),(&r.run_on,Type::TEXT),(&r.transport,Type::BOOL),(&r.conditions.0,Type::TEXT),(&r.actions.0,Type::TEXT),(&r.stop,Type::BOOL)]).await
}
pub async fn admin_delete(
    exec: &ScopedExecutor,
    a: &AuthContext,
    id: i64,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    write(
        exec,
        a,
        op,
        "admin.delete",
        "SELECT rule_config_delete($2,$4)::text WHERE $1::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8)],
    )
    .await
}
/// Frozen Go's prepared SET LOCAL + SELECT batch always fails (42601) after
/// finding the rule. Keep the same request outcome; do not redesign its preview.
pub async fn admin_test(exec: &ScopedExecutor, id: i64) -> Result<bool, StatementFailure> {
    let rows = exec
        .read(
            "SELECT mailbox_id,conditions::text,actions::text FROM rules WHERE id=$1",
            &[(&id, Type::INT8)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let mailbox: Option<i64> = row.try_get(0).map_err(|_| invalid())?;
    exec.read("SET LOCAL statement_timeout = '5s'; SELECT DISTINCT m.id,m.received_at,m.message_id,m.from_addr,m.subject FROM messages m JOIN message_tags mt ON mt.message_id=m.id AND mt.received_at=m.received_at JOIN tags t ON t.id=mt.tag_id WHERE t.mailbox_id=COALESCE($1,t.mailbox_id) AND m.received_at>now()-interval '7 days' ORDER BY m.received_at DESC LIMIT 20",&[(&mailbox,Type::INT8)]).await?;
    Err(invalid())
}
pub mod templates;
