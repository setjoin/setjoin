//! Directory sync (F02): AD/LDAP administration reads and writes + SCIM 2.0 protocol helpers.
//!
//! Foundation dependencies only (`authz`, `contracts`, `config-secret`, `db`, `pg`, `sql-catalog`).
//! Authority comes from sealed principals (`UserPrincipal`, `AdminPermissionProof`) minted by
//! `TxFactory`; request ids name targets but never grant authority.
#![forbid(unsafe_code)]
pub mod ad;
pub mod ldap;
pub mod observers;
pub mod scim;
pub mod sql;

pub use sql::SQL_CONTRACTS;

use serde_json::{json, Map, Value};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F02";

/// Go's `admin.ConsoleScopes[ConsoleAuth]`, in registration order.
pub const AUTH_CONSOLE: [&str; 4] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
];
pub const IDENTITY_WRITE: [&str; 1] = ["identity.write"];

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid directory result".into(),
    }
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

pub(crate) fn envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// Go writes the same durable console-denial audit row, best effort.
pub async fn console_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before = json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": permission
    })
    .to_string();
    let env = envelope(user.user(), user.generation(), operation, &before);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(command("console.denied")),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// encoding/json output: HTML escapes applied, RawMessage fields compacted.
pub fn go_json(value: &Value) -> String {
    go_escape(&serde_json::to_string(value).unwrap_or_else(|_| "null".into())) + "\n"
}

pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn compact(text: &str) -> String {
    let (mut out, mut quoted, mut escaped) = (String::with_capacity(text.len()), false, false);
    for ch in text.chars() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            out.push(ch);
        } else if !ch.is_ascii_whitespace() {
            out.push(ch);
        }
    }
    out
}

/// Go's `redactConfigValue` + `configStringForResponse` for AD/LDAP rows.
fn config_text(key: &str, value: &str, encrypted: bool) -> String {
    if encrypted || key.ends_with("_enc") || key == "assist.api_key" {
        return "[ENCRYPTED]".into();
    }
    match serde_json::from_str::<Value>(value) {
        Ok(Value::String(text)) => text,
        Ok(Value::Null) => String::new(),
        _ => value.into(),
    }
}

/// Which directory's configuration or ledger a read serves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ad,
    Ldap,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Ad => "ad",
            Source::Ldap => "ldap",
        }
    }
}

pub async fn config(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    source: Source,
) -> Result<String, StatementFailure> {
    let contract = match source {
        Source::Ad => &sql::CONFIG_AD,
        Source::Ldap => &sql::CONFIG_LDAP,
    };
    let rows = factory
        .run_admin_read_contract(admin, contract, &[])
        .await?;
    let mut out = Map::new();
    for row in rows {
        let key: String = row.try_get(0).map_err(|_| invalid())?;
        let value: String = row.try_get(1).map_err(|_| invalid())?;
        let encrypted: bool = row.try_get(2).map_err(|_| invalid())?;
        let text = config_text(&key, &value, encrypted);
        out.insert(key, Value::String(text));
    }
    Ok(go_json(&Value::Object(out)))
}

pub async fn sync_log(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    source: Source,
    domain_scope: i64,
    limit: i64,
) -> Result<String, StatementFailure> {
    if domain_scope != 0 {
        return Ok("[]\n".into());
    }
    let source = source.name();
    let rows = factory
        .run_admin_read_contract(admin, &sql::SYNC_LOG, &[&source, &limit])
        .await?;
    let mut out = Vec::new();
    for row in rows {
        let int = |i: usize| row.try_get::<_, i32>(i).map_err(|_| invalid());
        let details: String = row.try_get(9).map_err(|_| invalid())?;
        let mut item = Map::new();
        item.insert(
            "source".into(),
            json!(row.try_get::<_, String>(0).map_err(|_| invalid())?),
        );
        item.insert("checked".into(), json!(int(1)?));
        item.insert("created".into(), json!(int(2)?));
        item.insert("updated".into(), json!(int(3)?));
        item.insert("disabled".into(), json!(int(4)?));
        item.insert("skipped".into(), json!(int(5)?));
        item.insert("errors".into(), json!(int(6)?));
        item.insert("durationSeconds".into(), json!(int(7)? / 1000));
        item.insert(
            "syncedAt".into(),
            json!(row.try_get::<_, String>(8).map_err(|_| invalid())?),
        );
        item.insert("details".into(), json!("\u{0}details"));
        let text = serde_json::to_string(&Value::Object(item)).map_err(|_| invalid())?;
        out.push(text.replace("\"\\u0000details\"", &compact(&details)));
    }
    Ok(go_escape(&format!("[{}]", out.join(","))) + "\n")
}

/// Test-only (feature `oracle-mutants`, mutant `dirsync-conflicts-unscoped`).
fn conflicts_unscoped() -> bool {
    setjoin_contracts::mutants::on("dirsync-conflicts-unscoped")
}

/// Owner-approved security fix 2026-11-05 (#510): only the conflicts of users the caller reaches.
pub async fn conflicts(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let actor_id = admin.actor().get();
    let unscoped = conflicts_unscoped();
    let rows = factory
        .run_admin_read_contract(admin, &sql::CONFLICTS_LIST, &[&actor_id, &unscoped])
        .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(json!({
            "id": row.try_get::<_, i64>(0).map_err(|_| invalid())?,
            "userId": row.try_get::<_, i64>(1).map_err(|_| invalid())?,
            "email": row.try_get::<_, String>(2).map_err(|_| invalid())?,
            "field": row.try_get::<_, String>(3).map_err(|_| invalid())?,
            "localValue": row.try_get::<_, String>(4).map_err(|_| invalid())?,
            "remoteValue": row.try_get::<_, String>(5).map_err(|_| invalid())?,
            "detectedAt": row.try_get::<_, String>(6).map_err(|_| invalid())?,
        }));
    }
    Ok(go_json(&Value::Array(items)))
}

pub fn resolution(wire: &str) -> Option<&'static str> {
    match wire {
        "keep_local" => Some("kept_local"),
        "accept_remote" => Some("accepted_remote"),
        _ => None,
    }
}

fn count(rows: &[setjoin_pg::Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Go's one UPDATE; the number of rows decides 204 or 404 at the edge.
pub async fn resolve_conflict(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    id: i64,
    resolution: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor_id = admin.actor().get();
    let unscoped = conflicts_unscoped();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{id}:{resolution}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONFLICT_RESOLVE_ONE,
            &[&actor_id, &id, &resolution, &unscoped],
            Some(command("ad_conflict_resolve")),
            |rows| count(&rows),
        )
        .await
}

pub async fn resolve_all(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    resolution: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor_id = admin.actor().get();
    let unscoped = conflicts_unscoped();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("all:{resolution}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONFLICT_RESOLVE_ALL,
            &[&actor_id, &resolution, &unscoped],
            Some(command("ad_conflict_resolve_all")),
            |rows| count(&rows),
        )
        .await
}

/// Owner-approved security fix 2026-11-05 (#376).
pub async fn field_policy(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    user: i64,
) -> Result<String, StatementFailure> {
    let actor_id = admin.actor().get();
    let contract = if setjoin_contracts::mutants::on("fieldpolicy-get-foreign") {
        &sql::FIELD_POLICY_GET_FOREIGN
    } else if setjoin_contracts::mutants::on("fieldpolicy-any-grant") {
        &sql::FIELD_POLICY_GET_ANY_GRANT
    } else {
        &sql::FIELD_POLICY_GET_PERM
    };
    let rows = factory
        .run_admin_read_contract(admin, contract, &[&user, &actor_id])
        .await?;
    let mut out = Map::new();
    for row in rows {
        let field: String = row.try_get(0).map_err(|_| invalid())?;
        let policy: String = row.try_get(1).map_err(|_| invalid())?;
        out.insert(field, Value::String(policy));
    }
    Ok(go_json(&Value::Object(out)))
}

/// Go's pre-check `admin_can_reach(actor, target)`.
pub async fn reach(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
) -> Result<bool, StatementFailure> {
    let actor_id = admin.actor().get();
    let rows = factory
        .run_admin_read_contract(admin, &sql::ADMIN_CAN_REACH, &[&actor_id, &target])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// `reach` through the route's own permission (#529).
pub async fn reach_perm(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
    perms: &[&str],
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on("fieldpolicy-any-grant") {
        return reach(factory, admin, target).await;
    }
    let actor_id = admin.actor().get();
    let perms: Vec<String> = perms.iter().map(|p| (*p).to_owned()).collect();
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::ADMIN_CAN_REACH_PERM,
            &[&actor_id, &target, &perms],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

pub async fn set_field_policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    target: i64,
    field: &str,
    policy: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor_id = admin.actor().get();
    let managed = policy == "ad_managed";
    let any_grant = setjoin_contracts::mutants::on("fieldpolicy-any-grant");
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{target}:{field}:{policy}"),
    );
    if managed {
        factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &sql::FIELD_POLICY_DELETE,
                &[&actor_id, &target, &field, &any_grant],
                Some(command("ad_field_policy_clear")),
                |rows| count(&rows),
            )
            .await
    } else {
        factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &sql::FIELD_POLICY_UPSERT,
                &[&actor_id, &target, &field, &policy, &any_grant],
                Some(command("ad_field_policy_set")),
                |rows| count(&rows),
            )
            .await
    }
}

/// `Some(None)` is an existing user with no principal; `None` is no user.
pub async fn principal_current(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    user: i64,
) -> Result<Option<Option<String>>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::PRINCIPAL_CURRENT, &[&user])
        .await?;
    rows.first()
        .map(|r| r.try_get::<_, Option<String>>(0).map_err(|_| invalid()))
        .transpose()
}

/// Go's `ad_principal_set` reducer via `AdminWriteTx` (`ReducerWritesCoreAudit`).
pub async fn set_principal(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
    new_principal: &str,
    old_principal: Option<&str>,
    ip: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{target}:{new_principal}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::PRINCIPAL_SET,
            &[&target, &new_principal, &old_principal, &ip],
            Some(command("ad_principal_set")),
            |rows, _audited| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}
