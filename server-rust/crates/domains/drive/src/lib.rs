//! F14 Drive and sharing. Identity is always the sealed verified principal.
#![forbid(unsafe_code)]
pub mod core;
pub mod part_b;
pub mod part_c;
pub mod sql;
pub mod watch;
pub use sql::SQL_CONTRACTS;

use serde_json::{json, Value};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, SqlContract, StatementFailure, ToSql};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};

pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

pub(crate) fn user_envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    digest_source: &[u8],
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(digest_source).into()),
        command: (),
    }
}

pub async fn feature_enabled(factory: &TxFactory, key: &str) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::FEATURE_ENABLED, &[&key])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

pub async fn feature_any_enabled(
    factory: &TxFactory,
    key: &str,
    alternate: Option<&str>,
) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::FEATURE_ANY_ENABLED, &[&key, &alternate])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

pub async fn denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    manage: bool,
    operation: [u8; 16],
) {
    let before = json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": if manage { "sharing.manage" } else { "sharing.read|sharing.manage" }
    })
    .to_string();
    let env = user_envelope(user.user(), user.generation(), operation, b"console.denied");
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SHARING_CONSOLE_DENIED,
            &[&before, &path],
            Some(ReceiptCommand {
                family: "F14",
                command: "console.denied",
            }),
            |_| Ok(()),
        )
        .await;
}

pub async fn reason_required(factory: &TxFactory, proof: &AdminPermissionProof) -> bool {
    factory
        .run_admin_read_contract(proof, &sql::SHARING_REASON_REQUIRED, &[])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let env = user_envelope(
        user.user(),
        user.generation(),
        operation,
        b"sensitive_action.reason_missing",
    );
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SHARING_REASON_MISSING,
            &[&actor, &ip],
            Some(ReceiptCommand {
                family: "F14",
                command: "sensitive_action.reason_missing",
            }),
            |_| Ok(()),
        )
        .await;
}

pub fn decode_json_rows(rows: &[Row]) -> Result<Value, StatementFailure> {
    rows.iter()
        .map(|row| {
            let raw = row.try_get::<_, String>(0).map_err(|_| StatementFailure {
                sqlstate: None,
                message: "invalid database JSON".into(),
                hint: None,
            })?;
            serde_json::from_str(&raw).map_err(|_| StatementFailure {
                sqlstate: None,
                message: "invalid database JSON".into(),
                hint: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

async fn admin_read_json(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
) -> Result<Value, StatementFailure> {
    let mut tx = factory.begin_admin_read(proof).await?;
    let rows = tx.query_iterated_contract(contract, values).await?;
    let _ = tx.finish().await;
    decode_json_rows(&rows)
}

pub async fn list_defaults(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<Value, StatementFailure> {
    let domain = proof.enforced_domain_scope().unwrap_or(0);
    admin_read_json(factory, proof, &sql::ADMIN_LIST_DEFAULTS, &[&domain]).await
}

pub async fn audit(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<Value, StatementFailure> {
    admin_read_json(
        factory,
        proof,
        &sql::ADMIN_SHARING_AUDIT,
        &[&user, &limit, &offset],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_default(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    owner_scope: &str,
    owner_ref: i64,
    audience: &str,
    audience_ref: i64,
    level: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(
        proof.actor(),
        proof.generation(),
        operation,
        b"sharing_default_set",
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::ADMIN_CREATE_DEFAULT,
            &[&owner_scope, &owner_ref, &audience, &audience_ref, &level],
            Some(ReceiptCommand {
                family: "F14",
                command: "sharing_default_set",
            }),
            |rows, _| {
                let id = rows
                    .first()
                    .and_then(|row| row.try_get::<_, i64>(0).ok())
                    .ok_or_else(|| StatementFailure {
                        sqlstate: Some("42501".into()),
                        message: "authority changed".into(),
                        hint: None,
                    })?;
                Ok(json!({ "id": id }))
            },
        )
        .await
}

pub async fn delete_default(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(
        proof.actor(),
        proof.generation(),
        operation,
        b"sharing_default_clear",
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::ADMIN_DELETE_DEFAULT,
            &[&id],
            Some(ReceiptCommand {
                family: "F14",
                command: "sharing_default_clear",
            }),
            |rows, _| {
                if rows.is_empty() {
                    return Err(StatementFailure {
                        sqlstate: Some("42501".into()),
                        message: "authority changed".into(),
                        hint: None,
                    });
                }
                Ok(Value::Null)
            },
        )
        .await
}

pub async fn oversight(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: i64,
) -> Result<Option<Value>, StatementFailure> {
    let domain = proof.enforced_domain_scope().unwrap_or(0);
    let rows = match factory
        .run_admin_read_contract(proof, &sql::ADMIN_OVERSIGHT_USER, &[&user, &domain])
        .await
    {
        Ok(rows) => rows,
        Err(_) => return Ok(None),
    };
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let delegates =
        admin_read_json(factory, proof, &sql::ADMIN_OVERSIGHT_DELEGATES, &[&user]).await?;
    let grants = admin_read_json(
        factory,
        proof,
        &sql::ADMIN_OVERSIGHT_CALENDAR_GRANTS,
        &[&user],
    )
    .await?;
    let defaults =
        admin_read_json(factory, proof, &sql::ADMIN_OVERSIGHT_DEFAULTS, &[&user]).await?;
    let email: String = row.try_get(0).map_err(|_| StatementFailure {
        sqlstate: None,
        message: "invalid oversight user email".into(),
        hint: None,
    })?;
    let display_name: String = row.try_get(1).map_err(|_| StatementFailure {
        sqlstate: None,
        message: "invalid oversight user display name".into(),
        hint: None,
    })?;
    Ok(Some(json!({
        "userId": user,
        "email": email,
        "displayName": display_name,
        "delegates": delegates,
        "calendarGrants": grants,
        "defaults": defaults
    })))
}
