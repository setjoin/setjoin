//! Rules and templates (F09). Frozen Go is authoritative; see DOX.md.
#![forbid(unsafe_code)]
pub mod authority;
pub mod input;
pub mod sql;
pub mod templates;
pub use sql::SQL_CONTRACTS;

use setjoin_authz::principals::{
    AdminPermissionProof, MutateCapability, ReadCapability, TxFactory, UserPrincipal,
};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure, ToSql};
use setjoin_sql_catalog::SqlContract;
use sha2::{Digest as _, Sha256};

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

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn rule(r: &Row) -> Result<String, StatementFailure> {
    let id: i64 = r.try_get(0).map_err(|_| invalid())?;
    let mb: Option<i64> = r.try_get(1).map_err(|_| invalid())?;
    let mailbox = mb
        .map(|m| format!(",\"mailboxId\":{m}"))
        .unwrap_or_default();
    Ok(format!(
        "{{\"id\":{id}{mailbox},\"name\":{},\"enabled\":{},\"priority\":{},\"runOn\":{},\"isTransportRule\":{},\"conditions\":{},\"actions\":{},\"stopProcessing\":{},\"createdAt\":{},\"updatedAt\":{}}}",
        s(r.try_get(2).map_err(|_| invalid())?),
        r.try_get::<_, bool>(3).map_err(|_| invalid())?,
        r.try_get::<_, i32>(4).map_err(|_| invalid())?,
        s(r.try_get(5).map_err(|_| invalid())?),
        r.try_get::<_, bool>(6).map_err(|_| invalid())?,
        templates::raw(r.try_get(7).map_err(|_| invalid())?),
        templates::raw(r.try_get(8).map_err(|_| invalid())?),
        r.try_get::<_, bool>(9).map_err(|_| invalid())?,
        s(r.try_get(10).map_err(|_| invalid())?),
        s(r.try_get(11).map_err(|_| invalid())?)
    ))
}

/// Format rows produced by `sql::ADMIN_LIST_*` or `sql::PERSONAL_LIST` into Go wire JSON.
pub fn format_rules_json(rows: &[Row]) -> String {
    done(format!(
        "[{}]",
        rows.iter()
            .filter_map(|r| rule(r).ok())
            .collect::<Vec<_>>()
            .join(",")
    ))
}

fn mailbox_envelope(
    mutate: &MutateCapability,
    op: [u8; 16],
    name: &'static str,
    digest_input: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(op),
        authority: AuthorityKey {
            actor: mutate.actor(),
            scope: ResourceScope::Mailbox(mutate.mailbox()),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{name}:{digest_input}").as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn user_envelope(
    user: &UserPrincipal,
    op: [u8; 16],
    name: &'static str,
    digest_input: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(op),
        authority: AuthorityKey {
            actor: user.user(),
            scope: ResourceScope::User(user.user()),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{name}:{digest_input}").as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn admin_envelope(
    proof: &AdminPermissionProof,
    op: [u8; 16],
    name: &'static str,
    digest_input: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(op),
        authority: AuthorityKey {
            actor: proof.actor(),
            scope: ResourceScope::User(proof.actor()),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{name}:{digest_input}").as_bytes()).into()),
        command: (),
    }
}

fn project_text0(rows: Vec<Row>) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

pub async fn personal_list(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let mut tx = tx_factory.begin_user_read(user).await?;
    let rows = tx
        .query_iterated_contract(&sql::PERSONAL_LIST, &[&uid])
        .await?;
    tx.finish().await?;
    Ok(format_rules_json(&rows))
}

pub async fn personal_count(
    tx_factory: &TxFactory,
    read: &ReadCapability,
) -> Result<i64, StatementFailure> {
    let mb = read.mailbox().get();
    tx_factory
        .run_mailbox_read_contract(read, &sql::PERSONAL_COUNT, &[&mb])
        .await?
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

pub const PERSONAL_RULE_CAP: i64 = 100;
pub const ACTIVE_SWEEP_CAP: i64 = 3;

#[allow(clippy::too_many_arguments)]
async fn write_capped(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    op: [u8; 16],
    name: &'static str,
    count_contract: &'static SqlContract,
    cap: i64,
    write_contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    digest_input: &str,
) -> CommandOutcome<String, StatementFailure> {
    let mb = mutate.mailbox().get();
    let envelope = mailbox_envelope(mutate, op, name, digest_input);
    tx_factory
        .run_mailbox_locked_tx(mutate, &envelope, deadline(), async move |tx| {
            tx.query_contract(&sql::LOCK_MAILBOX, &[&mb]).await?;
            let counted = tx.query_contract(count_contract, &[&mb]).await?;
            let n: i64 = counted
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?;
            let value = if n >= cap {
                "cap".to_owned()
            } else {
                let rows = tx.query_contract(write_contract, values).await?;
                project_text0(rows)?
            };
            tx.record_receipt(
                OperationId(op),
                ReceiptCommand {
                    family: "F09",
                    command: name,
                },
            )
            .await?;
            Ok(value)
        })
        .await
}

/// `Committed("cap")` means the mailbox is at its personal-rule cap and nothing was
/// written. Owner-approved security fix 2026-11-05 (#484): the cap is enforced in the
/// database under a mailbox row lock (Go counted in a separate, unlocked statement).
pub async fn personal_create(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let cap = if setjoin_contracts::mutants::on("rules-cap-count-then-insert") {
        i64::MAX
    } else {
        PERSONAL_RULE_CAP
    };
    let mb = mutate.mailbox().get();
    let digest = format!(
        "{mb}:{}:{}:{}:{}:{:?}:{:?}:{}",
        r.name, r.enabled, r.priority, r.run_on, r.conditions.0, r.actions.0, r.stop
    );
    write_capped(
        tx_factory,
        mutate,
        op,
        "personal.create",
        &sql::PERSONAL_COUNT,
        cap,
        &sql::PERSONAL_CREATE,
        &[
            &mb,
            &r.name,
            &r.enabled,
            &r.priority,
            &r.run_on,
            &r.conditions.0,
            &r.actions.0,
            &r.stop,
        ],
        &digest,
    )
    .await
}

pub async fn personal_update(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    id: i64,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = mutate.actor().get();
    let digest = format!(
        "{id}:{uid}:{}:{}:{}:{}:{:?}:{:?}:{}",
        r.name, r.enabled, r.priority, r.run_on, r.conditions.0, r.actions.0, r.stop
    );
    let envelope = mailbox_envelope(mutate, op, "personal.update", &digest);
    tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            &envelope,
            deadline(),
            &sql::PERSONAL_UPDATE,
            &[
                &id,
                &uid,
                &r.name,
                &r.enabled,
                &r.priority,
                &r.run_on,
                &r.conditions.0,
                &r.actions.0,
                &r.stop,
            ],
            Some(ReceiptCommand {
                family: "F09",
                command: "personal.update",
            }),
            project_text0,
        )
        .await
}

pub async fn personal_delete(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    id: i64,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = mutate.actor().get();
    let envelope = mailbox_envelope(mutate, op, "personal.delete", &format!("{id}:{uid}"));
    tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            &envelope,
            deadline(),
            &sql::PERSONAL_DELETE,
            &[&id, &uid],
            Some(ReceiptCommand {
                family: "F09",
                command: "personal.delete",
            }),
            project_text0,
        )
        .await
}

pub async fn active_sweeps(
    tx_factory: &TxFactory,
    read: &ReadCapability,
) -> Result<i64, StatementFailure> {
    let mb = read.mailbox().get();
    tx_factory
        .run_mailbox_read_contract(read, &sql::ACTIVE_SWEEPS, &[&mb])
        .await?
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// `Committed("cap")` means the mailbox already has [`ACTIVE_SWEEP_CAP`] sweeps in
/// progress and nothing was enqueued (security fix 2026-11-05, #484: counted under the
/// mailbox row lock in the same transaction as the enqueue).
pub async fn apply(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    id: i64,
    window: &str,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let cap = if setjoin_contracts::mutants::on("rules-cap-count-then-insert") {
        i64::MAX
    } else {
        ACTIVE_SWEEP_CAP
    };
    let mb = mutate.mailbox().get();
    write_capped(
        tx_factory,
        mutate,
        op,
        "personal.apply",
        &sql::ACTIVE_SWEEPS,
        cap,
        &sql::APPLY_RETROACTIVE,
        &[&mb, &id, &window],
        &format!("{mb}:{id}:{window}"),
    )
    .await
}

pub async fn apply_status(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: &str,
) -> Result<Option<String>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::APPLY_STATUS, &[&id, &uid])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let mut out =
        serde_json::json!({"status": row.try_get::<_, String>(0).map_err(|_| invalid())?});
    if let Some(v) = row.try_get::<_, Option<i64>>(1).map_err(|_| invalid())? {
        out["processed"] = serde_json::json!(v)
    }
    if let Some(v) = row.try_get::<_, Option<bool>>(2).map_err(|_| invalid())? {
        out["truncated"] = serde_json::json!(v)
    }
    Ok(Some(done(out.to_string())))
}

pub async fn admin_list(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    mailbox: Option<i64>,
) -> Result<String, StatementFailure> {
    let mut tx = tx_factory.begin_admin_read(proof).await?;
    let rows = if let Some(mb) = mailbox {
        tx.query_iterated_contract(&sql::ADMIN_LIST_BY_MAILBOX, &[&mb])
            .await?
    } else {
        tx.query_iterated_contract(&sql::ADMIN_LIST_ALL, &[])
            .await?
    };
    tx.finish().await?;
    Ok(format_rules_json(&rows))
}

pub async fn admin_get(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = tx_factory
        .run_admin_read_contract(proof, &sql::ADMIN_GET, &[&id])
        .await?;
    rows.first().map(|r| rule(r).map(done)).transpose()
}

pub async fn mailbox_exists(tx_factory: &TxFactory, proof: &AdminPermissionProof, id: i64) -> bool {
    tx_factory
        .run_admin_read_contract(proof, &sql::MAILBOX_EXISTS, &[&id])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

pub async fn admin_create(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let digest = format!(
        "{:?}:{}:{}:{}:{}:{}:{:?}:{:?}:{}",
        r.mailbox_id,
        r.name,
        r.enabled,
        r.priority,
        r.run_on,
        r.transport,
        r.conditions.0,
        r.actions.0,
        r.stop
    );
    let envelope = admin_envelope(proof, op, "admin.create", &digest);
    tx_factory
        .run_admin_audited_reducer_contract(
            proof,
            &envelope,
            deadline(),
            &sql::ADMIN_CREATE,
            &[
                &r.mailbox_id,
                &r.name,
                &r.enabled,
                &r.priority,
                &r.run_on,
                &r.transport,
                &r.conditions.0,
                &r.actions.0,
                &r.stop,
            ],
            Some(ReceiptCommand {
                family: "F09",
                command: "admin.create",
            }),
            |rows, _| project_text0(rows),
        )
        .await
}

pub async fn admin_update(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    r: &input::Rule,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let digest = format!(
        "{id}:{:?}:{}:{}:{}:{}:{}:{:?}:{:?}:{}",
        r.mailbox_id,
        r.name,
        r.enabled,
        r.priority,
        r.run_on,
        r.transport,
        r.conditions.0,
        r.actions.0,
        r.stop
    );
    let envelope = admin_envelope(proof, op, "admin.update", &digest);
    tx_factory
        .run_admin_audited_reducer_contract(
            proof,
            &envelope,
            deadline(),
            &sql::ADMIN_UPDATE,
            &[
                &id,
                &r.mailbox_id,
                &r.name,
                &r.enabled,
                &r.priority,
                &r.run_on,
                &r.transport,
                &r.conditions.0,
                &r.actions.0,
                &r.stop,
            ],
            Some(ReceiptCommand {
                family: "F09",
                command: "admin.update",
            }),
            |rows, _| project_text0(rows),
        )
        .await
}

pub async fn admin_delete(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    op: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let envelope = admin_envelope(proof, op, "admin.delete", &id.to_string());
    tx_factory
        .run_admin_audited_reducer_contract(
            proof,
            &envelope,
            deadline(),
            &sql::ADMIN_DELETE,
            &[&id],
            Some(ReceiptCommand {
                family: "F09",
                command: "admin.delete",
            }),
            |rows, _| project_text0(rows),
        )
        .await
}

/// Frozen Go's prepared SET LOCAL + SELECT batch always fails (42601) after
/// finding the rule. Keep the same request outcome; do not redesign its preview.
pub async fn admin_test(
    tx_factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<bool, StatementFailure> {
    let rows = tx_factory
        .run_admin_read_contract(proof, &sql::ADMIN_TEST_LOOKUP, &[&id])
        .await?;
    let Some(_row) = rows.first() else {
        return Ok(false);
    };
    Err(StatementFailure {
        sqlstate: Some("42601".into()),
        hint: None,
        message: "cannot insert multiple commands into a prepared statement".into(),
    })
}
