//! Slice `quarantine` (#320): Go's user `QuarantineHandler` and admin `QuarantineHandler`.
//!
//! Both list handlers scan `timestamptz` columns into Go strings, which pgx cannot do in
//! binary format, so every row fails its `Scan` and is skipped: frozen Go always answers
//! `{"items":null}` when the query itself runs (parity, not an accepted divergence). The
//! query still runs so a database error keeps Go's 500, and the deferred-row-error seam
//! (`query_iterated_contract`) keeps Go's `Rows.Err` blindness.
//!
//! User release and reject run via `MailboxTx` (`MutateCapability`); admin
//! release and reject use the `QUARANTINE_ADMIN_RELEASE|REJECT` `WorkerBypass` contracts
//! executed by the gateway composition root so cross-tenant FORCE RLS (`V287`) is satisfied
//! without writing an extra `admin_audit_log` row beyond frozen Go's contract.
use super::{command, deadline, done, invalid, mailbox_envelope, s, sql};
use setjoin_authz::principals::{
    AdminPermissionProof, MutateCapability, ReadCapability, TxFactory, UserPrincipal,
};
use setjoin_pg::{CommandOutcome, Row, StatementFailure};

fn unscoped_mutant() -> bool {
    setjoin_contracts::mutants::on("quarantine-admin-unscoped")
}

/// `GET /quarantine`: `{"items":null}` after Go's per-row scan failures.
pub async fn user_list(
    factory: &TxFactory,
    cap: &ReadCapability,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let user = cap.actor().get();
    let mut tx = factory.begin_mailbox_read(cap).await?;
    tx.query_iterated_contract(&sql::QUARANTINE_USER_LIST, &[&user, &limit, &offset])
        .await?;
    tx.finish().await?;
    Ok(done("{\"items\":null}".into()))
}

/// `GET /quarantine/count`: Go ignores the scan error, so a failed read counts 0.
pub async fn user_count(factory: &TxFactory, user: &UserPrincipal) -> String {
    let uid = user.user().get();
    let count = match factory
        .run_user_read_contract(user, &sql::QUARANTINE_USER_COUNT, &[&uid])
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .unwrap_or(0),
        Err(_) => 0,
    };
    done(format!("{{\"count\":{count}}}"))
}

/// Admin list filter: Go's `QuarantineStatus` switch and `ILIKE` over sender and subject.
pub async fn admin_list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    status: &str,
    q: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let user = admin.actor().get();
    let contract = if unscoped_mutant() {
        &sql::QUARANTINE_ADMIN_LIST_MUTANT
    } else {
        &sql::QUARANTINE_ADMIN_LIST
    };
    let mut tx = factory.begin_admin_read(admin).await?;
    tx.query_iterated_contract(contract, &[&user, &status, &q, &limit, &offset])
        .await?;
    tx.finish().await?;
    Ok(done("{\"items\":null}".into()))
}

/// `GET /admin/quarantine/stats`: sorted-key map; Go ignores each scan error (0).
pub async fn admin_stats(factory: &TxFactory, admin: &AdminPermissionProof) -> String {
    let user = admin.actor().get();
    let contract = if unscoped_mutant() {
        &sql::QUARANTINE_ADMIN_STATS_MUTANT
    } else {
        &sql::QUARANTINE_ADMIN_STATS
    };
    let count = |bucket: &'static str| async move {
        match factory
            .run_admin_read_contract(admin, contract, &[&user, &bucket])
            .await
        {
            Ok(rows) => rows
                .first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .unwrap_or(0),
            Err(_) => 0,
        }
    };
    let active = count("active").await;
    let released = count("released").await;
    let rejected = count("rejected").await;
    done(format!(
        "{{\"active\":{active},\"rejected\":{rejected},\"released\":{released}}}"
    ))
}

/// `GET /admin/quarantine/{id}/preview`: `None` is Go's 404 (no row or any read error).
pub async fn admin_preview(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = admin.actor().get();
    let contract = if unscoped_mutant() {
        &sql::QUARANTINE_ADMIN_PREVIEW_MUTANT
    } else {
        &sql::QUARANTINE_ADMIN_PREVIEW
    };
    let rows = match factory
        .run_admin_read_contract(admin, contract, &[&id, &user])
        .await
    {
        Ok(rows) => rows,
        Err(_) => return Ok(None),
    };
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let text = |i: usize| row.try_get::<_, String>(i).map_err(|_| invalid());
    Ok(Some(done(format!(
        "{{\"fromAddr\":{},\"html\":{},\"quarantinedAt\":{},\"subject\":{}}}",
        s(&text(2)?),
        s(&text(0)?),
        s(&text(3)?),
        s(&text(1)?)
    ))))
}

fn first_bool(rows: Vec<Row>) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// Release (`reject == false`) or reject one quarantined message owned by the caller's mailbox.
/// `Committed(false)` is Go's "not found or already processed".
pub async fn user_resolve(
    factory: &TxFactory,
    cap: &MutateCapability,
    id: i64,
    reject: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let user = cap.actor().get();
    let (name, contract) = if reject {
        ("quarantine.reject", &sql::QUARANTINE_USER_REJECT)
    } else {
        ("quarantine.release", &sql::QUARANTINE_USER_RELEASE)
    };
    let env = mailbox_envelope(
        cap.actor(),
        cap.mailbox(),
        operation,
        &format!("{name}:{id}:false"),
    );
    factory
        .run_mailbox_write_contract_pipelined(
            cap,
            &env,
            deadline(),
            contract,
            &[&user, &id],
            Some(command(name)),
            first_bool,
        )
        .await
}

/// Go's three one-key status documents.
pub fn status_body(status: &str) -> String {
    done(format!("{{\"status\":{}}}", s(status)))
}
