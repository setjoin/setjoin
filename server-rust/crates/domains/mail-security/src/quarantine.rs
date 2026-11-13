//! Slice `quarantine` (#320): Go's user `QuarantineHandler` and admin `QuarantineHandler`.
//!
//! Both list handlers scan `timestamptz` columns into Go strings, which pgx cannot do in
//! binary format, so every row fails its `Scan` and is skipped: frozen Go always answers
//! `{"items":null}` when the query itself runs (parity, not an accepted divergence). The
//! query still runs so a database error keeps Go's 500, and the deferred-row-error seam
//! (`read_iterated`) keeps Go's `Rows.Err` blindness.
//!
//! Release and reject are Go's UPDATE (ownership in its WHERE) followed by a second
//! transaction for the tag rewrite or message delete. They call one reducer each
//! (`rust_mailsec_quarantine_release|reject`) so the data change, tag restore and push are
//! atomic; Go commits the UPDATE before the rewrite, so a failing rewrite leaves Go's row
//! released while the reducer rolls everything back (a reviewed divergence that no recorded
//! case can reach: the rewrite cannot fail for a row the UPDATE just matched).
use super::{command, deadline, done, envelope, invalid, s, scope, MAIL_CONSOLE, MAIL_EXPORT};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};

/// Owner-approved security fix 2026-11-05 (#448): frozen Go's admin list, stats and preview
/// had no per-domain filter. The caller's grants carrying one of `perms` must reach the owner
/// of the quarantined mailbox (`admin_can_reach_perm`; domain from the stored mailbox row,
/// OU and scope-set narrowing included; an organization-wide grant reaches everyone), so a
/// domain-scoped admin sees and previews only its own domain's mail and a foreign row
/// answers like a missing one. Release and reject carry the same rule inside their
/// reducer's UPDATE. The restored-bug mutant (`quarantine-admin-unscoped`, test builds
/// only) drops the predicate as frozen Go did.
fn reach(actor: &str, perms: &[&str]) -> String {
    if setjoin_contracts::mutants::on("quarantine-admin-unscoped") {
        return "true".into();
    }
    let list: Vec<String> = perms.iter().map(|p| format!("'{p}'")).collect();
    format!(
        "admin_can_reach_perm({actor}, (SELECT mb.user_id FROM mailboxes mb WHERE mb.id = qm.mailbox_id), ARRAY[{}])",
        list.join(",")
    )
}

/// `GET /quarantine`: `{"items":null}` after Go's per-row scan failures.
pub async fn user_list(
    worker: &ScopedExecutor,
    user: i64,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    worker
        .read_iterated(
            "SELECT qm.id, qm.message_id, m.subject, m.from_addr, \
             qm.reason, qm.virus_name, qm.preview_token, qm.quarantined_at, \
             qm.released_at, qm.rejected_at, m.size_bytes \
             FROM quarantined_messages qm \
             JOIN messages m ON m.id = qm.message_id \
             JOIN mailboxes mb ON mb.id = qm.mailbox_id \
             WHERE mb.user_id = $1 \
             ORDER BY qm.quarantined_at DESC LIMIT $2 OFFSET $3",
            &[
                (&user, Type::INT8),
                (&limit, Type::INT8),
                (&offset, Type::INT8),
            ],
        )
        .await?;
    Ok(done("{\"items\":null}".into()))
}

/// `GET /quarantine/count`: Go ignores the scan error, so a failed read counts 0.
pub async fn user_count(exec: &ScopedExecutor, user: i64) -> String {
    let count = match exec
        .read(
            "SELECT COUNT(*)::bigint FROM quarantined_messages qm \
             JOIN mailboxes mb ON mb.id = qm.mailbox_id \
             WHERE mb.user_id = $1 AND qm.released_at IS NULL AND qm.rejected_at IS NULL",
            &[(&user, Type::INT8)],
        )
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
    worker: &ScopedExecutor,
    actor: &AuthContext,
    status: &str,
    q: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let mut filter = match status {
        "released" => "qm.released_at IS NOT NULL",
        "rejected" => "qm.rejected_at IS NOT NULL",
        "active" => "qm.released_at IS NULL AND qm.rejected_at IS NULL",
        _ => "1=1",
    }
    .to_owned();
    let pattern = format!("%{q}%");
    let user = actor.user_id();
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![(&user, Type::INT8)];
    let mut next = 1;
    filter.push_str(&format!(" AND {}", reach("$1::bigint", &MAIL_CONSOLE)));
    if !q.is_empty() {
        next += 1;
        filter.push_str(&format!(
            " AND (m.from_addr ILIKE ${next} OR m.subject ILIKE ${next})"
        ));
        params.push((&pattern, Type::TEXT));
    }
    let sql = format!(
        "SELECT qm.id, qm.message_id, qm.mailbox_id, m.subject, m.from_addr, \
         qm.original_tag, qm.reason, qm.reason_type, qm.virus_name, qm.preview_token, \
         qm.quarantined_at, qm.released_at, qm.released_by, qm.rejected_at, qm.rejected_by, \
         m.size_bytes, mb.email as recipient \
         FROM quarantined_messages qm \
         JOIN messages m ON m.id = qm.message_id \
         JOIN mailboxes mb ON mb.id = qm.mailbox_id \
         WHERE {filter} ORDER BY qm.quarantined_at DESC LIMIT ${} OFFSET ${}",
        next + 1,
        next + 2
    );
    params.push((&limit, Type::INT8));
    params.push((&offset, Type::INT8));
    worker.read_iterated(&sql, &params).await?;
    Ok(done("{\"items\":null}".into()))
}

/// `GET /admin/quarantine/stats`: sorted-key map; Go ignores each scan error (0).
pub async fn admin_stats(worker: &ScopedExecutor, actor: &AuthContext) -> String {
    let user = actor.user_id();
    let count = |sql: &'static str| async move {
        let sql = format!(
            "{sql} AND {}",
            reach("$1::bigint", &MAIL_CONSOLE)
        );
        match worker.read(&sql, &[(&user, Type::INT8)]).await {
            Ok(rows) => rows
                .first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .unwrap_or(0),
            Err(_) => 0,
        }
    };
    let active = count("SELECT COUNT(*)::bigint FROM quarantined_messages qm WHERE released_at IS NULL AND rejected_at IS NULL").await;
    let released =
        count("SELECT COUNT(*)::bigint FROM quarantined_messages qm WHERE released_at IS NOT NULL")
            .await;
    let rejected =
        count("SELECT COUNT(*)::bigint FROM quarantined_messages qm WHERE rejected_at IS NOT NULL")
            .await;
    done(format!(
        "{{\"active\":{active},\"rejected\":{rejected},\"released\":{released}}}"
    ))
}

/// `GET /admin/quarantine/{id}/preview`: `None` is Go's 404 (no row or any read error).
pub async fn admin_preview(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = actor.user_id();
    let sql = format!(
        "SELECT COALESCE(m.body_html,''), COALESCE(m.subject,''), COALESCE(m.from_addr,''), \
         to_char(qm.quarantined_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM quarantined_messages qm JOIN messages m ON m.id = qm.message_id \
         WHERE qm.id = $1 AND {}",
        reach("$2::bigint", &MAIL_EXPORT)
    );
    let rows = match worker
        .read(&sql, &[(&id, Type::INT8), (&user, Type::INT8)])
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

fn first_bool(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// Release (`reject == false`) or reject one quarantined message. `admin` lifts the owner
/// predicate (org-wide console gate, checked by the caller); otherwise the row must sit in
/// one of the verified user's own mailboxes, in the same WHERE as the UPDATE (R3).
/// `Committed(false)` is Go's "not found or already processed".
pub async fn resolve(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    admin: bool,
    reject: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let user = actor.user_id();
    let (name, sql) = if reject {
        ("quarantine.reject", "SELECT rust_mailsec_quarantine_reject($4,$5,$6) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''")
    } else {
        ("quarantine.release", "SELECT rust_mailsec_quarantine_release($4,$5,$6) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''")
    };
    setjoin_pg::run_receipted_command(
        worker,
        command(name),
        &envelope(&auth, operation, &format!("{name}:{id}:{admin}")),
        &auth,
        deadline(),
        sql,
        &[(&user, Type::INT8), (&id, Type::INT8), (&admin, Type::BOOL)],
        first_bool,
    )
    .await
}

/// Go's three one-key status documents.
pub fn status_body(status: &str) -> String {
    done(format!("{{\"status\":{}}}", s(status)))
}
