//! Slice `queue` (#321): Go's `admin.QueueHandler` (`Summary`, `List`, `ForceRetry`,
//! `Bounce`). The queue is global (no tenant column); every route is behind the admin
//! console gate the adapter checks (`requireMailPerm` for reads, `requireQueueWrite` for the
//! two writes). Reads run via `AdminReadTx`; retry and bounce use `QUEUE_RETRY`/`QUEUE_BOUNCE`
//! `WorkerBypass` contracts executed by the gateway composition root (because the bounce DSN
//! trigger inserts into FORCE-RLS `scheduled_actions` with `mailbox_id = NULL` and Go writes
//! no `admin_audit_log` row).
use super::{invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{Row, StatementFailure};

/// `GET /admin/queue/summary`: sorted-key map; any query error is Go's 500.
pub async fn summary(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::QUEUE_SUMMARY, &[])
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let n = |i: usize| row.try_get::<_, i64>(i).map_err(|_| invalid());
    let oldest = row.try_get::<_, f64>(4).map_err(|_| invalid())?;
    Ok(super::done(format!(
        "{{\"bouncedToday\":{},\"deferred\":{},\"oldestMinutes\":{},\"pending\":{},\"stuck\":{}}}",
        n(2)?,
        n(1)?,
        s(&format!("{oldest:.0} min")),
        n(0)?,
        n(3)?
    )))
}

fn item(row: &Row) -> Result<String, StatementFailure> {
    let bad = |_| invalid();
    let rcpts: Vec<String> = row.try_get(4).map_err(bad)?;
    let last: Option<String> = row.try_get(7).map_err(bad)?;
    let mailbox: Option<i64> = row.try_get(9).map_err(bad)?;
    Ok(format!(
        "{{\"attemptCount\":{},\"fromAddr\":{},\"id\":{},\"lastError\":{},\"mailboxId\":{},\"messageId\":{},\"nextAttemptAt\":{},\"queuedAt\":{},\"recipients\":[{}],\"status\":{}}}",
        row.try_get::<_, i32>(5).map_err(bad)?,
        s(&row.try_get::<_, String>(2).map_err(bad)?),
        row.try_get::<_, i64>(0).map_err(bad)?,
        s(last.as_deref().unwrap_or("")),
        mailbox.map_or("null".to_owned(), |m| m.to_string()),
        s(&row.try_get::<_, String>(1).map_err(bad)?),
        s(&row.try_get::<_, String>(6).map_err(bad)?),
        s(&row.try_get::<_, String>(8).map_err(bad)?),
        rcpts.iter().map(|r| s(r)).collect::<Vec<_>>().join(","),
        s(&row.try_get::<_, String>(3).map_err(bad)?),
    ))
}

/// `GET /admin/queue`: a JSON array (`[]` when empty). `limit` and `offset` are already
/// Go's `ParseLimitOffset(50, 200)` results.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    status: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = match status {
        "" | "all" => {
            tx.query_iterated_contract(&sql::QUEUE_LIST_ALL, &[&limit, &offset])
                .await?
        }
        "failed" => {
            tx.query_iterated_contract(&sql::QUEUE_LIST_FAILED, &[&limit, &offset])
                .await?
        }
        "held" => {
            tx.query_iterated_contract(&sql::QUEUE_LIST_HELD, &[&limit, &offset])
                .await?
        }
        _ => {
            tx.query_iterated_contract(&sql::QUEUE_LIST_STATUS, &[&status, &limit, &offset])
                .await?
        }
    };
    tx.finish().await?;
    // Go skips a row whose Scan fails; every column here is scannable.
    let items = rows.iter().filter_map(|r| item(r).ok()).collect::<Vec<_>>();
    Ok(super::done(format!("[{}]", items.join(","))))
}
