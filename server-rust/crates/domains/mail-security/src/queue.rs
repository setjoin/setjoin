//! Slice `queue` (#321): Go's `admin.QueueHandler` (`Summary`, `List`, `ForceRetry`,
//! `Bounce`). The queue is global (no tenant column); every route is behind the admin
//! console gate the adapter checks (`requireMailPerm` for reads, `requireQueueWrite` for the
//! two writes). Retry and bounce are Go's single UPDATE each, called through a reducer so
//! the DSN trigger and the immutable-status guard run in the same statement as in Go.
use super::{command, deadline, envelope, invalid, nano, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};

/// `GET /admin/queue/summary`: sorted-key map; any query error is Go's 500.
pub async fn summary(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT COUNT(*) FILTER (WHERE status = 'pending')::bigint, \
             COUNT(*) FILTER (WHERE status = 'deferred')::bigint, \
             COUNT(*) FILTER (WHERE status = 'bounced' AND delivered_at > now() - interval '24 hours')::bigint, \
             COUNT(*) FILTER (WHERE attempt_count >= 10 AND status IN ('deferred','pending'))::bigint, \
             COALESCE(EXTRACT(EPOCH FROM (now() - MIN(queued_at) FILTER (WHERE status IN ('pending','deferred'))))/60, 0)::float8 \
             FROM outbound_queue",
            &[],
        )
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

/// Go's `mapQueueStatus`: the WHERE clause and whether the tab value binds as `$1`.
fn status_clause(tab: &str) -> (&'static str, bool) {
    match tab {
        "" | "all" => ("", false),
        "failed" => ("status = 'bounced'", false),
        "held" => (
            "attempt_count >= 10 AND status IN ('deferred','pending')",
            false,
        ),
        _ => ("status = $1", true),
    }
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
    worker: &ScopedExecutor,
    status: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let (clause, bind) = status_clause(status);
    let select = format!(
        "SELECT id, message_id, from_addr, status, rcpt_addrs, attempt_count, {} , last_error, {}, mailbox_id \
         FROM outbound_queue",
        nano("next_attempt_at"),
        nano("queued_at")
    );
    // Column order above: 0 id, 1 message_id, 2 from_addr, 3 status, 4 rcpt_addrs,
    // 5 attempt_count, 6 next_attempt_at, 7 last_error, 8 queued_at, 9 mailbox_id.
    let rows = match (clause.is_empty(), bind) {
        (true, _) => {
            worker
                .read_iterated(
                    &format!("{select} ORDER BY queued_at DESC LIMIT $1 OFFSET $2"),
                    &[(&limit, Type::INT8), (&offset, Type::INT8)],
                )
                .await?
        }
        (false, true) => {
            worker
                .read_iterated(
                    &format!("{select} WHERE {clause} ORDER BY queued_at DESC LIMIT $2 OFFSET $3"),
                    &[
                        (&status, Type::TEXT),
                        (&limit, Type::INT8),
                        (&offset, Type::INT8),
                    ],
                )
                .await?
        }
        (false, false) => {
            worker
                .read_iterated(
                    &format!("{select} WHERE {clause} ORDER BY queued_at DESC LIMIT $1 OFFSET $2"),
                    &[(&limit, Type::INT8), (&offset, Type::INT8)],
                )
                .await?
        }
    };
    // Go skips a row whose Scan fails; every column here is scannable.
    let items = rows.iter().filter_map(|r| item(r).ok()).collect::<Vec<_>>();
    Ok(super::done(format!("[{}]", items.join(","))))
}

/// Retry (`bounce == false`) or bounce one queue item. `Committed(false)` is Go's 404.
pub async fn resolve(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    bounce: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let (name, sql) = if bounce {
        ("queue.bounce", "SELECT rust_mailsec_queue_bounce($4) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''")
    } else {
        ("queue.retry", "SELECT rust_mailsec_queue_retry($4) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''")
    };
    setjoin_pg::run_receipted_command(
        worker,
        command(name),
        &envelope(&auth, operation, &format!("{name}:{id}")),
        &auth,
        deadline(),
        sql,
        &[(&id, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, bool>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
