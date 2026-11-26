//! Standalone operator DLQ helpers for `setjoin-mailctl` (`feature = "operator"`).

use setjoin_pg::{operator::OperatorConnection, Type};

use crate::{parse_dead_letter_row, DeadLetter, WorkQueueStats};

const DLQ_LIST_SQL: &str = "SELECT id, work_item_id, kind, payload::text, idempotency_key, \
     priority, attempts, max_attempts, last_error, failed_by, \
     to_char(enqueued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
     to_char(dead_lettered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
     CASE WHEN replayed_at IS NOT NULL THEN to_char(replayed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') ELSE NULL END, \
     replayed_work_item_id \
     FROM public.work_queue_dlq_list($1, $2, $3, $4)";

const DLQ_INSPECT_SQL: &str = "SELECT id, work_item_id, kind, payload::text, idempotency_key, \
     priority, attempts, max_attempts, last_error, failed_by, \
     to_char(enqueued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
     to_char(dead_lettered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
     CASE WHEN replayed_at IS NOT NULL THEN to_char(replayed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') ELSE NULL END, \
     replayed_work_item_id \
     FROM public.work_queue_dlq_inspect($1)";

const DLQ_REPLAY_SQL: &str =
    "SELECT dlq_id, work_item_id FROM public.work_queue_dlq_replay($1, $2, $3)";

const DLQ_PURGE_SQL: &str = "SELECT public.work_queue_dlq_purge($1, $2, $3, $4)";

const STATS_SQL: &str =
    "SELECT pending, leased, dead_letters, oldest_due_age_secs FROM public.work_queue_stats()";

/// List dead-lettered items (limit clamped to `1..=500`, offset `>= 0`).
pub async fn dlq_list(
    conn: &OperatorConnection,
    kind: Option<&str>,
    include_replayed: bool,
    limit: i32,
    offset: i32,
) -> Result<Vec<DeadLetter>, String> {
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);
    let kind_opt = kind.filter(|s| !s.is_empty());
    let rows = conn
        .query(
            DLQ_LIST_SQL,
            &[
                (&kind_opt, Type::TEXT),
                (&include_replayed, Type::BOOL),
                (&limit, Type::INT4),
                (&offset, Type::INT4),
            ],
        )
        .await?;
    rows.iter().map(parse_dead_letter_row).collect()
}

/// Inspect a single dead-lettered item by ID.
pub async fn dlq_inspect(conn: &OperatorConnection, id: i64) -> Result<Option<DeadLetter>, String> {
    let rows = conn.query(DLQ_INSPECT_SQL, &[(&id, Type::INT8)]).await?;
    rows.first().map(parse_dead_letter_row).transpose()
}

/// Replay a single dead-lettered item inside one transaction.
pub async fn dlq_replay_one(
    conn: &OperatorConnection,
    id: i64,
    reset_idempotency: bool,
    force: bool,
) -> Result<(i64, i64), String> {
    conn.batch("BEGIN").await?;
    let result = conn
        .query(
            DLQ_REPLAY_SQL,
            &[
                (&id, Type::INT8),
                (&reset_idempotency, Type::BOOL),
                (&force, Type::BOOL),
            ],
        )
        .await;
    match result {
        Ok(rows) => {
            let parsed = rows
                .first()
                .ok_or_else(|| "work_queue_dlq_replay returned no rows".to_owned())
                .and_then(|row| {
                    Ok((
                        row.try_get::<_, i64>(0).map_err(|e| e.to_string())?,
                        row.try_get::<_, i64>(1).map_err(|e| e.to_string())?,
                    ))
                });
            match parsed {
                Ok(pair) => {
                    conn.batch("COMMIT").await?;
                    Ok(pair)
                }
                Err(err) => {
                    let _ = conn.batch("ROLLBACK").await;
                    Err(err)
                }
            }
        }
        Err(err) => {
            let _ = conn.batch("ROLLBACK").await;
            Err(err)
        }
    }
}

/// Replay up to `limit` un-replayed dead-lettered items (optionally filtered by kind)
/// inside one atomic transaction with `FOR UPDATE` row locking.
pub async fn dlq_replay_batch(
    conn: &OperatorConnection,
    kind: Option<&str>,
    limit: i32,
    reset_idempotency: bool,
    force: bool,
) -> Result<Vec<(i64, i64)>, String> {
    let limit = limit.clamp(1, 500);
    let kind_opt = kind.filter(|s| !s.is_empty());
    conn.batch("BEGIN").await?;
    let ids_res = conn
        .query(
            "SELECT id FROM public.work_dead_letters \
             WHERE ($1::text IS NULL OR kind = $1) \
               AND replayed_at IS NULL \
             ORDER BY id ASC \
             LIMIT $2 \
             FOR UPDATE",
            &[(&kind_opt, Type::TEXT), (&i64::from(limit), Type::INT8)],
        )
        .await;
    let ids: Vec<i64> = match ids_res.and_then(|rows| {
        rows.iter()
            .map(|r| r.try_get::<_, i64>(0).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()
    }) {
        Ok(ids) => ids,
        Err(err) => {
            let _ = conn.batch("ROLLBACK").await;
            return Err(err);
        }
    };
    let mut replayed = Vec::with_capacity(ids.len());
    for id in ids {
        match conn
            .query(
                DLQ_REPLAY_SQL,
                &[
                    (&id, Type::INT8),
                    (&reset_idempotency, Type::BOOL),
                    (&force, Type::BOOL),
                ],
            )
            .await
        {
            Ok(rows) => {
                let parsed = rows
                    .first()
                    .ok_or_else(|| "work_queue_dlq_replay returned no rows".to_owned())
                    .and_then(|row| {
                        Ok((
                            row.try_get::<_, i64>(0).map_err(|e| e.to_string())?,
                            row.try_get::<_, i64>(1).map_err(|e| e.to_string())?,
                        ))
                    });
                match parsed {
                    Ok(pair) => replayed.push(pair),
                    Err(err) => {
                        let _ = conn.batch("ROLLBACK").await;
                        return Err(err);
                    }
                }
            }
            Err(err) => {
                let _ = conn.batch("ROLLBACK").await;
                return Err(err);
            }
        }
    }
    conn.batch("COMMIT").await?;
    Ok(replayed)
}

/// Purge dead-lettered items by ID, kind, and/or age.
pub async fn dlq_purge(
    conn: &OperatorConnection,
    id: Option<i64>,
    kind: Option<&str>,
    older_than_days: Option<i32>,
    replayed_only: bool,
) -> Result<i32, String> {
    let kind_opt = kind.filter(|s| !s.is_empty());
    let rows = conn
        .query(
            DLQ_PURGE_SQL,
            &[
                (&id, Type::INT8),
                (&kind_opt, Type::TEXT),
                (&older_than_days, Type::INT4),
                (&replayed_only, Type::BOOL),
            ],
        )
        .await?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, i32>(0).ok())
        .unwrap_or(0))
}

/// Fetch scalar queue statistics.
pub async fn stats(conn: &OperatorConnection) -> Result<WorkQueueStats, String> {
    let rows = conn.query(STATS_SQL, &[]).await?;
    let row = rows
        .first()
        .ok_or_else(|| "work_queue_stats returned no rows".to_owned())?;
    Ok(WorkQueueStats {
        pending: row.try_get(0).map_err(|e| e.to_string())?,
        leased: row.try_get(1).map_err(|e| e.to_string())?,
        dead_letters: row.try_get(2).map_err(|e| e.to_string())?,
        oldest_due_age_secs: row.try_get(3).map_err(|e| e.to_string())?,
    })
}
