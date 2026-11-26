//! Distributed `FOR UPDATE SKIP LOCKED` periodic schedule store (Wave 2.2, #549).
//!
//! Backed by `public.worker_schedules` (`V287`) and `SECURITY INVOKER`
//! `worker_schedule_*` reducers over a verified `WorkerPool` (`BYPASSRLS`).

use setjoin_pg::{Row, StatementFailure, Type, WorkerPool, WorkerTx};

use crate::{truncate_utf8_bytes, WorkQueueError, MAX_ERROR_BYTES};

/// Credential tier required to run a scheduled task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleCredential {
    Worker,
    Owner,
}

impl ScheduleCredential {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Owner => "owner",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, WorkQueueError> {
        match raw {
            "worker" => Ok(Self::Worker),
            "owner" => Ok(Self::Owner),
            _ => Err(WorkQueueError::Protocol("invalid schedule credential")),
        }
    }
}

/// Completion outcome recorded on `public.worker_schedules.last_outcome`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleOutcome {
    Ok,
    Error,
    Timeout,
    Cancelled,
}

impl ScheduleOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Registration descriptor for a periodic task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleSpec {
    pub task_name: String,
    pub schedule_spec: String,
    pub timeout_secs: i32,
    pub schedule_tz: String,
    pub credential: ScheduleCredential,
}

/// A schedule row returned by `worker_schedule_register` or `worker_schedule_claim`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleRow {
    pub task_name: String,
    pub schedule_spec: String,
    pub timeout_secs: i32,
    pub schedule_tz: String,
    pub credential: ScheduleCredential,
    pub enabled: bool,
    pub fencing_token: i64,
    pub lease_owner: Option<String>,
    pub consecutive_failures: i32,
}

const REGISTER_SQL: &str = "SELECT task_name, schedule_spec, timeout_secs, schedule_tz, \
     credential, enabled, fencing_token, lease_owner, consecutive_failures \
     FROM public.worker_schedule_register($1, $2, $3, $4, $5)";

const CLAIM_SQL: &str = "SELECT task_name, schedule_spec, timeout_secs, schedule_tz, \
     credential, enabled, fencing_token, lease_owner, consecutive_failures \
     FROM public.worker_schedule_claim($1, $2, $3, $4)";

const HEARTBEAT_SQL: &str = "SELECT public.worker_schedule_heartbeat($1, $2, $3, $4)";

const COMPLETE_SQL: &str =
    "SELECT public.worker_schedule_complete($1, $2, $3, $4, $5, $6, $7::text::timestamptz)";

const RELEASE_SQL: &str = "SELECT public.worker_schedule_release($1, $2, $3)";

const DB_NOW_UTC_SQL: &str =
    "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')";

/// Privileged schedule-lease store over [`WorkerPool`].
#[derive(Clone)]
pub struct ScheduleStore {
    pool: WorkerPool,
}

impl ScheduleStore {
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &WorkerPool {
        &self.pool
    }

    /// Upsert a schedule definition; fails closed with `BZ040` on cross-node
    /// `schedule_tz` mismatch.
    pub async fn register(&self, spec: &ScheduleSpec) -> Result<ScheduleRow, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let cred = spec.credential.as_str();
        let rows = match tx
            .query(
                REGISTER_SQL,
                &[
                    (&spec.task_name, Type::TEXT),
                    (&spec.schedule_spec, Type::TEXT),
                    (&spec.timeout_secs, Type::INT4),
                    (&spec.schedule_tz, Type::TEXT),
                    (&cred, Type::TEXT),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        let row = rows.first().ok_or(WorkQueueError::Protocol(
            "worker_schedule_register returned no rows",
        ))?;
        parse_schedule_row(row)
    }

    /// Claim up to `limit` due schedules in `names` via `FOR UPDATE SKIP LOCKED`.
    pub async fn claim(
        &self,
        names: &[String],
        owner: &str,
        lease_secs: i32,
        limit: i32,
    ) -> Result<Vec<ScheduleRow>, WorkQueueError> {
        if owner.trim().is_empty() {
            return Err(WorkQueueError::InvalidArgument(
                "owner must not be empty".into(),
            ));
        }
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin_read_write().await?;
        let names_vec = names.to_vec();
        let lease_secs = lease_secs.max(1);
        let limit = limit.max(1);
        let rows = match tx
            .query(
                CLAIM_SQL,
                &[
                    (&names_vec, Type::TEXT_ARRAY),
                    (&owner, Type::TEXT),
                    (&lease_secs, Type::INT4),
                    (&limit, Type::INT4),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        rows.iter().map(parse_schedule_row).collect()
    }

    /// Extend a leased schedule row while `(task_name, fencing_token, lease_owner)`
    /// match and `lease_expires_at > clock_timestamp()`.
    pub async fn heartbeat(
        &self,
        task_name: &str,
        fencing_token: i64,
        owner: &str,
        lease_secs: i32,
    ) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let lease_secs = lease_secs.max(1);
        let rows = match tx
            .query(
                HEARTBEAT_SQL,
                &[
                    (&task_name, Type::TEXT),
                    (&fencing_token, Type::INT8),
                    (&owner, Type::TEXT),
                    (&lease_secs, Type::INT4),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Fenced completion in its own transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete(
        &self,
        task_name: &str,
        fencing_token: i64,
        owner: &str,
        outcome: ScheduleOutcome,
        duration_ms: i32,
        error: Option<&str>,
        next_due_at_rfc3339: &str,
    ) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let ok = match Self::complete_tx(
            &mut tx,
            task_name,
            fencing_token,
            owner,
            outcome,
            duration_ms,
            error,
            next_due_at_rfc3339,
        )
        .await
        {
            Ok(ok) => ok,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        Ok(ok)
    }

    /// Fenced completion inside the caller's open [`WorkerTx`] (atomic with
    /// worker-credential cron statement effects).
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_tx(
        tx: &mut WorkerTx,
        task_name: &str,
        fencing_token: i64,
        owner: &str,
        outcome: ScheduleOutcome,
        duration_ms: i32,
        error: Option<&str>,
        next_due_at_rfc3339: &str,
    ) -> Result<bool, StatementFailure> {
        let outcome_str = outcome.as_str();
        let err_truncated = error.map(|e| truncate_utf8_bytes(e, MAX_ERROR_BYTES).to_owned());
        let rows = tx
            .query(
                COMPLETE_SQL,
                &[
                    (&task_name, Type::TEXT),
                    (&fencing_token, Type::INT8),
                    (&owner, Type::TEXT),
                    (&outcome_str, Type::TEXT),
                    (&duration_ms, Type::INT4),
                    (&err_truncated, Type::TEXT),
                    (&next_due_at_rfc3339, Type::TEXT),
                ],
            )
            .await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Fenced graceful shutdown handoff releasing the lease for `<1s` peer pickup.
    pub async fn release(
        &self,
        task_name: &str,
        fencing_token: i64,
        owner: &str,
    ) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let rows = match tx
            .query(
                RELEASE_SQL,
                &[
                    (&task_name, Type::TEXT),
                    (&fencing_token, Type::INT8),
                    (&owner, Type::TEXT),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Read PostgreSQL `clock_timestamp()` in UTC RFC3339 format (never host local clock).
    pub async fn db_now_utc(&self) -> Result<String, WorkQueueError> {
        let mut tx = self.pool.begin_repeatable_read_only().await?;
        let rows = match tx.query(DB_NOW_UTC_SQL, &[]).await {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        let row = rows
            .first()
            .ok_or(WorkQueueError::Protocol("db_now_utc returned no rows"))?;
        row.try_get(0)
            .map_err(|_| WorkQueueError::Protocol("invalid db_now_utc column"))
    }
}

fn parse_schedule_row(row: &Row) -> Result<ScheduleRow, WorkQueueError> {
    let cred_raw: String = row
        .try_get(4)
        .map_err(|_| WorkQueueError::Protocol("invalid credential column"))?;
    Ok(ScheduleRow {
        task_name: row
            .try_get(0)
            .map_err(|_| WorkQueueError::Protocol("invalid task_name column"))?,
        schedule_spec: row
            .try_get(1)
            .map_err(|_| WorkQueueError::Protocol("invalid schedule_spec column"))?,
        timeout_secs: row
            .try_get(2)
            .map_err(|_| WorkQueueError::Protocol("invalid timeout_secs column"))?,
        schedule_tz: row
            .try_get(3)
            .map_err(|_| WorkQueueError::Protocol("invalid schedule_tz column"))?,
        credential: ScheduleCredential::parse(&cred_raw)?,
        enabled: row.try_get(5).unwrap_or(true),
        fencing_token: row
            .try_get(6)
            .map_err(|_| WorkQueueError::Protocol("invalid fencing_token column"))?,
        lease_owner: row.try_get(7).unwrap_or(None),
        consecutive_failures: row.try_get(8).unwrap_or(0),
    })
}
