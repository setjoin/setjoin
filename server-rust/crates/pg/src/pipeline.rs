//! 1-RTT `tokio::join!(biased; ...)` pipelining, pre-encoding, merged static
//! preambles, and exact outcome truth-table classification.

use crate::{
    auth::AuditKeys,
    executor::Param,
    outcome::{commit_failure_observation, CommandOutcome, Rejection, StatementFailure},
    pool::{ManagedClient, ManagedLease, PlanCacheHint, PreparedStatementMode, SetjoinPool},
    statement::{admit, admit_select},
};
use setjoin_contracts::{
    authority::AuthorityKey,
    command::{CommandEnvelope, CommitObservation},
    ids::OperationId,
};
use setjoin_db::lifecycle::{accepted_contract, LifecycleError};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_postgres::{
    types::{private::BytesMut, Format, IsNull, ToSql, Type},
    Row, Statement,
};

/// A parameter whose `ToSql::to_sql_checked` has already succeeded into a
/// wire-ready buffer **before** `BEGIN` is enqueued.
///
/// Its `ToSql` implementation is infallible, guaranteeing zero mid-pipeline
/// client-side encoding failures inside `tokio::join!(biased; ...)`.
#[derive(Debug)]
pub(crate) struct PreEncodedParam {
    ty: Type,
    format: Format,
    bytes: Option<Vec<u8>>,
}

impl PreEncodedParam {
    pub(crate) fn encode(param: &Param<'_>) -> Result<Self, StatementFailure> {
        let (val, ty) = param;
        let format = val.encode_format(ty);
        let mut buf = BytesMut::new();
        let is_null = val.to_sql_checked(ty, &mut buf).map_err(|e| {
            StatementFailure::refused_owned(format!("parameter encoding failed: {e}"))
        })?;
        if buf.len() > i32::MAX as usize {
            return Err(StatementFailure::refused(
                "parameter exceeds i32::MAX bytes",
            ));
        }
        let bytes = match is_null {
            IsNull::Yes => None,
            IsNull::No => Some(buf.to_vec()),
        };
        Ok(Self {
            ty: ty.clone(),
            format,
            bytes,
        })
    }

    pub(crate) fn as_param(&self) -> Param<'_> {
        (self as &(dyn ToSql + Sync), self.ty.clone())
    }

    pub(crate) fn ty(&self) -> &Type {
        &self.ty
    }
}

impl ToSql for PreEncodedParam {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match &self.bytes {
            None => Ok(IsNull::Yes),
            Some(b) => {
                out.extend_from_slice(b);
                Ok(IsNull::No)
            }
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        debug_assert_eq!(ty, &self.ty);
        self.to_sql(ty, out)
    }

    fn encode_format(&self, _ty: &Type) -> Format {
        self.format
    }
}

/// Pre-encode a slice of parameters before `BEGIN` is sent.
pub(crate) fn pre_encode_params(
    params: &[Param<'_>],
) -> Result<Vec<PreEncodedParam>, StatementFailure> {
    if params.len() > i16::MAX as usize {
        return Err(StatementFailure::refused(
            "statement parameter count exceeds PostgreSQL i16::MAX limit",
        ));
    }
    params.iter().map(PreEncodedParam::encode).collect()
}

/// A fully validated, pre-encoded pipeline step ready to enqueue after `BEGIN`.
pub(crate) struct EncodedStep {
    pub(crate) sql: &'static str,
    pub(crate) params: Vec<PreEncodedParam>,
    pub(crate) prepared: Option<Statement>,
}

impl EncodedStep {
    pub(crate) fn new_admitted(
        sql: &'static str,
        params: &[Param<'_>],
        select_only: bool,
    ) -> Result<Self, StatementFailure> {
        if select_only {
            admit_select(sql).map_err(StatementFailure::refused)?;
        } else {
            admit(sql).map_err(StatementFailure::refused)?;
        }
        let encoded = pre_encode_params(params)?;
        Ok(Self {
            sql,
            params: encoded,
            prepared: None,
        })
    }

    pub(crate) fn new_infrastructure(
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Self, StatementFailure> {
        let encoded = pre_encode_params(params)?;
        Ok(Self {
            sql,
            params: encoded,
            prepared: None,
        })
    }

    fn types(&self) -> Vec<Type> {
        self.params.iter().map(|p| p.ty().clone()).collect()
    }

    /// Execute this step on `client`, draining its entire row stream to
    /// `ReadyForQuery` so multi-chunk (>64 KB) responses never deadlock
    /// `mpsc::channel(1)` inside `tokio::join!(biased; ...)`.
    pub(crate) async fn execute(
        &self,
        client: &tokio_postgres::Client,
    ) -> Result<Vec<Row>, tokio_postgres::Error> {
        if let Some(stmt) = &self.prepared {
            let refs: Vec<&(dyn ToSql + Sync)> = self
                .params
                .iter()
                .map(|p| p as &(dyn ToSql + Sync))
                .collect();
            client.query(stmt, &refs).await
        } else {
            let typed: Vec<Param<'_>> = self.params.iter().map(PreEncodedParam::as_param).collect();
            client.query_typed(self.sql, &typed).await
        }
    }
}

/// Classification of a pre-`BEGIN` `prepare_steps_before_begin` failure so
/// callers distinguish retryable transport errors from deterministic local or
/// server-side refusals.
pub(crate) enum PrepareError {
    Local(StatementFailure),
    Server(StatementFailure),
    Transport(StatementFailure),
}

impl PrepareError {
    pub(crate) fn into_failure(self) -> StatementFailure {
        match self {
            Self::Local(f) | Self::Server(f) | Self::Transport(f) => f,
        }
    }

    pub(crate) fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_))
    }
}

/// Prepare all steps in `OptIn` mode strictly **before** `BEGIN`, evicting any
/// LRU entries before entering the transaction and asserting exact parameter
/// types against PostgreSQL's `ParameterDescription`.
pub(crate) async fn prepare_steps_before_begin(
    managed: &mut ManagedClient,
    mode: PreparedStatementMode,
    steps: &mut [&mut EncodedStep],
) -> Result<(), PrepareError> {
    if !matches!(mode, PreparedStatementMode::OptIn(_)) {
        return Ok(());
    }
    for step in steps {
        let types = step.types();
        let stmt = managed
            .prepared
            .get_or_prepare(&managed.client, step.sql, &types)
            .await
            .map_err(|e| {
                let failure = StatementFailure::from_db(&e);
                if e.as_db_error().is_some() {
                    PrepareError::Server(failure)
                } else {
                    PrepareError::Transport(failure)
                }
            })?;
        if stmt.params() != types.as_slice() {
            return Err(PrepareError::Local(StatementFailure::refused_owned(
                format!(
                    "prepared parameter signature mismatch: server expects {:?}, caller bound {:?}",
                    stmt.params(),
                    types
                ),
            )));
        }
        step.prepared = Some(stmt);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Merged static preambles (1 statement, NEVER inside an RLS CTE)
// ---------------------------------------------------------------------------

const PREAMBLE_BASE: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true)";

const PREAMBLE_LOCK: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            pg_advisory_xact_lock(hashtextextended($3::text, 0))";

const PREAMBLE_KEYS: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            set_config('app.encryption_key', $3, true), \
            set_config('app.audit_hmac_key', $4, true)";

const PREAMBLE_KEYS_LOCK: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            set_config('app.encryption_key', $3, true), \
            set_config('app.audit_hmac_key', $4, true), \
            pg_advisory_xact_lock(hashtextextended($5::text, 0))";

const PREAMBLE_OP: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            set_config('app.rust_operation_id', $3, true)";

const PREAMBLE_OP_LOCK: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            set_config('app.rust_operation_id', $3, true), \
            pg_advisory_xact_lock(hashtextextended($4::text, 0))";

const PREAMBLE_OP_KEYS: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            set_config('app.rust_operation_id', $3, true), \
            set_config('app.encryption_key', $4, true), \
            set_config('app.audit_hmac_key', $5, true)";

const PREAMBLE_OP_KEYS_LOCK: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
            set_config('app.current_user_id', $2, true), \
            set_config('app.rust_operation_id', $3, true), \
            set_config('app.encryption_key', $4, true), \
            set_config('app.audit_hmac_key', $5, true), \
            pg_advisory_xact_lock(hashtextextended($6::text, 0))";

/// Transaction-scoped GUC/lock preamble installed as a separate statement
/// immediately after `BEGIN` (never folded into an RLS CTE).
#[derive(Clone, Debug)]
pub(crate) struct Preamble {
    pub(crate) mailbox: String,
    pub(crate) actor: String,
    pub(crate) operation_id: Option<String>,
    pub(crate) audit_keys: Option<Arc<AuditKeys>>,
    pub(crate) lock_key: Option<String>,
}

impl Preamble {
    pub(crate) fn to_step(&self) -> Result<EncodedStep, StatementFailure> {
        let (sql, params): (&'static str, Vec<Param<'_>>) =
            match (&self.operation_id, &self.audit_keys, &self.lock_key) {
                (None, None, None) => (
                    PREAMBLE_BASE,
                    vec![(&self.mailbox, Type::TEXT), (&self.actor, Type::TEXT)],
                ),
                (None, None, Some(lock)) => (
                    PREAMBLE_LOCK,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (lock, Type::TEXT),
                    ],
                ),
                (None, Some(keys), None) => (
                    PREAMBLE_KEYS,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                    ],
                ),
                (None, Some(keys), Some(lock)) => (
                    PREAMBLE_KEYS_LOCK,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                        (lock, Type::TEXT),
                    ],
                ),
                (Some(op), None, None) => (
                    PREAMBLE_OP,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (op, Type::TEXT),
                    ],
                ),
                (Some(op), None, Some(lock)) => (
                    PREAMBLE_OP_LOCK,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (op, Type::TEXT),
                        (lock, Type::TEXT),
                    ],
                ),
                (Some(op), Some(keys), None) => (
                    PREAMBLE_OP_KEYS,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (op, Type::TEXT),
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                    ],
                ),
                (Some(op), Some(keys), Some(lock)) => (
                    PREAMBLE_OP_KEYS_LOCK,
                    vec![
                        (&self.mailbox, Type::TEXT),
                        (&self.actor, Type::TEXT),
                        (op, Type::TEXT),
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                        (lock, Type::TEXT),
                    ],
                ),
            };
        EncodedStep::new_infrastructure(sql, &params)
    }
}

/// Build the step-1 simple-protocol batch (`BEGIN ...; SET LOCAL ...`).
pub(crate) fn build_begin_sql(
    begin_clause: &str,
    timeout: Duration,
    hint: PlanCacheHint,
) -> String {
    build_begin_sql_with_idle_timeout(begin_clause, timeout, None, hint)
}

/// Build the step-1 simple-protocol batch (`BEGIN ...; SET LOCAL ...`) with an
/// optional transaction-local `idle_in_transaction_session_timeout` (in ms) for
/// effect transactions that perform bounded peripheral I/O (#546a).
pub(crate) fn build_begin_sql_with_idle_timeout(
    begin_clause: &str,
    timeout: Duration,
    idle_in_tx_ms: Option<u32>,
    hint: PlanCacheHint,
) -> String {
    let ms = timeout.as_millis().clamp(1, i32::MAX as u128);
    let mut sql = format!("{begin_clause}; SET LOCAL statement_timeout = {ms}");
    if let Some(idle_ms) = idle_in_tx_ms {
        let clamped = idle_ms.max(1);
        sql.push_str(&format!(
            "; SET LOCAL idle_in_transaction_session_timeout = {clamped}"
        ));
    }
    if matches!(hint, PlanCacheHint::ForceCustomPlan) {
        sql.push_str("; SET LOCAL plan_cache_mode = force_custom_plan");
    }
    sql
}

/// Execute a 1-RTT pipelined `BEGIN READ ONLY` query with stale-socket 1-retry.
///
/// Strictly for pure read-only transactions (`MailboxTx<ReadOnly>`,
/// `UserTx<ReadOnly>`, `AdminReadTx<Standard>`). NEVER used for `READ WRITE` or
/// `AdminSensitiveRead` audit transactions.
pub(crate) async fn execute_read_pipeline(
    pool: &SetjoinPool,
    preamble: &Preamble,
    sql: &'static str,
    params: &[Param<'_>],
    operation_lock: Option<&str>,
) -> Result<Vec<Row>, StatementFailure> {
    let mut preamble_with_lock = preamble.clone();
    if let Some(lock) = operation_lock {
        preamble_with_lock.lock_key = Some(lock.to_owned());
    }
    let mut preamble_step = preamble_with_lock.to_step()?;
    let mut query_step = EncodedStep::new_admitted(sql, params, true)?;

    let begin_clause = if operation_lock.is_some() {
        "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY"
    } else {
        "BEGIN READ ONLY"
    };
    let overall_deadline = Instant::now() + pool.timeouts.statement * 2;

    for attempt in 0..2 {
        let remaining = overall_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(StatementFailure::refused("read timed out"));
        }
        let mut lease = pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;

        // Clear any statement cached on a previous connection before retry.
        preamble_step.prepared = None;
        query_step.prepared = None;
        if let Err(err) = prepare_steps_before_begin(
            lease.managed_mut(),
            pool.prepared_mode,
            &mut [&mut preamble_step, &mut query_step],
        )
        .await
        {
            if attempt == 0 && err.is_transport() {
                lease.quarantine();
                continue;
            }
            if !err.is_transport() && !lease.is_closed() {
                lease.keep();
            } else {
                lease.quarantine();
            }
            return Err(err.into_failure());
        }

        let begin_sql =
            build_begin_sql(begin_clause, pool.timeouts.statement, pool.plan_cache_hint);
        let client = lease.client();
        let piped = tokio::time::timeout(remaining, async {
            tokio::join!(
                biased;
                client.batch_execute(&begin_sql),
                preamble_step.execute(client),
                query_step.execute(client),
                client.batch_execute("COMMIT"),
            )
        })
        .await;

        let Ok((begin_res, preamble_res, query_res, commit_res)) = piped else {
            // Timeout drops lease -> quarantine + CancelRequest.
            return Err(StatementFailure::refused("read timed out"));
        };

        // Pre-response transport error on attempt 0: quarantine dead socket and
        // retry ONCE within remaining deadline.
        if let Err(ref e) = begin_res {
            if attempt == 0 && e.as_db_error().is_none() {
                lease.quarantine();
                continue;
            }
            lease.quarantine();
            return Err(StatementFailure::from_db(e));
        }

        if let Err(ref e) = preamble_res {
            if e.as_db_error().is_some() && commit_res.is_ok() && !lease.is_closed() {
                lease.keep();
            } else {
                lease.quarantine();
            }
            return Err(StatementFailure::from_db(e));
        }

        if let Err(ref e) = query_res {
            if e.as_db_error().is_some() && commit_res.is_ok() && !lease.is_closed() {
                lease.keep();
            } else {
                lease.quarantine();
            }
            return Err(StatementFailure::from_db(e));
        }

        match commit_res {
            Ok(()) => {
                let rows = query_res.expect("checked Ok above");
                if !lease.is_closed() {
                    lease.keep();
                } else {
                    lease.quarantine();
                }
                return Ok(rows);
            }
            Err(e) => {
                lease.quarantine();
                return Err(StatementFailure::from_db(&e));
            }
        }
    }

    Err(StatementFailure::refused("pool unavailable"))
}

/// Pure per-step observation extracted from a wire `Result` so every branch of
/// the pipeline truth table is unit-testable without driver internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StepObs {
    Ok,
    DbError(StatementFailure),
    TransportError,
}

impl StepObs {
    fn from_result<T>(res: &Result<T, tokio_postgres::Error>) -> Self {
        match res {
            Ok(_) => Self::Ok,
            Err(e) if e.as_db_error().is_some() => Self::DbError(StatementFailure::from_db(e)),
            Err(_) => Self::TransportError,
        }
    }

    fn is_db_error(&self) -> bool {
        matches!(self, Self::DbError(_))
    }
}

/// Pure outcome classifier for a completed 1-RTT write pipeline implementing
/// PLAN-540 §4.3 + Delta Note 1.
#[derive(Debug)]
pub(crate) enum PipelineDecision {
    Committed {
        rows: Vec<Row>,
        recycle: bool,
    },
    RolledBack {
        rejection: Rejection<StatementFailure>,
        recycle: bool,
    },
    Unknown,
}

/// Pure truth-table outcome independent of `Vec<Row>` payload.
#[derive(Debug)]
pub(crate) enum PurePipelineDecision {
    Committed {
        recycle: bool,
    },
    RolledBack {
        rejection: Rejection<StatementFailure>,
        recycle: bool,
    },
    Unknown,
}

/// Evaluate the wire observations of a 1-RTT write pipeline according to the
/// tightened truth table:
///
/// - Step 1 (`BEGIN`) `TransportError` -> `Unknown` + quarantine.
/// - Step 1 (`BEGIN`) `DbError` -> always quarantine; `RolledBack(Unavailable)`
///   only if every mutating step (3/4/5) also returned `DbError`, else
///   `Unknown`.
/// - Steps 2–5 first non-`Ok` observation:
///   - `DbError(first)` -> `RolledBack(Statement(first))` (never masked by
///     downstream `25P02`); recycle only if step 6 (`COMMIT`) returned `Ok`
///     and `!client_closed`, else quarantine.
///   - `TransportError` -> `Unknown` + quarantine.
/// - Step 6 (`COMMIT`) error -> `commit_failure_observation(sqlstate)`:
///   - `RolledBack` -> `RolledBack(CommitRefused(code))`, recycle iff
///     `!client_closed`.
///   - `Unknown` -> `Unknown` + quarantine.
/// - All steps `Ok` -> `Committed`, recycle iff `!client_closed`.
pub(crate) fn classify_write_pipeline_obs(
    begin: &StepObs,
    preamble: &StepObs,
    business: &StepObs,
    audit: Option<&StepObs>,
    receipt: Option<&StepObs>,
    commit: &StepObs,
    client_closed: bool,
) -> PurePipelineDecision {
    // 1. Step 1 (BEGIN) failure.
    match begin {
        StepObs::TransportError => return PurePipelineDecision::Unknown,
        StepObs::DbError(_) => {
            // Server ErrorResponse on BEGIN: PG may have stayed Idle ('I').
            // ALWAYS quarantine. Only return RolledBack(Unavailable) if EVERY
            // mutating step (3/4/5) also failed with a server ErrorResponse.
            let mutating_all_db_err = business.is_db_error()
                && audit.is_none_or(StepObs::is_db_error)
                && receipt.is_none_or(StepObs::is_db_error);

            return if mutating_all_db_err {
                PurePipelineDecision::RolledBack {
                    rejection: Rejection::Unavailable,
                    recycle: false,
                }
            } else {
                PurePipelineDecision::Unknown
            };
        }
        StepObs::Ok => {}
    }

    // 2. Steps 2..=5 in wire order (first error wins, never masked by 25P02).
    let commit_ack = matches!(commit, StepObs::Ok);
    let step_obs: [Option<&StepObs>; 4] = [Some(preamble), Some(business), audit, receipt];
    if let Some(first_err) = step_obs
        .into_iter()
        .flatten()
        .find(|obs| !matches!(obs, StepObs::Ok))
    {
        return match first_err {
            StepObs::DbError(failure) => PurePipelineDecision::RolledBack {
                rejection: Rejection::Statement(failure.clone()),
                recycle: commit_ack && !client_closed,
            },
            StepObs::TransportError => PurePipelineDecision::Unknown,
            StepObs::Ok => unreachable!(),
        };
    }

    // 3. Step 6 (COMMIT) outcome when steps 1..=5 all succeeded.
    match commit {
        StepObs::Ok => PurePipelineDecision::Committed {
            recycle: !client_closed,
        },
        StepObs::DbError(failure) => {
            let code = failure.sqlstate.as_deref();
            match commit_failure_observation(code) {
                CommitObservation::RolledBack => PurePipelineDecision::RolledBack {
                    rejection: Rejection::CommitRefused(code.unwrap_or("").to_owned()),
                    recycle: !client_closed,
                },
                CommitObservation::Unknown | CommitObservation::Committed => {
                    PurePipelineDecision::Unknown
                }
            }
        }
        StepObs::TransportError => PurePipelineDecision::Unknown,
    }
}

/// Classify completed wire results from a 1-RTT write pipeline.
pub(crate) fn classify_write_pipeline(
    begin_res: Result<(), tokio_postgres::Error>,
    preamble_res: Result<Vec<Row>, tokio_postgres::Error>,
    business_res: Result<Vec<Row>, tokio_postgres::Error>,
    audit_res: Option<Result<Vec<Row>, tokio_postgres::Error>>,
    receipt_res: Option<Result<Vec<Row>, tokio_postgres::Error>>,
    commit_res: Result<(), tokio_postgres::Error>,
    client_closed: bool,
) -> PipelineDecision {
    let begin_obs = StepObs::from_result(&begin_res);
    let preamble_obs = StepObs::from_result(&preamble_res);
    let business_obs = StepObs::from_result(&business_res);
    let audit_obs = audit_res.as_ref().map(StepObs::from_result);
    let receipt_obs = receipt_res.as_ref().map(StepObs::from_result);
    let commit_obs = StepObs::from_result(&commit_res);

    match classify_write_pipeline_obs(
        &begin_obs,
        &preamble_obs,
        &business_obs,
        audit_obs.as_ref(),
        receipt_obs.as_ref(),
        &commit_obs,
        client_closed,
    ) {
        PurePipelineDecision::Committed { recycle } => PipelineDecision::Committed {
            rows: business_res.expect("checked Ok above"),
            recycle,
        },
        PurePipelineDecision::RolledBack { rejection, recycle } => {
            PipelineDecision::RolledBack { rejection, recycle }
        }
        PurePipelineDecision::Unknown => PipelineDecision::Unknown,
    }
}

/// Execute a 1-RTT SQL-validated pipelined write transaction (`BEGIN READ
/// WRITE`, merged preamble, business SQL, optional audit, optional receipt,
/// and `COMMIT`) using `tokio::join!(biased; ...)`.
///
/// All validation (`CommandEnvelope`, deadline, `statement::admit` including
/// `\0`, parameter count, `ToSql::to_sql_checked` pre-encoding, and `OptIn`
/// prepared resolution) finishes strictly **before** `BEGIN` is enqueued.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_write_pipeline<C, T, P>(
    pool: &SetjoinPool,
    envelope: &CommandEnvelope<C>,
    authority: AuthorityKey,
    deadline: Instant,
    preamble: &Preamble,
    mut business: EncodedStep,
    mut audit: Option<EncodedStep>,
    mut receipt: Option<EncodedStep>,
    project: P,
) -> CommandOutcome<T, StatementFailure>
where
    P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
{
    let operation: OperationId = envelope.operation;

    // 1. Validate envelope, authority, and deadline before touching the pool.
    if let Err(e) = envelope.validate(authority, accepted_contract()) {
        return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e)));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::DeadlineElapsed));
    }

    // 2. Encode preamble before pool checkout.
    let mut preamble_step = match preamble.to_step() {
        Ok(s) => s,
        Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
    };

    // 3. Checkout connection (RecyclingMethod::Fast — 0 RTT).
    let mut lease: ManagedLease = match pool.get().await {
        Ok(l) => l,
        Err(_) => return CommandOutcome::RolledBack(Rejection::Unavailable),
    };

    // 4. In OptIn prepared mode, prepare + evict LRU strictly BEFORE BEGIN.
    {
        let mut to_prepare: Vec<&mut EncodedStep> = vec![&mut preamble_step, &mut business];
        if let Some(a) = audit.as_mut() {
            to_prepare.push(a);
        }
        if let Some(r) = receipt.as_mut() {
            to_prepare.push(r);
        }
        if let Err(err) =
            prepare_steps_before_begin(lease.managed_mut(), pool.prepared_mode, &mut to_prepare)
                .await
        {
            if err.is_transport() || lease.is_closed() {
                lease.quarantine();
            } else {
                lease.keep();
            }
            return CommandOutcome::RolledBack(Rejection::Statement(err.into_failure()));
        }
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        lease.keep();
        return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::DeadlineElapsed));
    }

    let begin_sql = build_begin_sql("BEGIN READ WRITE", remaining, pool.plan_cache_hint);

    // 5. Enqueue entire transaction in deterministic wire order in 1 RTT.
    let client = lease.client();
    let wire_result = tokio::time::timeout(remaining, async {
        match (&audit, &receipt) {
            (None, None) => {
                let (b, p, s, c) = tokio::join!(
                    biased;
                    client.batch_execute(&begin_sql),
                    preamble_step.execute(client),
                    business.execute(client),
                    client.batch_execute("COMMIT"),
                );
                (b, p, s, None, None, c)
            }
            (Some(a), None) => {
                let (b, p, s, ar, c) = tokio::join!(
                    biased;
                    client.batch_execute(&begin_sql),
                    preamble_step.execute(client),
                    business.execute(client),
                    a.execute(client),
                    client.batch_execute("COMMIT"),
                );
                (b, p, s, Some(ar), None, c)
            }
            (None, Some(r)) => {
                let (b, p, s, rr, c) = tokio::join!(
                    biased;
                    client.batch_execute(&begin_sql),
                    preamble_step.execute(client),
                    business.execute(client),
                    r.execute(client),
                    client.batch_execute("COMMIT"),
                );
                (b, p, s, None, Some(rr), c)
            }
            (Some(a), Some(r)) => {
                let (b, p, s, ar, rr, c) = tokio::join!(
                    biased;
                    client.batch_execute(&begin_sql),
                    preamble_step.execute(client),
                    business.execute(client),
                    a.execute(client),
                    r.execute(client),
                    client.batch_execute("COMMIT"),
                );
                (b, p, s, Some(ar), Some(rr), c)
            }
        }
    })
    .await;

    let Ok((begin_res, preamble_res, business_res, audit_res, receipt_res, commit_res)) =
        wire_result
    else {
        // Timed out after flush: quarantine + bounded CancelRequest.
        lease.quarantine();
        return CommandOutcome::Unknown { operation };
    };

    let decision = classify_write_pipeline(
        begin_res,
        preamble_res,
        business_res,
        audit_res,
        receipt_res,
        commit_res,
        lease.is_closed(),
    );

    match decision {
        PipelineDecision::Committed { rows, recycle } => {
            if recycle {
                lease.keep();
            } else {
                lease.quarantine();
            }
            // Post-commit projection: PG already committed, so a projection
            // failure MUST NEVER return RolledBack!
            match project(rows) {
                Ok(value) => CommandOutcome::Committed(value),
                Err(_) => CommandOutcome::Unknown { operation },
            }
        }
        PipelineDecision::RolledBack { rejection, recycle } => {
            if recycle {
                lease.keep();
            } else {
                lease.quarantine();
            }
            CommandOutcome::RolledBack(rejection)
        }
        PipelineDecision::Unknown => {
            lease.quarantine();
            CommandOutcome::Unknown { operation }
        }
    }
}
