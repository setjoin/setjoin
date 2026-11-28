use crate::capability::AuditEvent;
use crate::outcome::commit_failure_observation;
use crate::pipeline::{build_begin_sql, pre_encode_params};
use crate::pool::{
    pg_version_allows_prepared_rls, PgBouncerAttestation, PlanCacheHint,
    DEFAULT_PREPARED_CACHE_CAP, MIN_PGBOUNCER_MAX_PREPARED, PGBOUNCER_PREPARED_HEADROOM,
};
use crate::statement::{admit, admit_select};
use setjoin_contracts::command::CommitObservation;
use std::time::Duration;
use tokio_postgres::types::{private::BytesMut, IsNull, ToSql, Type};

#[test]
fn ordinary_scoped_statements_are_admitted() {
    for sql in [
        "SELECT id FROM messages WHERE mailbox_id = $1",
        "  update messages SET is_read = $2 WHERE id = $1 AND mailbox_id = $3",
        "WITH t AS (SELECT 1) SELECT * FROM t",
        "INSERT INTO change_journal (mailbox_id) VALUES ($1)",
        "SELECT pg_notify('mailbox_changes', $1)",
        "SELECT * FROM settings_reset_log", // `reset` only inside an identifier
        "SELECT ';' AS semi",               // semicolon inside a literal
        "UPDATE meeting_members SET role = $1 WHERE meeting_id = $2", // a column named role
        "SELECT 1 -- ; SET ROLE x",         // comment text is ignored
        "SELECT pg_advisory_xact_lock(42)", // xact-scoped lock is transaction-local
    ] {
        assert_eq!(admit(sql), Ok(()), "{sql}");
    }
}

#[test]
fn role_session_transaction_control_nul_and_session_locks_are_refused() {
    for sql in [
        "SET ROLE setjoin_worker",
        "set local role postgres",
        "RESET ROLE",
        "SET SESSION AUTHORIZATION mail",
        "SELECT 1; SET ROLE setjoin_worker",
        "BEGIN",
        "start transaction",
        "COMMIT",
        "END",
        "ROLLBACK",
        "ABORT",
        "SAVEPOINT a",
        "RELEASE a",
        "PREPARE p AS SELECT 1",
        "DEALLOCATE ALL",
        "DISCARD ALL",
        "LISTEN x",
        "SELECT set_config('app.current_mailbox_id', '7', true)",
        "select SET_CONFIG ('role', 'mail', false)",
        "SELECT \"set_config\"('app.current_mailbox_id', '7', true)",
        "SELECT 1; SELECT 2",
        "",
        // Interior NUL bytes
        "SELECT 1\0",
        "SELECT 'a\0b'",
        "SELECT 1\0; DROP TABLE users",
        // All 7 session-level advisory lock functions (plus quoted forms)
        "SELECT pg_advisory_lock(1)",
        "SELECT pg_try_advisory_lock(1, 2)",
        "SELECT pg_advisory_unlock(1)",
        "SELECT pg_advisory_lock_shared(1)",
        "SELECT pg_try_advisory_lock_shared(1)",
        "SELECT pg_advisory_unlock_shared(1)",
        "SELECT pg_advisory_unlock_all()",
        "SELECT PG_ADVISORY_LOCK(42)",
        "SELECT \"pg_advisory_lock\"(42)",
    ] {
        assert!(admit(sql).is_err(), "expected refusal for {sql:?}");
    }
}

#[test]
fn admit_select_accepts_only_select_statements() {
    assert_eq!(admit_select("SELECT 1"), Ok(()));
    assert_eq!(admit_select("/* lead */ SELECT id FROM messages"), Ok(()));
    assert!(admit_select("UPDATE messages SET is_read = true").is_err());
    assert!(admit_select("DELETE FROM messages").is_err());
    assert!(admit_select("WITH d AS (DELETE FROM messages RETURNING 1) SELECT * FROM d").is_err());
    assert!(admit_select("SELECT pg_advisory_lock(1)").is_err());
    assert!(admit_select("SELECT 1\0").is_err());
}

#[test]
fn cve_2026_14666_prepared_rls_version_floor_rejects_vulnerable_17_and_18_series() {
    for rejected in [
        150000, 160004, 170000, 170009, 170010, // PG < 17.11
        180000, 180001, 180002, 180003, 180004, 180005, // PG 18.0–18.5
    ] {
        assert!(
            !pg_version_allows_prepared_rls(rejected),
            "version {rejected} must be rejected under CVE-2026-14666"
        );
    }
    for admitted in [170011, 170012, 170099, 179999, 180006, 180007, 190000] {
        assert!(
            pg_version_allows_prepared_rls(admitted),
            "version {admitted} should be admitted"
        );
    }
}

#[test]
fn pgbouncer_attestation_validates_bounds_and_computes_effective_cap() {
    assert!(PgBouncerAttestation::with_default_cap(0, false).is_err());
    assert!(PgBouncerAttestation::with_default_cap(MIN_PGBOUNCER_MAX_PREPARED - 1, false).is_err());
    assert!(PgBouncerAttestation::with_default_cap(MIN_PGBOUNCER_MAX_PREPARED, true).is_err());
    assert!(PgBouncerAttestation::new(MIN_PGBOUNCER_MAX_PREPARED, false, 0).is_err());

    let default_att = PgBouncerAttestation::with_default_cap(200, false).unwrap();
    assert_eq!(default_att.effective_cap(), DEFAULT_PREPARED_CACHE_CAP);
    assert_eq!(default_att.max_prepared_statements(), 200);
    assert!(!default_att.server_reset_query_always());

    let clamped = PgBouncerAttestation::new(200, false, 200).unwrap();
    assert_eq!(clamped.effective_cap(), 200 - PGBOUNCER_PREPARED_HEADROOM);
}

#[test]
fn plan_cache_hint_force_custom_plan_appends_to_step1_begin_sql() {
    let auto = build_begin_sql(
        "BEGIN READ WRITE",
        Duration::from_secs(2),
        PlanCacheHint::Auto,
    );
    assert_eq!(auto, "BEGIN READ WRITE; SET LOCAL statement_timeout = 2000");

    let forced = build_begin_sql(
        "BEGIN READ WRITE",
        Duration::from_secs(2),
        PlanCacheHint::ForceCustomPlan,
    );
    assert_eq!(
        forced,
        "BEGIN READ WRITE; SET LOCAL statement_timeout = 2000; SET LOCAL plan_cache_mode = force_custom_plan"
    );
}

#[test]
fn audit_event_requires_non_empty_action_and_target_type() {
    assert!(AuditEvent::new("", "user").is_err());
    assert!(AuditEvent::new("   ", "user").is_err());
    assert!(AuditEvent::new("user.update", "").is_err());
    assert!(AuditEvent::new("user.update", "\t\n").is_err());
    let ok = AuditEvent::new("user.update", "user")
        .unwrap()
        .with_target_id(42)
        .with_notes("verified");
    assert_eq!(ok.action(), "user.update");
    assert_eq!(ok.target_type(), "user");
}

#[derive(Debug)]
struct FailingToSql;

impl ToSql for FailingToSql {
    fn to_sql(
        &self,
        _ty: &Type,
        _out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        Err("synthetic client encoding failure".into())
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    tokio_postgres::types::to_sql_checked!();
}

#[test]
fn pre_encode_params_catches_type_mismatch_custom_error_and_param_overflow_before_begin() {
    // Mismatched Rust type vs PostgreSQL Type
    let num: i32 = 7;
    assert!(pre_encode_params(&[(&num, Type::TEXT)]).is_err());

    // Custom ToSql error
    let bad = FailingToSql;
    assert!(pre_encode_params(&[(&bad, Type::TEXT)]).is_err());

    // Valid params succeed
    let ok = pre_encode_params(&[(&num, Type::INT4), (&"hello", Type::TEXT)]);
    assert!(ok.is_ok());

    // Exceeding i16::MAX parameters rejected before wire
    let too_many: Vec<(&'static (dyn ToSql + Sync), Type)> =
        vec![(&1i32 as &(dyn ToSql + Sync), Type::INT4); (i16::MAX as usize) + 1];
    assert!(pre_encode_params(&too_many).is_err());
}

#[test]
fn classify_write_pipeline_covers_all_truth_table_branches() {
    use crate::outcome::{Rejection, StatementFailure};
    use crate::pipeline::{classify_write_pipeline_obs, PurePipelineDecision, StepObs};

    let db_err = |code: &str| {
        StepObs::DbError(StatementFailure {
            sqlstate: Some(code.into()),
            message: format!("err {code}"),
            hint: None,
        })
    };

    // 1. All steps Ok -> Committed (recycle iff !client_closed)
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::Ok,
            Some(&StepObs::Ok),
            Some(&StepObs::Ok),
            &StepObs::Ok,
            false,
        ),
        PurePipelineDecision::Committed { recycle: true }
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::Ok,
            None,
            None,
            &StepObs::Ok,
            true,
        ),
        PurePipelineDecision::Committed { recycle: false }
    ));

    // 2. Step 1 (BEGIN) transport error -> Unknown
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::TransportError,
            &StepObs::TransportError,
            &StepObs::TransportError,
            None,
            None,
            &StepObs::TransportError,
            false,
        ),
        PurePipelineDecision::Unknown
    ));

    // 3. Step 1 (BEGIN) DB error + ALL mutating steps DB error -> RolledBack(Unavailable), recycle=false
    assert!(matches!(
        classify_write_pipeline_obs(
            &db_err("53300"),
            &db_err("53300"),
            &db_err("53300"),
            Some(&db_err("53300")),
            Some(&db_err("53300")),
            &db_err("53300"),
            false,
        ),
        PurePipelineDecision::RolledBack {
            rejection: Rejection::Unavailable,
            recycle: false
        }
    ));

    // 4. Step 1 (BEGIN) DB error + any mutating step Ok or TransportError -> Unknown
    assert!(matches!(
        classify_write_pipeline_obs(
            &db_err("53300"),
            &db_err("53300"),
            &StepObs::Ok,
            None,
            None,
            &StepObs::Ok,
            false,
        ),
        PurePipelineDecision::Unknown
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &db_err("53300"),
            &db_err("53300"),
            &db_err("53300"),
            Some(&StepObs::TransportError),
            None,
            &StepObs::TransportError,
            false,
        ),
        PurePipelineDecision::Unknown
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &db_err("53300"),
            &db_err("53300"),
            &db_err("53300"),
            None,
            Some(&StepObs::Ok),
            &StepObs::Ok,
            false,
        ),
        PurePipelineDecision::Unknown
    ));

    // 5. Mid-pipeline DB error (step 2 preamble / step 3 BZ001, step 5 25P02):
    //    - COMMIT Ok + !closed -> RolledBack(first), recycle=true
    //    - COMMIT Ok + closed  -> RolledBack(first), recycle=false
    //    - COMMIT TransportError -> RolledBack(first), recycle=false
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &db_err("42501"),
            &db_err("25P02"),
            None,
            None,
            &StepObs::Ok,
            true,
        ),
        PurePipelineDecision::RolledBack {
            rejection: Rejection::Statement(f),
            recycle: false,
        } if f.sqlstate.as_deref() == Some("42501")
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &db_err("BZ001"),
            None,
            Some(&db_err("25P02")),
            &StepObs::Ok,
            false,
        ),
        PurePipelineDecision::RolledBack {
            rejection: Rejection::Statement(f),
            recycle: true,
        } if f.sqlstate.as_deref() == Some("BZ001")
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &db_err("BZ001"),
            None,
            Some(&db_err("25P02")),
            &StepObs::TransportError,
            false,
        ),
        PurePipelineDecision::RolledBack {
            rejection: Rejection::Statement(f),
            recycle: false,
        } if f.sqlstate.as_deref() == Some("BZ001")
    ));

    // 6. Mid-pipeline transport error without prior server ErrorResponse -> Unknown
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::TransportError,
            None,
            None,
            &StepObs::TransportError,
            false,
        ),
        PurePipelineDecision::Unknown
    ));

    // 7. Step 6 (COMMIT) definite-abort SQLSTATE (40001) -> RolledBack(CommitRefused), recycle iff !closed
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::Ok,
            None,
            None,
            &db_err("40001"),
            false,
        ),
        PurePipelineDecision::RolledBack {
            rejection: Rejection::CommitRefused(code),
            recycle: true,
        } if code == "40001"
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::Ok,
            None,
            None,
            &db_err("40001"),
            true,
        ),
        PurePipelineDecision::RolledBack {
            rejection: Rejection::CommitRefused(code),
            recycle: false,
        } if code == "40001"
    ));

    // 8. Step 6 (COMMIT) ambiguous SQLSTATE (08006) or TransportError -> Unknown
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::Ok,
            None,
            None,
            &db_err("08006"),
            false,
        ),
        PurePipelineDecision::Unknown
    ));
    assert!(matches!(
        classify_write_pipeline_obs(
            &StepObs::Ok,
            &StepObs::Ok,
            &StepObs::Ok,
            None,
            None,
            &StepObs::TransportError,
            false,
        ),
        PurePipelineDecision::Unknown
    ));
}

#[test]
fn commit_with_no_server_response_is_unknown_never_rolled_back() {
    assert_eq!(commit_failure_observation(None), CommitObservation::Unknown);
}

#[test]
fn commit_refused_by_deferred_constraint_or_serialization_is_rolled_back() {
    // 23505 unique_violation (deferred), 40001 serialization_failure,
    // P0001 raise_exception from a deferred trigger, BZ business code.
    for code in ["23505", "40001", "40P01", "P0001", "BZ139"] {
        assert_eq!(
            commit_failure_observation(Some(code)),
            CommitObservation::RolledBack,
            "{code}"
        );
    }
}

#[test]
fn commit_error_from_connection_or_server_failure_classes_is_unknown() {
    // 08006 connection_failure, 08P01 protocol_violation (PgBouncer),
    // 57P01 admin_shutdown, 58030 io_error, XX000 internal_error, 53300 too_many_connections.
    for code in ["08006", "08P01", "57P01", "58030", "XX000", "53300"] {
        assert_eq!(
            commit_failure_observation(Some(code)),
            CommitObservation::Unknown,
            "{code}"
        );
    }
}

/// Review item 4: a rejection is logged as its kind and SQLSTATE only. The
/// driver's message (which can quote row values, e.g. a unique-violation
/// `Key (email)=(alice@example.com)`) never reaches the log line.
#[test]
fn rejection_log_summary_carries_sqlstate_not_postgres_text() {
    use crate::outcome::{Rejection, StatementFailure};
    use setjoin_db::lifecycle::LifecycleError;
    let leak = "duplicate key value violates unique constraint; Key (email)=(alice@example.com)";
    let statement: Rejection<StatementFailure> = Rejection::Statement(StatementFailure {
        hint: None,
        sqlstate: Some("23505".into()),
        message: leak.into(),
    });
    assert_eq!(statement.log_summary(), "statement sqlstate=23505");
    let body: Rejection<StatementFailure> = Rejection::Body(StatementFailure {
        hint: None,
        sqlstate: None,
        message: leak.into(),
    });
    assert_eq!(body.log_summary(), "body sqlstate=none");
    let cases: [(Rejection<StatementFailure>, &str); 4] = [
        (Rejection::Unavailable, "unavailable"),
        (
            Rejection::CommitRefused("40001".into()),
            "commit-refused sqlstate=40001",
        ),
        (
            Rejection::Authority(LifecycleError::DeadlineElapsed),
            "authority deadline-elapsed",
        ),
        (
            Rejection::Authority(LifecycleError::InvalidTransition),
            "authority invalid-transition",
        ),
    ];
    for (r, want) in cases {
        assert_eq!(r.log_summary(), want);
    }
}

#[test]
fn contract_param_zip_and_scope_checks_enforce_exact_arity_and_scope() {
    use crate::capability::{check_contract_scope, zip_contract_params};
    use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope};

    static RO_CONTRACT: SqlContract = SqlContract {
        id: "test.ro",
        domain: "test",
        sql: "SELECT $1::bigint",
        params: &[Type::INT8],
        columns: &[ColumnSpec::unnamed(Type::INT8)],
        scope: SqlScope::MailboxReadOnly,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };
    static WORKER_CONTRACT: SqlContract = SqlContract {
        id: "test.worker",
        domain: "test",
        sql: "SELECT 1",
        params: &[],
        columns: &[ColumnSpec::unnamed(Type::INT4)],
        scope: SqlScope::WorkerBypass,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };

    // Exact arity passes; short or extra values are refused locally before wire I/O.
    let v: i64 = 42;
    let zipped = zip_contract_params(&RO_CONTRACT, &[&v]).expect("matching arity");
    assert_eq!(zipped.len(), 1);
    assert_eq!(zipped[0].1, Type::INT8);

    let short = zip_contract_params(&RO_CONTRACT, &[]).unwrap_err();
    assert!(short.message.contains("parameter count mismatch"));
    let extra = zip_contract_params(&RO_CONTRACT, &[&v, &v]).unwrap_err();
    assert!(extra.message.contains("parameter count mismatch"));

    // Scope mismatches fail closed before executing any SQL.
    assert!(check_contract_scope(
        &RO_CONTRACT,
        &[SqlScope::MailboxReadOnly],
        "MailboxTx<ReadOnly>"
    )
    .is_ok());
    let mismatch = check_contract_scope(
        &WORKER_CONTRACT,
        &[SqlScope::MailboxReadOnly],
        "contract scope mismatch for MailboxTx<ReadOnly>",
    )
    .unwrap_err();
    assert!(mismatch.message.contains("contract scope mismatch"));
    assert!(check_contract_scope(
        &RO_CONTRACT,
        &[SqlScope::MailboxReadWrite],
        "MailboxTx<ReadWrite>::execute_contract"
    )
    .is_err());
    assert!(
        check_contract_scope(&RO_CONTRACT, &[SqlScope::UserScoped], "UserTx<ReadOnly>").is_err()
    );
    assert!(check_contract_scope(
        &RO_CONTRACT,
        &[SqlScope::AdminRead],
        "AdminReadTx<Standard>"
    )
    .is_err());
}

#[test]
fn begin_sql_with_idle_timeout_appends_local_guc() {
    use crate::pipeline::build_begin_sql_with_idle_timeout;
    let sql = build_begin_sql_with_idle_timeout(
        "BEGIN READ WRITE",
        Duration::from_millis(5000),
        Some(8_000),
        PlanCacheHint::Auto,
    );
    assert_eq!(
        sql,
        "BEGIN READ WRITE; SET LOCAL statement_timeout = 5000; \
         SET LOCAL idle_in_transaction_session_timeout = 8000"
    );
    let custom = build_begin_sql_with_idle_timeout(
        "BEGIN READ WRITE",
        Duration::from_millis(2500),
        Some(8_000),
        PlanCacheHint::ForceCustomPlan,
    );
    assert_eq!(
        custom,
        "BEGIN READ WRITE; SET LOCAL statement_timeout = 2500; \
         SET LOCAL idle_in_transaction_session_timeout = 8000; \
         SET LOCAL plan_cache_mode = force_custom_plan"
    );
}

#[test]
fn try_app_pool_shares_effect_semaphore_budget() {
    use std::sync::Arc;
    let exec = crate::ScopedExecutor::from_dsn("postgres://mail@127.0.0.1:1/nonexistent", 2)
        .expect("lazy pool creation must not connect eagerly");
    let pool_a = exec.try_app_pool().expect("fast pool yields AppPool");
    let pool_b = exec
        .clone()
        .try_app_pool()
        .expect("cloned executor yields AppPool");
    assert!(
        Arc::ptr_eq(pool_a.effect_sem(), pool_b.effect_sem()),
        "all derived AppPools from one ScopedExecutor must share one effect_sem"
    );
    let before = pool_b.effect_sem().available_permits();
    let _permit = pool_a.effect_sem().try_acquire().expect("permit available");
    assert_eq!(pool_b.effect_sem().available_permits(), before - 1);
}

#[tokio::test]
async fn run_mailbox_audited_read_contract_rejects_mailbox_read_write() {
    use setjoin_contracts::{
        authority::{AuthorityKey, ResourceScope},
        command::CommandEnvelope,
        ids::{ActorId, Digest, Generation, MailboxId, OperationId},
    };
    use setjoin_sql_catalog::{RlsCheck, SqlAuditPosture, SqlContract, SqlScope};

    static RW_CONTRACT: SqlContract = SqlContract {
        id: "test.rw_rejected_by_audited_read",
        domain: "test",
        sql: "UPDATE messages SET is_read = TRUE WHERE mailbox_id = $1",
        params: &[Type::INT8],
        columns: &[],
        scope: SqlScope::MailboxReadWrite,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };

    let exec = crate::ScopedExecutor::from_dsn("postgres://mail@127.0.0.1:1/nonexistent", 1)
        .expect("lazy pool");
    let pool = exec.try_app_pool().expect("AppPool");
    let actor = ActorId::new(10).unwrap();
    let mb = MailboxId::new(20).unwrap();
    let verified = crate::mint::mailbox(actor, mb, Generation(1));
    let env = CommandEnvelope {
        operation: OperationId([1; 16]),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::Mailbox(mb),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest([2; 32]),
        command: (),
    };
    let mailbox_id = 20_i64;
    let out = pool
        .run_mailbox_audited_read_contract_pipelined(
            &env,
            &verified,
            std::time::Instant::now() + Duration::from_secs(5),
            &RW_CONTRACT,
            &[&mailbox_id],
            None,
            |_| Ok(()),
        )
        .await;
    match out {
        crate::CommandOutcome::RolledBack(crate::Rejection::Statement(f)) => {
            assert!(
                f.message.contains("contract scope mismatch"),
                "unexpected failure message: {f:?}"
            );
        }
        other => panic!("expected RolledBack(Statement(scope mismatch)), got {other:?}"),
    }
}
