use crate::outcome::commit_failure_observation;
use crate::statement::admit;

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
    ] {
        assert_eq!(admit(sql), Ok(()), "{sql}");
    }
}

#[test]
fn role_session_and_transaction_control_statements_are_refused() {
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
        "SELECT 1; SELECT 2",
        "",
    ] {
        assert!(admit(sql).is_err(), "{sql:?}");
    }
}
use setjoin_contracts::command::CommitObservation;

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
