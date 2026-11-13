//! #317: frozen-Go EmailSubmission HTTP/effect oracle, replayed with no upstream.
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_email_oracle;
use jmap_email_oracle::{run, Mutation};
use setjoin_conformance::harness::{BoxError, Db};
macro_rules! replay {
    ($name:ident, $case:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let db = Db::for_case(stringify!($name)).ok_or("database required")?;
            run(&db, $case, Mutation::None).await
        }
    };
}
replay!(submission_get, "submission-get");

replay!(submission_query, "submission-query");

replay!(submission_get_cross_tenant, "submission-get-cross-tenant");
replay!(submission_get_malformed, "submission-get-malformed");
replay!(
    submission_query_cross_tenant,
    "submission-query-cross-tenant"
);
replay!(submission_query_clamped, "submission-query-clamped");

replay!(submission_cancel, "submission-cancel");

replay!(submission_set, "submission-set");
replay!(submission_cancel_repeat, "submission-cancel-repeat");
replay!(
    submission_cancel_cross_tenant,
    "submission-cancel-cross-tenant"
);
replay!(
    submission_cancel_foreign_message,
    "submission-cancel-foreign-message"
);
replay!(submission_cancel_invalid, "submission-cancel-invalid");

replay!(submission_set_cross_tenant, "submission-set-cross-tenant");

replay!(
    submission_set_foreign_message,
    "submission-set-foreign-message"
);

replay!(submission_set_invalid, "submission-set-invalid");

replay!(
    submission_set_invalid_create,
    "submission-set-invalid-create"
);

replay!(submission_set_repeat, "submission-set-repeat");

replay!(submission_set_external, "submission-set-external");

replay!(submission_set_local, "submission-set-local");

replay!(submission_set_patch, "submission-set-patch");

replay!(submission_set_undo_window, "submission-set-undo-window");

replay!(submission_query_total_page, "submission-query-total-page");

replay!(submission_get_missing_id, "submission-get-missing-id");

replay!(submission_undo, "submission-undo");

replay!(submission_undo_cross_tenant, "submission-undo-cross-tenant");

replay!(submission_undo_invalid, "submission-undo-invalid");

replay!(submission_undo_repeat, "submission-undo-repeat");

replay!(submission_undo_expired, "submission-undo-expired");

replay!(submission_undo_shared_id, "submission-undo-shared-id");

replay!(submission_recall, "submission-recall");

replay!(
    submission_recall_cross_tenant,
    "submission-recall-cross-tenant"
);

replay!(submission_recall_invalid, "submission-recall-invalid");

replay!(submission_recall_repeat, "submission-recall-repeat");

replay!(submission_recall_disabled, "submission-recall-disabled");

replay!(
    submission_recall_sender_denied,
    "submission-recall-sender-denied"
);

replay!(submission_recall_alias, "submission-recall-alias");

replay!(submission_recall_expired, "submission-recall-expired");

replay!(submission_get_invalid_type, "submission-get-invalid-type");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_smime_preprocessing_defers_the_whole_mixed_map() -> Result<(), BoxError> {
    let db = Db::for_case("submission_smime_preprocessing_defers_the_whole_mixed_map")
        .ok_or("database required")?;
    run(
        &db,
        "submission-smime-deferred",
        Mutation::PreprocessingOwner,
    )
    .await?;
    run(
        &db,
        "submission-smime-unicode",
        Mutation::PreprocessingOwner,
    )
    .await
}

replay!(submission_get_case_folded, "submission-get-case-folded");

replay!(
    submission_get_missing_account,
    "submission-get-missing-account"
);

replay!(
    submission_get_invalid_element,
    "submission-get-invalid-element"
);

replay!(
    submission_query_invalid_limit,
    "submission-query-invalid-limit"
);

replay!(
    submission_query_position_overflow,
    "submission-query-position-overflow"
);

replay!(submission_cancel_missing_id, "submission-cancel-missing-id");

replay!(
    submission_cancel_invalid_type,
    "submission-cancel-invalid-type"
);

replay!(
    submission_set_invalid_account,
    "submission-set-invalid-account"
);

replay!(submission_set_null_create, "submission-set-null-create");

replay!(submission_set_db_error, "submission-set-db-error");

replay!(submission_get_db_error, "submission-get-db-error");

macro_rules! status_mutant {
    ($name:ident,$case:literal,$route:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let db = Db::for_case(stringify!($name)).ok_or("database required")?;
            let diff = run(&db, $case, Mutation::WrongStatus)
                .await
                .expect_err("status mutant must fail")
                .to_string();
            assert!(diff.contains("/response/status"), "{diff}");
            println!("MUTANT-REJECTED: {} :: changed-status", $route);
            Ok(())
        }
    };
}
macro_rules! notify_mutant {
    ($name:ident,$case:literal,$route:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let db = Db::for_case(stringify!($name)).ok_or("database required")?;
            let diff = run(&db, $case, Mutation::NoNotify)
                .await
                .expect_err("notify mutant must fail")
                .to_string();
            assert!(diff.contains("/notify/"), "{diff}");
            println!("MUTANT-REJECTED: {} :: no-notify", $route);
            Ok(())
        }
    };
}
status_mutant!(
    mutant_submission_get_status,
    "submission-get",
    "POST /jmap EmailSubmission/get"
);
status_mutant!(
    mutant_submission_query_status,
    "submission-query",
    "POST /jmap EmailSubmission/query"
);
status_mutant!(
    mutant_submission_set_status,
    "submission-set",
    "POST /jmap EmailSubmission/set"
);
status_mutant!(
    mutant_submission_cancel_status,
    "submission-cancel",
    "POST /jmap EmailSubmission/cancel"
);
status_mutant!(
    mutant_submission_undo_status,
    "submission-undo",
    "POST /messages/{id}/undo"
);
status_mutant!(
    mutant_submission_recall_status,
    "submission-recall",
    "POST /messages/{id}/recall"
);
notify_mutant!(
    mutant_submission_set_notify,
    "submission-set",
    "POST /jmap EmailSubmission/set"
);
notify_mutant!(
    mutant_submission_cancel_notify,
    "submission-cancel",
    "POST /jmap EmailSubmission/cancel"
);
notify_mutant!(
    mutant_submission_undo_notify,
    "submission-undo",
    "POST /messages/{id}/undo"
);
notify_mutant!(
    mutant_submission_recall_notify,
    "submission-recall",
    "POST /messages/{id}/recall"
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutant_submission_recall_audit() -> Result<(), BoxError> {
    let db = Db::for_case("mutant_submission_recall_audit").ok_or("database required")?;
    let diff = run(&db, "submission-recall", Mutation::NoRecallAudit)
        .await
        .expect_err("missing recall audit must fail")
        .to_string();
    assert!(diff.contains("message_recalls"), "{diff}");
    println!("MUTANT-REJECTED: POST /messages/{{id}}/recall :: no-recall-audit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_commit_lost_before_send_is_unknown_and_absent() -> Result<(), BoxError> {
    let db = Db::for_case("submission_commit_lost_before_send_is_unknown_and_absent")
        .ok_or("database required")?;
    run(&db, "submission-set", Mutation::CommitBefore).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_commit_lost_after_commit_is_unknown_and_once() -> Result<(), BoxError> {
    let db = Db::for_case("submission_commit_lost_after_commit_is_unknown_and_once")
        .ok_or("database required")?;
    run(&db, "submission-set", Mutation::CommitAfter).await
}

replay!(
    submission_set_invalid_argument_type,
    "submission-set-invalid-argument-type"
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_attachment_preprocessing_defers_the_whole_mixed_map() -> Result<(), BoxError> {
    let db = Db::for_case("submission_attachment_preprocessing_defers_the_whole_mixed_map")
        .ok_or("database required")?;
    run(
        &db,
        "submission-attachment-deferred",
        Mutation::PreprocessingOwner,
    )
    .await?;
    run(
        &db,
        "submission-attachment-invalid-id",
        Mutation::PreprocessingOwner,
    )
    .await
}
