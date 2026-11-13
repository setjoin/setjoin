//! JMAP1 (#315) `email-methods` slice replayed from frozen-Go recordings
//! without a Go upstream. Cases live in `jmap_email_oracle/cases.rs`.
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_email_oracle;

use jmap_email_oracle::{run, Mutation};
use setjoin_conformance::harness::{BoxError, Db};

macro_rules! replay {
    ($name:ident, $case:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(db) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            run(&db, $case, Mutation::None).await
        }
    };
}

macro_rules! status_mutant {
    ($name:ident, $case:literal, $pointer:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(db) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            let diff = run(&db, $case, Mutation::WrongStatus)
                .await
                .expect_err("a changed status must fail the replay")
                .to_string();
            assert!(diff.contains("/response/status"), "{diff}");
            if let Some(method) = receipt_method($case) {
                println!("MUTANT-REJECTED: POST /jmap {method} :: changed-status");
            }
            Ok(())
        }
    };
}

/// The adequacy gate requires each status mutant to name the method it stands for.
fn receipt_method(case: &str) -> Option<&'static str> {
    Some(match case {
        "email-get" => "Email/get",
        "email-deleted-query" => "Email/deletedQuery",
        "email-bundles" => "Email/bundles",
        "email-recover" => "Email/recover",
        "email-purge" => "Email/purge",
        "email-nudges" => "Email/nudges",
        "email-nudge-dismiss" => "Email/nudgeDismiss",
        "email-recovery-receipt" | "email-recovery-receipt-disabled" => "Email/recoveryReceipt",
        _ => return None,
    })
}

replay!(
    email_get_replays_frozen_go_recording_without_go,
    "email-get"
);
replay!(
    email_get_replays_properties_and_not_found_without_go,
    "email-get-properties-not-found"
);
replay!(
    email_get_replays_cross_tenant_denial_without_go,
    "email-get-cross-tenant"
);
replay!(
    email_get_replays_a_foreign_message_as_not_found_without_go,
    "email-get-foreign-message"
);
replay!(
    email_get_replays_malformed_ids_without_go,
    "email-get-malformed-ids"
);
status_mutant!(
    email_get_replay_reports_a_changed_rust_http_response,
    "email-get",
    "/response/status"
);
replay!(
    email_deleted_query_replays_a_list_without_go,
    "email-deleted-query"
);
replay!(
    email_deleted_query_replays_cross_tenant_denial_without_go,
    "email-deleted-query-cross-tenant"
);
replay!(
    email_deleted_query_replays_clamped_paging_without_go,
    "email-deleted-query-clamped"
);
replay!(email_bundles_replays_a_list_without_go, "email-bundles");
replay!(
    email_bundles_replays_cross_tenant_denial_without_go,
    "email-bundles-cross-tenant"
);
replay!(
    email_bundles_replays_a_clamped_limit_without_go,
    "email-bundles-clamped"
);
status_mutant!(
    email_deleted_query_replay_reports_a_changed_rust_http_response,
    "email-deleted-query",
    "/response/status"
);
status_mutant!(
    email_bundles_replay_reports_a_changed_rust_http_response,
    "email-bundles",
    "/response/status"
);
replay!(email_recover_replays_a_recovery_without_go, "email-recover");
replay!(
    email_recover_replays_a_repeat_without_go,
    "email-recover-repeat"
);
replay!(
    email_recover_replays_cross_tenant_denial_without_go,
    "email-recover-cross-tenant"
);
replay!(
    email_recover_replays_a_foreign_message_without_go,
    "email-recover-foreign-message"
);
replay!(
    email_recover_replays_malformed_ids_without_go,
    "email-recover-malformed"
);
replay!(email_purge_replays_a_purge_without_go, "email-purge");
replay!(
    email_purge_replays_a_repeat_without_go,
    "email-purge-repeat"
);
replay!(
    email_purge_replays_cross_tenant_denial_without_go,
    "email-purge-cross-tenant"
);
replay!(
    email_purge_replays_a_foreign_message_without_go,
    "email-purge-foreign-message"
);
replay!(
    email_purge_replays_malformed_ids_without_go,
    "email-purge-malformed"
);
status_mutant!(
    email_recover_replay_reports_a_changed_rust_http_response,
    "email-recover",
    "/response/status"
);
status_mutant!(
    email_purge_replay_reports_a_changed_rust_http_response,
    "email-purge",
    "/response/status"
);
replay!(email_nudges_replays_a_list_without_go, "email-nudges");
replay!(
    email_nudges_replays_the_toggle_off_answer_without_go,
    "email-nudges-off"
);
replay!(
    email_nudges_replays_cross_tenant_denial_without_go,
    "email-nudges-cross-tenant"
);
replay!(
    email_nudges_replays_a_clamped_limit_without_go,
    "email-nudges-clamped"
);
replay!(
    email_nudge_dismiss_replays_a_dismissal_without_go,
    "email-nudge-dismiss"
);
replay!(
    email_nudge_dismiss_replays_a_repeat_without_go,
    "email-nudge-dismiss-repeat"
);
replay!(
    email_nudge_dismiss_replays_the_toggle_off_answer_without_go,
    "email-nudge-dismiss-off"
);
replay!(
    email_nudge_dismiss_replays_cross_tenant_denial_without_go,
    "email-nudge-dismiss-cross-tenant"
);
replay!(
    email_nudge_dismiss_replays_an_empty_thread_without_go,
    "email-nudge-dismiss-empty-thread"
);
status_mutant!(
    email_nudges_replay_reports_a_changed_rust_http_response,
    "email-nudges",
    "/response/status"
);
status_mutant!(
    email_nudge_dismiss_replay_reports_a_changed_rust_http_response,
    "email-nudge-dismiss",
    "/response/status"
);
replay!(email_recovery_receipt_replays_the_disabled_answer_without_go, "email-recovery-receipt-disabled");
replay!(email_recovery_receipt_replays_cross_tenant_denial_without_go, "email-recovery-receipt-cross-tenant");
replay!(email_recovery_receipt_replays_invalid_arguments_without_go, "email-recovery-receipt-invalid");
status_mutant!(email_recovery_receipt_replay_reports_a_changed_rust_http_response, "email-recovery-receipt-disabled", "/response/status");
