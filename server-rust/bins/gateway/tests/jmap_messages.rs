//! #469: the `/messages/{id}/*` REST routes, replayed from frozen-Go goldens with no upstream.
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
macro_rules! status_mutant {
    ($name:ident, $case:literal, $route:literal) => {
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
replay!(focus_success, "focus-success");
replay!(focus_focused, "focus-focused");
replay!(focus_repeat, "focus-repeat");
replay!(focus_body_quirks, "focus-body-quirks");
replay!(focus_cross_tenant, "focus-cross-tenant");
replay!(focus_invalid_id, "focus-invalid-id");
replay!(focus_invalid_body, "focus-invalid-body");
replay!(download_success, "download-success");
replay!(download_cross_tenant, "download-cross-tenant");
replay!(download_invalid_id, "download-invalid-id");
replay!(download_large, "download-large");
replay!(download_no_blob, "download-no-blob");
replay!(zip_success, "zip-success");
replay!(zip_large, "zip-large");
replay!(zip_cross_tenant, "zip-cross-tenant");
replay!(zip_invalid_id, "zip-invalid-id");
replay!(zip_none, "zip-none");
replay!(unsubscribe_mailto, "unsubscribe-mailto");
replay!(unsubscribe_audit_full, "unsubscribe-audit-full");
replay!(unsubscribe_post_failed, "unsubscribe-post-failed");
replay!(unsubscribe_private_url, "unsubscribe-private-url");
replay!(unsubscribe_bad_header, "unsubscribe-bad-header");
replay!(unsubscribe_no_header, "unsubscribe-no-header");
replay!(unsubscribe_cross_tenant, "unsubscribe-cross-tenant");
replay!(unsubscribe_invalid_id, "unsubscribe-invalid-id");
status_mutant!(mutant_focus_status, "focus-success", "POST /messages/{id}/focus");
status_mutant!(mutant_download_status, "download-success", "GET /messages/{emailId}/download");
status_mutant!(mutant_zip_status, "zip-success", "GET /messages/{id}/attachments.zip");
status_mutant!(mutant_unsubscribe_status, "unsubscribe-mailto", "POST /messages/{emailId}/unsubscribe");
