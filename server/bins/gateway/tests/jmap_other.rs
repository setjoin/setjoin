//! JMAP2 recorded HTTP parity, Go upstream absent during replay.
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_email_oracle;
use jmap_email_oracle::{Mutation, run};
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
replay!(mailbox_get, "mailbox-get");

replay!(mailbox_get_ids, "mailbox-get-ids");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_sync_reads() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mailbox_sync_reads") else {
        return Ok(());
    };
    for case in ["mailbox-query", "mailbox-changes", "mailbox-query-changes"] {
        run(&db, case, Mutation::None).await?;
    }
    Ok(())
}

replay!(mailbox_set, "mailbox-set");

replay!(mailbox_get_cross_tenant, "mailbox-get-cross-tenant");

replay!(mailbox_get_invalid, "mailbox-get-invalid");

replay!(mailbox_query_cross_tenant, "mailbox-query-cross-tenant");

replay!(mailbox_query_invalid, "mailbox-query-invalid");

replay!(mailbox_changes_cross_tenant, "mailbox-changes-cross-tenant");

replay!(mailbox_changes_invalid, "mailbox-changes-invalid");

replay!(
    mailbox_query_changes_cross_tenant,
    "mailbox-query-changes-cross-tenant"
);

replay!(
    mailbox_query_changes_invalid,
    "mailbox-query-changes-invalid"
);

replay!(mailbox_set_cross_tenant, "mailbox-set-cross-tenant");

replay!(mailbox_set_invalid, "mailbox-set-invalid");

replay!(mailbox_set_repeat, "mailbox-set-repeat");

replay!(mailbox_set_rollback, "mailbox-set-rollback");

/// The adequacy gate requires each status mutant to name the route it stands for.
fn receipt_route(name: &str) -> Option<&'static str> {
    Some(match name {
        "blob_copy_status_mutant" => "POST /jmap Blob/copy",
        "blob_get_status_mutant" => "POST /jmap Blob/get",
        "blob_lookup_status_mutant" => "POST /jmap Blob/lookup",
        "core_echo_status_mutant" => "POST /jmap Core/echo",
        "identity_changes_status_mutant" => "POST /jmap Identity/changes",
        "identity_get_status_mutant" => "POST /jmap Identity/get",
        "identity_set_status_mutant" => "POST /jmap Identity/set",
        "jmap_attachment_token_status_mutant" => "POST /mail/attachment-transfer-token",
        "jmap_download_status_mutant" => "GET /jmap/download/{accountId}/{blobId}/{name}",
        "jmap_recovery_raw_status_mutant" => "GET /jmap/recovery-raw/{accountId}/{messageId}",
        "jmap_session_status_mutant" => "GET /.well-known/jmap",
        "jmap_upload_status_mutant" => "POST /jmap/upload/{accountId}",
        "mailbox_changes_status_mutant" => "POST /jmap Mailbox/changes",
        "mailbox_get_status_mutant" => "POST /jmap Mailbox/get",
        "mailbox_query_changes_status_mutant" => "POST /jmap Mailbox/queryChanges",
        "mailbox_query_status_mutant" => "POST /jmap Mailbox/query",
        "mailbox_set_status_mutant" => "POST /jmap Mailbox/set",
        "search_snippet_status_mutant" => "POST /jmap SearchSnippet/get",
        "thread_changes_status_mutant" => "POST /jmap Thread/changes",
        "thread_get_status_mutant" => "POST /jmap Thread/get",
        _ => return None,
    })
}

macro_rules! status_mutant {
    ($name:ident, $case:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(db) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            let diff = run(&db, $case, Mutation::WrongStatus)
                .await
                .expect_err("changed status must fail")
                .to_string();
            assert!(diff.contains("/response/status"), "{diff}");
            if let Some(route) = receipt_route(stringify!($name)) {
                println!("MUTANT-REJECTED: {route} :: changed-status");
            }
            Ok(())
        }
    };
}

status_mutant!(mailbox_get_status_mutant, "mailbox-get");

status_mutant!(mailbox_query_status_mutant, "mailbox-query");

status_mutant!(mailbox_changes_status_mutant, "mailbox-changes");

status_mutant!(mailbox_query_changes_status_mutant, "mailbox-query-changes");

status_mutant!(mailbox_set_status_mutant, "mailbox-set");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn thread_and_search_reads() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("thread_and_search_reads") else {
        return Ok(());
    };
    for case in ["thread-get", "thread-changes", "search-snippet"] {
        run(&db, case, Mutation::None).await?;
    }
    Ok(())
}

replay!(thread_get_cross_tenant, "thread-get-cross-tenant");

replay!(thread_get_invalid, "thread-get-invalid");

replay!(thread_changes_cross_tenant, "thread-changes-cross-tenant");

replay!(thread_changes_invalid, "thread-changes-invalid");

replay!(search_snippet_cross_tenant, "search-snippet-cross-tenant");

replay!(search_snippet_invalid, "search-snippet-invalid");

status_mutant!(thread_get_status_mutant, "thread-get");

status_mutant!(thread_changes_status_mutant, "thread-changes");

status_mutant!(search_snippet_status_mutant, "search-snippet");

replay!(core_echo, "core-echo");

replay!(core_echo_cross_tenant, "core-echo-cross-tenant");
replay!(core_echo_invalid, "core-echo-invalid");
status_mutant!(core_echo_status_mutant, "core-echo");
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blob_metadata_reads() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("blob_metadata_reads") else {
        return Ok(());
    };
    for case in ["blob-get", "blob-copy", "blob-lookup"] {
        run(&db, case, Mutation::None).await?;
    }
    Ok(())
}

replay!(blob_get_cross_tenant, "blob-get-cross-tenant");

replay!(blob_get_invalid, "blob-get-invalid");

replay!(blob_copy_cross_tenant, "blob-copy-cross-tenant");

replay!(blob_copy_invalid, "blob-copy-invalid");

replay!(blob_lookup_cross_tenant, "blob-lookup-cross-tenant");

replay!(blob_lookup_invalid, "blob-lookup-invalid");

status_mutant!(blob_get_status_mutant, "blob-get");

status_mutant!(blob_copy_status_mutant, "blob-copy");

status_mutant!(blob_lookup_status_mutant, "blob-lookup");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_struct_field_casing() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("go_struct_field_casing") else {
        return Ok(());
    };
    for case in ["blob-get-field-casing", "mailbox-query-field-casing"] {
        run(&db, case, Mutation::None).await?;
    }
    Ok(())
}

replay!(jmap_session, "jmap-session");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_delegated_accounts() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("session_delegated_accounts") else {
        return Ok(());
    };
    for case in [
        "jmap-session-delegated-send-as",
        "jmap-session-delegated-read",
    ] {
        run(&db, case, Mutation::None).await?;
    }
    Ok(())
}

replay!(jmap_session_configured, "jmap-session-configured");
replay!(jmap_session_native, "jmap-session-native");
replay!(jmap_session_cross_tenant, "jmap-session-cross-tenant");
replay!(jmap_session_invalid, "jmap-session-invalid");
status_mutant!(jmap_session_status_mutant, "jmap-session");

replay!(jmap_upload, "jmap-upload");

replay!(jmap_session_native_owner, "jmap-session-native-owner");

replay!(jmap_download, "jmap-download");

replay!(jmap_upload_cross_tenant, "jmap-upload-cross-tenant");
replay!(jmap_upload_invalid, "jmap-upload-invalid");
replay!(jmap_upload_over_quota, "jmap-upload-over-quota");
replay!(jmap_upload_delegated, "jmap-upload-delegated");
status_mutant!(jmap_upload_status_mutant, "jmap-upload");

replay!(jmap_session_admin, "jmap-session-admin");

replay!(jmap_recovery_raw, "jmap-recovery-raw");

replay!(jmap_download_range, "jmap-download-range");

replay!(jmap_download_invalid_range, "jmap-download-invalid-range");

replay!(jmap_download_not_modified, "jmap-download-not-modified");

replay!(jmap_download_cross_tenant, "jmap-download-cross-tenant");

replay!(jmap_download_invalid, "jmap-download-invalid");

replay!(jmap_download_delegated, "jmap-download-delegated");

replay!(jmap_download_filename, "jmap-download-filename");

status_mutant!(jmap_download_status_mutant, "jmap-download");

replay!(jmap_attachment_token, "jmap-attachment-token");

replay!(jmap_recovery_raw_s3, "jmap-recovery-raw-s3");

replay!(
    jmap_recovery_raw_cross_tenant,
    "jmap-recovery-raw-cross-tenant"
);

replay!(jmap_recovery_raw_invalid, "jmap-recovery-raw-invalid");

replay!(jmap_recovery_raw_missing, "jmap-recovery-raw-missing");

replay!(jmap_recovery_raw_hidden, "jmap-recovery-raw-hidden");

replay!(
    jmap_attachment_token_cross_tenant,
    "jmap-attachment-token-cross-tenant"
);

replay!(
    jmap_attachment_token_invalid,
    "jmap-attachment-token-invalid"
);

replay!(
    jmap_attachment_token_policy_denied,
    "jmap-attachment-token-policy-denied"
);

replay!(
    jmap_attachment_token_browser,
    "jmap-attachment-token-browser"
);

replay!(jmap_attachment_token_hidden, "jmap-attachment-token-hidden");

status_mutant!(jmap_recovery_raw_status_mutant, "jmap-recovery-raw");
status_mutant!(jmap_attachment_token_status_mutant, "jmap-attachment-token");

replay!(mailbox_set_database_fault, "mailbox-set-database-fault");
replay!(mailbox_get_database_fault, "mailbox-get-database-fault");

replay!(identity_get, "identity-get");

replay!(identity_get_cross_tenant, "identity-get-cross-tenant");

replay!(identity_get_invalid, "identity-get-invalid");

replay!(identity_changes, "identity-changes");

replay!(
    identity_changes_cross_tenant,
    "identity-changes-cross-tenant"
);

replay!(identity_changes_invalid, "identity-changes-invalid");

replay!(identity_set, "identity-set");

replay!(identity_set_repeat, "identity-set-repeat");

replay!(identity_set_cross_tenant, "identity-set-cross-tenant");

replay!(identity_set_invalid, "identity-set-invalid");

status_mutant!(identity_get_status_mutant, "identity-get");

status_mutant!(identity_changes_status_mutant, "identity-changes");

status_mutant!(identity_set_status_mutant, "identity-set");

replay!(identity_set_database_fault, "identity-set-database-fault");
