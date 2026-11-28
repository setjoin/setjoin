//! F08 slice `jobs-storage` (#301): jobs console and storage read models, frozen-Go
//! oracle replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::jobs_storage::run($action, $kind).await
        }
    };
}

case!(summary_success, "jobs-summary", "success");
case!(summary_denied, "jobs-summary", "denied");
case!(summary_scoped, "jobs-summary", "scoped");
case!(summary_ignored_query, "jobs-summary", "ignored-query");
case!(summary_outbound, "jobs-summary", "outbound");
case!(summary_scheduled, "jobs-summary", "scheduled");
case!(summary_bulk_role, "jobs-summary", "bulk-role");
case!(summary_empty, "jobs-summary", "empty");
case!(summary_unknown, "jobs-summary", "unknown");
case!(summary_status_mutant, "jobs-summary", "success-status-mutant");
case!(list_success, "jobs-list", "success");
case!(list_denied, "jobs-list", "denied");
case!(list_scoped, "jobs-list", "scoped");
case!(list_ignored_query, "jobs-list", "ignored-query");
case!(list_outbound, "jobs-list", "outbound");
case!(list_scheduled, "jobs-list", "scheduled");
case!(list_bulk_role, "jobs-list", "bulk-role");
case!(list_empty, "jobs-list", "empty");
case!(list_unknown, "jobs-list", "unknown");
case!(list_attention, "jobs-list", "attention");
case!(list_active, "jobs-list", "active");
case!(list_done, "jobs-list", "done");
case!(list_all, "jobs-list", "all");
case!(list_page, "jobs-list", "page");
case!(list_bad_limit, "jobs-list", "bad-limit");
case!(list_huge_limit, "jobs-list", "huge-limit");
case!(list_bad_status, "jobs-list", "bad-status");
case!(list_status_mutant, "jobs-list", "success-status-mutant");
case!(journal_retry_success, "jobs-journal-retry", "success");
case!(journal_retry_not_dead, "jobs-journal-retry", "not-dead");
case!(journal_retry_missing, "jobs-journal-retry", "missing");
case!(journal_retry_bad_id, "jobs-journal-retry", "bad-id");
case!(journal_retry_repeat, "jobs-journal-retry", "repeat");
case!(journal_retry_denied, "jobs-journal-retry", "denied");
case!(journal_retry_scoped, "jobs-journal-retry", "scoped");
case!(journal_retry_status_mutant, "jobs-journal-retry", "success-status-mutant");
case!(bulk_detail_success, "jobs-bulk-detail", "success");
case!(bulk_detail_not_error, "jobs-bulk-detail", "not-error");
case!(bulk_detail_queued, "jobs-bulk-detail", "queued");
case!(bulk_detail_missing, "jobs-bulk-detail", "missing");
case!(bulk_detail_bad_id, "jobs-bulk-detail", "bad-id");
case!(bulk_detail_denied, "jobs-bulk-detail", "denied");
case!(bulk_detail_scoped, "jobs-bulk-detail", "scoped");
case!(bulk_detail_status_mutant, "jobs-bulk-detail", "success-status-mutant");
case!(bulk_retry_success, "jobs-bulk-retry", "success");
case!(bulk_retry_not_error, "jobs-bulk-retry", "not-error");
case!(bulk_retry_queued, "jobs-bulk-retry", "queued");
case!(bulk_retry_missing, "jobs-bulk-retry", "missing");
case!(bulk_retry_bad_id, "jobs-bulk-retry", "bad-id");
case!(bulk_retry_repeat, "jobs-bulk-retry", "repeat");
case!(bulk_retry_denied, "jobs-bulk-retry", "denied");
case!(bulk_retry_scoped, "jobs-bulk-retry", "scoped");
case!(bulk_retry_status_mutant, "jobs-bulk-retry", "success-status-mutant");
case!(dr_list_success, "storage-dr-list", "success");
case!(dr_list_denied, "storage-dr-list", "denied");
case!(dr_list_scoped, "storage-dr-list", "scoped");
case!(dr_list_ignored_query, "storage-dr-list", "ignored-query");
case!(dr_list_empty, "storage-dr-list", "empty");
case!(dr_list_status_mutant, "storage-dr-list", "success-status-mutant");
case!(dr_get_success, "storage-dr-get", "success");
case!(dr_get_running, "storage-dr-get", "running");
case!(dr_get_failed, "storage-dr-get", "failed");
case!(dr_get_null_details, "storage-dr-get", "null-details");
case!(dr_get_odd_details, "storage-dr-get", "odd-details");
case!(dr_get_object_details, "storage-dr-get", "object-details");
case!(dr_get_missing, "storage-dr-get", "missing");
case!(dr_get_bad_id, "storage-dr-get", "bad-id");
case!(dr_get_denied, "storage-dr-get", "denied");
case!(dr_get_scoped, "storage-dr-get", "scoped");
case!(dr_get_status_mutant, "storage-dr-get", "success-status-mutant");
case!(migrate_list_success, "storage-migrate-list", "success");
case!(migrate_list_denied, "storage-migrate-list", "denied");
case!(migrate_list_scoped, "storage-migrate-list", "scoped");
case!(migrate_list_ignored_query, "storage-migrate-list", "ignored-query");
case!(migrate_list_empty, "storage-migrate-list", "empty");
case!(migrate_list_null_started, "storage-migrate-list", "null-started");
case!(migrate_list_status_mutant, "storage-migrate-list", "success-status-mutant");
case!(migrate_get_success, "storage-migrate-get", "success");
case!(migrate_get_backfill, "storage-migrate-get", "backfill");
case!(migrate_get_pending, "storage-migrate-get", "pending");
case!(migrate_get_zero_total, "storage-migrate-get", "zero-total");
case!(migrate_get_escaped, "storage-migrate-get", "escaped");
case!(migrate_get_null_started, "storage-migrate-get", "null-started");
case!(migrate_get_missing, "storage-migrate-get", "missing");
case!(migrate_get_bad_id, "storage-migrate-get", "bad-id");
case!(migrate_get_denied, "storage-migrate-get", "denied");
case!(migrate_get_scoped, "storage-migrate-get", "scoped");
case!(migrate_get_status_mutant, "storage-migrate-get", "success-status-mutant");
