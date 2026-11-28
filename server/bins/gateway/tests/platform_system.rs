//! F08 slice `system-features`, group `system`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(version_success, "version", "success");
case!(version_denied, "version", "denied");
case!(version_scoped, "version", "scoped");
case!(version_ignored_query, "version", "ignored-query");
case!(version_status_mutant, "version", "success-status-mutant");

case!(schema_version_success, "schema-version", "success");
case!(schema_version_pending, "schema-version", "pending");
case!(schema_version_denied, "schema-version", "denied");
case!(
    schema_version_ignored_query,
    "schema-version",
    "ignored-query"
);
case!(
    schema_version_status_mutant,
    "schema-version",
    "success-status-mutant"
);

case!(status_success, "status", "success");
case!(status_denied, "status", "denied");
case!(status_ignored_query, "status", "ignored-query");
case!(status_status_mutant, "status", "success-status-mutant");

case!(health_success, "health", "success");
case!(health_denied, "health", "denied");
case!(health_ignored_query, "health", "ignored-query");
case!(health_status_mutant, "health", "success-status-mutant");

case!(backup_list_success, "backup-list", "success");
case!(backup_list_empty, "backup-list", "empty");
case!(backup_list_denied, "backup-list", "denied");
case!(backup_list_scoped, "backup-list", "scoped");
case!(backup_list_ignored_query, "backup-list", "ignored-query");
case!(
    backup_list_status_mutant,
    "backup-list",
    "success-status-mutant"
);
fault!(
    backup_list_no_tenant_filter_fault,
    "backup-list",
    "success",
    "no-tenant-filter"
);

case!(backup_enqueue_success, "backup-enqueue", "success");
case!(backup_enqueue_repeat, "backup-enqueue", "repeat");
case!(backup_enqueue_denied, "backup-enqueue", "denied");
case!(backup_enqueue_bad_body, "backup-enqueue", "bad-body");
case!(
    backup_enqueue_status_mutant,
    "backup-enqueue",
    "success-status-mutant"
);
fault!(
    backup_enqueue_no_notify_fault,
    "backup-enqueue",
    "success",
    "no-notify"
);
fault!(
    backup_enqueue_double_bump_fault,
    "backup-enqueue",
    "success",
    "double-bump"
);
fault!(
    backup_enqueue_no_audit_fault,
    "backup-enqueue",
    "denied",
    "no-audit"
);

case!(backup_download_success, "backup-download", "success");
case!(backup_download_denied, "backup-download", "denied");
case!(
    backup_download_ignored_query,
    "backup-download",
    "ignored-query"
);
case!(
    backup_download_status_mutant,
    "backup-download",
    "success-status-mutant"
);

case!(backup_delete_success, "backup-delete", "success");
case!(backup_delete_denied, "backup-delete", "denied");
case!(
    backup_delete_ignored_query,
    "backup-delete",
    "ignored-query"
);
case!(
    backup_delete_status_mutant,
    "backup-delete",
    "success-status-mutant"
);
