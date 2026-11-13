//! Frozen-Go CalDAV HTTP oracle (#426). No Go upstream during replay.
mod caldav_oracle;
mod common;

#[tokio::test]
async fn options_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "success", None).await
}

#[tokio::test]
async fn propfind_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "success", None).await
}

#[tokio::test]
async fn propfind_properties() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "properties", None).await
}

#[tokio::test]
async fn propfind_timezone_owned() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "timezone-owned", None).await
}

#[tokio::test]
async fn propfind_timezone_foreign() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "timezone-foreign", None).await
}

#[tokio::test]
async fn get_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "success", None).await
}

#[tokio::test]
async fn get_todo() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "todo", None).await
}

#[tokio::test]
async fn get_journal() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "journal", None).await
}

#[tokio::test]
async fn get_all_day() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "all-day", None).await
}

#[tokio::test]
async fn get_timezone() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "timezone", None).await
}

#[tokio::test]
async fn get_recurring() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "recurring", None).await
}

#[tokio::test]
async fn get_fold() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "fold", None).await
}

#[tokio::test]
async fn report_query_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "success", None).await
}

#[tokio::test]
async fn report_query_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "cross-tenant", None).await
}

#[tokio::test]
async fn report_query_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "invalid-input", None).await
}

#[tokio::test]
async fn report_multiget_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "success", None).await
}

#[tokio::test]
async fn report_multiget_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "cross-tenant", None).await
}

#[tokio::test]
async fn report_multiget_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "invalid-input", None).await
}

#[tokio::test]
async fn report_freebusy_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "success", None).await
}

#[tokio::test]
async fn report_freebusy_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "cross-tenant", None).await
}

#[tokio::test]
async fn report_freebusy_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "invalid-input", None).await
}

#[tokio::test]
async fn report_sync_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "success", None).await
}

#[tokio::test]
async fn report_sync_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "cross-tenant", None).await
}

#[tokio::test]
async fn report_sync_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "invalid-input", None).await
}

#[tokio::test]
async fn reads_get_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "cross-tenant", None).await
}

#[tokio::test]
async fn reads_get_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "invalid-input", None).await
}

#[tokio::test]
async fn reads_options_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "cross-tenant", None).await
}

#[tokio::test]
async fn reads_options_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "invalid-input", None).await
}

#[tokio::test]
async fn reads_propfind_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "cross-tenant", None).await
}

#[tokio::test]
async fn reads_propfind_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "invalid-input", None).await
}

#[tokio::test]
async fn reads_propfind_members() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "members", None).await
}

#[tokio::test]
async fn reads_propfind_event() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "event", None).await
}

#[tokio::test]
async fn reads_propfind_length() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "length", None).await
}

#[tokio::test]
async fn put_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", None).await
}

#[tokio::test]
async fn put_more_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "cross-tenant", None).await
}

#[tokio::test]
async fn put_more_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "invalid-input", None).await
}

#[tokio::test]
async fn put_more_update() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "update", None).await
}

#[tokio::test]
async fn put_more_repeat() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "repeat", None).await
}

#[tokio::test]
async fn put_more_if_none() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "if-none", None).await
}

#[tokio::test]
async fn put_more_if_match() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "if-match", None).await
}

#[tokio::test]
async fn put_more_if_match_create() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "if-match-create", None).await
}

#[tokio::test]
async fn put_more_uid_mismatch() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "uid-mismatch", None).await
}

#[tokio::test]
async fn put_more_bad_path() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "bad-path", None).await
}

#[tokio::test]
async fn put_more_todo() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "todo", None).await
}

#[tokio::test]
async fn put_more_journal() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "journal", None).await
}

#[tokio::test]
async fn put_more_attendees() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "attendees", None).await
}

#[tokio::test]
async fn put_more_recurring() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "recurring", None).await
}

#[tokio::test]
async fn writes_delete_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "success", None).await
}

#[tokio::test]
async fn writes_delete_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "cross-tenant", None).await
}

#[tokio::test]
async fn writes_delete_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "invalid-input", None).await
}

#[tokio::test]
async fn writes_delete_if_match() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "if-match", None).await
}

#[tokio::test]
async fn writes_delete_repeat() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "repeat", None).await
}

#[tokio::test]
async fn writes_mkcalendar_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "success", None).await
}

#[tokio::test]
async fn writes_mkcalendar_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "cross-tenant", None).await
}

#[tokio::test]
async fn writes_mkcalendar_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "invalid-input", None).await
}

#[tokio::test]
async fn writes_unsupported_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "success", None).await
}

#[tokio::test]
async fn writes_unsupported_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "cross-tenant", None).await
}

#[tokio::test]
async fn writes_unsupported_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "invalid-input", None).await
}

#[tokio::test]
async fn writes_head_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("head", "success", None).await
}

#[tokio::test]
async fn hardening_get_encoded() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "encoded", None).await
}

#[tokio::test]
async fn hardening_put_todo_date() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "todo-date", None).await
}

#[tokio::test]
async fn hardening_put_recurrence_invalid() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "recurrence-invalid", None).await
}

#[tokio::test]
async fn hardening_put_recurrence_parameters() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "recurrence-parameters", None).await
}

#[tokio::test]
async fn hardening_propfind_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind-limit", "invalid-input", None).await
}

#[tokio::test]
async fn hardening_report_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("report-limit", "invalid-input", None).await
}

#[tokio::test]
async fn hardening_put_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("put-limit", "invalid-input", None).await
}

#[tokio::test]
async fn hardening_mkcalendar_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar-limit", "invalid-input", None).await
}

#[tokio::test]
async fn calendar_entitlement_denied() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "denied", None).await
}

#[tokio::test]
async fn timezone_cache_lifecycle() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "timezone-cache", None).await
}

#[tokio::test]
async fn mutants_reject_no_audit() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "denied", Some("no-audit")).await
}

#[tokio::test]
async fn mutants_reject_no_notify() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("no-notify")).await
}

#[tokio::test]
async fn mutants_reject_no_tenant_filter() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "cross-tenant", Some("no-tenant-filter")).await
}

#[tokio::test]
async fn mutants_reject_double_bump() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("double-bump")).await
}

#[tokio::test]
async fn recovery_before_commit() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("commit-before")).await
}
#[tokio::test]
async fn recovery_after_commit() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("commit-after")).await
}

#[tokio::test]
async fn real_client_sessions() -> Result<(), common::BoxError> {
    caldav_oracle::run("session", "python-caldav", None).await
}

#[tokio::test]
async fn executable_client_sessions() -> Result<(), common::BoxError> {
    caldav_oracle::run("executable", "python-caldav", None).await
}

#[tokio::test]
async fn entitlement_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "cross-tenant", None).await
}
#[tokio::test]
async fn entitlement_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "invalid-input", None).await
}

#[tokio::test]
async fn status_mutant_options() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_propfind() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_get() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_query() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_multiget() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_freebusy() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_sync() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_put() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_delete() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_mkcalendar() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_unsupported() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_entitlement() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "denied", Some("status")).await
}
