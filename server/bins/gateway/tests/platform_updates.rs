//! F08 slice `updates-deploy`, group `updates`: upgrade history and client update
//! management, replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::updates::run($action, $kind, None).await
        }
    };
}

case!(history_success, "updates-history", "success");
case!(history_empty, "updates-history", "empty");
case!(history_denied, "updates-history", "denied");
case!(history_scoped, "updates-history", "scoped");
case!(history_ignored_query, "updates-history", "ignored-query");
case!(history_null_downtime, "updates-history", "null-downtime");
case!(history_status_mutant, "updates-history", "success-status-mutant");

case!(summary_success, "updates-summary", "success");
case!(summary_empty, "updates-summary", "empty");
case!(summary_denied, "updates-summary", "denied");
case!(summary_scoped, "updates-summary", "scoped");
case!(summary_ignored_query, "updates-summary", "ignored-query");
case!(summary_null_platform, "updates-summary", "null-platform");
case!(summary_status_mutant, "updates-summary", "success-status-mutant");

case!(devices_success, "updates-devices", "success");
case!(devices_empty, "updates-devices", "empty");
case!(devices_denied, "updates-devices", "denied");
case!(devices_scoped, "updates-devices", "scoped");
case!(devices_null_seen, "updates-devices", "null-seen");
case!(devices_null_name, "updates-devices", "null-name");
case!(devices_null_os, "updates-devices", "null-os");
case!(devices_paging, "updates-devices", "paging");
case!(devices_bad_paging, "updates-devices", "bad-paging");
case!(devices_big_limit, "updates-devices", "big-limit");
case!(devices_huge_offset, "updates-devices", "huge-offset");
case!(devices_ignored_query, "updates-devices", "ignored-query");
case!(devices_status_mutant, "updates-devices", "success-status-mutant");

case!(push_success, "updates-push", "success");
case!(push_repeat, "updates-push", "repeat");
case!(push_denied, "updates-push", "denied");
case!(push_scoped, "updates-push", "scoped");
case!(push_bad_json, "updates-push", "bad-json");
case!(push_bad_type, "updates-push", "bad-type");
case!(push_bad_float, "updates-push", "bad-float");
case!(push_empty_ids, "updates-push", "empty-ids");
case!(push_missing, "updates-push", "missing");
case!(push_null_body, "updates-push", "null-body");
case!(push_array_body, "updates-push", "array-body");
case!(push_empty_body, "updates-push", "empty-body");
case!(push_folded, "updates-push", "folded");
case!(push_unknown_key, "updates-push", "unknown-key");
case!(push_status_mutant, "updates-push", "success-status-mutant");
