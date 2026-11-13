//! F08 slice `system-features`, group `features` (health, registry, sod-mode): frozen-Go oracle replayed without a Go upstream.
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

case!(health_success, "admin-health", "success");
case!(health_error, "admin-health", "error");
case!(health_null_details, "admin-health", "null-details");
case!(health_empty, "admin-health", "empty");
case!(health_denied, "admin-health", "denied");
case!(health_scoped, "admin-health", "scoped");
case!(health_ignored_query, "admin-health", "ignored-query");
case!(
    health_status_mutant,
    "admin-health",
    "success-status-mutant"
);

case!(flist_success, "features-list", "success");
case!(flist_enforce, "features-list", "enforce");
case!(flist_denied, "features-list", "denied");
case!(flist_scoped, "features-list", "scoped");
case!(flist_ignored_query, "features-list", "ignored-query");
case!(
    flist_status_mutant,
    "features-list",
    "success-status-mutant"
);

case!(fset_success, "features-set", "success");
case!(fset_repeat, "features-set", "repeat");
case!(fset_new_key, "features-set", "new-key");
case!(fset_off, "features-set", "off");
case!(fset_enforce_unknown, "features-set", "enforce-unknown");
case!(fset_sod_key, "features-set", "sod-key");
case!(fset_invalid_key, "features-set", "invalid-key");
case!(fset_no_reason, "features-set", "no-reason");
case!(fset_reason_area, "features-set", "reason-area");
case!(fset_long_reason, "features-set", "long-reason");
case!(fset_bad_json, "features-set", "bad-json");
case!(fset_unknown_field, "features-set", "unknown-field");
case!(fset_no_enabled, "features-set", "no-enabled");
case!(fset_null_enabled, "features-set", "null-enabled");
case!(fset_trailing, "features-set", "trailing");
case!(fset_trailing_garbage, "features-set", "trailing-garbage");
case!(fset_typed, "features-set", "typed");
case!(fset_folded, "features-set", "folded");
case!(fset_array, "features-set", "array");
case!(fset_oversize, "features-set", "oversize");
case!(fset_denied, "features-set", "denied");
case!(fset_scoped, "features-set", "scoped");
case!(fset_status_mutant, "features-set", "success-status-mutant");

case!(fdel_success, "features-delete", "success");
case!(fdel_repeat, "features-delete", "repeat");
case!(fdel_absent, "features-delete", "absent");
case!(fdel_known, "features-delete", "known");
case!(fdel_invalid_key, "features-delete", "invalid-key");
case!(fdel_no_reason, "features-delete", "no-reason");
case!(fdel_denied, "features-delete", "denied");
case!(fdel_scoped, "features-delete", "scoped");
case!(
    fdel_status_mutant,
    "features-delete",
    "success-status-mutant"
);

case!(fmode_success, "features-mode", "success");
case!(fmode_repeat, "features-mode", "repeat");
case!(fmode_enforce, "features-mode", "enforce");
case!(fmode_enforce_unknown, "features-mode", "enforce-unknown");
case!(fmode_enforce_skew, "features-mode", "enforce-skew");
case!(fmode_invalid_mode, "features-mode", "invalid-mode");
case!(fmode_empty_mode, "features-mode", "empty-mode");
case!(fmode_bad_json, "features-mode", "bad-json");
case!(fmode_unknown_field, "features-mode", "unknown-field");
case!(fmode_no_reason, "features-mode", "no-reason");
case!(fmode_denied, "features-mode", "denied");
case!(fmode_scoped, "features-mode", "scoped");
case!(
    fmode_status_mutant,
    "features-mode",
    "success-status-mutant"
);

case!(sodget_success, "sod-get", "success");
case!(sodget_clean, "sod-get", "clean");
case!(sodget_on, "sod-get", "on");
case!(sodget_denied, "sod-get", "denied");
case!(sodget_scoped, "sod-get", "scoped");
case!(sodget_ignored_query, "sod-get", "ignored-query");
case!(sodget_status_mutant, "sod-get", "success-status-mutant");

case!(sodset_success, "sod-set", "success");
case!(sodset_repeat, "sod-set", "repeat");
case!(sodset_enable_violations, "sod-set", "enable-violations");
case!(sodset_enable_clean, "sod-set", "enable-clean");
case!(sodset_reason_area, "sod-set", "reason-area");
case!(sodset_bad_json, "sod-set", "bad-json");
case!(sodset_typed, "sod-set", "typed");
case!(sodset_empty_object, "sod-set", "empty-object");
case!(sodset_folded, "sod-set", "folded");
case!(sodset_denied, "sod-set", "denied");
case!(sodset_scoped, "sod-set", "scoped");
case!(sodset_status_mutant, "sod-set", "success-status-mutant");
