//! F08 slice `system-features`, group `sysconf` (welcome-email, jit-defaults, auth-methods): frozen-Go oracle replayed without a Go upstream.
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

case!(wget_success, "welcome-get", "success");
case!(wget_shell, "welcome-get", "shell");
case!(wget_denied, "welcome-get", "denied");
case!(wget_scoped, "welcome-get", "scoped");
case!(wget_ignored_query, "welcome-get", "ignored-query");
case!(wget_status_mutant, "welcome-get", "success-status-mutant");

case!(wput_success, "welcome-put", "success");
case!(wput_repeat, "welcome-put", "repeat");
case!(wput_full, "welcome-put", "full");
case!(wput_folded, "welcome-put", "folded");
case!(wput_bad_default, "welcome-put", "bad-default");
case!(wput_no_en, "welcome-put", "no-en");
case!(wput_empty_subject, "welcome-put", "empty-subject");
case!(wput_empty_text, "welcome-put", "empty-text");
case!(wput_unknown_locale, "welcome-put", "unknown-locale");
case!(wput_null_locales, "welcome-put", "null-locales");
case!(wput_bad_json, "welcome-put", "bad-json");
case!(wput_array, "welcome-put", "array");
case!(wput_typed, "welcome-put", "typed");
case!(wput_oversize, "welcome-put", "oversize");
case!(wput_denied, "welcome-put", "denied");
case!(wput_scoped, "welcome-put", "scoped");
case!(wput_status_mutant, "welcome-put", "success-status-mutant");

case!(wtest_success, "welcome-test", "success");
case!(wtest_repeat, "welcome-test", "repeat");
case!(wtest_placeholders, "welcome-test", "placeholders");
case!(wtest_folded, "welcome-test", "folded");
case!(wtest_no_subject, "welcome-test", "no-subject");
case!(wtest_no_text, "welcome-test", "no-text");
case!(wtest_bad_json, "welcome-test", "bad-json");
case!(wtest_typed, "welcome-test", "typed");
case!(wtest_oversize, "welcome-test", "oversize");
case!(wtest_denied, "welcome-test", "denied");
case!(wtest_scoped, "welcome-test", "scoped");
case!(wtest_status_mutant, "welcome-test", "success-status-mutant");

case!(jget_success, "jit-get", "success");
case!(jget_defaults, "jit-get", "defaults");
case!(jget_denied, "jit-get", "denied");
case!(jget_scoped, "jit-get", "scoped");
case!(jget_ignored_query, "jit-get", "ignored-query");
case!(jget_status_mutant, "jit-get", "success-status-mutant");

case!(jput_success, "jit-put", "success");
case!(jput_repeat, "jit-put", "repeat");
case!(jput_no_justification, "jit-put", "no-justification");
case!(jput_folded, "jit-put", "folded");
case!(jput_zero, "jit-put", "zero");
case!(jput_negative, "jit-put", "negative");
case!(jput_bad_json, "jit-put", "bad-json");
case!(jput_overflow, "jit-put", "overflow");
case!(jput_typed, "jit-put", "typed");
case!(jput_float, "jit-put", "float");
case!(jput_oversize, "jit-put", "oversize");
case!(jput_denied, "jit-put", "denied");
case!(jput_scoped, "jit-put", "scoped");
case!(jput_status_mutant, "jit-put", "success-status-mutant");

case!(alist_success, "auth-list", "success");
case!(alist_denied, "auth-list", "denied");
case!(alist_scoped, "auth-list", "scoped");
case!(alist_ignored_query, "auth-list", "ignored-query");
case!(alist_status_mutant, "auth-list", "success-status-mutant");

case!(aupd_success, "auth-update", "success");
case!(aupd_repeat, "auth-update", "repeat");
case!(aupd_priority, "auth-update", "priority");
case!(aupd_config, "auth-update", "config");
case!(aupd_config_null, "auth-update", "config-null");
case!(aupd_all, "auth-update", "all");
case!(aupd_folded, "auth-update", "folded");
case!(aupd_empty, "auth-update", "empty");
case!(aupd_null_fields, "auth-update", "null-fields");
case!(aupd_bad_json, "auth-update", "bad-json");
case!(aupd_typed, "auth-update", "typed");
case!(aupd_overflow, "auth-update", "overflow");
case!(aupd_float, "auth-update", "float");
case!(aupd_missing_slug, "auth-update", "missing-slug");
case!(aupd_denied, "auth-update", "denied");
case!(aupd_scoped, "auth-update", "scoped");
case!(aupd_status_mutant, "auth-update", "success-status-mutant");
