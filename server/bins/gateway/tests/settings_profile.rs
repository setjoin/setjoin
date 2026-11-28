//! F19 slice `profile`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod settings_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            settings_oracle::run("profile", $action, $kind, None).await
        }
    };
}

case!(profile_success, "profile-update", "success");
case!(profile_repeat, "profile-update", "repeat");
case!(profile_foreign, "profile-update", "foreign");
case!(profile_bad_json, "profile-update", "bad-json");
case!(profile_array_body, "profile-update", "array-body");
case!(profile_scalar_body, "profile-update", "scalar-body");
case!(profile_empty_body, "profile-update", "empty-body");
case!(profile_null_body, "profile-update", "null-body");
case!(profile_wrong_type, "profile-update", "wrong-type");
case!(profile_null_name, "profile-update", "null-name");
case!(profile_empty, "profile-update", "empty");
case!(profile_blank, "profile-update", "blank");
case!(profile_nbsp, "profile-update", "nbsp");
case!(profile_unicode_space, "profile-update", "unicode-space");
case!(profile_padded, "profile-update", "padded");
case!(profile_too_long, "profile-update", "too-long");
case!(profile_at_limit, "profile-update", "at-limit");
case!(profile_limit_padded, "profile-update", "limit-padded");
case!(profile_html, "profile-update", "html");
case!(profile_fold, "profile-update", "fold");
case!(profile_unknown_field, "profile-update", "unknown-field");
case!(profile_duplicate, "profile-update", "duplicate");
case!(profile_trailing, "profile-update", "trailing");
case!(profile_two_values, "profile-update", "two-values");
case!(profile_nul, "profile-update", "nul");
case!(profile_emoji, "profile-update", "emoji");
case!(profile_ignored_query, "profile-update", "ignored-query");
case!(
    profile_success_status_mutant,
    "profile-update",
    "success-status-mutant"
);

case!(quota_success, "quota-get", "success");
case!(quota_foreign, "quota-get", "foreign");
case!(quota_single, "quota-get", "single");
case!(quota_zero, "quota-get", "zero");
case!(quota_overflow, "quota-get", "overflow");
case!(quota_ignored_query, "quota-get", "ignored-query");
case!(
    quota_success_status_mutant,
    "quota-get",
    "success-status-mutant"
);
