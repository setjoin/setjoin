//! F08 slice `terms-remaining`, group `terms`: the admin terms-of-use editor, replayed
//! without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::terms::run($action, $kind, None).await
        }
    };
}

case!(list_success, "terms-list", "success");
case!(list_empty, "terms-list", "empty");
case!(list_denied, "terms-list", "denied");
case!(list_scoped, "terms-list", "scoped");
case!(list_limit_one, "terms-list", "limit-one");
case!(list_limit_two, "terms-list", "limit-two");
case!(list_limit_big, "terms-list", "limit-big");
case!(list_limit_bad, "terms-list", "limit-bad");
case!(list_limit_zero, "terms-list", "limit-zero");
case!(list_limit_negative, "terms-list", "limit-negative");
case!(list_limit_padded, "terms-list", "limit-padded");
case!(list_ignored_query, "terms-list", "ignored-query");
case!(list_escaping, "terms-list", "escaping");
case!(list_status_mutant, "terms-list", "success-status-mutant");

case!(create_success, "terms-create", "success");
case!(create_repeat, "terms-create", "repeat");
case!(create_default_lang, "terms-create", "default-lang");
case!(create_flags_off, "terms-create", "flags-off");
case!(create_denied, "terms-create", "denied");
case!(create_scoped, "terms-create", "scoped");
case!(create_bad_json, "terms-create", "bad-json");
case!(create_empty_body, "terms-create", "empty-body");
case!(create_null_body, "terms-create", "null-body");
case!(create_array_body, "terms-create", "array-body");
case!(create_string_body, "terms-create", "string-body");
case!(create_missing_name, "terms-create", "missing-name");
case!(create_missing_body, "terms-create", "missing-body");
case!(create_empty_name, "terms-create", "empty-name");
case!(create_version_zero, "terms-create", "version-zero");
case!(create_version_missing, "terms-create", "version-missing");
case!(create_version_negative, "terms-create", "version-negative");
case!(create_version_float, "terms-create", "version-float");
case!(create_version_whole_float, "terms-create", "version-whole-float");
case!(create_version_exponent, "terms-create", "version-exponent");
case!(create_version_string, "terms-create", "version-string");
case!(create_version_null, "terms-create", "version-null");
case!(create_version_overflow, "terms-create", "version-overflow");
case!(create_version_max_int, "terms-create", "version-max-int");
case!(create_version_huge, "terms-create", "version-huge");
case!(create_unknown_key, "terms-create", "unknown-key");
case!(create_folded, "terms-create", "folded");
case!(create_duplicate_key, "terms-create", "duplicate-key");
case!(create_null_field_keeps, "terms-create", "null-field-keeps");
case!(create_flag_string, "terms-create", "flag-string");
case!(create_name_number, "terms-create", "name-number");
case!(create_nul_name, "terms-create", "nul-name");
case!(create_escaped, "terms-create", "escaped");
case!(create_trailing_data, "terms-create", "trailing-data");
case!(create_trailing_junk, "terms-create", "trailing-junk");
case!(create_duplicate, "terms-create", "duplicate");
case!(create_same_name_other_lang, "terms-create", "same-name-other-lang");
case!(create_oversize, "terms-create", "oversize");
case!(create_status_mutant, "terms-create", "success-status-mutant");

case!(update_success, "terms-update", "success");
case!(update_repeat, "terms-update", "repeat");
case!(update_denied, "terms-update", "denied");
case!(update_scoped, "terms-update", "scoped");
case!(update_missing, "terms-update", "missing");
case!(update_zero_id, "terms-update", "zero-id");
case!(update_negative_id, "terms-update", "negative-id");
case!(update_plus_id, "terms-update", "plus-id");
case!(update_padded_id, "terms-update", "padded-id");
case!(update_bad_id, "terms-update", "bad-id");
case!(update_float_id, "terms-update", "float-id");
case!(update_huge_id, "terms-update", "huge-id");
case!(update_bad_id_bad_json, "terms-update", "bad-id-bad-json");
case!(update_missing_bad_body, "terms-update", "missing-bad-body");
case!(update_missing_version_overflow, "terms-update", "missing-version-overflow");
case!(update_bad_json, "terms-update", "bad-json");
case!(update_null_body, "terms-update", "null-body");
case!(update_array_body, "terms-update", "array-body");
case!(update_empty_body, "terms-update", "empty-body");
case!(update_missing_body, "terms-update", "missing-body");
case!(update_version_zero, "terms-update", "version-zero");
case!(update_version_float, "terms-update", "version-float");
case!(update_version_overflow, "terms-update", "version-overflow");
case!(update_default_lang, "terms-update", "default-lang");
case!(update_folded, "terms-update", "folded");
case!(update_unknown_key, "terms-update", "unknown-key");
case!(update_null_field_keeps, "terms-update", "null-field-keeps");
case!(update_duplicate, "terms-update", "duplicate");
case!(update_same_values, "terms-update", "same-values");
case!(update_others_untouched, "terms-update", "others-untouched");
case!(update_status_mutant, "terms-update", "success-status-mutant");

case!(delete_success, "terms-delete", "success");
case!(delete_repeat, "terms-delete", "repeat");
case!(delete_denied, "terms-delete", "denied");
case!(delete_scoped, "terms-delete", "scoped");
case!(delete_missing, "terms-delete", "missing");
case!(delete_zero_id, "terms-delete", "zero-id");
case!(delete_negative_id, "terms-delete", "negative-id");
case!(delete_plus_id, "terms-delete", "plus-id");
case!(delete_padded_id, "terms-delete", "padded-id");
case!(delete_bad_id, "terms-delete", "bad-id");
case!(delete_float_id, "terms-delete", "float-id");
case!(delete_huge_id, "terms-delete", "huge-id");
case!(delete_others_untouched, "terms-delete", "others-untouched");
case!(delete_status_mutant, "terms-delete", "success-status-mutant");
