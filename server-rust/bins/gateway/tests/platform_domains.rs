//! F08 slice `terms-remaining`, group `domains`: the admin email-domain editor, replayed
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

case!(list_success, "domains-list", "success");
case!(list_denied, "domains-list", "denied");
case!(list_scoped, "domains-list", "scoped");
case!(list_scoped_own, "domains-list", "scoped-own");
case!(list_ignored_query, "domains-list", "ignored-query");

case!(get_success, "domains-get", "success");
case!(get_denied, "domains-get", "denied");
case!(get_scoped, "domains-get", "scoped");
case!(get_scoped_own, "domains-get", "scoped-own");
case!(get_own_null_columns, "domains-get", "own-null-columns");
case!(get_plain_null_columns, "domains-get", "plain-null-columns");
case!(get_primary, "domains-get", "primary");
case!(get_empty_strings, "domains-get", "empty-strings");
case!(get_missing, "domains-get", "missing");
case!(get_zero, "domains-get", "zero");
case!(get_negative, "domains-get", "negative");
case!(get_plus, "domains-get", "plus");
case!(get_padded, "domains-get", "padded");
case!(get_word, "domains-get", "word");
case!(get_float, "domains-get", "float");
case!(get_huge, "domains-get", "huge");
case!(get_ignored_query, "domains-get", "ignored-query");

case!(create_success, "domains-create", "success");
case!(create_denied, "domains-create", "denied");
case!(create_scoped, "domains-create", "scoped");
case!(create_repeat, "domains-create", "repeat");
case!(create_defaults, "domains-create", "defaults");
case!(create_primary, "domains-create", "primary");
case!(
    create_primary_conflict,
    "domains-create",
    "primary-conflict"
);
case!(create_duplicate, "domains-create", "duplicate");
case!(create_duplicate_case, "domains-create", "duplicate-case");
case!(create_canonical, "domains-create", "canonical");
case!(create_folded, "domains-create", "folded");
case!(create_duplicate_key, "domains-create", "duplicate-key");
case!(create_null_fields, "domains-create", "null-fields");
case!(create_unknown_key, "domains-create", "unknown-key");
case!(create_max_zero, "domains-create", "max-zero");
case!(create_max_negative, "domains-create", "max-negative");
case!(create_empty_policies, "domains-create", "empty-policies");
case!(create_bad_dmarc, "domains-create", "bad-dmarc");
case!(create_bad_mta, "domains-create", "bad-mta");
case!(create_numeric_tld, "domains-create", "numeric-tld");
case!(create_bad_json, "domains-create", "bad-json");
case!(create_empty_body, "domains-create", "empty-body");
case!(create_null_body, "domains-create", "null-body");
case!(create_array_body, "domains-create", "array-body");
case!(create_string_body, "domains-create", "string-body");
case!(create_missing_name, "domains-create", "missing-name");
case!(create_empty_name, "domains-create", "empty-name");
case!(create_blank_name, "domains-create", "blank-name");
case!(create_name_number, "domains-create", "name-number");
case!(create_no_dot, "domains-create", "no-dot");
case!(create_bad_char, "domains-create", "bad-char");
case!(create_hyphen_edge, "domains-create", "hyphen-edge");
case!(create_hyphen_trail, "domains-create", "hyphen-trail");
case!(create_empty_label, "domains-create", "empty-label");
case!(create_trailing_dot, "domains-create", "trailing-dot");
case!(create_long_label, "domains-create", "long-label");
case!(create_long_name, "domains-create", "long-name");
case!(create_control_char, "domains-create", "control-char");
case!(create_unicode, "domains-create", "unicode");
case!(
    create_turkish_dotted_i,
    "domains-create",
    "turkish-dotted-i"
);
case!(create_kelvin, "domains-create", "kelvin");
case!(create_bool_string, "domains-create", "bool-string");
case!(create_max_float, "domains-create", "max-float");
case!(create_max_whole_float, "domains-create", "max-whole-float");
case!(create_max_string, "domains-create", "max-string");
case!(create_max_huge, "domains-create", "max-huge");
case!(create_quota_negative, "domains-create", "quota-negative");
case!(create_trailing_data, "domains-create", "trailing-data");
case!(create_trailing_junk, "domains-create", "trailing-junk");
case!(create_oversize, "domains-create", "oversize");

case!(update_success, "domains-update", "success");
case!(update_denied, "domains-update", "denied");
case!(update_repeat, "domains-update", "repeat");
case!(update_scoped, "domains-update", "scoped");
case!(update_scoped_own, "domains-update", "scoped-own");
case!(update_name_only, "domains-update", "name-only");
case!(update_is_local, "domains-update", "is-local");
case!(update_primary, "domains-update", "primary");
case!(
    update_primary_conflict,
    "domains-update",
    "primary-conflict"
);
case!(update_catch_all, "domains-update", "catch-all");
case!(
    update_catch_all_missing,
    "domains-update",
    "catch-all-missing"
);
case!(update_catch_all_zero, "domains-update", "catch-all-zero");
case!(update_policies, "domains-update", "policies");
case!(update_bad_dmarc, "domains-update", "bad-dmarc");
case!(update_bad_mta, "domains-update", "bad-mta");
case!(update_max_zero, "domains-update", "max-zero");
case!(update_max_negative, "domains-update", "max-negative");
case!(update_quota_zero, "domains-update", "quota-zero");
case!(update_folded, "domains-update", "folded");
case!(update_null_fields, "domains-update", "null-fields");
case!(update_null_then_value, "domains-update", "null-then-value");
case!(update_empty_strings, "domains-update", "empty-strings");
case!(
    update_empty_strings_and_int,
    "domains-update",
    "empty-strings-and-int"
);
case!(update_no_fields, "domains-update", "no-fields");
case!(update_unknown_only, "domains-update", "unknown-only");
case!(update_empty_name, "domains-update", "empty-name");
case!(update_invalid_name, "domains-update", "invalid-name");
case!(
    update_invalid_name_first,
    "domains-update",
    "invalid-name-first"
);
case!(update_duplicate_name, "domains-update", "duplicate-name");
case!(update_numeric_tld, "domains-update", "numeric-tld");
case!(update_kelvin, "domains-update", "kelvin");
case!(update_bad_json, "domains-update", "bad-json");
case!(update_empty_body, "domains-update", "empty-body");
case!(update_null_body, "domains-update", "null-body");
case!(update_array_body, "domains-update", "array-body");
case!(update_bool_string, "domains-update", "bool-string");
case!(update_max_float, "domains-update", "max-float");
case!(update_missing, "domains-update", "missing");
case!(
    update_missing_bad_body,
    "domains-update",
    "missing-bad-body"
);
case!(
    update_missing_no_fields,
    "domains-update",
    "missing-no-fields"
);
case!(update_bad_id, "domains-update", "bad-id");
case!(update_bad_id_bad_json, "domains-update", "bad-id-bad-json");
case!(update_zero_id, "domains-update", "zero-id");
case!(update_negative_id, "domains-update", "negative-id");
case!(update_plus_id, "domains-update", "plus-id");
case!(update_padded_id, "domains-update", "padded-id");
case!(update_huge_id, "domains-update", "huge-id");
case!(update_oversize, "domains-update", "oversize");
case!(
    update_others_untouched,
    "domains-update",
    "others-untouched"
);

case!(delete_success, "domains-delete", "success");
case!(delete_denied, "domains-delete", "denied");
case!(delete_repeat, "domains-delete", "repeat");
case!(
    delete_others_untouched,
    "domains-delete",
    "others-untouched"
);
case!(delete_scoped, "domains-delete", "scoped");
case!(delete_scoped_own, "domains-delete", "scoped-own");
case!(delete_missing, "domains-delete", "missing");
case!(delete_with_users, "domains-delete", "with-users");
case!(
    delete_with_cascade_rows,
    "domains-delete",
    "with-cascade-rows"
);
case!(delete_bad_id, "domains-delete", "bad-id");
case!(delete_zero_id, "domains-delete", "zero-id");
case!(delete_negative_id, "domains-delete", "negative-id");
case!(delete_plus_id, "domains-delete", "plus-id");
case!(delete_padded_id, "domains-delete", "padded-id");
case!(delete_huge_id, "domains-delete", "huge-id");

case!(list_status_mutant, "domains-list", "success-status-mutant");
case!(get_status_mutant, "domains-get", "success-status-mutant");
case!(
    create_status_mutant,
    "domains-create",
    "success-status-mutant"
);
case!(
    update_status_mutant,
    "domains-update",
    "success-status-mutant"
);
case!(
    delete_status_mutant,
    "domains-delete",
    "success-status-mutant"
);
