//! F08 slice `system-features`, group `config`: frozen-Go oracle replayed without a Go upstream.
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

case!(list_success, "config-list", "success");
case!(list_all, "config-list", "all");
case!(list_like, "config-list", "like");
case!(list_none, "config-list", "none");
case!(list_denied, "config-list", "denied");
case!(list_scoped, "config-list", "scoped");
case!(list_ignored_query, "config-list", "ignored-query");
case!(list_status_mutant, "config-list", "success-status-mutant");

case!(get_success, "config-get", "success");
case!(get_string, "config-get", "string");
case!(get_number, "config-get", "number");
case!(get_secret, "config-get", "secret");
case!(get_suffix, "config-get", "suffix");
case!(get_named, "config-get", "named");
case!(get_null, "config-get", "null");
case!(get_missing, "config-get", "missing");
case!(get_denied, "config-get", "denied");
case!(get_scoped, "config-get", "scoped");
case!(get_status_mutant, "config-get", "success-status-mutant");

case!(set_success, "config-set", "success");
case!(set_repeat, "config-set", "repeat");
case!(set_overwrite, "config-set", "overwrite");
case!(set_encrypted, "config-set", "encrypted");
case!(set_null_value, "config-set", "null-value");
case!(set_folded, "config-set", "folded");
case!(set_bool_upper, "config-set", "bool-upper");
case!(set_bool_json, "config-set", "bool-json");
case!(set_denied, "config-set", "denied");
case!(set_scoped, "config-set", "scoped");
case!(set_not_writable, "config-set", "not-writable");
case!(set_bad_json, "config-set", "bad-json");
case!(set_array_body, "config-set", "array-body");
case!(set_bad_bool, "config-set", "bad-bool");
case!(set_no_bool, "config-set", "no-bool");
case!(set_no_value, "config-set", "no-value");
case!(set_oversize, "config-set", "oversize");
case!(set_typed_encrypted, "config-set", "typed-encrypted");
case!(set_status_mutant, "config-set", "success-status-mutant");

case!(export_success, "config-export", "success");
case!(export_denied, "config-export", "denied");
case!(export_scoped, "config-export", "scoped");
case!(export_ignored_query, "config-export", "ignored-query");
case!(
    export_status_mutant,
    "config-export",
    "success-status-mutant"
);

case!(import_success, "config-import", "success");
case!(import_repeat, "config-import", "repeat");
case!(import_denied, "config-import", "denied");
case!(import_scoped, "config-import", "scoped");
case!(import_disallowed, "config-import", "disallowed");
case!(import_bad_json, "config-import", "bad-json");
case!(import_not_array, "config-import", "not-array");
case!(import_empty_body, "config-import", "empty-body");
case!(import_bare_item, "config-import", "bare-item");
case!(import_missing_comma, "config-import", "missing-comma");
case!(import_trailing_comma, "config-import", "trailing-comma");
case!(import_unterminated, "config-import", "unterminated");
case!(import_too_many, "config-import", "too-many");
case!(import_oversize, "config-import", "oversize");
case!(import_folded, "config-import", "folded");
case!(import_null_only, "config-import", "null-only");
case!(import_empty_array, "config-import", "empty-array");
case!(import_trailing_data, "config-import", "trailing-data");
case!(import_description_null, "config-import", "description-null");
case!(
    import_status_mutant,
    "config-import",
    "success-status-mutant"
);
