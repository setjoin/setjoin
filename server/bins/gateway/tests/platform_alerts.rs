//! F08 slice `terms-remaining`, group `alerts`: health alerts and their configuration, replayed
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

case!(list_scan_failure_first, "alerts-list", "scan-failure-first");
case!(
    list_scan_failure_middle,
    "alerts-list",
    "scan-failure-middle"
);
case!(list_success, "alerts-list", "success");
case!(list_empty, "alerts-list", "empty");
case!(list_denied, "alerts-list", "denied");
case!(list_scoped, "alerts-list", "scoped");
case!(list_ignored_query, "alerts-list", "ignored-query");
case!(list_minio_streak, "alerts-list", "minio-streak");

case!(ack_success, "alerts-ack", "success");
case!(ack_denied, "alerts-ack", "denied");
case!(ack_scoped, "alerts-ack", "scoped");
case!(ack_repeat, "alerts-ack", "repeat");

case!(unsuppress_success, "alerts-unsuppress", "success");
case!(unsuppress_denied, "alerts-unsuppress", "denied");
case!(unsuppress_scoped, "alerts-unsuppress", "scoped");
case!(unsuppress_repeat, "alerts-unsuppress", "repeat");

case!(ack_existing, "alerts-ack", "existing");

case!(unsuppress_existing, "alerts-unsuppress", "existing");

case!(ack_held, "alerts-ack", "held");

case!(unsuppress_held, "alerts-unsuppress", "held");

case!(ack_folded, "alerts-ack", "folded");

case!(unsuppress_folded, "alerts-unsuppress", "folded");

case!(ack_unknown_key, "alerts-ack", "unknown-key");

case!(unsuppress_unknown_key, "alerts-unsuppress", "unknown-key");

case!(ack_duplicate_key, "alerts-ack", "duplicate-key");

case!(
    unsuppress_duplicate_key,
    "alerts-unsuppress",
    "duplicate-key"
);

case!(ack_trailing_data, "alerts-ack", "trailing-data");

case!(
    unsuppress_trailing_data,
    "alerts-unsuppress",
    "trailing-data"
);

case!(ack_trailing_junk, "alerts-ack", "trailing-junk");

case!(
    unsuppress_trailing_junk,
    "alerts-unsuppress",
    "trailing-junk"
);

case!(ack_escaped, "alerts-ack", "escaped");

case!(unsuppress_escaped, "alerts-unsuppress", "escaped");

case!(ack_long_name, "alerts-ack", "long-name");

case!(unsuppress_long_name, "alerts-unsuppress", "long-name");

case!(ack_bad_json, "alerts-ack", "bad-json");

case!(unsuppress_bad_json, "alerts-unsuppress", "bad-json");

case!(ack_empty_body, "alerts-ack", "empty-body");

case!(unsuppress_empty_body, "alerts-unsuppress", "empty-body");

case!(ack_null_body, "alerts-ack", "null-body");

case!(unsuppress_null_body, "alerts-unsuppress", "null-body");

case!(ack_array_body, "alerts-ack", "array-body");

case!(unsuppress_array_body, "alerts-unsuppress", "array-body");

case!(ack_string_body, "alerts-ack", "string-body");

case!(unsuppress_string_body, "alerts-unsuppress", "string-body");

case!(ack_missing, "alerts-ack", "missing");

case!(unsuppress_missing, "alerts-unsuppress", "missing");

case!(ack_empty_name, "alerts-ack", "empty-name");

case!(unsuppress_empty_name, "alerts-unsuppress", "empty-name");

case!(ack_null_name, "alerts-ack", "null-name");

case!(unsuppress_null_name, "alerts-unsuppress", "null-name");

case!(ack_number_name, "alerts-ack", "number-name");

case!(unsuppress_number_name, "alerts-unsuppress", "number-name");

case!(ack_nul_name, "alerts-ack", "nul-name");

case!(unsuppress_nul_name, "alerts-unsuppress", "nul-name");

case!(ack_null_then_value, "alerts-ack", "null-then-value");

case!(
    unsuppress_null_then_value,
    "alerts-unsuppress",
    "null-then-value"
);

case!(ack_value_then_null, "alerts-ack", "value-then-null");

case!(
    unsuppress_value_then_null,
    "alerts-unsuppress",
    "value-then-null"
);

case!(config_get_success, "alerts-config-get", "success");
case!(config_get_denied, "alerts-config-get", "denied");
case!(config_get_scoped, "alerts-config-get", "scoped");
case!(
    config_get_defaults_only,
    "alerts-config-get",
    "defaults-only"
);
case!(
    config_get_ignored_query,
    "alerts-config-get",
    "ignored-query"
);

case!(config_set_success, "alerts-config-set", "success");
case!(config_set_denied, "alerts-config-set", "denied");
case!(config_set_scoped, "alerts-config-set", "scoped");
case!(config_set_repeat, "alerts-config-set", "repeat");
case!(config_set_numbers, "alerts-config-set", "numbers");
case!(config_set_structures, "alerts-config-set", "structures");
case!(config_set_empty_object, "alerts-config-set", "empty-object");
case!(config_set_null_body, "alerts-config-set", "null-body");
case!(
    config_set_overwrite_defaults,
    "alerts-config-set",
    "overwrite-defaults"
);
case!(
    config_set_duplicate_key,
    "alerts-config-set",
    "duplicate-key"
);
case!(config_set_bad_key, "alerts-config-set", "bad-key");
case!(
    config_set_mixed_bad_key,
    "alerts-config-set",
    "mixed-bad-key"
);
case!(
    config_set_uppercase_prefix,
    "alerts-config-set",
    "uppercase-prefix"
);
case!(config_set_prefix_only, "alerts-config-set", "prefix-only");
case!(config_set_empty_key, "alerts-config-set", "empty-key");
case!(
    config_set_similar_prefix,
    "alerts-config-set",
    "similar-prefix"
);
case!(
    config_set_folded_key_not_allowed,
    "alerts-config-set",
    "folded-key-not-allowed"
);
case!(config_set_bad_json, "alerts-config-set", "bad-json");
case!(config_set_empty_body, "alerts-config-set", "empty-body");
case!(config_set_array_body, "alerts-config-set", "array-body");
case!(config_set_string_body, "alerts-config-set", "string-body");
case!(config_set_number_body, "alerts-config-set", "number-body");
case!(config_set_huge_number, "alerts-config-set", "huge-number");
case!(config_set_nul_key, "alerts-config-set", "nul-key");
case!(config_set_nul_value, "alerts-config-set", "nul-value");
case!(
    config_set_trailing_data,
    "alerts-config-set",
    "trailing-data"
);
case!(
    config_set_trailing_junk,
    "alerts-config-set",
    "trailing-junk"
);
case!(
    config_set_atomic_failure,
    "alerts-config-set",
    "atomic-failure"
);
case!(config_set_large_value, "alerts-config-set", "large-value");

case!(list_status_mutant, "alerts-list", "success-status-mutant");
case!(ack_status_mutant, "alerts-ack", "success-status-mutant");
case!(
    unsuppress_status_mutant,
    "alerts-unsuppress",
    "success-status-mutant"
);
case!(
    config_get_status_mutant,
    "alerts-config-get",
    "success-status-mutant"
);
case!(
    config_set_status_mutant,
    "alerts-config-set",
    "success-status-mutant"
);
