//! F08 slice `terms-remaining`, group `apps`: the curated-application console, replayed
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

case!(list_success, "apps-list", "success");
case!(list_empty, "apps-list", "empty");
case!(list_denied, "apps-list", "denied");
case!(list_scoped, "apps-list", "scoped");
case!(list_provider_only, "apps-list", "provider-only");
case!(list_manage_only, "apps-list", "manage-only");
case!(list_not_ready, "apps-list", "not-ready");
case!(list_delivery_off, "apps-list", "delivery-off");
case!(list_active_operation, "apps-list", "active-operation");
case!(list_installed, "apps-list", "installed");
case!(list_ignored_query, "apps-list", "ignored-query");
case!(list_status_mutant, "apps-list", "success-status-mutant");

case!(request_success, "apps-request", "success");
case!(request_denied, "apps-request", "denied");
case!(request_scoped, "apps-request", "scoped");
case!(request_repeat, "apps-request", "repeat");
case!(
    request_no_reason_not_required,
    "apps-request",
    "no-reason-not-required"
);
case!(request_reason_required, "apps-request", "reason-required");
case!(
    request_reason_required_present,
    "apps-request",
    "reason-required-present"
);
case!(request_unknown_app, "apps-request", "unknown-app");
case!(
    request_unknown_app_bad_body,
    "apps-request",
    "unknown-app-bad-body"
);
case!(request_bad_json, "apps-request", "bad-json");
case!(request_empty_body, "apps-request", "empty-body");
case!(request_null_body, "apps-request", "null-body");
case!(request_array_body, "apps-request", "array-body");
case!(request_unknown_field, "apps-request", "unknown-field");
case!(request_folded_keys, "apps-request", "folded-keys");
case!(request_trailing_data, "apps-request", "trailing-data");
case!(request_trailing_space, "apps-request", "trailing-space");
case!(request_oversize, "apps-request", "oversize");
case!(request_kind_number, "apps-request", "kind-number");
case!(request_generation_float, "apps-request", "generation-float");
case!(
    request_generation_string,
    "apps-request",
    "generation-string"
);
case!(request_key_mismatch, "apps-request", "key-mismatch");
case!(
    request_key_missing_header,
    "apps-request",
    "key-missing-header"
);
case!(request_key_uppercase, "apps-request", "key-uppercase");
case!(request_key_urn, "apps-request", "key-urn");
case!(request_key_empty, "apps-request", "key-empty");
case!(request_request_missing, "apps-request", "request-missing");
case!(request_request_null, "apps-request", "request-null");
case!(request_request_array, "apps-request", "request-array");
case!(request_request_string, "apps-request", "request-string");
case!(
    request_request_extra_key,
    "apps-request",
    "request-extra-key"
);
case!(
    request_request_bad_profile,
    "apps-request",
    "request-bad-profile"
);
case!(
    request_request_no_ingress,
    "apps-request",
    "request-no-ingress"
);
case!(request_request_spaced, "apps-request", "request-spaced");
case!(request_bad_kind, "apps-request", "bad-kind");
case!(request_missing_kind, "apps-request", "missing-kind");
case!(request_provider_missing, "apps-request", "provider-missing");
case!(request_provider_other, "apps-request", "provider-other");
case!(
    request_generation_mismatch,
    "apps-request",
    "generation-mismatch"
);
case!(request_provider_active, "apps-request", "provider-active");
case!(
    request_already_installed,
    "apps-request",
    "already-installed"
);
case!(request_operation_active, "apps-request", "operation-active");
case!(request_delivery_off, "apps-request", "delivery-off");
case!(
    request_replay_changed_input,
    "apps-request",
    "replay-changed-input"
);
case!(
    request_reason_whitespace,
    "apps-request",
    "reason-whitespace"
);

case!(recover_success, "apps-recover", "success");
case!(recover_denied, "apps-recover", "denied");
case!(recover_scoped, "apps-recover", "scoped");
case!(recover_repeat, "apps-recover", "repeat");
case!(recover_operation_upper, "apps-recover", "operation-upper");
case!(recover_operation_plain, "apps-recover", "operation-plain");
case!(recover_operation_urn, "apps-recover", "operation-urn");
case!(recover_operation_braced, "apps-recover", "operation-braced");
case!(recover_operation_bad, "apps-recover", "operation-bad");
case!(
    recover_operation_bad_bad_body,
    "apps-recover",
    "operation-bad-bad-body"
);
case!(recover_unknown_app, "apps-recover", "unknown-app");
case!(
    recover_unknown_app_bad_operation,
    "apps-recover",
    "unknown-app-bad-operation"
);
case!(
    recover_no_reason_not_required,
    "apps-recover",
    "no-reason-not-required"
);
case!(recover_reason_required, "apps-recover", "reason-required");
case!(recover_bad_json, "apps-recover", "bad-json");
case!(recover_empty_body, "apps-recover", "empty-body");
case!(recover_null_body, "apps-recover", "null-body");
case!(recover_array_body, "apps-recover", "array-body");
case!(recover_empty_object, "apps-recover", "empty-object");
case!(recover_unknown_field, "apps-recover", "unknown-field");
case!(recover_folded, "apps-recover", "folded");
case!(recover_generation_float, "apps-recover", "generation-float");
case!(
    recover_generation_string,
    "apps-recover",
    "generation-string"
);
case!(recover_generation_null, "apps-recover", "generation-null");
case!(recover_generation_zero, "apps-recover", "generation-zero");
case!(
    recover_generation_negative,
    "apps-recover",
    "generation-negative"
);
case!(
    recover_generation_mismatch,
    "apps-recover",
    "generation-mismatch"
);
case!(recover_trailing_data, "apps-recover", "trailing-data");
case!(recover_trailing_space, "apps-recover", "trailing-space");
case!(
    recover_operation_missing,
    "apps-recover",
    "operation-missing"
);
case!(recover_not_recoverable, "apps-recover", "not-recoverable");
case!(recover_failed_rollback, "apps-recover", "failed-rollback");

case!(
    request_status_mutant,
    "apps-request",
    "success-status-mutant"
);
case!(
    recover_status_mutant,
    "apps-recover",
    "success-status-mutant"
);
