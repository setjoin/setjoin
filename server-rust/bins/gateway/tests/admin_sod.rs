//! F01 slice `sod` frozen-Go oracle, replayed without a Go upstream.
mod admin_sod_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_sod_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_sod_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(my_roles_success, "my-roles", "success");
case!(my_roles_foreign, "my-roles", "foreign");
case!(my_roles_configured, "my-roles", "configured");
case!(my_roles_configured_array, "my-roles", "configured-array");
case!(my_roles_cold_start, "my-roles", "cold-start");
case!(my_roles_ignored_query, "my-roles", "ignored-query");
case!(my_roles_status_mutant, "my-roles", "success-status-mutant");

case!(activate_success, "activate", "success");
case!(activate_repeat, "activate", "repeat");
case!(activate_cold_start, "activate", "cold-start");
case!(activate_clamp, "activate", "clamp");
case!(activate_cap, "activate", "cap");
case!(activate_fallback_clamp, "activate", "fallback-clamp");
case!(activate_configured, "activate", "configured");
case!(activate_configured_array, "activate", "configured-array");
case!(activate_foreign, "activate", "foreign");
case!(activate_not_eligible, "activate", "not-eligible");
case!(activate_unknown_role, "activate", "unknown-role");
case!(activate_toggle_off, "activate", "toggle-off");
case!(
    activate_justification_required,
    "activate",
    "justification-required"
);
case!(
    activate_blank_justification,
    "activate",
    "blank-justification"
);
case!(
    activate_empty_justification,
    "activate",
    "empty-justification"
);
case!(activate_justified, "activate", "justified");
case!(activate_bad_json, "activate", "bad-json");
case!(activate_zero, "activate", "zero");
case!(activate_negative, "activate", "negative");
case!(activate_required, "activate", "required");
case!(activate_typed, "activate", "typed");
case!(activate_fractional, "activate", "fractional");
case!(activate_null_body, "activate", "null-body");
case!(activate_huge, "activate", "huge");
case!(activate_folded, "activate", "folded");
case!(activate_padded, "activate", "padded");
case!(activate_oversize, "activate", "oversize");
case!(activate_bad_id, "activate", "bad-id");
case!(activate_approval, "activate", "approval");
case!(activate_status_mutant, "activate", "success-status-mutant");
fault!(activate_no_audit_fault, "activate", "success", "no-audit");

case!(deactivate_success, "deactivate", "success");
case!(deactivate_repeat, "deactivate", "repeat");
case!(deactivate_foreign, "deactivate", "foreign");
case!(deactivate_direct, "deactivate", "direct");
case!(deactivate_unknown_role, "deactivate", "unknown-role");
case!(deactivate_bad_id, "deactivate", "bad-id");
case!(
    deactivate_status_mutant,
    "deactivate",
    "success-status-mutant"
);
fault!(
    deactivate_no_audit_fault,
    "deactivate",
    "success",
    "no-audit"
);

case!(policy_get_success, "policy-get", "success");
case!(policy_get_fallback, "policy-get", "fallback");
case!(policy_get_configured, "policy-get", "configured");
case!(
    policy_get_configured_array,
    "policy-get",
    "configured-array"
);
case!(policy_get_missing, "policy-get", "missing");
case!(policy_get_bad_id, "policy-get", "bad-id");
case!(policy_get_denied, "policy-get", "denied");
case!(policy_get_foreign, "policy-get", "foreign");
case!(
    policy_get_status_mutant,
    "policy-get",
    "success-status-mutant"
);

case!(policy_put_success, "policy-put", "success");
case!(policy_put_update, "policy-put", "update");
case!(policy_put_repeat, "policy-put", "repeat");
case!(policy_put_invalid, "policy-put", "invalid");
case!(policy_put_zero, "policy-put", "zero");
case!(policy_put_negative, "policy-put", "negative");
case!(policy_put_required, "policy-put", "required");
case!(policy_put_typed, "policy-put", "typed");
case!(policy_put_huge, "policy-put", "huge");
case!(policy_put_bad_id, "policy-put", "bad-id");
case!(policy_put_missing_role, "policy-put", "missing-role");
case!(policy_put_denied, "policy-put", "denied");
case!(policy_put_foreign, "policy-put", "foreign");
case!(policy_put_folded, "policy-put", "folded");
case!(policy_put_justified, "policy-put", "justified");
case!(
    policy_put_status_mutant,
    "policy-put",
    "success-status-mutant"
);
