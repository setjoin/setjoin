//! F07 slice `mdm` frozen-Go oracle, replayed without a Go upstream.
mod common;
mod devices_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            devices_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            devices_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(mdm_devices_success, "mdm-devices", "success");
case!(mdm_devices_foreign, "mdm-devices", "foreign");
case!(mdm_devices_denied, "mdm-devices", "denied");
case!(mdm_devices_wrong_perm, "mdm-devices", "wrong-perm");
case!(mdm_devices_head, "mdm-devices", "head");
case!(mdm_devices_ignored_query, "mdm-devices", "ignored-query");
case!(mdm_devices_rls, "mdm-devices", "rls");
case!(mdm_device_success, "mdm-device", "success");
case!(mdm_device_pending, "mdm-device", "pending");
case!(mdm_device_executed, "mdm-device", "executed");
case!(mdm_device_grace, "mdm-device", "grace");
case!(mdm_device_reasons, "mdm-device", "reasons");
case!(mdm_device_foreign, "mdm-device", "foreign");
case!(mdm_device_foreign_own, "mdm-device", "foreign-own");
case!(mdm_device_missing, "mdm-device", "missing");
case!(mdm_device_invalid, "mdm-device", "invalid");
case!(mdm_device_upper, "mdm-device", "upper");
case!(mdm_device_braced, "mdm-device", "braced");
case!(mdm_device_urn, "mdm-device", "urn");
case!(mdm_device_compact, "mdm-device", "compact");
case!(mdm_device_head, "mdm-device", "head");
case!(mdm_device_denied, "mdm-device", "denied");
case!(mdm_device_wrong_perm, "mdm-device", "wrong-perm");
case!(mdm_wipe_success, "mdm-wipe", "success");
case!(mdm_wipe_device_level, "mdm-wipe", "device-level");
case!(mdm_wipe_repeat, "mdm-wipe", "repeat");
case!(mdm_wipe_conflict_level, "mdm-wipe", "conflict-level");
case!(mdm_wipe_executed, "mdm-wipe", "executed");
case!(mdm_wipe_missing, "mdm-wipe", "missing");
case!(mdm_wipe_foreign, "mdm-wipe", "foreign");
case!(mdm_wipe_foreign_own, "mdm-wipe", "foreign-own");
case!(mdm_wipe_invalid, "mdm-wipe", "invalid");
case!(mdm_wipe_bad_json, "mdm-wipe", "bad-json");
case!(mdm_wipe_empty_body, "mdm-wipe", "empty-body");
case!(mdm_wipe_null_body, "mdm-wipe", "null-body");
case!(mdm_wipe_bad_level, "mdm-wipe", "bad-level");
case!(mdm_wipe_typed, "mdm-wipe", "typed");
case!(mdm_wipe_case_key, "mdm-wipe", "case-key");
case!(mdm_wipe_unknown_keys, "mdm-wipe", "unknown-keys");
case!(mdm_wipe_trailing, "mdm-wipe", "trailing");
case!(mdm_wipe_denied, "mdm-wipe", "denied");
case!(mdm_wipe_wrong_perm, "mdm-wipe", "wrong-perm");
case!(mdm_wipe_rls, "mdm-wipe", "rls");
case!(policies_success, "policies", "success");
case!(policies_empty, "policies", "empty");
case!(policies_foreign, "policies", "foreign");
case!(policies_head, "policies", "head");
case!(policies_denied, "policies", "denied");
case!(policies_wrong_perm, "policies", "wrong-perm");
case!(policies_rls, "policies", "rls");
case!(policy_create_success, "policy-create", "success");
case!(policy_create_repeat, "policy-create", "repeat");
case!(policy_create_full, "policy-create", "full");
case!(policy_create_implicit, "policy-create", "implicit");
case!(policy_create_html, "policy-create", "html");
case!(policy_create_no_name, "policy-create", "no-name");
case!(policy_create_empty_name, "policy-create", "empty-name");
case!(policy_create_bad_scope, "policy-create", "bad-scope");
case!(
    policy_create_bad_complexity,
    "policy-create",
    "bad-complexity"
);
case!(
    policy_create_bad_jailbreak,
    "policy-create",
    "bad-jailbreak"
);
case!(
    policy_create_negative_length,
    "policy-create",
    "negative-length"
);
case!(policy_create_bad_json, "policy-create", "bad-json");
case!(policy_create_eof, "policy-create", "eof");
case!(policy_create_typed_int, "policy-create", "typed-int");
case!(policy_create_float_int, "policy-create", "float-int");
case!(policy_create_typed_bool, "policy-create", "typed-bool");
case!(
    policy_create_typed_scope_id,
    "policy-create",
    "typed-scope-id"
);
case!(policy_create_overflow, "policy-create", "overflow");
case!(policy_create_check_fail, "policy-create", "check-fail");
case!(policy_create_null_body, "policy-create", "null-body");
case!(policy_create_array_body, "policy-create", "array-body");
case!(policy_create_case_keys, "policy-create", "case-keys");
case!(policy_create_unknown_keys, "policy-create", "unknown-keys");
case!(policy_create_trailing, "policy-create", "trailing");
case!(policy_create_foreign, "policy-create", "foreign");
case!(policy_create_denied, "policy-create", "denied");
case!(policy_create_wrong_perm, "policy-create", "wrong-perm");
case!(policy_create_rls, "policy-create", "rls");
case!(policy_update_success, "policy-update", "success");
case!(policy_update_repeat, "policy-update", "repeat");
case!(policy_update_full, "policy-update", "full");
case!(policy_update_scope_reset, "policy-update", "scope-reset");
case!(policy_update_missing, "policy-update", "missing");
case!(policy_update_invalid, "policy-update", "invalid");
case!(policy_update_plus_id, "policy-update", "plus-id");
case!(policy_update_empty_name, "policy-update", "empty-name");
case!(policy_update_bad_scope, "policy-update", "bad-scope");
case!(policy_update_bad_json, "policy-update", "bad-json");
case!(policy_update_typed, "policy-update", "typed");
case!(policy_update_empty_object, "policy-update", "empty-object");
case!(policy_update_overflow, "policy-update", "overflow");
case!(policy_update_check_fail, "policy-update", "check-fail");
case!(policy_update_foreign, "policy-update", "foreign");
case!(policy_update_denied, "policy-update", "denied");
case!(policy_update_wrong_perm, "policy-update", "wrong-perm");
case!(policy_delete_success, "policy-delete", "success");
case!(policy_delete_repeat, "policy-delete", "repeat");
case!(policy_delete_last_global, "policy-delete", "last-global");
case!(
    policy_delete_disabled_global,
    "policy-delete",
    "disabled-global"
);
case!(policy_delete_missing, "policy-delete", "missing");
case!(policy_delete_invalid, "policy-delete", "invalid");
case!(policy_delete_foreign, "policy-delete", "foreign");
case!(policy_delete_denied, "policy-delete", "denied");
case!(policy_delete_wrong_perm, "policy-delete", "wrong-perm");
case!(policy_reorder_success, "policy-reorder", "success");
case!(policy_reorder_repeat, "policy-reorder", "repeat");
case!(policy_reorder_single, "policy-reorder", "single");
case!(policy_reorder_repeat_ids, "policy-reorder", "repeat-ids");
case!(policy_reorder_unknown_ids, "policy-reorder", "unknown-ids");
case!(policy_reorder_empty_list, "policy-reorder", "empty-list");
case!(policy_reorder_no_ids, "policy-reorder", "no-ids");
case!(policy_reorder_bad_json, "policy-reorder", "bad-json");
case!(policy_reorder_typed_id, "policy-reorder", "typed-id");
case!(policy_reorder_float_id, "policy-reorder", "float-id");
case!(policy_reorder_null_id, "policy-reorder", "null-id");
case!(policy_reorder_null_ids, "policy-reorder", "null-ids");
case!(policy_reorder_not_array, "policy-reorder", "not-array");
case!(policy_reorder_foreign, "policy-reorder", "foreign");
case!(policy_reorder_denied, "policy-reorder", "denied");
case!(policy_reorder_wrong_perm, "policy-reorder", "wrong-perm");
case!(queue_success, "queue", "success");
case!(queue_foreign_target, "queue", "foreign-target");
case!(queue_approved, "queue", "approved");
case!(queue_revoked, "queue", "revoked");
case!(queue_unenrolled, "queue", "unenrolled");
case!(queue_q_email, "queue", "q-email");
case!(queue_q_name, "queue", "q-name");
case!(queue_q_wild, "queue", "q-wild");
case!(queue_limit, "queue", "limit");
case!(queue_limit_bad, "queue", "limit-bad");
case!(queue_limit_negative, "queue", "limit-negative");
case!(queue_limit_big, "queue", "limit-big");
case!(queue_empty, "queue", "empty");
case!(queue_head, "queue", "head");
case!(queue_foreign, "queue", "foreign");
case!(queue_denied, "queue", "denied");
case!(queue_wrong_perm, "queue", "wrong-perm");
case!(queue_rls, "queue", "rls");
case!(devices_list_success, "devices-list", "success");
case!(
    devices_list_foreign_target,
    "devices-list",
    "foreign-target"
);
case!(devices_list_other_user, "devices-list", "other-user");
case!(devices_list_no_user, "devices-list", "no-user");
case!(devices_list_invalid, "devices-list", "invalid");
case!(devices_list_zero, "devices-list", "zero");
case!(devices_list_negative, "devices-list", "negative");
case!(devices_list_missing, "devices-list", "missing");
case!(devices_list_head, "devices-list", "head");
case!(devices_list_foreign, "devices-list", "foreign");
case!(devices_list_denied, "devices-list", "denied");
case!(devices_list_wrong_perm, "devices-list", "wrong-perm");
case!(devices_list_rls, "devices-list", "rls");
case!(transition_success, "transition", "success");
case!(transition_enroll, "transition", "enroll");
case!(transition_revoke, "transition", "revoke");
case!(transition_revoke_enrolled, "transition", "revoke-enrolled");
case!(transition_illegal, "transition", "illegal");
case!(transition_missing, "transition", "missing");
case!(transition_unknown_action, "transition", "unknown-action");
case!(transition_invalid_id, "transition", "invalid-id");
case!(transition_reason, "transition", "reason");
case!(transition_no_body, "transition", "no-body");
case!(transition_bad_json, "transition", "bad-json");
case!(transition_reason_typed, "transition", "reason-typed");
case!(transition_zero_id, "transition", "zero-id");
case!(transition_repeat, "transition", "repeat");
case!(transition_foreign, "transition", "foreign");
case!(transition_denied, "transition", "denied");
case!(transition_wrong_perm, "transition", "wrong-perm");
case!(transition_rls, "transition", "rls");
case!(transition_rls_own, "transition", "rls-own");
case!(transition_foreign_target, "transition", "foreign-target");
case!(
    mdm_devices_status_mutant,
    "mdm-devices",
    "success-status-mutant"
);
case!(
    mdm_device_status_mutant,
    "mdm-device",
    "success-status-mutant"
);
case!(mdm_wipe_status_mutant, "mdm-wipe", "success-status-mutant");
case!(policies_status_mutant, "policies", "success-status-mutant");
case!(
    policy_create_status_mutant,
    "policy-create",
    "success-status-mutant"
);
case!(
    policy_update_status_mutant,
    "policy-update",
    "success-status-mutant"
);
case!(
    policy_delete_status_mutant,
    "policy-delete",
    "success-status-mutant"
);
case!(
    policy_reorder_status_mutant,
    "policy-reorder",
    "success-status-mutant"
);
case!(queue_status_mutant, "queue", "success-status-mutant");
case!(
    devices_list_status_mutant,
    "devices-list",
    "success-status-mutant"
);
case!(
    transition_status_mutant,
    "transition",
    "success-status-mutant"
);
fault!(wipe_no_audit_fault, "mdm-wipe", "success", "no-audit");
fault!(wipe_no_notify_fault, "mdm-wipe", "success", "no-notify");
fault!(wipe_double_bump_fault, "mdm-wipe", "success", "double-bump");
fault!(
    mdm_devices_no_tenant_filter_fault,
    "mdm-devices",
    "foreign",
    "no-tenant-filter"
);
