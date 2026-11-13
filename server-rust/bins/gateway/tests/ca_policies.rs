//! F03 slice `policies` frozen-Go oracle, replayed without a Go upstream.
mod ca_policies_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ca_policies_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ca_policies_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(list_success, "list", "success");
case!(list_foreign, "list", "foreign");
case!(list_invalid, "list", "invalid");
case!(list_denied, "list", "denied");
case!(list_deleted, "list", "deleted");
case!(list_zero, "list", "zero");
case!(list_status_mutant, "list", "success-status-mutant");

case!(create_success, "create", "success");
case!(create_foreign, "create", "foreign");
case!(create_invalid, "create", "invalid");
case!(create_repeat, "create", "repeat");
case!(create_denied, "create", "denied");
case!(create_empty, "create", "empty");
case!(create_bad_key, "create", "bad-key");
case!(create_bad_enum, "create", "bad-enum");
case!(create_bad_int, "create", "bad-int");
case!(create_bad_time, "create", "bad-time");
case!(create_bad_grant, "create", "bad-grant");
case!(create_bad_conditions, "create", "bad-conditions");
case!(create_bad_actions, "create", "bad-actions");
case!(create_bad_priority, "create", "bad-priority");
case!(create_big_priority, "create", "big-priority");
case!(create_lockout, "create", "lockout");
case!(create_session, "create", "session");
case!(create_bad_session, "create", "bad-session");
case!(create_bad_scope, "create", "bad-scope");
case!(create_bad_state, "create", "bad-state");
case!(create_dup_on, "create", "dup-on");
case!(create_null_docs, "create", "null-docs");
case!(create_folded, "create", "folded");
case!(create_default_state, "create", "default-state");
case!(create_priority, "create", "priority");
case!(create_status_mutant, "create", "success-status-mutant");

case!(update_success, "update", "success");
case!(update_foreign, "update", "foreign");
case!(update_invalid, "update", "invalid");
case!(update_repeat, "update", "repeat");
case!(update_denied, "update", "denied");
case!(update_bad_json, "update", "bad-json");
case!(update_empty_name, "update", "empty-name");
case!(update_missing, "update", "missing");
case!(update_bad_key, "update", "bad-key");
case!(update_bad_grant, "update", "bad-grant");
case!(update_bad_priority, "update", "bad-priority");
case!(update_big_priority, "update", "big-priority");
case!(update_lockout, "update", "lockout");
case!(update_session, "update", "session");
case!(update_bad_session, "update", "bad-session");
case!(update_folded, "update", "folded");
case!(update_status_mutant, "update", "success-status-mutant");

case!(delete_success, "delete", "success");
case!(delete_foreign, "delete", "foreign");
case!(delete_invalid, "delete", "invalid");
case!(delete_repeat, "delete", "repeat");
case!(delete_denied, "delete", "denied");
case!(delete_missing, "delete", "missing");
case!(delete_status_mutant, "delete", "success-status-mutant");

case!(restore_success, "restore", "success");
case!(restore_foreign, "restore", "foreign");
case!(restore_invalid, "restore", "invalid");
case!(restore_repeat, "restore", "repeat");
case!(restore_denied, "restore", "denied");
case!(restore_missing, "restore", "missing");
case!(restore_conflict, "restore", "conflict");
case!(restore_status_mutant, "restore", "success-status-mutant");

case!(promote_preview_blocked, "promote", "preview-blocked");
case!(promote_preview_clean, "promote", "preview-clean");
case!(promote_success, "promote", "success");
case!(promote_foreign, "promote", "foreign");
case!(promote_invalid, "promote", "invalid");
case!(promote_repeat, "promote", "repeat");
case!(promote_denied, "promote", "denied");
case!(promote_bad_json, "promote", "bad-json");
case!(promote_empty_body, "promote", "empty-body");
case!(promote_lockout, "promote", "lockout");
case!(promote_already_on, "promote", "already-on");
case!(promote_missing, "promote", "missing");
case!(promote_missing_confirm, "promote", "missing-confirm");
case!(promote_folded, "promote", "folded");
case!(promote_status_mutant, "promote", "success-status-mutant");

case!(restore_from_audit_success, "restore-from-audit", "success");
case!(restore_from_audit_foreign, "restore-from-audit", "foreign");
case!(restore_from_audit_invalid, "restore-from-audit", "invalid");
case!(restore_from_audit_repeat, "restore-from-audit", "repeat");
case!(restore_from_audit_denied, "restore-from-audit", "denied");
case!(
    restore_from_audit_required,
    "restore-from-audit",
    "required"
);
case!(
    restore_from_audit_bad_type,
    "restore-from-audit",
    "bad-type"
);
case!(
    restore_from_audit_missing_audit,
    "restore-from-audit",
    "missing-audit"
);
case!(restore_from_audit_folded, "restore-from-audit", "folded");
case!(
    restore_from_audit_status_mutant,
    "restore-from-audit",
    "success-status-mutant"
);

case!(reorder_success, "reorder", "success");
case!(reorder_foreign, "reorder", "foreign");
case!(reorder_invalid, "reorder", "invalid");
case!(reorder_repeat, "reorder", "repeat");
case!(reorder_denied, "reorder", "denied");
case!(reorder_empty, "reorder", "empty");
case!(reorder_null, "reorder", "null");
case!(reorder_bad_element, "reorder", "bad-element");
case!(reorder_missing_ids, "reorder", "missing-ids");
case!(reorder_null_element, "reorder", "null-element");
case!(reorder_status_mutant, "reorder", "success-status-mutant");

fault!(create_no_audit_fault, "create", "success", "no-audit");
fault!(create_no_notify_fault, "create", "success", "no-notify");
fault!(create_double_bump_fault, "create", "success", "double-bump");
fault!(
    list_no_tenant_filter_fault,
    "list",
    "success",
    "no-tenant-filter"
);
