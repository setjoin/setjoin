//! F07 offline HTTP/effects oracle.
mod common;
mod offline_oracle;
#[tokio::test]
async fn policies_success() -> Result<(), common::BoxError> {
    offline_oracle::run("policies", "success", None).await
}

#[tokio::test]
async fn governance_reads_success() -> Result<(), common::BoxError> {
    for action in ["policy", "enabled", "pending"] {
        offline_oracle::run(action, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn policy_writes_success() -> Result<(), common::BoxError> {
    for action in ["create", "update", "delete"] {
        offline_oracle::run(action, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn toggle_and_preview_success() -> Result<(), common::BoxError> {
    for action in ["toggle", "preview"] {
        offline_oracle::run(action, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn device_admin_actions_success() -> Result<(), common::BoxError> {
    for action in ["approve", "deny", "revoke", "wipe"] {
        offline_oracle::run(action, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn user_offline_success() -> Result<(), common::BoxError> {
    for action in ["size", "ack"] {
        offline_oracle::run(action, "success", None).await?;
    }
    Ok(())
}

macro_rules! case {
    ($name:ident,$action:literal,$kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            offline_oracle::run($action, $kind, None).await
        }
    };
}
case!(q_policies_success, "policies", "success");
case!(q_policies_foreign, "policies", "foreign");
case!(q_policies_invalid, "policies", "invalid");
case!(q_policies_denied, "policies", "denied");
case!(q_policies_empty, "policies", "empty");
case!(q_policies_head, "policies", "head");
case!(q_policy_success, "policy", "success");
case!(q_policy_foreign, "policy", "foreign");
case!(q_policy_invalid, "policy", "invalid");
case!(q_policy_denied, "policy", "denied");
case!(q_policy_missing, "policy", "missing");
case!(q_policy_head, "policy", "head");
case!(q_policy_plus_id, "policy", "plus-id");
case!(q_enabled_success, "enabled", "success");
case!(q_enabled_foreign, "enabled", "foreign");
case!(q_enabled_invalid, "enabled", "invalid");
case!(q_enabled_denied, "enabled", "denied");
case!(q_pending_success, "pending", "success");
case!(q_pending_foreign, "pending", "foreign");
case!(q_pending_invalid, "pending", "invalid");
case!(q_pending_denied, "pending", "denied");
case!(q_pending_populated, "pending", "populated");
case!(q_pending_head, "pending", "head");
case!(q_create_success, "create", "success");
case!(q_create_foreign, "create", "foreign");
case!(q_create_invalid, "create", "invalid");
case!(q_create_denied, "create", "denied");
case!(q_create_repeat, "create", "repeat");
case!(q_create_qos, "create", "qos");
case!(q_create_partial_qos, "create", "partial-qos");
case!(q_create_null, "create", "null");
case!(q_create_trailing, "create", "trailing");
case!(q_create_unknown_field, "create", "unknown-field");
case!(q_create_typed, "create", "typed");
case!(q_create_no_name, "create", "no-name");
case!(q_create_bad_scope, "create", "bad-scope");
case!(q_create_int32_overflow, "create", "int32-overflow");
case!(q_create_fraction, "create", "fraction");
case!(q_create_negative_days, "create", "negative-days");
case!(q_create_duplicate_null, "create", "duplicate-null");
case!(q_create_too_large, "create", "too-large");
case!(q_update_success, "update", "success");
case!(q_update_foreign, "update", "foreign");
case!(q_update_invalid, "update", "invalid");
case!(q_update_denied, "update", "denied");
case!(q_update_repeat, "update", "repeat");
case!(q_update_qos, "update", "qos");
case!(q_update_missing, "update", "missing");
case!(q_update_trailing, "update", "trailing");
case!(q_delete_success, "delete", "success");
case!(q_delete_foreign, "delete", "foreign");
case!(q_delete_invalid, "delete", "invalid");
case!(q_delete_denied, "delete", "denied");
case!(q_delete_repeat, "delete", "repeat");
case!(q_delete_last_global, "delete", "last-global");
case!(q_delete_missing, "delete", "missing");
case!(q_toggle_success, "toggle", "success");
case!(q_toggle_foreign, "toggle", "foreign");
case!(q_toggle_invalid, "toggle", "invalid");
case!(q_toggle_denied, "toggle", "denied");
case!(q_toggle_repeat, "toggle", "repeat");
case!(q_toggle_null, "toggle", "null");
case!(q_toggle_empty_object, "toggle", "empty-object");
case!(q_toggle_trailing, "toggle", "trailing");
case!(q_toggle_unknown_field, "toggle", "unknown-field");
case!(q_toggle_typed, "toggle", "typed");
case!(q_toggle_case_keys, "toggle", "case-keys");
case!(q_toggle_duplicate_null, "toggle", "duplicate-null");
case!(q_preview_success, "preview", "success");
case!(q_preview_foreign, "preview", "foreign");
case!(q_preview_invalid, "preview", "invalid");
case!(q_preview_denied, "preview", "denied");
case!(q_preview_repeat, "preview", "repeat");
case!(q_preview_missing, "preview", "missing");
case!(q_preview_bad_target, "preview", "bad-target");
case!(q_preview_bad_device, "preview", "bad-device");
case!(q_preview_trailing, "preview", "trailing");
case!(q_preview_unknown_field, "preview", "unknown-field");
case!(q_preview_typed, "preview", "typed");
case!(q_approve_success, "approve", "success");
case!(q_approve_foreign, "approve", "foreign");
case!(q_approve_invalid, "approve", "invalid");
case!(q_approve_denied, "approve", "denied");
case!(q_approve_repeat, "approve", "repeat");
case!(q_approve_rls, "approve", "rls");
case!(q_approve_approved, "approve", "approved");
case!(q_approve_missing, "approve", "missing");
case!(q_deny_success, "deny", "success");
case!(q_deny_foreign, "deny", "foreign");
case!(q_deny_invalid, "deny", "invalid");
case!(q_deny_denied, "deny", "denied");
case!(q_deny_repeat, "deny", "repeat");
case!(q_deny_rls, "deny", "rls");
case!(q_deny_approved, "deny", "approved");
case!(q_revoke_success, "revoke", "success");
case!(q_revoke_foreign, "revoke", "foreign");
case!(q_revoke_invalid, "revoke", "invalid");
case!(q_revoke_denied, "revoke", "denied");
case!(q_revoke_repeat, "revoke", "repeat");
case!(q_revoke_rls, "revoke", "rls");
case!(q_revoke_pending, "revoke", "pending");
case!(q_wipe_success, "wipe", "success");
case!(q_wipe_foreign, "wipe", "foreign");
case!(q_wipe_invalid, "wipe", "invalid");
case!(q_wipe_denied, "wipe", "denied");
case!(q_wipe_repeat, "wipe", "repeat");
case!(q_wipe_rls, "wipe", "rls");
case!(q_wipe_pending, "wipe", "pending");
case!(q_size_success, "size", "success");
case!(q_size_foreign, "size", "foreign");
case!(q_size_invalid, "size", "invalid");
case!(q_size_windows, "size", "windows");
case!(q_size_deleted, "size", "deleted");
case!(q_size_empty, "size", "empty");
case!(q_size_head, "size", "head");
case!(q_ack_success, "ack", "success");
case!(q_ack_foreign, "ack", "foreign");
case!(q_ack_invalid, "ack", "invalid");
case!(q_ack_repeat, "ack", "repeat");
case!(q_ack_rls, "ack", "rls");
case!(q_ack_missing, "ack", "missing");
case!(q_ack_negative_id, "ack", "negative-id");
case!(q_ack_zero_id, "ack", "zero-id");
case!(q_ack_typed, "ack", "typed");
case!(q_ack_trailing, "ack", "trailing");
case!(q_ack_spoofed_owner, "ack", "spoofed-owner");
case!(fault_policies_read_error, "policies", "read-error");
case!(fault_policy_read_error, "policy", "read-error");
case!(fault_pending_read_error, "pending", "read-error");
case!(fault_preview_read_error, "preview", "read-error");
case!(fault_create_write_error, "create", "write-error");
case!(fault_create_audit_error, "create", "audit-error");
case!(fault_create_notify_error, "create", "notify-error");
case!(fault_toggle_audit_error, "toggle", "audit-error");
case!(fault_toggle_notify_error, "toggle", "notify-error");
case!(fault_approve_audit_error, "approve", "audit-error");
case!(fault_approve_notify_error, "approve", "notify-error");
case!(fault_ack_audit_error, "ack", "audit-error");
case!(fault_ack_notify_error, "ack", "notify-error");
case!(policies_status_mutant, "policies", "success-status-mutant");
case!(policy_status_mutant, "policy", "success-status-mutant");
case!(enabled_status_mutant, "enabled", "success-status-mutant");
case!(pending_status_mutant, "pending", "populated-status-mutant");
case!(create_status_mutant, "create", "success-status-mutant");
case!(update_status_mutant, "update", "success-status-mutant");
case!(delete_status_mutant, "delete", "success-status-mutant");
case!(toggle_status_mutant, "toggle", "success-status-mutant");
case!(preview_status_mutant, "preview", "success-status-mutant");
case!(approve_status_mutant, "approve", "success-status-mutant");
case!(deny_status_mutant, "deny", "success-status-mutant");
case!(revoke_status_mutant, "revoke", "success-status-mutant");
case!(wipe_status_mutant, "wipe", "success-status-mutant");
case!(size_status_mutant, "size", "success-status-mutant");
case!(ack_status_mutant, "ack", "success-status-mutant");
#[tokio::test]
async fn no_audit_mutant() -> Result<(), common::BoxError> {
    offline_oracle::run("create", "success", Some("no-audit")).await
}
#[tokio::test]
async fn no_notify_mutant() -> Result<(), common::BoxError> {
    offline_oracle::run("create", "success", Some("no-notify")).await
}
#[tokio::test]
async fn no_tenant_filter_mutant() -> Result<(), common::BoxError> {
    offline_oracle::run("ack", "foreign", Some("no-tenant-filter")).await
}
#[tokio::test]
async fn double_bump_mutant() -> Result<(), common::BoxError> {
    offline_oracle::run("create", "success", Some("double-bump")).await
}
case!(commit_create_before, "create", "commit-before");
case!(commit_create_after, "create", "commit-after");
case!(commit_toggle_before, "toggle", "commit-before");
case!(commit_toggle_after, "toggle", "commit-after");
case!(commit_wipe_before, "wipe", "commit-before");
case!(commit_wipe_after, "wipe", "commit-after");
case!(commit_ack_before, "ack", "commit-before");
case!(commit_ack_after, "ack", "commit-after");

case!(q_policies_large, "policies", "large");
case!(q_policies_large_head, "policies", "large-head");

case!(fault_enabled_read_error, "enabled", "read-error");
case!(fault_size_read_error, "size", "read-error");

case!(q_toggle_unbounded, "toggle", "unbounded");
