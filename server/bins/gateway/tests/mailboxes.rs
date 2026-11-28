//! F05 slice `mailboxes` frozen-Go oracle, replayed without a Go upstream.
mod common;
mod mailboxes_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailboxes_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailboxes_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(list_success, "list", "success");
case!(list_q, "list", "q");
case!(list_global_q, "list", "global-q");
case!(list_q_escape, "list", "q-escape");
case!(list_user, "list", "user");
case!(list_user_bad, "list", "user-bad");
case!(list_user_wins, "list", "user-wins");
case!(list_foreign, "list", "foreign");
case!(list_invalid, "list", "invalid");
case!(list_paging, "list", "paging");
case!(list_big_limit, "list", "big-limit");
case!(list_big_offset, "list", "big-offset");
case!(list_denied, "list", "denied");
case!(list_wrong_perm, "list", "wrong-perm");
case!(get_success, "get", "success");
case!(get_global, "get", "global");
case!(get_foreign, "get", "foreign");
case!(get_invalid, "get", "invalid");
case!(get_zero, "get", "zero");
case!(get_plus, "get", "plus");
case!(get_missing, "get", "missing");
case!(get_denied, "get", "denied");
case!(get_wrong_perm, "get", "wrong-perm");
case!(create_success, "create", "success");
case!(create_repeat, "create", "repeat");
case!(create_no_primary, "create", "no-primary");
case!(create_no_quota, "create", "no-quota");
case!(create_display_email, "create", "display-email");
case!(create_zero_quota, "create", "zero-quota");
case!(create_foreign, "create", "foreign");
case!(create_invalid, "create", "invalid");
case!(create_bad_json, "create", "bad-json");
case!(create_typed, "create", "typed");
case!(create_bad_email, "create", "bad-email");
case!(create_dots, "create", "dots");
case!(create_leading_dot, "create", "leading-dot");
case!(create_no_dot_domain, "create", "no-dot-domain");
case!(create_underscore_domain, "create", "underscore-domain");
case!(create_long_email, "create", "long-email");
case!(create_type_group, "create", "type-group");
case!(create_type_personal, "create", "type-personal");
case!(create_unknown_user, "create", "unknown-user");
case!(create_guest, "create", "guest");
case!(create_dup, "create", "dup");
case!(create_folded, "create", "folded");
case!(create_unicode_name, "create", "unicode-name");
case!(create_denied, "create", "denied");
case!(create_wrong_perm, "create", "wrong-perm");
case!(update_success, "update", "success");
case!(update_repeat, "update", "repeat");
case!(update_global_success, "update", "global-success");
case!(update_foreign, "update", "foreign");
case!(update_invalid, "update", "invalid");
case!(update_bad_json, "update", "bad-json");
case!(update_typed, "update", "typed");
case!(update_missing, "update", "missing");
case!(update_partial, "update", "partial");
case!(update_empty, "update", "empty");
case!(update_huge_purge, "update", "huge-purge");
case!(update_huge_purge_missing, "update", "huge-purge-missing");
case!(update_negative_quota, "update", "negative-quota");
case!(update_folded, "update", "folded");
case!(update_null_fields, "update", "null-fields");
case!(update_denied, "update", "denied");
case!(update_wrong_perm, "update", "wrong-perm");
case!(delete_success, "delete", "success");
case!(delete_repeat, "delete", "repeat");
case!(delete_global, "delete", "global");
case!(delete_foreign, "delete", "foreign");
case!(delete_invalid, "delete", "invalid");
case!(delete_missing, "delete", "missing");
case!(delete_missing_global, "delete", "missing-global");
case!(delete_gate, "delete", "gate");
case!(delete_denied, "delete", "denied");
case!(delete_wrong_perm, "delete", "wrong-perm");
case!(folders_success, "folders", "success");
case!(folders_global, "folders", "global");
case!(folders_foreign, "folders", "foreign");
case!(folders_invalid, "folders", "invalid");
case!(folders_zero, "folders", "zero");
case!(folders_missing, "folders", "missing");
case!(folders_missing_global, "folders", "missing-global");
case!(folders_denied, "folders", "denied");
case!(folders_wrong_perm, "folders", "wrong-perm");
case!(folder_create_success, "folder-create", "success");
case!(folder_create_repeat, "folder-create", "repeat");
case!(folder_create_parent, "folder-create", "parent");
case!(
    folder_create_parent_missing,
    "folder-create",
    "parent-missing"
);
case!(folder_create_parent_zero, "folder-create", "parent-zero");
case!(
    folder_create_parent_negative,
    "folder-create",
    "parent-negative"
);
case!(folder_create_foreign, "folder-create", "foreign");
case!(folder_create_invalid, "folder-create", "invalid");
case!(folder_create_name_empty, "folder-create", "name-empty");
case!(folder_create_dup, "folder-create", "dup");
case!(folder_create_path_clash, "folder-create", "path-clash");
case!(folder_create_typed, "folder-create", "typed");
case!(folder_create_slash, "folder-create", "slash");
case!(
    folder_create_invalid_mailbox,
    "folder-create",
    "invalid-mailbox"
);
case!(folder_create_denied, "folder-create", "denied");
case!(folder_create_wrong_perm, "folder-create", "wrong-perm");
case!(folder_update_success, "folder-update", "success");
case!(folder_update_repeat, "folder-update", "repeat");
case!(folder_update_foreign, "folder-update", "foreign");
case!(folder_update_invalid, "folder-update", "invalid");
case!(
    folder_update_invalid_mailbox,
    "folder-update",
    "invalid-mailbox"
);
case!(folder_update_bad_folder, "folder-update", "bad-folder");
case!(
    folder_update_missing_folder,
    "folder-update",
    "missing-folder"
);
case!(
    folder_update_other_mailbox,
    "folder-update",
    "other-mailbox"
);
case!(folder_update_child, "folder-update", "child");
case!(folder_update_collision, "folder-update", "collision");
case!(folder_update_tag_clash, "folder-update", "tag-clash");
case!(folder_update_name_empty, "folder-update", "name-empty");
case!(folder_update_bad_json, "folder-update", "bad-json");
case!(folder_update_typed, "folder-update", "typed");
case!(folder_update_backslash, "folder-update", "backslash");
case!(folder_update_denied, "folder-update", "denied");
case!(folder_update_wrong_perm, "folder-update", "wrong-perm");
case!(folder_delete_success, "folder-delete", "success");
case!(folder_delete_repeat, "folder-delete", "repeat");
case!(folder_delete_foreign, "folder-delete", "foreign");
case!(folder_delete_invalid, "folder-delete", "invalid");
case!(
    folder_delete_invalid_mailbox,
    "folder-delete",
    "invalid-mailbox"
);
case!(folder_delete_bad_folder, "folder-delete", "bad-folder");
case!(
    folder_delete_missing_folder,
    "folder-delete",
    "missing-folder"
);
case!(
    folder_delete_other_mailbox,
    "folder-delete",
    "other-mailbox"
);
case!(folder_delete_child, "folder-delete", "child");
case!(folder_delete_denied, "folder-delete", "denied");
case!(folder_delete_wrong_perm, "folder-delete", "wrong-perm");
case!(preview_success, "preview", "success");
case!(preview_retained, "preview", "retained");
case!(preview_foreign, "preview", "foreign");
case!(preview_invalid, "preview", "invalid");
case!(preview_bad_id, "preview", "bad-id");
case!(preview_missing, "preview", "missing");
case!(preview_global, "preview", "global");
case!(preview_denied, "preview", "denied");
case!(preview_wrong_perm, "preview", "wrong-perm");
case!(retained_success, "retained", "success");
case!(retained_foreign, "retained", "foreign");
case!(retained_global, "retained", "global");
case!(retained_denied, "retained", "denied");
case!(retained_wrong_perm, "retained", "wrong-perm");
case!(parity_success, "parity", "success");
case!(parity_foreign, "parity", "foreign");
case!(parity_denied, "parity", "denied");
case!(parity_wrong_perm, "parity", "wrong-perm");
case!(transition_success, "transition", "success");
case!(transition_resume, "transition", "resume");
case!(transition_detach, "transition", "detach");
case!(
    transition_detach_rejecting,
    "transition",
    "detach-rejecting"
);
case!(transition_reconnect, "transition", "reconnect");
case!(transition_reconnect_link, "transition", "reconnect-link");
case!(transition_reconnect_none, "transition", "reconnect-none");
case!(
    transition_reconnect_primary,
    "transition",
    "reconnect-primary"
);
case!(
    transition_reconnect_bad_target,
    "transition",
    "reconnect-bad-target"
);
case!(transition_not_bound, "transition", "not-bound");
case!(transition_idem_conflict, "transition", "idem-conflict");
case!(transition_stale, "transition", "stale");
case!(transition_foreign, "transition", "foreign");
case!(transition_missing, "transition", "missing");
case!(transition_disabled, "transition", "disabled");
case!(transition_repeat, "transition", "repeat");
case!(transition_invalid, "transition", "invalid");
case!(transition_bad_id, "transition", "bad-id");
case!(transition_bad_json, "transition", "bad-json");
case!(transition_unknown_field, "transition", "unknown-field");
case!(transition_trailing, "transition", "trailing");
case!(transition_trailing_ws, "transition", "trailing-ws");
case!(transition_null_body, "transition", "null-body");
case!(transition_array_body, "transition", "array-body");
case!(transition_folded, "transition", "folded");
case!(transition_oversize, "transition", "oversize");
case!(transition_reason_mismatch, "transition", "reason-mismatch");
case!(transition_reason_short, "transition", "reason-short");
case!(transition_key_mismatch, "transition", "key-mismatch");
case!(transition_key_missing, "transition", "key-missing");
case!(transition_key_bad, "transition", "key-bad");
case!(transition_key_nil, "transition", "key-nil");
case!(transition_key_urn, "transition", "key-urn");
case!(transition_gen_bad, "transition", "gen-bad");
case!(transition_gen_zero, "transition", "gen-zero");
case!(transition_action_bad, "transition", "action-bad");
case!(transition_evidence_bad, "transition", "evidence-bad");
case!(transition_delivery_bad, "transition", "delivery-bad");
case!(transition_delivery_ok, "transition", "delivery-ok");
case!(transition_redirect_set, "transition", "redirect-set");
case!(transition_denied, "transition", "denied");
case!(transition_wrong_perm, "transition", "wrong-perm");
case!(purge_success, "purge", "success");
case!(purge_repeat, "purge", "repeat");
case!(purge_foreign, "purge", "foreign");
case!(purge_invalid, "purge", "invalid");
case!(purge_bad_id, "purge", "bad-id");
case!(purge_not_retained, "purge", "not-retained");
case!(purge_stale_gen, "purge", "stale-gen");
case!(purge_stale_digest, "purge", "stale-digest");
case!(purge_short_digest, "purge", "short-digest");
case!(purge_upper_digest, "purge", "upper-digest");
case!(purge_same_approver, "purge", "same-approver");
case!(purge_approver_zero, "purge", "approver-zero");
case!(purge_bad_json, "purge", "bad-json");
case!(purge_unknown_field, "purge", "unknown-field");
case!(purge_reason_mismatch, "purge", "reason-mismatch");
case!(purge_key_mismatch, "purge", "key-mismatch");
case!(purge_disabled, "purge", "disabled");
case!(purge_denied, "purge", "denied");
case!(purge_wrong_perm, "purge", "wrong-perm");
case!(approval_success, "approval", "success");
case!(approval_deny, "approval", "deny");
case!(approval_foreign, "approval", "foreign");
case!(approval_missing, "approval", "missing");
case!(approval_invalid, "approval", "invalid");
case!(approval_bad_id, "approval", "bad-id");
case!(approval_bad_decision, "approval", "bad-decision");
case!(approval_comment_long, "approval", "comment-long");
case!(approval_bad_json, "approval", "bad-json");
case!(approval_unknown_field, "approval", "unknown-field");
case!(approval_repeat, "approval", "repeat");
case!(approval_denied, "approval", "denied");
case!(approval_wrong_perm, "approval", "wrong-perm");
case!(execute_success, "execute", "success");
case!(execute_foreign, "execute", "foreign");
case!(execute_not_approved, "execute", "not-approved");
case!(execute_self_approved, "execute", "self-approved");
case!(execute_not_eligible, "execute", "not-eligible");
case!(execute_missing, "execute", "missing");
case!(execute_invalid, "execute", "invalid");
case!(execute_nil_uuid, "execute", "nil-uuid");
case!(execute_bad_json, "execute", "bad-json");
case!(execute_unknown_field, "execute", "unknown-field");
case!(execute_reason_mismatch, "execute", "reason-mismatch");
case!(execute_key_mismatch, "execute", "key-mismatch");
case!(execute_repeat, "execute", "repeat");
case!(execute_denied, "execute", "denied");
case!(execute_wrong_perm, "execute", "wrong-perm");
case!(cancel_success, "cancel", "success");
case!(cancel_foreign, "cancel", "foreign");
case!(cancel_uncancellable, "cancel", "uncancellable");
case!(cancel_missing, "cancel", "missing");
case!(cancel_invalid, "cancel", "invalid");
case!(cancel_nil_uuid, "cancel", "nil-uuid");
case!(cancel_bad_json, "cancel", "bad-json");
case!(cancel_reason_mismatch, "cancel", "reason-mismatch");
case!(cancel_key_mismatch, "cancel", "key-mismatch");
case!(cancel_repeat, "cancel", "repeat");
case!(cancel_denied, "cancel", "denied");
case!(cancel_wrong_perm, "cancel", "wrong-perm");
case!(list_status_mutant, "list", "success-status-mutant");
case!(get_status_mutant, "get", "success-status-mutant");
case!(create_status_mutant, "create", "success-status-mutant");
case!(update_status_mutant, "update", "success-status-mutant");
case!(delete_status_mutant, "delete", "success-status-mutant");
case!(folders_status_mutant, "folders", "success-status-mutant");
case!(
    folder_create_status_mutant,
    "folder-create",
    "success-status-mutant"
);
case!(
    folder_update_status_mutant,
    "folder-update",
    "success-status-mutant"
);
case!(
    folder_delete_status_mutant,
    "folder-delete",
    "success-status-mutant"
);
case!(preview_status_mutant, "preview", "success-status-mutant");
case!(retained_status_mutant, "retained", "success-status-mutant");
case!(parity_status_mutant, "parity", "success-status-mutant");
case!(
    transition_status_mutant,
    "transition",
    "success-status-mutant"
);
case!(purge_status_mutant, "purge", "success-status-mutant");
case!(approval_status_mutant, "approval", "success-status-mutant");
case!(execute_status_mutant, "execute", "success-status-mutant");
case!(cancel_status_mutant, "cancel", "success-status-mutant");
fault!(
    list_no_tenant_filter_fault,
    "list",
    "success",
    "no-tenant-filter"
);
fault!(
    transition_no_audit_fault,
    "transition",
    "success",
    "no-audit"
);
fault!(
    transition_no_notify_fault,
    "transition",
    "success",
    "no-notify"
);
fault!(update_double_bump_fault, "update", "success", "double-bump");
