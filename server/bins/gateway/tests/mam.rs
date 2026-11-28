//! F07 MAM: frozen-Go HTTP/effects, replayed without Go.
mod common;
mod mam_oracle;
macro_rules! case {
    ($name:ident,$action:literal,$kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mam_oracle::run($action, $kind, None).await
        }
    };
}
case!(policies_success, "policies", "success");
case!(policies_denied, "policies", "denied");
case!(policies_foreign, "policies", "foreign");
case!(policies_invalid, "policies", "invalid");
case!(policies_empty, "policies", "empty");
case!(policies_rls, "policies", "rls");
case!(policies_head, "policies", "head");
case!(policies_wrong_perm, "policies", "wrong-perm");
case!(policies_read_error, "policies", "read-error");
case!(policies_group_read_error, "policies", "group-read-error");
case!(global_success, "global", "success");
case!(global_denied, "global", "denied");
case!(global_foreign, "global", "foreign");
case!(global_invalid, "global", "invalid");
case!(global_repeat, "global", "repeat");
case!(global_null, "global", "null");
case!(global_empty_map, "global", "empty-map");
case!(global_missing_map, "global", "missing-map");
case!(global_typed_map, "global", "typed-map");
case!(global_typed_value, "global", "typed-value");
case!(global_null_value, "global", "null-value");
case!(global_case_keys, "global", "case-keys");
case!(global_duplicate_fields, "global", "duplicate-fields");
case!(global_trailing, "global", "trailing");
case!(global_html, "global", "html");
case!(global_rls, "global", "rls");
case!(global_wrong_perm, "global", "wrong-perm");
case!(global_unicode_field, "global", "unicode-field");
case!(global_policy_error, "global", "policy-error");
case!(global_notify_error, "global", "notify-error");
case!(group_success, "group", "success");
case!(group_denied, "group", "denied");
case!(group_foreign, "group", "foreign");
case!(group_invalid, "group", "invalid");
case!(group_repeat, "group", "repeat");
case!(group_null, "group", "null");
case!(group_no_type, "group", "no-type");
case!(group_bad_type, "group", "bad-type");
case!(group_zero_id, "group", "zero-id");
case!(group_negative_id, "group", "negative-id");
case!(group_typed_id, "group", "typed-id");
case!(group_typed_value, "group", "typed-value");
case!(group_empty_map, "group", "empty-map");
case!(group_trailing, "group", "trailing");
case!(group_rls, "group", "rls");
case!(group_wrong_perm, "group", "wrong-perm");
case!(group_duplicate_null, "group", "duplicate-null");
case!(group_policy_error, "group", "policy-error");
case!(group_notify_error, "group", "notify-error");
case!(group_delete_success, "group-delete", "success");
case!(group_delete_denied, "group-delete", "denied");
case!(group_delete_foreign, "group-delete", "foreign");
case!(group_delete_invalid, "group-delete", "invalid");
case!(group_delete_repeat, "group-delete", "repeat");
case!(group_delete_missing, "group-delete", "missing");
case!(group_delete_bad_type, "group-delete", "bad-type");
case!(group_delete_plus_id, "group-delete", "plus-id");
case!(group_delete_escaped_key, "group-delete", "escaped-key");
case!(group_delete_rls, "group-delete", "rls");
case!(group_delete_wrong_perm, "group-delete", "wrong-perm");
case!(group_delete_policy_error, "group-delete", "policy-error");
case!(group_delete_notify_error, "group-delete", "notify-error");
case!(devices_success, "devices", "success");
case!(devices_denied, "devices", "denied");
case!(devices_foreign, "devices", "foreign");
case!(devices_invalid, "devices", "invalid");
case!(devices_empty, "devices", "empty");
case!(devices_head, "devices", "head");
case!(devices_rls, "devices", "rls");
case!(devices_rls_scoped, "devices", "rls-scoped");
case!(devices_wrong_perm, "devices", "wrong-perm");
case!(devices_read_error, "devices", "read-error");
case!(events_success, "events", "success");
case!(events_denied, "events", "denied");
case!(events_foreign, "events", "foreign");
case!(events_invalid, "events", "invalid");
case!(events_registry_only, "events", "registry-only");
case!(events_no_fingerprint, "events", "no-fingerprint");
case!(events_missing, "events", "missing");
case!(events_zero_id, "events", "zero-id");
case!(events_negative_id, "events", "negative-id");
case!(events_plus_id, "events", "plus-id");
case!(events_no_events, "events", "no-events");
case!(events_limit_one, "events", "limit-one");
case!(events_limit_bad, "events", "limit-bad");
case!(events_limit_big, "events", "limit-big");
case!(events_offset, "events", "offset");
case!(events_head, "events", "head");
case!(events_rls, "events", "rls");
case!(events_rls_scoped, "events", "rls-scoped");
case!(events_wrong_perm, "events", "wrong-perm");
case!(events_resolve_error, "events", "resolve-error");
case!(events_events_error, "events", "events-error");
case!(events_scope_error, "events", "scope-error");
case!(events_numeric_details, "events", "numeric-details");
case!(lock_success, "lock", "success");
case!(lock_denied, "lock", "denied");
case!(lock_foreign, "lock", "foreign");
case!(lock_invalid, "lock", "invalid");
case!(lock_repeat, "lock", "repeat");
case!(lock_registry_only, "lock", "registry-only");
case!(lock_no_fingerprint, "lock", "no-fingerprint");
case!(lock_missing, "lock", "missing");
case!(lock_zero_id, "lock", "zero-id");
case!(lock_negative_id, "lock", "negative-id");
case!(lock_plus_id, "lock", "plus-id");
case!(lock_ignored_body, "lock", "ignored-body");
case!(lock_rls, "lock", "rls");
case!(lock_rls_scoped, "lock", "rls-scoped");
case!(lock_wrong_perm, "lock", "wrong-perm");
case!(lock_event_error, "lock", "event-error");
case!(lock_notify_error, "lock", "notify-error");
case!(lock_resolve_error, "lock", "resolve-error");
case!(lock_scope_error, "lock", "scope-error");
case!(unlock_success, "unlock", "success");
case!(unlock_denied, "unlock", "denied");
case!(unlock_foreign, "unlock", "foreign");
case!(unlock_invalid, "unlock", "invalid");
case!(unlock_repeat, "unlock", "repeat");
case!(unlock_registry_only, "unlock", "registry-only");
case!(unlock_missing, "unlock", "missing");
case!(unlock_rls, "unlock", "rls");
case!(unlock_rls_scoped, "unlock", "rls-scoped");
case!(unlock_wrong_perm, "unlock", "wrong-perm");
case!(unlock_event_error, "unlock", "event-error");
case!(unlock_notify_error, "unlock", "notify-error");
case!(unlock_resolve_error, "unlock", "resolve-error");
case!(unlock_scope_error, "unlock", "scope-error");
case!(device_set_success, "device-set", "success");
case!(device_set_denied, "device-set", "denied");
case!(device_set_foreign, "device-set", "foreign");
case!(device_set_invalid, "device-set", "invalid");
case!(device_set_repeat, "device-set", "repeat");
case!(device_set_registry_only, "device-set", "registry-only");
case!(device_set_missing, "device-set", "missing");
case!(device_set_bad_json, "device-set", "bad-json");
case!(device_set_null, "device-set", "null");
case!(device_set_empty_map, "device-set", "empty-map");
case!(device_set_missing_map, "device-set", "missing-map");
case!(device_set_typed_map, "device-set", "typed-map");
case!(device_set_typed_value, "device-set", "typed-value");
case!(device_set_null_value, "device-set", "null-value");
case!(device_set_case_keys, "device-set", "case-keys");
case!(
    device_set_duplicate_fields,
    "device-set",
    "duplicate-fields"
);
case!(device_set_trailing, "device-set", "trailing");
case!(device_set_html, "device-set", "html");
case!(device_set_spoofed_owner, "device-set", "spoofed-owner");
case!(device_set_rls, "device-set", "rls");
case!(device_set_rls_scoped, "device-set", "rls-scoped");
case!(device_set_wrong_perm, "device-set", "wrong-perm");
case!(device_set_policy_error, "device-set", "policy-error");
case!(device_set_event_error, "device-set", "event-error");
case!(device_set_notify_error, "device-set", "notify-error");
case!(device_set_resolve_error, "device-set", "resolve-error");
case!(device_set_scope_error, "device-set", "scope-error");
case!(
    device_set_evidence_scope_error,
    "device-set",
    "evidence-scope-error"
);
case!(device_delete_success, "device-delete", "success");
case!(device_delete_denied, "device-delete", "denied");
case!(device_delete_foreign, "device-delete", "foreign");
case!(device_delete_invalid, "device-delete", "invalid");
case!(device_delete_repeat, "device-delete", "repeat");
case!(
    device_delete_registry_only,
    "device-delete",
    "registry-only"
);
case!(device_delete_missing, "device-delete", "missing");
case!(device_delete_missing_key, "device-delete", "missing-key");
case!(device_delete_plus_id, "device-delete", "plus-id");
case!(device_delete_escaped_key, "device-delete", "escaped-key");
case!(device_delete_rls, "device-delete", "rls");
case!(device_delete_rls_scoped, "device-delete", "rls-scoped");
case!(device_delete_wrong_perm, "device-delete", "wrong-perm");
case!(device_delete_policy_error, "device-delete", "policy-error");
case!(device_delete_notify_error, "device-delete", "notify-error");
case!(
    device_delete_resolve_error,
    "device-delete",
    "resolve-error"
);
case!(device_delete_scope_error, "device-delete", "scope-error");

// Every route must reject a changed HTTP status.
case!(policies_status_mutant, "policies", "success-status-mutant");
case!(global_status_mutant, "global", "success-status-mutant");
case!(group_status_mutant, "group", "success-status-mutant");
case!(
    group_delete_status_mutant,
    "group-delete",
    "success-status-mutant"
);
case!(devices_status_mutant, "devices", "success-status-mutant");
case!(events_status_mutant, "events", "success-status-mutant");
case!(lock_status_mutant, "lock", "success-status-mutant");
case!(unlock_status_mutant, "unlock", "success-status-mutant");
case!(
    device_set_status_mutant,
    "device-set",
    "success-status-mutant"
);
case!(
    device_delete_status_mutant,
    "device-delete",
    "success-status-mutant"
);

macro_rules! fault {
    ($name:ident,$action:literal,$kind:literal,$fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mam_oracle::run($action, $kind, Some($fault)).await
        }
    };
}
fault!(family_no_audit_mutant, "policies", "denied", "no-audit");
fault!(family_no_notify_mutant, "global", "success", "no-notify");
fault!(
    family_no_tenant_filter_mutant,
    "devices",
    "foreign",
    "no-tenant-filter"
);
fault!(family_double_bump_mutant, "lock", "success", "double-bump");
case!(global_commit_before, "global", "commit-before");
case!(global_commit_after, "global", "commit-after");
case!(lock_commit_before, "lock", "commit-before");
case!(lock_commit_after, "lock", "commit-after");
