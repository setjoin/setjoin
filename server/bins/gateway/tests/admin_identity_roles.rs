//! F01 slice `roles` frozen-Go oracle, replayed without a Go upstream.
mod admin_identity_roles_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_roles_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_roles_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(roles_success, "roles", "success");
case!(roles_cross_tenant, "roles", "foreign");
case!(roles_denied, "roles", "denied");
case!(roles_invalid_input, "roles", "invalid");
case!(roles_scoped, "roles", "scoped");
case!(roles_status_mutant, "roles", "success-status-mutant");
mutant!(
    roles_no_tenant_filter_mutant,
    "roles",
    "scoped",
    "no-tenant-filter"
);
case!(role_success, "role", "success");
case!(role_cross_tenant, "role", "foreign");
case!(role_invalid_input, "role", "invalid");
case!(role_missing, "role", "missing");
case!(role_scoped, "role", "scoped");
case!(role_denied, "role", "denied");
case!(role_status_mutant, "role", "success-status-mutant");
mutant!(
    role_no_tenant_filter_mutant,
    "role",
    "foreign",
    "no-tenant-filter"
);
case!(role_create_success, "role-create", "success");
case!(role_create_cross_tenant, "role-create", "foreign");
case!(role_create_invalid_input, "role-create", "invalid");
case!(role_create_empty, "role-create", "empty");
case!(role_create_bad_name, "role-create", "bad-name");
case!(role_create_no_perms, "role-create", "no-perms");
case!(role_create_unknown_perm, "role-create", "unknown-perm");
case!(role_create_not_held, "role-create", "not-held");
case!(role_create_dup, "role-create", "dup");
case!(role_create_folded, "role-create", "folded");
case!(role_create_scoped, "role-create", "scoped");
case!(role_create_scoped_wrong, "role-create", "scoped-wrong");
case!(role_create_denied, "role-create", "denied");
case!(role_create_reason, "role-create", "reason");
case!(role_create_repeat, "role-create", "repeat");
case!(
    role_create_status_mutant,
    "role-create",
    "success-status-mutant"
);
mutant!(
    role_create_no_audit_mutant,
    "role-create",
    "success",
    "no-audit"
);
case!(role_update_success, "role-update", "success");
case!(role_update_cross_tenant, "role-update", "foreign");
case!(role_update_invalid_input, "role-update", "invalid");
case!(role_update_missing, "role-update", "missing");
case!(role_update_builtin, "role-update", "builtin");
case!(role_update_bad_json, "role-update", "bad-json");
case!(role_update_empty, "role-update", "empty");
case!(role_update_empty_name, "role-update", "empty-name");
case!(role_update_bad_name, "role-update", "bad-name");
case!(role_update_unknown_perm, "role-update", "unknown-perm");
case!(role_update_not_held, "role-update", "not-held");
case!(role_update_partial, "role-update", "partial");
case!(role_update_global, "role-update", "scoped-global");
case!(role_update_move, "role-update", "scoped-move");
case!(role_update_folded, "role-update", "folded");
case!(role_update_sod_violation, "role-update", "sod-violation");
case!(role_update_sod_collision, "role-update", "sod-collision");
case!(role_update_denied, "role-update", "denied");
case!(role_update_repeat, "role-update", "repeat");
case!(
    role_update_status_mutant,
    "role-update",
    "success-status-mutant"
);
mutant!(
    role_update_no_tenant_filter_mutant,
    "role-update",
    "foreign",
    "no-tenant-filter"
);
mutant!(
    role_update_no_audit_mutant,
    "role-update",
    "success",
    "no-audit"
);
case!(role_delete_success, "role-delete", "success");
case!(role_delete_cross_tenant, "role-delete", "foreign");
case!(role_delete_invalid_input, "role-delete", "invalid");
case!(role_delete_missing, "role-delete", "missing");
case!(role_delete_builtin, "role-delete", "builtin");
case!(role_delete_repeat, "role-delete", "repeat");
case!(role_delete_denied, "role-delete", "denied");
case!(
    role_delete_status_mutant,
    "role-delete",
    "success-status-mutant"
);
mutant!(
    role_delete_no_tenant_filter_mutant,
    "role-delete",
    "foreign",
    "no-tenant-filter"
);
mutant!(
    role_delete_no_audit_mutant,
    "role-delete",
    "success",
    "no-audit"
);
case!(member_assign_success, "member-assign", "success");
case!(member_assign_cross_tenant, "member-assign", "foreign");
case!(member_assign_invalid_input, "member-assign", "invalid");
case!(member_assign_update, "member-assign", "update");
case!(member_assign_bad_json, "member-assign", "bad-json");
case!(member_assign_no_user, "member-assign", "no-user");
case!(
    member_assign_scope_retired,
    "member-assign",
    "scope-retired"
);
case!(member_assign_scope_bad, "member-assign", "scope-bad");
case!(member_assign_scope_noid, "member-assign", "scope-noid");
case!(member_assign_scope_orphan, "member-assign", "scope-orphan");
case!(member_assign_set_missing, "member-assign", "set-missing");
case!(member_assign_set, "member-assign", "set");
case!(member_assign_expires_bad, "member-assign", "expires-bad");
case!(member_assign_missing, "member-assign", "missing");
case!(member_assign_not_held, "member-assign", "not-held");
case!(member_assign_protected, "member-assign", "protected");
case!(member_assign_sod, "member-assign", "sod");
case!(member_assign_folded, "member-assign", "folded");
case!(member_assign_scoped, "member-assign", "scoped");
case!(
    member_assign_scoped_override,
    "member-assign",
    "scoped-override"
);
case!(
    member_assign_scoped_override_wrong,
    "member-assign",
    "scoped-override-wrong"
);
case!(member_assign_denied, "member-assign", "denied");
case!(member_assign_repeat, "member-assign", "repeat");
case!(
    member_assign_status_mutant,
    "member-assign",
    "success-status-mutant"
);
mutant!(
    member_assign_no_tenant_filter_mutant,
    "member-assign",
    "foreign",
    "no-tenant-filter"
);
mutant!(
    member_assign_no_audit_mutant,
    "member-assign",
    "success",
    "no-audit"
);
case!(member_remove_success, "member-remove", "success");
case!(member_remove_cross_tenant, "member-remove", "foreign");
case!(member_remove_invalid_input, "member-remove", "invalid");
case!(member_remove_missing, "member-remove", "missing");
case!(member_remove_protected, "member-remove", "protected");
case!(member_remove_repeat, "member-remove", "repeat");
case!(member_remove_denied, "member-remove", "denied");
case!(
    member_remove_status_mutant,
    "member-remove",
    "success-status-mutant"
);
mutant!(
    member_remove_no_tenant_filter_mutant,
    "member-remove",
    "foreign",
    "no-tenant-filter"
);
mutant!(
    member_remove_no_audit_mutant,
    "member-remove",
    "success",
    "no-audit"
);
case!(bulk_assign_success, "bulk-assign", "success");
case!(bulk_assign_cross_tenant, "bulk-assign", "foreign");
case!(bulk_assign_invalid_input, "bulk-assign", "invalid");
case!(bulk_assign_bad_json, "bulk-assign", "bad-json");
case!(bulk_assign_empty, "bulk-assign", "empty");
case!(bulk_assign_too_many, "bulk-assign", "too-many");
case!(bulk_assign_expires_bad, "bulk-assign", "expires-bad");
case!(bulk_assign_expires_empty, "bulk-assign", "expires-empty");
case!(bulk_assign_expires_past, "bulk-assign", "expires-past");
case!(bulk_assign_scope_bad, "bulk-assign", "scope-bad");
case!(bulk_assign_scope_ou, "bulk-assign", "scope-ou");
case!(bulk_assign_missing, "bulk-assign", "missing");
case!(bulk_assign_not_held, "bulk-assign", "not-held");
case!(bulk_assign_folded, "bulk-assign", "folded");
case!(bulk_assign_denied, "bulk-assign", "denied");
case!(bulk_assign_repeat, "bulk-assign", "repeat");
case!(
    bulk_assign_status_mutant,
    "bulk-assign",
    "success-status-mutant"
);
case!(bulk_revoke_success, "bulk-revoke", "success");
case!(bulk_revoke_cross_tenant, "bulk-revoke", "foreign");
case!(bulk_revoke_invalid_input, "bulk-revoke", "invalid");
case!(bulk_revoke_bad_json, "bulk-revoke", "bad-json");
case!(bulk_revoke_empty, "bulk-revoke", "empty");
case!(bulk_revoke_missing, "bulk-revoke", "missing");
case!(bulk_revoke_not_held, "bulk-revoke", "not-held");
case!(bulk_revoke_folded, "bulk-revoke", "folded");
case!(bulk_revoke_denied, "bulk-revoke", "denied");
case!(bulk_revoke_repeat, "bulk-revoke", "repeat");
case!(
    bulk_revoke_status_mutant,
    "bulk-revoke",
    "success-status-mutant"
);
case!(effective_success, "effective", "success");
case!(effective_cross_tenant, "effective", "foreign");
case!(effective_invalid_input, "effective", "invalid");
case!(effective_none, "effective", "none");
case!(effective_missing, "effective", "missing");
case!(effective_scoped, "effective", "scoped");
case!(effective_denied, "effective", "denied");
case!(
    effective_status_mutant,
    "effective",
    "success-status-mutant"
);
mutant!(
    effective_no_tenant_filter_mutant,
    "effective",
    "foreign",
    "no-tenant-filter"
);
case!(permissions_success, "permissions", "success");
case!(permissions_cross_tenant, "permissions", "foreign");
case!(permissions_invalid_input, "permissions", "invalid");
case!(permissions_denied, "permissions", "denied");
case!(
    permissions_status_mutant,
    "permissions",
    "success-status-mutant"
);
