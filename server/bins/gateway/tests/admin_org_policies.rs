//! F01 slice `org-policies` frozen-Go oracle, replayed without a Go upstream.
mod admin_org_policies_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_org_policies_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_org_policies_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(dept_list_success, "dept-list", "success");
case!(dept_list_cross_tenant, "dept-list", "foreign");
case!(dept_list_denied, "dept-list", "denied");
case!(
    dept_list_status_mutant,
    "dept-list",
    "success-status-mutant"
);

case!(dept_tree_success, "dept-tree", "success");
case!(dept_tree_cross_tenant, "dept-tree", "foreign");
case!(dept_tree_denied, "dept-tree", "denied");
case!(
    dept_tree_status_mutant,
    "dept-tree",
    "success-status-mutant"
);

case!(dept_create_success, "dept-create", "success");
case!(dept_create_child, "dept-create", "child");
case!(dept_create_cross_tenant, "dept-create", "foreign");
case!(dept_create_foreign_parent, "dept-create", "foreign-parent");
case!(dept_create_invalid_input, "dept-create", "invalid");
case!(dept_create_empty_name, "dept-create", "empty-name");
case!(dept_create_bad_name, "dept-create", "bad-name");
case!(dept_create_long_name, "dept-create", "long-name");
case!(dept_create_parent_missing, "dept-create", "parent-missing");
case!(dept_create_parent_zero, "dept-create", "parent-zero");
case!(
    dept_create_parent_negative,
    "dept-create",
    "parent-negative"
);
case!(dept_create_dup, "dept-create", "dup");
case!(dept_create_ldap_trim, "dept-create", "ldap-trim");
case!(dept_create_folded, "dept-create", "folded");
case!(dept_create_typed, "dept-create", "typed");
case!(dept_create_denied, "dept-create", "denied");
case!(dept_create_foreign_ou, "dept-create", "foreign-ou");
case!(dept_create_repeat, "dept-create", "repeat");
case!(
    dept_create_status_mutant,
    "dept-create",
    "success-status-mutant"
);

case!(dept_update_success, "dept-update", "success");
case!(dept_update_move, "dept-update", "move");
case!(dept_update_cross_tenant, "dept-update", "foreign");
case!(dept_update_invalid_id, "dept-update", "invalid-id");
case!(dept_update_zero_id, "dept-update", "zero-id");
case!(dept_update_invalid_input, "dept-update", "invalid");
case!(dept_update_missing, "dept-update", "missing");
case!(dept_update_empty, "dept-update", "empty");
case!(dept_update_parent_zero, "dept-update", "parent-zero");
case!(dept_update_parent_missing, "dept-update", "parent-missing");
case!(dept_update_sort_only, "dept-update", "sort-only");
case!(dept_update_big_sort, "dept-update", "big-sort");
case!(dept_update_ldap_only, "dept-update", "ldap-only");
case!(dept_update_name_dup, "dept-update", "name-dup");
case!(dept_update_typed, "dept-update", "typed");
case!(dept_update_folded, "dept-update", "folded");
case!(dept_update_denied, "dept-update", "denied");
case!(dept_update_foreign_ou, "dept-update", "foreign-ou");
case!(dept_update_repeat, "dept-update", "repeat");
case!(
    dept_update_status_mutant,
    "dept-update",
    "success-status-mutant"
);

case!(dept_delete_success, "dept-delete", "success");
case!(dept_delete_cross_tenant, "dept-delete", "foreign");
case!(dept_delete_invalid_id, "dept-delete", "invalid-id");
case!(dept_delete_zero_id, "dept-delete", "zero-id");
case!(dept_delete_missing, "dept-delete", "missing");
case!(dept_delete_children, "dept-delete", "children");
case!(dept_delete_users, "dept-delete", "users");
case!(dept_delete_denied, "dept-delete", "denied");
case!(dept_delete_foreign_ou, "dept-delete", "foreign-ou");
case!(dept_delete_repeat, "dept-delete", "repeat");
case!(
    dept_delete_status_mutant,
    "dept-delete",
    "success-status-mutant"
);

case!(dept_assign_success, "dept-assign", "success");
case!(dept_assign_clear, "dept-assign", "clear");
case!(dept_assign_zero_dept, "dept-assign", "zero-dept");
case!(dept_assign_cross_tenant, "dept-assign", "foreign");
case!(dept_assign_invalid_input, "dept-assign", "invalid");
case!(dept_assign_no_user, "dept-assign", "no-user");
case!(dept_assign_negative_user, "dept-assign", "negative-user");
case!(dept_assign_dept_missing, "dept-assign", "dept-missing");
case!(dept_assign_missing_user, "dept-assign", "missing-user");
case!(dept_assign_folded, "dept-assign", "folded");
case!(dept_assign_denied, "dept-assign", "denied");
case!(dept_assign_foreign_ou, "dept-assign", "foreign-ou");
case!(dept_assign_repeat, "dept-assign", "repeat");
case!(
    dept_assign_status_mutant,
    "dept-assign",
    "success-status-mutant"
);

case!(policy_list_success, "policy-list", "success");
case!(policy_list_cross_tenant, "policy-list", "foreign");
case!(policy_list_denied, "policy-list", "denied");
case!(
    policy_list_status_mutant,
    "policy-list",
    "success-status-mutant"
);

case!(policy_create_success, "policy-create", "success");
case!(policy_create_minimal, "policy-create", "minimal");
case!(policy_create_cross_tenant, "policy-create", "foreign");
case!(policy_create_invalid_input, "policy-create", "invalid");
case!(policy_create_no_name, "policy-create", "no-name");
case!(policy_create_no_template, "policy-create", "no-template");
case!(policy_create_template_at, "policy-create", "template-at");
case!(policy_create_template_var, "policy-create", "template-var");
case!(
    policy_create_template_unknown,
    "policy-create",
    "template-unknown"
);
case!(policy_create_dup, "policy-create", "dup");
case!(policy_create_bad_dupres, "policy-create", "bad-dupres");
case!(policy_create_nulls, "policy-create", "nulls");
case!(policy_create_typed_array, "policy-create", "typed-array");
case!(
    policy_create_float_priority,
    "policy-create",
    "float-priority"
);
case!(policy_create_big_priority, "policy-create", "big-priority");
case!(policy_create_empty_arrays, "policy-create", "empty-arrays");
case!(policy_create_folded, "policy-create", "folded");
case!(policy_create_denied, "policy-create", "denied");
case!(policy_create_repeat, "policy-create", "repeat");
case!(
    policy_create_status_mutant,
    "policy-create",
    "success-status-mutant"
);

case!(policy_update_success, "policy-update", "success");
case!(policy_update_cross_tenant, "policy-update", "foreign");
case!(policy_update_invalid_id, "policy-update", "invalid-id");
case!(policy_update_invalid_input, "policy-update", "invalid");
case!(policy_update_missing, "policy-update", "missing");
case!(policy_update_dup, "policy-update", "dup");
case!(policy_update_empty, "policy-update", "empty");
case!(policy_update_partial, "policy-update", "partial");
case!(policy_update_rename, "policy-update", "rename");
case!(policy_update_bad_template, "policy-update", "bad-template");
case!(policy_update_bad_dupres, "policy-update", "bad-dupres");
case!(policy_update_empty_dupres, "policy-update", "empty-dupres");
case!(policy_update_arrays, "policy-update", "arrays");
case!(policy_update_typed, "policy-update", "typed");
case!(policy_update_folded, "policy-update", "folded");
case!(policy_update_denied, "policy-update", "denied");
case!(policy_update_repeat, "policy-update", "repeat");
case!(
    policy_update_status_mutant,
    "policy-update",
    "success-status-mutant"
);

case!(policy_delete_success, "policy-delete", "success");
case!(policy_delete_cross_tenant, "policy-delete", "foreign");
case!(policy_delete_invalid_id, "policy-delete", "invalid-id");
case!(policy_delete_missing, "policy-delete", "missing");
case!(policy_delete_repeat, "policy-delete", "repeat");
case!(policy_delete_denied, "policy-delete", "denied");
case!(
    policy_delete_status_mutant,
    "policy-delete",
    "success-status-mutant"
);

case!(policy_reorder_success, "policy-reorder", "success");
case!(policy_reorder_cross_tenant, "policy-reorder", "foreign");
case!(policy_reorder_invalid_input, "policy-reorder", "invalid");
case!(policy_reorder_empty, "policy-reorder", "empty");
case!(policy_reorder_collision, "policy-reorder", "collision");
case!(policy_reorder_unknown, "policy-reorder", "unknown");
case!(policy_reorder_dups, "policy-reorder", "dups");
case!(
    policy_reorder_with_disabled,
    "policy-reorder",
    "with-disabled"
);
case!(policy_reorder_null_body, "policy-reorder", "null-body");
case!(policy_reorder_denied, "policy-reorder", "denied");
case!(policy_reorder_repeat, "policy-reorder", "repeat");
case!(
    policy_reorder_status_mutant,
    "policy-reorder",
    "success-status-mutant"
);

case!(policy_preview_success, "policy-preview", "success");
case!(policy_preview_cross_tenant, "policy-preview", "foreign");
case!(policy_preview_invalid_input, "policy-preview", "invalid");
case!(policy_preview_missing, "policy-preview", "missing");
case!(policy_preview_empty_local, "policy-preview", "empty-local");
case!(policy_preview_no_user, "policy-preview", "no-user");
case!(policy_preview_denied, "policy-preview", "denied");
case!(
    policy_preview_status_mutant,
    "policy-preview",
    "success-status-mutant"
);

case!(policy_match_count_success, "policy-match-count", "success");
case!(
    policy_match_count_cross_tenant,
    "policy-match-count",
    "foreign"
);
case!(
    policy_match_count_invalid_input,
    "policy-match-count",
    "invalid"
);
case!(policy_match_count_none, "policy-match-count", "none");
case!(policy_match_count_domain, "policy-match-count", "domain");
case!(policy_match_count_ou, "policy-match-count", "ou");
case!(policy_match_count_typed, "policy-match-count", "typed");
case!(policy_match_count_denied, "policy-match-count", "denied");
case!(
    policy_match_count_status_mutant,
    "policy-match-count",
    "success-status-mutant"
);

case!(policy_apply_success, "policy-apply", "success");
case!(policy_apply_cross_tenant, "policy-apply", "foreign");
case!(policy_apply_invalid_input, "policy-apply", "invalid");
case!(policy_apply_all, "policy-apply", "all");
case!(policy_apply_null_body, "policy-apply", "null-body");
case!(policy_apply_typed, "policy-apply", "typed");
case!(policy_apply_missing, "policy-apply", "missing");
case!(policy_apply_denied, "policy-apply", "denied");
case!(policy_apply_repeat, "policy-apply", "repeat");
case!(
    policy_apply_status_mutant,
    "policy-apply",
    "success-status-mutant"
);

case!(
    policy_apply_status_success,
    "policy-apply-status",
    "success"
);
case!(
    policy_apply_status_cross_tenant,
    "policy-apply-status",
    "foreign"
);
case!(
    policy_apply_status_invalid_input,
    "policy-apply-status",
    "invalid"
);
case!(
    policy_apply_status_missing,
    "policy-apply-status",
    "missing"
);
case!(policy_apply_status_error, "policy-apply-status", "error");
case!(policy_apply_status_queued, "policy-apply-status", "queued");
case!(policy_apply_status_denied, "policy-apply-status", "denied");
case!(
    policy_apply_status_status_mutant,
    "policy-apply-status",
    "success-status-mutant"
);

case!(groups_success, "groups", "success");
case!(groups_cross_tenant, "groups", "foreign");
case!(groups_denied, "groups", "denied");
case!(groups_status_mutant, "groups", "success-status-mutant");

fault!(
    dept_create_ou_reach_bypass_fault,
    "dept-create",
    "foreign-ou",
    "reach-bypass"
);
fault!(
    dept_update_ou_reach_bypass_fault,
    "dept-update",
    "foreign-ou",
    "reach-bypass"
);
fault!(
    dept_delete_ou_reach_bypass_fault,
    "dept-delete",
    "foreign-ou",
    "reach-bypass"
);
fault!(
    dept_assign_ou_reach_bypass_fault,
    "dept-assign",
    "foreign-ou",
    "reach-bypass"
);
fault!(
    dept_assign_cross_tenant_reach_bypass_fault,
    "dept-assign",
    "foreign",
    "reach-bypass"
);
