//! F01 slice `scope-sets` frozen-Go oracle, replayed without a Go upstream.
mod admin_scope_sets_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_scope_sets_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_scope_sets_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(list_success, "list", "success");
case!(list_cross_tenant, "list", "foreign");
case!(list_invalid_input, "list", "denied");
case!(list_status_mutant, "list", "success-status-mutant");
case!(get_success, "get", "success");
case!(get_cross_tenant, "get", "foreign");
case!(get_invalid_input, "get", "invalid");
case!(get_empty, "get", "empty");
case!(get_missing, "get", "missing");
case!(get_denied, "get", "denied");
case!(get_status_mutant, "get", "success-status-mutant");

case!(create_success, "create", "success");
case!(create_cross_tenant, "create", "foreign");
case!(create_invalid_input, "create", "invalid");
case!(create_repeat, "create", "repeat");
case!(create_empty, "create", "empty");
case!(create_dup, "create", "dup");
case!(create_dup_global, "create", "dup-global");
case!(create_dup_quoted, "create", "dup-quoted");
case!(create_bad_domain, "create", "bad-domain");
case!(create_folded, "create", "folded");
case!(create_denied, "create", "denied");
case!(create_reason, "create", "reason");
case!(create_reasoned, "create", "reasoned");
case!(create_status_mutant, "create", "success-status-mutant");
fault!(create_no_audit_fault, "create", "success", "no-audit");

case!(update_success, "update", "success");
case!(update_cross_tenant, "update", "foreign");
case!(update_invalid_input, "update", "invalid");
case!(update_repeat, "update", "repeat");
case!(update_bad_json, "update", "bad-json");
case!(update_missing, "update", "missing");
case!(update_dup, "update", "dup");
case!(update_empty, "update", "empty");
case!(update_empty_name, "update", "empty-name");
case!(update_partial, "update", "partial");
case!(update_typed, "update", "typed");
case!(update_folded, "update", "folded");
case!(update_denied, "update", "denied");
case!(update_reason, "update", "reason");
case!(update_status_mutant, "update", "success-status-mutant");
fault!(update_no_audit_fault, "update", "success", "no-audit");

case!(delete_success, "delete", "success");
case!(delete_cross_tenant, "delete", "foreign");
case!(delete_invalid_input, "delete", "invalid");
case!(delete_repeat, "delete", "repeat");
case!(delete_missing, "delete", "missing");
case!(delete_in_use, "delete", "in-use");
case!(delete_denied, "delete", "denied");
case!(delete_reason, "delete", "reason");
case!(delete_status_mutant, "delete", "success-status-mutant");
fault!(delete_no_audit_fault, "delete", "success", "no-audit");

case!(member_add_success, "member-add", "success");
case!(member_add_cross_tenant, "member-add", "foreign");
case!(member_add_invalid_input, "member-add", "invalid");
case!(member_add_repeat, "member-add", "repeat");
case!(member_add_bad_json, "member-add", "bad-json");
case!(member_add_required, "member-add", "required");
case!(member_add_zero, "member-add", "zero");
case!(member_add_bad_type, "member-add", "bad-type");
case!(member_add_missing_set, "member-add", "missing-set");
case!(member_add_ou, "member-add", "ou");
case!(member_add_foreign_ou, "member-add", "foreign-ou");
case!(member_add_group, "member-add", "group");
case!(member_add_foreign_group, "member-add", "foreign-group");
case!(member_add_group_missing, "member-add", "group-missing");
case!(member_add_group_dynamic, "member-add", "group-dynamic");
case!(member_add_group_plain, "member-add", "group-plain");
case!(member_add_folded, "member-add", "folded");
case!(member_add_denied, "member-add", "denied");
case!(member_add_reason, "member-add", "reason");
case!(
    member_add_status_mutant,
    "member-add",
    "success-status-mutant"
);
fault!(
    member_add_no_audit_fault,
    "member-add",
    "success",
    "no-audit"
);
fault!(
    member_add_reach_bypass_fault,
    "member-add",
    "foreign",
    "reach-bypass"
);
fault!(
    member_add_ou_reach_bypass_fault,
    "member-add",
    "foreign-ou",
    "reach-bypass"
);

case!(member_remove_success, "member-remove", "success");
case!(member_remove_cross_tenant, "member-remove", "foreign");
case!(member_remove_invalid_input, "member-remove", "invalid");
case!(member_remove_repeat, "member-remove", "repeat");
case!(member_remove_bad_type, "member-remove", "bad-type");
case!(member_remove_bad_member, "member-remove", "bad-member");
case!(member_remove_missing, "member-remove", "missing");
case!(member_remove_ou, "member-remove", "ou");
case!(member_remove_group, "member-remove", "group");
case!(member_remove_orphan, "member-remove", "orphan");
case!(member_remove_denied, "member-remove", "denied");
case!(member_remove_reason, "member-remove", "reason");
case!(
    member_remove_status_mutant,
    "member-remove",
    "success-status-mutant"
);
fault!(
    member_remove_no_audit_fault,
    "member-remove",
    "success",
    "no-audit"
);
