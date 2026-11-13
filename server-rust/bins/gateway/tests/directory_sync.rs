//! F02 slice 1 (AD administration) frozen-Go oracle, replayed without a Go upstream.
mod common;
mod dirsync_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            dirsync_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            dirsync_oracle::run($action, $kind, Some($fault)).await
        }
    };
}
case!(config_success, "config", "success");
case!(config_cross_tenant, "config", "foreign");
case!(config_invalid_input, "config", "invalid");
case!(sync_log_success, "sync-log", "success");
case!(sync_log_cross_tenant, "sync-log", "foreign");
case!(sync_log_invalid_input, "sync-log", "invalid");
case!(sync_log_limit, "sync-log", "limit");
case!(ldap_config_success, "ldap-config", "success");
case!(ldap_config_cross_tenant, "ldap-config", "foreign");
case!(ldap_config_invalid_input, "ldap-config", "invalid");
case!(ldap_sync_log_success, "ldap-sync-log", "success");
case!(ldap_sync_log_cross_tenant, "ldap-sync-log", "foreign");
case!(ldap_sync_log_invalid_input, "ldap-sync-log", "invalid");
case!(ldap_sync_log_limit, "ldap-sync-log", "limit");
case!(conflicts_success, "conflicts", "success");
case!(conflicts_cross_tenant, "conflicts", "foreign");
case!(conflicts_invalid_input, "conflicts", "invalid");
case!(resolve_success, "resolve", "success");
case!(resolve_cross_tenant, "resolve", "foreign");
case!(resolve_invalid_input, "resolve", "invalid");
case!(resolve_repeat, "resolve", "repeat");
case!(resolve_bad_resolution, "resolve", "bad-resolution");
case!(resolve_all_success, "resolve-all", "success");
case!(resolve_all_cross_tenant, "resolve-all", "foreign");
case!(resolve_all_invalid_input, "resolve-all", "invalid");
case!(resolve_all_repeat, "resolve-all", "repeat");
case!(resolve_all_accept_remote, "resolve-all", "accept");
case!(policy_get_success, "policy-get", "success");
case!(policy_get_cross_tenant, "policy-get", "foreign");
case!(policy_get_invalid_input, "policy-get", "invalid");
case!(policy_get_scoped_foreign, "policy-get", "scoped-foreign");
case!(policy_set_success, "policy-set", "success");
case!(policy_set_cross_tenant, "policy-set", "foreign");
case!(policy_set_invalid_input, "policy-set", "invalid");
case!(policy_set_repeat, "policy-set", "repeat");
case!(policy_set_managed, "policy-set", "managed");
case!(policy_set_krb5_managed, "policy-set", "krb5-managed");
case!(policy_set_bad_policy, "policy-set", "bad-policy");
case!(policy_set_folded_keys, "policy-set", "folded");
case!(principal_success, "principal", "success");
case!(principal_cross_tenant, "principal", "foreign");
case!(principal_invalid_input, "principal", "invalid");
case!(principal_repeat, "principal", "repeat");
case!(principal_blank, "principal", "blank");
case!(principal_missing_user, "principal", "missing-user");

case!(
    ldap_config_status_mutant,
    "ldap-config",
    "success-status-mutant"
);
case!(
    ldap_sync_log_status_mutant,
    "ldap-sync-log",
    "success-status-mutant"
);
case!(config_status_mutant, "config", "success-status-mutant");
case!(sync_log_status_mutant, "sync-log", "success-status-mutant");
case!(
    conflicts_status_mutant,
    "conflicts",
    "success-status-mutant"
);
case!(resolve_status_mutant, "resolve", "success-status-mutant");
case!(
    resolve_all_status_mutant,
    "resolve-all",
    "success-status-mutant"
);
case!(
    policy_get_status_mutant,
    "policy-get",
    "success-status-mutant"
);
case!(
    policy_set_status_mutant,
    "policy-set",
    "success-status-mutant"
);
case!(
    principal_status_mutant,
    "principal",
    "success-status-mutant"
);
mutant!(
    principal_no_audit_mutant,
    "principal",
    "success",
    "no-audit"
);
mutant!(
    principal_no_notify_mutant,
    "principal",
    "success",
    "no-notify"
);
mutant!(
    resolve_double_bump_mutant,
    "resolve",
    "success",
    "double-bump"
);
mutant!(
    resolve_all_no_tenant_filter_mutant,
    "resolve-all",
    "foreign",
    "no-tenant-filter"
);
