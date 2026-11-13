//! F01 slice `users` frozen-Go oracle, replayed without a Go upstream.
mod admin_identity_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(users_success, "users", "success");
case!(users_cross_tenant, "users", "foreign");
case!(users_denied, "users", "denied");
case!(users_invalid_input, "users", "invalid");
case!(users_filtered, "users", "filtered");
case!(users_paged, "users", "paged");
case!(users_scoped, "users", "scoped");
case!(users_status_mutant, "users", "success-status-mutant");
mutant!(
    users_no_tenant_filter_mutant,
    "users",
    "foreign",
    "no-tenant-filter"
);
case!(user_success, "user", "success");
case!(user_cross_tenant, "user", "foreign");
case!(user_invalid_input, "user", "invalid");
case!(user_missing, "user", "missing");
case!(user_status_mutant, "user", "success-status-mutant");
mutant!(
    user_no_tenant_filter_mutant,
    "user",
    "foreign",
    "no-tenant-filter"
);
case!(aliases_success, "aliases", "success");
case!(aliases_cross_tenant, "aliases", "foreign");
case!(aliases_invalid_input, "aliases", "invalid");
case!(aliases_zero, "aliases", "zero");
case!(aliases_status_mutant, "aliases", "success-status-mutant");
mutant!(
    aliases_no_tenant_filter_mutant,
    "aliases",
    "foreign",
    "no-tenant-filter"
);
case!(alias_add_success, "alias-add", "success");
case!(alias_add_cross_tenant, "alias-add", "foreign");
case!(alias_add_invalid_input, "alias-add", "invalid");
case!(alias_add_empty, "alias-add", "empty");
case!(alias_add_bad_email, "alias-add", "bad-email");
case!(alias_add_reserved, "alias-add", "reserved");
case!(alias_add_dup, "alias-add", "dup");
case!(alias_add_repeat, "alias-add", "repeat");
case!(alias_add_folded, "alias-add", "folded");
case!(alias_add_denied, "alias-add", "denied");
case!(
    alias_add_status_mutant,
    "alias-add",
    "success-status-mutant"
);
mutant!(
    alias_add_no_tenant_filter_mutant,
    "alias-add",
    "foreign",
    "no-tenant-filter"
);
case!(alias_remove_success, "alias-remove", "success");
case!(alias_remove_cross_tenant, "alias-remove", "foreign");
case!(alias_remove_invalid_input, "alias-remove", "invalid");
case!(alias_remove_repeat, "alias-remove", "repeat");
case!(
    alias_remove_status_mutant,
    "alias-remove",
    "success-status-mutant"
);
mutant!(
    alias_remove_no_tenant_filter_mutant,
    "alias-remove",
    "foreign",
    "no-tenant-filter"
);
case!(quota_success, "quota", "success");
case!(quota_cross_tenant, "quota", "foreign");
case!(quota_invalid_input, "quota", "invalid");
case!(quota_missing, "quota", "missing");
case!(quota_status_mutant, "quota", "success-status-mutant");
mutant!(
    quota_no_tenant_filter_mutant,
    "quota",
    "foreign",
    "no-tenant-filter"
);
case!(quota_set_success, "quota-set", "success");
case!(quota_set_cross_tenant, "quota-set", "foreign");
case!(quota_set_invalid_input, "quota-set", "invalid");
case!(quota_set_bad_json, "quota-set", "bad-json");
case!(quota_set_partial, "quota-set", "partial");
case!(quota_set_nonpositive, "quota-set", "nonpositive");
case!(quota_set_folded, "quota-set", "folded");
case!(quota_set_repeat, "quota-set", "repeat");
case!(
    quota_set_status_mutant,
    "quota-set",
    "success-status-mutant"
);
mutant!(
    quota_set_no_tenant_filter_mutant,
    "quota-set",
    "foreign",
    "no-tenant-filter"
);
case!(app_passwords_success, "app-passwords", "success");
case!(app_passwords_cross_tenant, "app-passwords", "foreign");
case!(app_passwords_invalid_input, "app-passwords", "invalid");
case!(
    app_passwords_status_mutant,
    "app-passwords",
    "success-status-mutant"
);
mutant!(
    app_passwords_no_tenant_filter_mutant,
    "app-passwords",
    "foreign",
    "no-tenant-filter"
);
case!(app_access_success, "app-access", "success");
case!(app_access_cross_tenant, "app-access", "foreign");
case!(app_access_invalid_input, "app-access", "invalid");
case!(
    app_access_status_mutant,
    "app-access",
    "success-status-mutant"
);
mutant!(
    app_access_no_tenant_filter_mutant,
    "app-access",
    "foreign",
    "no-tenant-filter"
);
case!(app_access_set_success, "app-access-set", "success");
case!(app_access_set_update, "app-access-set", "update");
case!(app_access_set_invalid_input, "app-access-set", "invalid");
case!(app_access_set_cross_tenant, "app-access-set", "foreign");
case!(app_access_set_bad_app, "app-access-set", "bad-app");
case!(app_access_set_bad_body, "app-access-set", "bad-body");
case!(app_access_set_empty, "app-access-set", "empty");
case!(
    app_access_set_missing_user,
    "app-access-set",
    "missing-user"
);
case!(app_access_set_repeat, "app-access-set", "repeat");
case!(
    app_access_set_status_mutant,
    "app-access-set",
    "success-status-mutant"
);
case!(sessions_success, "sessions", "success");
case!(sessions_cross_tenant, "sessions", "foreign");
case!(sessions_invalid_input, "sessions", "invalid");
case!(sessions_missing, "sessions", "missing");
case!(sessions_scoped, "sessions", "scoped");
case!(sessions_status_mutant, "sessions", "success-status-mutant");
mutant!(
    app_access_set_no_audit_mutant,
    "app-access-set",
    "success",
    "no-audit"
);
mutant!(
    quota_set_double_bump_mutant,
    "quota-set",
    "success",
    "double-bump"
);
