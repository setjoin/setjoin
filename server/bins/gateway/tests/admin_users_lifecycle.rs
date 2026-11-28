//! F01 slice `user-lifecycle` frozen-Go oracle, replayed without a Go upstream.
mod admin_users_lifecycle_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_users_lifecycle_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_users_lifecycle_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(create_success, "create", "success");
case!(create_derived_name, "create", "derived-name");
case!(create_folded, "create", "folded");
case!(create_quoted, "create", "quoted");
case!(create_outbox, "create", "outbox");
case!(create_scoped, "create", "scoped");
case!(create_bad_json, "create", "bad-json");
case!(create_required, "create", "required");
case!(create_bad_email, "create", "bad-email");
case!(create_reserved, "create", "reserved");
case!(create_display_long, "create", "display-long");
case!(create_weak, "create", "weak");
case!(create_no_upper, "create", "no-upper");
case!(create_too_long, "create", "too-long");
case!(create_contains_email, "create", "contains-email");
case!(create_common, "create", "common");
case!(create_non_local, "create", "non-local");
case!(create_scoped_foreign, "create", "scoped-foreign");
case!(create_duplicate, "create", "duplicate");
case!(create_oversize, "create", "oversize");
case!(create_denied, "create", "denied");
case!(create_repeat, "create", "repeat");
case!(create_status_mutant, "create", "success-status-mutant");

case!(update_success, "update", "success");
case!(update_disable, "update", "disable");
case!(update_enable, "update", "enable");
case!(update_all, "update", "all");
case!(update_folded, "update", "folded");
case!(update_no_fields, "update", "no-fields");
case!(update_empty_name, "update", "empty-name");
case!(update_typed, "update", "typed");
case!(update_bad_json, "update", "bad-json");
case!(update_bad_id, "update", "bad-id");
case!(update_missing, "update", "missing");
case!(update_foreign, "update", "foreign");
case!(update_self, "update", "self");
case!(update_guest, "update", "guest");
case!(update_denied, "update", "denied");
case!(update_outbox, "update", "outbox");
case!(update_repeat, "update", "repeat");
case!(update_status_mutant, "update", "success-status-mutant");

case!(delete_success, "delete", "success");
case!(delete_bad_id, "delete", "bad-id");
case!(delete_missing, "delete", "missing");
case!(delete_foreign, "delete", "foreign");
case!(delete_self, "delete", "self");
case!(delete_guest, "delete", "guest");
case!(delete_lifecycle, "delete", "lifecycle");
case!(delete_denied, "delete", "denied");
case!(delete_outbox, "delete", "outbox");
case!(delete_repeat, "delete", "repeat");
case!(delete_status_mutant, "delete", "success-status-mutant");

case!(password_success, "password", "success");
case!(password_keep, "password", "keep");
case!(password_must_change_null, "password", "must-change-null");
case!(password_weak, "password", "weak");
case!(password_empty, "password", "empty");
case!(password_contains_email, "password", "contains-email");
case!(password_common, "password", "common");
case!(password_bad_json, "password", "bad-json");
case!(password_bad_id, "password", "bad-id");
case!(password_missing, "password", "missing");
case!(password_foreign, "password", "foreign");
case!(password_guest, "password", "guest");
case!(password_denied, "password", "denied");
case!(password_repeat, "password", "repeat");
case!(password_status_mutant, "password", "success-status-mutant");

case!(secure_success, "secure", "success");
case!(secure_bad_id, "secure", "bad-id");
case!(secure_missing, "secure", "missing");
case!(secure_foreign, "secure", "foreign");
case!(secure_denied, "secure", "denied");
case!(secure_repeat, "secure", "repeat");
case!(secure_status_mutant, "secure", "success-status-mutant");

case!(sign_ins_success, "sign-ins", "success");
case!(sign_ins_empty, "sign-ins", "empty");
case!(sign_ins_bad_id, "sign-ins", "bad-id");
case!(sign_ins_missing, "sign-ins", "missing");
case!(sign_ins_foreign, "sign-ins", "foreign");
case!(sign_ins_denied, "sign-ins", "denied");
case!(sign_ins_status_mutant, "sign-ins", "success-status-mutant");

case!(
    app_password_revoke_success,
    "app-password-revoke",
    "success"
);
case!(app_password_revoke_repeat, "app-password-revoke", "repeat");
case!(app_password_revoke_bad_id, "app-password-revoke", "bad-id");
case!(app_password_revoke_bad_ap, "app-password-revoke", "bad-ap");
case!(
    app_password_revoke_missing,
    "app-password-revoke",
    "missing"
);
case!(
    app_password_revoke_missing_ap,
    "app-password-revoke",
    "missing-ap"
);
case!(
    app_password_revoke_foreign,
    "app-password-revoke",
    "foreign"
);
case!(app_password_revoke_denied, "app-password-revoke", "denied");
case!(
    app_password_revoke_status_mutant,
    "app-password-revoke",
    "success-status-mutant"
);

case!(import_success, "import", "success");
case!(import_headers_only, "import", "headers-only");
case!(import_malformed, "import", "malformed");
case!(import_bare_quote, "import", "bare-quote");
case!(import_missing_column, "import", "missing-column");
case!(import_missing_email, "import", "missing-email");
case!(import_empty_file, "import", "empty-file");
case!(import_common_row, "import", "common-row");
case!(import_scoped, "import", "scoped");
case!(import_crlf, "import", "crlf");
case!(import_blank_lines, "import", "blank-lines");
case!(import_single_row, "import", "single-row");
case!(import_no_file, "import", "no-file");
case!(import_value_file, "import", "value-file");
case!(import_not_multipart, "import", "not-multipart");
case!(import_no_boundary, "import", "no-boundary");
case!(import_truncated_form, "import", "truncated-form");
case!(import_denied, "import", "denied");
case!(import_repeat, "import", "repeat");
case!(import_status_mutant, "import", "success-status-mutant");

fault!(
    app_password_revoke_no_audit_fault,
    "app-password-revoke",
    "success",
    "no-audit"
);
fault!(secure_no_notify_mutant, "secure", "success", "no-notify");
