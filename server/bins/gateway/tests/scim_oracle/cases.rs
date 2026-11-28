case!(users_list_sync, "users-list", "sync");
case!(users_list_sync_foreign, "users-list", "sync-foreign");
case!(users_create_too_large, "users-create", "too-large");
case!(sp_success, "sp", "success");
case!(sp_foreign, "sp", "foreign");
case!(sp_invalid, "sp", "invalid");
case!(sp_bad_token, "sp", "bad-token");
case!(sp_expired, "sp", "expired");
case!(sp_legacy, "sp", "legacy");
case!(sp_empty_bearer, "sp", "empty-bearer");
case!(sp_wrong_scheme, "sp", "wrong-scheme");
case!(users_list_success, "users-list", "success");
case!(users_list_foreign, "users-list", "foreign");
case!(users_list_invalid, "users-list", "invalid");
case!(users_list_filter_eq, "users-list", "filter-eq");
case!(users_list_filter_co, "users-list", "filter-co");
case!(users_list_filter_sw, "users-list", "filter-sw");
case!(users_list_filter_pr, "users-list", "filter-pr");
case!(users_list_filter_id, "users-list", "filter-id");
case!(users_list_filter_active, "users-list", "filter-active");
case!(
    users_list_filter_unsupported,
    "users-list",
    "filter-unsupported"
);
case!(users_list_filter_bad_op, "users-list", "filter-bad-op");
case!(users_list_filter_co_bool, "users-list", "filter-co-bool");
case!(users_list_filter_bad_bool, "users-list", "filter-bad-bool");
case!(users_list_filter_empty, "users-list", "filter-empty");
case!(users_list_page, "users-list", "page");
case!(users_list_page_bad, "users-list", "page-bad");
case!(users_list_sync_bad, "users-list", "sync-bad");
case!(users_list_legacy, "users-list", "legacy");
case!(users_create_success, "users-create", "success");
case!(users_create_foreign, "users-create", "foreign");
case!(users_create_invalid, "users-create", "invalid");
case!(users_create_invalid_json, "users-create", "invalid-json");
case!(users_create_wrong_type, "users-create", "wrong-type");
case!(users_create_no_external, "users-create", "no-external");
case!(
    users_create_bad_content_type,
    "users-create",
    "bad-content-type"
);
case!(
    users_create_no_content_type,
    "users-create",
    "no-content-type"
);
case!(
    users_create_json_content_type,
    "users-create",
    "json-content-type"
);
case!(users_create_repeat, "users-create", "repeat");
case!(
    users_create_disabled_on_create,
    "users-create",
    "disabled-on-create"
);
case!(users_get_success, "users-get", "success");
case!(users_get_foreign, "users-get", "foreign");
case!(users_get_invalid, "users-get", "invalid");
case!(users_get_missing, "users-get", "missing");
case!(users_get_signed_id, "users-get", "signed-id");
case!(users_put_success, "users-put", "success");
case!(users_put_foreign, "users-put", "foreign");
case!(users_put_invalid, "users-put", "invalid");
case!(users_put_bad_id, "users-put", "bad-id");
case!(users_put_mismatch, "users-put", "mismatch");
case!(users_put_disable, "users-put", "disable");
case!(users_put_repeat, "users-put", "repeat");
case!(users_patch_success, "users-patch", "success");
case!(users_patch_foreign, "users-patch", "foreign");
case!(users_patch_invalid, "users-patch", "invalid");
case!(users_patch_bad_path, "users-patch", "bad-path");
case!(users_patch_bad_id, "users-patch", "bad-id");
case!(users_patch_bad_json, "users-patch", "bad-json");
case!(users_patch_deactivate, "users-patch", "deactivate");
case!(users_patch_null_active, "users-patch", "null-active");
case!(users_patch_object_active, "users-patch", "object-active");
case!(users_patch_remove_title, "users-patch", "remove-title");
case!(users_patch_remove_active, "users-patch", "remove-active");
case!(users_patch_emails_phones, "users-patch", "emails-phones");
case!(users_patch_department, "users-patch", "department");
case!(users_patch_empty_ops, "users-patch", "empty-ops");
case!(users_patch_repeat, "users-patch", "repeat");
case!(users_delete_success, "users-delete", "success");
case!(users_delete_foreign, "users-delete", "foreign");
case!(users_delete_invalid, "users-delete", "invalid");
case!(users_delete_hard, "users-delete", "hard");
case!(users_delete_missing, "users-delete", "missing");
case!(users_delete_repeat, "users-delete", "repeat");
case!(groups_list_success, "groups-list", "success");
case!(groups_list_foreign, "groups-list", "foreign");
case!(groups_list_invalid, "groups-list", "invalid");
case!(groups_list_page, "groups-list", "page");
case!(groups_list_page_bad, "groups-list", "page-bad");
case!(groups_create_success, "groups-create", "success");
case!(groups_create_foreign, "groups-create", "foreign");
case!(groups_create_invalid, "groups-create", "invalid");
case!(groups_create_invalid_json, "groups-create", "invalid-json");
case!(
    groups_create_unknown_member,
    "groups-create",
    "unknown-member"
);
case!(groups_create_rls_members, "groups-create", "rls-members");
case!(groups_create_repeat, "groups-create", "repeat");
case!(groups_get_success, "groups-get", "success");
case!(groups_get_foreign, "groups-get", "foreign");
case!(groups_get_invalid, "groups-get", "invalid");
case!(groups_patch_success, "groups-patch", "success");
case!(groups_patch_foreign, "groups-patch", "foreign");
case!(groups_patch_invalid, "groups-patch", "invalid");
case!(groups_patch_bad_path, "groups-patch", "bad-path");
case!(
    groups_patch_remove_members,
    "groups-patch",
    "remove-members"
);
case!(
    groups_patch_replace_members,
    "groups-patch",
    "replace-members"
);
case!(groups_patch_single_member, "groups-patch", "single-member");
case!(
    groups_patch_unknown_member,
    "groups-patch",
    "unknown-member"
);
case!(groups_patch_bad_id, "groups-patch", "bad-id");
case!(groups_patch_rls_members, "groups-patch", "rls-members");
case!(groups_patch_repeat, "groups-patch", "repeat");
case!(groups_delete_success, "groups-delete", "success");
case!(groups_delete_foreign, "groups-delete", "foreign");
case!(groups_delete_invalid, "groups-delete", "invalid");
case!(groups_delete_repeat, "groups-delete", "repeat");
case!(
    users_list_status_mutant,
    "users-list",
    "success-status-mutant"
);
case!(
    users_create_status_mutant,
    "users-create",
    "success-status-mutant"
);
case!(sp_status_mutant, "sp", "success-status-mutant");
case!(
    users_get_status_mutant,
    "users-get",
    "success-status-mutant"
);
case!(
    users_put_status_mutant,
    "users-put",
    "success-status-mutant"
);
case!(
    users_patch_status_mutant,
    "users-patch",
    "success-status-mutant"
);
case!(
    users_delete_status_mutant,
    "users-delete",
    "success-status-mutant"
);
case!(
    groups_list_status_mutant,
    "groups-list",
    "success-status-mutant"
);
case!(
    groups_create_status_mutant,
    "groups-create",
    "success-status-mutant"
);
case!(
    groups_get_status_mutant,
    "groups-get",
    "success-status-mutant"
);
case!(
    groups_patch_status_mutant,
    "groups-patch",
    "success-status-mutant"
);
case!(
    groups_delete_status_mutant,
    "groups-delete",
    "success-status-mutant"
);
