// Authored external-behavior case registrations; frozen Go supplies expectations.
case!(personal_list_foreign, "personal-list", "foreign");
case!(personal_list_invalid, "personal-list", "invalid");
case!(personal_list_program, "personal-list", "program");
case!(personal_list_transport, "personal-list", "transport");
mutant!(
    personal_list_status_mutant,
    "personal-list",
    "changed-status"
);
case!(personal_create_foreign, "personal-create", "foreign");
case!(personal_create_invalid, "personal-create", "invalid");
case!(personal_create_repeat, "personal-create", "repeat");
case!(personal_create_all_states, "personal-create", "all-states");
case!(personal_create_empty_body, "personal-create", "empty-body");
case!(personal_create_null_body, "personal-create", "null-body");
case!(personal_create_bad_type, "personal-create", "bad-type");
case!(personal_create_trailing, "personal-create", "trailing");
case!(personal_create_folded, "personal-create", "folded");
case!(personal_create_duplicate, "personal-create", "duplicate");
case!(personal_create_name_long, "personal-create", "name-long");
case!(personal_create_name_utf8, "personal-create", "name-utf8");
case!(personal_create_name_200, "personal-create", "name-200");
case!(personal_create_blank_name, "personal-create", "blank-name");
case!(personal_create_body_size, "personal-create", "body-size");
case!(
    personal_create_program_size,
    "personal-create",
    "program-size"
);
case!(
    personal_create_actions_size,
    "personal-create",
    "actions-size"
);
case!(
    personal_create_many_actions,
    "personal-create",
    "many-actions"
);
case!(
    personal_create_many_conditions,
    "personal-create",
    "many-conditions"
);
case!(
    personal_create_object_conditions,
    "personal-create",
    "object-conditions"
);
case!(
    personal_create_object_actions,
    "personal-create",
    "object-actions"
);
case!(
    personal_create_scalar_entry,
    "personal-create",
    "scalar-entry"
);
case!(
    personal_create_type_number,
    "personal-create",
    "type-number"
);
case!(personal_create_null_entry, "personal-create", "null-entry");
case!(
    personal_create_null_program,
    "personal-create",
    "null-program"
);
case!(
    personal_create_missing_program,
    "personal-create",
    "missing-program"
);
case!(personal_create_bad_run_on, "personal-create", "bad-run-on");
case!(
    personal_create_bad_priority,
    "personal-create",
    "bad-priority"
);
case!(
    personal_create_huge_priority,
    "personal-create",
    "huge-priority"
);
case!(personal_create_rule_limit, "personal-create", "rule-limit");
case!(
    personal_create_raw_surrogate,
    "personal-create",
    "raw-surrogate"
);
case!(
    personal_create_string_surrogate,
    "personal-create",
    "string-surrogate"
);
case!(
    personal_create_block_forward_to,
    "personal-create",
    "block-forward_to"
);
case!(
    personal_create_block_redirect,
    "personal-create",
    "block-redirect"
);
case!(personal_create_block_bcc, "personal-create", "block-bcc");
case!(
    personal_create_block_append_footer,
    "personal-create",
    "block-append_footer"
);
case!(
    personal_create_block_add_header,
    "personal-create",
    "block-add_header"
);
mutant!(
    personal_create_status_mutant,
    "personal-create",
    "changed-status"
);
case!(personal_update_foreign, "personal-update", "foreign");
case!(personal_update_invalid, "personal-update", "invalid");
case!(personal_update_repeat, "personal-update", "repeat");
case!(personal_update_all_states, "personal-update", "all-states");
case!(personal_update_empty_body, "personal-update", "empty-body");
case!(personal_update_null_body, "personal-update", "null-body");
case!(personal_update_trailing, "personal-update", "trailing");
case!(personal_update_folded, "personal-update", "folded");
case!(personal_update_transport, "personal-update", "transport");
case!(personal_update_missing, "personal-update", "missing");
case!(personal_update_encoded_id, "personal-update", "encoded-id");
case!(personal_update_bad_run_on, "personal-update", "bad-run-on");
case!(
    personal_update_object_conditions,
    "personal-update",
    "object-conditions"
);
mutant!(
    personal_update_status_mutant,
    "personal-update",
    "changed-status"
);
case!(personal_delete_foreign, "personal-delete", "foreign");
case!(personal_delete_invalid, "personal-delete", "invalid");
case!(personal_delete_repeat, "personal-delete", "repeat");
case!(personal_delete_all_states, "personal-delete", "all-states");
case!(personal_delete_transport, "personal-delete", "transport");
case!(personal_delete_missing, "personal-delete", "missing");
case!(personal_delete_encoded_id, "personal-delete", "encoded-id");
mutant!(
    personal_delete_status_mutant,
    "personal-delete",
    "changed-status"
);
case!(retro_apply_foreign, "retro-apply", "foreign");
case!(retro_apply_invalid, "retro-apply", "invalid");
case!(retro_apply_repeat, "retro-apply", "repeat");
case!(retro_apply_all_states, "retro-apply", "all-states");
case!(retro_apply_empty_body, "retro-apply", "empty-body");
case!(retro_apply_null_body, "retro-apply", "null-body");
case!(retro_apply_bad_type, "retro-apply", "bad-type");
case!(retro_apply_bad_window, "retro-apply", "bad-window");
case!(retro_apply_window_all, "retro-apply", "window-all");
case!(retro_apply_window_1y, "retro-apply", "window-1y");
case!(retro_apply_inflight_limit, "retro-apply", "inflight-limit");
case!(retro_apply_missing, "retro-apply", "missing");
case!(retro_apply_transport, "retro-apply", "transport");
case!(retro_apply_encoded_suffix, "retro-apply", "encoded-suffix");
mutant!(retro_apply_status_mutant, "retro-apply", "changed-status");
case!(retro_status_foreign, "retro-status", "foreign");
case!(retro_status_invalid, "retro-status", "invalid");
case!(retro_status_pending, "retro-status", "pending");
case!(retro_status_bad_payload, "retro-status", "bad-payload");
mutant!(retro_status_status_mutant, "retro-status", "changed-status");
case!(admin_list_foreign, "admin-list", "foreign");
case!(admin_list_invalid, "admin-list", "invalid");
case!(admin_list_denied, "admin-list", "denied");
case!(admin_list_mailbox_own, "admin-list", "mailbox-own");
case!(admin_list_mailbox_other, "admin-list", "mailbox-other");
case!(admin_list_program, "admin-list", "program");
case!(admin_list_transport, "admin-list", "transport");
mutant!(admin_list_status_mutant, "admin-list", "changed-status");
case!(admin_get_foreign, "admin-get", "foreign");
case!(admin_get_invalid, "admin-get", "invalid");
case!(admin_get_denied, "admin-get", "denied");
case!(admin_get_missing, "admin-get", "missing");
case!(admin_get_transport, "admin-get", "transport");
case!(admin_get_program, "admin-get", "program");
case!(admin_get_encoded_id, "admin-get", "encoded-id");
mutant!(admin_get_status_mutant, "admin-get", "changed-status");
case!(admin_create_foreign, "admin-create", "foreign");
case!(admin_create_invalid, "admin-create", "invalid");
case!(admin_create_repeat, "admin-create", "repeat");
case!(admin_create_all_states, "admin-create", "all-states");
case!(admin_create_denied, "admin-create", "denied");
case!(admin_create_empty_body, "admin-create", "empty-body");
case!(admin_create_null_body, "admin-create", "null-body");
case!(admin_create_bad_type, "admin-create", "bad-type");
case!(admin_create_folded, "admin-create", "folded");
case!(admin_create_blank_name, "admin-create", "blank-name");
case!(
    admin_create_missing_mailbox,
    "admin-create",
    "missing-mailbox"
);
case!(
    admin_create_transport_body,
    "admin-create",
    "transport-body"
);
case!(
    admin_create_foreign_mailbox,
    "admin-create",
    "foreign-mailbox"
);
case!(admin_create_bad_run_on, "admin-create", "bad-run-on");
case!(admin_create_huge_priority, "admin-create", "huge-priority");
case!(
    admin_create_missing_program,
    "admin-create",
    "missing-program"
);
case!(admin_create_raw_surrogate, "admin-create", "raw-surrogate");
case!(admin_create_expired, "admin-create", "expired");
case!(admin_create_eligible, "admin-create", "eligible");
case!(admin_create_revoked, "admin-create", "revoked");
mutant!(admin_create_status_mutant, "admin-create", "changed-status");
case!(admin_update_foreign, "admin-update", "foreign");
case!(admin_update_invalid, "admin-update", "invalid");
case!(admin_update_repeat, "admin-update", "repeat");
case!(admin_update_all_states, "admin-update", "all-states");
case!(admin_update_denied, "admin-update", "denied");
case!(admin_update_empty_body, "admin-update", "empty-body");
case!(admin_update_null_body, "admin-update", "null-body");
case!(admin_update_foreign_rule, "admin-update", "foreign-rule");
case!(admin_update_transport, "admin-update", "transport");
case!(admin_update_missing, "admin-update", "missing");
case!(admin_update_encoded_id, "admin-update", "encoded-id");
case!(admin_update_bad_run_on, "admin-update", "bad-run-on");
mutant!(admin_update_status_mutant, "admin-update", "changed-status");
case!(admin_delete_foreign, "admin-delete", "foreign");
case!(admin_delete_invalid, "admin-delete", "invalid");
case!(admin_delete_repeat, "admin-delete", "repeat");
case!(admin_delete_all_states, "admin-delete", "all-states");
case!(admin_delete_denied, "admin-delete", "denied");
case!(admin_delete_foreign_rule, "admin-delete", "foreign-rule");
case!(admin_delete_transport, "admin-delete", "transport");
case!(admin_delete_missing, "admin-delete", "missing");
case!(admin_delete_encoded_id, "admin-delete", "encoded-id");
mutant!(admin_delete_status_mutant, "admin-delete", "changed-status");
case!(admin_test_foreign, "admin-test", "foreign");
case!(admin_test_invalid, "admin-test", "invalid");
case!(admin_test_denied, "admin-test", "denied");
case!(admin_test_missing, "admin-test", "missing");
case!(admin_test_transport, "admin-test", "transport");
case!(admin_test_encoded_suffix, "admin-test", "encoded-suffix");
case!(admin_test_read_console, "admin-test", "read-console");
mutant!(admin_test_status_mutant, "admin-test", "changed-status");
case!(template_list_foreign, "template-list", "foreign");
case!(template_list_invalid, "template-list", "invalid");
case!(template_list_scoped, "template-list", "scoped");
case!(template_list_empty_list, "template-list", "empty-list");
case!(
    template_list_null_description,
    "template-list",
    "null-description"
);
case!(
    template_list_schema_missing,
    "template-list",
    "schema-missing"
);
mutant!(
    template_list_status_mutant,
    "template-list",
    "changed-status"
);
case!(template_get_foreign, "template-get", "foreign");
case!(template_get_invalid, "template-get", "invalid");
case!(template_get_scoped, "template-get", "scoped");
case!(template_get_missing, "template-get", "missing");
case!(template_get_system, "template-get", "system");
case!(template_get_disabled, "template-get", "disabled");
case!(
    template_get_null_description,
    "template-get",
    "null-description"
);
case!(template_get_encoded_id, "template-get", "encoded-id");
case!(
    template_get_schema_missing,
    "template-get",
    "schema-missing"
);
mutant!(template_get_status_mutant, "template-get", "changed-status");
case!(template_resolve_foreign, "template-resolve", "foreign");
case!(template_resolve_invalid, "template-resolve", "invalid");
case!(template_resolve_scoped, "template-resolve", "scoped");
case!(template_resolve_missing, "template-resolve", "missing");
case!(template_resolve_disabled, "template-resolve", "disabled");
case!(
    template_resolve_null_description,
    "template-resolve",
    "null-description"
);
case!(
    template_resolve_encoded_suffix,
    "template-resolve",
    "encoded-suffix"
);
case!(
    template_resolve_schema_missing,
    "template-resolve",
    "schema-missing"
);
mutant!(
    template_resolve_status_mutant,
    "template-resolve",
    "changed-status"
);
case!(template_create_foreign, "template-create", "foreign");
case!(template_create_invalid, "template-create", "invalid");
case!(template_create_repeat, "template-create", "repeat");
case!(template_create_all_states, "template-create", "all-states");
case!(template_create_scoped, "template-create", "scoped");
case!(template_create_empty_body, "template-create", "empty-body");
case!(template_create_null_body, "template-create", "null-body");
case!(template_create_bad_type, "template-create", "bad-type");
case!(template_create_trailing, "template-create", "trailing");
case!(template_create_folded, "template-create", "folded");
case!(
    template_create_bad_category,
    "template-create",
    "bad-category"
);
case!(
    template_create_sort_overflow,
    "template-create",
    "sort-overflow"
);
case!(
    template_create_raw_surrogate,
    "template-create",
    "raw-surrogate"
);
case!(
    template_create_schema_missing,
    "template-create",
    "schema-missing"
);
mutant!(
    template_create_status_mutant,
    "template-create",
    "changed-status"
);
case!(template_update_foreign, "template-update", "foreign");
case!(template_update_invalid, "template-update", "invalid");
case!(template_update_repeat, "template-update", "repeat");
case!(template_update_all_states, "template-update", "all-states");
case!(template_update_scoped, "template-update", "scoped");
case!(template_update_empty_body, "template-update", "empty-body");
case!(template_update_null_body, "template-update", "null-body");
case!(template_update_system, "template-update", "system");
case!(template_update_missing, "template-update", "missing");
case!(template_update_folded, "template-update", "folded");
case!(
    template_update_bad_category,
    "template-update",
    "bad-category"
);
case!(
    template_update_sort_overflow,
    "template-update",
    "sort-overflow"
);
case!(
    template_update_schema_missing,
    "template-update",
    "schema-missing"
);
mutant!(
    template_update_status_mutant,
    "template-update",
    "changed-status"
);
case!(template_delete_foreign, "template-delete", "foreign");
case!(template_delete_invalid, "template-delete", "invalid");
case!(template_delete_repeat, "template-delete", "repeat");
case!(template_delete_all_states, "template-delete", "all-states");
case!(template_delete_scoped, "template-delete", "scoped");
case!(template_delete_missing, "template-delete", "missing");
case!(template_delete_system, "template-delete", "system");
case!(template_delete_disabled, "template-delete", "disabled");
case!(template_delete_encoded_id, "template-delete", "encoded-id");
case!(
    template_delete_schema_missing,
    "template-delete",
    "schema-missing"
);
mutant!(
    template_delete_status_mutant,
    "template-delete",
    "changed-status"
);
case!(
    template_visibility_get_foreign,
    "template-visibility-get",
    "foreign"
);
case!(
    template_visibility_get_invalid,
    "template-visibility-get",
    "invalid"
);
case!(
    template_visibility_get_scoped,
    "template-visibility-get",
    "scoped"
);
case!(
    template_visibility_get_missing,
    "template-visibility-get",
    "missing"
);
case!(
    template_visibility_get_visibility_many,
    "template-visibility-get",
    "visibility-many"
);
case!(
    template_visibility_get_encoded_suffix,
    "template-visibility-get",
    "encoded-suffix"
);
case!(
    template_visibility_get_schema_missing,
    "template-visibility-get",
    "schema-missing"
);
mutant!(
    template_visibility_get_status_mutant,
    "template-visibility-get",
    "changed-status"
);
case!(
    template_visibility_set_foreign,
    "template-visibility-set",
    "foreign"
);
case!(
    template_visibility_set_invalid,
    "template-visibility-set",
    "invalid"
);
case!(
    template_visibility_set_repeat,
    "template-visibility-set",
    "repeat"
);
case!(
    template_visibility_set_all_states,
    "template-visibility-set",
    "all-states"
);
case!(
    template_visibility_set_scoped,
    "template-visibility-set",
    "scoped"
);
case!(
    template_visibility_set_empty_body,
    "template-visibility-set",
    "empty-body"
);
case!(
    template_visibility_set_null_body,
    "template-visibility-set",
    "null-body"
);
case!(
    template_visibility_set_bad_type,
    "template-visibility-set",
    "bad-type"
);
case!(
    template_visibility_set_global_hide,
    "template-visibility-set",
    "global-hide"
);
case!(
    template_visibility_set_global_show,
    "template-visibility-set",
    "global-show"
);
case!(
    template_visibility_set_show_user,
    "template-visibility-set",
    "show-user"
);
case!(
    template_visibility_set_unknown_user,
    "template-visibility-set",
    "unknown-user"
);
case!(
    template_visibility_set_missing,
    "template-visibility-set",
    "missing"
);
case!(
    template_visibility_set_schema_missing,
    "template-visibility-set",
    "schema-missing"
);
mutant!(
    template_visibility_set_status_mutant,
    "template-visibility-set",
    "changed-status"
);
case!(
    template_personal_list_foreign,
    "template-personal-list",
    "foreign"
);
case!(
    template_personal_list_invalid,
    "template-personal-list",
    "invalid"
);
case!(
    template_personal_list_empty_list,
    "template-personal-list",
    "empty-list"
);
case!(
    template_personal_list_admin_view,
    "template-personal-list",
    "admin-view"
);
case!(
    template_personal_list_null_description,
    "template-personal-list",
    "null-description"
);
case!(
    template_personal_list_schema_missing,
    "template-personal-list",
    "schema-missing"
);
mutant!(
    template_personal_list_status_mutant,
    "template-personal-list",
    "changed-status"
);
case!(
    admin_create_from_template_invalid,
    "admin-create",
    "from-template-invalid"
);
case!(
    admin_create_from_template_type,
    "admin-create",
    "from-template-type"
);
case!(
    admin_create_from_template_null,
    "admin-create",
    "from-template-null"
);
case!(
    admin_create_from_template_unresolved,
    "admin-create",
    "from-template-unresolved"
);
case!(
    admin_create_from_template_missing,
    "admin-create",
    "from-template-missing"
);
case!(
    admin_create_from_template_bad_id,
    "admin-create",
    "from-template-bad-id"
);
case!(
    admin_create_from_template_disabled,
    "admin-create",
    "from-template-disabled"
);
case!(
    admin_create_from_template_spoof,
    "admin-create",
    "from-template-spoof"
);
case!(
    admin_create_from_template_schema_missing,
    "admin-create",
    "from-template-schema-missing"
);
case!(
    admin_create_from_template_repeat,
    "admin-create",
    "from-template-repeat"
);
