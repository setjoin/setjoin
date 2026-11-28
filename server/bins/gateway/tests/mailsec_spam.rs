//! F06 slice `spam`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("spam", $action, $kind, None).await
        }
    };
}

case!(dashboard_success, "dashboard", "success");
case!(dashboard_empty, "dashboard", "empty");
case!(dashboard_denied, "dashboard", "denied");
case!(dashboard_scoped, "dashboard", "scoped");
case!(dashboard_ignored_query, "dashboard", "ignored-query");
case!(
    dashboard_status_mutant,
    "dashboard",
    "success-status-mutant"
);

case!(reset_success, "reset", "success");
case!(reset_norow, "reset", "norow");
case!(reset_missing, "reset", "missing");
case!(reset_unreachable, "reset", "unreachable");
case!(reset_scoped, "reset", "scoped");
case!(reset_denied, "reset", "denied");
case!(reset_bad_id, "reset", "bad-id");
case!(reset_zero_id, "reset", "zero-id");
case!(reset_negative_id, "reset", "negative-id");
case!(reset_repeat, "reset", "repeat");
case!(reset_status_mutant, "reset", "success-status-mutant");

case!(disable_success, "disable", "success");
case!(disable_fresh, "disable", "fresh");
case!(disable_missing, "disable", "missing");
case!(disable_unreachable, "disable", "unreachable");
case!(disable_scoped, "disable", "scoped");
case!(disable_denied, "disable", "denied");
case!(disable_bad_id, "disable", "bad-id");
case!(disable_repeat, "disable", "repeat");
case!(disable_status_mutant, "disable", "success-status-mutant");

case!(enable_success, "enable", "success");
case!(enable_norow, "enable", "norow");
case!(enable_unreachable, "enable", "unreachable");
case!(enable_scoped, "enable", "scoped");
case!(enable_denied, "enable", "denied");
case!(enable_bad_id, "enable", "bad-id");
case!(enable_repeat, "enable", "repeat");
case!(enable_status_mutant, "enable", "success-status-mutant");

case!(senders_get_success, "senders-get", "success");
case!(senders_get_empty, "senders-get", "empty");
case!(senders_get_foreign, "senders-get", "foreign");
case!(senders_get_flag_on, "senders-get", "flag-on");
case!(senders_get_flag_on_empty, "senders-get", "flag-on-empty");
case!(senders_get_ignored_query, "senders-get", "ignored-query");
case!(
    senders_get_status_mutant,
    "senders-get",
    "success-status-mutant"
);

case!(senders_put_success, "senders-put", "success");
case!(senders_put_empty_lists, "senders-put", "empty-lists");
case!(senders_put_null_lists, "senders-put", "null-lists");
case!(senders_put_duplicate, "senders-put", "duplicate");
case!(senders_put_invalid_json, "senders-put", "invalid-json");
case!(senders_put_null_element, "senders-put", "null-element");
case!(
    senders_put_mixed_case_keys,
    "senders-put",
    "mixed-case-keys"
);
case!(senders_put_foreign, "senders-put", "foreign");
case!(senders_put_repeat, "senders-put", "repeat");
case!(
    senders_put_flag_on_success,
    "senders-put",
    "flag-on-success"
);
case!(senders_put_flag_on_repeat, "senders-put", "flag-on-repeat");
case!(
    senders_put_flag_on_missing_headers,
    "senders-put",
    "flag-on-missing-headers"
);
case!(
    senders_put_flag_on_nil_lists,
    "senders-put",
    "flag-on-nil-lists"
);
case!(senders_put_flag_on_stale, "senders-put", "flag-on-stale");
case!(
    senders_put_flag_on_invalid,
    "senders-put",
    "flag-on-invalid"
);
case!(
    senders_put_flag_on_overlap,
    "senders-put",
    "flag-on-overlap"
);
case!(
    senders_put_status_mutant,
    "senders-put",
    "success-status-mutant"
);

case!(never_block_success, "never-block", "success");
case!(never_block_absent, "never-block", "absent");
case!(never_block_already_safe, "never-block", "already-safe");
case!(never_block_empty_sender, "never-block", "empty-sender");
case!(never_block_invalid_json, "never-block", "invalid-json");
case!(never_block_flag_on, "never-block", "flag-on");
case!(never_block_foreign, "never-block", "foreign");
case!(never_block_repeat, "never-block", "repeat");
case!(
    never_block_status_mutant,
    "never-block",
    "success-status-mutant"
);

case!(control_get_success, "control-get", "success");
case!(control_get_with_state, "control-get", "with-state");
case!(control_get_foreign, "control-get", "foreign");
case!(
    control_get_missing_message,
    "control-get",
    "missing-message"
);
case!(control_get_bad_mailbox, "control-get", "bad-mailbox");
case!(control_get_bad_message, "control-get", "bad-message");
case!(control_get_bad_time, "control-get", "bad-time");
case!(control_get_missing_params, "control-get", "missing-params");
case!(
    control_get_status_mutant,
    "control-get",
    "success-status-mutant"
);

case!(control_action_success, "control-action", "success");
case!(
    control_action_always_focus,
    "control-action",
    "always-focus"
);
case!(control_action_never_focus, "control-action", "never-focus");
case!(control_action_vip, "control-action", "vip");
case!(control_action_not_vip, "control-action", "not-vip");
case!(control_action_block, "control-action", "block");
case!(control_action_never_block, "control-action", "never-block");
case!(control_action_report_spam, "control-action", "report-spam");
case!(
    control_action_report_phishing,
    "control-action",
    "report-phishing"
);
case!(control_action_undo, "control-action", "undo");
case!(control_action_undo_stale, "control-action", "undo-stale");
case!(
    control_action_undo_no_target,
    "control-action",
    "undo-no-target"
);
case!(control_action_stale, "control-action", "stale");
case!(control_action_conflict, "control-action", "conflict");
case!(control_action_bad_action, "control-action", "bad-action");
case!(control_action_flag_off, "control-action", "flag-off");
case!(control_action_foreign, "control-action", "foreign");
case!(control_action_bad_json, "control-action", "bad-json");
case!(
    control_action_unknown_field,
    "control-action",
    "unknown-field"
);
case!(control_action_trailing, "control-action", "trailing");
case!(control_action_bad_target, "control-action", "bad-target");
case!(
    control_action_bad_operation,
    "control-action",
    "bad-operation"
);
case!(
    control_action_bad_target_operation,
    "control-action",
    "bad-target-operation"
);
case!(
    control_action_missing_if_match,
    "control-action",
    "missing-if-match"
);
case!(control_action_repeat, "control-action", "repeat");
case!(
    control_action_status_mutant,
    "control-action",
    "success-status-mutant"
);

case!(trusted_list_success, "trusted-list", "success");
case!(trusted_list_empty, "trusted-list", "empty");
case!(trusted_list_foreign, "trusted-list", "foreign");
case!(trusted_list_ignored_query, "trusted-list", "ignored-query");
case!(
    trusted_list_status_mutant,
    "trusted-list",
    "success-status-mutant"
);

case!(trusted_add_success, "trusted-add", "success");
case!(trusted_add_normalized, "trusted-add", "normalized");
case!(trusted_add_duplicate, "trusted-add", "duplicate");
case!(trusted_add_invalid, "trusted-add", "invalid");
case!(trusted_add_empty_sender, "trusted-add", "empty-sender");
case!(trusted_add_invalid_json, "trusted-add", "invalid-json");
case!(trusted_add_unicode, "trusted-add", "unicode");
case!(trusted_add_display_name, "trusted-add", "display-name");
case!(trusted_add_foreign, "trusted-add", "foreign");
case!(trusted_add_repeat, "trusted-add", "repeat");
case!(
    trusted_add_status_mutant,
    "trusted-add",
    "success-status-mutant"
);

case!(trusted_remove_success, "trusted-remove", "success");
case!(trusted_remove_missing, "trusted-remove", "missing");
case!(trusted_remove_invalid, "trusted-remove", "invalid");
case!(trusted_remove_uppercase, "trusted-remove", "uppercase");
case!(trusted_remove_foreign, "trusted-remove", "foreign");
case!(trusted_remove_encoded, "trusted-remove", "encoded");
case!(trusted_remove_repeat, "trusted-remove", "repeat");
case!(
    trusted_remove_status_mutant,
    "trusted-remove",
    "success-status-mutant"
);

case!(external_get_success, "external-get", "success");
case!(external_get_domain, "external-get", "domain");
case!(
    external_get_domain_null_text,
    "external-get",
    "domain-null-text"
);
case!(external_get_disabled, "external-get", "disabled");
case!(external_get_foreign, "external-get", "foreign");
case!(external_get_ignored_query, "external-get", "ignored-query");
case!(
    external_get_status_mutant,
    "external-get",
    "success-status-mutant"
);

case!(external_put_success, "external-put", "success");
case!(external_put_enable, "external-put", "enable");
case!(external_put_missing, "external-put", "missing");
case!(external_put_null, "external-put", "null");
case!(external_put_wrong_type, "external-put", "wrong-type");
case!(external_put_invalid_json, "external-put", "invalid-json");
case!(external_put_repeat, "external-put", "repeat");
case!(external_put_foreign, "external-put", "foreign");
case!(
    external_put_status_mutant,
    "external-put",
    "success-status-mutant"
);

case!(report_success, "report", "success");
case!(report_phishing, "report", "phishing");
case!(report_concern, "report", "concern");
case!(report_with_note, "report", "with-note");
case!(report_foreign, "report", "foreign");
case!(report_missing, "report", "missing");
case!(report_bad_type, "report", "bad-type");
case!(report_empty_id, "report", "empty-id");
case!(report_bad_id, "report", "bad-id");
case!(report_invalid_json, "report", "invalid-json");
case!(report_flag_on, "report", "flag-on");
case!(report_repeat, "report", "repeat");
case!(report_status_mutant, "report", "success-status-mutant");
