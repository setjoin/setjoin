//! F19 slice `settings-a`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod settings_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            settings_oracle::run("settings-a", $action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            settings_oracle::run("settings-a", $action, $kind, Some($fault)).await
        }
    };
}

case!(imap_get_success, "imap-get", "success");
case!(imap_get_foreign, "imap-get", "foreign");
case!(imap_get_ignored_query, "imap-get", "ignored-query");
case!(imap_get_status_mutant, "imap-get", "success-status-mutant");

case!(imap_put_success, "imap-put", "success");
case!(imap_put_foreign, "imap-put", "foreign");
case!(imap_put_new_row, "imap-put", "new-row");
case!(imap_put_bad_json, "imap-put", "bad-json");
case!(imap_put_wrong_type, "imap-put", "wrong-type");
case!(imap_put_partial, "imap-put", "partial");
case!(imap_put_null_tags, "imap-put", "null-tags");
case!(imap_put_empty_tags, "imap-put", "empty-tags");
case!(imap_put_fold, "imap-put", "fold");
case!(imap_put_repeat, "imap-put", "repeat");
case!(imap_put_status_mutant, "imap-put", "success-status-mutant");

case!(view_get_success, "view-get", "success");
case!(view_get_foreign, "view-get", "foreign");
case!(view_get_array, "view-get", "array");
case!(view_get_jsonnull, "view-get", "jsonnull");
case!(view_get_partial, "view-get", "partial");
case!(view_get_numbers, "view-get", "numbers");
case!(view_get_html, "view-get", "html");
case!(view_get_ignored_query, "view-get", "ignored-query");
case!(view_get_status_mutant, "view-get", "success-status-mutant");

case!(view_put_success, "view-put", "success");
case!(view_put_foreign, "view-put", "foreign");
case!(view_put_bad_json, "view-put", "bad-json");
case!(view_put_array_body, "view-put", "array-body");
case!(view_put_null_body, "view-put", "null-body");
case!(view_put_bad_window, "view-put", "bad-window");
case!(view_put_bad_window_value, "view-put", "bad-window-value");
case!(view_put_empty, "view-put", "empty");
case!(view_put_trailing, "view-put", "trailing");
case!(view_put_numbers, "view-put", "numbers");
case!(view_put_html, "view-put", "html");
case!(view_put_repeat, "view-put", "repeat");
case!(view_put_status_mutant, "view-put", "success-status-mutant");

case!(undo_get_success, "undo-get", "success");
case!(undo_get_foreign, "undo-get", "foreign");
case!(undo_get_float, "undo-get", "float");
case!(undo_get_negative, "undo-get", "negative");
case!(undo_get_string, "undo-get", "string");
case!(undo_get_huge, "undo-get", "huge");
case!(undo_get_array, "undo-get", "array");
case!(undo_get_ignored_query, "undo-get", "ignored-query");
case!(undo_get_status_mutant, "undo-get", "success-status-mutant");

case!(undo_put_success, "undo-put", "success");
case!(undo_put_foreign, "undo-put", "foreign");
case!(undo_put_bad_json, "undo-put", "bad-json");
case!(undo_put_string, "undo-put", "string");
case!(undo_put_float, "undo-put", "float");
case!(undo_put_low, "undo-put", "low");
case!(undo_put_high, "undo-put", "high");
case!(undo_put_missing, "undo-put", "missing");
case!(undo_put_null_body, "undo-put", "null-body");
case!(undo_put_fold, "undo-put", "fold");
case!(undo_put_array, "undo-put", "array");
case!(undo_put_null_prefs, "undo-put", "null-prefs");
case!(undo_put_repeat, "undo-put", "repeat");
case!(undo_put_status_mutant, "undo-put", "success-status-mutant");

case!(newsletter_get_success, "newsletter-get", "success");
case!(newsletter_get_foreign, "newsletter-get", "foreign");
case!(newsletter_get_array, "newsletter-get", "array");
case!(newsletter_get_bad_types, "newsletter-get", "bad-types");
case!(newsletter_get_null_items, "newsletter-get", "null-items");
case!(newsletter_get_null_list, "newsletter-get", "null-list");
case!(
    newsletter_get_ignored_query,
    "newsletter-get",
    "ignored-query"
);
case!(
    newsletter_get_status_mutant,
    "newsletter-get",
    "success-status-mutant"
);

case!(newsletter_put_success, "newsletter-put", "success");
case!(newsletter_put_foreign, "newsletter-put", "foreign");
case!(newsletter_put_bad_json, "newsletter-put", "bad-json");
case!(newsletter_put_wrong_type, "newsletter-put", "wrong-type");
case!(newsletter_put_bundle_only, "newsletter-put", "bundle-only");
case!(newsletter_put_lists_only, "newsletter-put", "lists-only");
case!(newsletter_put_empty_lists, "newsletter-put", "empty-lists");
case!(newsletter_put_null_lists, "newsletter-put", "null-lists");
case!(newsletter_put_nothing, "newsletter-put", "nothing");
case!(newsletter_put_html, "newsletter-put", "html");
case!(newsletter_put_null_prefs, "newsletter-put", "null-prefs");
case!(newsletter_put_array, "newsletter-put", "array");
case!(newsletter_put_repeat, "newsletter-put", "repeat");
case!(
    newsletter_put_status_mutant,
    "newsletter-put",
    "success-status-mutant"
);

case!(signature_list_success, "signature-list", "success");
case!(signature_list_foreign, "signature-list", "foreign");
case!(
    signature_list_ignored_query,
    "signature-list",
    "ignored-query"
);
case!(
    signature_list_status_mutant,
    "signature-list",
    "success-status-mutant"
);

case!(signature_put_success, "signature-put", "success");
case!(signature_put_foreign, "signature-put", "foreign");
case!(signature_put_bad_json, "signature-put", "bad-json");
case!(signature_put_bool_default, "signature-put", "bool-default");
case!(signature_put_no_alias, "signature-put", "no-alias");
case!(signature_put_null_body, "signature-put", "null-body");
case!(signature_put_long_alias, "signature-put", "long-alias");
case!(signature_put_long_html, "signature-put", "long-html");
case!(signature_put_long_text, "signature-put", "long-text");
case!(signature_put_too_big, "signature-put", "too-big");
case!(
    signature_put_bad_default_for,
    "signature-put",
    "bad-default-for"
);
case!(signature_put_update, "signature-put", "update");
case!(signature_put_role_flip, "signature-put", "role-flip");
case!(signature_put_default_both, "signature-put", "default-both");
case!(signature_put_empty_role, "signature-put", "empty-role");
case!(signature_put_limit, "signature-put", "limit");
case!(signature_put_limit_update, "signature-put", "limit-update");
case!(signature_put_repeat, "signature-put", "repeat");
case!(
    signature_put_status_mutant,
    "signature-put",
    "success-status-mutant"
);

case!(signature_delete_success, "signature-delete", "success");
case!(signature_delete_foreign, "signature-delete", "foreign");
case!(signature_delete_bad_id, "signature-delete", "bad-id");
case!(signature_delete_missing, "signature-delete", "missing");
case!(signature_delete_plus, "signature-delete", "plus");
case!(signature_delete_repeat, "signature-delete", "repeat");
case!(
    signature_delete_status_mutant,
    "signature-delete",
    "success-status-mutant"
);

// Family mutants: each plants a real database fault the unchanged expectation must reject.
fault!(
    signature_list_no_tenant_filter_fault,
    "signature-list",
    "success",
    "no-tenant-filter"
);
fault!(
    view_put_double_bump_fault,
    "view-put",
    "success",
    "double-bump"
);
