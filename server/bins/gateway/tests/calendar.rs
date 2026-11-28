//! F17 slice `calendar-booking` frozen-Go oracle, replayed without a Go upstream.
mod calendar_oracle;
mod common;

macro_rules! case {
    ($name:ident, $route:literal, $label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            calendar_oracle::run($route, $label, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $route:literal, $label:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            calendar_oracle::run($route, $label, Some($fault)).await
        }
    };
}

case!(pages_list_success, "pages-list", "success");
case!(pages_list_cross_tenant, "pages-list", "cross-tenant");
case!(pages_list_invalid_input, "pages-list", "invalid-input");
case!(pages_list_toggle_off, "pages-list", "toggle-off");

case!(pages_put_success, "pages-put", "success");
case!(pages_put_update, "pages-put", "update");
case!(pages_put_repeat, "pages-put", "repeat");
case!(pages_put_invalid_input, "pages-put", "invalid-input");
case!(pages_put_empty, "pages-put", "empty");
case!(pages_put_slug_invalid, "pages-put", "slug-invalid");
case!(pages_put_bad_id, "pages-put", "bad-id");
case!(pages_put_scalar, "pages-put", "scalar");
case!(pages_put_null_body, "pages-put", "null-body");
case!(pages_put_duplicate_slug, "pages-put", "duplicate-slug");
case!(pages_put_trailing, "pages-put", "trailing");
case!(pages_put_oversize, "pages-put", "oversize");
case!(pages_put_cross_tenant, "pages-put", "cross-tenant");
case!(pages_put_toggle_off, "pages-put", "toggle-off");

case!(pages_delete_success, "pages-delete", "success");
case!(pages_delete_repeat, "pages-delete", "repeat");
case!(pages_delete_invalid_input, "pages-delete", "invalid-input");
case!(pages_delete_bad_id, "pages-delete", "bad-id");
case!(pages_delete_cross_tenant, "pages-delete", "cross-tenant");
case!(pages_delete_toggle_off, "pages-delete", "toggle-off");

case!(public_meta_success, "public-meta", "success");
case!(public_meta_unknown_slug, "public-meta", "unknown-slug");
case!(public_meta_disabled, "public-meta", "disabled");
case!(public_meta_folded, "public-meta", "folded");
case!(public_meta_suffix_quirk, "public-meta", "suffix-quirk");
case!(public_meta_toggle_off, "public-meta", "toggle-off");

case!(public_slots_success, "public-slots", "success");
case!(public_slots_invalid_input, "public-slots", "invalid-input");
case!(public_slots_bad_date, "public-slots", "bad-date");
case!(public_slots_range, "public-slots", "range");
case!(public_slots_reversed, "public-slots", "reversed");
case!(public_slots_unknown_slug, "public-slots", "unknown-slug");
case!(public_slots_disabled, "public-slots", "disabled");
case!(public_slots_toggle_off, "public-slots", "toggle-off");

case!(public_book_success, "public-book", "success");
case!(public_book_repeat, "public-book", "repeat");
case!(public_book_honeypot, "public-book", "honeypot");
case!(public_book_missing_answer, "public-book", "missing-answer");
case!(public_book_unknown_slug, "public-book", "unknown-slug");
case!(public_book_disabled, "public-book", "disabled");
case!(public_book_invalid_input, "public-book", "invalid-input");
case!(public_book_oversize, "public-book", "oversize");
case!(public_book_bad_start, "public-book", "bad-start");
case!(
    public_book_no_answers_field,
    "public-book",
    "no-answers-field"
);
case!(
    public_book_null_name_folded,
    "public-book",
    "null-name-folded"
);
case!(
    public_book_unparseable_email,
    "public-book",
    "unparseable-email"
);
case!(public_book_type_error, "public-book", "type-error");
case!(public_book_unicode_title, "public-book", "unicode-title");
case!(public_book_toggle_off, "public-book", "toggle-off");

case!(public_confirm_success, "public-confirm", "success");
case!(public_confirm_repeat, "public-confirm", "repeat");
case!(
    public_confirm_unicode_title,
    "public-confirm",
    "unicode-title"
);
case!(
    public_confirm_invalid_input,
    "public-confirm",
    "invalid-input"
);
case!(
    public_confirm_unknown_token,
    "public-confirm",
    "unknown-token"
);
case!(public_confirm_toggle_off, "public-confirm", "toggle-off");

case!(public_cancel_success, "public-cancel", "success");
case!(public_cancel_repeat, "public-cancel", "repeat");
case!(
    public_cancel_invalid_input,
    "public-cancel",
    "invalid-input"
);
case!(
    public_cancel_unknown_token,
    "public-cancel",
    "unknown-token"
);
case!(public_cancel_toggle_off, "public-cancel", "toggle-off");

case!(free_busy_success, "free-busy", "success");
case!(free_busy_cross_tenant, "free-busy", "cross-tenant");
case!(free_busy_open_by_default, "free-busy", "open-by-default");
case!(free_busy_rooms, "free-busy", "rooms");
case!(free_busy_unknown_ids, "free-busy", "unknown-ids");
case!(free_busy_invalid_input, "free-busy", "invalid-input");
case!(free_busy_no_entities, "free-busy", "no-entities");
case!(free_busy_too_many, "free-busy", "too-many");
case!(free_busy_missing_start, "free-busy", "missing-start");
case!(free_busy_missing_end, "free-busy", "missing-end");
case!(free_busy_bad_start, "free-busy", "bad-start");
case!(free_busy_bad_end, "free-busy", "bad-end");
case!(free_busy_end_day, "free-busy", "end-day");
case!(free_busy_extra_text, "free-busy", "extra-text");
case!(free_busy_reversed, "free-busy", "reversed");
case!(free_busy_window, "free-busy", "window");
case!(free_busy_type_error, "free-busy", "type-error");
case!(
    free_busy_fractional_offset,
    "free-busy",
    "fractional-offset"
);

case!(subs_list_success, "subs-list", "success");
case!(subs_list_cross_tenant, "subs-list", "cross-tenant");
case!(subs_list_invalid_input, "subs-list", "invalid-input");

case!(subs_delete_success, "subs-delete", "success");
case!(subs_delete_repeat, "subs-delete", "repeat");
case!(subs_delete_invalid_input, "subs-delete", "invalid-input");
case!(subs_delete_cross_tenant, "subs-delete", "cross-tenant");
case!(subs_delete_missing, "subs-delete", "missing");

case!(subs_create_success, "subs-create", "success");
case!(subs_create_repeat, "subs-create", "repeat");
case!(subs_create_cross_tenant, "subs-create", "cross-tenant");
case!(subs_create_invalid_input, "subs-create", "invalid-input");
case!(subs_create_no_url, "subs-create", "no-url");
case!(subs_create_private_url, "subs-create", "private-url");
case!(subs_create_bad_scheme, "subs-create", "bad-scheme");
case!(subs_create_webcal, "subs-create", "webcal");
case!(subs_create_long_name, "subs-create", "long-name");

case!(
    pages_list_status_mutant,
    "pages-list",
    "success-status-mutant"
);
case!(
    pages_put_status_mutant,
    "pages-put",
    "success-status-mutant"
);
case!(
    pages_delete_status_mutant,
    "pages-delete",
    "success-status-mutant"
);
case!(
    public_meta_status_mutant,
    "public-meta",
    "success-status-mutant"
);
case!(
    public_slots_status_mutant,
    "public-slots",
    "success-status-mutant"
);
case!(
    public_book_status_mutant,
    "public-book",
    "success-status-mutant"
);
case!(
    public_confirm_status_mutant,
    "public-confirm",
    "success-status-mutant"
);
case!(
    public_cancel_status_mutant,
    "public-cancel",
    "success-status-mutant"
);
case!(
    free_busy_status_mutant,
    "free-busy",
    "success-status-mutant"
);
case!(
    subs_list_status_mutant,
    "subs-list",
    "success-status-mutant"
);
case!(
    subs_delete_status_mutant,
    "subs-delete",
    "success-status-mutant"
);
case!(
    subs_create_status_mutant,
    "subs-create",
    "success-status-mutant"
);

fault!(
    pages_list_no_tenant_filter_mutant,
    "pages-list",
    "success",
    "no-tenant-filter"
);
fault!(
    public_cancel_no_notify_mutant,
    "public-cancel",
    "success",
    "no-notify"
);
fault!(
    public_cancel_double_bump_mutant,
    "public-cancel",
    "success",
    "double-bump"
);
