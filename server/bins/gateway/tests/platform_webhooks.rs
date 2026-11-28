//! F08 slice `webhooks` (#302): frozen-Go oracle replayed without a Go upstream.
mod common;
#[path = "platform_oracle/mod.rs"]
#[allow(dead_code)]
mod platform_oracle;
mod platform_webhooks_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_webhooks_oracle::run($action, $kind).await
        }
    };
}

case!(list_success, "list", "success");
case!(list_empty, "list", "empty");
case!(list_denied, "list", "denied");
case!(list_scoped, "list", "scoped");
case!(list_ignored_query, "list", "ignored-query");
case!(list_odd_types, "list", "odd-types");
case!(list_status_mutant, "list", "success-status-mutant");

case!(events_success, "events", "success");
case!(events_denied, "events", "denied");
case!(events_ignored_query, "events", "ignored-query");
case!(events_status_mutant, "events", "success-status-mutant");

case!(deliveries_success, "deliveries", "success");
case!(deliveries_empty, "deliveries", "empty");
case!(deliveries_unknown_subscription, "deliveries", "missing");
case!(deliveries_bad_id, "deliveries", "bad-id");
case!(deliveries_other_owner, "deliveries", "other-owner");
case!(deliveries_denied, "deliveries", "denied");
case!(deliveries_status_mutant, "deliveries", "success-status-mutant");

case!(create_success, "create", "success");
case!(create_default_scope, "create", "default");
case!(create_repeat, "create", "repeat");
case!(create_bad_json, "create", "bad-json");
case!(create_empty_body, "create", "empty-body");
case!(create_missing_url, "create", "missing-url");
case!(create_empty_url, "create", "empty-url");
case!(create_missing_types, "create", "missing-types");
case!(create_null_types, "create", "null-types");
case!(create_empty_types, "create", "empty-types");
case!(create_bad_scope, "create", "bad-scope");
case!(create_unknown_event, "create", "unknown-event");
case!(create_duplicate_event, "create", "duplicate-event");
case!(create_too_many, "create", "too-many");
case!(create_all_types, "create", "all-types");
case!(create_folded, "create", "folded");
case!(create_trailing_data, "create", "trailing-data");
case!(create_wrong_type, "create", "wrong-type");
case!(create_null_element, "create", "null-element");
case!(create_markup_url, "create", "markup-url");
case!(create_denied, "create", "denied");
case!(create_status_mutant, "create", "success-status-mutant");

case!(delete_success, "delete", "success");
case!(delete_repeat, "delete", "repeat");
case!(delete_missing, "delete", "missing");
case!(delete_bad_id, "delete", "bad-id");
case!(delete_other_owner, "delete", "other-owner");
case!(delete_denied, "delete", "denied");
case!(delete_status_mutant, "delete", "success-status-mutant");

case!(rotate_success, "rotate", "success");
case!(rotate_repeat, "rotate", "repeat");
case!(rotate_legacy, "rotate", "legacy");
case!(rotate_malformed, "rotate", "malformed");
case!(rotate_unknown_key, "rotate", "unknown-key");
case!(rotate_no_key_id, "rotate", "no-key-id");
case!(rotate_missing, "rotate", "missing");
case!(rotate_bad_id, "rotate", "bad-id");
case!(rotate_other_owner, "rotate", "other-owner");
case!(rotate_denied, "rotate", "denied");
case!(rotate_status_mutant, "rotate", "success-status-mutant");
