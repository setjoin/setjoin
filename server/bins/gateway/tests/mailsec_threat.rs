//! F06 slice `threat`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("threat", $action, $kind, None).await
        }
    };
}

// GET /admin/threat/{view}
case!(view_attempts_success, "view", "attempts-success");
case!(view_attempts_empty, "view", "attempts-empty");
case!(view_denied, "view", "denied");
case!(view_scoped, "view", "scoped");
case!(view_attempts_limit, "view", "attempts-limit");
case!(view_attempts_offset, "view", "attempts-offset");
case!(view_attempts_big_limit, "view", "attempts-big-limit");
case!(view_attempts_bad_limit, "view", "attempts-bad-limit");
case!(view_attempts_zero_limit, "view", "attempts-zero-limit");
case!(view_attempts_negative_offset, "view", "attempts-negative-offset");
case!(view_attempts_sort, "view", "attempts-sort");
case!(view_attempts_sort_desc, "view", "attempts-sort-desc");
case!(view_attempts_sort_bad, "view", "attempts-sort-bad");
case!(view_attempts_sort_injection, "view", "attempts-sort-injection");
case!(view_attempts_query, "view", "attempts-query");
case!(view_attempts_query_address, "view", "attempts-query-address");
case!(view_attempts_query_wildcard, "view", "attempts-query-wildcard");
case!(view_attempts_query_none, "view", "attempts-query-none");
case!(view_attempts_since, "view", "attempts-since");
case!(view_attempts_since_days, "view", "attempts-since-days");
case!(view_attempts_since_wide, "view", "attempts-since-wide");
case!(view_attempts_bad_since, "view", "attempts-bad-since");
case!(view_attempts_bad_utf8, "view", "attempts-bad-utf8");
case!(view_attempts_csv, "view", "attempts-csv");
case!(view_attempts_csv_limit, "view", "attempts-csv-limit");
case!(view_attempts_csv_sorted, "view", "attempts-csv-sorted");
case!(view_attempts_csv_upper, "view", "attempts-csv-upper");
case!(view_attempts_ignored_query, "view", "attempts-ignored-query");
case!(view_attempts_status_mutant, "view", "attempts-success-status-mutant");

case!(view_lockouts_success, "view", "lockouts-success");
case!(view_lockouts_empty, "view", "lockouts-empty");
case!(view_lockouts_limit, "view", "lockouts-limit");
case!(view_lockouts_offset, "view", "lockouts-offset");
case!(view_lockouts_huge_offset, "view", "lockouts-huge-offset");
case!(view_lockouts_sort, "view", "lockouts-sort");
case!(view_lockouts_sort_desc, "view", "lockouts-sort-desc");
case!(view_lockouts_sort_bad, "view", "lockouts-sort-bad");
case!(view_lockouts_query, "view", "lockouts-query");
case!(view_lockouts_query_wildcard, "view", "lockouts-query-wildcard");
case!(view_lockouts_csv, "view", "lockouts-csv");
case!(view_lockouts_since_ignored, "view", "lockouts-since-ignored");

case!(view_feed_blocks_success, "view", "feed-blocks-success");
case!(view_feed_blocks_empty, "view", "feed-blocks-empty");
case!(view_feed_blocks_limit, "view", "feed-blocks-limit");
case!(view_feed_blocks_offset, "view", "feed-blocks-offset");
case!(view_feed_blocks_sort, "view", "feed-blocks-sort");
case!(view_feed_blocks_sort_desc, "view", "feed-blocks-sort-desc");
case!(view_feed_blocks_query, "view", "feed-blocks-query");
case!(view_feed_blocks_query_address, "view", "feed-blocks-query-address");
case!(view_feed_blocks_csv, "view", "feed-blocks-csv");
case!(view_feed_blocks_since_ignored, "view", "feed-blocks-since-ignored");

case!(view_rate_counters_success, "view", "rate-counters-success");
case!(view_rate_counters_empty, "view", "rate-counters-empty");
case!(view_rate_counters_limit, "view", "rate-counters-limit");
case!(view_rate_counters_offset, "view", "rate-counters-offset");
case!(view_rate_counters_sort, "view", "rate-counters-sort");
case!(view_rate_counters_sort_desc, "view", "rate-counters-sort-desc");
case!(view_rate_counters_query, "view", "rate-counters-query");
case!(view_rate_counters_csv, "view", "rate-counters-csv");
case!(view_rate_counters_csv_limit, "view", "rate-counters-csv-limit");

case!(view_unknown, "view", "unknown");
case!(view_unknown_escaped, "view", "unknown-escaped");

// GET /admin/threat/ip-rules
case!(ip_list_success, "ip-list", "success");
case!(ip_list_empty, "ip-list", "empty");
case!(ip_list_denied, "ip-list", "denied");
case!(ip_list_scoped, "ip-list", "scoped");
case!(ip_list_limit, "ip-list", "limit");
case!(ip_list_offset, "ip-list", "offset");
case!(ip_list_big_limit, "ip-list", "big-limit");
case!(ip_list_bad_limit, "ip-list", "bad-limit");
case!(ip_list_zero_limit, "ip-list", "zero-limit");
case!(ip_list_negative_offset, "ip-list", "negative-offset");
case!(ip_list_ignored_query, "ip-list", "ignored-query");
case!(ip_list_status_mutant, "ip-list", "success-status-mutant");

// POST /admin/threat/ip-rules
case!(ip_create_success, "ip-create", "success");
case!(ip_create_success_expires, "ip-create", "success-expires");
case!(ip_create_success_null_expires, "ip-create", "success-null-expires");
case!(ip_create_success_nonmasked, "ip-create", "success-nonmasked");
case!(ip_create_success_extra_fields, "ip-create", "success-extra-fields");
case!(ip_create_success_case_keys, "ip-create", "success-case-keys");
case!(ip_create_success_trailing, "ip-create", "success-trailing");
case!(ip_create_success_v4mapped, "ip-create", "success-v4mapped");
case!(ip_create_repeat, "ip-create", "repeat");
case!(ip_create_denied, "ip-create", "denied");
case!(ip_create_scoped, "ip-create", "scoped");
case!(ip_create_invalid_json, "ip-create", "invalid-json");
case!(ip_create_empty_body, "ip-create", "empty-body");
case!(ip_create_array_body, "ip-create", "array-body");
case!(ip_create_null_body, "ip-create", "null-body");
case!(ip_create_wrong_type, "ip-create", "wrong-type");
case!(ip_create_wrong_type_expires, "ip-create", "wrong-type-expires");
case!(ip_create_bad_cidr_nomask, "ip-create", "bad-cidr-nomask");
case!(ip_create_bad_cidr_text, "ip-create", "bad-cidr-text");
case!(ip_create_bad_cidr_octet, "ip-create", "bad-cidr-octet");
case!(ip_create_bad_cidr_bits, "ip-create", "bad-cidr-bits");
case!(ip_create_bad_cidr_bits_text, "ip-create", "bad-cidr-bits-text");
case!(ip_create_bad_cidr_bits_zero_pad, "ip-create", "bad-cidr-bits-zero-pad");
case!(ip_create_bad_cidr_zone, "ip-create", "bad-cidr-zone");
case!(ip_create_bad_cidr_short, "ip-create", "bad-cidr-short");
case!(ip_create_bad_cidr_leading_zero, "ip-create", "bad-cidr-leading-zero");
case!(ip_create_bad_cidr_unicode, "ip-create", "bad-cidr-unicode");
case!(ip_create_bad_cidr_control, "ip-create", "bad-cidr-control");
case!(ip_create_bad_cidr_v6, "ip-create", "bad-cidr-v6");
case!(ip_create_bad_cidr_v6_bits, "ip-create", "bad-cidr-v6-bits");
case!(ip_create_bad_cidr_embedded, "ip-create", "bad-cidr-embedded");
case!(ip_create_bad_cidr_empty, "ip-create", "bad-cidr-empty");
case!(ip_create_bad_action, "ip-create", "bad-action");
case!(ip_create_bad_action_case, "ip-create", "bad-action-case");
case!(ip_create_bad_action_quote, "ip-create", "bad-action-quote");
case!(ip_create_no_description, "ip-create", "no-description");
case!(ip_create_bad_expires, "ip-create", "bad-expires");
case!(ip_create_empty_expires, "ip-create", "empty-expires");
case!(ip_create_status_mutant, "ip-create", "success-status-mutant");

// DELETE /admin/threat/ip-rules/{id}
case!(ip_delete_success, "ip-delete", "success");
case!(ip_delete_success_v6, "ip-delete", "success-v6");
case!(ip_delete_plus_id, "ip-delete", "plus-id");
case!(ip_delete_repeat, "ip-delete", "repeat");
case!(ip_delete_missing, "ip-delete", "missing");
case!(ip_delete_empty, "ip-delete", "empty");
case!(ip_delete_bad_id, "ip-delete", "bad-id");
case!(ip_delete_zero_id, "ip-delete", "zero-id");
case!(ip_delete_negative_id, "ip-delete", "negative-id");
case!(ip_delete_huge_id, "ip-delete", "huge-id");
case!(ip_delete_denied, "ip-delete", "denied");
case!(ip_delete_scoped, "ip-delete", "scoped");
case!(ip_delete_status_mutant, "ip-delete", "success-status-mutant");
