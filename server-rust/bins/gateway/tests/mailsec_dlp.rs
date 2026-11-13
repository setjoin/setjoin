//! F06 slice `dlp`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("dlp", $action, $kind, None).await
        }
    };
}

case!(patterns_get_success, "patterns-get", "success");
case!(patterns_get_empty, "patterns-get", "empty");
case!(patterns_get_denied, "patterns-get", "denied");
case!(patterns_get_scoped, "patterns-get", "scoped");
case!(patterns_get_ignored_query, "patterns-get", "ignored-query");
case!(
    patterns_get_status_mutant,
    "patterns-get",
    "success-status-mutant"
);

case!(patterns_put_success, "patterns-put", "success");
case!(patterns_put_repeat, "patterns-put", "repeat");
case!(patterns_put_severities, "patterns-put", "severities");
case!(patterns_put_escapes, "patterns-put", "escapes");
case!(patterns_put_folded_keys, "patterns-put", "folded-keys");
case!(patterns_put_empty_array, "patterns-put", "empty-array");
case!(patterns_put_null, "patterns-put", "null");
case!(patterns_put_null_element, "patterns-put", "null-element");
case!(patterns_put_trailing, "patterns-put", "trailing");
case!(
    patterns_put_violation_blocks,
    "patterns-put",
    "violation-blocks"
);
case!(patterns_put_invalid_json, "patterns-put", "invalid-json");
case!(patterns_put_empty_body, "patterns-put", "empty-body");
case!(patterns_put_wrong_type, "patterns-put", "wrong-type");
case!(patterns_put_bad_field, "patterns-put", "bad-field");
case!(patterns_put_bad_id, "patterns-put", "bad-id");
case!(patterns_put_denied, "patterns-put", "denied");
case!(patterns_put_scoped, "patterns-put", "scoped");
case!(
    patterns_put_status_mutant,
    "patterns-put",
    "success-status-mutant"
);

case!(anti_get_success, "anti-get", "success");
case!(anti_get_defaults, "anti-get", "defaults");
case!(anti_get_mixed, "anti-get", "mixed");
case!(anti_get_bad_list, "anti-get", "bad-list");
case!(anti_get_string_lists, "anti-get", "string-lists");
case!(anti_get_denied, "anti-get", "denied");
case!(anti_get_scoped, "anti-get", "scoped");
case!(anti_get_status_mutant, "anti-get", "success-status-mutant");

case!(anti_put_success, "anti-put", "success");
case!(anti_put_repeat, "anti-put", "repeat");
case!(anti_put_overwrite, "anti-put", "overwrite");
case!(anti_put_defaults_body, "anti-put", "defaults-body");
case!(anti_put_null_lists, "anti-put", "null-lists");
case!(anti_put_empty_lists, "anti-put", "empty-lists");
case!(anti_put_folded_keys, "anti-put", "folded-keys");
case!(anti_put_null_bool, "anti-put", "null-bool");
case!(anti_put_trailing, "anti-put", "trailing");
case!(anti_put_invalid_json, "anti-put", "invalid-json");
case!(anti_put_empty_body, "anti-put", "empty-body");
case!(anti_put_wrong_type, "anti-put", "wrong-type");
case!(anti_put_bad_list, "anti-put", "bad-list");
case!(anti_put_denied, "anti-put", "denied");
case!(anti_put_scoped, "anti-put", "scoped");
case!(anti_put_status_mutant, "anti-put", "success-status-mutant");

case!(audit_success, "audit", "success");
case!(audit_empty, "audit", "empty");
case!(audit_denied, "audit", "denied");
case!(audit_scoped, "audit", "scoped");
case!(audit_since, "audit", "since");
case!(audit_since_offset, "audit", "since-offset");
case!(audit_since_fraction, "audit", "since-fraction");
case!(audit_zero_since, "audit", "zero-since");
case!(audit_bad_since, "audit", "bad-since");
case!(audit_url_hash, "audit", "url-hash");
case!(audit_url_hash_since, "audit", "url-hash-since");
case!(audit_limit, "audit", "limit");
case!(audit_bad_limit, "audit", "bad-limit");
case!(audit_zero_limit, "audit", "zero-limit");
case!(audit_negative_limit, "audit", "negative-limit");
case!(audit_big_limit, "audit", "big-limit");
case!(audit_max_limit, "audit", "max-limit");
case!(audit_no_match, "audit", "no-match");
case!(audit_null_message, "audit", "null-message");
case!(audit_null_ip, "audit", "null-ip");
case!(audit_ignored_query, "audit", "ignored-query");
case!(audit_status_mutant, "audit", "success-status-mutant");
