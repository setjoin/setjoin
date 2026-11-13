//! F08 slice `terms-remaining`, group `federation`: the admin federation allow-list console,
//! replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::terms::run($action, $kind, None).await
        }
    };
}

case!(list_success, "federation-list", "success");
case!(list_denied, "federation-list", "denied");
case!(list_scoped, "federation-list", "scoped");
case!(list_empty, "federation-list", "empty");
case!(list_no_transport, "federation-list", "no-transport");
case!(list_ignored_query, "federation-list", "ignored-query");
case!(
    list_status_mutant,
    "federation-list",
    "success-status-mutant"
);

case!(upsert_success, "federation-upsert", "success");
case!(upsert_denied, "federation-upsert", "denied");
case!(upsert_scoped, "federation-upsert", "scoped");
case!(upsert_repeat, "federation-upsert", "repeat");
case!(
    upsert_update_existing,
    "federation-upsert",
    "update-existing"
);
case!(upsert_carry_anchor, "federation-upsert", "carry-anchor");
case!(
    upsert_carry_anchor_blank,
    "federation-upsert",
    "carry-anchor-blank"
);
case!(upsert_disable, "federation-upsert", "disable");
case!(
    upsert_new_without_anchor,
    "federation-upsert",
    "new-without-anchor"
);
case!(
    upsert_uppercase_domain,
    "federation-upsert",
    "uppercase-domain"
);
case!(upsert_scope_room, "federation-upsert", "scope-room");
case!(upsert_self_domain, "federation-upsert", "self-domain");
case!(
    upsert_self_domain_upper,
    "federation-upsert",
    "self-domain-upper"
);
case!(upsert_bad_scope, "federation-upsert", "bad-scope");
case!(upsert_scope_upper, "federation-upsert", "scope-upper");
case!(upsert_scope_empty, "federation-upsert", "scope-empty");
case!(upsert_empty_domain, "federation-upsert", "empty-domain");
case!(upsert_blank_domain, "federation-upsert", "blank-domain");
case!(upsert_garbage_anchor, "federation-upsert", "garbage-anchor");
case!(
    upsert_private_key_anchor,
    "federation-upsert",
    "private-key-anchor"
);
case!(
    upsert_truncated_anchor,
    "federation-upsert",
    "truncated-anchor"
);
case!(
    upsert_bad_base64_anchor,
    "federation-upsert",
    "bad-base64-anchor"
);
case!(
    upsert_empty_block_anchor,
    "federation-upsert",
    "empty-block-anchor"
);
case!(
    upsert_leading_junk_anchor,
    "federation-upsert",
    "leading-junk-anchor"
);
case!(
    upsert_trailing_junk_anchor,
    "federation-upsert",
    "trailing-junk-anchor"
);
case!(upsert_crlf_anchor, "federation-upsert", "crlf-anchor");
case!(
    upsert_two_blocks_anchor,
    "federation-upsert",
    "two-blocks-anchor"
);
case!(
    upsert_key_then_cert_anchor,
    "federation-upsert",
    "key-then-cert-anchor"
);
case!(
    upsert_indented_anchor,
    "federation-upsert",
    "indented-anchor"
);
case!(upsert_folded, "federation-upsert", "folded");
case!(upsert_unknown_key, "federation-upsert", "unknown-key");
case!(upsert_duplicate_key, "federation-upsert", "duplicate-key");
case!(
    upsert_enabled_default,
    "federation-upsert",
    "enabled-default"
);
case!(upsert_enabled_string, "federation-upsert", "enabled-string");
case!(upsert_domain_number, "federation-upsert", "domain-number");
case!(upsert_trailing_data, "federation-upsert", "trailing-data");
case!(upsert_bad_json, "federation-upsert", "bad-json");
case!(upsert_empty_body, "federation-upsert", "empty-body");
case!(upsert_null_body, "federation-upsert", "null-body");
case!(upsert_array_body, "federation-upsert", "array-body");
case!(upsert_oversize, "federation-upsert", "oversize");

case!(
    upsert_status_mutant,
    "federation-upsert",
    "success-status-mutant"
);
case!(delete_success, "federation-delete", "success");
case!(delete_denied, "federation-delete", "denied");
case!(delete_scoped, "federation-delete", "scoped");
case!(delete_repeat, "federation-delete", "repeat");
case!(delete_enabled_peer, "federation-delete", "enabled-peer");
case!(delete_with_transport, "federation-delete", "with-transport");
case!(delete_missing, "federation-delete", "missing");
case!(delete_uppercase, "federation-delete", "uppercase");
case!(delete_padded, "federation-delete", "padded");
case!(delete_blank, "federation-delete", "blank");
case!(
    delete_status_mutant,
    "federation-delete",
    "success-status-mutant"
);
