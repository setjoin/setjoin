//! Frozen-Go HTTP/effect oracle for #290.
mod common;
mod retention_audit_oracle;
#[tokio::test]
async fn policies_success() -> Result<(), common::BoxError> {
    retention_audit_oracle::run("policies", "success", "").await
}

#[tokio::test]
async fn create_success() -> Result<(), common::BoxError> {
    retention_audit_oracle::run("create", "success", "").await
}

macro_rules! case {
    ($name:ident,$action:literal,$label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            retention_audit_oracle::run($action, $label, "").await
        }
    };
}
case!(update_success, "update", "success");
case!(delete_success, "delete", "success");
case!(policies_foreign, "policies", "foreign");
case!(policies_invalid, "policies", "invalid");
case!(policies_denied, "policies", "denied");
case!(policies_null_description, "policies", "null-description");
case!(create_foreign, "create", "foreign");
case!(create_invalid, "create", "invalid");
case!(create_denied, "create", "denied");
case!(create_repeat, "create", "repeat");
case!(update_foreign, "update", "foreign");
case!(update_invalid, "update", "invalid");
case!(update_denied, "update", "denied");
case!(update_repeat, "update", "repeat");
case!(delete_foreign, "delete", "foreign");
case!(delete_invalid, "delete", "invalid");
case!(delete_denied, "delete", "denied");
case!(delete_repeat, "delete", "repeat");
case!(create_bad_json, "create", "bad-json");
case!(create_typed, "create", "typed");
case!(create_null, "create", "null");
case!(create_folded, "create", "folded");
case!(create_audit_failure, "create", "audit-failure");
case!(create_range, "create", "range");
case!(update_bad_json, "update", "bad-json");
case!(update_typed, "update", "typed");
case!(update_null, "update", "null");
case!(update_folded, "update", "folded");
case!(update_audit_failure, "update", "audit-failure");
case!(update_range, "update", "range");
case!(delete_audit_failure, "delete", "audit-failure");
case!(policies_bad_query, "policies", "bad-query");
case!(log_get_success, "log_get", "success");
case!(log_set_success, "log_set", "success");
case!(log_prune_success, "log_prune", "success");
case!(log_get_foreign, "log_get", "foreign");
case!(log_get_invalid, "log_get", "invalid");
case!(log_get_domain_scope, "log_get", "domain-scope");
case!(log_get_broken_config, "log_get", "broken-config");
case!(log_get_missing_config, "log_get", "missing-config");
case!(log_set_foreign, "log_set", "foreign");
case!(log_set_invalid, "log_set", "invalid");
case!(log_set_domain_scope, "log_set", "domain-scope");
case!(log_set_repeat, "log_set", "repeat");
case!(log_prune_foreign, "log_prune", "foreign");
case!(log_prune_invalid, "log_prune", "invalid");
case!(log_prune_domain_scope, "log_prune", "domain-scope");
case!(log_prune_repeat, "log_prune", "repeat");
case!(log_set_config_failure, "log_set", "config-failure");
case!(log_set_folded, "log_set", "folded");
case!(log_set_null, "log_set", "null");
case!(log_set_bad_json, "log_set", "bad-json");
case!(log_prune_query_failure, "log_prune", "query-failure");
case!(audit_policy_success, "audit_policy", "success");
case!(audit_set_success, "audit_set", "success");
case!(audit_list_success, "audit_list", "success");
case!(audit_csv_success, "audit_csv", "success");
case!(audit_csv_rows, "audit_csv", "rows");
case!(audit_verify_success, "audit_verify", "success");
case!(audit_policy_foreign, "audit_policy", "foreign");
case!(audit_policy_invalid, "audit_policy", "invalid");
case!(audit_policy_domain_scope, "audit_policy", "domain-scope");
case!(audit_set_foreign, "audit_set", "foreign");
case!(audit_set_invalid, "audit_set", "invalid");
case!(audit_set_domain_scope, "audit_set", "domain-scope");
case!(audit_set_repeat, "audit_set", "repeat");
case!(audit_list_foreign, "audit_list", "foreign");
case!(audit_list_invalid, "audit_list", "invalid");
case!(audit_list_domain_scope, "audit_list", "domain-scope");
case!(audit_csv_foreign, "audit_csv", "foreign");
case!(audit_csv_invalid, "audit_csv", "invalid");
case!(audit_csv_domain_scope, "audit_csv", "domain-scope");
case!(audit_verify_foreign, "audit_verify", "foreign");
case!(audit_verify_invalid, "audit_verify", "invalid");
case!(audit_verify_domain_scope, "audit_verify", "domain-scope");
case!(audit_set_missing_header, "audit_set", "missing-header");
case!(audit_set_body_reason, "audit_set", "body-reason");
case!(audit_set_level, "audit_set", "level");
case!(audit_set_typed, "audit_set", "typed");
case!(audit_set_null, "audit_set", "null");
case!(audit_set_folded, "audit_set", "folded");
case!(audit_set_null_entry, "audit_set", "null-entry");
case!(audit_set_audit_failure, "audit_set", "audit-failure");
case!(audit_set_missing_policy, "audit_set", "missing-policy");
case!(audit_set_read_only, "audit_set", "read-only");
case!(
    audit_policy_missing_policy,
    "audit_policy",
    "missing-policy"
);
case!(audit_policy_empty_areas, "audit_policy", "empty-areas");
case!(audit_list_all, "audit_list", "all");
case!(audit_list_filter, "audit_list", "filter");
case!(audit_list_empty, "audit_list", "empty");
case!(audit_list_pagination, "audit_list", "pagination");
case!(audit_list_invalid_utf8, "audit_list", "invalid-utf8");
case!(audit_csv_read_only, "audit_csv", "read-only");
case!(audit_csv_ignored_filter, "audit_csv", "ignored-filter");
case!(audit_verify_keyed, "audit_verify", "keyed");
case!(audit_verify_tampered, "audit_verify", "tampered");
case!(audit_verify_range, "audit_verify", "range");
case!(audit_verify_empty, "audit_verify", "empty");
case!(search_success, "search", "success");
case!(purge_success, "purge", "success");
case!(search_foreign, "search", "foreign");
case!(search_denied, "search", "denied");
case!(search_invalid, "search", "invalid");
case!(search_bad_json, "search", "bad-json");
case!(search_typed, "search", "typed");
case!(search_null, "search", "null");
case!(search_folded, "search", "folded");
case!(search_from_only, "search", "from-only");
case!(search_from_filter, "search", "from-filter");
case!(search_date_from, "search", "date-from");
case!(search_date_to, "search", "date-to");
case!(search_date_invalid, "search", "date-invalid");
case!(search_mailboxes, "search", "mailboxes");
case!(search_empty_mailboxes, "search", "empty-mailboxes");
case!(search_null_mailbox, "search", "null-mailbox");
case!(search_kql, "search", "kql");
case!(search_kql_mailbox, "search", "kql-mailbox");
case!(search_kql_negated, "search", "kql-negated");
case!(search_kql_bad, "search", "kql-bad");
case!(search_kql_unclosed, "search", "kql-unclosed");
case!(search_kql_length, "search", "kql-length");
case!(search_kql_depth, "search", "kql-depth");
case!(search_kql_terms, "search", "kql-terms");
case!(search_kql_space, "search", "kql-space");
case!(search_body_cap, "search", "body-cap");
case!(purge_foreign, "purge", "foreign");
case!(purge_denied, "purge", "denied");
case!(purge_invalid, "purge", "invalid");
case!(purge_bad_json, "purge", "bad-json");
case!(purge_null, "purge", "null");
case!(purge_empty, "purge", "empty");
case!(purge_null_ids, "purge", "null-ids");
case!(purge_null_entry, "purge", "null-entry");
case!(purge_duplicates, "purge", "duplicates");
case!(purge_missing, "purge", "missing");
case!(purge_negative, "purge", "negative");
case!(purge_short_reason, "purge", "short-reason");
case!(purge_unicode_reason, "purge", "unicode-reason");
case!(purge_folded, "purge", "folded");
case!(purge_audit_failure, "purge", "audit-failure");
case!(purge_query_failure, "purge", "query-failure");
case!(purge_mailbox_held, "purge", "mailbox-held");
case!(purge_repeat, "purge", "repeat");
case!(purge_too_many, "purge", "too-many");
case!(purge_body_cap, "purge", "body-cap");
case!(create_scoped, "create", "scoped");
case!(update_scoped, "update", "scoped");
case!(delete_scoped, "delete", "scoped");
macro_rules! mutant {
    ($name:ident,$action:literal,$kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            retention_audit_oracle::mutants::reject($action, $kind).await
        }
    };
}
mutant!(mutant_policies, "policies", "status");
mutant!(mutant_create, "create", "status");
mutant!(mutant_update, "update", "status");
mutant!(mutant_delete, "delete", "status");
mutant!(mutant_log_get, "log_get", "status");
mutant!(mutant_log_set, "log_set", "status");
mutant!(mutant_log_prune, "log_prune", "status");
mutant!(mutant_audit_policy, "audit_policy", "status");
mutant!(mutant_audit_set, "audit_set", "status");
mutant!(mutant_audit_list, "audit_list", "status");
mutant!(mutant_audit_csv, "audit_csv", "status");
mutant!(mutant_audit_verify, "audit_verify", "status");
mutant!(mutant_search, "search", "status");
mutant!(mutant_purge, "purge", "status");
mutant!(mutant_no_audit, "create", "no-audit");
mutant!(mutant_no_notify, "log_set", "no-notify");
mutant!(mutant_no_tenant_filter, "update", "no-tenant-filter");
mutant!(mutant_double_bump, "purge", "double-bump");
#[tokio::test]
async fn commit_create_before() -> Result<(), common::BoxError> {
    retention_audit_oracle::run("create", "success", "commit-before").await
}

macro_rules! commit_case {
    ($name:ident,$action:literal,$cut:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            retention_audit_oracle::run($action, "success", $cut).await
        }
    };
}
commit_case!(commit_create_after, "create", "commit-after");
commit_case!(commit_update_before, "update", "commit-before");
commit_case!(commit_update_after, "update", "commit-after");
commit_case!(commit_delete_before, "delete", "commit-before");
commit_case!(commit_delete_after, "delete", "commit-after");
commit_case!(commit_log_set_before, "log_set", "commit-before");
commit_case!(commit_log_set_after, "log_set", "commit-after");
commit_case!(commit_log_prune_before, "log_prune", "commit-before");
commit_case!(commit_log_prune_after, "log_prune", "commit-after");
commit_case!(commit_audit_set_before, "audit_set", "commit-before");
commit_case!(commit_audit_set_after, "audit_set", "commit-after");
commit_case!(commit_purge_before, "purge", "commit-before");
commit_case!(commit_purge_after, "purge", "commit-after");

#[tokio::test]
async fn switches_all_routes() -> Result<(), common::BoxError> {
    retention_audit_oracle::switches().await
}
#[tokio::test]
async fn refuses_a_nul_kql_locally() -> Result<(), common::BoxError> {
    retention_audit_oracle::forwarding().await
}
