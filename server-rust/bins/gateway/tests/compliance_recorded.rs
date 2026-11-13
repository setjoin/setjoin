//! Frozen Go HTTP and committed-effect oracle for F04 eDiscovery.
mod common;
mod compliance_oracle;
#[tokio::test]
async fn cases_list_success() -> Result<(), common::BoxError> {
    compliance_oracle::run("list", "success").await
}

#[tokio::test]
async fn case_get_success() -> Result<(), common::BoxError> {
    compliance_oracle::run("get", "success").await
}

macro_rules! case {
    ($name:ident,$action:literal,$label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            compliance_oracle::run($action, $label).await
        }
    };
}
case!(cases_list_foreign, "list", "foreign");
case!(cases_list_invalid, "list", "invalid");
case!(cases_list_denied, "list", "denied");
case!(cases_list_null_description, "list", "null-description");
case!(case_get_foreign, "get", "foreign");
case!(case_get_invalid, "get", "invalid");
case!(case_get_missing, "get", "missing");
case!(case_get_null_description, "get", "null-description");

case!(case_create_success, "create", "success");

case!(case_update_success, "update", "success");
case!(case_create_foreign, "create", "foreign");
case!(case_create_invalid, "create", "invalid");
case!(case_create_bad_json, "create", "bad-json");
case!(case_create_typed, "create", "typed");
case!(case_create_null, "create", "null");
case!(case_create_folded, "create", "folded");
case!(case_create_repeat, "create", "repeat");

case!(case_delete_success, "delete", "success");
case!(case_update_foreign, "update", "foreign");
case!(case_update_invalid, "update", "invalid");
case!(case_update_repeat, "update", "repeat");
case!(case_update_missing, "update", "missing");
case!(case_update_empty, "update", "empty");
case!(case_update_typed, "update", "typed");
case!(case_update_bad_json, "update", "bad-json");
case!(case_update_null, "update", "null");
case!(case_update_folded, "update", "folded");
case!(case_update_empty_name, "update", "empty-name");
case!(case_update_clear, "update", "clear");
case!(case_update_closed, "update", "closed");

case!(case_associate_success, "associate", "success");
case!(case_delete_foreign, "delete", "foreign");
case!(case_delete_invalid, "delete", "invalid");
case!(case_delete_repeat, "delete", "repeat");
case!(case_delete_missing, "delete", "missing");
case!(case_delete_associated, "delete", "associated");
case!(case_get_with_search, "get", "with-search");

case!(case_close_success, "close", "success");
case!(case_associate_foreign, "associate", "foreign");
case!(case_associate_invalid, "associate", "invalid");
case!(case_associate_bad_json, "associate", "bad-json");
case!(case_associate_typed, "associate", "typed");
case!(case_associate_missing_search, "associate", "missing-search");
case!(case_associate_missing_case, "associate", "missing-case");
case!(case_associate_repeat, "associate", "repeat");
case!(case_associate_closed, "associate", "closed");
case!(case_associate_folded, "associate", "folded");
case!(case_close_foreign, "close", "foreign");
case!(case_close_invalid, "close", "invalid");
case!(case_close_repeat, "close", "repeat");
case!(case_close_missing, "close", "missing");
case!(case_close_closed, "close", "closed");
case!(case_close_bad_json, "close", "bad-json");
case!(case_close_typed, "close", "typed");
case!(case_close_empty, "close", "empty");
case!(case_close_null, "close", "null");
case!(case_close_folded, "close", "folded");

case!(hold_success, "hold", "success");

case!(release_success, "release", "success");
case!(hold_foreign, "hold", "foreign");
case!(hold_invalid, "hold", "invalid");
case!(hold_repeat, "hold", "repeat");
case!(hold_empty, "hold", "empty");
case!(hold_null, "hold", "null");
case!(hold_null_body, "hold", "null-body");
case!(hold_empty_list, "hold", "empty-list");
case!(hold_duplicates, "hold", "duplicates");
case!(hold_mixed, "hold", "mixed");
case!(hold_null_entry, "hold", "null-entry");
case!(hold_negative, "hold", "negative");
case!(hold_folded, "hold", "folded");
case!(hold_huge, "hold", "huge");
case!(release_foreign, "release", "foreign");
case!(release_invalid, "release", "invalid");
case!(release_repeat, "release", "repeat");
case!(release_empty, "release", "empty");
case!(release_null, "release", "null");
case!(release_null_body, "release", "null-body");
case!(release_empty_list, "release", "empty-list");
case!(release_duplicates, "release", "duplicates");
case!(release_mixed, "release", "mixed");
case!(release_null_entry, "release", "null-entry");
case!(release_negative, "release", "negative");
case!(release_folded, "release", "folded");
case!(release_huge, "release", "huge");

case!(search_get_success, "search", "success");
case!(search_get_foreign, "search", "foreign");
case!(search_get_invalid, "search", "invalid");
case!(search_get_missing, "search", "missing");
case!(search_get_pending, "search", "pending");
case!(search_get_unbound, "search", "unbound");
case!(search_get_zero, "search", "zero");
case!(search_get_no_count, "search", "no-count");
case!(search_get_missing_key, "search", "missing-key");
case!(search_get_empty_binding, "search", "empty-binding");
case!(search_get_fields, "search", "fields");
case!(search_get_mixed_mailboxes, "search", "mixed-mailboxes");
case!(search_get_huge_mailbox, "search", "huge-mailbox");

case!(search_start_success, "start", "success");

case!(search_start_from_filter, "start", "from-filter");

case!(search_start_date_from, "start", "date-from");

case!(search_start_date_to, "start", "date-to");

case!(search_start_mailboxes, "start", "mailboxes");

case!(search_start_kql, "start", "kql");

case!(search_get_bad_kql, "search", "bad-kql");

#[tokio::test]
async fn nul_kql_is_refused_and_worm_requests_forward_untouched() -> Result<(), common::BoxError> {
    compliance_oracle::forwarding().await
}

case!(search_start_kql_unicode, "start", "kql-unicode");
case!(search_start_foreign, "start", "foreign");
case!(search_start_invalid, "start", "invalid");
case!(search_start_repeat, "start", "repeat");
case!(search_start_bad_json, "start", "bad-json");
case!(search_start_typed, "start", "typed");
case!(search_start_null, "start", "null");
case!(search_start_folded, "start", "folded");
case!(search_start_no_case, "start", "no-case");
case!(search_start_missing_case, "start", "missing-case");
case!(search_start_case_zero, "start", "case-zero");
case!(search_start_from_only, "start", "from-only");
case!(search_start_date_invalid, "start", "date-invalid");
case!(search_start_mailboxes_empty, "start", "mailboxes-empty");
case!(
    search_start_mailboxes_null_entry,
    "start",
    "mailboxes-null-entry"
);
case!(search_start_kql_mailbox, "start", "kql-mailbox");
case!(
    search_start_kql_negated_subject,
    "start",
    "kql-negated-subject"
);
case!(search_start_kql_negated_body, "start", "kql-negated-body");
case!(search_start_kql_mixed, "start", "kql-mixed");
case!(search_start_kql_empty, "start", "kql-empty");
case!(search_start_kql_depth, "start", "kql-depth");
case!(search_start_kql_terms, "start", "kql-terms");
case!(search_start_kql_length, "start", "kql-length");
case!(search_start_kql_quote, "start", "kql-quote");
case!(search_start_kql_date_empty, "start", "kql-date-empty");
case!(search_start_kql_control, "start", "kql-control");
case!(
    search_start_kql_trailing_operator,
    "start",
    "kql-trailing-operator"
);
case!(
    search_start_kql_unclosed_quote,
    "start",
    "kql-unclosed-quote"
);
case!(
    search_start_kql_ignores_filters,
    "start",
    "kql-ignores-filters"
);

case!(export_success, "export", "success");

case!(export_foreign, "export", "foreign");
case!(export_denied, "export", "denied");
case!(export_invalid, "export", "invalid");
case!(export_missing_ids, "export", "missing-ids");
case!(export_missing_case_id, "export", "missing-case-id");
case!(export_missing_case, "export", "missing-case");
case!(export_closed, "export", "closed");
case!(export_no_completed, "export", "no-completed");
case!(export_empty_binding, "export", "empty-binding");
case!(export_unbound, "export", "unbound");
case!(export_too_many, "export", "too-many");
case!(export_duplicates, "export", "duplicates");
case!(export_empty_numeric, "export", "empty-numeric");
case!(export_mixed, "export", "mixed");
case!(export_pst, "export", "pst");
case!(export_repeat, "export", "repeat");
case!(export_raw, "export", "raw");
case!(export_large, "export", "large");
case!(export_binary, "export", "binary");
case!(export_missing_blob, "export", "missing-blob");
case!(export_audit_error, "export", "audit-error");

macro_rules! mutant {
    ($test:ident,$action:literal,$name:literal) => {
        #[tokio::test]
        async fn $test() -> Result<(), common::BoxError> {
            compliance_oracle::mutants::reject($action, $name).await
        }
    };
}
mutant!(mutant_list, "list", "status");
mutant!(mutant_get, "get", "status");
mutant!(mutant_create, "create", "status");
mutant!(mutant_update, "update", "status");
mutant!(mutant_delete, "delete", "status");
mutant!(mutant_close, "close", "status");
mutant!(mutant_associate, "associate", "status");
mutant!(mutant_start, "start", "status");
mutant!(mutant_search, "search", "status");
mutant!(mutant_export, "export", "status");
mutant!(mutant_hold, "hold", "status");
mutant!(mutant_release, "release", "status");
mutant!(mutant_no_audit, "hold", "no-audit");
mutant!(mutant_double_bump, "hold", "double-bump");
mutant!(mutant_no_tenant_filter, "list", "no-tenant-filter");
#[tokio::test]
async fn switches_restore_all_twelve_routes_to_go() -> Result<(), common::BoxError> {
    compliance_oracle::kill_switch().await
}

case!(cases_list_large_json, "list", "large-json");

macro_rules! commit_fault {
    ($test:ident,$action:literal,$cut:literal) => {
        #[tokio::test]
        async fn $test() -> Result<(), common::BoxError> {
            compliance_oracle::run_with($action, "success", $cut).await
        }
    };
}
commit_fault!(commit_create_before, "create", "commit-before");
commit_fault!(commit_create_after, "create", "commit-after");
commit_fault!(commit_close_before, "close", "commit-before");
commit_fault!(commit_close_after, "close", "commit-after");
commit_fault!(commit_hold_before, "hold", "commit-before");
commit_fault!(commit_hold_after, "hold", "commit-after");
commit_fault!(commit_export_before, "export", "commit-before");
commit_fault!(commit_export_after, "export", "commit-after");

case!(fault_hold_audit, "hold", "audit-failure");
case!(fault_release_audit, "release", "audit-failure");
case!(fault_close_audit, "close", "audit-failure");
case!(fault_hold_query, "hold", "query-failure");
case!(fault_release_query, "release", "query-failure");

case!(head_list_head, "list", "head");
case!(head_list_large_head, "list", "large-head");
case!(head_get_head, "get", "head");
case!(head_search_head, "search", "head");
case!(head_export_head, "export", "head");
case!(head_export_large_head, "export", "large-head");

case!(head_export_huge, "export", "huge-head");

case!(query_export_bytes, "export", "byte-ids");
case!(query_export_semicolon, "export", "semicolon");
case!(query_export_escape, "export", "bad-escape");
