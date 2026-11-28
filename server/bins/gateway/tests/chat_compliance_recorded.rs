//! #291 frozen-Go HTTP/effect parity at the front door.
mod chat_compliance_oracle;
mod common;
#[tokio::test]
async fn policies_success() -> Result<(), common::BoxError> {
    chat_compliance_oracle::run("policies", "success", "").await
}
#[tokio::test]
async fn policies_foreign() -> Result<(), common::BoxError> {
    chat_compliance_oracle::run("policies", "foreign", "").await
}

macro_rules! case {
    ($name:ident,$route:literal,$label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            chat_compliance_oracle::run($route, $label, "").await
        }
    };
}
case!(policies_invalid, "policies", "invalid");
case!(cases_success, "cases", "success");
case!(cases_foreign, "cases", "foreign");
case!(cases_invalid, "cases", "invalid");
case!(holds_success, "holds", "success");
case!(holds_foreign, "holds", "foreign");
case!(holds_invalid, "holds", "invalid");
case!(preview_success, "preview", "success");
case!(preview_foreign, "preview", "foreign");
case!(preview_invalid, "preview", "invalid");
case!(overview_success, "overview", "success");
case!(overview_foreign, "overview", "foreign");
case!(overview_invalid, "overview", "invalid");
case!(overview_last_run, "overview", "last-run");
case!(policies_disabled, "policies", "disabled");
case!(create_success, "create", "success");
case!(create_foreign, "create", "foreign");
case!(create_invalid, "create", "invalid");
case!(create_repeat, "create", "repeat");
case!(create_audit_failure, "create", "audit-failure");
case!(update_success, "update", "success");
case!(update_foreign, "update", "foreign");
case!(update_invalid, "update", "invalid");
case!(update_repeat, "update", "repeat");
case!(update_grace_shorten, "update", "grace-shorten");
case!(update_grace_lengthen, "update", "grace-lengthen");
case!(
    update_grace_disable_shield,
    "update",
    "grace-disable-shield"
);
case!(update_grace_repeat, "update", "grace-repeat");
case!(delete_success, "delete", "success");
case!(delete_foreign, "delete", "foreign");
case!(delete_invalid, "delete", "invalid");
case!(delete_repeat, "delete", "repeat");
case!(delete_exposure, "delete", "exposure");
case!(delete_confirm, "delete", "confirm");
case!(delete_wrong_confirm, "delete", "wrong-confirm");
case!(delete_audit_failure, "delete", "audit-failure");
case!(hold_success, "hold", "success");
case!(hold_foreign, "hold", "foreign");
case!(hold_invalid, "hold", "invalid");
case!(hold_repeat, "hold", "repeat");
case!(hold_closed, "hold", "closed");
case!(hold_missing_channel, "hold", "missing-channel");
case!(hold_empty_reason, "hold", "empty-reason");
case!(hold_folded, "hold", "folded");
case!(hold_bad_json, "hold", "bad-json");
case!(hold_trailing, "hold", "trailing");
case!(hold_custodian, "hold", "custodian");
case!(hold_unreachable_custodian, "hold", "unreachable-custodian");
case!(hold_audit_failure, "hold", "audit-failure");
case!(hold_chain_failure, "hold", "chain-failure");
case!(release_success, "release", "success");
case!(release_foreign, "release", "foreign");
case!(release_invalid, "release", "invalid");
case!(release_repeat, "release", "repeat");
case!(release_missing, "release", "missing");
case!(release_empty_reason, "release", "empty-reason");
case!(release_null, "release", "null");
case!(release_bad_json, "release", "bad-json");
case!(release_closed, "release", "closed");
case!(release_other_hold, "release", "other-hold");
case!(release_audit_failure, "release", "audit-failure");
case!(release_chain_failure, "release", "chain-failure");
case!(search_success, "search", "success");
case!(search_foreign, "search", "foreign");
case!(search_invalid, "search", "invalid");
case!(search_repeat, "search", "repeat");
case!(search_manage_only, "search", "manage-only");
case!(search_nonmember, "search", "nonmember");
case!(search_closed, "search", "closed");
case!(search_missing_case, "search", "missing-case");
case!(search_han, "search", "han");
case!(search_han_mark, "search", "han-mark");
case!(search_invalid_date, "search", "invalid-date");
case!(search_date_from, "search", "date-from");
case!(search_date_to, "search", "date-to");
case!(search_bad_json, "search", "bad-json");
case!(search_folded, "search", "folded");
case!(search_null_channels, "search", "null-channels");
case!(search_null_channel_entry, "search", "null-channel-entry");
case!(search_limit_overflow, "search", "limit-overflow");
case!(search_audit_failure, "search", "audit-failure");
case!(search_chain_failure, "search", "chain-failure");
case!(search_date_offset24, "search", "date-offset24");
case!(read_success, "read", "success");
case!(read_foreign, "read", "foreign");
case!(read_invalid, "read", "invalid");
case!(read_repeat, "read", "repeat");
case!(read_manage_only, "read", "manage-only");
case!(read_nonmember, "read", "nonmember");
case!(read_closed, "read", "closed");
case!(read_missing_case, "read", "missing-case");
case!(read_missing_channel, "read", "missing-channel");
case!(read_bad_case, "read", "bad-case");
case!(read_bad_before, "read", "bad-before");
case!(read_bad_limit, "read", "bad-limit");
case!(read_zero_limit, "read", "zero-limit");
case!(read_before, "read", "before");
case!(read_encoded_id, "read", "encoded-id");
case!(read_encoded_mount, "read", "encoded-mount");
case!(read_audit_failure, "read", "audit-failure");
case!(read_chain_failure, "read", "chain-failure");
case!(read_huge_json, "read", "huge-json");
case!(export_success, "export", "success");

case!(export_scheduled, "export", "scheduled");

case!(export_federated_hub, "export", "federated-hub");

case!(export_attachments, "export", "attachments");

case!(export_attachments_corrupt, "export", "attachments-corrupt");

case!(export_foreign, "export", "foreign");
case!(export_invalid, "export", "invalid");
case!(export_repeat, "export", "repeat");
case!(export_manage_only, "export", "manage-only");
case!(export_disabled, "export", "disabled");
case!(export_nonmember, "export", "nonmember");
case!(export_closed, "export", "closed");
case!(export_missing_case, "export", "missing-case");
case!(export_missing_channel, "export", "missing-channel");
case!(export_mixed_missing, "export", "mixed-missing");
case!(export_bad_channel, "export", "bad-channel");
case!(export_channel_overflow, "export", "channel-overflow");
case!(export_empty_channels, "export", "empty-channels");
case!(export_duplicate_channels, "export", "duplicate-channels");
case!(export_audit_failure, "export", "audit-failure");
case!(export_chain_failure, "export", "chain-failure");
case!(export_huge_json, "export", "huge-json");
case!(export_revisions, "export", "revisions");
case!(export_scheduled_bad, "export", "scheduled-bad");
case!(export_federated_spoke, "export", "federated-spoke");
case!(export_federated_dm, "export", "federated-dm");
case!(export_federated_empty, "export", "federated-empty");
case!(export_bad_coverage, "export", "bad-coverage");
case!(export_attachments_missing, "export", "attachments-missing");
case!(
    export_attachments_no_modified,
    "export",
    "attachments-no-modified"
);
case!(export_attachments_false, "export", "attachments-false");

case!(export_channel_control, "export", "channel-control");
case!(export_channel_unicode, "export", "channel-unicode");
case!(
    export_channel_syntax_after_signed_overflow,
    "export",
    "channel-syntax-after-signed-overflow"
);

case!(export_channel_bytes, "export", "channel-bytes");

case!(search_locale, "search", "locale");
case!(search_locale_reducer, "search", "locale-reducer");
case!(search_locale_invalid, "search", "locale-invalid");
case!(export_locale, "export", "locale");
case!(policies_locale_disabled, "policies", "locale-disabled");
case!(policies_locale_foreign, "policies", "locale-foreign");
case!(holds_repeat, "holds", "repeat");

case!(policies_head, "policies", "head");
case!(cases_head, "cases", "head");
case!(holds_head, "holds", "head");
case!(read_head, "read", "head");
case!(export_head, "export", "head");
case!(preview_head, "preview", "head");
case!(overview_head, "overview", "head");
case!(export_large, "export", "large");
case!(export_head_large, "export", "head-large");
case!(policies_query_failure, "policies", "query-failure");
case!(cases_query_failure, "cases", "query-failure");
case!(holds_query_failure, "holds", "query-failure");
case!(preview_query_failure, "preview", "query-failure");
case!(overview_query_failure, "overview", "query-failure");
case!(create_write_failure, "create", "write-failure");
case!(update_write_failure, "update", "write-failure");
case!(delete_write_failure, "delete", "write-failure");
case!(export_case_name_failure, "export", "case-name-failure");

macro_rules! mutant {
    ($name:ident,$action:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            chat_compliance_oracle::qualification::mutant($action).await
        }
    };
}
mutant!(mutant_policies, "policies");
mutant!(mutant_create, "create");
mutant!(mutant_update, "update");
mutant!(mutant_delete, "delete");
mutant!(mutant_cases, "cases");
mutant!(mutant_holds, "holds");
mutant!(mutant_hold, "hold");
mutant!(mutant_release, "release");
mutant!(mutant_search, "search");
mutant!(mutant_read, "read");
mutant!(mutant_export, "export");
mutant!(mutant_preview, "preview");
mutant!(mutant_overview, "overview");

macro_rules! commit_fault {
    ($name:ident,$action:literal,$mode:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            chat_compliance_oracle::run($action, "success", $mode).await
        }
    };
}
commit_fault!(commit_create_before, "create", "commit-before");
commit_fault!(commit_create_after, "create", "commit-after");
commit_fault!(commit_update_before, "update", "commit-before");
commit_fault!(commit_update_after, "update", "commit-after");
commit_fault!(commit_delete_before, "delete", "commit-before");
commit_fault!(commit_delete_after, "delete", "commit-after");
commit_fault!(commit_hold_before, "hold", "commit-before");
commit_fault!(commit_hold_after, "hold", "commit-after");
commit_fault!(commit_release_before, "release", "commit-before");
commit_fault!(commit_release_after, "release", "commit-after");
commit_fault!(commit_search_before, "search", "commit-before");
commit_fault!(commit_search_after, "search", "commit-after");
commit_fault!(commit_read_before, "read", "commit-before");
commit_fault!(commit_read_after, "read", "commit-after");
commit_fault!(commit_export_before, "export", "commit-before");
commit_fault!(commit_export_after, "export", "commit-after");

#[tokio::test]
async fn kill_switch() -> Result<(), common::BoxError> {
    chat_compliance_oracle::qualification::kill_switch().await
}

case!(create_bad_json, "create", "bad-json");
case!(create_zero_days, "create", "zero-days");
case!(create_empty_name, "create", "empty-name");
case!(update_bad_json, "update", "bad-json");
case!(update_invalid_kind, "update", "invalid-kind");
case!(update_zero_days, "update", "zero-days");
case!(update_missing, "update", "missing");
case!(overview_last_null, "overview", "last-null");
case!(overview_last_invalid, "overview", "last-invalid");
