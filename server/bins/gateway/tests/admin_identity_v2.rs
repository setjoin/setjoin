//! F01 slice `idv2-sources` (read half) frozen-Go oracle, replayed without a Go upstream.
mod admin_identity_v2_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_v2_oracle::run($action, $kind).await
        }
    };
}

case!(sources_success, "sources", "success");
case!(sources_scoped, "sources", "scoped");
case!(sources_denied, "sources", "denied");
case!(sources_filter, "sources", "filter");
case!(sources_state, "sources", "state");
case!(sources_source, "sources", "source");
case!(sources_sort, "sources", "sort");
case!(sources_limit, "sources", "limit");
case!(sources_limit_max, "sources", "limit-max");
case!(sources_limit_plus, "sources", "limit-plus");
case!(sources_page2, "sources", "page2");
case!(sources_bad_limit, "sources", "bad-limit");
case!(sources_bad_limit_text, "sources", "bad-limit-text");
case!(sources_over_limit, "sources", "over-limit");
case!(sources_bad_sort, "sources", "bad-sort");
case!(sources_unknown_param, "sources", "unknown-param");
case!(sources_repeated, "sources", "repeated");
case!(sources_bad_state, "sources", "bad-state");
case!(sources_long_filter, "sources", "long-filter");
case!(sources_non_utf8_filter, "sources", "non-utf8-filter");
case!(sources_non_utf8_source, "sources", "non-utf8-source");
case!(sources_non_utf8_state, "sources", "non-utf8-state");
case!(sources_non_utf8_cursor, "sources", "non-utf8-cursor");
case!(sources_non_utf8_name, "sources", "non-utf8-name");
case!(sources_non_utf8_limit, "sources", "non-utf8-limit");
case!(sources_non_utf8_sort, "sources", "non-utf8-sort");
case!(people_non_utf8_filter, "people", "non-utf8-filter");
case!(people_non_utf8_source, "people", "non-utf8-source");
case!(people_non_utf8_state, "people", "non-utf8-state");
case!(people_non_utf8_cursor, "people", "non-utf8-cursor");
case!(people_non_utf8_name, "people", "non-utf8-name");
case!(people_non_utf8_limit, "people", "non-utf8-limit");
case!(people_non_utf8_sort, "people", "non-utf8-sort");
case!(conflicts_non_utf8_filter, "conflicts", "non-utf8-filter");
case!(conflicts_non_utf8_source, "conflicts", "non-utf8-source");
case!(conflicts_non_utf8_state, "conflicts", "non-utf8-state");
case!(conflicts_non_utf8_cursor, "conflicts", "non-utf8-cursor");
case!(conflicts_non_utf8_name, "conflicts", "non-utf8-name");
case!(conflicts_non_utf8_limit, "conflicts", "non-utf8-limit");
case!(conflicts_non_utf8_sort, "conflicts", "non-utf8-sort");
case!(events_non_utf8_filter, "events", "non-utf8-filter");
case!(events_non_utf8_source, "events", "non-utf8-source");
case!(events_non_utf8_state, "events", "non-utf8-state");
case!(events_non_utf8_cursor, "events", "non-utf8-cursor");
case!(events_non_utf8_name, "events", "non-utf8-name");
case!(events_non_utf8_limit, "events", "non-utf8-limit");
case!(events_non_utf8_sort, "events", "non-utf8-sort");
case!(sources_bad_source, "sources", "bad-source");
case!(sources_long_source, "sources", "long-source");
case!(sources_semicolon, "sources", "semicolon");
case!(sources_bad_cursor, "sources", "bad-cursor");
case!(sources_cursor_mismatch, "sources", "cursor-mismatch");
case!(sources_cursor_expired, "sources", "cursor-expired");
case!(sources_cursor_shape, "sources", "cursor-shape");
case!(sources_cursor_trailing, "sources", "cursor-trailing");
case!(sources_cursor_empty, "sources", "cursor-empty");
case!(sources_cursor_null, "sources", "cursor-null");
case!(sources_cursor_version, "sources", "cursor-version");
case!(sources_cursor_fields, "sources", "cursor-fields");
case!(sources_etag_match, "sources", "etag-match");
case!(sources_etag_star, "sources", "etag-star");
case!(sources_etag_miss, "sources", "etag-miss");
case!(
    sources_success_status_mutant,
    "sources",
    "success-status-mutant"
);

case!(people_success, "people", "success");
case!(people_scoped, "people", "scoped");
case!(people_denied, "people", "denied");
case!(people_filter, "people", "filter");
case!(people_state, "people", "state");
case!(people_source, "people", "source");
case!(people_sort, "people", "sort");
case!(people_limit, "people", "limit");
case!(people_limit_max, "people", "limit-max");
case!(people_limit_plus, "people", "limit-plus");
case!(people_page2, "people", "page2");
case!(people_bad_limit, "people", "bad-limit");
case!(people_bad_limit_text, "people", "bad-limit-text");
case!(people_over_limit, "people", "over-limit");
case!(people_bad_sort, "people", "bad-sort");
case!(people_unknown_param, "people", "unknown-param");
case!(people_repeated, "people", "repeated");
case!(people_bad_state, "people", "bad-state");
case!(people_long_filter, "people", "long-filter");
case!(people_bad_source, "people", "bad-source");
case!(people_long_source, "people", "long-source");
case!(people_semicolon, "people", "semicolon");
case!(people_bad_cursor, "people", "bad-cursor");
case!(people_cursor_mismatch, "people", "cursor-mismatch");
case!(people_cursor_expired, "people", "cursor-expired");
case!(people_cursor_shape, "people", "cursor-shape");
case!(people_cursor_trailing, "people", "cursor-trailing");
case!(people_cursor_empty, "people", "cursor-empty");
case!(people_cursor_null, "people", "cursor-null");
case!(people_cursor_version, "people", "cursor-version");
case!(people_cursor_fields, "people", "cursor-fields");
case!(people_etag_match, "people", "etag-match");
case!(people_etag_star, "people", "etag-star");
case!(people_etag_miss, "people", "etag-miss");
case!(
    people_success_status_mutant,
    "people",
    "success-status-mutant"
);

case!(conflicts_success, "conflicts", "success");
case!(conflicts_scoped, "conflicts", "scoped");
case!(conflicts_denied, "conflicts", "denied");
case!(conflicts_filter, "conflicts", "filter");
case!(conflicts_state, "conflicts", "state");
case!(conflicts_source, "conflicts", "source");
case!(conflicts_sort, "conflicts", "sort");
case!(conflicts_limit, "conflicts", "limit");
case!(conflicts_limit_max, "conflicts", "limit-max");
case!(conflicts_limit_plus, "conflicts", "limit-plus");
case!(conflicts_page2, "conflicts", "page2");
case!(conflicts_bad_limit, "conflicts", "bad-limit");
case!(conflicts_bad_limit_text, "conflicts", "bad-limit-text");
case!(conflicts_over_limit, "conflicts", "over-limit");
case!(conflicts_bad_sort, "conflicts", "bad-sort");
case!(conflicts_unknown_param, "conflicts", "unknown-param");
case!(conflicts_repeated, "conflicts", "repeated");
case!(conflicts_bad_state, "conflicts", "bad-state");
case!(conflicts_long_filter, "conflicts", "long-filter");
case!(conflicts_bad_source, "conflicts", "bad-source");
case!(conflicts_long_source, "conflicts", "long-source");
case!(conflicts_semicolon, "conflicts", "semicolon");
case!(conflicts_bad_cursor, "conflicts", "bad-cursor");
case!(conflicts_cursor_mismatch, "conflicts", "cursor-mismatch");
case!(conflicts_cursor_expired, "conflicts", "cursor-expired");
case!(conflicts_cursor_shape, "conflicts", "cursor-shape");
case!(conflicts_cursor_trailing, "conflicts", "cursor-trailing");
case!(conflicts_cursor_empty, "conflicts", "cursor-empty");
case!(conflicts_cursor_null, "conflicts", "cursor-null");
case!(conflicts_cursor_version, "conflicts", "cursor-version");
case!(conflicts_cursor_fields, "conflicts", "cursor-fields");
case!(conflicts_etag_match, "conflicts", "etag-match");
case!(conflicts_etag_star, "conflicts", "etag-star");
case!(conflicts_etag_miss, "conflicts", "etag-miss");
case!(
    conflicts_success_status_mutant,
    "conflicts",
    "success-status-mutant"
);

case!(events_success, "events", "success");
case!(events_scoped, "events", "scoped");
case!(events_denied, "events", "denied");
case!(events_filter, "events", "filter");
case!(events_state, "events", "state");
case!(events_source, "events", "source");
case!(events_sort, "events", "sort");
case!(events_limit, "events", "limit");
case!(events_limit_max, "events", "limit-max");
case!(events_limit_plus, "events", "limit-plus");
case!(events_page2, "events", "page2");
case!(events_bad_limit, "events", "bad-limit");
case!(events_bad_limit_text, "events", "bad-limit-text");
case!(events_over_limit, "events", "over-limit");
case!(events_bad_sort, "events", "bad-sort");
case!(events_unknown_param, "events", "unknown-param");
case!(events_repeated, "events", "repeated");
case!(events_bad_state, "events", "bad-state");
case!(events_long_filter, "events", "long-filter");
case!(events_bad_source, "events", "bad-source");
case!(events_long_source, "events", "long-source");
case!(events_semicolon, "events", "semicolon");
case!(events_bad_cursor, "events", "bad-cursor");
case!(events_cursor_mismatch, "events", "cursor-mismatch");
case!(events_cursor_expired, "events", "cursor-expired");
case!(events_cursor_shape, "events", "cursor-shape");
case!(events_cursor_trailing, "events", "cursor-trailing");
case!(events_cursor_empty, "events", "cursor-empty");
case!(events_cursor_null, "events", "cursor-null");
case!(events_cursor_version, "events", "cursor-version");
case!(events_cursor_fields, "events", "cursor-fields");
case!(events_etag_match, "events", "etag-match");
case!(events_etag_star, "events", "etag-star");
case!(events_etag_miss, "events", "etag-miss");
case!(
    events_success_status_mutant,
    "events",
    "success-status-mutant"
);

case!(person_success, "person", "success");
case!(person_scoped, "person", "scoped");
case!(person_foreign, "person", "foreign");
case!(person_denied, "person", "denied");
case!(person_missing, "person", "missing");
case!(person_bad_id, "person", "bad-id");
case!(person_zero_id, "person", "zero-id");
case!(person_etag_match, "person", "etag-match");
case!(person_etag_miss, "person", "etag-miss");
case!(
    person_success_status_mutant,
    "person",
    "success-status-mutant"
);

case!(conflict_success, "conflict", "success");
case!(conflict_scoped, "conflict", "scoped");
case!(conflict_foreign, "conflict", "foreign");
case!(conflict_denied, "conflict", "denied");
case!(conflict_missing, "conflict", "missing");
case!(conflict_bad_id, "conflict", "bad-id");
case!(conflict_nil_id, "conflict", "nil-id");
case!(conflict_soft, "conflict", "soft");
case!(conflict_rejected, "conflict", "rejected");
case!(conflict_uppercase, "conflict", "uppercase");
case!(conflict_compact, "conflict", "compact");
case!(conflict_etag_match, "conflict", "etag-match");
case!(conflict_etag_miss, "conflict", "etag-miss");
case!(
    conflict_success_status_mutant,
    "conflict",
    "success-status-mutant"
);

macro_rules! case2 {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_identity_v2_oracle::run($action, $kind).await
        }
    };
}

case2!(mappings_success, "mappings", "success");
case2!(mappings_scoped, "mappings", "scoped");
case2!(mappings_denied, "mappings", "denied");
case2!(
    mappings_success_status_mutant,
    "mappings",
    "success-status-mutant"
);

case2!(inventory_success, "inventory", "success");
case2!(inventory_scoped, "inventory", "scoped");
case2!(inventory_denied, "inventory", "denied");
case2!(
    inventory_success_status_mutant,
    "inventory",
    "success-status-mutant"
);

case2!(export_success, "export", "success");
case2!(export_scoped, "export", "scoped");
case2!(export_denied, "export", "denied");
case2!(
    export_success_status_mutant,
    "export",
    "success-status-mutant"
);

case2!(job_success, "job", "success");
case2!(job_running, "job", "running");
case2!(job_other_actor, "job", "other-actor");
case2!(job_missing, "job", "missing");
case2!(job_bad_id, "job", "bad-id");
case2!(job_nil_id, "job", "nil-id");
case2!(job_uppercase, "job", "uppercase");
case2!(job_kind_denied, "job", "kind-denied");
case2!(job_denied, "job", "denied");
case2!(job_scoped, "job", "scoped");
case2!(job_etag_match, "job", "etag-match");
case2!(job_success_status_mutant, "job", "success-status-mutant");

case2!(results_success, "results", "success");
case2!(results_page, "results", "page");
case2!(results_page_limit, "results", "page-limit");
case2!(results_after_end, "results", "after-end");
case2!(results_bad_after, "results", "bad-after");
case2!(results_bad_after_text, "results", "bad-after-text");
case2!(results_bad_limit, "results", "bad-limit-job");
case2!(results_bad_limit_text, "results", "bad-limit-job-text");
case2!(results_over_limit, "results", "over-limit-job");
case2!(results_other_actor, "results", "other-actor");
case2!(results_missing, "results", "missing");
case2!(results_bad_id, "results", "bad-id");
case2!(results_kind_denied, "results", "kind-denied");
case2!(results_denied, "results", "denied");
case2!(results_scoped, "results", "scoped");
case2!(
    results_success_status_mutant,
    "results",
    "success-status-mutant"
);

case2!(source_success, "source", "success");
case2!(source_with_secrets, "source", "with-secrets");
case2!(source_draft, "source", "draft");
case2!(source_no_envelope, "source", "no-envelope");
case2!(source_unknown_field, "source", "unknown-field");
case2!(source_corrupt, "source", "corrupt");
case2!(source_missing, "source", "missing");
case2!(source_bad_key, "source", "bad-key");
case2!(source_denied, "source", "denied");
case2!(source_scoped, "source", "scoped");
case2!(source_etag_match, "source", "etag-match");
case2!(
    source_success_status_mutant,
    "source",
    "success-status-mutant"
);

case2!(source_export_success, "source-export", "success");
case2!(source_export_with_secrets, "source-export", "with-secrets");
case2!(source_export_missing, "source-export", "missing");
case2!(source_export_denied, "source-export", "denied");
case2!(source_export_scoped, "source-export", "scoped");
case2!(
    source_export_success_status_mutant,
    "source-export",
    "success-status-mutant"
);

case2!(pause_success, "pause", "success");
case2!(pause_repeat, "pause", "repeat");
case2!(pause_scoped, "pause", "scoped");
case2!(pause_denied, "pause", "denied");
case2!(pause_bad_json, "pause", "bad-json");
case2!(pause_unknown_field, "pause", "unknown-field");
case2!(pause_typed, "pause", "typed");
case2!(pause_trailing, "pause", "trailing");
case2!(pause_null_body, "pause", "null-body");
case2!(pause_oversize, "pause", "oversize");
case2!(pause_bad_generation, "pause", "bad-generation");
case2!(pause_no_if_match, "pause", "no-if-match");
case2!(pause_key_mismatch, "pause", "key-mismatch");
case2!(pause_bad_key, "pause", "bad-key");
case2!(pause_reason_mismatch, "pause", "reason-mismatch");
case2!(pause_reason_required, "pause", "reason-required");
case2!(pause_stale, "pause", "stale");
case2!(pause_illegal, "pause", "illegal");
case2!(pause_idem_reuse, "pause", "idem-reuse");
case2!(pause_missing_source, "pause", "missing-source");
case2!(pause_bad_source_key, "pause", "bad-source-key");
case2!(pause_etag_match, "pause", "etag-match");
case2!(
    pause_success_status_mutant,
    "pause",
    "success-status-mutant"
);

case2!(resume_success, "resume", "success");
case2!(resume_repeat, "resume", "repeat");
case2!(resume_scoped, "resume", "scoped");
case2!(resume_denied, "resume", "denied");
case2!(resume_bad_json, "resume", "bad-json");
case2!(resume_stale, "resume", "stale");
case2!(
    resume_success_status_mutant,
    "resume",
    "success-status-mutant"
);

case2!(retire_success, "retire", "success");
case2!(retire_repeat, "retire", "repeat");
case2!(retire_scoped, "retire", "scoped");
case2!(retire_denied, "retire", "denied");
case2!(retire_bad_json, "retire", "bad-json");
case2!(retire_stale, "retire", "stale");
case2!(
    retire_success_status_mutant,
    "retire",
    "success-status-mutant"
);

case2!(activate_success, "activate", "success");
case2!(activate_repeat, "activate", "repeat");
case2!(activate_scoped, "activate", "scoped");
case2!(activate_denied, "activate", "denied");
case2!(activate_bad_json, "activate", "bad-json");
case2!(activate_stale, "activate", "stale");
case2!(
    activate_success_status_mutant,
    "activate",
    "success-status-mutant"
);

case2!(cancel_success, "cancel", "success");
case2!(cancel_repeat, "cancel", "repeat");
case2!(cancel_running_job, "cancel", "running-job");
case2!(cancel_terminal, "cancel", "terminal");
case2!(cancel_other_actor, "cancel", "other-actor");
case2!(cancel_missing, "cancel", "missing");
case2!(cancel_bad_id, "cancel", "bad-id");
case2!(cancel_kind_denied, "cancel", "kind-denied");
case2!(cancel_denied, "cancel", "denied");
case2!(cancel_scoped, "cancel", "scoped");
case2!(
    cancel_success_status_mutant,
    "cancel",
    "success-status-mutant"
);

case2!(decision_success, "decision", "success");
case2!(decision_repeat, "decision", "repeat");
case2!(decision_defer, "decision", "defer");
case2!(decision_scoped, "decision", "scoped");
case2!(decision_foreign, "decision", "foreign");
case2!(decision_no_user, "decision", "no-user");
case2!(decision_denied, "decision", "denied");
case2!(decision_missing, "decision", "missing");
case2!(decision_bad_json, "decision", "bad-json");
case2!(decision_bad_decision, "decision", "bad-decision");
case2!(decision_reason_mismatch, "decision", "reason-mismatch");
case2!(decision_no_if_match, "decision", "no-if-match");
case2!(decision_link_no_person, "decision", "link-no-person");
case2!(decision_person_on_reject, "decision", "person-on-reject");
case2!(decision_bad_person, "decision", "bad-person");
case2!(decision_bad_conflict_id, "decision", "bad-conflict-id");
case2!(decision_stale, "decision", "stale");
case2!(decision_soft_link, "decision", "soft-link");
case2!(
    decision_success_status_mutant,
    "decision",
    "success-status-mutant"
);
case2!(source_export_bad_key, "source-export", "bad-key");

/// Family mutant: a reducer notification that never arrives must be seen by the oracle.
#[tokio::test]
async fn family_oracle_rejects_no_notify() -> Result<(), common::BoxError> {
    admin_identity_v2_oracle::run("pause", "success-no-notify-fault").await
}

case2!(create_success, "create", "success");
case2!(create_repeat, "create", "repeat");
case2!(create_ad, "create", "ad");
case2!(create_exists, "create", "exists");
case2!(create_scoped, "create", "scoped");
case2!(create_denied, "create", "denied");
case2!(create_bad_json, "create", "bad-json");
case2!(create_unknown_field, "create", "unknown-field");
case2!(create_doc_null, "create", "doc-null");
case2!(create_doc_missing, "create", "doc-missing");
case2!(create_bad_api_version, "create", "bad-api-version");
case2!(create_bad_metadata, "create", "bad-metadata");
case2!(create_spec_no_type, "create", "spec-no-type");
case2!(create_spec_unknown_field, "create", "spec-unknown-field");
case2!(create_unknown_type, "create", "unknown-type");
case2!(create_bad_endpoint, "create", "bad-endpoint");
case2!(create_bad_ad_subject, "create", "bad-ad-subject");
case2!(create_bad_capability, "create", "bad-capability");
case2!(create_if_match_new, "create", "if-match-new");
case2!(create_key_mismatch, "create", "key-mismatch");
case2!(create_reason_mismatch, "create", "reason-mismatch");
case2!(create_oversize, "create", "oversize");
case2!(
    create_success_status_mutant,
    "create",
    "success-status-mutant"
);

case2!(put_success, "put", "success");
case2!(put_repeat, "put", "repeat");
case2!(put_path_mismatch, "put", "path-mismatch");
case2!(put_stale, "put", "stale");
case2!(put_no_if_match, "put", "no-if-match");
case2!(put_not_draft, "put", "not-draft");
case2!(put_scoped, "put", "scoped");
case2!(put_denied, "put", "denied");
case2!(put_bad_json, "put", "bad-json");
case2!(put_success_status_mutant, "put", "success-status-mutant");

case2!(plan_success, "plan", "success");
case2!(plan_unchanged, "plan", "unchanged");
case2!(plan_changed, "plan", "changed");
case2!(plan_scoped, "plan", "scoped");
case2!(plan_denied, "plan", "denied");
case2!(plan_doc_null, "plan", "doc-null");
case2!(plan_bad_api_version, "plan", "bad-api-version");
case2!(plan_bad_metadata, "plan", "bad-metadata");
case2!(plan_spec_no_type, "plan", "spec-no-type");
case2!(plan_unknown_field_doc, "plan", "unknown-field-doc");
case2!(plan_unknown_type, "plan", "unknown-type");
case2!(create_doc_string, "create", "doc-string");
case2!(create_doc_array, "create", "doc-array");
case2!(create_doc_number, "create", "doc-number");
case2!(create_doc_bool, "create", "doc-bool");
case2!(create_doc_api_type, "create", "doc-api-type");
case2!(create_doc_kind_type, "create", "doc-kind-type");
case2!(create_doc_kind_object, "create", "doc-kind-object");
case2!(create_doc_metadata_string, "create", "doc-metadata-string");
case2!(create_doc_metadata_array, "create", "doc-metadata-array");
case2!(create_doc_key_type, "create", "doc-key-type");
case2!(create_doc_display_type, "create", "doc-display-type");
case2!(
    create_doc_type_before_unknown,
    "create",
    "doc-type-before-unknown"
);
case2!(
    create_doc_unknown_before_type,
    "create",
    "doc-unknown-before-type"
);
case2!(
    create_doc_metadata_unknown_before_type,
    "create",
    "doc-metadata-unknown-before-type"
);
case2!(
    create_doc_metadata_type_before_unknown,
    "create",
    "doc-metadata-type-before-unknown"
);
case2!(plan_doc_string, "plan", "doc-string");
case2!(plan_doc_array, "plan", "doc-array");
case2!(plan_doc_number, "plan", "doc-number");
case2!(plan_doc_bool, "plan", "doc-bool");
case2!(plan_doc_api_type, "plan", "doc-api-type");
case2!(plan_doc_kind_type, "plan", "doc-kind-type");
case2!(plan_doc_kind_object, "plan", "doc-kind-object");
case2!(plan_doc_metadata_string, "plan", "doc-metadata-string");
case2!(plan_doc_metadata_array, "plan", "doc-metadata-array");
case2!(plan_doc_key_type, "plan", "doc-key-type");
case2!(plan_doc_display_type, "plan", "doc-display-type");
case2!(
    plan_doc_type_before_unknown,
    "plan",
    "doc-type-before-unknown"
);
case2!(
    plan_doc_unknown_before_type,
    "plan",
    "doc-unknown-before-type"
);
case2!(
    plan_doc_metadata_unknown_before_type,
    "plan",
    "doc-metadata-unknown-before-type"
);
case2!(
    plan_doc_metadata_type_before_unknown,
    "plan",
    "doc-metadata-type-before-unknown"
);
case2!(put_doc_api_type, "put", "doc-api-type");
case2!(put_doc_string, "put", "doc-string");
case2!(plan_success_status_mutant, "plan", "success-status-mutant");

case2!(secret_set_success, "secret-set", "success");
case2!(secret_set_repeat, "secret-set", "repeat");
case2!(secret_set_gamma, "secret-set", "set-gamma");
case2!(secret_set_scoped, "secret-set", "scoped");
case2!(secret_set_denied, "secret-set", "denied");
case2!(secret_set_bad_media, "secret-set", "bad-media");
case2!(secret_set_bad_name, "secret-set", "bad-name");
case2!(secret_set_bad_key, "secret-set", "bad-key");
case2!(secret_set_missing_source, "secret-set", "missing-source");
case2!(secret_set_empty, "secret-set", "empty");
case2!(secret_set_oversize, "secret-set", "oversize");
case2!(secret_set_stale, "secret-set", "stale");
case2!(secret_set_bad_idem, "secret-set", "bad-idem");
case2!(secret_set_reason_mismatch, "secret-set", "reason-mismatch");
case2!(
    secret_set_success_status_mutant,
    "secret-set",
    "success-status-mutant"
);

case2!(secret_rotate_success, "secret-rotate", "success");
case2!(
    secret_rotate_not_configured,
    "secret-rotate",
    "not-configured"
);
case2!(secret_rotate_repeat, "secret-rotate", "repeat");
case2!(secret_rotate_scoped, "secret-rotate", "scoped");
case2!(secret_rotate_denied, "secret-rotate", "denied");
case2!(secret_rotate_stale, "secret-rotate", "stale");
case2!(
    secret_rotate_success_status_mutant,
    "secret-rotate",
    "success-status-mutant"
);

case2!(dry_run_success, "dry-run", "success");
case2!(dry_run_repeat, "dry-run", "repeat");
case2!(dry_run_blockers, "dry-run", "blockers");
case2!(dry_run_stale, "dry-run", "stale");
case2!(dry_run_missing_source, "dry-run", "missing-source");
case2!(dry_run_invalid_doc, "dry-run", "invalid-doc");
case2!(dry_run_scoped, "dry-run", "scoped");
case2!(dry_run_denied, "dry-run", "denied");
case2!(dry_run_bad_json, "dry-run", "bad-json");
case2!(dry_run_no_if_match, "dry-run", "no-if-match");
case2!(dry_run_probe_reachable, "dry-run", "probe-reachable");
case2!(dry_run_probe_ad, "dry-run", "probe-ad");
case2!(dry_run_probe_bad_password, "dry-run", "probe-bad-password");
case2!(dry_run_probe_down, "dry-run", "probe-down");
case2!(
    dry_run_probe_search_failure,
    "dry-run",
    "probe-search-failure"
);
case2!(dry_run_probe_bad_secret, "dry-run", "probe-bad-secret");
case2!(
    dry_run_probe_status_mutant,
    "dry-run",
    "probe-reachable-status-mutant"
);
case2!(dry_run_key_mismatch, "dry-run", "key-mismatch");
case2!(
    dry_run_success_status_mutant,
    "dry-run",
    "success-status-mutant"
);
case2!(secret_rotate_bad_name, "secret-rotate", "bad-name");
case2!(secret_rotate_bad_media, "secret-rotate", "bad-media");
case2!(secret_rotate_empty, "secret-rotate", "empty");

case2!(mappings_put_success, "mappings-put", "success");
case2!(mappings_put_repeat, "mappings-put", "repeat");
case2!(mappings_put_oidc, "mappings-put", "oidc");
case2!(mappings_put_with_role, "mappings-put", "with-role");
case2!(
    mappings_put_role_no_manage,
    "mappings-put",
    "role-no-manage"
);
case2!(
    mappings_put_role_perm_missing,
    "mappings-put",
    "role-perm-missing"
);
case2!(mappings_put_unknown_role, "mappings-put", "unknown-role");
case2!(mappings_put_invalid_type, "mappings-put", "invalid-type");
case2!(mappings_put_oidc_missing, "mappings-put", "oidc-missing");
case2!(mappings_put_saml_missing, "mappings-put", "saml-missing");
case2!(mappings_put_bad_json, "mappings-put", "bad-json");
case2!(mappings_put_null_body, "mappings-put", "null-body");
case2!(mappings_put_not_array, "mappings-put", "not-array");
case2!(mappings_put_bad_type, "mappings-put", "bad-type");
case2!(mappings_put_empty_group, "mappings-put", "empty-group");
case2!(mappings_put_control_char, "mappings-put", "control-char");
case2!(mappings_put_long_group, "mappings-put", "long-group");
case2!(mappings_put_too_many, "mappings-put", "too-many");
case2!(mappings_put_trailing, "mappings-put", "trailing");
case2!(mappings_put_scoped, "mappings-put", "scoped");
case2!(mappings_put_denied, "mappings-put", "denied");
case2!(
    mappings_put_success_status_mutant,
    "mappings-put",
    "success-status-mutant"
);

// Slice `idv2-transitions` (#370).
case2!(t_list_success, "t-list", "success");
case2!(t_list_scoped, "t-list", "scoped");
case2!(t_list_denied, "t-list", "denied");
case2!(t_list_filter, "t-list", "filter");
case2!(t_list_state, "t-list", "state");
case2!(t_list_source, "t-list", "source");
case2!(t_list_sort, "t-list", "sort");
case2!(t_list_limit, "t-list", "limit");
case2!(t_list_page2, "t-list", "page2");
case2!(t_list_bad_limit, "t-list", "bad-limit");
case2!(t_list_bad_limit_text, "t-list", "bad-limit-text");
case2!(t_list_over_limit, "t-list", "over-limit");
case2!(t_list_bad_sort, "t-list", "bad-sort");
case2!(t_list_unknown_param, "t-list", "unknown-param");
case2!(t_list_repeated, "t-list", "repeated");
case2!(t_list_bad_state, "t-list", "bad-state");
case2!(t_list_long_state, "t-list", "long-state");
case2!(t_list_long_filter, "t-list", "long-filter");
case2!(t_list_bad_source, "t-list", "bad-source");
case2!(t_list_non_utf8_filter, "t-list", "non-utf8-filter");
case2!(t_list_non_utf8_source, "t-list", "non-utf8-source");
case2!(t_list_non_utf8_state, "t-list", "non-utf8-state");
case2!(t_list_non_utf8_cursor, "t-list", "non-utf8-cursor");
case2!(t_list_non_utf8_name, "t-list", "non-utf8-name");
case2!(t_list_long_source, "t-list", "long-source");
case2!(t_list_semicolon, "t-list", "semicolon");
case2!(t_list_bad_cursor, "t-list", "bad-cursor");
case2!(t_list_cursor_mismatch, "t-list", "cursor-mismatch");
case2!(t_list_cursor_expired, "t-list", "cursor-expired");
case2!(t_list_etag_match, "t-list", "etag-match");
case2!(t_list_etag_star, "t-list", "etag-star");
case2!(t_list_etag_miss, "t-list", "etag-miss");
case2!(
    t_list_success_status_mutant,
    "t-list",
    "success-status-mutant"
);

case2!(t_read_success, "t-read", "success");
case2!(t_read_executed, "t-read", "executed");
case2!(t_read_scoped, "t-read", "scoped");
case2!(t_read_denied, "t-read", "denied");
case2!(t_read_bad_id, "t-read", "bad-id");
case2!(t_read_nil_id, "t-read", "nil-id");
case2!(t_read_missing, "t-read", "missing");
case2!(t_read_uppercase, "t-read", "uppercase");
case2!(t_read_etag_match, "t-read", "etag-match");
case2!(t_read_etag_miss, "t-read", "etag-miss");
case2!(
    t_read_success_status_mutant,
    "t-read",
    "success-status-mutant"
);

case2!(t_report_success, "t-report", "success");
case2!(t_report_scoped, "t-report", "scoped");
case2!(t_report_denied, "t-report", "denied");
case2!(t_report_bad_id, "t-report", "bad-id");
case2!(t_report_nil_id, "t-report", "nil-id");
case2!(t_report_missing, "t-report", "missing");
case2!(
    t_report_success_status_mutant,
    "t-report",
    "success-status-mutant"
);

case2!(t_preview_success, "t-preview", "success");
case2!(t_preview_repeat, "t-preview", "repeat");
case2!(t_preview_header_key, "t-preview", "header-key");
case2!(t_preview_scoped, "t-preview", "scoped");
case2!(t_preview_denied, "t-preview", "denied");
case2!(t_preview_bad_json, "t-preview", "bad-json");
case2!(t_preview_unknown_field, "t-preview", "unknown-field");
case2!(t_preview_typed, "t-preview", "typed");
case2!(t_preview_trailing, "t-preview", "trailing");
case2!(t_preview_null_body, "t-preview", "null-body");
case2!(t_preview_oversize, "t-preview", "oversize");
case2!(t_preview_reason_mismatch, "t-preview", "reason-mismatch");
case2!(t_preview_reason_required, "t-preview", "reason-required");
case2!(t_preview_key_mismatch, "t-preview", "key-mismatch");
case2!(t_preview_bad_key, "t-preview", "bad-key");
case2!(t_preview_bad_user, "t-preview", "bad-user");
case2!(t_preview_missing_user, "t-preview", "missing-user");
case2!(t_preview_bad_target, "t-preview", "bad-target");
case2!(
    t_preview_success_status_mutant,
    "t-preview",
    "success-status-mutant"
);

case2!(t_issue_success, "t-issue", "success");
case2!(t_issue_repeat, "t-issue", "repeat");
case2!(t_issue_scoped, "t-issue", "scoped");
case2!(t_issue_denied, "t-issue", "denied");
case2!(t_issue_bad_json, "t-issue", "bad-json");
case2!(t_issue_bad_digest, "t-issue", "bad-digest");
case2!(t_issue_no_if_match, "t-issue", "no-if-match");
case2!(t_issue_key_mismatch, "t-issue", "key-mismatch");
case2!(t_issue_bad_key, "t-issue", "bad-key");
case2!(t_issue_stale, "t-issue", "stale");
case2!(t_issue_bad_id, "t-issue", "bad-id");
case2!(t_issue_missing, "t-issue", "missing");
case2!(
    t_issue_success_status_mutant,
    "t-issue",
    "success-status-mutant"
);

case2!(t_complete_success, "t-complete", "success");
case2!(t_complete_repeat, "t-complete", "repeat");
case2!(t_complete_no_aal2, "t-complete", "no-aal2");
case2!(t_complete_weak_amr, "t-complete", "weak-amr");
case2!(t_complete_expired_iat, "t-complete", "expired-iat");
case2!(t_complete_bad_challenge, "t-complete", "bad-challenge");
case2!(t_complete_stale, "t-complete", "stale");
case2!(t_complete_scoped, "t-complete", "scoped");
case2!(t_complete_denied, "t-complete", "denied");
case2!(t_complete_bad_json, "t-complete", "bad-json");
case2!(t_complete_bad_digest, "t-complete", "bad-digest");
case2!(
    t_complete_success_status_mutant,
    "t-complete",
    "success-status-mutant"
);

case2!(t_request_success, "t-request", "success");
case2!(t_request_repeat, "t-request", "repeat");
case2!(t_request_protected, "t-request", "protected");
case2!(t_request_scoped, "t-request", "scoped");
case2!(t_request_denied, "t-request", "denied");
case2!(t_request_bad_json, "t-request", "bad-json");
case2!(t_request_bad_digest, "t-request", "bad-digest");
case2!(t_request_no_if_match, "t-request", "no-if-match");
case2!(t_request_bad_elevation, "t-request", "bad-elevation");
case2!(t_request_bad_approval, "t-request", "bad-approval");
case2!(t_request_key_mismatch, "t-request", "key-mismatch");
case2!(t_request_reason_mismatch, "t-request", "reason-mismatch");
case2!(t_request_reason_required, "t-request", "reason-required");
case2!(t_request_stale, "t-request", "stale");
case2!(t_request_bad_elevation_id, "t-request", "bad-elevation-id");
case2!(
    t_request_success_status_mutant,
    "t-request",
    "success-status-mutant"
);

case2!(t_approve_success, "t-approve", "success");
case2!(t_approve_repeat, "t-approve", "repeat");
case2!(t_approve_not_approver, "t-approve", "not-approver");
case2!(t_approve_scoped, "t-approve", "scoped");
case2!(t_approve_denied, "t-approve", "denied");
case2!(t_approve_bad_json, "t-approve", "bad-json");
case2!(t_approve_bad_digest, "t-approve", "bad-digest");
case2!(t_approve_stale, "t-approve", "stale");
case2!(
    t_approve_success_status_mutant,
    "t-approve",
    "success-status-mutant"
);

case2!(t_deny_success, "t-deny", "success");
case2!(t_deny_repeat, "t-deny", "repeat");
case2!(t_deny_scoped, "t-deny", "scoped");
case2!(t_deny_denied, "t-deny", "denied");
case2!(t_deny_bad_json, "t-deny", "bad-json");
case2!(
    t_deny_success_status_mutant,
    "t-deny",
    "success-status-mutant"
);

case2!(t_execute_success, "t-execute", "success");
case2!(t_execute_repeat, "t-execute", "repeat");
case2!(t_execute_not_authorized, "t-execute", "not-authorized");
case2!(t_execute_stale, "t-execute", "stale");
case2!(t_execute_scoped, "t-execute", "scoped");
case2!(t_execute_denied, "t-execute", "denied");
case2!(t_execute_bad_json, "t-execute", "bad-json");
case2!(t_execute_bad_digest, "t-execute", "bad-digest");
case2!(
    t_execute_success_status_mutant,
    "t-execute",
    "success-status-mutant"
);

case2!(t_cancel_success, "t-cancel", "success");
case2!(t_cancel_repeat, "t-cancel", "repeat");
case2!(t_cancel_stale, "t-cancel", "stale");
case2!(t_cancel_no_if_match, "t-cancel", "no-if-match");
case2!(t_cancel_bad_generation, "t-cancel", "bad-generation");
case2!(t_cancel_scoped, "t-cancel", "scoped");
case2!(t_cancel_denied, "t-cancel", "denied");
case2!(t_cancel_bad_json, "t-cancel", "bad-json");
case2!(t_cancel_key_mismatch, "t-cancel", "key-mismatch");
case2!(t_cancel_reason_mismatch, "t-cancel", "reason-mismatch");
case2!(t_cancel_reason_required, "t-cancel", "reason-required");
case2!(
    t_cancel_success_status_mutant,
    "t-cancel",
    "success-status-mutant"
);

case2!(t_rollback_preview_success, "t-rollback-preview", "success");
case2!(t_rollback_preview_repeat, "t-rollback-preview", "repeat");
case2!(
    t_rollback_preview_wrong_state,
    "t-rollback-preview",
    "wrong-state"
);
case2!(t_rollback_preview_stale, "t-rollback-preview", "stale");
case2!(t_rollback_preview_scoped, "t-rollback-preview", "scoped");
case2!(t_rollback_preview_denied, "t-rollback-preview", "denied");
case2!(
    t_rollback_preview_bad_json,
    "t-rollback-preview",
    "bad-json"
);
case2!(
    t_rollback_preview_no_if_match,
    "t-rollback-preview",
    "no-if-match"
);
case2!(
    t_rollback_preview_success_status_mutant,
    "t-rollback-preview",
    "success-status-mutant"
);

case2!(t_retry_success, "t-retry", "success");
case2!(t_retry_repeat, "t-retry", "repeat");
case2!(t_retry_not_failed, "t-retry", "not-failed");
case2!(t_retry_bad_effect, "t-retry", "bad-effect");
case2!(t_retry_stale, "t-retry", "stale");
case2!(t_retry_scoped, "t-retry", "scoped");
case2!(t_retry_denied, "t-retry", "denied");
case2!(t_retry_bad_json, "t-retry", "bad-json");
case2!(t_retry_no_if_match, "t-retry", "no-if-match");
case2!(
    t_retry_success_status_mutant,
    "t-retry",
    "success-status-mutant"
);

case2!(t_rollback_success, "t-rollback", "success");
case2!(t_rollback_repeat, "t-rollback", "repeat");
case2!(t_rollback_no_approval, "t-rollback", "no-approval");
case2!(t_rollback_stale, "t-rollback", "stale");
case2!(t_rollback_scoped, "t-rollback", "scoped");
case2!(t_rollback_denied, "t-rollback", "denied");
case2!(t_rollback_bad_json, "t-rollback", "bad-json");
case2!(t_rollback_bad_digest, "t-rollback", "bad-digest");
case2!(
    t_rollback_success_status_mutant,
    "t-rollback",
    "success-status-mutant"
);

fn signed_admin_token(user: i64, perms: &[&str]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = serde_json::json!(true);
    claims["perms"] = serde_json::json!(perms);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

async fn cut_authority_proxy(
    dsn: &str,
) -> Result<(String, tokio::task::JoinHandle<()>), common::BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cfg: tokio_postgres::Config = dsn.parse()?;
    let host = match cfg.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => return Err("TCP fixture DSN required".into()),
    };
    let port = *cfg.get_ports().first().unwrap_or(&5432);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut proxied = format!("host=127.0.0.1 port={}", listener.local_addr()?.port());
    {
        let mut add = |key: &str, value: &str| {
            proxied.push_str(&format!(
                " {key}='{}'",
                value.replace('\\', "\\\\").replace('\'', "\\'")
            ));
        };
        if let Some(v) = cfg.get_user() {
            add("user", v);
        }
        if let Some(v) = cfg.get_password() {
            add("password", std::str::from_utf8(v)?);
        }
        if let Some(v) = cfg.get_dbname() {
            add("dbname", v);
        }
        if let Some(v) = cfg.get_options() {
            add("options", v);
        }
    }
    let task = tokio::spawn(async move {
        const MARKER: &[u8] = b"rg.permissions";
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let host = host.clone();
            tokio::spawn(async move {
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let c2s = async {
                    let mut buf = [0u8; 8192];
                    let mut tail = Vec::with_capacity(MARKER.len());
                    loop {
                        let Ok(n) = cr.read(&mut buf).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        let mut window = Vec::with_capacity(tail.len() + n);
                        window.extend_from_slice(&tail);
                        window.extend_from_slice(&buf[..n]);
                        if window.windows(MARKER.len()).any(|w| w == MARKER) {
                            let _ = sw.shutdown().await;
                            break;
                        }
                        let keep = window.len().min(MARKER.len() - 1);
                        tail.clear();
                        tail.extend_from_slice(&window[window.len() - keep..]);
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                let s2c = async {
                    let _ = tokio::io::copy(&mut sr, &mut cw).await;
                };
                tokio::select! {
                    _ = c2s => {}
                    _ = s2c => {}
                }
            });
        }
    });
    Ok((proxied, task))
}

#[tokio::test]
async fn sources_plan_and_apply_answer_surrogates_and_huge_numbers_natively(
) -> Result<(), common::BoxError> {
    use hyper::{Request, Response};
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{
        admin_identity_v2::{AdminIdentityV2Route, SourceSecrets},
        RouteTable,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _serial = admin_identity_v2_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin-identity-v2-json-native") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin7-194-json").await?;
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{identity.write,users.read}',NULL) RETURNING id",
            &[&format!("admin7-194-json-{}", a.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role_id],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();

    let result = async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker =
            common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        let route = AdminIdentityV2Route {
            exec,
            worker,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            secrets: SourceSecrets::new(|name| (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))),
        };
        let go_hits = Arc::new(AtomicUsize::new(0));
        let hits = go_hits.clone();
        let upstream = common::fake_upstream(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            async { Response::builder().status(500).body(common::full("go-called")).unwrap() }
        })
        .await;
        let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
        let token = signed_admin_token(a.user, &["identity.write"]);

        let send_post = |path: &str, body: String, extra: &[(&str, &str)]| {
            let token = token.clone();
            let path = path.to_owned();
            let extra: Vec<(String, String)> = extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            async move {
                let mut builder = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"));
                for (k, v) in &extra {
                    builder = builder.header(k.as_str(), v.as_str());
                }
                let resp = common::send(gw, builder.body(common::full(body))?).await;
                let status = resp.status().as_u16();
                let text = String::from_utf8(common::body_bytes(resp).await.to_vec())?;
                Ok::<_, common::BoxError>((status, text))
            }
        };

        // Plan: lone surrogate & out-of-f64-range numbers answered natively.
        let (st, _) = send_post(
            "/api/admin/identity/v2/sources/plan",
            r#"{"\uD800":1}"#.into(),
            &[],
        )
        .await?;
        assert_eq!(st, 400);

        let (st, body) = send_post(
            "/api/admin/identity/v2/sources/plan",
            r#"{"apiVersion":1e999}"#.into(),
            &[],
        )
        .await?;
        assert_eq!(st, 400);
        assert!(body.contains("cannot unmarshal number"), "{body}");

        let valid_huge = r#"{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"test194-huge","displayName":"Test194 Huge"},"spec":{"type":"local","passwordPolicy":{"minLength":1e999}}}"#;
        let (st, body) = send_post(
            "/api/admin/identity/v2/sources/plan",
            valid_huge.into(),
            &[],
        )
        .await?;
        assert_eq!(st, 200, "{body}");
        assert!(body.contains("1e999"), "{body}");

        // Apply (POST /sources): lone surrogate & out-of-f64-range numbers answered natively.
        let idem1 = "95300000-0000-4000-8000-000000000194";
        let idem2 = "95300000-0000-4000-8000-000000000195";
        let hdrs1 = [("x-audit-reason", "test194"), ("idempotency-key", idem1)];
        let hdrs2 = [("x-audit-reason", "test194"), ("idempotency-key", idem2)];

        let (st, _) = send_post(
            "/api/admin/identity/v2/sources",
            format!(r#"{{"document":{{"\uD800":1}},"reason":"test194","idempotencyKey":"{idem1}"}}"#),
            &hdrs1,
        )
        .await?;
        assert_eq!(st, 400);

        let (st, body) = send_post(
            "/api/admin/identity/v2/sources",
            format!(r#"{{"document":{{"apiVersion":1e999}},"reason":"test194","idempotencyKey":"{idem1}"}}"#),
            &hdrs1,
        )
        .await?;
        assert_eq!(st, 400);
        assert!(body.contains("cannot unmarshal number"), "{body}");

        let (st, body) = send_post(
            "/api/admin/identity/v2/sources",
            format!(r#"{{"document":{valid_huge},"reason":"test194","idempotencyKey":"{idem2}"}}"#),
            &hdrs2,
        )
        .await?;
        assert_eq!(st, 201, "{body}");

        assert_eq!(go_hits.load(Ordering::SeqCst), 0, "must not forward to Go");
        let metrics = common::send(
            gw,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics_body = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        assert!(
            metrics_body
                .lines()
                .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0"),
            "unexpected F01 proxy metric: {metrics_body}"
        );
        Ok::<_, common::BoxError>(())
    }
    .await;

    let _ = owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM identity_source_operations WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key='test194-huge'); \
             DELETE FROM identity_link_events WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key='test194-huge'); \
             DELETE FROM identity_sources WHERE source_key='test194-huge'; COMMIT;",
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)",
            &[&receipts],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role_id])
        .await;
    let _ = common::remove_blob_account(&owner, &a).await;
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"
        ))
        .await;
    result
}

#[tokio::test]
async fn dry_run_without_source_probe_returns_503_natively() -> Result<(), common::BoxError> {
    use hyper::{Request, Response};
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{
        admin_identity_v2::{AdminIdentityV2Route, SourceSecrets},
        RouteTable,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _serial = admin_identity_v2_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin-identity-v2-dry-run-no-probe") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin7-194-probe").await?;
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{identity.write,users.read}',NULL) RETURNING id",
            &[&format!("admin7-194-probe-{}", a.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role_id],
        )
        .await?;
    let deployment_id: String = owner
        .query_one(
            "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
            &[],
        )
        .await?
        .get(0);
    let keyring = setjoin_config_secret::keyring_from_lookup(&deployment_id, |name| {
        (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
    })?;
    let codec = setjoin_config_secret::ConfigSecretCodec::new(keyring)?;
    let plain = r#"{"document":{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"test194-ldap","displayName":"Test194 LDAP"},"spec":{"type":"ldap","baseDN":"dc=example,dc=test","subjectAttribute":"entryUUID","endpoint":{"host":"ldap.test","port":636,"tls":"ldaps"}}},"secrets":{"bindPassword":"c2VjcmV0"}}"#;
    let sealed = codec.encrypt("identity_source.test194-ldap", plain.as_bytes())?;
    owner
        .execute(
            "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version,config_envelope,config_key_version) \
             VALUES('test194-ldap','Test194 LDAP','ldap','{\"authenticate\": false, \"provision_lifecycle\": true, \"stable_immutable_subject\": true}'::jsonb,'draft',1,2,$1,1)",
            &[&sealed],
        )
        .await?;

    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();

    let result = async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker =
            common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        // SourceSecrets::new has probe: None.
        let route = AdminIdentityV2Route {
            exec,
            worker,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            secrets: SourceSecrets::new(|name| {
                (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
            }),
        };
        let go_hits = Arc::new(AtomicUsize::new(0));
        let hits = go_hits.clone();
        let upstream = common::fake_upstream(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            async {
                Response::builder()
                    .status(500)
                    .body(common::full("go-called"))
                    .unwrap()
            }
        })
        .await;
        let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
        let token = signed_admin_token(a.user, &["identity.write"]);
        let idem = "95300000-0000-4000-8000-000000000196";
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/identity/v2/sources/test194-ldap/dry-run")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", "application/json")
            .header("if-match", "\"1\"")
            .header("idempotency-key", idem)
            .header("x-audit-reason", "test194")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(format!(
                r#"{{"expectedGeneration":"1","idempotencyKey":"{idem}","reason":"test194"}}"#
            )))?;
        let resp = common::send(gw, req).await;
        let status = resp.status().as_u16();
        let body = String::from_utf8(common::body_bytes(resp).await.to_vec())?;
        assert_eq!(
            status, 503,
            "expected 503 without SourceProbe, got {status}: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(
            v["detail"],
            "identity source directory probe is unavailable"
        );
        assert_eq!(go_hits.load(Ordering::SeqCst), 0, "must not forward to Go");
        let metrics = common::send(
            gw,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics_body = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        assert!(
            metrics_body
                .lines()
                .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0"),
            "unexpected F01 proxy metric: {metrics_body}"
        );
        Ok::<_, common::BoxError>(())
    }
    .await;

    let _ = owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM identity_source_operations WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key='test194-ldap'); \
             DELETE FROM identity_link_events WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key='test194-ldap'); \
             DELETE FROM identity_sources WHERE source_key='test194-ldap'; COMMIT;",
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)",
            &[&receipts],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role_id])
        .await;
    let _ = common::remove_blob_account(&owner, &a).await;
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"
        ))
        .await;
    result
}

#[tokio::test]
async fn authority_lookup_failure_fails_closed_without_forwarding() -> Result<(), common::BoxError>
{
    use hyper::{Request, Response};
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{
        admin_identity_v2::{AdminIdentityV2Route, SourceSecrets},
        RouteTable,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _serial = admin_identity_v2_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin-identity-v2-authority-fail-closed") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin7-194-auth").await?;
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{users.read}',NULL) RETURNING id",
            &[&format!("admin7-194-auth-{}", a.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role_id],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();

    let exec_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let (proxied_dsn, db_proxy) = cut_authority_proxy(exec_dsn).await?;
    let result = async {
        let exec =
            common::patient_exec(&proxied_dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        let worker =
            common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        let route = AdminIdentityV2Route {
            exec,
            worker,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            secrets: SourceSecrets::new(|name| {
                (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
            }),
        };
        let go_hits = Arc::new(AtomicUsize::new(0));
        let hits = go_hits.clone();
        let upstream = common::fake_upstream(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            async {
                Response::builder()
                    .status(500)
                    .body(common::full("go-called"))
                    .unwrap()
            }
        })
        .await;
        let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
        let token = signed_admin_token(a.user, &["users.read"]);
        let req = Request::builder()
            .method("GET")
            .uri("/api/admin/identity/v2/sources")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?;
        let resp = common::send(gw, req).await;
        let status = resp.status().as_u16();
        let body = String::from_utf8(common::body_bytes(resp).await.to_vec())?;
        assert_eq!(
            status, 403,
            "expected fail-closed 403, got {status}: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(v["detail"], "Forbidden");
        assert_eq!(go_hits.load(Ordering::SeqCst), 0, "must not forward to Go");
        let metrics = common::send(
            gw,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics_body = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        assert!(
            metrics_body
                .lines()
                .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0"),
            "unexpected F01 proxy metric: {metrics_body}"
        );
        Ok::<_, common::BoxError>(())
    }
    .await;

    db_proxy.abort();
    let _ = owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)",
            &[&receipts],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role_id])
        .await;
    let _ = common::remove_blob_account(&owner, &a).await;
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"
        ))
        .await;
    result
}

#[tokio::test]
async fn wave2b_185_transition_report_stable_etag_304_and_nil_uuid() -> Result<(), common::BoxError>
{
    use hyper::Request;
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{
        admin_identity_v2::{AdminIdentityV2Route, SourceSecrets},
        RouteTable,
    };
    use std::sync::Arc;

    let _serial = admin_identity_v2_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin8-wave2b-185") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "w2b185-admin").await?;
    let t = fixture::account(&owner, "w2b185-target").await?;
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{users.read,audit.export,identity.write}',NULL) RETURNING id",
            &[&format!("w2b185-role-{}", a.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role_id],
        )
        .await?;
    let saved_toggles: Vec<(String, bool)> = owner
        .query(
            "SELECT key, enabled FROM feature_toggles WHERE key IN ('feature.identity_model_v2','feature.identity_transitions','feature.cae_runtime')",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    owner
        .batch_execute(
            "UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.identity_model_v2','feature.identity_transitions','feature.cae_runtime')",
        )
        .await?;
    let domain: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&t.domain])
        .await?
        .get(0);
    let source = owner
        .query_one(
            "SELECT id, generation FROM identity_sources WHERE source_key='legacy:scim'",
            &[],
        )
        .await?;
    let applied_text: String = owner
        .query_one(
            "SELECT identity_source_scim_apply($1,$2,gen_random_uuid(),$3,$4::text::jsonb)::text",
            &[
                &source.get::<_, i64>(0),
                &source.get::<_, i64>(1),
                &format!("w2b185-subj-{}", t.user),
                &serde_json::json!({
                    "operation": "upsert",
                    "email": format!("w2b185-linked-{}@{domain}", t.user),
                    "displayName": "W2B185 Target",
                    "enabled": true
                })
                .to_string(),
            ],
        )
        .await?
        .get(0);
    let applied: serde_json::Value = serde_json::from_str(&applied_text)?;
    let target_id: i64 = applied["userId"].as_str().ok_or("userId")?.parse()?;
    owner
        .execute(
            "UPDATE users SET password_hash='local-recovery-proof' WHERE id=$1",
            &[&target_id],
        )
        .await?;
    let preview_text: String = owner
        .query_one(
            "SELECT identity_transition_preview($1,$2,'wave2b-185','95400000-0000-4000-8000-000000000185')::text",
            &[&a.user, &target_id],
        )
        .await?
        .get(0);
    let preview: serde_json::Value = serde_json::from_str(&preview_text)?;
    let tid = preview["transitionId"]
        .as_str()
        .ok_or("transitionId")?
        .to_owned();
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);

    let result = async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker =
            common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
        let route = AdminIdentityV2Route {
            exec,
            worker,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            secrets: SourceSecrets::new(|name| {
                (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
            }),
        };
        let upstream = common::fake_upstream(|_| async {
            hyper::Response::builder()
                .status(500)
                .body(common::full("go"))
                .unwrap()
        })
        .await;
        let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;
        let token = signed_admin_token(a.user, &["users.read", "audit.export"]);

        // 1. Nil UUID is rejected with 400 consistently with read.
        let nil_resp = common::send(
            gw,
            Request::get(
                "/api/admin/identity/v2/transitions/00000000-0000-0000-0000-000000000000/report",
            )
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?,
        )
        .await;
        assert_eq!(nil_resp.status().as_u16(), 400);

        // 2. Two report reads at different timestamps yield the exact same ETag.
        let r1 = common::send(
            gw,
            Request::get(format!("/api/admin/identity/v2/transitions/{tid}/report"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(r1.status().as_u16(), 200);
        let etag1 = r1
            .headers()
            .get("etag")
            .ok_or("etag1")?
            .to_str()?
            .to_owned();
        let body1: serde_json::Value = serde_json::from_slice(&common::body_bytes(r1).await)?;
        assert!(body1["generatedAt"].is_string());

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let r2 = common::send(
            gw,
            Request::get(format!("/api/admin/identity/v2/transitions/{tid}/report"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(r2.status().as_u16(), 200);
        let etag2 = r2
            .headers()
            .get("etag")
            .ok_or("etag2")?
            .to_str()?
            .to_owned();
        let body2: serde_json::Value = serde_json::from_slice(&common::body_bytes(r2).await)?;
        assert_ne!(
            body1["generatedAt"], body2["generatedAt"],
            "statement_timestamp should advance"
        );
        assert_eq!(etag1, etag2, "ETag must be stable despite advancing generatedAt");

        // 3. If-None-Match with the stable ETag answers 304 Not Modified.
        let r3 = common::send(
            gw,
            Request::get(format!("/api/admin/identity/v2/transitions/{tid}/report"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("if-none-match", &etag1)
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(r3.status().as_u16(), 304);
        assert_eq!(
            r3.headers().get("etag").and_then(|v| v.to_str().ok()),
            Some(etag1.as_str())
        );

        // 4. Changing transition state changes the ETag (If-None-Match misses -> 200).
        let generation: i64 = owner
            .query_one(
                "SELECT transition_generation FROM identity_transitions WHERE id=$1::text::uuid",
                &[&tid],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT identity_transition_cancel($1,$2::text::uuid,$3,'wave2b-185-cancel','95400000-0000-4000-8000-000000000186')",
                &[&a.user, &tid, &generation],
            )
            .await?;
        let r4 = common::send(
            gw,
            Request::get(format!("/api/admin/identity/v2/transitions/{tid}/report"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("if-none-match", &etag1)
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(r4.status().as_u16(), 200);
        let etag4 = r4
            .headers()
            .get("etag")
            .ok_or("etag4")?
            .to_str()?
            .to_owned();
        assert_ne!(
            etag1, etag4,
            "mutated transition must yield a different ETag"
        );

        Ok::<_, common::BoxError>(())
    }
    .await;

    for (key, enabled) in &saved_toggles {
        let _ = owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[key, enabled],
            )
            .await;
    }
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM identity_transition_effect_targets WHERE transition_id='{tid}'::uuid; \
             DELETE FROM identity_transition_effects WHERE transition_id='{tid}'::uuid; \
             DELETE FROM identity_transition_steps WHERE transition_id='{tid}'::uuid; \
             DELETE FROM identity_transition_idempotency WHERE transition_id='{tid}'::uuid; \
             DELETE FROM identity_link_events WHERE user_id={target_id} OR actor_user_id={}; \
             DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); \
             DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); \
             UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; \
             DELETE FROM identity_transition_elevations WHERE transition_id='{tid}'::uuid; \
             DELETE FROM identity_transition_challenges WHERE transition_id='{tid}'::uuid; \
             DELETE FROM identity_transitions WHERE id='{tid}'::uuid; \
             DELETE FROM identity_attribute_authority WHERE user_id={target_id}; \
             DELETE FROM identity_entitlement_grants WHERE user_id={target_id}; \
             DELETE FROM user_lifecycle_authorities WHERE user_id={target_id}; \
             DELETE FROM user_identity_links WHERE user_id={target_id}; \
             DELETE FROM admin_role_assignments WHERE role_group_id={role_id}; \
             DELETE FROM admin_role_groups WHERE id={role_id}; \
             DELETE FROM admin_audit_log WHERE id>{audit_start}; \
             COMMIT; \
             DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id={target_id}); \
             DELETE FROM mailboxes WHERE user_id={target_id}; \
             DELETE FROM users WHERE id={target_id};",
            a.user
        ))
        .await;
    for acct in [&t, &a] {
        let _ = common::remove_blob_account(&owner, acct).await;
    }
    result
}
