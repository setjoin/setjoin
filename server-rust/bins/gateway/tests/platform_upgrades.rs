//! F08 slice `updates-deploy`, group `upgrades`: the release-first upgrade control plane,
//! replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::updates::run($action, $kind, None).await
        }
    };
}


case!(console_success, "upgrades-console", "success");
case!(console_denied, "upgrades-console", "denied");
case!(console_scoped, "upgrades-console", "scoped");
case!(console_ignored_query, "upgrades-console", "ignored-query");

case!(recovery_context_success, "upgrades-recovery-context", "success");
case!(recovery_context_denied, "upgrades-recovery-context", "denied");
case!(recovery_context_scoped, "upgrades-recovery-context", "scoped");
case!(recovery_context_ignored_query, "upgrades-recovery-context", "ignored-query");

case!(intent_read_success, "upgrades-intent-read", "success");
case!(intent_read_denied, "upgrades-intent-read", "denied");
case!(intent_read_zero, "upgrades-intent-read", "zero");
case!(intent_read_word, "upgrades-intent-read", "word");
case!(intent_read_padded, "upgrades-intent-read", "padded");
case!(intent_read_huge, "upgrades-intent-read", "huge");

case!(diagnostics_success, "upgrades-diagnostics", "success");
case!(diagnostics_denied, "upgrades-diagnostics", "denied");
case!(diagnostics_scoped, "upgrades-diagnostics", "scoped");
case!(diagnostics_zero, "upgrades-diagnostics", "zero");
case!(diagnostics_word, "upgrades-diagnostics", "word");

case!(preview_ready, "upgrades-preview", "ready");
case!(preview_success, "upgrades-preview", "success");
case!(preview_denied, "upgrades-preview", "denied");
case!(preview_scoped, "upgrades-preview", "scoped");
case!(preview_bad_json, "upgrades-preview", "bad-json");
case!(preview_unknown_field, "upgrades-preview", "unknown-field");
case!(preview_two_values, "upgrades-preview", "two-values");
case!(preview_array_body, "upgrades-preview", "array-body");
case!(preview_null_body, "upgrades-preview", "null-body");
case!(preview_bad_type, "upgrades-preview", "bad-type");
case!(preview_no_reason_header, "upgrades-preview", "no-reason-header");
case!(preview_reason_mismatch, "upgrades-preview", "reason-mismatch");
case!(preview_reason_short, "upgrades-preview", "reason-short");
case!(preview_reason_required, "upgrades-preview", "reason-required");
case!(preview_bad_schedule, "upgrades-preview", "bad-schedule");
case!(preview_schedule, "upgrades-preview", "schedule");

case!(challenge_success, "upgrades-challenge", "success");
case!(challenge_denied, "upgrades-challenge", "denied");
case!(challenge_scoped, "upgrades-challenge", "scoped");
case!(challenge_bad_json, "upgrades-challenge", "bad-json");
case!(challenge_unknown_field, "upgrades-challenge", "unknown-field");
case!(challenge_two_values, "upgrades-challenge", "two-values");
case!(challenge_array_body, "upgrades-challenge", "array-body");
case!(challenge_null_body, "upgrades-challenge", "null-body");
case!(challenge_bad_type, "upgrades-challenge", "bad-type");
case!(challenge_no_reason_header, "upgrades-challenge", "no-reason-header");
case!(challenge_reason_mismatch, "upgrades-challenge", "reason-mismatch");
case!(challenge_reason_short, "upgrades-challenge", "reason-short");
case!(challenge_reason_required, "upgrades-challenge", "reason-required");
case!(challenge_bad_schedule, "upgrades-challenge", "bad-schedule");
case!(challenge_schedule, "upgrades-challenge", "schedule");
case!(challenge_bad_digest, "upgrades-challenge", "bad-digest");
case!(challenge_key_mismatch, "upgrades-challenge", "key-mismatch");
case!(challenge_key_nil, "upgrades-challenge", "key-nil");

case!(intent_request_success, "upgrades-intent-request", "success");
case!(intent_request_denied, "upgrades-intent-request", "denied");
case!(intent_request_scoped, "upgrades-intent-request", "scoped");
case!(intent_request_bad_json, "upgrades-intent-request", "bad-json");
case!(intent_request_unknown_field, "upgrades-intent-request", "unknown-field");
case!(intent_request_two_values, "upgrades-intent-request", "two-values");
case!(intent_request_array_body, "upgrades-intent-request", "array-body");
case!(intent_request_null_body, "upgrades-intent-request", "null-body");
case!(intent_request_bad_type, "upgrades-intent-request", "bad-type");
case!(intent_request_no_reason_header, "upgrades-intent-request", "no-reason-header");
case!(intent_request_reason_mismatch, "upgrades-intent-request", "reason-mismatch");
case!(intent_request_reason_short, "upgrades-intent-request", "reason-short");
case!(intent_request_reason_required, "upgrades-intent-request", "reason-required");
case!(intent_request_bad_schedule, "upgrades-intent-request", "bad-schedule");
case!(intent_request_bad_digest, "upgrades-intent-request", "bad-digest");
case!(intent_request_bad_elevation, "upgrades-intent-request", "bad-elevation");
case!(intent_request_key_mismatch, "upgrades-intent-request", "key-mismatch");
case!(intent_request_key_nil, "upgrades-intent-request", "key-nil");

case!(intent_cancel_success, "upgrades-intent-cancel", "success");
case!(intent_cancel_denied, "upgrades-intent-cancel", "denied");
case!(intent_cancel_scoped, "upgrades-intent-cancel", "scoped");
case!(intent_cancel_bad_json, "upgrades-intent-cancel", "bad-json");
case!(intent_cancel_unknown_field, "upgrades-intent-cancel", "unknown-field");
case!(intent_cancel_two_values, "upgrades-intent-cancel", "two-values");
case!(intent_cancel_array_body, "upgrades-intent-cancel", "array-body");
case!(intent_cancel_null_body, "upgrades-intent-cancel", "null-body");
case!(intent_cancel_bad_type, "upgrades-intent-cancel", "bad-type");
case!(intent_cancel_no_reason_header, "upgrades-intent-cancel", "no-reason-header");
case!(intent_cancel_reason_mismatch, "upgrades-intent-cancel", "reason-mismatch");
case!(intent_cancel_reason_short, "upgrades-intent-cancel", "reason-short");
case!(intent_cancel_reason_required, "upgrades-intent-cancel", "reason-required");
case!(intent_cancel_zero, "upgrades-intent-cancel", "zero");
case!(intent_cancel_word, "upgrades-intent-cancel", "word");
case!(intent_cancel_bad_generation, "upgrades-intent-cancel", "bad-generation");

case!(recovery_set_success, "upgrades-recovery-set", "success");
case!(recovery_set_denied, "upgrades-recovery-set", "denied");
case!(recovery_set_scoped, "upgrades-recovery-set", "scoped");
case!(recovery_set_bad_json, "upgrades-recovery-set", "bad-json");
case!(recovery_set_unknown_field, "upgrades-recovery-set", "unknown-field");
case!(recovery_set_two_values, "upgrades-recovery-set", "two-values");
case!(recovery_set_array_body, "upgrades-recovery-set", "array-body");
case!(recovery_set_null_body, "upgrades-recovery-set", "null-body");
case!(recovery_set_bad_type, "upgrades-recovery-set", "bad-type");
case!(recovery_set_no_reason_header, "upgrades-recovery-set", "no-reason-header");
case!(recovery_set_reason_mismatch, "upgrades-recovery-set", "reason-mismatch");
case!(recovery_set_reason_short, "upgrades-recovery-set", "reason-short");
case!(recovery_set_reason_required, "upgrades-recovery-set", "reason-required");
case!(recovery_set_bad_digest, "upgrades-recovery-set", "bad-digest");
case!(recovery_set_bad_identity, "upgrades-recovery-set", "bad-identity");
case!(recovery_set_huge_schema, "upgrades-recovery-set", "huge-schema");
case!(recovery_set_float_schema, "upgrades-recovery-set", "float-schema");
case!(recovery_set_bad_time, "upgrades-recovery-set", "bad-time");
case!(recovery_set_stale, "upgrades-recovery-set", "stale");
case!(recovery_set_short_checks, "upgrades-recovery-set", "short-checks");
case!(recovery_set_bad_checks, "upgrades-recovery-set", "bad-checks");
case!(recovery_set_no_checks, "upgrades-recovery-set", "no-checks");
case!(recovery_set_wrong_timeline, "upgrades-recovery-set", "wrong-timeline");
case!(recovery_set_repeat, "upgrades-recovery-set", "repeat");

case!(restore_proof_success, "upgrades-restore-proof", "success");
case!(restore_proof_denied, "upgrades-restore-proof", "denied");
case!(restore_proof_scoped, "upgrades-restore-proof", "scoped");
case!(restore_proof_bad_json, "upgrades-restore-proof", "bad-json");
case!(restore_proof_unknown_field, "upgrades-restore-proof", "unknown-field");
case!(restore_proof_two_values, "upgrades-restore-proof", "two-values");
case!(restore_proof_array_body, "upgrades-restore-proof", "array-body");
case!(restore_proof_null_body, "upgrades-restore-proof", "null-body");
case!(restore_proof_bad_type, "upgrades-restore-proof", "bad-type");
case!(restore_proof_no_reason_header, "upgrades-restore-proof", "no-reason-header");
case!(restore_proof_reason_mismatch, "upgrades-restore-proof", "reason-mismatch");
case!(restore_proof_reason_short, "upgrades-restore-proof", "reason-short");
case!(restore_proof_reason_required, "upgrades-restore-proof", "reason-required");
case!(restore_proof_bad_identity, "upgrades-restore-proof", "bad-identity");
case!(restore_proof_no_set, "upgrades-restore-proof", "no-set");
case!(restore_proof_bad_time, "upgrades-restore-proof", "bad-time");
case!(console_status_mutant, "upgrades-console", "success-status-mutant");
case!(recovery_context_status_mutant, "upgrades-recovery-context", "success-status-mutant");
case!(intent_read_status_mutant, "upgrades-intent-read", "success-status-mutant");
case!(diagnostics_status_mutant, "upgrades-diagnostics", "success-status-mutant");
case!(challenge_complete_success, "upgrades-challenge-complete", "success");
case!(challenge_complete_repeat, "upgrades-challenge-complete", "repeat");
case!(challenge_complete_denied, "upgrades-challenge-complete", "denied");
case!(challenge_complete_scoped, "upgrades-challenge-complete", "scoped");
case!(challenge_complete_weak, "upgrades-challenge-complete", "weak");
case!(challenge_complete_stale, "upgrades-challenge-complete", "stale");
case!(challenge_complete_single_factor, "upgrades-challenge-complete", "single-factor");
case!(challenge_complete_no_mfa, "upgrades-challenge-complete", "no-mfa");
case!(challenge_complete_aal1, "upgrades-challenge-complete", "aal1");
case!(challenge_complete_extensions, "upgrades-challenge-complete", "extensions");
case!(challenge_complete_duplicates, "upgrades-challenge-complete", "duplicates");
case!(challenge_complete_bad_id, "upgrades-challenge-complete", "bad-id");
case!(challenge_complete_nil_id, "upgrades-challenge-complete", "nil-id");
case!(challenge_complete_no_id, "upgrades-challenge-complete", "no-id");
case!(challenge_complete_bad_json, "upgrades-challenge-complete", "bad-json");
case!(challenge_complete_unknown_field, "upgrades-challenge-complete", "unknown-field");
case!(challenge_complete_two_values, "upgrades-challenge-complete", "two-values");
case!(challenge_complete_array_body, "upgrades-challenge-complete", "array-body");
case!(challenge_complete_null_body, "upgrades-challenge-complete", "null-body");
case!(challenge_complete_bad_type, "upgrades-challenge-complete", "bad-type");
case!(challenge_complete_status_mutant, "upgrades-challenge-complete", "success-status-mutant");
case!(preview_status_mutant, "upgrades-preview", "success-status-mutant");
case!(challenge_repeat, "upgrades-challenge", "repeat");
case!(challenge_status_mutant, "upgrades-challenge", "success-status-mutant");
case!(intent_request_repeat, "upgrades-intent-request", "repeat");
case!(intent_request_status_mutant, "upgrades-intent-request", "success-status-mutant");
case!(intent_cancel_repeat, "upgrades-intent-cancel", "repeat");
case!(intent_cancel_status_mutant, "upgrades-intent-cancel", "success-status-mutant");
case!(recovery_set_status_mutant, "upgrades-recovery-set", "success-status-mutant");
case!(restore_proof_repeat, "upgrades-restore-proof", "repeat");
case!(restore_proof_status_mutant, "upgrades-restore-proof", "success-status-mutant");

#[tokio::test]
async fn recovery_context_wrong_schema_is_rejected() -> Result<(), common::BoxError> {
    let error = platform_oracle::updates::run("upgrades-recovery-context", "success", Some("wrong-schema"))
        .await.expect_err("schema mismatch must fail before normalization");
    assert!(error.to_string().contains("schema version does not match the live database"), "{error}");
    Ok(())
}
