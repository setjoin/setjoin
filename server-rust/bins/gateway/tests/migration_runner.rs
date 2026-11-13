//! F05 slice `migration`, job runner routes (#431), replayed from frozen-Go goldens.
mod common;
mod migration_runner_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            migration_runner_oracle::run($action, $kind, stringify!($name).starts_with("provider_"))
                .await
        }
    };
}

case!(start_success, "start", "success");
case!(start_repeat, "start", "repeat");
case!(start_bare, "start", "bare");
case!(start_bad_login, "start", "bad-login");
case!(start_multi, "start", "multi");
case!(start_no_port, "start", "no-port");
case!(start_unknown_target, "start", "unknown-target");
case!(start_no_host, "start", "no-host");
case!(start_bad_type, "start", "bad-type");
case!(start_no_type, "start", "no-type");
case!(start_no_targets, "start", "no-targets");
case!(start_null_targets, "start", "null-targets");
case!(start_empty_source, "start", "empty-source");
case!(start_empty_target, "start", "empty-target");
case!(start_ews_no_url, "start", "ews-no-url");
case!(start_ews_http, "start", "ews-http");
case!(start_ews_ip, "start", "ews-ip");
case!(start_m365_no_config, "start", "m365-no-config");
case!(start_case_keys, "start", "case-keys");
case!(start_bad_json, "start", "bad-json");
case!(start_typed, "start", "typed");
case!(start_port_float, "start", "port-float");
case!(start_empty_body, "start", "empty-body");
case!(start_array_body, "start", "array-body");
case!(start_foreign, "start", "foreign");
case!(start_denied, "start", "denied");
case!(start_wrong_perm, "start", "wrong-perm");
case!(cancel_running, "cancel", "running");
case!(cancel_failed, "cancel", "failed");
case!(cancel_completed, "cancel", "completed");
case!(cancel_missing, "cancel", "missing");
case!(cancel_invalid, "cancel", "invalid");
case!(cancel_plus, "cancel", "plus");
case!(cancel_huge, "cancel", "huge");
case!(cancel_zero, "cancel", "zero");
case!(cancel_negative, "cancel", "negative");
case!(cancel_repeat, "cancel", "repeat");
case!(cancel_foreign, "cancel", "foreign");
case!(cancel_denied, "cancel", "denied");
case!(cancel_wrong_perm, "cancel", "wrong-perm");
case!(retry_failed, "retry", "failed");
case!(retry_pending, "retry", "pending");
case!(retry_completed, "retry", "completed");
case!(retry_running, "retry", "running");
case!(retry_missing, "retry", "missing");
case!(retry_invalid, "retry", "invalid");
case!(retry_zero, "retry", "zero");
case!(retry_negative, "retry", "negative");
case!(retry_repeat, "retry", "repeat");
case!(retry_foreign, "retry", "foreign");
case!(retry_denied, "retry", "denied");
case!(retry_wrong_perm, "retry", "wrong-perm");
case!(pause_running, "pause", "running");
case!(pause_missing, "pause", "missing");
case!(pause_failed, "pause", "failed");
case!(pause_invalid, "pause", "invalid");
case!(pause_repeat, "pause", "repeat");
case!(pause_foreign, "pause", "foreign");
case!(pause_denied, "pause", "denied");
case!(pause_wrong_perm, "pause", "wrong-perm");
case!(resume_paused, "resume", "paused");
case!(resume_pending, "resume", "pending");
case!(resume_missing, "resume", "missing");
case!(resume_running, "resume", "running");
case!(resume_invalid, "resume", "invalid");
case!(resume_repeat, "resume", "repeat");
case!(resume_foreign, "resume", "foreign");
case!(resume_denied, "resume", "denied");
case!(resume_wrong_perm, "resume", "wrong-perm");
case!(test_connection_success, "test-connection", "success");
case!(test_connection_login, "test-connection", "login");
case!(test_connection_bad_login, "test-connection", "bad-login");
case!(
    test_connection_list_only_user,
    "test-connection",
    "list-only-user"
);
case!(test_connection_refused, "test-connection", "refused");
case!(test_connection_private, "test-connection", "private");
case!(test_connection_loopback, "test-connection", "loopback");
case!(test_connection_metadata, "test-connection", "metadata");
case!(test_connection_no_host, "test-connection", "no-host");
case!(test_connection_bad_type, "test-connection", "bad-type");
case!(test_connection_no_type, "test-connection", "no-type");
case!(test_connection_ews_no_url, "test-connection", "ews-no-url");
case!(test_connection_ews_http, "test-connection", "ews-http");
case!(test_connection_ews_ip, "test-connection", "ews-ip");
case!(
    test_connection_m365_no_config,
    "test-connection",
    "m365-no-config"
);
case!(test_connection_case_keys, "test-connection", "case-keys");
case!(test_connection_bad_json, "test-connection", "bad-json");
case!(test_connection_typed, "test-connection", "typed");
case!(test_connection_empty_body, "test-connection", "empty-body");
case!(test_connection_array_body, "test-connection", "array-body");
case!(test_connection_repeat, "test-connection", "repeat");
case!(test_connection_foreign, "test-connection", "foreign");
case!(test_connection_denied, "test-connection", "denied");
case!(test_connection_wrong_perm, "test-connection", "wrong-perm");
case!(start_status_mutant, "start", "success-status-mutant");
case!(cancel_status_mutant, "cancel", "running-status-mutant");
case!(retry_status_mutant, "retry", "failed-status-mutant");
case!(pause_status_mutant, "pause", "running-status-mutant");
case!(resume_status_mutant, "resume", "paused-status-mutant");
case!(
    test_connection_status_mutant,
    "test-connection",
    "login-status-mutant"
);

case!(provider_ews_start_success, "start", "ews-success");
case!(provider_ews_start_repeat, "start", "ews-repeat");
case!(provider_ews_start_foreign, "start", "ews-foreign");
case!(provider_ews_start_invalid, "start", "ews-invalid");
case!(provider_ews_start_legacy, "start", "ews-legacy");
case!(
    provider_ews_test_connection_success,
    "test-connection",
    "ews-success"
);
case!(
    provider_ews_test_connection_repeat,
    "test-connection",
    "ews-repeat"
);
case!(
    provider_ews_test_connection_foreign,
    "test-connection",
    "ews-foreign"
);
case!(
    provider_ews_test_connection_invalid,
    "test-connection",
    "ews-invalid"
);
case!(
    provider_ews_test_connection_http_error,
    "test-connection",
    "ews-http-error"
);
case!(provider_ews_retry_success, "retry", "ews-success");
case!(provider_ews_retry_foreign, "retry", "ews-foreign");
case!(provider_ews_retry_invalid, "retry", "ews-invalid");
case!(provider_ews_cancel_success, "cancel", "ews-success");
case!(provider_ews_cancel_foreign, "cancel", "ews-foreign");
case!(provider_ews_cancel_invalid, "cancel", "ews-invalid");
case!(provider_ews_pause_success, "pause", "ews-success");
case!(provider_ews_pause_foreign, "pause", "ews-foreign");
case!(provider_ews_pause_invalid, "pause", "ews-invalid");
case!(provider_ews_resume_success, "resume", "ews-success");
case!(provider_ews_resume_foreign, "resume", "ews-foreign");
case!(provider_ews_resume_invalid, "resume", "ews-invalid");
case!(provider_m365_start_success, "start", "m365-success");
case!(provider_m365_start_repeat, "start", "m365-repeat");
case!(provider_m365_start_foreign, "start", "m365-foreign");
case!(provider_m365_start_invalid, "start", "m365-invalid");
case!(provider_m365_start_legacy, "start", "m365-legacy");
case!(
    provider_m365_test_connection_success,
    "test-connection",
    "m365-success"
);
case!(
    provider_m365_test_connection_repeat,
    "test-connection",
    "m365-repeat"
);
case!(
    provider_m365_test_connection_foreign,
    "test-connection",
    "m365-foreign"
);
case!(
    provider_m365_test_connection_invalid,
    "test-connection",
    "m365-invalid"
);
case!(
    provider_m365_test_connection_http_error,
    "test-connection",
    "m365-http-error"
);
case!(provider_m365_retry_success, "retry", "m365-success");
case!(provider_m365_retry_foreign, "retry", "m365-foreign");
case!(provider_m365_retry_invalid, "retry", "m365-invalid");
case!(provider_m365_cancel_success, "cancel", "m365-success");
case!(provider_m365_cancel_foreign, "cancel", "m365-foreign");
case!(provider_m365_cancel_invalid, "cancel", "m365-invalid");
case!(provider_m365_pause_success, "pause", "m365-success");
case!(provider_m365_pause_foreign, "pause", "m365-foreign");
case!(provider_m365_pause_invalid, "pause", "m365-invalid");
case!(provider_m365_resume_success, "resume", "m365-success");
case!(provider_m365_resume_foreign, "resume", "m365-foreign");
case!(provider_m365_resume_invalid, "resume", "m365-invalid");
case!(
    provider_m365_contact_failure,
    "start",
    "m365-contact-failure"
);
case!(provider_callback_success, "callback", "success");
case!(provider_callback_repeat, "callback", "repeat");
case!(provider_callback_foreign, "callback", "foreign");
case!(provider_callback_denied, "callback", "denied");
case!(provider_callback_wrong_perm, "callback", "wrong-perm");
case!(provider_callback_expired, "callback", "expired");
case!(provider_callback_fabricated, "callback", "fabricated");
case!(provider_callback_other_actor, "callback", "other-actor");
case!(
    provider_callback_verify_failure,
    "callback",
    "verify-failure"
);
case!(provider_callback_no_config, "callback", "no-config");
case!(provider_callback_bad_config, "callback", "bad-config");
case!(provider_callback_no_cookie, "callback", "no-cookie");
case!(provider_callback_mismatch, "callback", "mismatch");
case!(provider_callback_no_state, "callback", "no-state");
case!(
    provider_callback_denied_consent,
    "callback",
    "denied-consent"
);
case!(provider_callback_no_tenant, "callback", "no-tenant");
case!(provider_callback_description, "callback", "description");
case!(provider_callback_head, "callback", "head");

case!(provider_upload_ics_success, "resume", "upload-ics-success");
case!(provider_upload_vcf_success, "resume", "upload-vcf-success");
case!(provider_upload_ics_repeat, "resume", "upload-ics-repeat");
case!(provider_upload_vcf_repeat, "resume", "upload-vcf-repeat");
case!(provider_upload_ics_missing, "resume", "upload-ics-missing");
case!(provider_upload_vcf_missing, "resume", "upload-vcf-missing");
case!(
    provider_upload_ics_overwrite,
    "resume",
    "upload-ics-overwrite"
);
case!(
    provider_upload_vcf_overwrite,
    "resume",
    "upload-vcf-overwrite"
);
case!(provider_upload_ics_rename, "resume", "upload-ics-rename");
case!(provider_upload_vcf_rename, "resume", "upload-vcf-rename");
case!(
    provider_upload_compound_success,
    "resume",
    "upload-compound-success"
);
case!(provider_ews_contacts_only, "start", "ews-contacts-only");
case!(
    provider_callback_status_mutant,
    "callback",
    "success-status-mutant"
);

case!(
    provider_ews_test_connection_negotiate,
    "test-connection",
    "ews-negotiate"
);

case!(
    provider_m365_calendar_failure,
    "start",
    "m365-calendar-failure"
);
case!(provider_m365_china_start, "start", "m365-china");
case!(provider_ews_contacts_legacy, "start", "ews-contacts-legacy");
