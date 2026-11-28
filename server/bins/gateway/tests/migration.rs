//! F05 slice `migration` frozen-Go oracle, replayed without a Go upstream.
mod common;
mod migration_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            migration_oracle::run($action, $kind).await
        }
    };
}

case!(jobs_success, "jobs", "success");
case!(jobs_status, "jobs", "status");
case!(jobs_user, "jobs", "user");
case!(jobs_both, "jobs", "both");
case!(jobs_empty, "jobs", "empty");
case!(jobs_invalid, "jobs", "invalid");
case!(jobs_spaced, "jobs", "spaced");
case!(jobs_plus, "jobs", "plus");
case!(jobs_head, "jobs", "head");
case!(jobs_foreign, "jobs", "foreign");
case!(jobs_denied, "jobs", "denied");
case!(jobs_wrong_perm, "jobs", "wrong-perm");
case!(job_get_success, "job-get", "success");
case!(job_get_failed, "job-get", "failed");
case!(job_get_cancelled, "job-get", "cancelled");
case!(job_get_invalid, "job-get", "invalid");
case!(job_get_plus, "job-get", "plus");
case!(job_get_huge, "job-get", "huge");
case!(job_get_missing, "job-get", "missing");
case!(job_get_zero, "job-get", "zero");
case!(job_get_negative, "job-get", "negative");
case!(job_get_head, "job-get", "head");
case!(job_get_foreign, "job-get", "foreign");
case!(job_get_denied, "job-get", "denied");
case!(job_get_wrong_perm, "job-get", "wrong-perm");
case!(job_delete_success, "job-delete", "success");
case!(job_delete_repeat, "job-delete", "repeat");
case!(job_delete_other, "job-delete", "other");
case!(job_delete_invalid, "job-delete", "invalid");
case!(job_delete_missing, "job-delete", "missing");
case!(job_delete_foreign, "job-delete", "foreign");
case!(job_delete_denied, "job-delete", "denied");
case!(job_delete_wrong_perm, "job-delete", "wrong-perm");
case!(source_get_success, "source-get", "success");
case!(source_get_ews, "source-get", "ews");
case!(source_get_m365, "source-get", "m365");
case!(source_get_imap_missing, "source-get", "imap-missing");
case!(source_get_ews_missing, "source-get", "ews-missing");
case!(source_get_m365_missing, "source-get", "m365-missing");
case!(source_get_ews_plain, "source-get", "ews-plain");
case!(source_get_ews_garbage, "source-get", "ews-garbage");
case!(source_get_ews_wrapper, "source-get", "ews-wrapper");
case!(source_get_ews_array, "source-get", "ews-array");
case!(source_get_ews_base64, "source-get", "ews-base64");
case!(source_get_ews_null, "source-get", "ews-null");
case!(source_get_ews_fields, "source-get", "ews-fields");
case!(source_get_m365_fields, "source-get", "m365-fields");
case!(source_get_m365_folded, "source-get", "m365-folded");
case!(source_get_imap_sealed, "source-get", "imap-sealed");
case!(source_get_invalid, "source-get", "invalid");
case!(source_get_foreign, "source-get", "foreign");
case!(source_get_denied, "source-get", "denied");
case!(source_get_wrong_perm, "source-get", "wrong-perm");
case!(source_delete_success, "source-delete", "success");
case!(source_delete_repeat, "source-delete", "repeat");
case!(source_delete_ews, "source-delete", "ews");
case!(source_delete_m365, "source-delete", "m365");
case!(source_delete_missing, "source-delete", "missing");
case!(source_delete_others_stay, "source-delete", "others-stay");
case!(source_delete_invalid, "source-delete", "invalid");
case!(source_delete_foreign, "source-delete", "foreign");
case!(source_delete_denied, "source-delete", "denied");
case!(source_delete_wrong_perm, "source-delete", "wrong-perm");
case!(put_imap_success, "put-imap", "success");
case!(put_imap_defaults, "put-imap", "defaults");
case!(put_imap_ssl, "put-imap", "ssl");
case!(put_imap_starttls, "put-imap", "starttls");
case!(put_imap_none, "put-imap", "none");
case!(put_imap_policy, "put-imap", "policy");
case!(put_imap_overwrite, "put-imap", "overwrite");
case!(put_imap_overwrite_sealed, "put-imap", "overwrite-sealed");
case!(put_imap_repeat, "put-imap", "repeat");
case!(put_imap_escape, "put-imap", "escape");
case!(put_imap_no_host, "put-imap", "no-host");
case!(put_imap_bad_tls, "put-imap", "bad-tls");
case!(put_imap_policy_half, "put-imap", "policy-half");
case!(put_imap_policy_cidr_half, "put-imap", "policy-cidr-half");
case!(put_imap_policy_bad_host, "put-imap", "policy-bad-host");
case!(put_imap_policy_slash_host, "put-imap", "policy-slash-host");
case!(put_imap_policy_bad_cidr, "put-imap", "policy-bad-cidr");
case!(
    put_imap_policy_public_cidr,
    "put-imap",
    "policy-public-cidr"
);
case!(put_imap_policy_wide_cidr, "put-imap", "policy-wide-cidr");
case!(put_imap_policy_empty, "put-imap", "policy-empty");
case!(
    put_imap_policy_null_element,
    "put-imap",
    "policy-null-element"
);
case!(put_imap_bad_json, "put-imap", "bad-json");
case!(put_imap_invalid, "put-imap", "invalid");
case!(put_imap_typed, "put-imap", "typed");
case!(put_imap_float_port, "put-imap", "float-port");
case!(put_imap_null_fields, "put-imap", "null-fields");
case!(put_imap_case_keys, "put-imap", "case-keys");
case!(put_imap_unknown_keys, "put-imap", "unknown-keys");
case!(put_imap_trailing, "put-imap", "trailing");
case!(put_imap_empty_body, "put-imap", "empty-body");
case!(put_imap_array, "put-imap", "array");
case!(put_imap_null_body, "put-imap", "null-body");
case!(put_imap_foreign, "put-imap", "foreign");
case!(put_imap_denied, "put-imap", "denied");
case!(put_imap_wrong_perm, "put-imap", "wrong-perm");
case!(put_ews_success, "put-ews", "success");
case!(put_ews_defaults, "put-ews", "defaults");
case!(put_ews_policy, "put-ews", "policy");
case!(put_ews_overwrite, "put-ews", "overwrite");
case!(put_ews_overwrite_plain, "put-ews", "overwrite-plain");
case!(put_ews_repeat, "put-ews", "repeat");
case!(put_ews_no_url, "put-ews", "no-url");
case!(put_ews_no_user, "put-ews", "no-user");
case!(put_ews_http, "put-ews", "http");
case!(put_ews_no_scheme, "put-ews", "no-scheme");
case!(put_ews_ip, "put-ews", "ip");
case!(put_ews_public_ip, "put-ews", "public-ip");
case!(put_ews_loopback, "put-ews", "loopback");
case!(put_ews_ipv6, "put-ews", "ipv6");
case!(put_ews_local, "put-ews", "local");
case!(put_ews_userinfo, "put-ews", "userinfo");
case!(put_ews_bad_port, "put-ews", "bad-port");
case!(put_ews_space_host, "put-ews", "space-host");
case!(put_ews_upper_scheme, "put-ews", "upper-scheme");
case!(put_ews_escaped_host, "put-ews", "escaped-host");
case!(put_ews_bad_escape, "put-ews", "bad-escape");
case!(put_ews_control, "put-ews", "control");
case!(put_ews_empty_host, "put-ews", "empty-host");
case!(put_ews_policy_half, "put-ews", "policy-half");
case!(put_ews_policy_bad_cidr, "put-ews", "policy-bad-cidr");
case!(put_ews_escape, "put-ews", "escape");
case!(put_ews_bad_json, "put-ews", "bad-json");
case!(put_ews_invalid, "put-ews", "invalid");
case!(put_ews_typed, "put-ews", "typed");
case!(put_ews_typed_bool, "put-ews", "typed-bool");
case!(put_ews_null_fields, "put-ews", "null-fields");
case!(put_ews_case_keys, "put-ews", "case-keys");
case!(put_ews_empty_body, "put-ews", "empty-body");
case!(put_ews_foreign, "put-ews", "foreign");
case!(put_ews_denied, "put-ews", "denied");
case!(put_ews_wrong_perm, "put-ews", "wrong-perm");
case!(put_m365_success, "put-m365", "success");
case!(put_m365_minimal, "put-m365", "minimal");
case!(put_m365_extras, "put-m365", "extras");
case!(put_m365_overwrite, "put-m365", "overwrite");
case!(put_m365_repeat, "put-m365", "repeat");
case!(put_m365_no_client, "put-m365", "no-client");
case!(put_m365_no_secret, "put-m365", "no-secret");
case!(put_m365_escape, "put-m365", "escape");
case!(put_m365_bad_json, "put-m365", "bad-json");
case!(put_m365_invalid, "put-m365", "invalid");
case!(put_m365_typed, "put-m365", "typed");
case!(put_m365_null_fields, "put-m365", "null-fields");
case!(put_m365_case_keys, "put-m365", "case-keys");
case!(put_m365_unknown_keys, "put-m365", "unknown-keys");
case!(put_m365_foreign, "put-m365", "foreign");
case!(put_m365_denied, "put-m365", "denied");
case!(put_m365_wrong_perm, "put-m365", "wrong-perm");
case!(m365_connect_success, "m365-connect", "success");
case!(m365_connect_china, "m365-connect", "china");
case!(m365_connect_global, "m365-connect", "global");
case!(m365_connect_empty_cloud, "m365-connect", "empty-cloud");
case!(m365_connect_invalid, "m365-connect", "invalid");
case!(m365_connect_no_config, "m365-connect", "no-config");
case!(m365_connect_plain, "m365-connect", "plain");
case!(m365_connect_bad_wrapper, "m365-connect", "bad-wrapper");
case!(m365_connect_bad_base64, "m365-connect", "bad-base64");
case!(m365_connect_bad_cipher, "m365-connect", "bad-cipher");
case!(m365_connect_bad_fields, "m365-connect", "bad-fields");
case!(
    m365_connect_escape_client_id,
    "m365-connect",
    "escape-client-id"
);
case!(m365_connect_stale, "m365-connect", "stale");
case!(m365_connect_head, "m365-connect", "head");
case!(m365_connect_foreign, "m365-connect", "foreign");
case!(m365_connect_denied, "m365-connect", "denied");
case!(m365_connect_wrong_perm, "m365-connect", "wrong-perm");
case!(jobs_status_mutant, "jobs", "success-status-mutant");
case!(job_get_status_mutant, "job-get", "success-status-mutant");
case!(
    job_delete_status_mutant,
    "job-delete",
    "success-status-mutant"
);
case!(
    source_get_status_mutant,
    "source-get",
    "success-status-mutant"
);
case!(
    source_delete_status_mutant,
    "source-delete",
    "success-status-mutant"
);
case!(put_imap_status_mutant, "put-imap", "success-status-mutant");
case!(put_ews_status_mutant, "put-ews", "success-status-mutant");
case!(put_m365_status_mutant, "put-m365", "success-status-mutant");
case!(
    m365_connect_status_mutant,
    "m365-connect",
    "success-status-mutant"
);
