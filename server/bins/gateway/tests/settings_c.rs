//! F19 slice `settings-c`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod settings_oracle;
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            settings_oracle::run("settings-c", $action, $kind, Some($fault)).await
        }
    };
}
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            settings_oracle::run("settings-c", $action, $kind, None).await
        }
    };
}

case!(sessions_list_success, "sessions-list", "success");
case!(sessions_list_foreign, "sessions-list", "foreign");
case!(
    sessions_list_ignored_query,
    "sessions-list",
    "ignored-query"
);
case!(
    sessions_list_success_status_mutant,
    "sessions-list",
    "success-status-mutant"
);

case!(session_revoke_success, "session-revoke", "success");
case!(session_revoke_current, "session-revoke", "current");
case!(
    session_revoke_oauth_family,
    "session-revoke",
    "oauth-family"
);
case!(
    session_revoke_rotated_child,
    "session-revoke",
    "rotated-child"
);
case!(
    session_revoke_oauth_legacy,
    "session-revoke",
    "oauth-legacy"
);
case!(
    session_revoke_app_password,
    "session-revoke",
    "app-password"
);
case!(
    session_revoke_revoked_token,
    "session-revoke",
    "revoked-token"
);
case!(
    session_revoke_expired_token,
    "session-revoke",
    "expired-token"
);
case!(session_revoke_foreign, "session-revoke", "foreign");
case!(session_revoke_repeat, "session-revoke", "repeat");
case!(
    session_revoke_foreign_token,
    "session-revoke",
    "foreign-token"
);
case!(session_revoke_unknown, "session-revoke", "unknown");
case!(
    session_revoke_revoke_all_word,
    "session-revoke",
    "revoke-all-word"
);
case!(session_revoke_encoded, "session-revoke", "encoded");
case!(
    session_revoke_success_status_mutant,
    "session-revoke",
    "success-status-mutant"
);

case!(revoke_all_success, "sessions-revoke-all", "success");
case!(revoke_all_foreign, "sessions-revoke-all", "foreign");
case!(revoke_all_bad_body, "sessions-revoke-all", "bad-body");
case!(
    revoke_all_ignored_query,
    "sessions-revoke-all",
    "ignored-query"
);
case!(revoke_all_repeat, "sessions-revoke-all", "repeat");
case!(
    revoke_all_success_status_mutant,
    "sessions-revoke-all",
    "success-status-mutant"
);

case!(devices_list_success, "devices-list", "success");
case!(devices_list_foreign, "devices-list", "foreign");
case!(devices_list_ignored_query, "devices-list", "ignored-query");
case!(
    devices_list_success_status_mutant,
    "devices-list",
    "success-status-mutant"
);

case!(history_success, "login-history", "success");
case!(history_foreign, "login-history", "foreign");
case!(history_empty, "login-history", "empty");
case!(history_ignored_query, "login-history", "ignored-query");
case!(history_outcome_success, "login-history", "outcome-success");
case!(history_outcome_failed, "login-history", "outcome-failed");
case!(history_outcome_other, "login-history", "outcome-other");
case!(history_limit, "login-history", "limit");
case!(history_offset, "login-history", "offset");
case!(history_offset_past_end, "login-history", "offset-past-end");
case!(history_bad_limit, "login-history", "bad-limit");
case!(history_big_limit, "login-history", "big-limit");
case!(history_zero_limit, "login-history", "zero-limit");
case!(history_negative_offset, "login-history", "negative-offset");
case!(history_plus_limit, "login-history", "plus-limit");
case!(history_range_limit, "login-history", "range-limit");
case!(history_range_offset, "login-history", "range-offset");
case!(history_encoded_outcome, "login-history", "encoded-outcome");
case!(
    history_success_status_mutant,
    "login-history",
    "success-status-mutant"
);

case!(secure_success, "secure-account", "success");
case!(secure_foreign, "secure-account", "foreign");
case!(secure_bad_body, "secure-account", "bad-body");
case!(secure_ignored_query, "secure-account", "ignored-query");
case!(secure_repeat, "secure-account", "repeat");
case!(
    secure_success_status_mutant,
    "secure-account",
    "success-status-mutant"
);

case!(score_success, "security-score", "success");
case!(score_foreign, "security-score", "foreign");
case!(score_baseline, "security-score", "baseline");
case!(score_perfect, "security-score", "perfect");
case!(score_five, "security-score", "five");
case!(score_empty_codes, "security-score", "empty-codes");
case!(score_totp_only, "security-score", "totp-only");
case!(score_codes_only, "security-score", "codes-only");
case!(score_ignored_query, "security-score", "ignored-query");
case!(
    score_success_status_mutant,
    "security-score",
    "success-status-mutant"
);

// Family mutants: each plants a real database fault the unchanged expectation must reject.
fault!(
    session_revoke_no_audit_fault,
    "session-revoke",
    "success",
    "no-audit"
);
fault!(
    session_revoke_no_notify_fault,
    "session-revoke",
    "success",
    "no-notify"
);
