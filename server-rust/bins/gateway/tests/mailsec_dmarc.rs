//! F06 slice `dmarc`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("dmarc", $action, $kind, None).await
        }
    };
}

case!(live_success, "live", "success");
case!(live_empty, "live", "empty");
case!(live_denied, "live", "denied");
case!(live_scoped, "live", "scoped");
case!(live_ignored_query, "live", "ignored-query");
case!(live_status_mutant, "live", "success-status-mutant");

case!(failures_success, "failures", "success");
case!(failures_empty, "failures", "empty");
case!(failures_denied, "failures", "denied");
case!(failures_scoped, "failures", "scoped");
case!(failures_limit, "failures", "limit");
case!(failures_bad_limit, "failures", "bad-limit");
case!(failures_big_limit, "failures", "big-limit");
case!(failures_zero_limit, "failures", "zero-limit");
case!(failures_negative_limit, "failures", "negative-limit");
case!(failures_status_mutant, "failures", "success-status-mutant");

case!(trend_success, "trend", "success");
case!(trend_empty, "trend", "empty");
case!(trend_denied, "trend", "denied");
case!(trend_scoped, "trend", "scoped");
case!(trend_ignored_query, "trend", "ignored-query");
case!(trend_status_mutant, "trend", "success-status-mutant");

case!(auth_log_success, "auth-log", "success");
case!(auth_log_empty, "auth-log", "empty");
case!(auth_log_denied, "auth-log", "denied");
case!(auth_log_scoped, "auth-log", "scoped");
case!(auth_log_provider, "auth-log", "provider");
case!(auth_log_event, "auth-log", "event");
case!(auth_log_provider_all, "auth-log", "provider-all");
case!(auth_log_since, "auth-log", "since");
case!(auth_log_bad_since, "auth-log", "bad-since");
case!(auth_log_email, "auth-log", "email");
case!(auth_log_email_like, "auth-log", "email-like");
case!(auth_log_limit, "auth-log", "limit");
case!(auth_log_zero_limit, "auth-log", "zero-limit");
case!(auth_log_bad_limit, "auth-log", "bad-limit");
case!(auth_log_negative_limit, "auth-log", "negative-limit");
case!(auth_log_combined, "auth-log", "combined");
case!(auth_log_no_match, "auth-log", "no-match");
case!(auth_log_status_mutant, "auth-log", "success-status-mutant");
