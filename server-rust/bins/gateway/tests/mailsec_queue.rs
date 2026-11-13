//! F06 slice `queue`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("queue", $action, $kind, None).await
        }
    };
}

case!(summary_success, "summary", "success");
case!(summary_empty, "summary", "empty");
case!(summary_denied, "summary", "denied");
case!(summary_scoped, "summary", "scoped");
case!(summary_ignored_query, "summary", "ignored-query");
case!(summary_status_mutant, "summary", "success-status-mutant");

case!(list_success, "list", "success");
case!(list_empty, "list", "empty");
case!(list_denied, "list", "denied");
case!(list_scoped, "list", "scoped");
case!(list_pending, "list", "pending");
case!(list_deferred, "list", "deferred");
case!(list_bounced, "list", "bounced");
case!(list_sending, "list", "sending");
case!(list_delivered, "list", "delivered");
case!(list_failed, "list", "failed");
case!(list_held, "list", "held");
case!(list_all, "list", "all");
case!(list_unknown_status, "list", "unknown-status");
case!(list_limit, "list", "limit");
case!(list_offset, "list", "offset");
case!(list_bad_limit, "list", "bad-limit");
case!(list_negative_offset, "list", "negative-offset");
case!(list_big_limit, "list", "big-limit");
case!(list_zero_limit, "list", "zero-limit");
case!(list_max_limit, "list", "max-limit");
case!(list_status_limit, "list", "status-limit");
case!(list_ignored_query, "list", "ignored-query");
case!(list_status_mutant, "list", "success-status-mutant");

case!(retry_success, "retry", "success");
case!(retry_pending, "retry", "pending");
case!(retry_already, "retry", "already");
case!(retry_sending, "retry", "sending");
case!(retry_bounced, "retry", "bounced");
case!(retry_missing, "retry", "missing");
case!(retry_bad_id, "retry", "bad-id");
case!(retry_denied, "retry", "denied");
case!(retry_scoped, "retry", "scoped");
case!(retry_repeat, "retry", "repeat");
case!(retry_status_mutant, "retry", "success-status-mutant");

case!(bounce_success, "bounce", "success");
case!(bounce_deferred, "bounce", "deferred");
case!(bounce_delivered, "bounce", "delivered");
case!(bounce_bounced_again, "bounce", "bounced-again");
case!(bounce_missing, "bounce", "missing");
case!(bounce_bad_id, "bounce", "bad-id");
case!(bounce_denied, "bounce", "denied");
case!(bounce_scoped, "bounce", "scoped");
case!(bounce_repeat, "bounce", "repeat");
case!(bounce_status_mutant, "bounce", "success-status-mutant");
