//! F06 slice `quarantine`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("quarantine", $action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("quarantine", $action, $kind, Some($fault)).await
        }
    };
}

case!(user_list_success, "user-list", "success");
case!(user_list_foreign, "user-list", "foreign");
case!(user_list_limit, "user-list", "limit");
case!(user_list_offset, "user-list", "offset");
case!(user_list_clamp, "user-list", "clamp");
case!(user_list_bad_limit, "user-list", "bad-limit");
case!(user_list_negative_offset, "user-list", "negative-offset");
case!(user_list_zero_limit, "user-list", "zero-limit");
case!(user_list_ignored_query, "user-list", "ignored-query");
case!(
    user_list_status_mutant,
    "user-list",
    "success-status-mutant"
);

case!(user_count_success, "user-count", "success");
case!(user_count_foreign, "user-count", "foreign");
case!(user_count_ignored_query, "user-count", "ignored-query");
case!(
    user_count_status_mutant,
    "user-count",
    "success-status-mutant"
);

case!(user_release_success, "user-release", "success");
case!(user_release_foreign, "user-release", "foreign");
case!(user_release_bad_id, "user-release", "bad-id");
case!(user_release_already, "user-release", "already");
case!(user_release_missing, "user-release", "missing");
case!(user_release_repeat, "user-release", "repeat");
case!(
    user_release_status_mutant,
    "user-release",
    "success-status-mutant"
);

case!(user_reject_success, "user-reject", "success");
case!(user_reject_foreign, "user-reject", "foreign");
case!(user_reject_bad_id, "user-reject", "bad-id");
case!(user_reject_already, "user-reject", "already");
case!(user_reject_missing, "user-reject", "missing");
case!(user_reject_rejected_again, "user-reject", "rejected-again");
case!(user_reject_repeat, "user-reject", "repeat");
case!(
    user_reject_status_mutant,
    "user-reject",
    "success-status-mutant"
);

case!(admin_list_success, "admin-list", "success");
case!(admin_list_denied, "admin-list", "denied");
case!(admin_list_scoped, "admin-list", "scoped");
case!(admin_list_active, "admin-list", "active");
case!(admin_list_released, "admin-list", "released");
case!(admin_list_rejected, "admin-list", "rejected");
case!(admin_list_all, "admin-list", "all");
case!(admin_list_unknown_status, "admin-list", "unknown-status");
case!(admin_list_q_subject, "admin-list", "q-subject");
case!(admin_list_q_from, "admin-list", "q-from");
case!(admin_list_q_wild, "admin-list", "q-wild");
case!(admin_list_limit, "admin-list", "limit");
case!(admin_list_offset, "admin-list", "offset");
case!(admin_list_bad_limit, "admin-list", "bad-limit");
case!(admin_list_negative_offset, "admin-list", "negative-offset");
case!(admin_list_big_limit, "admin-list", "big-limit");
case!(
    admin_list_status_mutant,
    "admin-list",
    "success-status-mutant"
);

case!(admin_stats_success, "admin-stats", "success");
case!(admin_stats_denied, "admin-stats", "denied");
case!(admin_stats_scoped, "admin-stats", "scoped");
case!(admin_stats_ignored_query, "admin-stats", "ignored-query");
case!(
    admin_stats_status_mutant,
    "admin-stats",
    "success-status-mutant"
);

case!(admin_preview_success, "admin-preview", "success");
case!(admin_preview_denied, "admin-preview", "denied");
case!(admin_preview_scoped, "admin-preview", "scoped");
case!(admin_preview_bad_id, "admin-preview", "bad-id");
case!(admin_preview_missing, "admin-preview", "missing");
case!(admin_preview_no_html, "admin-preview", "no-html");
case!(
    admin_preview_status_mutant,
    "admin-preview",
    "success-status-mutant"
);

case!(admin_release_success, "admin-release", "success");
case!(admin_release_denied, "admin-release", "denied");
case!(admin_release_scoped, "admin-release", "scoped");
case!(admin_release_bad_id, "admin-release", "bad-id");
case!(admin_release_missing, "admin-release", "missing");
case!(admin_release_already, "admin-release", "already");
case!(admin_release_repeat, "admin-release", "repeat");
case!(
    admin_release_status_mutant,
    "admin-release",
    "success-status-mutant"
);

case!(admin_reject_success, "admin-reject", "success");
case!(admin_reject_denied, "admin-reject", "denied");
case!(admin_reject_scoped, "admin-reject", "scoped");
case!(admin_reject_bad_id, "admin-reject", "bad-id");
case!(admin_reject_missing, "admin-reject", "missing");
case!(admin_reject_already, "admin-reject", "already");
case!(admin_reject_repeat, "admin-reject", "repeat");
case!(
    admin_reject_status_mutant,
    "admin-reject",
    "success-status-mutant"
);

// Family mutants: each plants a real database fault the unchanged expectation must reject.
fault!(
    user_list_no_tenant_filter_fault,
    "user-list",
    "success",
    "no-tenant-filter"
);
fault!(
    user_release_no_notify_fault,
    "user-release",
    "success",
    "no-notify"
);
fault!(
    user_release_double_bump_fault,
    "user-release",
    "success",
    "double-bump"
);
fault!(
    admin_list_no_audit_fault,
    "admin-list",
    "denied",
    "no-audit"
);
