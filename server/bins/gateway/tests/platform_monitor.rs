//! F08 slice `terms-remaining`, group `monitor`: the live counters and the mail-flow summary,
//! replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::terms::run($action, $kind, None).await
        }
    };
}

case!(live_success, "monitor-live", "success");
case!(live_denied, "monitor-live", "denied");
case!(live_scoped, "monitor-live", "scoped");
case!(live_empty_db, "monitor-live", "empty-db");
case!(live_sections_dmarc, "monitor-live", "sections-dmarc");
case!(live_sections_queue, "monitor-live", "sections-queue");
case!(
    live_sections_quarantine,
    "monitor-live",
    "sections-quarantine"
);
case!(live_sections_volume, "monitor-live", "sections-volume");
case!(live_sections_threats, "monitor-live", "sections-threats");
case!(live_sections_system, "monitor-live", "sections-system");
case!(live_sections_two, "monitor-live", "sections-two");
case!(
    live_sections_substring,
    "monitor-live",
    "sections-substring"
);
case!(live_sections_unknown, "monitor-live", "sections-unknown");
case!(live_sections_case, "monitor-live", "sections-case");
case!(live_sections_empty, "monitor-live", "sections-empty");
case!(live_sections_repeated, "monitor-live", "sections-repeated");
case!(live_ignored_query, "monitor-live", "ignored-query");

case!(summary_success, "reports-summary", "success");
case!(summary_denied, "reports-summary", "denied");
case!(summary_scoped, "reports-summary", "scoped");
case!(summary_empty, "reports-summary", "empty");
case!(summary_days_1, "reports-summary", "days-1");
case!(summary_days_2, "reports-summary", "days-2");
case!(summary_days_3, "reports-summary", "days-3");
case!(summary_days_90, "reports-summary", "days-90");
case!(summary_days_91, "reports-summary", "days-91");
case!(summary_days_0, "reports-summary", "days-0");
case!(summary_days_negative, "reports-summary", "days-negative");
case!(summary_days_bad, "reports-summary", "days-bad");
case!(summary_days_float, "reports-summary", "days-float");
case!(summary_days_plus, "reports-summary", "days-plus");
case!(summary_days_padded, "reports-summary", "days-padded");
case!(summary_days_huge, "reports-summary", "days-huge");
case!(summary_days_empty, "reports-summary", "days-empty");
case!(summary_days_space, "reports-summary", "days-space");
case!(summary_days_repeated, "reports-summary", "days-repeated");
case!(summary_ignored_query, "reports-summary", "ignored-query");

case!(live_status_mutant, "monitor-live", "success-status-mutant");
case!(
    summary_status_mutant,
    "reports-summary",
    "success-status-mutant"
);
