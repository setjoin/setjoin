//! F08 slice `terms-remaining`, group `setup`: the unauthenticated `GET /setup/status`
//! first-boot probe (#364), replayed without a Go upstream.
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

case!(status_empty_db, "setup-status", "empty-db");
case!(status_initialized, "setup-status", "initialized");
case!(status_count_fails, "setup-status", "count-fails");
case!(
    status_second_count_user,
    "setup-status",
    "second-count-user"
);
case!(
    status_second_count_fails,
    "setup-status",
    "second-count-fails"
);
case!(status_head, "setup-status", "head");
case!(status_head_empty_db, "setup-status", "head-empty-db");
case!(status_api_alias, "setup-status", "api-alias");
case!(
    status_api_alias_empty_db,
    "setup-status",
    "api-alias-empty-db"
);
case!(status_escaped, "setup-status", "escaped");
case!(status_escaped_empty_db, "setup-status", "escaped-empty-db");
case!(
    status_escaped_api_empty_db,
    "setup-status",
    "escaped-api-empty-db"
);
case!(status_ignored_query, "setup-status", "ignored-query");
case!(status_with_session, "setup-status", "with-session");
case!(status_post, "setup-status", "post");
case!(status_post_empty_db, "setup-status", "post-empty-db");
case!(status_trailing_slash, "setup-status", "trailing-slash");
case!(status_rate_limit, "setup-status", "rate-limit");
case!(
    status_initialized_status_mutant,
    "setup-status",
    "initialized-status-mutant"
);
