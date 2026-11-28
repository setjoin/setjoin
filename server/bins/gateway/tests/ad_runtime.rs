//! #381 AD runtime routes and `ad-sync` worker: frozen-Go oracle replayed without a Go upstream.
mod ad_oracle;
mod common;
macro_rules! case {
    ($name:ident, $route:literal, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ad_oracle::run($route, $case, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $route:literal, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ad_oracle::run($route, $case, Some("changed-status")).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $route:literal, $case:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ad_oracle::run($route, $case, Some($fault)).await
        }
    };
}
macro_rules! worker {
    ($name:ident, $route:literal, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ad_oracle::run_worker($route, $case).await
        }
    };
}
case!(test_success, "test", "success");
case!(test_foreign, "test", "foreign");
case!(test_invalid, "test", "invalid");
case!(test_bad_password, "test", "bad-password");
case!(test_unreachable, "test", "unreachable");
case!(test_search_failure, "test", "search-failure");
case!(test_srv, "test", "srv");
case!(test_srv_missing, "test", "srv-missing");
case!(test_disabled, "test", "disabled");
case!(test_bad_uac, "test", "bad-uac");
case!(sync_success, "sync", "success");
case!(sync_blocked, "sync", "blocked");
case!(sync_foreign, "sync", "foreign");
case!(sync_invalid, "sync", "invalid");
case!(sync_repeat, "sync", "repeat");
case!(sync_search_failure, "sync", "search-failure");
case!(sync_bad_password, "sync", "bad-password");
case!(sync_unreachable, "sync", "unreachable");
case!(sync_incremental, "sync", "incremental");
case!(sync_quarantine, "sync", "quarantine");
case!(sync_duplicate, "sync", "duplicate");
case!(sync_source_paused, "sync", "source-paused");
case!(sync_bad_uac, "sync", "bad-uac");
case!(sync_bad_cursor, "sync", "bad-cursor");
case!(sync_srv, "sync", "srv");
case!(sync_disabled, "sync", "disabled");
case!(health_success, "health", "success");
case!(health_foreign, "health", "foreign");
case!(health_invalid, "health", "invalid");
case!(health_error, "health", "error");
case!(health_disabled, "health", "disabled");
case!(config_put_success, "config", "put-success");
case!(config_put_repeat, "config", "put-repeat");
case!(config_put_foreign, "config", "put-foreign");
case!(config_put_invalid, "config", "put-invalid");
case!(config_put_bad_json, "config", "put-bad-json");
case!(config_put_foreign_key, "config", "put-foreign-key");
case!(config_put_preserve, "config", "put-preserve");
case!(config_put_absent_secret, "config", "put-absent-secret");
case!(config_put_null, "config", "put-null");
case!(config_put_trailing, "config", "put-trailing");
case!(config_put_no_domain, "config", "put-no-domain");
case!(config_put_srv, "config", "put-srv");
case!(config_put_srv_failure, "config", "put-srv-failure");
case!(config_put_disabled, "config", "put-disabled");
mutant!(test_success_status_mutant, "test", "success");
mutant!(sync_success_status_mutant, "sync", "success");
mutant!(health_success_status_mutant, "health", "success");
mutant!(config_put_success_status_mutant, "config", "put-success");
worker!(worker_replays_sync_success, "sync", "success");
worker!(worker_replays_sync_incremental, "sync", "incremental");
worker!(worker_replays_sync_quarantine, "sync", "quarantine");
fault!(sync_drop_links_mutant, "sync", "success", "drop-links");
fault!(sync_touch_users_mutant, "sync", "success", "touch-users");
fault!(sync_skip_disable_mutant, "sync", "success", "skip-disable");
