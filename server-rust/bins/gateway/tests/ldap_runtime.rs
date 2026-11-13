//! #380 LDAP runtime routes and `ldap-sync` worker: frozen-Go oracle replayed without a Go upstream.
mod common;
mod ldap_oracle;
macro_rules! case {
    ($name:ident, $route:literal, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ldap_oracle::run($route, $case, None).await
        }
    };
}
macro_rules! mutant {
    ($name:ident, $route:literal, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ldap_oracle::run($route, $case, Some("changed-status")).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $route:literal, $case:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ldap_oracle::run($route, $case, Some($fault)).await
        }
    };
}
macro_rules! worker {
    ($name:ident, $route:literal, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ldap_oracle::run_worker($route, $case).await
        }
    };
}
case!(test_success, "test", "success");
case!(test_foreign, "test", "foreign");
case!(test_invalid, "test", "invalid");
case!(test_bad_password, "test", "bad-password");
case!(test_unreachable, "test", "unreachable");
case!(test_search_failure, "test", "search-failure");
case!(test_starttls, "test", "starttls");
case!(preview_success, "preview", "success");
case!(preview_limit, "preview", "limit");
case!(preview_foreign, "preview", "foreign");
case!(preview_invalid, "preview", "invalid");
case!(preview_empty, "preview", "empty");
case!(preview_bad_password, "preview", "bad-password");
case!(sync_success, "sync", "success");
case!(sync_foreign, "sync", "foreign");
case!(sync_invalid, "sync", "invalid");
case!(sync_unconfigured, "sync", "unconfigured");
case!(sync_search_failure, "sync", "search-failure");
case!(sync_bad_password, "sync", "bad-password");
case!(sync_no_dept, "sync", "no-dept");
case!(sync_incremental, "sync", "incremental");
case!(sync_sweep_due, "sync", "sweep-due");
case!(sync_sweep_fresh, "sync", "sweep-fresh");
case!(sync_filtered, "sync", "filtered");
case!(sync_paged, "sync", "paged");
case!(sync_normalized, "sync", "normalized");
case!(sync_normalized_duplicate, "sync", "normalized-duplicate");
case!(sync_normalized_blocked, "sync", "normalized-blocked");
case!(health_success, "health", "success");
case!(health_foreign, "health", "foreign");
case!(health_invalid, "health", "invalid");
case!(health_error, "health", "error");
case!(config_put_success, "config", "put-success");
case!(config_put_foreign, "config", "put-foreign");
case!(config_put_invalid, "config", "put-invalid");
case!(config_put_bad_json, "config", "put-bad-json");
case!(config_put_foreign_key, "config", "put-foreign-key");
case!(config_put_bad_filter, "config", "put-bad-filter");
case!(config_put_bad_bool, "config", "put-bad-bool");
case!(config_put_preserve, "config", "put-preserve");
case!(config_put_absent_secret, "config", "put-absent-secret");
case!(config_put_null, "config", "put-null");
case!(config_put_trailing, "config", "put-trailing");
case!(preview_unconfigured, "preview", "unconfigured");
case!(sync_repeat, "sync", "repeat");
case!(config_put_repeat, "config", "put-repeat");
mutant!(test_success_status_mutant, "test", "success");
mutant!(preview_success_status_mutant, "preview", "success");
mutant!(sync_success_status_mutant, "sync", "success");
mutant!(health_success_status_mutant, "health", "success");
mutant!(config_put_success_status_mutant, "config", "put-success");
worker!(worker_replays_sync_success, "sync", "success");
worker!(worker_replays_sync_normalized, "sync", "normalized");
worker!(worker_replays_sync_sweep_due, "sync", "sweep-due");
fault!(
    sync_drop_conflicts_mutant,
    "sync",
    "success",
    "drop-conflicts"
);
fault!(sync_touch_users_mutant, "sync", "success", "touch-users");
fault!(sync_skip_disable_mutant, "sync", "success", "skip-disable");
