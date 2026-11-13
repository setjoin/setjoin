//! F08 slice `updates-deploy`, group `retired`: the legacy auto-update, maintenance-window
//! and gateway-upgrade routes Go answers with a typed 410, replayed without a Go upstream.
mod common;
mod platform_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            platform_oracle::updates::run($action, $kind, None).await
        }
    };
}

case!(auto_update_get_success, "retired-auto-update-get", "success");
case!(auto_update_get_denied, "retired-auto-update-get", "denied");
case!(auto_update_get_scoped, "retired-auto-update-get", "scoped");
case!(auto_update_get_ignored_query, "retired-auto-update-get", "ignored-query");
case!(auto_update_get_language, "retired-auto-update-get", "accept-language");
case!(auto_update_get_status_mutant, "retired-auto-update-get", "success-status-mutant");

case!(auto_update_put_success, "retired-auto-update-put", "success");
case!(auto_update_put_denied, "retired-auto-update-put", "denied");
case!(auto_update_put_body, "retired-auto-update-put", "body");
case!(auto_update_put_status_mutant, "retired-auto-update-put", "success-status-mutant");

case!(maintenance_get_success, "retired-maintenance-get", "success");
case!(maintenance_get_denied, "retired-maintenance-get", "denied");
case!(maintenance_get_ignored_query, "retired-maintenance-get", "ignored-query");
case!(maintenance_get_status_mutant, "retired-maintenance-get", "success-status-mutant");

case!(maintenance_put_success, "retired-maintenance-put", "success");
case!(maintenance_put_denied, "retired-maintenance-put", "denied");
case!(maintenance_put_body, "retired-maintenance-put", "body");
case!(maintenance_put_status_mutant, "retired-maintenance-put", "success-status-mutant");

case!(upgrade_check_success, "retired-upgrade-check", "success");
case!(upgrade_check_denied, "retired-upgrade-check", "denied");
case!(upgrade_check_body, "retired-upgrade-check", "body");
case!(upgrade_check_status_mutant, "retired-upgrade-check", "success-status-mutant");

case!(upgrade_apply_success, "retired-upgrade-apply", "success");
case!(upgrade_apply_denied, "retired-upgrade-apply", "denied");
case!(upgrade_apply_body, "retired-upgrade-apply", "body");
case!(upgrade_apply_status_mutant, "retired-upgrade-apply", "success-status-mutant");

case!(upgrade_rollback_success, "retired-upgrade-rollback", "success");
case!(upgrade_rollback_denied, "retired-upgrade-rollback", "denied");
case!(upgrade_rollback_body, "retired-upgrade-rollback", "body");
case!(upgrade_rollback_status_mutant, "retired-upgrade-rollback", "success-status-mutant");
