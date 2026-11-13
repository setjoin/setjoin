//! Frozen Go CardDAV oracle: real front door, assigned disposable DB, no Go in replay.
mod carddav_oracle;
mod common;
#[tokio::test]
async fn options_success() -> Result<(), common::BoxError> {
    carddav_oracle::run("options", "success", None).await
}

#[tokio::test]
async fn propfind_success() -> Result<(), common::BoxError> {
    carddav_oracle::run("propfind", "success", None).await
}

#[tokio::test]
async fn get_success() -> Result<(), common::BoxError> {
    carddav_oracle::run("get", "success", None).await
}

#[tokio::test]
async fn propfind_members() -> Result<(), common::BoxError> {
    carddav_oracle::run("propfind", "members", None).await
}

#[tokio::test]
async fn reports_success() -> Result<(), common::BoxError> {
    for kind in ["query", "multiget", "sync"] {
        carddav_oracle::run(kind, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn writes_success() -> Result<(), common::BoxError> {
    for kind in ["put", "put-update", "delete"] {
        carddav_oracle::run(kind, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn gal_success() -> Result<(), common::BoxError> {
    for kind in [
        "gal-options",
        "gal-propfind",
        "gal-get",
        "gal-query",
        "gal-multiget",
        "gal-sync",
        "gal-put",
        "gal-delete",
    ] {
        carddav_oracle::run(kind, "success", None).await?;
    }
    Ok(())
}

macro_rules! case {
    ($name:ident,$route:literal,$label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            carddav_oracle::run($route, $label, None).await
        }
    };
}
case!(
    qualification_options_cross_tenant,
    "options",
    "cross-tenant"
);
case!(
    qualification_options_invalid_input,
    "options",
    "invalid-input"
);
case!(
    qualification_propfind_cross_tenant,
    "propfind",
    "cross-tenant"
);
case!(
    qualification_propfind_invalid_input,
    "propfind",
    "invalid-input"
);
case!(qualification_get_cross_tenant, "get", "cross-tenant");
case!(qualification_get_invalid_input, "get", "invalid-input");
case!(qualification_query_cross_tenant, "query", "cross-tenant");
case!(qualification_query_invalid_input, "query", "invalid-input");
case!(
    qualification_multiget_cross_tenant,
    "multiget",
    "cross-tenant"
);
case!(
    qualification_multiget_invalid_input,
    "multiget",
    "invalid-input"
);
case!(qualification_sync_cross_tenant, "sync", "cross-tenant");
case!(qualification_sync_invalid_input, "sync", "invalid-input");
case!(qualification_put_cross_tenant, "put", "cross-tenant");
case!(qualification_put_invalid_input, "put", "invalid-input");
case!(
    qualification_put_update_cross_tenant,
    "put-update",
    "cross-tenant"
);
case!(
    qualification_put_update_invalid_input,
    "put-update",
    "invalid-input"
);
case!(qualification_delete_cross_tenant, "delete", "cross-tenant");
case!(
    qualification_delete_invalid_input,
    "delete",
    "invalid-input"
);
case!(
    qualification_unsupported_cross_tenant,
    "unsupported",
    "cross-tenant"
);
case!(
    qualification_unsupported_invalid_input,
    "unsupported",
    "invalid-input"
);
case!(qualification_unsupported_success, "unsupported", "success");
case!(
    qualification_gal_options_cross_tenant,
    "gal-options",
    "cross-tenant"
);
case!(
    qualification_gal_options_invalid_input,
    "gal-options",
    "invalid-input"
);
case!(
    qualification_gal_propfind_cross_tenant,
    "gal-propfind",
    "cross-tenant"
);
case!(
    qualification_gal_propfind_invalid_input,
    "gal-propfind",
    "invalid-input"
);
case!(
    qualification_gal_get_cross_tenant,
    "gal-get",
    "cross-tenant"
);
case!(
    qualification_gal_get_invalid_input,
    "gal-get",
    "invalid-input"
);
case!(
    qualification_gal_query_cross_tenant,
    "gal-query",
    "cross-tenant"
);
case!(
    qualification_gal_query_invalid_input,
    "gal-query",
    "invalid-input"
);
case!(
    qualification_gal_multiget_cross_tenant,
    "gal-multiget",
    "cross-tenant"
);
case!(
    qualification_gal_multiget_invalid_input,
    "gal-multiget",
    "invalid-input"
);
case!(
    qualification_gal_sync_cross_tenant,
    "gal-sync",
    "cross-tenant"
);
case!(
    qualification_gal_sync_invalid_input,
    "gal-sync",
    "invalid-input"
);
case!(
    qualification_gal_put_cross_tenant,
    "gal-put",
    "cross-tenant"
);
case!(
    qualification_gal_put_invalid_input,
    "gal-put",
    "invalid-input"
);
case!(
    qualification_gal_delete_cross_tenant,
    "gal-delete",
    "cross-tenant"
);
case!(
    qualification_gal_delete_invalid_input,
    "gal-delete",
    "invalid-input"
);
case!(
    qualification_entitlement_cross_tenant,
    "entitlement",
    "cross-tenant"
);
case!(
    qualification_entitlement_invalid_input,
    "entitlement",
    "invalid-input"
);
case!(qualification_entitlement_success, "entitlement", "success");
case!(edge_put_repeat, "put", "repeat");
case!(edge_put_update_repeat, "put-update", "repeat");
case!(edge_delete_repeat, "delete", "repeat");
case!(edge_gal_propfind_repeat, "gal-propfind", "repeat");
case!(edge_gal_get_repeat, "gal-get", "repeat");
case!(edge_gal_query_repeat, "gal-query", "repeat");
case!(edge_gal_multiget_repeat, "gal-multiget", "repeat");
case!(edge_gal_sync_repeat, "gal-sync", "repeat");
case!(edge_gal_put_repeat, "gal-put", "repeat");
case!(edge_gal_delete_repeat, "gal-delete", "repeat");
case!(edge_propfind_properties, "propfind", "properties");
case!(edge_propfind_resource, "propfind", "resource");
case!(edge_propfind_depth0, "propfind", "depth0");
case!(edge_propfind_limit, "propfind", "limit");
case!(edge_propfind_gal_off, "propfind", "gal-off");
case!(edge_get_fold, "get", "fold");
case!(edge_get_encoded, "get", "encoded");
case!(edge_query_filter, "query", "filter");
case!(edge_query_no_match, "query", "no-match");
case!(edge_query_unknown, "query", "unknown");
case!(edge_query_wrong_namespace, "query", "wrong-namespace");
case!(edge_query_limit, "query", "limit");
case!(edge_multiget_uid_collision, "multiget", "uid-collision");
case!(edge_sync_current, "sync", "current");
case!(edge_sync_removed, "sync", "removed");
case!(edge_sync_updated, "sync", "updated");
case!(edge_sync_pruned, "sync", "pruned");
case!(edge_sync_resync, "sync", "resync");
case!(edge_sync_future, "sync", "future");
case!(edge_put_if_none, "put", "if-none");
case!(edge_put_if_match_missing, "put", "if-match-missing");
case!(edge_put_bad_path, "put", "bad-path");
case!(edge_put_limit, "put", "limit");
case!(edge_put_vcard4, "put", "vcard4");
case!(edge_put_photo, "put", "photo");
case!(edge_put_update_if_match, "put-update", "if-match");
case!(edge_put_update_if_match_good, "put-update", "if-match-good");
case!(edge_delete_if_match, "delete", "if-match");
case!(edge_delete_if_match_good, "delete", "if-match-good");
case!(edge_delete_bad_path, "delete", "bad-path");
case!(edge_unsupported_head, "unsupported", "head");
case!(edge_unsupported_mkcol, "unsupported", "mkcol");
case!(edge_unsupported_proppatch, "unsupported", "proppatch");
case!(edge_unsupported_copy, "unsupported", "copy");
case!(edge_unsupported_move, "unsupported", "move");
case!(edge_unsupported_lock, "unsupported", "lock");
case!(edge_unsupported_unlock, "unsupported", "unlock");
case!(edge_gal_get_disabled, "gal-get", "disabled");
case!(edge_gal_get_hidden, "gal-get", "hidden");
case!(edge_gal_get_guest, "gal-get", "guest");
case!(edge_gal_get_gal_off, "gal-get", "gal-off");
case!(edge_gal_get_full_profile, "gal-get", "full-profile");
case!(edge_gal_propfind_properties, "gal-propfind", "properties");
case!(edge_gal_propfind_depth0, "gal-propfind", "depth0");
case!(edge_gal_propfind_gal_off, "gal-propfind", "gal-off");
case!(edge_gal_propfind_limit, "gal-propfind", "limit");
case!(edge_gal_query_alias_filter, "gal-query", "alias-filter");
case!(edge_gal_query_hidden_manager, "gal-query", "hidden-manager");
case!(edge_gal_query_guest, "gal-query", "guest");
case!(edge_gal_query_gal_off, "gal-query", "gal-off");
case!(edge_gal_multiget_gal_off, "gal-multiget", "gal-off");
case!(edge_gal_sync_current, "gal-sync", "current");
case!(edge_gal_sync_removed, "gal-sync", "removed");
case!(edge_gal_sync_never_visible, "gal-sync", "never-visible");
case!(edge_gal_sync_count_mismatch, "gal-sync", "count-mismatch");
case!(edge_gal_sync_future, "gal-sync", "future");
case!(edge_gal_sync_gal_off, "gal-sync", "gal-off");
case!(edge_gal_put_gal_off, "gal-put", "gal-off");
case!(edge_gal_delete_gal_off, "gal-delete", "gal-off");

#[tokio::test]
async fn scan_errors_preserve_contacts() -> Result<(), common::BoxError> {
    for route in ["get", "put-update", "delete"] {
        carddav_oracle::run(route, "bad-json", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn recovery_before_commit() -> Result<(), common::BoxError> {
    for route in ["put", "put-update", "delete", "gal-sync"] {
        carddav_oracle::run(route, "success", Some("commit-before")).await?;
    }
    Ok(())
}
#[tokio::test]
async fn recovery_after_commit() -> Result<(), common::BoxError> {
    for route in ["put", "put-update", "delete", "gal-sync"] {
        carddav_oracle::run(route, "success", Some("commit-after")).await?;
    }
    Ok(())
}
macro_rules! mutant_case {
    ($name:ident,$route:literal,$label:literal,$mutant:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            carddav_oracle::run($route, $label, Some($mutant)).await
        }
    };
}
mutant_case!(mutants_no_notify, "put", "success", "no-notify");
mutant_case!(mutants_no_audit, "entitlement", "success", "no-audit");
mutant_case!(
    mutants_no_tenant_filter,
    "get",
    "cross-tenant",
    "no-tenant-filter"
);
mutant_case!(mutants_double_bump, "put", "success", "double-bump");
mutant_case!(status_mutant_options, "options", "success", "status");
mutant_case!(status_mutant_propfind, "propfind", "success", "status");
mutant_case!(status_mutant_get, "get", "success", "status");
mutant_case!(status_mutant_query, "query", "success", "status");
mutant_case!(status_mutant_multiget, "multiget", "success", "status");
mutant_case!(status_mutant_sync, "sync", "success", "status");
mutant_case!(status_mutant_put, "put", "success", "status");
mutant_case!(status_mutant_put_update, "put-update", "success", "status");
mutant_case!(status_mutant_delete, "delete", "success", "status");
mutant_case!(
    status_mutant_unsupported,
    "unsupported",
    "success",
    "status"
);
mutant_case!(
    status_mutant_gal_options,
    "gal-options",
    "success",
    "status"
);
mutant_case!(
    status_mutant_gal_propfind,
    "gal-propfind",
    "success",
    "status"
);
mutant_case!(status_mutant_gal_get, "gal-get", "success", "status");
mutant_case!(status_mutant_gal_query, "gal-query", "success", "status");
mutant_case!(
    status_mutant_gal_multiget,
    "gal-multiget",
    "success",
    "status"
);
mutant_case!(status_mutant_gal_sync, "gal-sync", "success", "status");
mutant_case!(status_mutant_gal_put, "gal-put", "success", "status");
mutant_case!(status_mutant_gal_delete, "gal-delete", "success", "status");
mutant_case!(
    status_mutant_entitlement,
    "entitlement",
    "success",
    "status"
);

#[tokio::test]
async fn real_client_sessions() -> Result<(), common::BoxError> {
    carddav_oracle::run("client-session", "vdirsyncer", None).await
}
#[tokio::test]
async fn executable_client_sessions() -> Result<(), common::BoxError> {
    carddav_oracle::run("client-executable", "vdirsyncer", None).await
}
case!(fault_put_db_fault, "put", "db-fault");
case!(fault_put_unaccounted, "put", "unaccounted");
case!(fault_put_bad_accounting, "put", "bad-accounting");
case!(fault_put_update_db_fault, "put-update", "db-fault");
case!(fault_put_update_unaccounted, "put-update", "unaccounted");
case!(
    fault_put_update_bad_accounting,
    "put-update",
    "bad-accounting"
);
case!(fault_delete_db_fault, "delete", "db-fault");
case!(fault_delete_unaccounted, "delete", "unaccounted");
case!(fault_delete_bad_accounting, "delete", "bad-accounting");
case!(fault_sync_db_fault, "sync", "db-fault");
case!(fault_gal_sync_db_fault, "gal-sync", "db-fault");

#[tokio::test]
async fn stale_contacts_are_accounted() -> Result<(), common::BoxError> {
    carddav_oracle::accounting::stale().await
}

case!(
    disabled_bridge_is_native_not_found,
    "options",
    "bridge-disabled"
);
