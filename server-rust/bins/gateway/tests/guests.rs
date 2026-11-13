//! F11 frozen-Go HTTP oracle, replayed without a Go upstream.
mod common;
mod guests_oracle;

/// Per-file serial guard (#362). Cases install and remove shared fixture rows
/// (`system_config` keys such as `authserver.public_url`), and snapshot global
/// audit windows, NOTIFY channels and user tables, so parallel cases collide
/// or observe each other's actors. The cargo workspace and the other test
/// binaries keep their normal parallelism.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[tokio::test]
async fn profiles_list_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profiles-list", "success", false).await
}
#[tokio::test]
async fn profiles_list_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profiles-list", "foreign", false).await
}
#[tokio::test]
async fn profiles_list_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profiles-list", "invalid", false).await
}
#[tokio::test]
async fn profile_get_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-get", "success", false).await
}
#[tokio::test]
async fn profile_get_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-get", "foreign", false).await
}
#[tokio::test]
async fn profile_get_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-get", "invalid", false).await
}
#[tokio::test]
async fn profile_domains_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-domains", "success", false).await
}
#[tokio::test]
async fn profile_domains_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-domains", "foreign", false).await
}
#[tokio::test]
async fn profile_domains_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-domains", "invalid", false).await
}
#[tokio::test]
async fn profile_create_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "success").await
}
#[tokio::test]
async fn profile_create_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "foreign").await
}
#[tokio::test]
async fn profile_create_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "invalid").await
}
#[tokio::test]
async fn profile_create_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "repeat").await
}
#[tokio::test]
async fn profile_update_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-update", "success").await
}
#[tokio::test]
async fn profile_update_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-update", "foreign").await
}
#[tokio::test]
async fn profile_update_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-update", "invalid").await
}
#[tokio::test]
async fn profile_update_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-update", "repeat").await
}
#[tokio::test]
async fn profile_delete_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-delete", "success").await
}
#[tokio::test]
async fn profile_delete_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-delete", "foreign").await
}
#[tokio::test]
async fn profile_delete_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-delete", "invalid").await
}
#[tokio::test]
async fn profile_delete_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-delete", "repeat").await
}
#[tokio::test]
async fn guests_list_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guests-list", "success", false).await
}
#[tokio::test]
async fn guests_list_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guests-list", "foreign", false).await
}
#[tokio::test]
async fn guests_list_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guests-list", "invalid", false).await
}
#[tokio::test]
async fn guest_get_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guest-get", "success", false).await
}
#[tokio::test]
async fn guest_get_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guest-get", "foreign", false).await
}
#[tokio::test]
async fn guest_get_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guest-get", "invalid", false).await
}
#[tokio::test]
async fn sponsor_options_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("sponsors", "success", false).await
}
#[tokio::test]
async fn sponsor_options_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("sponsors", "foreign", false).await
}
#[tokio::test]
async fn sponsor_options_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("sponsors", "invalid", false).await
}
#[tokio::test]
async fn guest_disable_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "success").await
}
#[tokio::test]
async fn guest_disable_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "foreign").await
}
#[tokio::test]
async fn guest_disable_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "invalid").await
}
#[tokio::test]
async fn guest_disable_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "repeat").await
}
#[tokio::test]
async fn guest_enable_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("enable", "success").await
}
#[tokio::test]
async fn guest_enable_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("enable", "foreign").await
}
#[tokio::test]
async fn guest_enable_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("enable", "invalid").await
}
#[tokio::test]
async fn guest_enable_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("enable", "repeat").await
}
#[tokio::test]
async fn guest_extend_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "success").await
}
#[tokio::test]
async fn guest_extend_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "foreign").await
}
#[tokio::test]
async fn guest_extend_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "invalid").await
}
#[tokio::test]
async fn guest_extend_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "repeat").await
}
#[tokio::test]
async fn guest_extend_truncates_go_microseconds() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "fractional").await
}
#[tokio::test]
async fn guest_extend_submicro_zero_is_not_missing() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "submicro-zero").await
}
#[tokio::test]
async fn guest_profile_assignment_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "success-qualified").await
}
#[tokio::test]
async fn guest_profile_assignment_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "foreign").await
}
#[tokio::test]
async fn guest_profile_assignment_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "invalid").await
}
#[tokio::test]
async fn guest_profile_assignment_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "repeat").await
}
#[tokio::test]
async fn guest_transfer_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("transfer", "success").await
}
#[tokio::test]
async fn guest_transfer_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("transfer", "foreign").await
}
#[tokio::test]
async fn guest_transfer_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("transfer", "invalid").await
}
#[tokio::test]
async fn guest_transfer_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("transfer", "repeat").await
}
#[tokio::test]
async fn invite_domain_add_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "success").await
}

#[tokio::test]
async fn invite_domain_add_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "foreign").await
}

#[tokio::test]
async fn invite_domain_add_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "invalid").await
}

#[tokio::test]
async fn invite_domain_remove_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("remove", "success").await
}

#[tokio::test]
async fn invite_domain_remove_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("remove", "foreign").await
}

#[tokio::test]
async fn invite_domain_remove_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("remove", "invalid").await
}

#[tokio::test]
async fn guest_invite_revoke_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "success-qualified").await
}

#[tokio::test]
async fn guest_invite_revoke_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "foreign-qualified").await
}

#[tokio::test]
async fn guest_invite_revoke_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "invalid-qualified").await
}

#[tokio::test]
async fn guest_invite_revoke_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "repeat-qualified").await
}

#[tokio::test]
async fn guest_invite_revoke_stale() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "stale-inventory-qualified").await
}
#[tokio::test]
async fn member_invite_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("success").await
}
#[tokio::test]
async fn member_invite_cross_tenant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("foreign").await
}
#[tokio::test]
async fn member_invite_invalid_input() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("invalid").await
}

#[tokio::test]
async fn guest_invite_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "success-qualified").await
}

#[tokio::test]
async fn guest_invite_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "foreign-qualified").await
}

#[tokio::test]
async fn guest_invite_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "invalid").await
}

#[tokio::test]
async fn guest_invite_delivery_fails() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "delivery-fails").await
}

#[tokio::test]
async fn guest_reinvite_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "success").await
}

#[tokio::test]
async fn guest_reinvite_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "foreign").await
}

#[tokio::test]
async fn guest_reinvite_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "invalid").await
}

#[tokio::test]
async fn guest_reinvite_delivery_fails() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "delivery-fails").await
}

#[tokio::test]
async fn profiles_list_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profiles-list", "success", true).await
}

#[tokio::test]
async fn profile_get_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-get", "success", true).await
}

#[tokio::test]
async fn profile_domains_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("profile-domains", "success", true).await
}

#[tokio::test]
async fn guests_list_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guests-list", "success", true).await
}

#[tokio::test]
async fn guest_get_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guest-get", "success", true).await
}

#[tokio::test]
async fn sponsor_options_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("sponsors", "success", true).await
}

#[tokio::test]
async fn profile_create_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "success-status-mutant").await
}

#[tokio::test]
async fn profile_update_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-update", "success-status-mutant").await
}

#[tokio::test]
async fn profile_delete_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-delete", "success-status-mutant").await
}

#[tokio::test]
async fn guest_disable_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "success-status-mutant").await
}

#[tokio::test]
async fn guest_enable_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("enable", "success-status-mutant").await
}

#[tokio::test]
async fn guest_extend_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "success-status-mutant").await
}

#[tokio::test]
async fn guest_assign_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "success-qualified-status-mutant").await
}

#[tokio::test]
async fn guest_transfer_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("transfer", "success-status-mutant").await
}

#[tokio::test]
async fn guest_revoke_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "success-qualified-status-mutant").await
}

#[tokio::test]
async fn guest_invite_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "success-qualified-status-mutant").await
}

#[tokio::test]
async fn guest_reinvite_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "success-status-mutant").await
}

#[tokio::test]
async fn invite_domain_add_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "success-status-mutant").await
}

#[tokio::test]
async fn invite_domain_remove_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("remove", "success-status-mutant").await
}

#[tokio::test]
async fn member_invite_status_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("success-status-mutant").await
}
#[tokio::test]
async fn guest_worker_expiry() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::worker::run("expiry").await
}
#[tokio::test]
async fn guest_worker_early() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::worker::run("early").await
}
#[tokio::test]
async fn guest_worker_absent() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::worker::run("absent").await
}
#[tokio::test]
async fn guest_worker_complete() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::worker::run("complete").await
}
#[tokio::test]
async fn guest_worker_failure() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::worker::run("failure").await
}
#[tokio::test]
async fn guest_worker_deadletter() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::worker::run("deadletter").await
}
#[tokio::test]
async fn profile_create_no_audit_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let error = guests_oracle::writes::run_fault("profile-create", "success", Some("no-audit"))
        .await
        .expect_err("missing audit survived")
        .to_string();
    if !error.contains("/audit/") {
        return Err(error.into());
    }
    eprintln!("MUTANT-REJECTED: POST /admin/guest-profiles :: no-audit");
    Ok(())
}
#[tokio::test]
async fn profile_create_double_bump_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let error = guests_oracle::writes::run_fault("profile-create", "success", Some("double-bump"))
        .await
        .expect_err("extra bump survived")
        .to_string();
    if !error.contains("/effects/") {
        return Err(error.into());
    }
    eprintln!("MUTANT-REJECTED: POST /admin/guest-profiles :: double-bump");
    Ok(())
}
#[tokio::test]
async fn guest_disable_no_notify_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let error = guests_oracle::mutations::run_fault("disable", "success", Some("no-notify"))
        .await
        .expect_err("missing publish survived")
        .to_string();
    if !error.contains("/notify/") {
        return Err(error.into());
    }
    eprintln!("MUTANT-REJECTED: POST /admin/guests/{{id}}/disable :: no-notify");
    Ok(())
}
#[tokio::test]
async fn guests_list_no_tenant_filter_mutant() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("guests-list", "foreign", false).await?;
    let error = guests_oracle::run("guests-list", "foreign-unfiltered", false)
        .await
        .expect_err("missing scope survived")
        .to_string();
    if !error.contains("/response/body") {
        return Err(error.into());
    }
    eprintln!("MUTANT-REJECTED: GET /admin/guests :: no-tenant-filter");
    Ok(())
}

#[tokio::test]
async fn invite_domain_add_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "repeat").await
}

#[tokio::test]
async fn invite_domain_remove_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("remove", "repeat").await
}

#[tokio::test]
async fn member_invite_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("repeat").await
}

#[tokio::test]
async fn guest_invite_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "repeat").await
}

#[tokio::test]
async fn guest_reinvite_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "repeat").await
}
#[tokio::test]
async fn guest_approval_applies_and_delivers() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("approval", "success-colliding-ids").await
}
#[tokio::test]
async fn guest_approval_denies_without_credentials() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("approval", "deny").await
}
#[tokio::test]
async fn guest_approval_delivery_failure_is_best_effort() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("approval", "delivery-fails-colliding-ids").await
}

#[tokio::test]
async fn guest_invite_profile() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "profile").await
}

#[tokio::test]
async fn guest_invite_bad_public_url() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "bad-public-url").await
}

#[tokio::test]
async fn guest_invite_bad_ttl() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "bad-ttl").await
}

#[tokio::test]
async fn guest_invite_overflow_ttl() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "overflow-ttl").await
}

#[tokio::test]
async fn guest_invite_allowlist() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "allowlist").await
}

#[tokio::test]
async fn guest_approval_invalid_metadata_rolls_back() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("approval", "bad-public-url").await
}

#[tokio::test]
async fn profile_create_surrogate() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "surrogate").await
}

#[tokio::test]
async fn profile_create_raw_days() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "raw-days").await
}

#[tokio::test]
async fn profile_create_folded() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "folded-qualified").await
}

#[tokio::test]
async fn profile_create_null_duplicate() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "null-duplicate").await
}

#[tokio::test]
async fn profile_create_primitive_null() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "primitive-null").await
}

#[tokio::test]
async fn profile_create_trailing() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "trailing").await
}

#[tokio::test]
async fn profile_create_unknown() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "unknown").await
}

#[tokio::test]
async fn guest_disable_encoded_id() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "encoded-id").await
}

#[tokio::test]
async fn guest_disable_encoded_prefix() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "encoded-prefix").await
}

#[tokio::test]
async fn guest_disable_encoded_slash() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "encoded-slash").await
}

#[tokio::test]
async fn guest_disable_encoded_mount() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("disable", "encoded-mount").await
}

#[tokio::test]
async fn guest_invite_profile_overflow() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "profile-overflow").await
}

#[tokio::test]
async fn guest_invite_profile_dst() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "profile-dst").await
}

#[tokio::test]
async fn guest_reinvite_null_expiry() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "null-expiry").await
}

#[tokio::test]
async fn invite_domain_feature_off() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "off").await
}

#[tokio::test]
async fn profile_create_read_failure_rolls_back() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "read-fault").await
}
#[tokio::test]
async fn guest_invite_profile_prepare_failure_rolls_back() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "profile-bad-url").await
}

#[tokio::test]
async fn guest_extend_time_hour() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "time-hour").await
}

#[tokio::test]
async fn guest_extend_time_comma() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "time-comma").await
}

#[tokio::test]
async fn guest_extend_time_zone_hour() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "time-zone-hour").await
}

#[tokio::test]
async fn guest_extend_time_zone_minute() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "time-zone-minute").await
}

#[tokio::test]
async fn guest_extend_time_leap() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "time-leap").await
}

#[tokio::test]
async fn guest_extend_time_lower_z() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "time-lower-z").await
}

#[tokio::test]
async fn guest_invite_wire_mime() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "wire-mime").await
}

#[tokio::test]
async fn guest_invite_bad_json() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "bad-json").await
}

#[tokio::test]
async fn guest_invite_bad_profile() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "bad-profile").await
}

#[tokio::test]
async fn guest_invite_bad_expiry() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("invite", "bad-expiry").await
}

#[tokio::test]
async fn guest_reinvite_bad_json() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("reinvite", "bad-json").await
}

#[tokio::test]
async fn guest_revoke_missing_expected() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "missing-expected").await
}

#[tokio::test]
async fn guest_revoke_bad_expected() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("revoke", "bad-expected").await
}

#[tokio::test]
async fn guest_transfer_bad_json() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("transfer", "bad-json").await
}

#[tokio::test]
async fn guest_assign_bad_json() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "bad-json").await
}

#[tokio::test]
async fn guest_assign_missing_profile() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "missing-profile").await
}

#[tokio::test]
async fn invite_domain_add_bad_json() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::domains::run("add", "bad-json").await
}

#[tokio::test]
async fn member_invite_bad_json() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("bad-json").await
}

#[tokio::test]
async fn member_invite_trailing() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("trailing").await
}

#[tokio::test]
async fn member_invite_feature_off() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("off").await
}

#[tokio::test]
async fn member_invite_no_policy() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::submit::run("no-policy").await
}

#[tokio::test]
async fn profile_create_bad_host() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "bad-host").await
}

#[tokio::test]
async fn profile_create_bad_apps() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "bad-apps").await
}

#[tokio::test]
async fn sponsors_long_query() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::run("sponsors", "long-query-qualified", false).await
}

#[tokio::test]
async fn profile_create_missing_days() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "missing-days").await
}

#[tokio::test]
async fn profile_create_missing_apps() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "missing-apps").await
}

#[tokio::test]
async fn profile_create_null_apps() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::writes::run("profile-create", "null-apps").await
}

#[tokio::test]
async fn guest_assign_null_profile() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("assign", "null-profile").await
}

#[tokio::test]
async fn guest_extend_missing_expiry() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    guests_oracle::mutations::run("extend", "missing-expiry").await
}
