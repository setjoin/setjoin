//! F03 slice `remaining` frozen-Go oracle, replayed without a Go upstream.
mod ca_remaining_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            ca_remaining_oracle::run($action, $kind).await
        }
    };
}

case!(loc_list_success, "loc-list", "success");
case!(loc_list_foreign, "loc-list", "foreign");
case!(loc_list_denied, "loc-list", "denied");
case!(loc_list_deleted, "loc-list", "deleted");
case!(loc_list_invalid, "loc-list", "invalid");
case!(loc_list_status_mutant, "loc-list", "success-status-mutant");

case!(loc_create_success, "loc-create", "success");
case!(loc_create_foreign, "loc-create", "foreign");
case!(loc_create_denied, "loc-create", "denied");
case!(loc_create_invalid, "loc-create", "invalid");
case!(loc_create_empty_name, "loc-create", "empty-name");
case!(loc_create_no_arrays, "loc-create", "no-arrays");
case!(loc_create_bad_cidr, "loc-create", "bad-cidr");
case!(loc_create_bare_ip, "loc-create", "bare-ip");
case!(loc_create_repeat, "loc-create", "repeat");
case!(
    loc_create_status_mutant,
    "loc-create",
    "success-status-mutant"
);

case!(loc_update_success, "loc-update", "success");
case!(loc_update_foreign, "loc-update", "foreign");
case!(loc_update_denied, "loc-update", "denied");
case!(loc_update_invalid, "loc-update", "invalid");
case!(loc_update_empty_name, "loc-update", "empty-name");
case!(loc_update_missing, "loc-update", "missing");
case!(loc_update_repeat, "loc-update", "repeat");
case!(
    loc_update_status_mutant,
    "loc-update",
    "success-status-mutant"
);

case!(loc_delete_success, "loc-delete", "success");
case!(loc_delete_foreign, "loc-delete", "foreign");
case!(loc_delete_denied, "loc-delete", "denied");
case!(loc_delete_invalid, "loc-delete", "invalid");
case!(loc_delete_missing, "loc-delete", "missing");
case!(loc_delete_repeat, "loc-delete", "repeat");
case!(
    loc_delete_status_mutant,
    "loc-delete",
    "success-status-mutant"
);

case!(loc_restore_success, "loc-restore", "success");
case!(loc_restore_foreign, "loc-restore", "foreign");
case!(loc_restore_denied, "loc-restore", "denied");
case!(loc_restore_invalid, "loc-restore", "invalid");
case!(loc_restore_conflict, "loc-restore", "conflict");
case!(loc_restore_repeat, "loc-restore", "repeat");
case!(
    loc_restore_status_mutant,
    "loc-restore",
    "success-status-mutant"
);

case!(str_list_success, "str-list", "success");
case!(str_list_foreign, "str-list", "foreign");
case!(str_list_denied, "str-list", "denied");
case!(str_list_invalid, "str-list", "invalid");
case!(str_list_status_mutant, "str-list", "success-status-mutant");

case!(str_create_success, "str-create", "success");
case!(str_create_foreign, "str-create", "foreign");
case!(str_create_denied, "str-create", "denied");
case!(str_create_invalid, "str-create", "invalid");
case!(str_create_no_slug, "str-create", "no-slug");
case!(str_create_raw_null, "str-create", "raw-null");
case!(str_create_repeat, "str-create", "repeat");
case!(
    str_create_status_mutant,
    "str-create",
    "success-status-mutant"
);

case!(str_update_success, "str-update", "success");
case!(str_update_foreign, "str-update", "foreign");
case!(str_update_denied, "str-update", "denied");
case!(str_update_invalid, "str-update", "invalid");
case!(str_update_builtin, "str-update", "builtin");
case!(str_update_missing, "str-update", "missing");
case!(str_update_partial, "str-update", "partial");
case!(str_update_repeat, "str-update", "repeat");
case!(
    str_update_status_mutant,
    "str-update",
    "success-status-mutant"
);

case!(str_delete_success, "str-delete", "success");
case!(str_delete_foreign, "str-delete", "foreign");
case!(str_delete_denied, "str-delete", "denied");
case!(str_delete_invalid, "str-delete", "invalid");
case!(str_delete_builtin, "str-delete", "builtin");
case!(str_delete_repeat, "str-delete", "repeat");
case!(
    str_delete_status_mutant,
    "str-delete",
    "success-status-mutant"
);

case!(principals_success, "principals", "success");
case!(principals_foreign, "principals", "foreign");
case!(principals_denied, "principals", "denied");
case!(principals_invalid, "principals", "invalid");
case!(principals_groups, "principals", "groups");
case!(
    principals_status_mutant,
    "principals",
    "success-status-mutant"
);

case!(bg_get_success, "bg-get", "success");
case!(bg_get_foreign, "bg-get", "foreign");
case!(bg_get_denied, "bg-get", "denied");
case!(bg_get_empty, "bg-get", "empty");
case!(bg_get_invalid, "bg-get", "invalid");
case!(bg_get_status_mutant, "bg-get", "success-status-mutant");

case!(bg_set_success, "bg-set", "success");
case!(bg_set_foreign, "bg-set", "foreign");
case!(bg_set_denied, "bg-set", "denied");
case!(bg_set_invalid, "bg-set", "invalid");
case!(bg_set_empty, "bg-set", "empty");
case!(bg_set_repeat, "bg-set", "repeat");
case!(bg_set_status_mutant, "bg-set", "success-status-mutant");

case!(signin_success, "signin", "success");
case!(signin_foreign, "signin", "foreign");
case!(signin_denied, "signin", "denied");
case!(signin_corr, "signin", "corr");
case!(signin_limit, "signin", "limit");
case!(signin_invalid, "signin", "invalid");
case!(signin_status_mutant, "signin", "success-status-mutant");

case!(revoke_success, "revoke", "success");
case!(revoke_foreign, "revoke", "foreign");
case!(revoke_denied, "revoke", "denied");
case!(revoke_invalid, "revoke", "invalid");
case!(revoke_repeat, "revoke", "repeat");
case!(revoke_status_mutant, "revoke", "success-status-mutant");

case!(sessions_log_success, "sessions-log", "success");
case!(sessions_log_foreign, "sessions-log", "foreign");
case!(sessions_log_denied, "sessions-log", "denied");
case!(sessions_log_invalid, "sessions-log", "invalid");
case!(
    sessions_log_status_mutant,
    "sessions-log",
    "success-status-mutant"
);

case!(tpl_list_success, "tpl-list", "success");
case!(tpl_list_foreign, "tpl-list", "foreign");
case!(tpl_list_denied, "tpl-list", "denied");
case!(tpl_list_invalid, "tpl-list", "invalid");
case!(tpl_list_status_mutant, "tpl-list", "success-status-mutant");

case!(tpl_instantiate_success, "tpl-instantiate", "success");
case!(tpl_instantiate_foreign, "tpl-instantiate", "foreign");
case!(tpl_instantiate_denied, "tpl-instantiate", "denied");
case!(tpl_instantiate_invalid, "tpl-instantiate", "invalid");
case!(tpl_instantiate_repeat, "tpl-instantiate", "repeat");
case!(
    tpl_instantiate_status_mutant,
    "tpl-instantiate",
    "success-status-mutant"
);

case!(why_success, "why", "success");
case!(why_foreign, "why", "foreign");
case!(why_denied, "why", "denied");
case!(why_email, "why", "email");
case!(why_notfound, "why", "notfound");
case!(why_invalid, "why", "invalid");
case!(why_required, "why", "required");
case!(why_status_mutant, "why", "success-status-mutant");

case!(impact_success, "impact", "success");
case!(impact_foreign, "impact", "foreign");
case!(impact_denied, "impact", "denied");
case!(impact_list, "impact", "list");
case!(impact_invalid, "impact", "invalid");
case!(impact_bad_window, "impact", "bad-window");
case!(impact_missing, "impact", "missing");
case!(impact_status_mutant, "impact", "success-status-mutant");

case!(coverage_success, "coverage", "success");
case!(coverage_foreign, "coverage", "foreign");
case!(coverage_denied, "coverage", "denied");
case!(coverage_invalid, "coverage", "invalid");
case!(coverage_status_mutant, "coverage", "success-status-mutant");

case!(doctor_success, "doctor", "success");
case!(doctor_foreign, "doctor", "foreign");
case!(doctor_denied, "doctor", "denied");
case!(doctor_ttfp, "doctor", "ttfp");
case!(doctor_invalid, "doctor", "invalid");
case!(doctor_status_mutant, "doctor", "success-status-mutant");

case!(export_success, "export", "success");
case!(export_foreign, "export", "foreign");
case!(export_denied, "export", "denied");
case!(export_invalid, "export", "invalid");
case!(export_status_mutant, "export", "success-status-mutant");

case!(import_success, "import", "success");
case!(import_foreign, "import", "foreign");
case!(import_denied, "import", "denied");
case!(import_invalid, "import", "invalid");
case!(import_bad_version, "import", "bad-version");
case!(import_bad_mode, "import", "bad-mode");
case!(import_repeat, "import", "repeat");
case!(import_status_mutant, "import", "success-status-mutant");

case!(diff_success, "diff", "success");
case!(diff_foreign, "diff", "foreign");
case!(diff_denied, "diff", "denied");
case!(diff_invalid, "diff", "invalid");
case!(diff_names_only, "diff", "names-only");
case!(diff_status_mutant, "diff", "success-status-mutant");

case!(risk_list_success, "risk-list", "success");
case!(risk_list_foreign, "risk-list", "foreign");
case!(risk_list_denied, "risk-list", "denied");
case!(risk_list_limit, "risk-list", "limit");
case!(risk_list_invalid, "risk-list", "invalid");
case!(
    risk_list_status_mutant,
    "risk-list",
    "success-status-mutant"
);

case!(risk_reset_success, "risk-reset", "success");
case!(risk_reset_foreign, "risk-reset", "foreign");
case!(risk_reset_denied, "risk-reset", "denied");
case!(risk_reset_invalid, "risk-reset", "invalid");
case!(risk_reset_missing, "risk-reset", "missing");
case!(risk_reset_repeat, "risk-reset", "repeat");
case!(
    risk_reset_status_mutant,
    "risk-reset",
    "success-status-mutant"
);

/// Batch driver: `GOFREE_CA2_CASES=action:label,...` (one Go process for the whole list).
#[tokio::test]
async fn batch() -> Result<(), common::BoxError> {
    match std::env::var("GOFREE_CA2_CASES") {
        Ok(list) => ca_remaining_oracle::run_many(&list).await,
        Err(_) => Ok(()),
    }
}

case!(simulate_success, "simulate", "success");

case!(gate_cae_deny, "gate", "cae-deny");

case!(gate_trust_missing, "gate", "trust-missing");

case!(gate_cae_allow, "gate", "cae-allow");
case!(gate_cae_step_up, "gate", "cae-step-up");
case!(gate_cae_satisfied, "gate", "cae-satisfied");
case!(gate_cae_break_glass, "gate", "cae-break-glass");
case!(gate_cae_fail_open, "gate", "cae-fail-open");
case!(gate_cae_fail_closed, "gate", "cae-fail-closed");
case!(gate_cae_sif_expired, "gate", "cae-sif-expired");
case!(gate_cae_sif_fresh, "gate", "cae-sif-fresh");
case!(gate_cae_dpop_missing, "gate", "cae-dpop-missing");
case!(gate_cae_dpop_valid, "gate", "cae-dpop-valid");
case!(gate_cae_dpop_replay, "gate", "cae-dpop-replay");
case!(gate_cae_revoked, "gate", "cae-revoked");
case!(gate_cae_notify, "gate", "cae-notify");
case!(gate_trust_allow, "gate", "trust-allow");
case!(gate_trust_quarantine, "gate", "trust-quarantine");
case!(gate_trust_wipe, "gate", "trust-wipe");
case!(gate_trust_revoked, "gate", "trust-revoked");
case!(gate_lockdown_deny, "gate", "lockdown-deny");
case!(gate_lockdown_allow, "gate", "lockdown-allow");
case!(gate_lockdown_foreign, "gate", "lockdown-foreign");
case!(gate_lockdown_invalid, "gate", "lockdown-invalid");
case!(gate_lockdown_external, "gate", "lockdown-external");
case!(gate_lockdown_no_exclude, "gate", "lockdown-no-exclude");
case!(gate_lockdown_break_glass, "gate", "lockdown-break-glass");
case!(gate_lockdown_unapproved, "gate", "lockdown-unapproved");
case!(gate_lockdown_revoked, "gate", "lockdown-revoked");
case!(gate_skipped_mutant, "gate", "cae-deny-gate-mutant");

case!(simulate_foreign, "simulate", "foreign");
case!(simulate_denied, "simulate", "denied");
case!(simulate_invalid, "simulate", "invalid");
case!(simulate_from_signin, "simulate", "from-signin");
case!(simulate_missing_signin, "simulate", "missing-signin");
case!(simulate_folded, "simulate", "folded");
case!(simulate_status_mutant,"simulate","success-status-mutant");
