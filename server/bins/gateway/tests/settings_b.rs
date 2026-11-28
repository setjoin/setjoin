//! F19 slice `settings-b`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod settings_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            settings_oracle::run("settings-b", $action, $kind, None).await
        }
    };
}

case!(notif_get_success, "notif-get", "success");
case!(notif_get_foreign, "notif-get", "foreign");
case!(notif_get_dnd, "notif-get", "dnd");
case!(notif_get_null_cols, "notif-get", "null-cols");
case!(notif_get_ignored_query, "notif-get", "ignored-query");
case!(
    notif_get_success_status_mutant,
    "notif-get",
    "success-status-mutant"
);

case!(notif_put_success, "notif-put", "success");
case!(notif_put_foreign, "notif-put", "foreign");
case!(notif_put_device, "notif-put", "device");
case!(notif_put_device_update, "notif-put", "device-update");
case!(notif_put_bad_json, "notif-put", "bad-json");
case!(notif_put_bad_fp, "notif-put", "bad-fp");
case!(notif_put_fp_short, "notif-put", "fp-short");
case!(notif_put_fp_empty, "notif-put", "fp-empty");
case!(notif_put_fp_int, "notif-put", "fp-int");
case!(notif_put_fp_upper, "notif-put", "fp-upper");
case!(notif_put_fp_urn, "notif-put", "fp-urn");
case!(notif_put_fp_braces, "notif-put", "fp-braces");
case!(notif_put_fp_plain, "notif-put", "fp-plain");
case!(notif_put_bad_policy, "notif-put", "bad-policy");
case!(notif_put_bad_chat, "notif-put", "bad-chat");
case!(notif_put_policy_keep, "notif-put", "policy-keep");
case!(notif_put_bad_dnd, "notif-put", "bad-dnd");
case!(
    notif_put_dnd_days_overflow,
    "notif-put",
    "dnd-days-overflow"
);
case!(notif_put_bad_mail, "notif-put", "bad-mail");
case!(notif_put_null_body, "notif-put", "null-body");
case!(notif_put_no_dnd, "notif-put", "no-dnd");
case!(notif_put_fold, "notif-put", "fold");
case!(notif_put_wrong_type, "notif-put", "wrong-type");
case!(notif_put_trailing, "notif-put", "trailing");
case!(notif_put_repeat, "notif-put", "repeat");
case!(
    notif_put_success_status_mutant,
    "notif-put",
    "success-status-mutant"
);

case!(vip_get_success, "vip-get", "success");
case!(vip_get_foreign, "vip-get", "foreign");
case!(vip_get_ignored_query, "vip-get", "ignored-query");
case!(
    vip_get_success_status_mutant,
    "vip-get",
    "success-status-mutant"
);

case!(vip_put_success, "vip-put", "success");
case!(vip_put_foreign, "vip-put", "foreign");
case!(vip_put_off, "vip-put", "off");
case!(vip_put_off_missing, "vip-put", "off-missing");
case!(vip_put_missing_vip, "vip-put", "missing-vip");
case!(vip_put_shared, "vip-put", "shared");
case!(vip_put_case, "vip-put", "case");
case!(vip_put_unicode, "vip-put", "unicode");
case!(vip_put_existing, "vip-put", "existing");
case!(vip_put_fold, "vip-put", "fold");
case!(vip_put_empty, "vip-put", "empty");
case!(vip_put_blank, "vip-put", "blank");
case!(vip_put_nbsp, "vip-put", "nbsp");
case!(vip_put_wrong_type, "vip-put", "wrong-type");
case!(vip_put_bad_json, "vip-put", "bad-json");
case!(vip_put_repeat, "vip-put", "repeat");
case!(
    vip_put_success_status_mutant,
    "vip-put",
    "success-status-mutant"
);

case!(vacation_get_success, "vacation-get", "success");
case!(vacation_get_foreign, "vacation-get", "foreign");
case!(vacation_get_null_html, "vacation-get", "null-html");
case!(vacation_get_no_dates, "vacation-get", "no-dates");
case!(vacation_get_ignored_query, "vacation-get", "ignored-query");
case!(
    vacation_get_success_status_mutant,
    "vacation-get",
    "success-status-mutant"
);

case!(vacation_put_success, "vacation-put", "success");
case!(vacation_put_foreign, "vacation-put", "foreign");
case!(vacation_put_disable, "vacation-put", "disable");
case!(
    vacation_put_empty_audience,
    "vacation-put",
    "empty-audience"
);
case!(vacation_put_bad_audience, "vacation-put", "bad-audience");
case!(vacation_put_bad_order, "vacation-put", "bad-order");
case!(vacation_put_bad_date, "vacation-put", "bad-date");
case!(vacation_put_empty_date, "vacation-put", "empty-date");
case!(vacation_put_clear_dates, "vacation-put", "clear-dates");
case!(vacation_put_loose_date, "vacation-put", "loose-date");
case!(vacation_put_html, "vacation-put", "html");
case!(vacation_put_fold, "vacation-put", "fold");
case!(vacation_put_nul, "vacation-put", "nul");
case!(vacation_put_long, "vacation-put", "long");
case!(vacation_put_wrong_type, "vacation-put", "wrong-type");
case!(vacation_put_null_body, "vacation-put", "null-body");
case!(vacation_put_bad_json, "vacation-put", "bad-json");
case!(vacation_put_repeat, "vacation-put", "repeat");
case!(
    vacation_put_success_status_mutant,
    "vacation-put",
    "success-status-mutant"
);

case!(delegation_get_success, "delegation-get", "success");
case!(delegation_get_foreign, "delegation-get", "foreign");
case!(
    delegation_get_ignored_query,
    "delegation-get",
    "ignored-query"
);
case!(
    delegation_get_success_status_mutant,
    "delegation-get",
    "success-status-mutant"
);

case!(delegation_put_success, "delegation-put", "success");
case!(delegation_put_foreign, "delegation-put", "foreign");
case!(delegation_put_self, "delegation-put", "self");
case!(
    delegation_put_cross_domain,
    "delegation-put",
    "cross-domain"
);
case!(
    delegation_put_missing_user,
    "delegation-put",
    "missing-user"
);
case!(delegation_put_bad_range, "delegation-put", "bad-range");
case!(delegation_put_equal_range, "delegation-put", "equal-range");
case!(delegation_put_no_times, "delegation-put", "no-times");
case!(delegation_put_bad_time, "delegation-put", "bad-time");
case!(delegation_put_offset, "delegation-put", "offset");
case!(delegation_put_clear, "delegation-put", "clear");
case!(
    delegation_put_disabled_with_delegate,
    "delegation-put",
    "disabled-with-delegate"
);
case!(
    delegation_put_zero_delegate,
    "delegation-put",
    "zero-delegate"
);
case!(delegation_put_wrong_type, "delegation-put", "wrong-type");
case!(delegation_put_float_id, "delegation-put", "float-id");
case!(delegation_put_fold, "delegation-put", "fold");
case!(delegation_put_null_body, "delegation-put", "null-body");
case!(delegation_put_bad_json, "delegation-put", "bad-json");
case!(delegation_put_array_body, "delegation-put", "array-body");
case!(delegation_put_repeat, "delegation-put", "repeat");
case!(
    delegation_put_success_status_mutant,
    "delegation-put",
    "success-status-mutant"
);

case!(sync_put_success, "sync-put", "success");
case!(sync_put_toggle_off, "sync-put", "toggle-off");
case!(sync_put_connectivity_off, "sync-put", "connectivity-off");
case!(sync_put_no_device_claim, "sync-put", "no-device-claim");
case!(sync_put_unregistered, "sync-put", "unregistered");
case!(sync_put_foreign, "sync-put", "foreign");
case!(sync_put_mode_off, "sync-put", "mode-off");
case!(sync_put_no_policy, "sync-put", "no-policy");
case!(sync_put_bad_json, "sync-put", "bad-json");
case!(sync_put_array_body, "sync-put", "array-body");
case!(sync_put_empty_body, "sync-put", "empty-body");
case!(sync_put_unknown_field, "sync-put", "unknown-field");
case!(sync_put_trailing, "sync-put", "trailing");
case!(sync_put_negative_window, "sync-put", "negative-window");
case!(sync_put_bad_network, "sync-put", "bad-network");
case!(sync_put_bad_prefetch, "sync-put", "bad-prefetch");
case!(sync_put_wrong_type, "sync-put", "wrong-type");
case!(sync_put_float_window, "sync-put", "float-window");
case!(sync_put_missing, "sync-put", "missing");
case!(sync_put_too_big, "sync-put", "too-big");
case!(sync_put_clamp, "sync-put", "clamp");
case!(sync_put_int_overflow, "sync-put", "int-overflow");
case!(sync_put_opt_out, "sync-put", "opt-out");
case!(sync_put_fold, "sync-put", "fold");
case!(sync_put_null_body, "sync-put", "null-body");
case!(sync_put_repeat, "sync-put", "repeat");
case!(
    sync_put_success_status_mutant,
    "sync-put",
    "success-status-mutant"
);
