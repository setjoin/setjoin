//! F01 slice `access-reviews` frozen-Go oracle, replayed without a Go upstream.
mod admin_access_reviews_oracle;
mod common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_access_reviews_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_access_reviews_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(list_success, "list", "success");
case!(list_cross_tenant, "list", "foreign");
case!(list_denied, "list", "denied");
case!(list_status_mutant, "list", "success-status-mutant");

case!(get_success, "get", "success");
case!(get_cross_tenant, "get", "foreign");
case!(get_invalid_input, "get", "invalid");
case!(get_missing, "get", "missing");
case!(get_denied, "get", "denied");
case!(get_closed, "get", "closed");
case!(get_empty, "get", "empty");
case!(get_orphan, "get", "orphan");
case!(get_status_mutant, "get", "success-status-mutant");

case!(start_success, "start", "success");
case!(start_cross_tenant, "start", "foreign");
case!(start_invalid_input, "start", "invalid");
case!(start_empty, "start", "empty");
case!(start_typed, "start", "typed");
case!(start_folded, "start", "folded");
case!(start_repeat, "start", "repeat");
case!(start_denied, "start", "denied");
case!(start_status_mutant, "start", "success-status-mutant");
fault!(start_no_audit_fault, "start", "success", "no-audit");

case!(decide_success, "decide", "success");
case!(decide_keep, "decide", "keep");
case!(decide_cross_tenant, "decide", "foreign");
case!(decide_foreign_item, "decide", "foreign-item");
case!(decide_invalid_input, "decide", "invalid");
case!(decide_bad_item, "decide", "bad-item");
case!(decide_bad_json, "decide", "bad-json");
case!(decide_bad_decision, "decide", "bad-decision");
case!(decide_typed_note, "decide", "typed-note");
case!(decide_missing, "decide", "missing");
case!(decide_missing_item, "decide", "missing-item");
case!(decide_wrong_campaign, "decide", "wrong-campaign");
case!(decide_closed, "decide", "closed");
case!(decide_self, "decide", "self");
case!(decide_sso_revoke, "decide", "sso-revoke");
case!(decide_sso_keep, "decide", "sso-keep");
case!(decide_folded, "decide", "folded");
case!(decide_denied, "decide", "denied");
case!(decide_repeat, "decide", "repeat");
case!(decide_status_mutant, "decide", "success-status-mutant");
fault!(decide_no_audit_fault, "decide", "success", "no-audit");

case!(bulk_success, "bulk", "success");
case!(bulk_revoke, "bulk", "revoke");
case!(bulk_cross_tenant, "bulk", "foreign");
case!(bulk_scoped_skip, "bulk", "scoped-skip");
case!(bulk_invalid_input, "bulk", "invalid");
case!(bulk_empty, "bulk", "empty");
case!(bulk_bad_decision, "bulk", "bad-decision");
case!(bulk_missing, "bulk", "missing");
case!(bulk_missing_items, "bulk", "missing-items");
case!(bulk_closed, "bulk", "closed");
case!(bulk_null_element, "bulk", "null-element");
case!(bulk_denied, "bulk", "denied");
case!(bulk_repeat, "bulk", "repeat");
case!(bulk_status_mutant, "bulk", "success-status-mutant");
fault!(bulk_no_audit_fault, "bulk", "success", "no-audit");

case!(close_success, "close", "success");
case!(close_keeps, "close", "keeps");
case!(close_cross_tenant, "close", "foreign");
case!(close_scoped, "close", "scoped");
case!(close_invalid_input, "close", "invalid");
case!(close_missing, "close", "missing");
case!(close_closed, "close", "closed");
case!(close_repeat, "close", "repeat");
case!(close_denied, "close", "denied");
case!(close_status_mutant, "close", "success-status-mutant");
fault!(close_no_audit_fault, "close", "success", "no-audit");
fault!(start_reach_bypass_fault, "start", "foreign", "reach-bypass");
fault!(
    decide_reach_bypass_fault,
    "decide",
    "foreign-item",
    "reach-bypass"
);
fault!(
    bulk_reach_bypass_fault,
    "bulk",
    "scoped-skip",
    "reach-bypass"
);
fault!(close_reach_bypass_fault, "close", "scoped", "reach-bypass");
