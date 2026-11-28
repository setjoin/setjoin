//! F01 slice `sod` frozen-Go oracle, replayed without a Go upstream.
use crate::admin_sod_oracle;
use crate::common;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_sod_oracle::run($action, $kind, None).await
        }
    };
}
macro_rules! fault {
    ($name:ident, $action:literal, $kind:literal, $fault:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            admin_sod_oracle::run($action, $kind, Some($fault)).await
        }
    };
}

case!(my_roles_success, "my-roles", "success");
case!(my_roles_foreign, "my-roles", "foreign");
case!(my_roles_configured, "my-roles", "configured");
case!(my_roles_configured_array, "my-roles", "configured-array");
case!(my_roles_cold_start, "my-roles", "cold-start");
case!(my_roles_ignored_query, "my-roles", "ignored-query");
case!(my_roles_status_mutant, "my-roles", "success-status-mutant");

case!(activate_success, "activate", "success");
case!(activate_repeat, "activate", "repeat");
case!(activate_cold_start, "activate", "cold-start");
case!(activate_clamp, "activate", "clamp");
case!(activate_cap, "activate", "cap");
case!(activate_fallback_clamp, "activate", "fallback-clamp");
case!(activate_configured, "activate", "configured");
case!(activate_configured_array, "activate", "configured-array");
case!(activate_foreign, "activate", "foreign");
case!(activate_not_eligible, "activate", "not-eligible");
case!(activate_unknown_role, "activate", "unknown-role");
case!(activate_toggle_off, "activate", "toggle-off");
case!(
    activate_justification_required,
    "activate",
    "justification-required"
);
case!(
    activate_blank_justification,
    "activate",
    "blank-justification"
);
case!(
    activate_empty_justification,
    "activate",
    "empty-justification"
);
case!(activate_justified, "activate", "justified");
case!(activate_bad_json, "activate", "bad-json");
case!(activate_zero, "activate", "zero");
case!(activate_negative, "activate", "negative");
case!(activate_required, "activate", "required");
case!(activate_typed, "activate", "typed");
case!(activate_fractional, "activate", "fractional");
case!(activate_null_body, "activate", "null-body");
case!(activate_huge, "activate", "huge");
case!(activate_folded, "activate", "folded");
case!(activate_padded, "activate", "padded");
case!(activate_oversize, "activate", "oversize");
case!(activate_bad_id, "activate", "bad-id");
case!(activate_approval, "activate", "approval");
case!(activate_status_mutant, "activate", "success-status-mutant");
fault!(activate_no_audit_fault, "activate", "success", "no-audit");

case!(deactivate_success, "deactivate", "success");
case!(deactivate_repeat, "deactivate", "repeat");
case!(deactivate_foreign, "deactivate", "foreign");
case!(deactivate_direct, "deactivate", "direct");
case!(deactivate_unknown_role, "deactivate", "unknown-role");
case!(deactivate_bad_id, "deactivate", "bad-id");
case!(
    deactivate_status_mutant,
    "deactivate",
    "success-status-mutant"
);
fault!(
    deactivate_no_audit_fault,
    "deactivate",
    "success",
    "no-audit"
);

case!(policy_get_success, "policy-get", "success");
case!(policy_get_fallback, "policy-get", "fallback");
case!(policy_get_configured, "policy-get", "configured");
case!(
    policy_get_configured_array,
    "policy-get",
    "configured-array"
);
case!(policy_get_missing, "policy-get", "missing");
case!(policy_get_bad_id, "policy-get", "bad-id");
case!(policy_get_denied, "policy-get", "denied");
case!(policy_get_foreign, "policy-get", "foreign");
case!(
    policy_get_status_mutant,
    "policy-get",
    "success-status-mutant"
);

case!(policy_put_success, "policy-put", "success");
case!(policy_put_update, "policy-put", "update");
case!(policy_put_repeat, "policy-put", "repeat");
case!(policy_put_invalid, "policy-put", "invalid");
case!(policy_put_zero, "policy-put", "zero");
case!(policy_put_negative, "policy-put", "negative");
case!(policy_put_required, "policy-put", "required");
case!(policy_put_typed, "policy-put", "typed");
case!(policy_put_huge, "policy-put", "huge");
case!(policy_put_bad_id, "policy-put", "bad-id");
case!(policy_put_missing_role, "policy-put", "missing-role");
case!(policy_put_denied, "policy-put", "denied");
case!(policy_put_foreign, "policy-put", "foreign");
case!(policy_put_folded, "policy-put", "folded");
case!(policy_put_justified, "policy-put", "justified");
case!(
    policy_put_status_mutant,
    "policy-put",
    "success-status-mutant"
);

#[tokio::test]
async fn wave2b_175_approval_gated_jit_activation_end_to_end() -> Result<(), common::BoxError> {
    use hyper::Request;
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{admin_sod::AdminSodRoute, RouteTable};
    use std::sync::Arc;

    let _serial = admin_sod_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin5-wave2b-175") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let req_user = fixture::account(&owner, "w2b175-req").await?;
    let approver = fixture::account(&owner, "w2b175-apr").await?;
    let jit_prev: bool = owner
        .query_one("SELECT enabled FROM feature_toggles WHERE key='rbac.jit'", &[])
        .await?
        .get(0);
    let apr_prev: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='approval.rbac'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key IN ('rbac.jit','approval.rbac')",
            &[],
        )
        .await?;
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions) VALUES($1,'{users.read}') RETURNING id",
            &[&format!("w2b175-role-{}", req_user.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) VALUES($1,$2,$1,true)",
            &[&req_user.user, &role],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_activation_policy(role_group_id,max_duration_minutes,require_justification,require_approval,approver_spec) \
             VALUES($1,60,false,true,jsonb_build_object('kind','named','user_id',$2::bigint))",
            &[&role, &approver.user],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();

    let result = async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker = common::patient_exec(&db.dsn, 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let upstream = common::fake_upstream(|_| async {
            hyper::Response::builder()
                .status(500)
                .body(common::full("go"))
                .unwrap()
        })
        .await;
        let gw = common::gateway(
            upstream,
            "",
            RouteTable::proxy_all().with(AdminSodRoute {
                exec,
                worker: Some(worker),
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
            }),
        )
        .await;
        let token = common::recovery_token_with(req_user.user, serde_json::json!({"admin": true}));
        let resp = common::send(
            gw,
            Request::post(format!("/api/admin/me/roles/{role}/activate"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(
                    r#"{"durationMinutes":30,"justification":"incident response"}"#,
                ))?,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 202);
        let body: serde_json::Value =
            serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert_eq!(body["status"], "pending_approval");
        assert_eq!(body["pendingApproval"], true);

        // Window is NOT open yet.
        let until_before: Option<String> = owner
            .query_one(
                "SELECT activated_until::text FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2",
                &[&req_user.user, &role],
            )
            .await?
            .get(0);
        assert!(until_before.is_none(), "window must stay closed until approved");

        // Pending approval request exists and approving it opens the JIT window.
        let req_id: i64 = owner
            .query_one(
                "SELECT id FROM approval_requests WHERE consumer_type='rbac.jit_activation' AND requester_user_id=$1 AND status='pending' ORDER BY id DESC LIMIT 1",
                &[&req_user.user],
            )
            .await?
            .get(0);
        owner
            .execute(
                "SELECT rbac_approval_decide($1, $2, 'approve', 'approved for incident')",
                &[&req_id, &approver.user],
            )
            .await?;
        let active_after: bool = owner
            .query_one(
                "SELECT activated_until > now() FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2",
                &[&req_user.user, &role],
            )
            .await?
            .get(0);
        assert!(active_after, "approving parked JIT request must open the window");
        Ok::<_, common::BoxError>(())
    }
    .await;

    let _ = owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='rbac.jit'",
            &[&jit_prev],
        )
        .await;
    let _ = owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='approval.rbac'",
            &[&apr_prev],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM approval_requests WHERE consumer_type='rbac.jit_activation' AND requester_user_id=$1",
            &[&req_user.user],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)",
            &[&receipts],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_activation_policy WHERE role_group_id=$1",
            &[&role],
        )
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await;
    for acct in [&req_user, &approver] {
        let _ = common::remove_blob_account(&owner, acct).await;
    }
    let _ = owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"
        ))
        .await;
    result
}
