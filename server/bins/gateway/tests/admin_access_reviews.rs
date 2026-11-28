//! F01 slice `access-reviews` frozen-Go oracle, replayed without a Go upstream.
use crate::admin_access_reviews_oracle;
use crate::common;
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

#[tokio::test]
async fn wave2b_174_counts_deleted_user_role_and_deterministic_order(
) -> Result<(), common::BoxError> {
    use hyper::Request;
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{admin_access_reviews::AdminAccessReviewsRoute, RouteTable};
    use std::sync::Arc;

    let _serial = admin_access_reviews_oracle::SERIAL.lock().await;
    let Some(db) = Db::for_case("admin4-wave2b-174") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "w2b174-admin").await?;
    let t = fixture::account(&owner, "w2b174-target").await?;
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions) VALUES($1,'{roles.manage}') RETURNING id",
            &[&format!("w2b174-role-{}", a.user)],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let camp: i64 = owner
        .query_one(
            "INSERT INTO access_review_campaigns(name,status,created_by) VALUES('w2b174-camp','open',$1) RETURNING id",
            &[&a.user],
        )
        .await?
        .get(0);
    // Insert two undecided items for the same user (out of id order via explicit ids),
    // plus one deleted-user item (keep) and one deleted-role item (revoke).
    let id_hi: i64 = 960020;
    let id_lo: i64 = 960010;
    let id_del_user: i64 = 960030;
    let id_del_role: i64 = 960040;
    owner
        .execute(
            "DELETE FROM access_review_items WHERE id IN (960010,960020,960030,960040)",
            &[],
        )
        .await?;
    for (id, uid, rid, decision) in [
        (id_hi, t.user, role, "undecided"),
        (id_lo, t.user, role, "undecided"),
        (id_del_user, 999999981_i64, role, "keep"),
        (id_del_role, t.user, 999999982_i64, "revoke"),
    ] {
        owner
            .execute(
                "INSERT INTO access_review_items(id,campaign_id,user_id,role_group_id,granted_at,is_sso,decision) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,now(),false,$5)",
                &[&id, &camp, &uid, &rid, &decision],
            )
            .await?;
    }

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
            RouteTable::proxy_all().with(AdminAccessReviewsRoute {
                exec,
                worker: Some(worker),
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
            }),
        )
        .await;
        let token = common::recovery_token_with(
            a.user,
            serde_json::json!({"admin": true, "perms": ["roles.manage"]}),
        );
        let resp = common::send(
            gw,
            Request::get(format!("/api/admin/access-reviews/{camp}"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value =
            serde_json::from_slice(&common::body_bytes(resp).await)?;
        assert_eq!(body["campaign"]["reviewed"], 2);
        assert_eq!(body["campaign"]["total"], 4);
        let items = body["items"].as_array().ok_or("items array")?;
        assert_eq!(items.len(), 4);
        // Undecided items for same user must be deterministically ordered by id ASC.
        assert_eq!(items[0]["id"], id_lo);
        assert_eq!(items[1]["id"], id_hi);
        // Deleted role & deleted user items serialize empty strings instead of 500.
        let del_role = items.iter().find(|i| i["id"] == id_del_role).ok_or("del_role")?;
        assert_eq!(del_role["roleName"], "");
        let del_user = items.iter().find(|i| i["id"] == id_del_user).ok_or("del_user")?;
        assert_eq!(del_user["userEmail"], "");
        Ok::<_, common::BoxError>(())
    }
    .await;

    let _ = owner
        .execute("DELETE FROM access_review_campaigns WHERE id=$1", &[&camp])
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_assignments WHERE role_group_id=$1", &[&role])
        .await;
    let _ = owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await;
    for acct in [&t, &a] {
        let _ = common::remove_blob_account(&owner, acct).await;
    }
    result
}
