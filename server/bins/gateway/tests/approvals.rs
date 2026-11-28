//! Recorded frozen-Go HTTP requests replayed through the real front door.
mod common;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{approvals::ApprovalsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

/// Per-file serial guard (#362). Every case except the read-only list cases
/// observes database state that is global by design, so parallel cases would
/// see each other's effects: the `admin_audit_log` window (`id > max(id)`
/// before the request), the `approval_created`/`approval_decided` NOTIFY
/// channels, F10 `rust_operation_receipts` cleanup by before/after set
/// difference, global `approval_policies` matching and priorities, and DDL
/// fault triggers on the shared approval tables. The list cases read only
/// their own requester's rows and stay parallel. The cargo workspace and the
/// other test binaries keep their normal parallelism.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn list_my_approvals_success() -> Result<(), common::BoxError> {
    run_list("success").await
}
async fn run_list(kind: &str) -> Result<(), common::BoxError> {
    list_probe(kind, false).await
}
async fn list_probe(kind: &str, mutant: bool) -> Result<(), common::BoxError> {
    let Some(db) = Db::for_case("approvals-list") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "appr1-list").await?;
    let id:i64=owner.query_one("INSERT INTO approval_requests(consumer_type,requester_user_id,subject,payload,approver_kind,approver_ref,created_at,expires_at,domain_id) VALUES('hr.leave',$1,'Leave <one>', '{\"reason\":\"trip\"}', 'user',$1,'2026-10-01T12:00:00Z','2099-11-01T12:00:00Z',$2) RETURNING id",&[&a.user,&a.domain]).await?.get(0);
    let stranger = if kind == "foreign" {
        Some(fixture::account(&owner, "appr1-list-stranger").await?)
    } else {
        None
    };
    let result=async {
 let endpoint=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;
 let oracle=common::go_oracle::start_named(&db,endpoint,None,"gofree-appr1-http").await?;
 let recording=oracle.is_some();
 let adapter=ApprovalsRoute{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),secret:b"blobs1-test-jwt-secret-for-recording".to_vec()};
 let mut inventory:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
 for r in inventory["routes"].as_array_mut().ok_or("routes")?{if r["family"]=="F10"{r["state"]=json!(if recording{"OFF"}else{"ON"});r["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});r["oracle_commands"]=json!([""]);}}
 let g=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(common::approval_probe::Probe{inner:adapter,changed_status:mutant}))?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;let server=tokio::spawn(g.serve(listener));
 let response=common::send(addr,Request::get(if kind=="invalid"{"/api/me/approvals?limit=bad&user_id=forged"}else{"/api/me/approvals"}).header("host","mail.test").header("x-request-id","gofree-appr1-oracle").header("authorization",format!("Bearer {}",common::recovery_token(stranger.as_ref().map(|s|s.user).unwrap_or(a.user)))).body(common::full(""))?).await;
 let status=response.status().as_u16();
 let mut headers=serde_json::Map::new();
 for name in response.headers().keys(){let values=response.headers().get_all(name).iter().map(|v|v.to_str().map(str::to_string)).collect::<Result<Vec<_>,_>>()?;headers.insert(name.as_str().to_string(),json!(values));}
 let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
 if status != 200 && !mutant { return Err(format!("approval list: {status}: {body}").into()); }
 let parsed:Value=serde_json::from_str(&body)?;
 if (kind=="foreign" && parsed!=json!({"pendingForMe":[],"myRequests":[]})) || (kind!="foreign"&&(parsed["myRequests"][0]["id"]!=id || parsed["myRequests"][0]["requesterUserId"]!=a.user)) {return Err("list failed to return authenticated fixture".into());}
 let body=body.replace(&format!("\"id\":{id}"),"\"id\":\"<request>\"").replace(&format!("\"requesterUserId\":{}",a.user),"\"requesterUserId\":\"<actor>\"").replace(&format!("\"approverRef\":{}",a.user),"\"approverRef\":\"<actor>\"");
 if let Some(date)=headers.get_mut("date"){if date[0].as_str().is_none_or(|s|chrono::DateTime::parse_from_rfc2822(s).is_err()){return Err("invalid HTTP Date".into());}*date=json!(["<timestamp>"]);}
 if headers.contains_key("content-length"){headers.insert("content-length".into(),json!([body.len().to_string()]));}
 let mut observed=json!({"request":{"method":"GET","path":"/me/approvals","external_path":"/api/me/approvals","query":if kind=="invalid"{"limit=bad&user_id=forged"}else{""}},"response":{"status":status,"headers":headers,"body":body},"effects":[],"audit":[],"notify":[]});
 if kind=="success"{observed["request"].as_object_mut().unwrap().remove("query");}
 if !recording{common::approval_probe::no_go(addr).await?;}
 server.abort();
 let path=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/approvals/goldens/list-{kind}.json"));
 if recording {golden::record(&path,&json!({"format":1,"route":"GET /me/approvals","case":kind,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observed}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;golden::compare(&expected["observation"],&observed)?;eprintln!("GOLDEN-REPLAY: GET /me/approvals :: {kind}");}
 Ok::<_,common::BoxError>(())
 }.await;
    owner
        .execute("DELETE FROM approval_requests WHERE id=$1", &[&id])
        .await?;
    common::remove_blob_account(&owner, &a).await?;
    if let Some(s) = stranger.as_ref() {
        common::remove_blob_account(&owner, s).await?;
    }
    result
}

#[tokio::test]
async fn cancel_pending_request_success() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::cancel().await
}

#[tokio::test]
async fn cancel_foreign_request_is_opaque() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::cancel_case("foreign").await
}

#[tokio::test]
async fn cancel_rejects_malformed_identifier() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::cancel_case("invalid").await
}

#[tokio::test]
async fn cancelled_request_cannot_be_cancelled_twice() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::cancel_case("repeat").await
}

#[tokio::test]
async fn approver_applies_hr_request() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "success").await
}

#[tokio::test]
async fn applied_hr_request_cannot_be_decided_twice() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "repeat").await
}

#[tokio::test]
async fn stranger_cannot_decide_another_request() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "foreign").await
}

#[tokio::test]
async fn decision_requires_approve_or_deny() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "bad-decision").await
}

#[tokio::test]
async fn decision_accepts_go_case_insensitive_fields() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "folded-fields").await
}

#[tokio::test]
async fn null_decision_body_matches_go() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "null-body").await
}

#[tokio::test]
async fn duplicate_decision_and_null_match_go() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "duplicates").await
}

#[tokio::test]
async fn unknown_decision_fields_are_rejected() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "unknown-field").await
}

#[tokio::test]
async fn decision_requires_one_json_object() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "trailing-json").await
}

#[tokio::test]
async fn unicode_decision_key_folding_matches_go() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "unicode-fold").await
}

#[tokio::test]
async fn requester_cannot_approve_own_hr_request() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "requester-sod").await
}

#[tokio::test]
async fn approval_viewer_cannot_decide_without_approver_authority() -> Result<(), common::BoxError>
{
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "visible-non-approver").await
}

#[tokio::test]
async fn governed_admin_lists_policies() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_list().await
}

#[tokio::test]
async fn ungoverned_admin_cannot_list_policies() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_list_case("foreign").await
}

#[tokio::test]
async fn policies_reject_go_unlisted_consumer_filter() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_list_case("invalid").await
}

#[tokio::test]
async fn governed_admin_creates_policy() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("create", "success").await
}

#[tokio::test]
async fn ungoverned_admin_cannot_create_policy() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("create", "foreign").await
}

#[tokio::test]
async fn policy_creation_requires_object_conditions() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("create", "invalid").await
}

#[tokio::test]
async fn repeated_policy_creation_preserves_go_new_policy_semantics() -> Result<(), common::BoxError>
{
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("create", "repeat").await
}

#[tokio::test]
async fn governed_admin_updates_policy() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("update", "success").await
}

#[tokio::test]
async fn governed_admin_deletes_policy() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("delete", "success").await
}

#[tokio::test]
async fn governed_admin_reorders_policies() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("reorder", "success-qualified").await
}

#[tokio::test]
async fn policies_update_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("update", "foreign-qualified").await
}

#[tokio::test]
async fn policies_update_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("update", "invalid").await
}

#[tokio::test]
async fn policies_update_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("update", "repeat").await
}

#[tokio::test]
async fn policies_delete_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("delete", "foreign").await
}

#[tokio::test]
async fn policies_delete_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("delete", "invalid").await
}

#[tokio::test]
async fn policies_delete_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("delete", "repeat").await
}

#[tokio::test]
async fn policies_reorder_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("reorder", "foreign").await
}

#[tokio::test]
async fn policies_reorder_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("reorder", "invalid").await
}

#[tokio::test]
async fn policies_reorder_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("reorder", "repeat").await
}

#[tokio::test]
async fn governed_admin_lists_audit() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("audit", "success").await
}

#[tokio::test]
async fn requester_submits_hr_request() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_submit::run("success-qualified").await
}

#[tokio::test]
async fn email_get_is_prefetch_safe() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-get", "success").await
}

#[tokio::test]
async fn email_post_records_bound_approver_decision() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-post", "success").await
}

#[tokio::test]
async fn approval_notification_matches_frozen_go_tick() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run().await
}

#[tokio::test]
async fn email_get_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-get", "foreign").await
}

#[tokio::test]
async fn email_get_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-get", "invalid").await
}

#[tokio::test]
async fn email_post_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-post", "foreign").await
}

#[tokio::test]
async fn email_post_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-post", "invalid").await
}

#[tokio::test]
async fn email_post_repeat() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-post", "repeat").await
}

#[tokio::test]
async fn audit_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("audit", "foreign").await
}

#[tokio::test]
async fn submit_foreign() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_submit::run("foreign").await
}

#[tokio::test]
async fn audit_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("audit", "invalid").await
}

#[tokio::test]
async fn submit_invalid() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_submit::run("invalid").await
}

#[tokio::test]
async fn list_foreign() -> Result<(), common::BoxError> {
    run_list("foreign").await
}

#[tokio::test]
async fn list_invalid() -> Result<(), common::BoxError> {
    run_list("invalid").await
}

#[tokio::test]
async fn list_rejects_changed_status() -> Result<(), common::BoxError> {
    common::approval_probe::rejected(list_probe("success", true).await, "GET /me/approvals")
}

#[tokio::test]
async fn cancel_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approvals::request_probe("cancel", "success", true).await,
        "POST /me/approvals/{id}/cancel",
    )
}

#[tokio::test]
async fn decide_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approvals::request_probe("decide", "success", true).await,
        "POST /me/approvals/{id}/decide",
    )
}

#[tokio::test]
async fn email_get_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approvals::request_probe("email-get", "success", true).await,
        "GET /approvals/email/{token}",
    )
}

#[tokio::test]
async fn email_post_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approvals::request_probe("email-post", "success", true).await,
        "POST /approvals/email/{token}",
    )
}

#[tokio::test]
async fn submit_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_submit::probe("success-qualified", true).await,
        "POST /me/approvals/hr",
    )
}

#[tokio::test]
async fn policy_list_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_admin::policies_probe("list", "success", true).await,
        "GET /admin/approval-policies",
    )
}

#[tokio::test]
async fn policy_create_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_admin::policies_probe("create", "success", true).await,
        "POST /admin/approval-policies",
    )
}

#[tokio::test]
async fn policy_update_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_admin::policies_probe("update", "success", true).await,
        "PUT /admin/approval-policies/{id}",
    )
}

#[tokio::test]
async fn policy_delete_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_admin::policies_probe("delete", "success", true).await,
        "DELETE /admin/approval-policies/{id}",
    )
}

#[tokio::test]
async fn policy_reorder_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_admin::policies_probe("reorder", "success-qualified", true).await,
        "POST /admin/approval-policies/reorder",
    )
}

#[tokio::test]
async fn policy_audit_rejects_changed_status() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_probe::rejected(
        common::approval_admin::policies_probe("audit", "success", true).await,
        "GET /admin/approval-requests/audit",
    )
}

#[tokio::test]
async fn cancel_rejects_no_audit() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let error = common::approvals::request_fault("cancel", "success", false, Some("no-audit"))
        .await
        .expect_err("family mutant survived")
        .to_string();
    if !error.contains("/audit/") {
        return Err(format!("wrong mutant failure: {error}").into());
    }
    eprintln!("MUTANT-REJECTED: POST /me/approvals/{{id}}/cancel :: no-audit");
    Ok(())
}

#[tokio::test]
async fn cancel_rejects_no_notify() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let error = common::approvals::request_fault("cancel", "success", false, Some("no-notify"))
        .await
        .expect_err("family mutant survived")
        .to_string();
    if !error.contains("/notify/") {
        return Err(format!("wrong mutant failure: {error}").into());
    }
    eprintln!("MUTANT-REJECTED: POST /me/approvals/{{id}}/cancel :: no-notify");
    Ok(())
}

#[tokio::test]
async fn cancel_rejects_no_tenant_filter() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_fault("cancel", "foreign", false, Some("owner-baseline")).await?;
    let error =
        common::approvals::request_fault("cancel", "foreign", false, Some("no-tenant-filter"))
            .await
            .expect_err("family mutant survived")
            .to_string();
    if !error.contains("/response/status") {
        return Err(format!("wrong mutant failure: {error}").into());
    }
    eprintln!("MUTANT-REJECTED: POST /me/approvals/{{id}}/cancel :: no-tenant-filter");
    Ok(())
}

#[tokio::test]
async fn cancel_rejects_double_bump() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let error = common::approvals::request_fault("cancel", "success", false, Some("double-bump"))
        .await
        .expect_err("family mutant survived")
        .to_string();
    if !error.contains("/effects/") {
        return Err(format!("wrong mutant failure: {error}").into());
    }
    eprintln!("MUTANT-REJECTED: POST /me/approvals/{{id}}/cancel :: double-bump");
    Ok(())
}

#[tokio::test]
async fn repeated_hr_submission_creates_another_request() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_submit::run("repeat").await
}

#[tokio::test]
async fn drive_access_approval_requires_epoch() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "drive-access-invalid").await
}

#[tokio::test]
async fn drive_access_missing_detail_rolls_back() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "drive-access-deny-missing").await
}

#[tokio::test]
async fn consumer_rbac_deny() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "consumer-rbac-deny").await
}

#[tokio::test]
async fn consumer_rbac_revoked() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "consumer-rbac-revoked").await
}

#[tokio::test]
async fn consumer_mail_deny() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "consumer-mail-deny").await
}

#[tokio::test]
async fn consumer_group_approve() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "consumer-group-approve").await
}

#[tokio::test]
async fn consumer_drive_export() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "consumer-drive-export").await
}

#[tokio::test]
async fn consumer_drive_share() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "consumer-drive-share").await
}

#[tokio::test]
async fn notify_off() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run_case("off").await
}

#[tokio::test]
async fn notify_role_group() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run_case("role-group").await
}

#[tokio::test]
async fn notify_rbac() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run_case("rbac").await
}

#[tokio::test]
async fn notify_malformed() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run_case("malformed").await
}

#[tokio::test]
async fn notify_fractional_expiry_uses_go_unix_seconds() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run_case("fractional-expiry").await
}

#[tokio::test]
async fn policy_creation_priority_collision_is_conflict() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_admin::policies_case("create", "priority-conflict").await
}

#[tokio::test]
async fn email_signature_accepts_go_crlf() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-get", "signature-crlf").await
}

#[tokio::test]
async fn email_signature_accepts_go_noncanonical_pad_bits() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("email-get", "signature-pad-bits").await
}

#[tokio::test]
async fn decision_projects_acl_conflict_without_sql_detail() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ254").await
}

#[tokio::test]
async fn decision_projects_typed_mail_quota() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ001").await
}

#[tokio::test]
async fn decision_projects_bz008() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ008").await
}

#[tokio::test]
async fn decision_projects_bz002() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ002").await
}

#[tokio::test]
async fn decision_projects_bz004() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ004").await
}

#[tokio::test]
async fn decision_projects_bz141() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ141").await
}

#[tokio::test]
async fn decision_projects_bz252() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ252").await
}

#[tokio::test]
async fn decision_projects_bz253() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ253").await
}

#[tokio::test]
async fn decision_projects_bz256() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approvals::request_case("decide", "project-BZ256").await
}

#[tokio::test]
async fn notify_rbac_skip_uses_go_field_folding() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    common::approval_notify::run_case("folded-rbac").await
}
