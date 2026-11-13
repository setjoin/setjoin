//! TOTP transport failures at the public auth boundary, with fresh-session recovery.
#[path = "../../gateway/tests/common/commit.rs"]
mod commit;
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
struct Wire(tokio::task::JoinHandle<std::io::Result<commit::CommitCut>>);
impl Drop for Wire {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn removal(cut: commit::CommitCut) {
    let db = Db::for_case("IDMFA1-removal-commit").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let receipt_ids = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa1-commit").await.unwrap();
    c.execute(
        "UPDATE users SET totp_enabled=true,factor_generation=2 WHERE id=$1",
        &[&a.user],
    )
    .await
    .unwrap();
    let b = fixture::account(&c, "idmfa1-commit-foreign").await.unwrap();
    let hash = format!("{:x}", Sha256::digest(b"idmfa1-commit-stepup"));
    c.execute("INSERT INTO totp_removal_step_ups(token_hash,user_id,session_jti,expires_at) VALUES($1,$2,'idmfa1-commit',now()+interval '5 minutes')",&[&hash,&a.user]).await.unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"uid":a.user,"typ":"access","jti":"idmfa1-commit","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600});
    let token = setjoin_authz::legacy_jwt::sign_hs256(
        f["secret"].as_str().unwrap().as_bytes(),
        &claims.to_string(),
    );
    let (dsn, task) = commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
    let mut wire = Wire(task);
    let server = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 1).unwrap(),
        Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    let response = server
        .handle(
            Request::post("/auth/totp/remove")
                .header("authorization", format!("Bearer {token}"))
                .body(body(
                    json!({"step_up_token":"idmfa1-commit-stepup","confirm":"REMOVE"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    let status = response.status();
    let operation = response
        .headers()
        .get("x-operation-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    assert!(!response.headers().contains_key("set-cookie"));
    let raw = response.into_body().collect().await.unwrap().to_bytes();
    drop(server);
    let observed = tokio::time::timeout(std::time::Duration::from_secs(10), &mut wire.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let lookup_exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )
    .unwrap();
    let proof =
        setjoin_identity::session::Session::verify(&token, None, &legacy, "mailserver").unwrap();
    let op = setjoin_contracts::ids::OperationId(
        *uuid::Uuid::parse_str(operation.as_deref().unwrap())
            .unwrap()
            .as_bytes(),
    );
    let found = setjoin_identity::totp::lookup_operation(
        &lookup_exec,
        &proof,
        op,
        setjoin_identity::totp::Operation::Remove,
    )
    .await
    .unwrap();
    let mut foreign_claims = claims.clone();
    foreign_claims["uid"] = json!(b.user);
    let foreign = setjoin_authz::legacy_jwt::sign_hs256(
        f["secret"].as_str().unwrap().as_bytes(),
        &foreign_claims.to_string(),
    );
    let foreign =
        setjoin_identity::session::Session::verify(&foreign, None, &legacy, "mailserver").unwrap();
    assert!(!setjoin_identity::totp::lookup_operation(
        &lookup_exec,
        &foreign,
        op,
        setjoin_identity::totp::Operation::Remove
    )
    .await
    .unwrap());
    let clean = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap(),
        Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    let recovered = clean
        .handle(
            Request::get("/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(body(""))
                .unwrap(),
        )
        .await;
    assert_eq!(recovered.status(), 200);
    let recovered: Value =
        serde_json::from_slice(&recovered.into_body().collect().await.unwrap().to_bytes()).unwrap();
    drop(clean);
    let rows=c.query_one("SELECT factor_generation,(SELECT count(*) FROM admin_audit_log WHERE user_id=$1 AND action='totp_removed'),(SELECT count(*) FROM totp_removal_step_ups WHERE user_id=$1) FROM users WHERE id=$1",&[&a.user]).await.unwrap();
    let generation: i64 = rows.get(0);
    let audits: i64 = rows.get(1);
    let stepups: i64 = rows.get(2);
    c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={};COMMIT",a.user)).await.unwrap();
    c.execute(
        "DELETE FROM totp_removal_step_ups WHERE user_id=$1",
        &[&a.user],
    )
    .await
    .unwrap();
    c.execute("UPDATE users SET enabled=false WHERE id=$1", &[&a.user])
        .await
        .unwrap();
    assert!(setjoin_identity::totp::lookup_operation(
        &lookup_exec,
        &proof,
        op,
        setjoin_identity::totp::Operation::Remove
    )
    .await
    .is_err());
    fixture::remove(&c, &a).await.unwrap();
    fixture::remove(&c, &b).await.unwrap();
    common::restore_receipts(&c, &receipt_ids).await;
    assert_eq!(observed, cut);
    assert_eq!(status, 503);
    assert!(operation.is_some_and(|op| uuid::Uuid::parse_str(&op).is_ok()));
    assert!(!String::from_utf8_lossy(&raw).contains("idmfa1-commit-stepup"));
    let committed = cut == commit::CommitCut::AfterCommit;
    assert_eq!(found, committed);
    assert_eq!(recovered["totp_enabled"], !committed);
    assert_eq!(generation, if committed { 3 } else { 2 });
    assert_eq!(audits, i64::from(committed));
    assert_eq!(stepups, i64::from(!committed));
}
#[tokio::test]
async fn removal_unknown_before_commit_preserves_factor_and_stepup() {
    removal(commit::CommitCut::BeforeCommit).await;
}
#[tokio::test]
async fn removal_unknown_after_commit_recovers_disabled_factor_once() {
    removal(commit::CommitCut::AfterCommit).await;
}
