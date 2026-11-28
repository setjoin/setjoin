//! #333 HTTP/COMMIT wire-loss oracle: never report successful revocation on Unknown.
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
async fn check(cut: commit::CommitCut) {
    let db = Db::for_case("IDLOGIN3-revoke-commit").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let actor = fixture::account(&c, "idlogin3-commit").await.unwrap();
    let token = "idlogin3-fault-token";
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    c.execute("INSERT INTO oauth_tokens(user_id,token_hash,token_type,issued_at,expires_at) VALUES($1,$2,'access','2026-01-02T03:04:05Z','2036-01-02T03:04:05Z')",&[&actor.user,&hash]).await.unwrap();
    let (dsn, task) = commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
    let mut wire = Wire(task);
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let mut config = Config::for_secret(f["secret"].as_str().unwrap().into());
    config.internal_api_key = "idlogin3-internal-test-key".into();
    let server = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 1).unwrap(),
        config,
    )
    .await
    .unwrap();
    let response = server
        .handle(
            Request::post("/auth/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", "Bearer idlogin3-internal-test-key")
                .body(body(format!("token={token}")))
                .unwrap(),
        )
        .await;
    let status = response.status();
    let operation = response
        .headers()
        .get("x-operation-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let raw = response.into_body().collect().await.unwrap().to_bytes();
    drop(server);
    let observed = tokio::time::timeout(std::time::Duration::from_secs(10), &mut wire.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let revoked: bool = c
        .query_one(
            "SELECT revoked_at IS NOT NULL FROM oauth_tokens WHERE user_id=$1 AND token_hash=$2",
            &[&actor.user, &hash],
        )
        .await
        .unwrap()
        .get(0);
    // Fresh service authentication recovers the external token state via RFC7662.
    let mut config = Config::for_secret(f["secret"].as_str().unwrap().into());
    config.internal_api_key = "idlogin3-internal-test-key".into();
    let clean = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap(),
        config,
    )
    .await
    .unwrap();
    let recovered = clean
        .handle(
            Request::post("/auth/introspect")
                .header("content-type", "application/json")
                .header("authorization", "Bearer idlogin3-internal-test-key")
                .body(body(json!({"token":token}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(recovered.status(), 200);
    let recovered: Value =
        serde_json::from_slice(&recovered.into_body().collect().await.unwrap().to_bytes()).unwrap();
    fixture::remove(&c, &actor).await.unwrap();
    assert_eq!(observed, cut, "fault did not reach COMMIT");
    assert_eq!(status, 503, "Unknown must not serialize success");
    assert!(operation.is_some_and(|s| uuid::Uuid::parse_str(&s).is_ok()));
    assert!(!String::from_utf8_lossy(&raw).contains(token));
    let committed = cut == commit::CommitCut::AfterCommit;
    assert_eq!(revoked, committed);
    assert_eq!(recovered["active"], !committed);
}
#[tokio::test]
async fn revoke_commit_lost_before_write_is_unknown_and_still_active() {
    check(commit::CommitCut::BeforeCommit).await;
}
#[tokio::test]
async fn revoke_commit_lost_after_write_is_unknown_and_inactive() {
    check(commit::CommitCut::AfterCommit).await;
}
