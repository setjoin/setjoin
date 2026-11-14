//! Authentication is user-scoped, including people without a mailbox. A lost
//! COMMIT never releases bearer credentials; lookup requires current password proof.
#[path = "../../gateway/tests/common/commit.rs"]
mod commit;
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
struct Wire(tokio::task::JoinHandle<std::io::Result<commit::CommitCut>>);
impl Drop for Wire {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn check(cut: commit::CommitCut) {
    let db = Db::for_case("IDLOGIN1-commit").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let actor = fixture::account(&c, "idlogin1-fault").await.unwrap();
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4).unwrap(), &actor.user],
    )
    .await
    .unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&actor.user])
        .await
        .unwrap()
        .get(0);
    let old = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await.unwrap();
    let (dsn, task) = commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
    let mut wire = Wire(task);
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&dsn, 1).unwrap();
    let server = AuthServer::load(
        exec,
        Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap()
    .with_threat_gate(&db.dsn)
    .await
    .unwrap();
    let response = server
        .handle(
            Request::post("/auth/login")
                .body(body(
                    json!({"email":email,"password":"Password1!"}).to_string(),
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
    let cookie = response.headers().contains_key("set-cookie");
    let response_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let response_text = std::str::from_utf8(&response_bytes).unwrap();
    assert!(!response_text.contains("access_token") && !response_text.contains("refresh_token"));
    drop(server);
    let observed = tokio::time::timeout(std::time::Duration::from_secs(10), &mut wire.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        observed, cut,
        "fault did not reach the intended COMMIT boundary"
    );
    let rows: i64 = c
        .query_one(
            "SELECT count(*) FROM oauth_tokens WHERE user_id=$1",
            &[&actor.user],
        )
        .await
        .unwrap()
        .get(0);
    let lookup = if let Some(ref id) = operation {
        let clean =
            setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
        let proof = setjoin_identity::login::verify(&clean, &email, "Password1!", setjoin_config_secret::CryptoProfile::Standard)
            .await
            .unwrap()
            .unwrap();
        let found = setjoin_identity::login::lookup_mint(&clean, &proof, id)
            .await
            .unwrap();
        c.execute(
            "UPDATE users SET password_hash=$1 WHERE id=$2",
            &[&bcrypt::hash("Changed1!", 4).unwrap(), &actor.user],
        )
        .await
        .unwrap();
        assert!(
            !setjoin_identity::login::lookup_mint(&clean, &proof, id)
                .await
                .unwrap(),
            "old password proof recovered an operation after credential replacement"
        );
        Some(found)
    } else {
        None
    };
    c.execute("DELETE FROM auth_event_log WHERE email=$1", &[&email])
        .await
        .unwrap();
    fixture::remove(&c, &actor).await.unwrap();
    if let Some(v) = old {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&v],
        )
        .await
        .unwrap();
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap();
    }
    assert_eq!(
        status, 503,
        "lost COMMIT must not report successful credentials"
    );
    assert!(!cookie);
    assert!(operation.is_some());
    let committed = cut == commit::CommitCut::AfterCommit;
    assert_eq!(rows, if committed { 1 } else { 0 });
    assert_eq!(lookup, Some(committed));
}
#[tokio::test]
async fn lost_commit_before_write_has_no_credentials_and_lookup_is_absent() {
    check(commit::CommitCut::BeforeCommit).await;
}
#[tokio::test]
async fn lost_commit_after_write_has_no_credentials_and_lookup_finds_one_anchor() {
    check(commit::CommitCut::AfterCommit).await;
}
