//! Public WebAuthn routes under lost COMMIT replies, with actor-bound recovery.
#[path = "common/webauthn_commit.rs"]
mod commit;
mod common;
use base64::Engine;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_identity::webauthn::{CookieCipher, Operation};
use sha2::{Digest, Sha256};
struct Wire(tokio::task::JoinHandle<std::io::Result<commit::CommitCut>>);
impl Drop for Wire {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn lost_reply(kind: &str, cut: commit::CommitCut) {
    let db = Db::for_case("IDMFA2-commit").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let rate = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await.unwrap();
    let a = fixture::account(&c, "idmfa2-commit").await.unwrap();
    let b = fixture::account(&c, "idmfa2-commit-foreign").await.unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-webauthn/vectors.json"
    ))
    .unwrap();
    let v = &vectors["cases"][0];
    let decode = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .unwrap()
    };
    let id = decode(v["id"].as_str().unwrap());
    let handle = decode(v["handle"].as_str().unwrap());
    let raw_key = v["key"].as_str().unwrap();
    let key: Vec<u8> = (0..raw_key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw_key[i..i + 2], 16).unwrap())
        .collect();
    c.execute(
        "UPDATE users SET webauthn_user_handle=$2 WHERE id=$1",
        &[&a.user, &handle],
    )
    .await
    .unwrap();
    let stored_id = if kind == "register-finish" {
        b"proving-key".to_vec()
    } else {
        id.clone()
    };
    c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,$3,'none',7,'Original',now(),true)",&[&stored_id,&a.user,&key]).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"uid":a.user,"typ":"access","jti":"idmfa2-commit","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600});
    let sign = |value: &Value| {
        setjoin_authz::legacy_jwt::sign_hs256(
            f["secret"].as_str().unwrap().as_bytes(),
            &value.to_string(),
        )
    };
    let token = sign(&claims);
    let proof_hash = format!("{:x}", Sha256::digest(b"idmfa2-proof"));
    let challenge_hash = format!(
        "{:x}",
        Sha256::digest(v["challenge"].as_str().unwrap().as_bytes())
    );
    let target = if kind == "register-finish" {
        Some(challenge_hash.clone())
    } else if kind == "revoke" {
        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&id))
    } else {
        None
    };
    if matches!(kind, "register-begin" | "register-finish" | "revoke") {
        let operation = if kind == "revoke" {
            "webauthn.revoke"
        } else {
            "webauthn.register"
        };
        c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,target_ref,proof_method,proving_factor_id,bound_factor_generation,token_scope,expires_at) VALUES($1,$2,'idmfa2-commit',$3,$4,'webauthn_uv',$5,0,'session',now()+interval '5 minutes')",&[&proof_hash,&a.user,&operation,&target,&stored_id]).await.unwrap();
    }
    if kind == "register-finish" {
        c.execute("INSERT INTO webauthn_ceremonies(challenge_hash,user_id,kind,operation,target_ref,session_jti,token_scope,expires_at) VALUES($1,$2,'registration','webauthn.register',$1,'idmfa2-commit','session',now()+interval '5 minutes')",&[&challenge_hash,&a.user]).await.unwrap();
    }
    let codec = CookieCipher::new(f["secret"].as_str().unwrap().as_bytes());
    let mut session = json!({"challenge":v["challenge"],"rpId":"localhost","user_id":base64::engine::general_purpose::STANDARD.encode(&handle),"expires":"0001-01-01T00:00:00Z"});
    let (method, path, payload, operation) = match kind {
        "name" => (
            "PUT",
            format!(
                "/auth/webauthn/credential/{}/name",
                v["id"].as_str().unwrap()
            ),
            json!({"device_name":"New"}).to_string(),
            Operation::Name,
        ),
        "revoke" => (
            "DELETE",
            format!("/auth/webauthn/credential/{}", v["id"].as_str().unwrap()),
            String::new(),
            Operation::Revoke,
        ),
        "register-begin" => (
            "GET",
            "/auth/webauthn/register/begin".into(),
            String::new(),
            Operation::RegisterBegin,
        ),
        "register-finish" => (
            "POST",
            "/auth/webauthn/register/finish".into(),
            v["registration"].to_string(),
            Operation::RegisterFinish,
        ),
        "counter" | "mint" => (
            "POST",
            "/auth/webauthn/login/finish".into(),
            v["assertions"]["success"]["request"].to_string(),
            if kind == "mint" {
                Operation::Mint
            } else {
                Operation::Counter
            },
        ),
        _ => unreachable!(),
    };
    let cookie = if matches!(kind, "counter" | "mint") {
        session["allowed_credentials"] =
            json!([base64::engine::general_purpose::STANDARD.encode(&id)]);
        format!(
            "wa_login_sess={}; wa_login_uid={}",
            codec.seal(session.to_string().as_bytes()).unwrap(),
            codec.seal(a.user.to_string().as_bytes()).unwrap()
        )
    } else {
        session["credParams"] = json!([{"type":"public-key","alg":-7}]);
        format!(
            "wa_reg_sess={}",
            codec.seal(session.to_string().as_bytes()).unwrap()
        )
    };
    let command = match kind {
        "name" => "webauthn-name",
        "counter" => "webauthn-counter",
        "mint" => "webauthn-mint",
        "revoke" => "webauthn-revoke",
        "register-begin" => "webauthn-register-begin",
        "register-finish" => "webauthn-register-finish",
        _ => unreachable!(),
    };
    let (dsn, task) =
        commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut, command).await;
    let mut wire = Wire(task);
    let server = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 1).unwrap(),
        Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    let response = server
        .handle(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("x-mfa-reauth", "idmfa2-proof")
                .header("cookie", cookie)
                .body(body(payload))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), 503, "{kind} {cut:?}");
    assert!(!response.headers().contains_key("set-cookie"));
    let op = setjoin_contracts::ids::OperationId(
        *uuid::Uuid::parse_str(response.headers()["x-operation-id"].to_str().unwrap())
            .unwrap()
            .as_bytes(),
    );
    let raw = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&raw).contains("idmfa2-proof"));
    drop(server);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut wire.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        cut
    );
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )
    .unwrap();
    let proof =
        setjoin_identity::session::Session::verify(&token, None, &legacy, "mailserver").unwrap();
    let committed = cut == commit::CommitCut::AfterCommit;
    assert_eq!(
        setjoin_identity::webauthn::lookup_operation(&exec, &proof, op, operation)
            .await
            .unwrap(),
        committed
    );
    let mut foreign = claims.clone();
    foreign["uid"] = json!(b.user);
    let foreign = sign(&foreign);
    let foreign =
        setjoin_identity::session::Session::verify(&foreign, None, &legacy, "mailserver").unwrap();
    assert!(
        !setjoin_identity::webauthn::lookup_operation(&exec, &foreign, op, operation)
            .await
            .unwrap()
    );
    let generation: i64 = c
        .query_one(
            "SELECT factor_generation FROM users WHERE id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    let audits: i64 = c
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE user_id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    let grants: i64 = c
        .query_one(
            "SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    let ceremonies: i64 = c
        .query_one(
            "SELECT count(*) FROM webauthn_ceremonies WHERE user_id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    let credentials=c.query("SELECT id,device_name,sign_count,revoked_at IS NOT NULL FROM passkey_credentials WHERE user_id=$1 ORDER BY id",&[&a.user]).await.unwrap();
    let refresh: i64 = c
        .query_one(
            "SELECT count(*) FROM oauth_tokens WHERE user_id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        refresh,
        i64::from(kind == "mint" && committed),
        "only the selected mint transaction can create an anchor"
    );
    let sessions: i64 = c
        .query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        sessions, 0,
        "unknown writes never start sign-in/session tails"
    );
    assert_eq!(
        generation,
        i64::from(committed && matches!(kind, "register-finish" | "revoke"))
    );
    assert_eq!(audits, generation);
    match kind {
        "name" => assert_eq!(
            credentials[0].get::<_, String>(1),
            if committed { "New" } else { "Original" }
        ),
        "counter" | "mint" => assert_eq!(
            credentials[0].get::<_, i32>(2),
            if kind == "mint" || committed { 8 } else { 7 }
        ),
        "revoke" => {
            assert_eq!(credentials[0].get::<_, bool>(3), committed);
            assert_eq!(grants, i64::from(!committed));
        }
        "register-begin" => {
            assert_eq!(ceremonies, i64::from(committed));
            let bound: bool = c
                .query_one(
                    "SELECT target_ref IS NOT NULL FROM mfa_reauth_step_ups WHERE user_id=$1",
                    &[&a.user],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(bound, committed);
        }
        "register-finish" => {
            assert_eq!(credentials.len(), if committed { 2 } else { 1 });
            assert_eq!(grants, i64::from(!committed));
            assert_eq!(ceremonies, i64::from(!committed));
        }
        _ => unreachable!(),
    }
    c.execute("INSERT INTO session_revocations(scope,user_id,jti,reason,expires_at) VALUES('jti',$1,'idmfa2-commit','idmfa2 fault authority',now()+interval '1 hour')",&[&a.user]).await.unwrap();
    assert!(
        setjoin_identity::webauthn::lookup_operation(&exec, &proof, op, operation)
            .await
            .is_err()
    );
    fixture::remove(&c, &a).await.unwrap();
    fixture::remove(&c, &b).await.unwrap();
    common::restore_receipts(&c, &receipts).await;
    if let Some(value) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&value],
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
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
}
macro_rules! fault {
    ($name:ident,$kind:literal,$cut:ident) => {
        #[tokio::test]
        async fn $name() {
            lost_reply($kind, commit::CommitCut::$cut).await;
        }
    };
}
fault!(name_before_commit, "name", BeforeCommit);
fault!(name_after_commit, "name", AfterCommit);
fault!(revoke_before_commit, "revoke", BeforeCommit);
fault!(revoke_after_commit, "revoke", AfterCommit);
fault!(begin_before_commit, "register-begin", BeforeCommit);
fault!(begin_after_commit, "register-begin", AfterCommit);
fault!(registration_before_commit, "register-finish", BeforeCommit);
fault!(registration_after_commit, "register-finish", AfterCommit);
fault!(counter_before_commit, "counter", BeforeCommit);
fault!(counter_after_commit, "counter", AfterCommit);

fault!(mint_before_commit, "mint", BeforeCommit);
fault!(mint_after_commit, "mint", AfterCommit);
