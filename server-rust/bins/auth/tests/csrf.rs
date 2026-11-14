//! Browser login reaches the decoder after Go's connection/forwarded-header CSRF derivation.
use http_body_util::BodyExt;
use hyper::Request;
use setjoin_auth::{body, AuthServer, ConnectionMeta};

#[tokio::test]
async fn browser_login_uses_direct_tls_and_sanitizes_forwarded_host() {
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN required");
    let (c, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(conn);
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    let flags: String = c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key=ANY($1::text[])", &[&vec!["feature.rate_limit","feature.conditional_access","feature.device_trust_enforcement"]]).await.unwrap().get(0);
    c.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false),('feature.conditional_access',false),('feature.device_trust_enforcement',false) ON CONFLICT(key) DO UPDATE SET enabled=false").await.unwrap();
    let server = AuthServer::new(setjoin_pg::ScopedExecutor::from_dsn(&dsn, 2).unwrap())
        .with_threat_gate(&dsn)
        .await
        .unwrap();
    let mut results = Vec::new();
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/security/csrf.json"
    ))
    .unwrap();
    let ipv6: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/security/csrf-ipv6.json"
    ))
    .unwrap();
    for case in golden["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(ipv6["cases"].as_array().unwrap())
    {
        let tls = case["tls"].as_bool().unwrap();
        let proto = case["proto"].as_str().unwrap();
        let host = case["host"].as_str().unwrap();
        let mut req = Request::post("/auth/login")
            .header("host", case["request_host"].as_str().unwrap_or("mail.test"))
            .header(
                "origin",
                case["origin"].as_str().unwrap_or("https://mail.test"),
            )
            .header("x-forwarded-proto", proto)
            .header("x-forwarded-host", host)
            .body(body("{"))
            .unwrap();
        req.extensions_mut().insert(ConnectionMeta {
            peer: "127.0.0.1:12345".parse().unwrap(),
            tls,
        });
        let resp = server.handle(req).await;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        results.push((case, status, String::from_utf8(bytes.to_vec()).unwrap()));
    }
    c.batch_execute("DELETE FROM feature_toggles WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.device_trust_enforcement')").await.unwrap();
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&flags]).await.unwrap();
    drop(c);
    driver.abort();
    for (case, status, body) in results {
        assert_eq!(status, case["status"].as_u64().unwrap() as u16, "{case}");
        assert_eq!(body, case["body"].as_str().unwrap());
    }
}

#[tokio::test]
async fn browser_login_credentials_over_direct_tls_and_malformed_forwarded_host() {
    use serde_json::{json, Value};
    use setjoin_conformance::{fixture, golden, harness::Db};
    let db = Db::for_case("IDLOGIN2-csrf-success").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let envelope = f["envelope"].as_str().unwrap();
    let envelope: Vec<u8> = (0..envelope.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&envelope[i..i + 2], 16).unwrap())
        .collect();
    c.execute("DELETE FROM signing_keys", &[]).await.unwrap();
    c.execute("INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES($1,'ES256',$2::text::jsonb,$3,'active')",&[&f["kid"].as_str().unwrap(),&f["jwks"]["keys"][0].to_string(),&envelope]).await.unwrap();
    let a = fixture::account(&c, "idlogin2-csrf").await.unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4).unwrap(), &a.user],
    )
    .await
    .unwrap();
    let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.rate_limit'",&[]).await.unwrap().get(0);
    c.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false").await.unwrap();
    let receipts: Vec<String> = c
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F21'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let server = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        setjoin_auth::Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap()
    .with_threat_gate(&db.dsn)
    .await
    .unwrap();
    let record = std::env::var_os("GOFREE_RECORD_CSRF_SUCCESS").is_some();
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )
    .unwrap();
    let mut observations = Vec::new();
    for (tls, proto, forwarded_host) in [
        (true, "", ""),
        (false, "https", "bad.example,mail.test"),
        (false, "https", "bad host"),
    ] {
        let input = json!({"email":email,"password":"Password1!"}).to_string();
        let (status, raw) = if record {
            let url = if tls {
                "https://127.0.0.1:48433/auth/login"
            } else {
                "http://127.0.0.1:48432/auth/login"
            };
            let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/gofree-idlogin2-tools/tls.crt");
            let output = std::process::Command::new("curl")
                .args([
                    "--silent",
                    "--show-error",
                    "--cacert",
                    ca.to_str().unwrap(),
                    "-i",
                    "-X",
                    "POST",
                    url,
                    "-H",
                    "Host: mail.test",
                    "-H",
                    "Origin: https://mail.test",
                    "-H",
                    &format!("X-Forwarded-Proto: {proto}"),
                    "-H",
                    &format!("X-Forwarded-Host: {forwarded_host}"),
                    "--data-binary",
                    &input,
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let wire = String::from_utf8(output.stdout).unwrap();
            let (head, raw) = wire.split_once("\r\n\r\n").unwrap();
            (
                head.split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<u16>()
                    .unwrap(),
                raw.to_owned(),
            )
        } else {
            let mut req = Request::post("/auth/login")
                .header("host", "mail.test")
                .header("origin", "https://mail.test")
                .header("x-forwarded-proto", proto)
                .header("x-forwarded-host", forwarded_host)
                .body(body(input))
                .unwrap();
            req.extensions_mut().insert(ConnectionMeta {
                peer: "127.0.0.1:12345".parse().unwrap(),
                tls,
            });
            let resp = server.handle(req).await;
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        };
        assert_eq!(status, 200, "{raw}");
        let value: Value = serde_json::from_str(&raw).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let access = legacy
            .validate(
                value["access_token"].as_str().unwrap(),
                "mailserver",
                "mailserver-gateway",
                now,
            )
            .expect("verified access");
        let refresh = legacy
            .validate(
                value["refresh_token"].as_str().unwrap(),
                "mailserver",
                "mailserver-gateway",
                now,
            )
            .expect("verified refresh");
        assert_eq!(access["uid"], a.user);
        assert_eq!(refresh["uid"], a.user);
        assert_eq!(access["fam"], refresh["fam"]);
        observations.push(json!({"tls":tls,"proto":proto,"forwarded_host":forwarded_host,"status":status,"access_type":access["typ"],"refresh_type":refresh["typ"],"verified_principal":true,"same_family":true}));
    }
    drop(server);
    c.execute("DELETE FROM rust_operation_receipts WHERE family='F21' AND operation_id::text<>ALL($1::text[])",&[&receipts]).await.unwrap();
    c.execute("DELETE FROM auth_event_log WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    c.execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    fixture::remove(&c, &a).await.unwrap();
    c.batch_execute("DELETE FROM feature_toggles WHERE key='feature.rate_limit'")
        .await
        .unwrap();
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&flags]).await.unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-login/security/csrf-success.json");
    let value = json!({"format":1,"go_source":f["go_source"],"route":"POST /auth/login","cases":observations});
    if record && !path.exists() {
        golden::record(&path, &value).unwrap();
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        golden::compare(&expected, &value).unwrap();
    }
}
