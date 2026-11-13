//! HTTP seam for the user recovery incident list.
mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::BodyExt;
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::json;
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::jmap::jwks::{jwk, Jwks};
use setjoin_gateway::recovery::{RecoveryCommands, RecoveryRoute};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use tokio_postgres::types::Type;

/// The gateway's verifying key for a RustCrypto test signer (production
/// verifies ES256 with ring).
fn public(key: &SigningKey) -> setjoin_gateway::jmap::token::VerifyingKey {
    setjoin_gateway::jmap::token::VerifyingKey::from_sec1(
        key.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
enum Case {
    Empty,
    Foreign,
    Visible,
    IgnoredInvalidQuery,
    EdgeBudget,
    Guest,
    Mutant,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_with_no_incidents_receives_empty_list() -> Result<(), common::BoxError> {
    run_case(Case::Empty).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_cannot_list_another_users_incident() -> Result<(), common::BoxError> {
    run_case(Case::Foreign).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_can_list_own_incident() -> Result<(), common::BoxError> {
    run_case(Case::Visible).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_incident_list_ignores_invalid_limit_query() -> Result<(), common::BoxError> {
    run_case(Case::IgnoredInvalidQuery).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn front_door_serves_incidents_after_authenticated_guest_precheck(
) -> Result<(), common::BoxError> {
    run_case(Case::EdgeBudget).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_token_still_forwards_before_the_recovery_route_budget(
) -> Result<(), common::BoxError> {
    run_case(Case::Guest).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(RecoveryRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &hyper::Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        r: hyper::Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<hyper::Response<setjoin_gateway::Body>> {
        let future = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        })
    }
}
#[tokio::test]
async fn incident_oracle_rejects_a_changed_rust_status() -> Result<(), common::BoxError> {
    let error = run_case(Case::Mutant)
        .await
        .expect_err("mutant must disagree with Go");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /recovery/incidents :: changed-status");
    Ok(())
}

async fn run_case(case: Case) -> Result<(), common::BoxError> {
    let case_name = match case {
        Case::Empty | Case::Guest => "recovery-incidents-empty",
        Case::Foreign => "recovery-incidents-foreign",
        Case::Visible | Case::EdgeBudget | Case::Mutant => "recovery-incidents-visible",
        Case::IgnoredInvalidQuery => "recovery-incidents-ignored-invalid-query",
    };
    let Some(db) = Db::for_case(case_name) else {
        return Ok(());
    };
    let _serial = common::recovery::SERIAL.lock().await;
    let owner = db.connect().await?;
    let flag = "feature.client_recovery_ingest";
    let previous = owner
        .query_typed(
            "SELECT enabled FROM feature_toggles WHERE key=$1",
            &[(&flag, Type::TEXT)],
        )
        .await?;
    let previous = previous.first().map(|row| row.get::<_, bool>(0));
    owner.query_typed("INSERT INTO feature_toggles (key,enabled) VALUES ($1,true) ON CONFLICT (key) DO UPDATE SET enabled=true", &[(&flag, Type::TEXT)]).await?;
    let account = fixture::account(&owner, "recovery-list").await?;
    let foreign = if matches!(case, Case::Foreign) {
        Some(fixture::account(&owner, "recovery-foreign").await?)
    } else {
        None
    };
    let incident_owner = match case {
        Case::Empty | Case::Guest => None,
        Case::Foreign => foreign.as_ref(),
        Case::Visible | Case::IgnoredInvalidQuery | Case::EdgeBudget | Case::Mutant => {
            Some(&account)
        }
    };
    let incident = if let Some(other) = incident_owner {
        let rows = owner.query_typed(
            "INSERT INTO mail_recovery_incidents (id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES (gen_random_uuid(),gen_random_uuid(),1,2,'oracle incident',$1,decode(repeat('00',32),'hex'),now()+interval '1 day',gen_random_uuid()) RETURNING id::text",
            &[(&other.user, Type::INT8)],
        ).await?;
        let id: String = rows[0].get(0);
        owner.query_typed(
            "INSERT INTO mail_recovery_incident_accounts (incident_id,mailbox_id,affected_user_id,evidence_token_sha256) VALUES ($1::text::uuid,$2,$3,decode(repeat('00',32),'hex'))",
            &[(&id, Type::TEXT), (&other.mailbox, Type::INT8), (&other.user, Type::INT8)],
        ).await?;
        Some(id)
    } else {
        None
    };
    let result = async {
        let key = SigningKey::from_slice(&[0x11; 32])?;
        let doc = json!({"keys": [jwk("test-es256-1", &public(&key))]}).to_string().into_bytes();
        let jwks = Jwks::with_fetch(Box::new(move || {
            let doc = doc.clone();
            Box::pin(async move { Ok(doc) })
        }));
        let route = RecoveryRoute(Arc::new(RecoveryCommands {
            exec: ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).map_err(|e| e.0)?,
            worker_exec: ScopedExecutor::from_dsn(&db.dsn, 4).map_err(|e| e.0)?,
            keys: jwks,
            issuer: "mailserver".into(),
            denylist: None,
            control_plane_ready: true,
            store: None,
        }));
        let mut inventory: serde_json::Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
        let entry = inventory["routes"].as_array_mut().unwrap().iter_mut().find(|row|
            row["listener"] == "gateway" && row["method"] == "GET" && row["path"] == "/recovery/incidents"
        ).ok_or("recovery incidents inventory entry is absent")?;
        entry["state"] = "ON".into();
        entry["upstream"] = "local-rust".into();
        let oracle=if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() && !matches!(case,Case::Guest|Case::Mutant) {
            let endpoint=common::fake_upstream(|request|async move {
                if request.uri().query()==Some("location=") {hyper::Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
                else {hyper::Response::new(common::full(""))}
            }).await;
            common::go_oracle::start(&db,endpoint).await?
        } else {None};
        let recording = std::env::var("GOFREE_RECORD_UPSTREAM").ok().filter(|v| !v.is_empty()).or_else(||oracle.as_ref().map(|oracle|format!("http://{}",oracle.address)));
        let upstream = if matches!(case, Case::Guest) {
            let address = common::fake_upstream(|request| async move {
                assert!(request.headers().get("authorization").is_some());
                hyper::Response::builder().status(418).body(common::full("go guest decision")).unwrap()
            }).await;
            Some(format!("http://{address}").parse()?)
        } else { recording.as_deref().map(str::parse).transpose()? };
        let routes = if recording.is_some() { RouteTable::proxy_all() } else if matches!(case,Case::Mutant) {RouteTable::proxy_all().with(ChangedStatus(route))} else { RouteTable::proxy_all().with(route) };
        let gateway = Gateway::new(Config {
            upstream,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: if matches!(case, Case::EdgeBudget | Case::Guest) {
                Some(setjoin_gateway::jmap::limit::EdgeLimit::for_front_door(
                    setjoin_gateway::jmap::limit::Limiter::new(600, 60)))
            } else { None },
        }, routes)?.with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let header = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256", "kid":"test-es256-1", "typ":"JWT"}).to_string());
        let mut claims = json!({"uid":account.user,"email":"x@test","typ":"access","jti":"recovery-test","fam":"recovery-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
        if matches!(case, Case::Guest) { claims["acct"] = "guest".into(); }
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
        let token = format!("{header}.{claims}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let path = if matches!(case, Case::IgnoredInvalidQuery) { "/api/recovery/incidents?limit=not-an-integer" } else { "/api/recovery/incidents" };
        let response = common::send(address, hyper::Request::get(path)
            .header("host", "mail.test").header("origin", "http://mail.test")
            .header("x-request-id", "gofree-blobs1-recovery-oracle")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full(""))?).await;
        let status = response.status();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            let values: Result<Vec<_>, _> = response.headers().get_all(name).iter().map(|value| {
                let text = value.to_str()?;
                Ok::<_, hyper::header::ToStrError>(if name == "date" { "<timestamp>".to_owned() } else { text.to_owned() })
            }).collect();
            headers.insert(name.to_string(), json!(values?));
        }
        let body = response.into_body().collect().await?.to_bytes();
        server.abort();
        if let Some(length) = headers.get("content-length").and_then(|v| v[0].as_str()) {
            if length.parse::<usize>()? != body.len() {
                return Err("incorrect response content-length".into());
            }
        }
        if matches!(case, Case::Guest) {
            if status != 418 || body != "go guest decision" {
                return Err(format!("guest did not reach Go unchanged: {status} {body:?}").into());
            }
            return Ok(());
        }
        if status != 200 && !matches!(case,Case::Mutant) {
            return Err(format!("unexpected response: {status} {}", String::from_utf8_lossy(&body)).into());
        }
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        let expected_count = if matches!(case, Case::Visible | Case::IgnoredInvalidQuery | Case::EdgeBudget | Case::Mutant) { 1 } else { 0 };
        if (status != 200 && !matches!(case,Case::Mutant)) || value["list"].as_array().map(Vec::len) != Some(expected_count) {
            return Err(format!("unexpected response: {status} {}", String::from_utf8_lossy(&body)).into());
        }
        let mut normalized_body = String::from_utf8(body.to_vec())?;
        if expected_count == 1 {
            let item = &value["list"][0];
            if item["id"].as_str() != incident.as_deref()
                || item["mailboxId"].as_str() != Some(account.mailbox.to_string().as_str())
            {
                return Err(format!("incident ownership did not match the caller: {item}").into());
            }
            let expected_expiry:String=owner.query_one("SELECT to_jsonb(expires_at)::text FROM mail_recovery_incidents WHERE id=$1::text::uuid AND opened_by=$2",&[&incident.as_ref().unwrap(),&account.user]).await?.get(0);
            if serde_json::to_string(&item["expiresAt"])?!=expected_expiry {return Err("incident expiry differs from fixture DB value".into());}
            for (field, placeholder) in [("id", "<incident>"), ("mailboxId", "<mailbox>"), ("expiresAt", "<expires>")] {
                let original = item[field].as_str().ok_or_else(|| format!("missing {field} in incident"))?;
                normalized_body = normalized_body.replace(&format!("\"{field}\": \"{original}\""), &format!("\"{field}\": \"{placeholder}\""));
            }
            if headers.contains_key("content-length") {
                headers.insert("content-length".into(), json!([normalized_body.len().to_string()]));
            }
        }
        let response = json!({"status":status.as_u16(), "headers":headers, "body":normalized_body});
        let canonical_case=case_name.replacen("recovery-incidents","incident-list",1);
        let observed=json!({"request":{"method":"GET","path":"/recovery/incidents","external_path":path,"headers":{"authorization":"<fixture-access-token>","x-request-id":"gofree-blobs1-recovery-oracle"}},"response":response,"effects":[],"audit":[],"notify":[]});
        let golden_path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/{canonical_case}.json"));
        if recording.is_some() {
            golden::record(&golden_path,&json!({"format":1,"route":"GET /recovery/incidents","case":canonical_case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["response date","verified fixture id/mailbox/DB expiry and adjusted content-length","fixture authorization"],"observation":observed}))?;
        } else {
            let expected:serde_json::Value=serde_json::from_slice(&std::fs::read(golden_path)?)?;
            golden::compare(&expected["observation"],&observed)?;
            eprintln!("GOLDEN-REPLAY: GET /recovery/incidents :: {canonical_case}");
        }
        Ok(())
    }.await;
    if let Some(id) = incident {
        owner
            .query_typed(
                "DELETE FROM mail_recovery_incidents WHERE id=$1::text::uuid",
                &[(&id, Type::TEXT)],
            )
            .await?;
    }
    if let Some(other) = &foreign {
        common::remove_blob_account(&owner, other).await?;
    }
    common::remove_blob_account(&owner, &account).await?;
    match previous {
        Some(enabled) => {
            owner
                .query_typed(
                    "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                    &[(&flag, Type::TEXT), (&enabled, Type::BOOL)],
                )
                .await?;
        }
        None => {
            owner
                .query_typed(
                    "DELETE FROM feature_toggles WHERE key=$1",
                    &[(&flag, Type::TEXT)],
                )
                .await?;
        }
    }
    result
}
