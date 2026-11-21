//! F21 `gateway * /auth/admin/` (#365) frozen-Go oracle and native replay.
//!
//! Separated from `platform_oracle/terms.rs` because `#365` owns F21 `* /auth/admin/`,
//! not F08 `/admin/*` / `/terms/*`. Reuses `platform_oracle` fixture, masking, token,
//! and rate-limit helpers.
use super::terms::{expand, whole_window};
use super::{admin_token, mask_uuids, masked, record};
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    auth_admin::AuthAdminRoute, catchall::CatchallRoute, jmap::jwks::Jwks, Body, BoxFuture, Config,
    Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Case {
    method: &'static str,
    external: &'static str,
    perm: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    status: u16,
    burst: Option<usize>,
}

struct Probe {
    inner: AuthAdminRoute<Jwks>,
    changed_status: bool,
}

impl Intercept for Probe {
    fn requires_session(&self, r: &Request<Body>) -> bool {
        self.inner.requires_session(r)
    }

    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }

    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }

    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

fn spec(label: &str) -> Option<Case> {
    let mut c = Case {
        method: "GET",
        external: "/auth/admin/unknown",
        perm: "identity.write",
        headers: vec![],
        status: 404,
        burst: None,
    };
    match label {
        "success" => {}
        "head" => c.method = "HEAD",
        "post" => c.method = "POST",
        "denied" => {
            c.perm = "users.read";
            c.headers
                .push(("authorization", "Bearer {token-claims-identity-write}"));
            c.status = 403;
        }
        "unauthenticated" => {
            c.headers.push(("authorization", ""));
            c.status = 401;
        }
        "bad-sig" => {
            c.headers
                .push(("authorization", "Bearer {token-bad-signature}"));
            c.status = 401;
        }
        "expired" => {
            c.headers.push(("authorization", "Bearer {token-expired}"));
            c.status = 401;
        }
        "alg-none" => {
            c.headers.push(("authorization", "Bearer {token-alg-none}"));
            c.status = 401;
        }
        "basic-auth" => {
            c.headers.push(("authorization", "Basic dXNlcjpwYXNz"));
            c.status = 401;
        }
        "guest" => {
            c.headers.push(("authorization", "Bearer {token-guest}"));
            c.status = 401;
        }
        "csrf" => {
            c.method = "POST";
            c.headers.push(("origin", "https://evil.test"));
            c.status = 403;
        }
        "rate-limit" => {
            c.burst = Some(20);
            c.status = 429;
        }
        "bare" => {
            c.external = "/auth/admin";
            c.headers.push(("authorization", ""));
            c.status = 307;
        }
        "bare-query" => {
            c.external = "/auth/admin?next=1";
            c.status = 307;
        }
        "bare-post" => {
            c.method = "POST";
            c.external = "/auth/admin";
            c.status = 307;
        }
        "bare-api" => {
            c.external = "/api/auth/admin";
            c.status = 307;
        }
        "api-alias" => {
            c.external = "/api/auth/admin/unknown";
        }
        "api-alias-denied" => {
            c.method = "POST";
            c.external = "/api/auth/admin/unknown";
            c.perm = "users.read";
            c.status = 403;
        }
        "escaped" => {
            c.external = "/auth/%61dmin/unknown";
        }
        "get-impersonate" => {
            c.external = "/auth/admin/users/1/impersonate";
        }
        "get-impersonate-denied" => {
            c.external = "/auth/admin/users/1/impersonate";
            c.perm = "users.read";
            c.status = 403;
        }
        "get-impersonate-unauth" => {
            c.external = "/auth/admin/users/1/impersonate";
            c.headers.push(("authorization", ""));
            c.status = 401;
        }
        _ => return None,
    }
    Some(c)
}

fn build_request(case: &Case, user: i64) -> Result<Request<Body>, BoxError> {
    let named = |wanted: &str| case.headers.iter().find(|(name, _)| *name == wanted);
    let mut request = Request::builder()
        .method(case.method)
        .uri(case.external)
        .header("host", "mail.test");
    let origin = named("origin").map_or("http://mail.test", |(_, v)| *v);
    if !origin.is_empty() {
        request = request.header("origin", origin);
    }
    request = request.header("x-request-id", "gofree-auth-admin-oracle");
    let auth = named("authorization").map_or_else(
        || format!("Bearer {}", admin_token(user)),
        |(_, v)| expand(v, user),
    );
    if !auth.is_empty() {
        request = request.header("authorization", auth);
    }
    Ok(request.body(common::full(""))?)
}

pub async fn run(label: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = super::SERIAL.lock().await;
    let case = spec(label).ok_or_else(|| format!("unknown auth-admin case: {label}"))?;
    let db = Db::for_case("gofree-auth-admin-365").expect("database required");
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "authadmin-actor").await?;
    let users: Vec<(i64, &str)> = vec![(a.user, "<admin>")];
    let domain_a: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
        .await?
        .get(0);
    let role = format!("authadmin-role-{}", a.user);
    let permissions = vec![case.perm];
    owner
        .execute(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL)",
            &[&role, &permissions],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2",
            &[&a.user, &role],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F08'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect();

    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let authserver_stub = common::fake_upstream(|req| async move {
            let mut resp = Response::new(common::full(if req.method() == hyper::Method::HEAD {
                ""
            } else {
                "404 page not found\n"
            }));
            *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
            resp.headers_mut()
                .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
            resp
        })
        .await;
        let auth_env = [("AUTHSERVER_URL", format!("http://{authserver_stub}"))];
        let go = common::go_oracle::start_named_with_env(&db, s3, "gofree-auth-admin", &auth_env)
            .await?;
        let recording = go.is_some();

        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts {
                pool_wait: patient,
                create: patient,
                statement: patient,
            },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn_with(
            &db.dsn,
            4,
            setjoin_pg::Timeouts {
                pool_wait: patient,
                create: patient,
                statement: patient,
            },
        )
        .map_err(|e| e.0)?;

        let adapter = Probe {
            inner: AuthAdminRoute::new(exec, Arc::new(common::recovery_keys()), "mailserver".into()),
            changed_status: mutant,
        };
        let mut inventory: Value =
            serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["listener"] == "gateway" && r["path"] == "/auth/admin/" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let edge_limit = (!recording && case.burst.is_some()).then(|| {
            setjoin_gateway::jmap::limit::EdgeLimit::new(
                setjoin_gateway::jmap::limit::Limiter::new(100_000, 60),
                Arc::new(|| -> BoxFuture<bool> { Box::pin(async { true }) }),
            )
        });
        let table = if recording {
            RouteTable::proxy_all()
        } else {
            RouteTable::proxy_all()
                .with(adapter)
                .with_admission(worker, Arc::new(common::recovery_keys()), "mailserver".into(), None)
                .with_catchall(CatchallRoute::new())
        };
        let gateway = Gateway::new(
            Config {
                upstream: go
                    .as_ref()
                    .map(|g| format!("http://{}", g.address).parse())
                    .transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit,
            },
            table,
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));

        let last: i64 = owner
            .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
            .await?
            .get(0);
        if let Some(spend) = case.burst {
            whole_window(900).await?;
            for _ in 0..spend {
                let spent = common::send(address, build_request(&case, a.user)?).await;
                let st = spent.status().as_u16();
                let _ = common::body_bytes(spent).await;
                if st == 429 {
                    return Err("auth-admin/rate-limit: budget spent before burst ended".into());
                }
            }
        }
        let response = common::send(address, build_request(&case, a.user)?).await;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(
                name.to_string(),
                json!(response
                    .headers()
                    .get_all(name)
                    .iter()
                    .map(|v| v.to_str().unwrap().to_owned())
                    .collect::<Vec<_>>()),
            );
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let mut audit: Vec<Value> = owner
            .query(
                "SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",
                &[&last],
            )
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        let names = |text: &str| text.replace(&domain_a, "host-a.test");
        for row in &mut audit {
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                    row[key] = json!("<checksum>");
                }
            }
            *row = masked(row.clone(), &users, &names)?;
        }
        if recording && case.status != 0 && status != case.status {
            return Err(format!("Go auth-admin/{label}: expected {}, got {status}: {raw}", case.status).into());
        }
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        let text = mask_uuids(&names(&raw));
        if case.method != "HEAD" {
            if let Some(length) = headers.get_mut("content-length") {
                *length = json!([text.len().to_string()]);
            }
        }
        let observation = json!({
            "request": {
                "method": "*",
                "path": "/auth/admin/",
                "wire_method": case.method,
                "external_path": case.external,
            },
            "response": {
                "status": status,
                "headers": headers,
                "body": text,
            },
            "effects": [{"table": "none", "before": [], "after": []}],
            "audit": audit,
            "notify": [],
        });
        if !recording {
            let metrics = common::send(
                address,
                Request::get("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            for line in [
                "setjoin_gateway_proxied_to_go_by_family_total{family=\"F21\"} 0",
                "setjoin_gateway_proxied_to_go_total 0",
            ] {
                if !metrics.lines().any(|l| l == line) {
                    return Err(format!("replay forwarded to Go ({line}): {metrics}").into());
                }
            }
        }
        server.abort();

        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/platform/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("auth-admin-{label}.json"));
        let route_name = "* /auth/admin/";
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(
                &file,
                &json!({"format": 1, "route": route_name, "case": label, "go_source": source, "observation": observation}),
            )?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            compared?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;

    owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)",
            &[&receipts],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role])
        .await?;
    common::remove_blob_account(&owner, &a).await?;
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"
        ))
        .await?;
    result
}

/// Verifies `POST /api/auth/admin/users/1/impersonate` dispatches to `rust-auth`
/// with `/api` stripped instead of being captured by `* /auth/admin/`, and that an active guest
/// is rejected by `SessionAdmission` (`404`) with zero Go hops.
pub async fn verify_routing_and_guest() -> Result<(), BoxError> {
    let _serial = super::SERIAL.lock().await;
    let db = Db::for_case("gofree-auth-admin-routing-365").expect("database required");
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "authadmin-route").await?;
    let email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let old_guest_flag = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));

    let seen_rust_auth = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let seen_clone = seen_rust_auth.clone();
    let rust_auth = common::fake_upstream(move |req| {
        let seen = seen_clone.clone();
        async move {
            let method = req.method().as_str().to_owned();
            let path = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("")
                .to_owned();
            seen.lock().unwrap().push((method, path));
            let mut resp = Response::new(common::full(r#"{"proxied":"rust-auth"}"#));
            resp.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            resp
        }
    })
    .await;
    let go_upstream = common::fake_upstream(|_| async {
        let mut resp = Response::new(common::full("unexpected go hit"));
        *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
        resp
    })
    .await;

    let result = async {
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
        let worker = common::patient_exec(&db.dsn, 4)?;
        let table = RouteTable::proxy_all()
            .with(AuthAdminRoute::new(
                exec,
                Arc::new(common::recovery_keys()),
                "mailserver".into(),
            ))
            .with_admission(
                worker,
                Arc::new(common::recovery_keys()),
                "mailserver".into(),
                None,
            )
            .with_catchall(CatchallRoute::new());
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{go_upstream}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            table,
        )?
        .with_inventory(setjoin_gateway::inventory::BUNDLED)?
        .with_rust_auth_upstream(format!("http://{rust_auth}").parse()?)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));

        let resp = common::send(
            address,
            Request::post("/api/auth/admin/users/1/impersonate")
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("authorization", format!("Bearer {}", admin_token(a.user)))
                .body(common::full("{}"))?,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body = common::body_bytes(resp).await;
        assert_eq!(std::str::from_utf8(&body)?, r#"{"proxied":"rust-auth"}"#);
        assert_eq!(
            seen_rust_auth.lock().unwrap().as_slice(),
            &[(
                "POST".to_owned(),
                "/auth/admin/users/1/impersonate".to_owned()
            )]
        );

        owner
            .execute(
                "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,$2,'inviter@host.test',$3,'active')",
                &[&a.user, &email, &a.domain],
            )
            .await?;
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES('feature.guest_accounts',true) ON CONFLICT(key) DO UPDATE SET enabled=true",
                &[],
            )
            .await?;
        let guest_tok = super::admin_token_with(a.user, &[0x11; 32], |claims| {
            claims["acct"] = json!("guest");
            claims["admin"] = json!(false);
            claims["perms"] = json!([]);
        });
        let guest_resp = common::send(
            address,
            Request::get("/auth/admin/unknown")
                .header("host", "mail.test")
                .header("authorization", format!("Bearer {guest_tok}"))
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(guest_resp.status().as_u16(), 404);
        let _ = common::body_bytes(guest_resp).await;

        let metrics = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        assert!(metrics.contains("setjoin_gateway_proxied_to_go_total 0"));
        server.abort();
        Ok::<_, BoxError>(())
    }
    .await;

    owner
        .execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&a.user])
        .await?;
    if let Some(prev) = old_guest_flag {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
                &[&prev],
            )
            .await?;
    } else {
        owner
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.guest_accounts'",
                &[],
            )
            .await?;
    }
    common::remove_blob_account(&owner, &a).await?;
    result
}
