//! HTTP routing proofs use the real adapter and an authenticated governed actor.
use super::*;
use http_body_util::BodyExt;
async fn setup() -> Result<(Db, tokio_postgres::Client, fixture::Account, i64), BoxError> {
    let db = Db::for_case("compl2-routing").ok_or("DB required")?;
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "compl2-routing").await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES('compl2-routing','{domains.read,compliance.write,audit.read,audit.export}') RETURNING id",&[]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(role_group_id,user_id) VALUES($1,$2)",
            &[&role, &a.user],
        )
        .await?;
    Ok((db, owner, a, role))
}
async fn cleanup(
    owner: &tokio_postgres::Client,
    a: &fixture::Account,
    role: i64,
) -> Result<(), BoxError> {
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={} OR (action='console.denied' AND notes LIKE '/admin/%');DELETE FROM rust_operation_receipts WHERE family='F04';COMMIT;",a.user)).await?;
    fixture::remove(owner, a).await?;
    Ok(())
}
fn adapter(
    db: &Db,
) -> Result<
    setjoin_gateway::retention_audit::RetentionAuditRoute<setjoin_gateway::jmap::jwks::Jwks>,
    BoxError,
> {
    Ok(setjoin_gateway::retention_audit::RetentionAuditRoute {
        exec: setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new()),
        worker: setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 2)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new()),
        keys: Arc::new(common::recovery_keys()),
        issuer: "mailserver".into(),
    })
}
async fn state(owner: &tokio_postgres::Client, a: &fixture::Account) -> Result<Value, BoxError> {
    Ok(
        json!({"logs":snapshot(owner,"log_set").await?,"audit":snapshot(owner,"audit_set").await?,"content":content_snapshot(owner,a,a).await?}),
    )
}
pub async fn switches() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let (db, owner, a, role) = setup().await?;
    let result = async {
        let before = state(&owner, &a).await?;
        for global in [false, true] {
            let calls = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
            let capture = calls.clone();
            let upstream = common::fake_upstream(move |r| {
                let capture = capture.clone();
                async move {
                    let method = r.method().to_string();
                    let uri = r.uri().to_string();
                    let body = String::from_utf8(
                        r.into_body().collect().await.unwrap().to_bytes().to_vec(),
                    )
                    .unwrap();
                    capture
                        .lock()
                        .unwrap()
                        .push(json!({"method":method,"uri":uri,"body":body}));
                    Response::builder()
                        .status(299)
                        .body(common::full("kill switch\n"))
                        .unwrap()
                }
            })
            .await;
            let mut inventory: Value =
                serde_json::from_str(include_str!("../../route-inventory.json"))?;
            let mut routes = Vec::new();
            for r in inventory["routes"].as_array_mut().unwrap() {
                if r["family"] == "F04" && r["slice"] == "retention-audit" {
                    routes.push((
                        r["method"].as_str().unwrap().to_owned(),
                        format!(
                            "/api{}?probe=%2b",
                            r["path"].as_str().unwrap().replace("{id}", "bad")
                        ),
                    ));
                    r["state"] = json!(if global { "ON" } else { "OFF" });
                    r["upstream"] = json!(if global { "local-rust" } else { "go-mail" });
                    r["oracle_commands"] = json!([""]);
                }
            }
            if routes.len() != 14 {
                return Err("expected fourteen switch routes".into());
            }
            let gateway = Gateway::new(
                Config {
                    upstream: Some(format!("http://{upstream}").parse()?),
                    trusted_proxies: TrustedProxies::parse("")?,
                    upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                    edge_limit: None,
                },
                RouteTable::proxy_all().with(adapter(&db)?),
            )?
            .with_inventory(&inventory.to_string())?
            .with_enabled(!global);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(gateway.serve(listener));
            let phase = async {
                let body = "invalid JSON\n";
                let mut expected = Vec::new();
                for (method, uri) in routes {
                    let response = common::send(
                        addr,
                        Request::builder()
                            .method(method.as_str())
                            .uri(&uri)
                            .header("host", "mail.test")
                            .header("origin", "http://mail.test")
                            .header("content-type", "application/json")
                            .header("x-audit-reason", "Switch proof")
                            .header("authorization", format!("Bearer {}", token(a.user)))
                            .body(common::full(body))?,
                    )
                    .await;
                    if response.status().as_u16() != 299 {
                        return Err(format!("switch served {method} {uri} locally").into());
                    }
                    if common::body_bytes(response).await.as_ref() != b"kill switch\n" {
                        return Err("switch response changed".into());
                    }
                    expected.push(json!({"method":method,"uri":uri,"body":body}));
                }
                let response = common::send(
                    addr,
                    Request::get("/_gateway/metrics").body(common::full(""))?,
                )
                .await;
                let status = response.status().as_u16();
                let text = String::from_utf8(common::body_bytes(response).await.to_vec())?;
                if global {
                    if status != 299 {
                        return Err("global switch intercepted metrics".into());
                    }
                    expected.push(json!({"method":"GET","uri":"/_gateway/metrics","body":""}));
                } else if !text.lines().any(|l| {
                    l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 14"
                }) {
                    return Err(format!("wrong switch metrics: {text}").into());
                }
                golden::compare(&json!(expected), &json!(*calls.lock().unwrap()))?;
                Ok::<_, BoxError>(())
            }
            .await;
            server.abort();
            let _ = server.await;
            phase?;
        }
        golden::compare(&before, &state(&owner, &a).await?)?;
        eprintln!(
            "SWITCHES: all fourteen routes forwarded unchanged by inventory OFF and global OFF"
        );
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&owner, &a, role).await?;
    result
}
pub async fn forwarding() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let (db, owner, a, role) = setup().await?;
    let result = async {
        let before = state(&owner, &a).await?;
        let calls = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let capture = calls.clone();
        let upstream = common::fake_upstream(move |r| {
            let capture = capture.clone();
            async move {
                let method = r.method().to_string();
                let uri = r.uri().to_string();
                let body =
                    String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec())
                        .unwrap();
                capture
                    .lock()
                    .unwrap()
                    .push(json!({"method":method,"uri":uri,"body":body}));
                Response::builder()
                    .status(299)
                    .body(common::full("deferred\n"))
                    .unwrap()
            }
        })
        .await;
        let mut inventory: Value =
            serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().unwrap() {
            if r["family"] == "F04" && r["slice"] == "retention-audit" {
                r["state"] = json!("ON");
                r["upstream"] = json!("local-rust");
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{upstream}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter(&db)?),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let phase = async {
            let uri = "/api/admin/content-search/search?keep=%2b";
            let body = r#" {"kql":"\"a\u0000b\"","keywords":"oracle","userId":-42} trailing"#;
            let response = common::send(
                addr,
                Request::post(uri)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", token(a.user)))
                    .body(common::full(body))?,
            )
            .await;
            // Owner-approved security fix 2026-11-05 (#436): a NUL in the KQL is refused locally
            // (400) and never forwarded; frozen Go's parser hung on it.
            if response.status().as_u16() != 400 {
                return Err(format!("NUL KQL answered {}", response.status()).into());
            }
            let text = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if !text.contains("invalid KQL query: query contains a NUL character") {
                return Err(format!("NUL KQL body: {text}").into());
            }
            golden::compare(&json!([]), &json!(*calls.lock().unwrap()))?;
            golden::compare(&before, &state(&owner, &a).await?)?;
            Ok::<_, BoxError>(())
        }
        .await;
        server.abort();
        let _ = server.await;
        phase
    }
    .await;
    cleanup(&owner, &a, role).await?;
    result
}
