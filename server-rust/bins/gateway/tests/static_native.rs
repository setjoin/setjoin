//! #271: contracts of the F22 adapter that need no database and no Go process:
//! what it must hand to Go because it cannot see the configuration Go reads.
mod common;
use common::BoxError;
use hyper::{Request, Response};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::sync::{Arc, Mutex};

fn config(
    edit: impl FnOnce(&mut setjoin_gateway::surface::SurfaceConfig),
) -> setjoin_gateway::surface::SurfaceConfig {
    let mut config = setjoin_gateway::surface::SurfaceConfig {
        network_mode: "airgap".into(),
        website_dir: true,
        setjoin: setjoin_static::wellknown::SetJoinConfig {
            crypto_profile: "standard".into(),
            login_field: String::new(),
            login_domain_hint: String::new(),
        },
        imap_tls: true,
        metrics: setjoin_static::metrics::MetricsAuth::from_values("", ""),
        probes_configured: false,
    };
    edit(&mut config);
    config
}

/// Returns the status and whether Go was consulted.
async fn call(
    config: setjoin_gateway::surface::SurfaceConfig,
    uri: &str,
) -> Result<(u16, usize), BoxError> {
    let forwards = Arc::new(Mutex::new(0usize));
    let counted = forwards.clone();
    let go = common::fake_upstream(move |_| {
        let counted = counted.clone();
        async move {
            *counted.lock().unwrap() += 1;
            Response::builder()
                .status(418)
                .body(common::full("go"))
                .unwrap()
        }
    })
    .await;
    // The pool is lazy: a path that never reads the database never connects.
    let exec = setjoin_pg::ScopedExecutor::from_dsn("postgres://nobody@127.0.0.1:1/none", 1)
        .map_err(|e| e.0)?;
    let surface = setjoin_gateway::surface::SurfaceRoute {
        discovery: None,
        fallback: None,
        exec,
        keys: Arc::new(common::recovery_keys()),
        issuer: "mailserver".into(),
        health: Arc::new(setjoin_static::health::HealthGate::new(
            config.probes_configured,
        )),
        config: Arc::new(config),
    };
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{go}").parse()?),
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(surface),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(gateway.serve(listener));
    let response = common::send(
        address,
        Request::builder()
            .uri(uri)
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    let status = response.status().as_u16();
    task.abort();
    let _ = task.await;
    let consulted = *forwards.lock().unwrap();
    Ok((status, consulted))
}

#[tokio::test]
async fn resolved_config_file_never_forwards_static_routes() -> Result<(), BoxError> {
    for (uri, expected) in [
        ("/.well-known/setjoin", 200),
        ("/.well-known/autoconfig/mail/config-v1.1.xml", 404),
        ("/downloads/asset/SetJoin_latest_linux-x86_64.deb", 302),
        ("/favicon.ico", 200),
    ] {
        let (status, consulted) = call(config(|_| {}), uri).await?;
        assert_eq!((status, consulted), (expected, 0), "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn resolved_empty_mode_and_absent_website_are_native() -> Result<(), BoxError> {
    let asset = "/downloads/asset/SetJoin_latest_linux-x86_64.deb";
    assert_eq!(
        call(config(|c| c.network_mode.clear()), asset).await?,
        (302, 0)
    );
    assert_eq!(
        call(config(|c| c.website_dir = false), "/favicon.ico").await?,
        (404, 0)
    );
    // The same requests are native once the configuration is visible.
    assert_eq!(call(config(|_| {}), asset).await?, (302, 0));
    assert_eq!(call(config(|_| {}), "/favicon.ico").await?, (200, 0));
    Ok(())
}

#[tokio::test]
async fn health_stays_on_go_while_live_probes_are_configured() -> Result<(), BoxError> {
    assert_eq!(
        call(config(|c| c.probes_configured = true), "/health").await?,
        (418, 1)
    );
    Ok(())
}

#[tokio::test]
async fn a_path_go_would_redirect_to_its_clean_form_stays_on_go() -> Result<(), BoxError> {
    assert_eq!(call(config(|_| {}), "/downloads/asset/.").await?, (418, 1));
    // Escaped dots are ordinary bytes to Go's mux (it cleans the escaped
    // path): the handler answers.
    assert_eq!(
        call(config(|_| {}), "/downloads/asset/%2e").await?,
        (302, 0)
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_discover_query_is_answered_without_go() -> Result<(), BoxError> {
    assert_eq!(
        call(config(|_| {}), "/api/discover?domain=%zz").await?,
        (400, 0)
    );
    assert_eq!(
        call(
            config(|_| {}),
            "/api/discover?domain=nonexistent-static1.invalid"
        )
        .await?,
        (404, 0)
    );
    Ok(())
}

#[tokio::test]
async fn metrics_fail_closed_without_a_token_and_never_reach_go() -> Result<(), BoxError> {
    assert_eq!(call(config(|_| {}), "/metrics").await?, (401, 0));
    Ok(())
}

/// Every entry this slice turned ON returns to Go through both rollback
/// switches, with the request intact, and the proxy counters see it by family.
#[tokio::test]
async fn both_kill_switches_return_every_route_to_go() -> Result<(), BoxError> {
    use serde_json::Value;
    let bundled: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
    let mut slice = Vec::new();
    for row in bundled["routes"].as_array().unwrap() {
        let on = row["state"] == "ON" && row["listener"] == "gateway";
        let ours = matches!(row["family"].as_str(), Some("F20" | "F22"))
            || row["path"] == "/chat/messages/{id}/translate";
        // The `/` and `/api/` catch-alls belong to the catch-all slice (#416), which
        // owns their kill-switch coverage in `catchall_startup`.
        let catch_all = row["path"] == "/" || row["path"] == "/api/";
        if on && ours && !catch_all {
            slice.push(row.clone());
        }
    }
    assert_eq!(slice.len(), 26, "the slice's ON entries");
    for mode in ["inventory", "global"] {
        let mut inventory = bundled.clone();
        if mode == "inventory" {
            for row in inventory["routes"].as_array_mut().unwrap() {
                if slice
                    .iter()
                    .any(|s| s["method"] == row["method"] && s["path"] == row["path"])
                {
                    row["state"] = "OFF".into();
                    row["upstream"] = "go-mail".into();
                    row.as_object_mut().unwrap().remove("oracle_commands");
                    row.as_object_mut().unwrap().remove("oracle_mutators");
                }
            }
        }
        let seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let counted = seen.clone();
        let go = common::fake_upstream(move |request| {
            let counted = counted.clone();
            async move {
                counted
                    .lock()
                    .unwrap()
                    .push((request.method().to_string(), request.uri().to_string()));
                Response::builder()
                    .status(418)
                    .body(common::full("go"))
                    .unwrap()
            }
        })
        .await;
        let exec = setjoin_pg::ScopedExecutor::from_dsn("postgres://nobody@127.0.0.1:1/none", 1)
            .map_err(|e| e.0)?;
        let config = config(|_| {});
        let surface = setjoin_gateway::surface::SurfaceRoute {
            discovery: None,
            fallback: None,
            exec: exec.clone(),
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            health: Arc::new(setjoin_static::health::HealthGate::new(false)),
            config: Arc::new(config),
        };
        let assist = setjoin_gateway::assist::AssistRoute {
            exec,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
        };
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{go}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(surface).with(assist),
        )?
        .with_inventory(&inventory.to_string())?
        .with_enabled(mode != "global");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(gateway.serve(listener));
        let check = async {
            for row in &slice {
                let template = row["path"].as_str().unwrap();
                let mounted = row["family"] == "F20"
                    || template == "/telemetry"
                    || template.starts_with("/chat/");
                let mut path = template
                    .replace("{platform}", "linux-x86_64")
                    .replace("{asset}", "x.deb")
                    .replace("{id}", "991");
                if mounted {
                    path = format!("/api{path}");
                }
                let method = row["method"].as_str().unwrap();
                let response = common::send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("host", "mail.test")
                        .body(common::full(""))?,
                )
                .await;
                assert_eq!(response.status(), 418, "{mode}: {method} {path}");
            }
            if mode == "inventory" {
                let response = common::send(
                    address,
                    Request::builder()
                        .uri("/_gateway/metrics")
                        .body(common::full(""))?,
                )
                .await;
                let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
                let want = |family: &str| slice.iter().filter(|r| r["family"] == family).count();
                for family in ["F20", "F22"] {
                    let line = format!(
                        "setjoin_gateway_proxied_to_go_by_family_total{{family=\"{family}\"}} {}",
                        want(family)
                    );
                    assert!(metrics.lines().any(|l| l == line), "{line}\n{metrics}");
                }
            }
            assert_eq!(seen.lock().unwrap().len(), slice.len(), "{mode}");
            Ok::<_, BoxError>(())
        }
        .await;
        task.abort();
        let _ = task.await;
        check?;
    }
    Ok(())
}
