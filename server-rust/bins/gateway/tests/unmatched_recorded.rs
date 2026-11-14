//! #357/#378: `/auth/*` spellings no inventory row claims get frozen Go's root-mux
//! answer natively (slash redirect, SPA or 404), never Go auth; the redirect runs after
//! CSRF, both budgets and admission; adapter-less local rows keep today's Go fallback.
//! A2: without a deployment verifier the guest belt fails closed (D-357a-1).
mod common;
use common::mux_oracle::{run, MuxCase, Website};
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Method, Request, Response};
use setjoin_gateway::catchall::CatchallRoute;
use setjoin_gateway::jmap::limit::{EdgeLimit, Limiter};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CORPUS: &str = "unmatched/goldens";

fn table(exec: setjoin_pg::ScopedExecutor, website: Website) -> RouteTable {
    let mut catchall = CatchallRoute::new().with_auth(
        exec,
        Arc::new(common::recovery_keys()),
        "mailserver".into(),
    );
    catchall.website = website;
    RouteTable::proxy_all().with_catchall(catchall)
}

macro_rules! case {
    ($name:ident, $method:literal, $uri:literal, $bearer:literal, $website:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            let case = MuxCase {
                name: stringify!($name),
                method: $method,
                uri: $uri,
                bearer: $bearer,
                website: $website,
            };
            run(CORPUS, &case, &[], &table).await
        }
    };
}

case!(auth_unknown_get, "GET", "/auth/unknown", false, false);
case!(auth_unknown_head, "HEAD", "/auth/unknown", false, false);
case!(auth_unknown_post, "POST", "/auth/unknown", false, false);
case!(
    auth_unknown_delete,
    "DELETE",
    "/auth/unknown/deeper?x=1",
    false,
    false
);
case!(auth_escaped_login, "POST", "/auth/login%2Fx", false, false);
case!(auth_escaped_prefix, "GET", "/auth%2Flogin", false, false);
case!(
    auth_escaped_root_segment,
    "GET",
    "/%61uth/totp",
    false,
    false
);
case!(auth_wrong_method, "GET", "/auth/login", false, false);
case!(auth_wrong_method_bearer, "GET", "/auth/login", true, false);
case!(auth_slash_redirect, "GET", "/auth/totp?x=1", false, false);
case!(auth_slash_redirect_post, "POST", "/auth/totp", false, false);
case!(
    auth_slash_redirect_head,
    "HEAD",
    "/auth/webauthn",
    false,
    false
);
case!(
    auth_slash_redirect_decoded,
    "GET",
    "/auth/%74otp",
    false,
    false
);
case!(
    auth_slash_redirect_query_slashes,
    "GET",
    "/auth/totp?//evil.example",
    false,
    false
);
case!(
    auth_escaped_slash_suffix,
    "GET",
    "/auth/totp%2F",
    false,
    false
);
case!(auth_admin_bare, "GET", "/auth/admin", false, false);
case!(auth_dot_segments, "GET", "/auth/./unknown", false, false);
case!(
    auth_unknown_get_website,
    "GET",
    "/auth/unknown",
    false,
    true
);
case!(
    auth_unknown_post_website,
    "POST",
    "/auth/unknown",
    false,
    true
);
case!(
    auth_slash_redirect_website,
    "GET",
    "/auth/totp",
    false,
    true
);

fn counting(
    hits: Arc<AtomicUsize>,
    body: &'static str,
) -> impl Fn(
    hyper::Request<hyper::body::Incoming>,
) -> std::future::Ready<hyper::Response<common::TestBody>>
       + Send
       + Sync
       + 'static {
    move |_| {
        hits.fetch_add(1, Ordering::SeqCst);
        std::future::ready(hyper::Response::new(common::full(body)))
    }
}

async fn serve(gateway: Gateway) -> Result<SocketAddr, BoxError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(gateway.serve(listener));
    Ok(addr)
}

fn config(upstream: SocketAddr, edge: Option<EdgeLimit>) -> Result<Config, BoxError> {
    Ok(Config {
        upstream: Some(format!("http://{upstream}").parse()?),
        trusted_proxies: TrustedProxies::parse("")?,
        upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
        edge_limit: edge,
    })
}

/// Finding 1: the adapter-less arm is unchanged; local rows no adapter claims still reach Go.
#[tokio::test]
async fn adapter_less_local_rows_keep_todays_go_fallback() -> Result<(), BoxError> {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = common::fake_upstream(counting(hits.clone(), "go")).await;
    let gw = common::gateway(
        upstream,
        "",
        RouteTable::proxy_all().with_catchall(CatchallRoute::new()),
    )
    .await;
    for uri in ["/link-protect?token=x", "/rtc", "/rtc/rtc/validate"] {
        let response = common::send(
            gw,
            Request::get(uri)
                .header("host", "mail.test")
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(response.status().as_u16(), 200, "{uri}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn unmatched_auth_paths_never_reach_either_go_upstream() -> Result<(), BoxError> {
    let mail_hits = Arc::new(AtomicUsize::new(0));
    let auth_hits = Arc::new(AtomicUsize::new(0));
    let mail = common::fake_upstream(counting(mail_hits.clone(), "go mail")).await;
    let auth = common::fake_upstream(counting(auth_hits.clone(), "go auth")).await;
    let gateway = Gateway::new(
        config(mail, None)?,
        RouteTable::proxy_all().with_catchall(CatchallRoute::new()),
    )?
    .with_auth_upstream(format!("http://{auth}").parse()?)?;
    let addr = serve(gateway).await?;
    for (method, uri, status) in [
        ("GET", "/auth/unknown", 404),
        ("POST", "/auth/login%2Fx", 404),
        ("POST", "/auth/totp", 307),
        ("GET", "/auth/%74otp", 307),
    ] {
        let response = common::send(
            addr,
            Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "mail.test")
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(response.status().as_u16(), status, "{method} {uri}");
    }
    assert_eq!(mail_hits.load(Ordering::SeqCst), 0);
    assert_eq!(auth_hits.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Finding 3: CSRF, the spent budget and admission all answer before the slash
/// redirect; no Location ever leaves the origin.
#[tokio::test]
async fn the_slash_redirect_runs_after_csrf_budget_and_admission() -> Result<(), BoxError> {
    let Some(db) = setjoin_conformance::harness::Db::for_case("unmatched-gates") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = setjoin_conformance::fixture::account(&owner, "unmatched-gates").await?;
    let result = std::panic::AssertUnwindSafe(gates(&db, account.user))
        .catch_unwind()
        .await;
    setjoin_conformance::fixture::remove(&owner, &account).await?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn gated(
    db: &setjoin_conformance::harness::Db,
    upstream: SocketAddr,
    limit: u64,
) -> Result<SocketAddr, BoxError> {
    let guest = setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 2).map_err(|e| e.0)?;
    let routes = RouteTable::proxy_all()
        .with_admission(
            guest,
            Arc::new(common::recovery_keys()),
            "mailserver".into(),
            None,
        )
        .with_catchall(CatchallRoute::new());
    serve(Gateway::new(
        config(
            upstream,
            Some(EdgeLimit::for_front_door(Limiter::new(limit, 60))),
        )?,
        routes,
    )?)
    .await
}

async fn gates(db: &setjoin_conformance::harness::Db, user: i64) -> Result<(), BoxError> {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = common::fake_upstream(counting(hits.clone(), "go")).await;
    let addr = gated(db, upstream, 600).await?;
    let send = |method: &'static str, uri: &'static str, headers: Vec<(&'static str, String)>| async move {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "mail.test");
        for (name, value) in headers {
            request = request.header(name, value);
        }
        common::send(addr, request.body(common::full("")).unwrap()).await
    };
    // Cross-site mutation: the global CSRF gate's 403, not the 307.
    let response = send(
        "POST",
        "/auth/totp",
        vec![("origin", "https://evil.test".into())],
    )
    .await;
    assert_eq!(response.status().as_u16(), 403);
    assert!(String::from_utf8_lossy(&common::body_bytes(response).await).contains("csrf_failed"));
    // An invalid bearer does not stop the redirect: the 307.
    let response = send(
        "POST",
        "/auth/totp",
        vec![("authorization", "Bearer a.b.c".into())],
    )
    .await;
    assert_eq!(response.status().as_u16(), 307);
    assert_eq!(response.headers()["location"], "/auth/totp/");
    // A guest-claim token without a live guest row: admission's 401, not the 307.
    let guest = common::recovery_token_with(user, serde_json::json!({"acct": "guest"}));
    let response = send(
        "GET",
        "/auth/totp",
        vec![("authorization", format!("Bearer {guest}"))],
    )
    .await;
    assert_eq!(response.status().as_u16(), 401);
    assert!(response.headers().get("location").is_none());
    // Open-redirect negatives: Location is the row plus the raw query, or on-site.
    let response = send("GET", "/auth/totp?//evil.example", vec![]).await;
    assert_eq!(response.status().as_u16(), 307);
    assert_eq!(response.headers()["location"], "/auth/totp/?//evil.example");
    for uri in [
        "//evil.example/auth/totp",
        "/auth/totp%2F",
        "/auth/totp/..%2F",
    ] {
        let response = send("GET", uri, vec![]).await;
        if let Some(location) = response.headers().get("location") {
            let location = location.to_str()?;
            assert!(
                location.starts_with('/')
                    && !location.starts_with("//")
                    && !location.contains('\\'),
                "{uri} -> {location}"
            );
        }
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // Spent budget: Go's 429 before the redirect.
    let spent = gated(db, upstream, 0).await?;
    let response = common::send(
        spent,
        Request::get("/auth/totp")
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    assert_eq!(response.status().as_u16(), 429);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

/// A route-limited local adapter that admits a member when `x-member: yes`.
struct AdminProbe;
impl Intercept for AdminProbe {
    fn matches(&self, r: &Request<Body>) -> bool {
        r.method() == Method::GET && r.uri().path() == "/api/admin/departments"
    }
    fn admits_member(&self, h: hyper::HeaderMap, _: &'static str) -> BoxFuture<bool> {
        let member = h.get("x-member").is_some_and(|v| v == "yes");
        Box::pin(async move { member })
    }
    fn handle(&self, _r: Request<Body>, _c: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async { Response::new(common::full("local")) })
    }
}

async fn belt(hits: Arc<AtomicUsize>, rolled_back: bool) -> Result<SocketAddr, BoxError> {
    let upstream = common::fake_upstream(counting(hits, "go")).await;
    let gateway = Gateway::new(
        config(upstream, Some(common::edge(600)))?,
        RouteTable::proxy_all()
            .with(AdminProbe)
            .with_catchall(CatchallRoute::new()),
    )?;
    let gateway = if rolled_back {
        let mut inventory: serde_json::Value =
            serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
        let mut flipped = 0;
        for row in inventory["routes"].as_array_mut().ok_or("routes")? {
            if row["listener"] == "gateway"
                && row["method"] == "GET"
                && row["path"] == "/admin/departments"
            {
                row["state"] = "OFF".into();
                row["upstream"] = "go-mail".into();
                flipped += 1;
            }
        }
        assert_eq!(
            flipped, 1,
            "GET /admin/departments is one ON local-rust row"
        );
        gateway.with_inventory(&inventory.to_string())?
    } else {
        gateway
    };
    serve(gateway).await
}

async fn belt_probe(addr: SocketAddr, headers: &[(&str, &str)]) -> (u16, String) {
    let mut request = Request::get("/api/admin/departments").header("host", "mail.test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = common::send(addr, request.body(common::full("")).unwrap()).await;
    let status = response.status().as_u16();
    (
        status,
        String::from_utf8_lossy(&common::body_bytes_unchecked(response).await).into_owned(),
    )
}

/// D-357a-1: without a verifier, a token the adapter cannot prove fails closed (503).
#[tokio::test]
async fn belt_bearer_and_cookie_fail_closed_without_go() -> Result<(), BoxError> {
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = belt(hits.clone(), false).await?;
    for headers in [
        [("authorization", "Bearer a.b.c")],
        [("cookie", "access_token=abc")],
    ] {
        let (status, body) = belt_probe(addr, &headers).await;
        assert_eq!(status, 503, "{headers:?}");
        assert!(
            body.contains("\"detail\":\"service unavailable\""),
            "{body}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn belt_admitted_member_and_tokenless_requests_pass() -> Result<(), BoxError> {
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = belt(hits.clone(), false).await?;
    assert_eq!(
        belt_probe(
            addr,
            &[("authorization", "Bearer a.b.c"), ("x-member", "yes")]
        )
        .await,
        (200, "local".into())
    );
    assert_eq!(belt_probe(addr, &[]).await, (200, "local".into()));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

/// D-357a-1 also covers a route-limited row rolled back to Go.
#[tokio::test]
async fn belt_go_mail_row_fails_closed_without_go() -> Result<(), BoxError> {
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = belt(hits.clone(), true).await?;
    let (status, _) = belt_probe(addr, &[("authorization", "Bearer a.b.c")]).await;
    assert_eq!(status, 503);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}
