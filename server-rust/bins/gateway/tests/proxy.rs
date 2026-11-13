//! Black-box tests: client -> setjoin-gateway -> fake upstream (#220).

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::{body_bytes, fake_upstream, full, gateway, send, within, BoxError};
use http_body_util::channel::Channel;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use setjoin_gateway::{Body, BoxFuture, Intercept, RequestContext, RouteTable, HEALTH_PATH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Give multi-request fixed-window tests room to run on the shared host.
async fn enough_window_time(window_secs: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let remaining = window_secs - now % window_secs;
    if remaining <= 10 {
        tokio::time::sleep(std::time::Duration::from_secs(remaining + 1)).await;
    }
}

#[tokio::test]
async fn plain_request_reaches_upstream_unchanged_and_response_returns_unchanged() {
    let upstream = fake_upstream(|req| async move {
        let seen = format!(
            "{} {} host={}",
            req.method(),
            req.uri(),
            req.headers()["host"].to_str().unwrap()
        );
        Response::builder()
            .status(StatusCode::CREATED)
            .header("x-upstream", "yes")
            .body(full(seen))
            .unwrap()
    })
    .await;
    let gw = gateway(upstream, "", RouteTable::proxy_all()).await;

    let resp = send(
        gw,
        Request::builder()
            .method("PATCH")
            .uri("/api/v1/thing?a=1&b=%20x")
            .header("host", "mail.example.test")
            .body(full(""))
            .unwrap(),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(resp.headers()["x-upstream"], "yes");
    assert_eq!(
        body_bytes(resp).await,
        "PATCH /api/v1/thing?a=1&b=%20x host=mail.example.test"
    );
}

/// Upstream that reports the request headers it received, one `name: value`
/// line each, in wire order.
async fn header_echo() -> std::net::SocketAddr {
    fake_upstream(|req| async move {
        let mut out = String::new();
        for (name, value) in req.headers() {
            out.push_str(&format!("{name}: {}\n", value.to_str().unwrap()));
        }
        Response::builder()
            .header("set-cookie", "a=1; Path=/")
            .header("set-cookie", "b=2; Path=/")
            .header("connection", "x-hop")
            .header("x-hop", "must-not-reach-client")
            .body(full(out))
            .unwrap()
    })
    .await
}

fn lines(body: &[u8]) -> Vec<String> {
    String::from_utf8(body.to_vec())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn untrusted_client_cannot_spoof_identity_headers_and_end_to_end_headers_pass_through() {
    let gw = gateway(header_echo().await, "", RouteTable::proxy_all()).await;

    let resp = send(
        gw,
        Request::builder()
            .uri("/jmap")
            .header("host", "mail.example.test")
            .header("authorization", "Bearer tok")
            .header("cookie", "session=s1")
            .header("x-multi", "first")
            .header("x-multi", "second")
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "evil.test")
            .header("x-real-ip", "6.6.6.6")
            .header("forwarded", "for=6.6.6.6;proto=https")
            .header("connection", "x-secret")
            .header("x-secret", "hop-only")
            .body(full(""))
            .unwrap(),
    )
    .await;

    let set_cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .cloned()
        .collect();
    assert_eq!(set_cookies, ["a=1; Path=/", "b=2; Path=/"]);
    assert!(
        resp.headers().get("x-hop").is_none(),
        "response hop-by-hop header leaked"
    );
    let seen = lines(&body_bytes(resp).await);
    for want in [
        "host: mail.example.test",
        "authorization: Bearer tok",
        "cookie: session=s1",
        "x-forwarded-for: 127.0.0.1",
        "x-forwarded-proto: http",
        "x-forwarded-host: mail.example.test",
    ] {
        assert!(
            seen.iter().any(|l| l == want),
            "missing {want:?} in {seen:?}"
        );
    }
    let multi: Vec<_> = seen.iter().filter(|l| l.starts_with("x-multi:")).collect();
    assert_eq!(multi, ["x-multi: first", "x-multi: second"]);
    for banned in [
        "x-real-ip",
        "forwarded:",
        "x-secret",
        "connection",
        "6.6.6.6",
        "evil.test",
    ] {
        assert!(
            !seen.iter().any(|l| l.contains(banned)),
            "{banned:?} leaked upstream: {seen:?}"
        );
    }
    assert_eq!(
        seen.iter()
            .filter(|l| l.starts_with("x-forwarded-for:"))
            .count(),
        1
    );
}

#[tokio::test]
async fn trusted_peer_forwards_rightmost_client_ip_and_scheme() {
    let gw = gateway(
        header_echo().await,
        "127.0.0.1, ::1",
        RouteTable::proxy_all(),
    )
    .await;

    let resp = send(
        gw,
        Request::builder()
            .uri("/")
            .header("host", "mail.example.test")
            .header("x-forwarded-for", "198.51.100.1, 203.0.113.9")
            .header("x-forwarded-proto", "https")
            .body(full(""))
            .unwrap(),
    )
    .await;

    let seen = lines(&body_bytes(resp).await);
    assert!(
        seen.contains(&"x-forwarded-for: 203.0.113.9".to_owned()),
        "{seen:?}"
    );
    assert!(
        seen.contains(&"x-forwarded-proto: https".to_owned()),
        "{seen:?}"
    );
}

#[tokio::test]
async fn large_request_body_streams_up_and_back_byte_for_byte() {
    // Upstream echoes the request body as the response body, streaming.
    let upstream =
        fake_upstream(
            |req| async move { Response::new(req.into_body().map_err(Into::into).boxed()) },
        )
        .await;
    let gw = gateway(upstream, "", RouteTable::proxy_all()).await;

    let payload: Vec<u8> = (0..16 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let (mut tx, rx) = Channel::<Bytes, BoxError>::new(4);
    let chunks = payload.clone();
    tokio::spawn(async move {
        for chunk in chunks.chunks(64 * 1024) {
            if tx.send_data(Bytes::copy_from_slice(chunk)).await.is_err() {
                return;
            }
        }
    });
    let resp = send(
        gw,
        Request::builder()
            .method("POST")
            .uri("/upload")
            .body(rx.boxed())
            .unwrap(),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let got = within(body_bytes(resp)).await;
    assert_eq!(got.len(), payload.len());
    assert!(got == payload, "body bytes differ");
}

#[tokio::test]
async fn sse_events_arrive_before_the_stream_ends() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
    let upstream = fake_upstream(move |req| {
        let release = release.clone();
        async move {
            assert_eq!(req.uri().path(), "/jmap/eventsource");
            let (mut tx, rx) = Channel::<Bytes, BoxError>::new(1);
            let gate = release.lock().await.take().unwrap();
            tokio::spawn(async move {
                tx.send_data("event: state\ndata: one\n\n".into())
                    .await
                    .unwrap();
                // The second event waits for the client to have seen the
                // first: a buffering proxy would stall here.
                gate.await.unwrap();
                tx.send_data("event: state\ndata: two\n\n".into())
                    .await
                    .unwrap();
            });
            Response::builder()
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .body(rx.boxed())
                .unwrap()
        }
    })
    .await;
    let gw = gateway(upstream, "", RouteTable::proxy_all()).await;

    let resp = send(
        gw,
        Request::builder()
            .uri("/jmap/eventsource?types=*")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body();
    let first = within(body.frame())
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, "event: state\ndata: one\n\n");
    release_tx.send(()).unwrap();
    let second = within(body.frame())
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(second, "event: state\ndata: two\n\n");
}

#[tokio::test]
async fn upstream_status_codes_pass_through() {
    let upstream = fake_upstream(|req| async move {
        let code: u16 = req.uri().path().trim_start_matches('/').parse().unwrap();
        let body = if code == 204 || code == 304 {
            ""
        } else {
            "body"
        };
        Response::builder().status(code).body(full(body)).unwrap()
    })
    .await;
    let gw = gateway(upstream, "", RouteTable::proxy_all()).await;

    for code in [
        200u16, 204, 301, 304, 400, 401, 403, 404, 409, 429, 500, 503,
    ] {
        let resp = send(
            gw,
            Request::builder()
                .uri(format!("/{code}"))
                .body(full(""))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), code);
        let body = body_bytes(resp).await;
        assert_eq!(body.is_empty(), code == 204 || code == 304, "status {code}");
    }
    let head = send(
        gw,
        Request::builder()
            .method("HEAD")
            .uri("/200")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(body_bytes(head).await.is_empty());
}

#[tokio::test]
async fn websocket_upgrade_tunnels_frames_both_ways() {
    let upstream = fake_upstream(|mut req| async move {
        if req.headers().get("upgrade").map(|v| v.as_bytes()) != Some(b"websocket")
            || req.headers().get("sec-websocket-key").is_none()
        {
            return Response::builder()
                .status(400)
                .body(full("not an upgrade"))
                .unwrap();
        }
        let on = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let mut io = TokioIo::new(on.await.unwrap());
            let mut buf = [0u8; 1024];
            loop {
                let n = io.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                io.write_all(&buf[..n]).await.unwrap();
            }
        });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            .body(full(""))
            .unwrap()
    })
    .await;
    let gw = gateway(upstream, "", RouteTable::proxy_all()).await;

    within(async move {
        let mut s = tokio::net::TcpStream::connect(gw).await.unwrap();
        s.write_all(
            b"GET /jmap/ws HTTP/1.1\r\nHost: mail.example.test\r\nConnection: Upgrade\r\n\
              Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        assert!(head.contains("upgrade: websocket"), "{head}");
        assert!(
            head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
            "{head}"
        );

        // A masked client text frame "Hello" (RFC 6455 §5.7), echoed raw.
        let frame = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        for _ in 0..3 {
            s.write_all(&frame).await.unwrap();
            let mut back = [0u8; 11];
            s.read_exact(&mut back).await.unwrap();
            assert_eq!(back, frame);
        }
    })
    .await;
}

#[tokio::test]
async fn upstream_down_is_bad_gateway_and_health_stays_up() {
    let closed = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let gw = gateway(closed, "", RouteTable::proxy_all()).await;

    let resp = send(gw, Request::builder().uri("/jmap").body(full("")).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let health = send(
        gw,
        Request::builder().uri(HEALTH_PATH).body(full("")).unwrap(),
    )
    .await;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(body_bytes(health).await, "ok\n");
}

/// A route that serves `POST /jmap` itself only when `x-take: yes`, and
/// otherwise declines by forwarding the whole request to Go: the shape #215
/// fills in.
struct TakeWhenAsked;

impl Intercept for TakeWhenAsked {
    fn matches(&self, req: &Request<Body>) -> bool {
        req.method() == hyper::Method::POST && req.uri().path() == "/jmap"
    }

    fn handle(&self, req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async move {
            if req.headers().get("x-take").is_some_and(|v| v == "yes") {
                Response::new(full("served by rust"))
            } else {
                ctx.upstream.forward(req, &ctx.identity).await
            }
        })
    }
}

#[tokio::test]
async fn unset_go_upstream_serves_claimed_routes_and_fails_closed_on_fallback() {
    let config = setjoin_gateway::Config {
        upstream: None,
        trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
        upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
        edge_limit: None,
    };
    let server =
        setjoin_gateway::Gateway::new(config, RouteTable::proxy_all().with(TakeWhenAsked)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve(listener));

    let claimed = Request::post("/jmap")
        .header("x-take", "yes")
        .body(full("{}"))
        .unwrap();
    assert_eq!(
        body_bytes(send(addr, claimed).await).await,
        "served by rust"
    );
    let fallback = Request::post("/jmap").body(full("{}")).unwrap();
    assert_eq!(send(addr, fallback).await.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn route_table_intercepts_only_matching_requests() {
    let upstream = fake_upstream(|req| async move {
        Response::new(full(format!("go {} {}", req.method(), req.uri().path())))
    })
    .await;
    let gw = gateway(upstream, "", RouteTable::proxy_all().with(TakeWhenAsked)).await;

    let post = |take: bool| {
        let mut b = Request::builder().method("POST").uri("/jmap");
        if take {
            b = b.header("x-take", "yes");
        }
        b.body(full("{}")).unwrap()
    };
    assert_eq!(
        body_bytes(send(gw, post(true)).await).await,
        "served by rust"
    );
    assert_eq!(
        body_bytes(send(gw, post(false)).await).await,
        "go POST /jmap"
    );
    let get = send(
        gw,
        Request::builder()
            .uri("/jmap/session")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(body_bytes(get).await, "go GET /jmap/session");
}

/// Review item 1: an upstream that accepts the request but never sends
/// response headers gets a `504` after the configured header timeout instead
/// of holding the client forever.
#[tokio::test]
async fn upstream_that_never_answers_is_gateway_timeout_after_the_header_bound() {
    let upstream = fake_upstream(|_req| async move {
        std::future::pending::<()>().await;
        unreachable!()
    })
    .await;
    let gw = common::gateway_with(
        upstream,
        "",
        RouteTable::proxy_all(),
        std::time::Duration::from_millis(300),
    )
    .await;
    let t = std::time::Instant::now();
    let resp = send(gw, Request::get("/slow").body(full("")).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        t.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        t.elapsed()
    );
}

/// Review item 3: with the Rust route installed the front door holds Go's
/// one per-IP core budget for every request (Go's `coreLimit` is the
/// outermost layer of its listener), and once it is spent answers exactly
/// what Go's limiter answers (REAL Go bytes, `tests/golden/go-rate-limited.json`)
/// without reaching Go. Requests Rust serves and requests Go serves draw from
/// the same count, so a client gets one budget, not one per process.
#[tokio::test]
async fn the_edge_budget_is_one_budget_with_go_s_429() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let upstream = fake_upstream(move |_req| {
        counter.fetch_add(1, Ordering::SeqCst);
        async { Response::new(full("ok")) }
    })
    .await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(2, common::Flags::On),
    )
    .await;
    for path in ["/jmap", "/api/settings"] {
        let resp = send(gw, Request::get(path).body(full("")).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    let resp = send(gw, Request::get("/api/settings").body(full("")).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(resp.headers()["content-type"], "application/problem+json");
    assert!(resp.headers().contains_key("x-request-id"));
    assert_eq!(
        &body_bytes(resp).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "the refused request never reached Go"
    );
    // The health probe is the gateway's own and never counted.
    let resp = send(gw, Request::get(HEALTH_PATH).body(full("")).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Review item 3: a request a Rust route serves and a request Go serves
/// spend the same per-IP budget; over it, neither the route nor Go runs.
#[tokio::test]
async fn rust_served_and_go_served_requests_share_the_budget() {
    let upstream = fake_upstream(|_req| async move { Response::new(full("go")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all().with(TakeWhenAsked),
        common::edge(2, common::Flags::On),
    )
    .await;
    let post = |take: bool| {
        let mut b = Request::builder().method("POST").uri("/jmap");
        if take {
            b = b.header("x-take", "yes");
        }
        b.body(full("{}")).unwrap()
    };
    assert_eq!(
        body_bytes(send(gw, post(true)).await).await,
        "served by rust"
    );
    assert_eq!(body_bytes(send(gw, post(false)).await).await, "go");
    for take in [true, false] {
        let resp = send(gw, post(take)).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "take={take}");
    }
}

/// Booking writes share Go's five-per-15-minute bucket across routes and
/// across a transferred Rust route and an untransferred Go route.
#[tokio::test]
async fn booking_write_budget_is_shared_across_rust_and_go_routes() {
    enough_window_time(15 * 60).await;
    struct Booking;
    impl Intercept for Booking {
        fn matches(&self, req: &Request<Body>) -> bool {
            req.uri().path() == "/api/public/booking/meeting/book"
        }
        fn handle(&self, _req: Request<Body>, _ctx: RequestContext) -> BoxFuture<Response<Body>> {
            Box::pin(async { Response::new(full("rust")) })
        }
    }

    let mail = fake_upstream(|_| async { Response::new(full("go")) }).await;
    let mut inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let original = inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| {
            route["listener"] == "gateway"
                && route["method"] == "POST"
                && route["path"] == "/public/booking/{slug}/book"
        })
        .unwrap();
    let mut transferred = original.clone();
    transferred["path"] = "/api/public/booking/{slug}/book".into();
    transferred["state"] = "ON".into();
    transferred["upstream"] = "local-rust".into();
    inventory["routes"]
        .as_array_mut()
        .unwrap()
        .push(transferred);
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: Some(common::edge(600, common::Flags::On)),
        },
        RouteTable::proxy_all().with(Booking),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));

    for (path, expected) in [
        ("/api/public/booking/meeting/book", "rust"),
        ("/api/public/booking/cancel", "go"),
        ("/api/public/booking/meeting/book", "rust"),
        ("/api/public/booking/cancel", "go"),
        ("/api/public/booking/meeting/book", "rust"),
    ] {
        let response = send(addr, Request::post(path).body(full("{}")).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await, expected);
    }
    let response = send(
        addr,
        Request::post("/api/public/booking/cancel")
            .body(full("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        &body_bytes(response).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
}

#[tokio::test]
async fn admin_routes_share_go_s_sixty_per_minute_budget() {
    enough_window_time(60).await;
    let upstream = fake_upstream(|_| async { Response::new(full("ok")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(600, common::Flags::On),
    )
    .await;
    for i in 0..60 {
        let path = if i % 2 == 0 {
            "/api/admin/users"
        } else {
            "/api/admin/domains"
        };
        assert_eq!(
            send(gw, Request::get(path).body(full("")).unwrap())
                .await
                .status(),
            StatusCode::OK,
            "request {i}"
        );
    }
    let response = send(gw, Request::get("/api/admin/users").body(full("")).unwrap()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        &body_bytes(response).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
    let bare = send(gw, Request::get("/admin/users").body(full("")).unwrap()).await;
    assert_eq!(
        bare.status(),
        StatusCode::OK,
        "bare path is not an API handler"
    );
}

#[tokio::test]
async fn auth_budget_is_shared_between_mail_and_direct_auth_upstreams() {
    enough_window_time(15 * 60).await;
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: Some(common::edge(600, common::Flags::On)),
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap()
    .with_rust_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    for i in 0..20 {
        let (path, expected) = if i % 2 == 0 {
            ("/api/quarantine", "mail")
        } else {
            ("/auth/password-policy", "auth")
        };
        let response = send(addr, Request::get(path).body(full("")).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await, expected);
    }
    let response = send(
        addr,
        Request::get("/api/quarantine").body(full("")).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        &body_bytes(response).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
}

#[tokio::test]
async fn meet_guest_write_budget_is_per_ip_and_meeting_slug() {
    enough_window_time(15 * 60).await;
    let upstream = fake_upstream(|_| async { Response::new(full("ok")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(600, common::Flags::On),
    )
    .await;
    for _ in 0..20 {
        let response = send(
            gw,
            Request::post("/api/public/meet/first/join-request")
                .body(full(""))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let first = send(
        gw,
        Request::post("/api/public/meet/%66irst/join-request")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    let second = send(
        gw,
        Request::post("/api/public/meet/second/join-request")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "a different meeting has its own bucket"
    );
}

#[tokio::test]
async fn csrf_rejection_precedes_route_limit_after_core_admission() {
    enough_window_time(15 * 60).await;
    let upstream = fake_upstream(|req| async move {
        if req.headers().contains_key("origin") {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full("csrf denied"))
                .unwrap()
        } else {
            Response::new(full("ok"))
        }
    })
    .await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(600, common::Flags::On),
    )
    .await;
    for _ in 0..5 {
        let response = send(
            gw,
            Request::post("/api/public/booking/cancel")
                .body(full(""))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = send(
        gw,
        Request::post("/api/public/booking/cancel")
            .header("host", "mail.example.test")
            .header("origin", "https://attacker.example")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_bytes(response).await, "{\"detail\":\"CSRF validation failed\",\"status\":403,\"title\":\"csrf_failed\",\"type\":\"about:blank\"}\n");
}

#[tokio::test]
async fn route_limit_response_has_go_s_security_headers() {
    enough_window_time(15 * 60).await;
    let upstream = fake_upstream(|_| async { Response::new(full("ok")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(600, common::Flags::On),
    )
    .await;
    for _ in 0..5 {
        let response = send(
            gw,
            Request::post("/api/public/booking/cancel")
                .body(full(""))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = send(
        gw,
        Request::post("/api/public/booking/cancel")
            .header("x-request-id", "route-limit-test")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert_eq!(
        response.headers()["cross-origin-opener-policy"],
        "same-origin"
    );
    assert_eq!(
        response.headers()["referrer-policy"],
        "strict-origin-when-cross-origin"
    );
    assert!(response.headers().contains_key("content-security-policy"));
    assert!(response.headers().contains_key("permissions-policy"));
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    assert_eq!(response.headers()["x-request-id"], "route-limit-test");
    assert_eq!(
        &body_bytes(response).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
}

#[tokio::test]
async fn guest_gate_precedes_route_budget_without_exposing_a_429() {
    enough_window_time(60).await;
    let upstream = fake_upstream(|req| async move {
        if req.headers().contains_key("authorization") || req.headers().contains_key("cookie") {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("not found\n"))
                .unwrap()
        } else {
            Response::new(full("ok"))
        }
    })
    .await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(600, common::Flags::On),
    )
    .await;
    for _ in 0..60 {
        let response = send(gw, Request::get("/api/admin/users").body(full("")).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = send(
        gw,
        Request::get("/api/admin/users")
            .header("authorization", "Bearer guest-token")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_bytes(response).await, "not found\n");
    let response = send(
        gw,
        Request::get("/api/admin/users")
            .header("cookie", "theme=light; access_token=guest-token")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_bytes(response).await, "not found\n");
}

#[tokio::test]
async fn qualified_auth_process_owns_threat_admission() {
    use setjoin_gateway::jmap::limit::{EdgeLimit, Limiter};
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let rust = fake_upstream(|req| async move {
        let reason = match req.headers()["x-forwarded-for"].to_str().unwrap() {
            "198.51.100.72" => "threat_blocked",
            "198.51.100.73" => "ip_blocked",
            "198.51.100.74" => {
                return Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(full(""))
                    .unwrap()
            }
            other => panic!("unexpected forwarded identity: {other}"),
        };
        let body = format!(
            "{}\n",
            serde_json::json!({
                "error": reason,
                "captcha_prompt": "Access denied by security policy"
            })
        );
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .header("x-threat-reason", reason)
            .body(full(body))
            .unwrap()
    })
    .await;
    let auth = fake_upstream(|_| async {
        panic!("qualified auth must reach setjoin-auth before any unported-shape handoff")
    })
    .await;
    let mut inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    for route in inventory["routes"].as_array_mut().unwrap() {
        if route["listener"] == "auth"
            && route["method"] == "POST"
            && route["path"] == "/auth/login"
        {
            route["state"] = "ON".into();
            route["upstream"] = "rust-auth".into();
        }
    }
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("127.0.0.1").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: Some(EdgeLimit::for_front_door(Limiter::new(600, 60))),
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap()
    .with_rust_auth_upstream(format!("http://{rust}").parse().unwrap())
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    for (ip, reason, golden) in [
        (
            "198.51.100.72",
            Some("threat_blocked"),
            &include_bytes!("golden/go-threat-blocked.json")[..],
        ),
        (
            "198.51.100.73",
            Some("ip_blocked"),
            &include_bytes!("golden/go-ip-blocked.json")[..],
        ),
        ("198.51.100.74", None, &b""[..]),
    ] {
        let response = send(
            addr,
            Request::post("/auth/login")
                .header("x-forwarded-for", ip)
                .body(full("{}"))
                .unwrap(),
        )
        .await;
        if let Some(reason) = reason {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()["x-threat-reason"], reason);
            assert_eq!(response.headers()["content-type"], "application/json");
        } else {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(!response.headers().contains_key("x-threat-reason"));
        }
        assert_eq!(&body_bytes(response).await[..], golden);
    }
}

#[tokio::test]
async fn resolved_disabled_scim_is_not_registered_and_never_proxies() {
    struct Scim;
    impl Intercept for Scim {
        fn matches(&self, req: &Request<Body>) -> bool {
            req.uri().path() == "/scim/v2/Users"
        }
        fn handle(&self, _req: Request<Body>, _ctx: RequestContext) -> BoxFuture<Response<Body>> {
            Box::pin(async { Response::new(full("rust")) })
        }
    }
    let mail = fake_upstream(|_| async {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full("not found\n"))
            .unwrap()
    })
    .await;
    let mut inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    for route in inventory["routes"].as_array_mut().unwrap() {
        if route["listener"] == "gateway"
            && route["method"] == "GET"
            && route["path"] == "/scim/v2/Users"
        {
            route["state"] = "ON".into();
            route["upstream"] = "local-rust".into();
        }
    }
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: Some(common::edge(600, common::Flags::On)),
        },
        RouteTable::proxy_all().with(Scim),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    let response = send(addr, Request::get("/scim/v2/Users").body(full("")).unwrap()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_bytes(response).await, "404 page not found\n");
    let metrics = send(addr, Request::get("/_gateway/metrics").body(full("")).unwrap()).await;
    let metrics = String::from_utf8(body_bytes(metrics).await.to_vec()).unwrap();
    assert!(metrics.lines().any(|line| line == "setjoin_gateway_proxied_to_go_total 0"));
}

/// Root review of item 3: with every Rust flag OFF the gateway must behave
/// as Go alone — a spent budget is not answered by the gateway; the request
/// reaches Go untouched and Go's own limiter decides.
#[tokio::test]
async fn flags_off_and_budget_spent_forwards_to_go() {
    let upstream = fake_upstream(|_req| async move { Response::new(full("go")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(0, common::Flags::Off),
    )
    .await;
    let resp = send(gw, Request::get("/api/settings").body(full("")).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, "go");
}

/// A Rust flag ON and the budget spent: Go's own 429 bytes, Go not reached.
#[tokio::test]
async fn a_flag_on_and_budget_spent_is_go_s_429() {
    let upstream = fake_upstream(|_req| async move { Response::new(full("go")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(0, common::Flags::On),
    )
    .await;
    let resp = send(gw, Request::get("/api/settings").body(full("")).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        &body_bytes(resp).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
}

/// The flag read stalls (or fails): counted as OFF, and the over-budget
/// request is forwarded to Go within the pre-check bound.
#[tokio::test]
async fn a_stalled_flag_read_with_budget_spent_forwards_within_the_bound() {
    let upstream = fake_upstream(|_req| async move { Response::new(full("go")) }).await;
    for flags in [common::Flags::Stalled, common::Flags::Failed] {
        let gw = common::gateway_limited(upstream, RouteTable::proxy_all(), common::edge(0, flags))
            .await;
        let t = std::time::Instant::now();
        let resp = send(gw, Request::get("/api/settings").body(full("")).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, "go");
        assert!(
            t.elapsed() < std::time::Duration::from_secs(3),
            "{:?}",
            t.elapsed()
        );
    }
}

#[tokio::test]
async fn ported_auth_requests_reach_rust_auth_upstream_directly() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("go auth")) }).await;
    let rust_auth = fake_upstream(|req| async move {
        Response::new(full(format!("rust auth {} {}", req.method(), req.uri())))
    })
    .await;
    let config = setjoin_gateway::Config {
        upstream: Some(format!("http://{mail}").parse().unwrap()),
        trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
        upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
        edge_limit: None,
    };
    let gateway = setjoin_gateway::Gateway::new(config, RouteTable::proxy_all())
        .unwrap()
        .with_auth_upstream(format!("http://{auth}").parse().unwrap())
        .unwrap()
        .with_rust_auth_upstream(format!("http://{rust_auth}").parse().unwrap())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    let response = send(
        addr,
        Request::post("/auth/refresh?next=%2F")
            .body(full("body"))
            .unwrap(),
    )
    .await;
    assert_eq!(
        body_bytes(response).await,
        "rust auth POST /auth/refresh?next=%2F"
    );
    let response = send(
        addr,
        Request::get("/authentication").body(full("")).unwrap(),
    )
    .await;
    assert_eq!(body_bytes(response).await, "mail");
}

#[tokio::test]
async fn inventory_dispatches_to_four_targets_and_keeps_off_routes_in_go() {
    let mail = fake_upstream(|_| async { Response::new(full("go mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("go auth")) }).await;
    let rust_auth =
        fake_upstream(|req| async move { Response::new(full(format!("rust auth {}", req.uri()))) })
            .await;
    let inventory = include_str!("../route-inventory.json");
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(TakeWhenAsked),
    )
    .unwrap()
    .with_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap()
    .with_rust_auth_upstream(format!("http://{rust_auth}").parse().unwrap())
    .unwrap()
    .with_inventory(inventory)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    for (method, path, expected) in [
        ("POST", "/jmap", "served by rust"),
        (
            "POST",
            "/auth/login?next=%2F",
            "rust auth /auth/login?next=%2F",
        ),
        (
            "GET",
            "/auth/password-policy",
            "rust auth /auth/password-policy",
        ),
        ("POST", "/auth/refresh", "rust auth /auth/refresh"),
        // SAML is ported (#546): the Rust auth upstream owns it.
        ("POST", "/auth/saml/idfed2/link", "rust auth /auth/saml/idfed2/link"),
        ("GET", "/admin/users", "go mail"),
        ("DELETE", "/auth/login", "go auth"),
    ] {
        let response = send(
            addr,
            Request::builder()
                .method(method)
                .uri(path)
                .header("x-take", "yes")
                .body(full("opaque body"))
                .unwrap(),
        )
        .await;
        assert_eq!(body_bytes(response).await, expected, "{method} {path}");
    }
}

#[tokio::test]
async fn kill_switch_forwards_every_request_to_go_without_interception() {
    let mail = fake_upstream(|req| async move {
        let head = format!(
            "{} {} {} {} ",
            req.method(),
            req.uri(),
            req.headers()["host"].to_str().unwrap(),
            req.headers()["x-custom"].to_str().unwrap()
        );
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(299)
            .body(full(format!("{head}{}", String::from_utf8_lossy(&body))))
            .unwrap()
    })
    .await;
    let auth = fake_upstream(|_| async { panic!("kill switch reached auth upstream") }).await;
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: Some(setjoin_gateway::jmap::limit::EdgeLimit::new(
                setjoin_gateway::jmap::limit::Limiter::new(0, 60),
                Arc::new(|| Box::pin(async { true })),
            )),
        },
        RouteTable::proxy_all().with(TakeWhenAsked),
    )
    .unwrap()
    .with_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap()
    .with_enabled(false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    for path in [
        "/jmap?x=%2F",
        "/auth/login",
        HEALTH_PATH,
        "/_gateway/metrics",
    ] {
        let response = send(
            addr,
            Request::post(path)
                .header("host", "mail.example.test")
                .header("x-custom", "opaque")
                .header("x-take", "yes")
                .body(full("body\0bytes"))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 299, "{path}");
        assert_eq!(
            body_bytes(response).await,
            format!("POST {path} mail.example.test opaque body\0bytes")
        );
    }
}

#[tokio::test]
async fn go_proxy_metrics_count_families_total_and_pilot_declines_once() {
    let mail = fake_upstream(|_| async { Response::new(full("go mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("go auth")) }).await;
    let rust_auth = fake_upstream(|_| async { Response::new(full("rust auth")) }).await;
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(TakeWhenAsked),
    )
    .unwrap()
    .with_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap()
    .with_rust_auth_upstream(format!("http://{rust_auth}").parse().unwrap())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    let metrics = || {
        send(
            addr,
            Request::get("/_gateway/metrics").body(full("")).unwrap(),
        )
    };
    let initial = metrics().await;
    assert_eq!(
        initial.headers()["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert!(String::from_utf8_lossy(&body_bytes(initial).await)
        .contains("setjoin_gateway_proxied_to_go_total 0\n"));
    for (method, path, take) in [
        ("GET", HEALTH_PATH, "no"),
        ("POST", "/jmap", "yes"),
        ("POST", "/jmap", "no"),
        ("GET", "/api/admin/users", "no"),
        ("POST", "/auth/refresh", "no"),
        // SAML is ported (#546): it reaches the Rust auth upstream and adds no Go forward.
        ("POST", "/auth/saml/idfed2/link", "no"),
    ] {
        let response = send(
            addr,
            Request::builder()
                .method(method)
                .uri(path)
                .header("x-take", take)
                .body(full(""))
                .unwrap(),
        )
        .await;
        let body = body_bytes(response).await;
        if path == "/auth/refresh" {
            assert_eq!(body, "rust auth", "ported auth must not reach Go");
        }
        if path == "/auth/saml/idfed2/link" {
            assert_eq!(body, "rust auth", "ported SAML must not reach Go");
        }
    }
    let body = String::from_utf8(body_bytes(metrics().await).await.to_vec()).unwrap();
    for line in [
        "setjoin_gateway_proxied_to_go_total 2",
        "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 1",
        "setjoin_gateway_proxied_to_go_by_family_total{family=\"F18\"} 1",
        "setjoin_gateway_proxied_to_go_by_family_total{family=\"F21\"} 0",
        "setjoin_gateway_proxied_to_go_by_family_total{family=\"F22\"} 0",
    ] {
        assert!(
            body.lines().any(|got| got == line),
            "missing {line} in {body}"
        );
    }
    assert_eq!(
        body_bytes(metrics().await).await,
        body,
        "scrapes must not increment Go counters"
    );
}

#[tokio::test]
async fn auth_csrf_is_scoped_to_the_listener() {
    let go_auth =
        fake_upstream(
            |req| async move { Response::new(full(format!("go auth {}", req.uri().path()))) },
        )
        .await;
    let rust_auth = fake_upstream(|req| async move {
        Response::new(full(format!("rust auth {}", req.uri().path())))
    })
    .await;
    let paths = ["/auth/totp/verify", "/auth/webauthn/login/finish"];
    for auth_only in [false, true] {
        for limited in [true, false] {
            for ported in [true, false] {
                let mut inventory: serde_json::Value =
                    serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
                let routes = inventory["routes"].as_array_mut().unwrap();
                if auth_only {
                    routes.retain(|row| row["listener"] == "auth");
                }
                if !ported {
                    for row in routes.iter_mut().filter(|row| {
                        row["listener"] == "auth" && paths.iter().any(|path| row["path"] == *path)
                    }) {
                        row["state"] = "OFF".into();
                    }
                }
                let gateway = setjoin_gateway::Gateway::new(
                    setjoin_gateway::Config {
                        upstream: None,
                        trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
                        upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                        edge_limit: limited.then(|| common::edge(600, common::Flags::On)),
                    },
                    RouteTable::proxy_all(),
                )
                .unwrap()
                .with_auth_upstream(format!("http://{go_auth}").parse().unwrap())
                .unwrap()
                .with_rust_auth_upstream(format!("http://{rust_auth}").parse().unwrap())
                .unwrap()
                .with_inventory(&inventory.to_string())
                .unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(gateway.serve(listener));
                for path in paths {
                    for origin in ["https://foreign.test", "http://mail.test"] {
                        let response = send(
                            address,
                            Request::post(path)
                                .header("host", "mail.test")
                                .header("origin", origin)
                                .body(full("{}"))
                                .unwrap(),
                        )
                        .await;
                        let context = format!("{path} auth_only={auth_only} limited={limited} ported={ported} origin={origin}");
                        if !auth_only && origin == "https://foreign.test" {
                            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{context}");
                            assert_eq!(
                                response.headers()["cache-control"],
                                "no-store",
                                "{context}"
                            );
                            assert_eq!(
                                response.headers()["x-content-type-options"],
                                "nosniff",
                                "{context}"
                            );
                            assert_eq!(body_bytes(response).await,
                                "{\"detail\":\"CSRF validation failed\",\"status\":403,\"title\":\"csrf_failed\",\"type\":\"about:blank\"}\n", "{context}");
                        } else {
                            assert_eq!(response.status(), StatusCode::OK, "{context}");
                            let upstream = if ported { "rust auth" } else { "go auth" };
                            assert_eq!(
                                body_bytes(response).await,
                                format!("{upstream} {path}"),
                                "{context}"
                            );
                        }
                    }
                }
                server.abort();
                let _ = server.await;
            }
        }
    }
}

#[tokio::test]
async fn auth_only_paths_reach_auth_without_overriding_gateway_routes() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    let rust_auth = fake_upstream(|_| async { Response::new(full("rust auth")) }).await;
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: Some(format!("http://{mail}").parse().unwrap()),
            trusted_proxies: setjoin_gateway::TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap()
    .with_rust_auth_upstream(format!("http://{rust_auth}").parse().unwrap())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    for (method, path, expected) in [
        ("GET", "/device/policy?device_id=1", "auth"),
        ("POST", "/device/checkin", "auth"),
        ("GET", "/api/v1/version", "rust auth"),
        ("GET", "/health", "mail"),
        ("GET", "/.well-known/setjoin", "mail"),
        ("POST", "/admin/reload", "mail"),
        ("POST", "/setup/restore", "mail"),
    ] {
        let response = send(
            addr,
            Request::builder()
                .method(method)
                .uri(path)
                .body(full(""))
                .unwrap(),
        )
        .await;
        assert_eq!(body_bytes(response).await, expected, "{method} {path}");
    }
}

#[tokio::test]
async fn escaped_pinned_paths_share_the_same_route_budget() {
    enough_window_time(60).await;
    let upstream = fake_upstream(|_| async { Response::new(full("go")) }).await;
    let gw = common::gateway_limited(
        upstream,
        RouteTable::proxy_all(),
        common::edge(600, common::Flags::On),
    )
    .await;
    for _ in 0..60 {
        let response = send(gw, Request::get("/setup/status").body(full("")).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = send(gw, Request::get("/s%65tup/status").body(full("")).unwrap()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        &body_bytes(response).await[..],
        include_bytes!("golden/go-rate-limited.json")
    );
}

#[tokio::test]
async fn unlimited_proxy_transport_preserves_go_oracle_csrf_requests() {
    let upstream = fake_upstream(|request| async move {
        assert_eq!(request.headers()["origin"], "https://foreign.test");
        Response::builder().status(403).body(full("frozen Go oracle")).unwrap()
    }).await;
    // The recorder has no local adapter or limiter: Go must see the request.
    let gateway = common::gateway(upstream, "", RouteTable::proxy_all()).await;
    let response=send(gateway,Request::post("/api/admin/departments")
        .header("host","mail.test").header("origin","https://foreign.test")
        .body(full("{}")).unwrap()).await;
    assert_eq!(response.status(),403);
    assert_eq!(body_bytes(response).await,"frozen Go oracle");
}

#[tokio::test]
async fn unlimited_local_adapters_still_enforce_global_csrf() {
    struct Local;
    impl Intercept for Local {
        fn matches(&self,_:&Request<Body>)->bool{true}
        fn handle(&self,_:Request<Body>,_:RequestContext)->BoxFuture<Response<Body>>{
            Box::pin(async {panic!("CSRF denial reached a local adapter")})
        }
    }
    let upstream=fake_upstream(|_|async{panic!("CSRF denial reached Go")}).await;
    let gateway=common::gateway(upstream,"",RouteTable::proxy_all().with(Local)).await;
    let response=send(gateway,Request::post("/api/admin/departments")
        .header("host","mail.test").header("origin","https://foreign.test")
        .body(full("{}")).unwrap()).await;
    assert_eq!(response.status(),403);
    assert_eq!(body_bytes(response).await,"{\"detail\":\"CSRF validation failed\",\"status\":403,\"title\":\"csrf_failed\",\"type\":\"about:blank\"}\n");
}
