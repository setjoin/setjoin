//! #410: the `/rtc` and `/rtc/` SFU signal proxy recorded from frozen Go.
//! Recording runs the frozen binary behind an empty route table with a fake
//! LiveKit signal peer on Go's hard-coded `127.0.0.1:7880`; replay serves the
//! same sessions natively against the same peer on an ephemeral port. A case
//! observes both ends: what the SFU received (request line, headers, body,
//! frames, close code) and what the client saw (upgrade answer, frames, close
//! code, plain answers, redirects, 502). The SFU is a fake peripheral: it
//! decides authentication (a bad or foreign token is answered 401/403 by it).
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
use common::BoxError;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{rtc::RtcRoute, Config, Gateway, RouteTable, TrustedProxies};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio_tungstenite::tungstenite::{protocol::Role, Message};
use tokio_tungstenite::WebSocketStream;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Sfu = Arc<Mutex<Vec<Value>>>;
type SfuBody = BoxBody<Bytes, Infallible>;

const KEY: &str = "meet5-key";
const SECRET: &str = "meet5-secret-meet5-secret-meet5-secret";

macro_rules! cases {
    ($($name:ident = $case:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run($case, Mutant::None).await
        }
    )*};
}

cases! {
    bare_ws_session = "bare-ws-session";
    bare_ws_bad_token = "bare-ws-bad-token";
    bare_other_room = "bare-other-room";
    bare_server_close = "bare-server-close";
    bare_plain_get = "bare-plain-get";
    bare_post_body = "bare-post-body";
    bare_upstream_down = "bare-upstream-down";
    sub_ws_session = "sub-ws-session";
    sub_validate_denied = "sub-validate-denied";
    sub_other_room = "sub-other-room";
    sub_unclean_redirect = "sub-unclean-redirect";
    sub_escaped_path = "sub-escaped-path";
    sub_gzip_decoded = "sub-gzip-decoded";
    sub_gzip_client = "sub-gzip-client";
    sub_spoofed_headers = "sub-spoofed-headers";
    sub_response_headers = "sub-response-headers";
    sub_chunked = "sub-chunked";
    sub_head = "sub-head";
    sub_upgrade_mismatch = "sub-upgrade-mismatch";
    sub_member_cookie = "sub-member-cookie";
}

#[derive(Clone, Copy, PartialEq)]
enum Mutant {
    None,
    /// The proxy strips one path segment too many (`/rtc/rtc/v1` -> `/v1`).
    OverStrip,
    /// The proxy answers a plain request with a changed status.
    Status,
}

#[tokio::test]
async fn planted_overstrip_mutant_fails_the_golden() -> Result<(), BoxError> {
    let failure = run("sub-ws-session", Mutant::OverStrip).await;
    assert!(
        failure.is_err(),
        "a proxy that strips an extra path segment must not match the Go recording"
    );
    println!("MUTANT-REJECTED: * /rtc/ :: mutant"); // strips an extra path segment
    Ok(())
}

#[tokio::test]
async fn planted_status_mutant_fails_the_golden() -> Result<(), BoxError> {
    let failure = run("bare-plain-get", Mutant::Status).await;
    assert!(
        failure.is_err(),
        "a proxy that changes the answer status must not match the Go recording"
    );
    println!("MUTANT-REJECTED: * /rtc :: mutant"); // changes the answer status
    Ok(())
}

fn sub(case: &str) -> bool {
    case.starts_with("sub-")
}

/// The request path a case sends through the front door.
fn target(case: &str) -> &'static str {
    match case {
        "bare-ws-session" => "/rtc?access_token=good&auto_subscribe=1",
        "bare-ws-bad-token" => "/rtc?access_token=bad",
        "bare-other-room" => "/rtc?access_token=room-b",
        "bare-server-close" => "/rtc?access_token=good&close=1",
        "bare-plain-get" => "/rtc",
        "bare-post-body" => "/rtc",
        "bare-upstream-down" => "/rtc?access_token=good",
        "sub-ws-session" => "/rtc/rtc/v1?access_token=good&protocol=15&sdk=js",
        "sub-validate-denied" => "/rtc/rtc/validate?access_token=bad",
        "sub-other-room" => "/rtc/rtc/validate?access_token=room-b",
        "sub-unclean-redirect" => "/rtc//rtc/./x/../v1?access_token=good",
        "sub-escaped-path" => "/rtc/rtc/a%20b%2Fc%21?x=1&y=%20",
        "sub-gzip-decoded" | "sub-gzip-client" => "/rtc/gzip",
        "sub-spoofed-headers" => "/rtc/echo",
        "sub-response-headers" => "/rtc/headers",
        "sub-chunked" => "/rtc/chunked",
        "sub-head" => "/rtc/echo",
        "sub-upgrade-mismatch" => "/rtc/mismatch",
        "sub-member-cookie" => "/rtc/rtc/v1?access_token=good",
        _ => unreachable!("unknown case"),
    }
}

fn websocket(case: &str) -> bool {
    matches!(
        case,
        "bare-ws-session"
            | "bare-ws-bad-token"
            | "bare-other-room"
            | "bare-server-close"
            | "bare-upstream-down"
            | "sub-ws-session"
            | "sub-upgrade-mismatch"
            | "sub-member-cookie"
    )
}

fn mask(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(at) = rest.find("127.0.0.1:") {
        out.push_str(&rest[..at]);
        out.push_str("<sfu>");
        rest = &rest[at + 10..];
        rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    out.push_str(rest);
    out
}

/// The fake SFU signal peer. `bind` is Go's fixed port when recording.
async fn sfu(bind: &str, events: Sfu) -> Result<SocketAddr, BoxError> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let events = events.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let events = events.clone();
                    async move { Ok::<_, Infallible>(peer(req, events).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    Ok(addr)
}

fn full(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Response<SfuBody> {
    let mut b = Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::copy_from_slice(body)).boxed())
        .unwrap()
}

async fn peer(mut req: Request<Incoming>, events: Sfu) -> Response<SfuBody> {
    let target = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let mut headers = serde_json::Map::new();
    for (k, v) in req.headers() {
        let name = k.as_str();
        let value = v.to_str().unwrap_or("<binary>");
        let value = match name {
            "host" => mask(value),
            "sec-websocket-key" => "<key>".to_owned(),
            "cookie" => "access_token=<jwt>".to_owned(),
            _ => value.to_owned(),
        };
        let slot = headers.entry(name.to_owned()).or_insert(json!([]));
        slot.as_array_mut().unwrap().push(json!(value));
    }
    // Frozen Go's own startup polls the SFU's twirp API; that is not /rtc traffic.
    if path.starts_with("/twirp/") {
        return full(200, &[("content-type", "application/protobuf")], b"");
    }
    let wants_upgrade = req.headers().contains_key("upgrade");
    let method = req.method().to_string();
    let key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let on_upgrade = hyper::upgrade::on(&mut req);
    let accept_gzip = req
        .headers()
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"));
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let note = |extra: Value| {
        let mut entry = json!({"method":method,"target":target,"headers":headers,
            "body":String::from_utf8_lossy(&body)});
        entry
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().cloned().unwrap_or_default());
        events.lock().unwrap().push(json!({"request":entry}));
    };
    let token = query
        .split('&')
        .find_map(|p| p.strip_prefix("access_token="))
        .unwrap_or("");
    if path == "/mismatch" {
        note(json!({}));
        return full(101, &[("connection", "upgrade"), ("upgrade", "h2c")], b"");
    }
    if wants_upgrade {
        note(json!({}));
        match token {
            "good" => {}
            "room-b" => {
                return full(
                    403,
                    &[("content-type", "text/plain; charset=utf-8")],
                    b"permission denied\n",
                )
            }
            _ => {
                return full(
                    401,
                    &[("content-type", "text/plain; charset=utf-8")],
                    b"invalid token\n",
                )
            }
        }
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(
            key.unwrap_or_default().as_bytes(),
        );
        let close_first = query.contains("close=1");
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let mut ws =
                WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
            if close_first {
                let _ = ws.send(Message::Text("hello from sfu".into())).await;
                let _ = ws
                    .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                        code: 4000.into(),
                        reason: "sfu says bye".into(),
                    }))
                    .await;
            }
            while let Some(Ok(msg)) = ws.next().await {
                let seen = match &msg {
                    Message::Text(t) => json!({"text": t.as_str()}),
                    Message::Binary(b) => json!({"binary": b.to_vec()}),
                    Message::Ping(p) => json!({"ping": p.to_vec()}),
                    Message::Pong(p) => json!({"pong": p.to_vec()}),
                    Message::Close(c) => {
                        json!({"close": c.as_ref().map(|c| json!({"code":u16::from(c.code),"reason":c.reason.as_str()}))})
                    }
                    Message::Frame(_) => continue,
                };
                events.lock().unwrap().push(json!({"sfu_received": seen}));
                match msg {
                    Message::Text(t) if t.as_str() == "ping-me" => {
                        let _ = ws.send(Message::Ping(vec![9, 9].into())).await;
                    }
                    Message::Text(t) => {
                        let _ = ws.send(Message::Text(format!("echo:{t}").into())).await;
                    }
                    Message::Binary(b) => {
                        let mut doubled = b.to_vec();
                        doubled.reverse();
                        let _ = ws.send(Message::Binary(doubled.into())).await;
                    }
                    _ => {}
                }
            }
        });
        return full(
            101,
            &[
                ("connection", "Upgrade"),
                ("upgrade", "websocket"),
                ("sec-websocket-accept", &accept),
                ("sec-websocket-protocol", "livekit"),
                ("x-sfu-node", "node-1"),
            ],
            b"",
        );
    }
    note(json!({}));
    match path.as_str() {
        "/rtc/v1" | "/validate" | "/v1/validate" => match token {
            "good" => full(
                200,
                &[("content-type", "text/plain; charset=utf-8")],
                b"success",
            ),
            "room-b" => full(
                403,
                &[("content-type", "text/plain; charset=utf-8")],
                b"permission denied\n",
            ),
            _ => full(
                401,
                &[("content-type", "text/plain; charset=utf-8")],
                b"invalid token\n",
            ),
        },
        "/gzip" => {
            if accept_gzip {
                use std::io::Write;
                let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                z.write_all(b"compressed signal answer").unwrap();
                full(
                    200,
                    &[
                        ("content-type", "text/plain; charset=utf-8"),
                        ("content-encoding", "gzip"),
                    ],
                    &z.finish().unwrap(),
                )
            } else {
                full(
                    200,
                    &[("content-type", "text/plain; charset=utf-8")],
                    b"plain signal answer",
                )
            }
        }
        "/headers" => full(
            200,
            &[
                ("content-type", "application/json"),
                ("x-content-type-options", "sfu-value"),
                ("cache-control", "max-age=60"),
                ("set-cookie", "a=1; Path=/"),
                ("set-cookie", "b=2; Path=/"),
                ("keep-alive", "timeout=5"),
                ("x-sfu-node", "node-2"),
                ("location", "/elsewhere"),
            ],
            b"{}",
        ),
        "/chunked" => {
            let chunks = futures_util::stream::iter(
                ["one,", "two,", "three"].map(|c| Ok::<_, Infallible>(Frame::data(Bytes::from(c)))),
            );
            Response::builder()
                .status(200)
                .header("content-type", "text/plain; charset=utf-8")
                .body(BodyExt::boxed(StreamBody::new(chunks)))
                .unwrap()
        }
        _ => full(
            200,
            &[
                ("content-type", "application/json"),
                ("x-sfu-node", "node-3"),
            ],
            json!({"path":path}).to_string().as_bytes(),
        ),
    }
}

/// Everything the client saw of a plain (non-upgrade) answer.
async fn plain(
    addr: SocketAddr,
    method: &str,
    case: &str,
    extra: &[(&str, &str)],
    body: &'static str,
) -> Result<Value, BoxError> {
    let mut b = Request::builder()
        .method(method)
        .uri(target(case))
        .header("host", "mail.test")
        .header("x-request-id", "meet5-rtc");
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let resp = common::send(addr, b.body(common::full(body))?).await;
    observe(resp).await
}

async fn observe(resp: Response<Incoming>) -> Result<Value, BoxError> {
    let status = resp.status().as_u16();
    let headers = filtered(resp.headers(), status == 101);
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok(json!({"status":status,"headers":headers,"body":String::from_utf8_lossy(&bytes)}))
}

fn filtered(h: &hyper::HeaderMap, keep_connection: bool) -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in h {
        let name = k.as_str();
        if matches!(
            name,
            "date" | "content-length" | "transfer-encoding" | "sec-websocket-accept"
        ) || (!keep_connection && name == "connection")
        {
            continue;
        }
        let slot = out.entry(name.to_owned()).or_insert(json!([]));
        slot.as_array_mut()
            .unwrap()
            .push(json!(v.to_str().unwrap_or("<binary>")));
    }
    Value::Object(out)
}

/// One WebSocket session through the front door.
async fn session(addr: SocketAddr, case: &str, extra: &[(&str, &str)]) -> Result<Value, BoxError> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://mail.test{}", target(case)).into_client_request()?;
    {
        let h = request.headers_mut();
        h.insert("origin", "http://mail.test".parse()?);
        h.insert("x-request-id", "meet5-rtc".parse()?);
        h.insert("sec-websocket-protocol", "livekit".parse()?);
        for (k, v) in extra {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes())?,
                v.parse()?,
            );
        }
    }
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio_tungstenite::client_async(request, stream),
    )
    .await?;
    let (mut ws, response) = match handshake {
        Ok(pair) => pair,
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            let body = response
                .body()
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            return Ok(
                json!({"handshake":"refused","status":response.status().as_u16(),
                "headers":filtered(response.headers(), false),"body":body}),
            );
        }
        Err(other) => return Ok(json!({"handshake":"failed","error":format!("{other}")})),
    };
    let mut seen = Vec::new();
    let mut script: Vec<Message> = vec![
        Message::Text("hello".into()),
        Message::Binary(vec![1, 2, 3].into()),
        Message::Text("ping-me".into()),
    ];
    if case.contains("server-close") {
        script.clear();
    }
    let mut expect: i32 = match case {
        "bare-server-close" => 0,
        _ => 3,
    };
    for message in script {
        ws.send(message).await?;
    }
    let mut closing = false;
    loop {
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await;
        match next {
            Ok(Some(Ok(Message::Text(t)))) => {
                seen.push(json!({"text":t.as_str()}));
                expect = expect.saturating_sub(1);
            }
            Ok(Some(Ok(Message::Binary(b)))) => {
                seen.push(json!({"binary":b.to_vec()}));
                expect = expect.saturating_sub(1);
            }
            Ok(Some(Ok(Message::Ping(p)))) => {
                seen.push(json!({"ping":p.to_vec()}));
                expect = expect.saturating_sub(1);
            }
            Ok(Some(Ok(Message::Pong(p)))) => seen.push(json!({"pong":p.to_vec()})),
            Ok(Some(Ok(Message::Close(c)))) => {
                seen.push(json!({"close":c.map(|c| json!({"code":u16::from(c.code),"reason":c.reason.as_str()}))}));
                break;
            }
            Ok(Some(Ok(Message::Frame(_)))) => {}
            Ok(Some(Err(error))) => {
                seen.push(json!({"error":format!("{error}")}));
                break;
            }
            Ok(None) => {
                seen.push(json!("eof"));
                break;
            }
            Err(_) => {
                seen.push(json!("timeout"));
                break;
            }
        }
        if expect == 0 && !closing && !case.contains("server-close") {
            closing = true;
            ws.send(Message::Close(Some(
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: 1000.into(),
                    reason: "client done".into(),
                },
            )))
            .await?;
        }
    }
    Ok(json!({"handshake":"ok","status":response.status().as_u16(),
        "headers":filtered(response.headers(), true),"frames":seen}))
}

async fn run(case: &'static str, mutant: Mutant) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let recording = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    if mutant != Mutant::None && recording {
        return Err("cannot record a planted mutant".into());
    }
    let Some(db) = Db::for_case("meet5-rtc") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let member = fixture::account(&c, "meet5-member").await?;
    let events: Sfu = Arc::default();
    let down = case.ends_with("upstream-down");
    let sfu_addr = if down {
        // A port nothing listens on: bind then release.
        let l = setjoin_conformance::ports::listener().await;
        let a = l.local_addr()?;
        drop(l);
        a
    } else {
        sfu(
            if recording {
                "127.0.0.1:7880"
            } else {
                "127.0.0.1:0"
            },
            events.clone(),
        )
        .await?
    };
    let result = std::panic::AssertUnwindSafe(async {
        let go_env: Vec<(&str, String)> = vec![
            ("LIVEKIT_API_KEY", KEY.into()),
            ("LIVEKIT_API_SECRET", SECRET.into()),
            ("LIVEKIT_URL", "ws://127.0.0.1:7880".into()),
        ];
        let unused =
            common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let oracle = common::go_oracle::start_named_with_env(
            &Db {
                dsn: db.dsn.clone(),
                direct: db.direct.clone(),
                app: db.app.clone(),
            },
            unused,
            "gofree-meet5",
            &go_env,
        )
        .await?;
        let routes = if oracle.is_some() {
            RouteTable::proxy_all()
        } else {
            let exec = patient(db.app.as_deref().unwrap_or(&db.dsn))?;
            let route = RtcRoute::new(
                exec,
                Arc::new(common::recovery_keys()),
                "mailserver".into(),
                true,
                sfu_addr,
            );
            RouteTable::proxy_all().with(Mutated(route, mutant))
        };
        let gateway = Gateway::new(
            Config {
                upstream: oracle
                    .as_ref()
                    .map(|o| format!("http://{}", o.address).parse())
                    .transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            routes,
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let cookie = format!(
            "access_token={}",
            meet_fixture::token(member.user, "meet5-rtc")
        );
        let client = match case {
            "bare-post-body" => {
                plain(
                    addr,
                    "POST",
                    case,
                    &[("content-type", "text/plain")],
                    "signal body",
                )
                .await?
            }
            "bare-plain-get" => plain(addr, "GET", case, &[], "").await?,
            "sub-head" => plain(addr, "HEAD", case, &[], "").await?,
            "sub-gzip-client" => {
                plain(addr, "GET", case, &[("accept-encoding", "gzip")], "").await?
            }
            "sub-spoofed-headers" => {
                plain(
                    addr,
                    "GET",
                    case,
                    &[
                        ("x-forwarded-for", "9.9.9.9"),
                        ("x-forwarded-host", "evil.test"),
                        ("x-forwarded-proto", "https"),
                        ("forwarded", "for=8.8.8.8"),
                        ("connection", "x-hop, keep-alive"),
                        ("x-hop", "dropped"),
                        ("te", "trailers, deflate"),
                        ("user-agent", "meet5/1"),
                        ("x-custom", "kept"),
                    ],
                    "",
                )
                .await?
            }
            "sub-member-cookie" => session(addr, case, &[("cookie", &cookie)]).await?,
            c if websocket(c) => session(addr, c, &[]).await?,
            _ => plain(addr, "GET", case, &[], "").await?,
        };
        server.abort();
        let _ = server.await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let upstream = events.lock().unwrap().clone();
        let observation = json!({
            "request": {"method": "*", "path": if sub(case) { "/rtc/" } else { "/rtc" },
                        "actual": target(case)},
            "response": {"status": client.get("status").cloned().unwrap_or(json!(0))},
            "client": client,
            "sfu": upstream,
            "effects": {}, "audit": [], "notify": [],
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/conformance/meet/goldens/rtc-{case}.json"
        ));
        let label = format!("* {}", if sub(case) { "/rtc/" } else { "/rtc" });
        if recording {
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"route":label,"case":format!("rtc-{case}"),
                    "go_source":std::env::var("GOFREE_GO_SOURCE")?,
                    "normalization":["SFU host masked; websocket key masked"],
                    "observation":observation}),
            )?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            setjoin_conformance::golden::compare(&expected["observation"], &observation)?;
            println!("GOLDEN-REPLAY: {label} :: rtc-{case}");
        }
        Ok::<_, BoxError>(())
    })
    .await;
    fixture::remove(&c, &member).await?;
    result
}

fn patient(dsn: &str) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let wait = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        2,
        setjoin_pg::Timeouts {
            pool_wait: wait,
            create: wait,
            statement: wait,
        },
    )
    .map_err(|e| e.0)?
    .with_audit_keys("22".repeat(32), String::new()))
}

/// Runs the real adapter; the planted mutant over-strips the request path.
struct Mutated<K: setjoin_authz::token::KeySource + 'static>(RtcRoute<K>, Mutant);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for Mutated<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        mut r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        if self.1 == Mutant::OverStrip {
            if let Some(rest) = r.uri().path().strip_prefix("/rtc/rtc") {
                let query = r.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
                *r.uri_mut() = format!("/rtc{rest}{query}").parse().unwrap();
            }
        }
        let reply = self.0.handle(r, c);
        let status = self.1 == Mutant::Status;
        Box::pin(async move {
            let mut reply = reply.await;
            if status {
                *reply.status_mut() = hyper::StatusCode::from_u16(599).unwrap();
            }
            reply
        })
    }
}
