//! F06 slice `dlp`: the unauthenticated link-protect click, frozen-Go oracle replayed without a
//! Go upstream. Go resolves the Spamhaus DBL through a fake DNS server (its container's
//! `resolv.conf` names it, Rust is given the same server), the token key is the fixed oracle
//! secret, and the audit rows the reducer writes are the observed effects.
mod common;
#[allow(dead_code, unused_imports)]
mod mailsec_oracle;
use common::BoxError;
use hmac::{Hmac, Mac};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    link_protect::{FixedDns, LinkProtectRoute, Scanners, TokenKeys, SAFE_BROWSING_ENDPOINT},
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::Sha256;
use std::net::UdpSocket;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SECRET: &str = "blobs1-test-jwt-secret-for-recording";
const DNS_IP: &str = "127.0.0.66";
const FAR: i64 = 4_102_444_800;

struct Probe {
    inner: LinkProtectRoute,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
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

/// `SignTokenN`: base64(payload).base64(HMAC-SHA256(key, base64(payload))), key derived per version.
fn sign(
    url: &str,
    message: &str,
    mailbox: i64,
    expires: i64,
    secret: &str,
    version: i64,
) -> String {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    let payload = format!(
        "{{\"u\":{},\"m\":{},\"b\":{mailbox},\"e\":{expires}}}",
        serde_json::to_string(url)
            .unwrap()
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026"),
        serde_json::to_string(message).unwrap()
    );
    let b64 = URL_SAFE.encode(payload);
    let mut kdf = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    kdf.update(format!("link-protect-v{version}: link-protect token hmac key").as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&kdf.finalize().into_bytes()).unwrap();
    mac.update(b64.as_bytes());
    format!("{b64}.{}", URL_SAFE.encode(mac.finalize().into_bytes()))
}

/// A tiny DBL: `evil*` is listed (127.0.1.2), `servfail*` answers SERVFAIL, `refused*` REFUSED,
/// `other*` is listed outside the DBL's 127.0.1.x range, every other name is NXDOMAIN.
fn serve_dns(socket: UdpSocket) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let p = &buf[..n];
            if p.len() < 17 {
                continue;
            }
            let mut at = 12;
            let mut first = String::new();
            let mut labels = 0;
            while p[at] != 0 {
                let len = p[at] as usize;
                if labels == 0 {
                    first = String::from_utf8_lossy(&p[at + 1..at + 1 + len]).to_lowercase();
                }
                labels += 1;
                at += 1 + len;
            }
            let qtype = u16::from_be_bytes([p[at + 1], p[at + 2]]);
            let question = &p[12..at + 5];
            let (rcode, answer): (u8, Option<[u8; 4]>) = if first.starts_with("evil") {
                (0, (qtype == 1).then_some([127, 0, 1, 2]))
            } else if first.starts_with("other") {
                (0, (qtype == 1).then_some([127, 0, 2, 2]))
            } else if first.starts_with("servfail") {
                (2, None)
            } else if first.starts_with("refused") {
                (5, None)
            } else {
                (3, None)
            };
            let mut out = vec![
                p[0],
                p[1],
                0x81 | (p[2] & 1),
                0x80 | rcode,
                0,
                1,
                0,
                u8::from(answer.is_some()),
                0,
                0,
                0,
                0,
            ];
            out.extend_from_slice(question);
            if let Some(ip) = answer {
                out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                out.extend_from_slice(&ip);
            }
            let _ = socket.send_to(&out, peer);
        }
    });
}

fn tidy(text: &str, token: &str) -> String {
    let text = if token.is_empty() { text.to_owned() } else { text.replace(token, "<token>") };
    mailsec_oracle::mask_timestamps(&text)
}

async fn run(label: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let mutant = label.ends_with("-status-mutant");
    let label = label.strip_suffix("-status-mutant").unwrap_or(label);
    let Some(db) = Db::for_case("mailsec1-http") else {
        return Ok(());
    };
    let dns_ip:std::net::Ipv4Addr=std::env::var("GOFREE_LINKPROTECT_DNS_IP").unwrap_or_else(|_|DNS_IP.into()).parse()?;
    if !dns_ip.is_loopback(){return Err("oracle DNS must be loopback".into());}
    let dns=std::net::SocketAddr::from((dns_ip,53));
    let prefix=std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_|"gofree-mailsec1".into());
    let resolv=std::env::temp_dir().join(format!("{prefix}-linkprotect-resolv.conf"));
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mailsec1-actor").await?;
    let b = fixture::account(&owner, "mailsec1-other").await?;
    // The audit table is global: move foreign rows aside, restore them afterwards.
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(t)::text FROM link_protect_audit t", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner.batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM link_protect_audit; COMMIT;").await?;
    let strict_before: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.link_protect_strict_mode'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    if label == "strict-on" {
        owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.link_protect_strict_mode'", &[]).await?;
    }
    let mut message_id = String::new();
    if matches!(label, "message-found" | "foreign-message") {
        let owner_of = if label == "message-found" { &a } else { &b };
        message_id = "<lp-oracle-1@oracle.test>".into();
        owner.execute(
            "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, thread_id, raw_ref, received_at, is_read) VALUES ($1,$2,$3,'lp','x@y.test',10,'thr-lp','raw-lp','2026-10-01T10:00:00Z',false)",
            &[&owner_of.mailbox, &owner_of.inbox, &message_id],
        ).await?;
    }
    let (url, extra_env): (String, Vec<(&'static str, String)>) = match label {
        "safe" | "repeat" | "message-found" | "foreign-message" | "strict-on-safe" => {
            ("https://ok.example/page?a=1".into(), vec![])
        }
        "malicious" | "rotated-current" | "previous-key" => {
            ("https://evil.example/phish".into(), vec![])
        }
        "userinfo-decoy" => ("http://internal.test:80@evil.example/".into(), vec![]),
        "dns-error" | "strict-on" | "unknown-continue" | "refused" => {
            ("https://servfail.example/x".into(), vec![])
        }
        "confirm" => ("https://servfail.example/c?x=1&y=2".into(), vec![]),
        "outside-dbl-range" => ("https://other.example/".into(), vec![]),
        "bare-domain" => ("ok.example/path?x=1".into(), vec![]),
        "relative-dotdot" => ("../up/../x/".into(), vec![]),
        "bad-url" => ("http://[bad/".into(), vec![]),
        "opaque" => ("mailto:a@evil.example".into(), vec![]),
        "ipv6" => ("http://[::1]:8080/p".into(), vec![]),
        "port-and-case" => ("HTTPS://EVIL.Example:8443/Case".into(), vec![]),
        "escapes" => ("https://ok.example/?a=<b>&c=\"d\"&e='f'".into(), vec![]),
        "unicode" => ("https://ok.example/\u{e9}\u{4e2d}".into(), vec![]),
        "bad-escape" => ("https://ok.example/%zz".into(), vec![]),
        "empty-url" => (String::new(), vec![]),
        "ftp" => ("ftp://ok.example/file".into(), vec![]),
        _ => ("https://ok.example/".into(), vec![]),
    };
    let mut extra_env = extra_env;
    let rotating = matches!(
        label,
        "rotated-current" | "previous-key" | "rotated-old-after-drain" | "v1-token-at-v2"
    );
    if rotating {
        extra_env.push(("JWT_LINK_PROTECT_TOKEN_VERSION", "2".into()));
        if label != "rotated-old-after-drain" {
            extra_env.push((
                "JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET",
                "previous-secret-for-oracle-padded-to-32-chars".into(),
            ));
        }
    }
    let token = match label {
        "bad-format" => "nodot".to_owned(),
        "bad-sig" => {
            let t = sign(&url, &message_id, a.mailbox, FAR, SECRET, 1);
            format!("{}.AAAA", t.split('.').next().unwrap())
        }
        "bad-sig-encoding" => {
            let t = sign(&url, &message_id, a.mailbox, FAR, SECRET, 1);
            format!("{}.@@@@", t.split('.').next().unwrap())
        }
        "tampered" => {
            let t = sign(&url, &message_id, a.mailbox, FAR, SECRET, 1);
            let (p, s) = t.split_once('.').unwrap();
            format!("{}x.{s}", p)
        }
        "expired" => sign(&url, &message_id, a.mailbox, 1_000_000_000, SECRET, 1),
        "wrong-key" => sign(&url, &message_id, a.mailbox, FAR, "some-other-secret", 1),
        "rotated-current" => sign(&url, &message_id, a.mailbox, FAR, SECRET, 2),
        "previous-key" | "rotated-old-after-drain" => sign(
            &url,
            &message_id,
            a.mailbox,
            FAR,
            "previous-secret-for-oracle-padded-to-32-chars",
            1,
        ),
        "v1-token-at-v2" => sign(&url, &message_id, a.mailbox, FAR, SECRET, 1),
        "missing-token" => String::new(),
        "foreign-mailbox" => sign(&url, &message_id, b.mailbox, FAR, SECRET, 1),
        "no-message-id" => sign(&url, "", a.mailbox, FAR, SECRET, 1),
        "mailbox-zero" => sign(&url, &message_id, 0, FAR, SECRET, 1),
        "mailbox-negative" => sign(&url, &message_id, -1, FAR, SECRET, 1),
        _ => sign(&url, &message_id, a.mailbox, FAR, SECRET, 1),
    };
    let query = match label {
        "missing-token" => String::new(),
        "empty-token" => "?token=".into(),
        "extra-params" => format!("?x=1&token={}&confirm=0", urlenc(&token)),
        "confirm" | "unknown-continue" | "confirm-on-safe" => {
            format!("?token={}&confirm=1", urlenc(&token))
        }
        "confirm-other" => format!("?token={}&confirm=yes", urlenc(&token)),
        _ => format!("?token={}", urlenc(&token)),
    };
    let query = if label == "double-token" {
        format!("?token={}&token=junk", urlenc(&token))
    } else {
        query
    };
    let result = async {
        // One fake DNS server per process: its thread never exits, so every case shares it.
        static DNS_SERVER: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
        DNS_SERVER
            .get_or_init(|| {
                let socket = UdpSocket::bind(dns).map_err(|e| format!("fake DNS needs {dns} (run as root): {e}"))?;
                serve_dns(socket);
                Ok(())
            })
            .clone()?;
        std::fs::write(&resolv,format!("nameserver {dns_ip}\noptions timeout:2 attempts:1\n"))?;
        std::env::set_var("GOFREE_ORACLE_RESOLV_CONF", &resolv);
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        // Go resolves the audited message through the request pool without a tenant GUC; the
        // pre-flip owner pool is the behaviour to record.
        let go = common::go_oracle::start_unscoped_with_env(&db, s3, "gofree-mailsec1-http", &extra_env).await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let timeouts = || setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts()).map_err(|e| e.0)?.with_audit_keys("22".repeat(32), String::new());
        let (version, previous) = if rotating { (2, if label == "rotated-old-after-drain" { "" } else { "previous-secret-for-oracle-padded-to-32-chars" }) } else { (1, "") };
        let route = LinkProtectRoute {
            worker,
            keys: TokenKeys::new(SECRET.as_bytes(), previous.as_bytes(), version),
            scanners: Scanners { safe_browsing_key: String::new(), safe_browsing_endpoint: SAFE_BROWSING_ENDPOINT.into(), dns: Arc::new(FixedDns(dns)) },
        };
        let adapter = Probe { inner: route, changed_status: mutant };
        let mut inventory: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F06" && r["path"] == "/link-protect" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
                r["oracle_mutators"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let send = || async {
            let request = Request::builder().method("GET").uri(format!("/link-protect{query}")).header("host", "mail.test").header("x-request-id", "gofree-mailsec1-oracle").body(common::full(""))?;
            Ok::<_, BoxError>(common::send(address, request).await)
        };
        if label == "repeat" {
            let first = send().await?;
            let data = common::body_bytes_unchecked(first).await;
            let _ = data;
        }
        let snapshot = || async {
            let found = owner.query("SELECT jsonb_build_object('url_hash',url_hash,'verdict',verdict,'scanner',scanner,'message_resolved',message_id IS NOT NULL,'mailbox',CASE WHEN mailbox_id=$1 THEN '<mailbox-actor>' WHEN mailbox_id=$2 THEN '<mailbox-other>' ELSE mailbox_id::text END,'client_ip',client_ip,'created_recent',created_at>now()-interval '1 hour')::text FROM link_protect_audit ORDER BY id", &[&a.mailbox, &b.mailbox]).await?;
            found.iter().map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)).map_err(BoxError::from)).collect::<Result<Vec<_>, _>>()
        };
        let before = snapshot().await?;
        let response = send().await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot().await?;
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        let text = tidy(&raw, &token);
        if let Some(length) = headers.get_mut("content-length") { *length = json!([text.len().to_string()]); }
        let effects = json!([{"table":"link_protect_audit","before":before,"after":after}]);
        let shown_query = tidy(&query, &urlenc(&token));
        let shown_query = if token.is_empty() { shown_query } else { shown_query.replace(&token, "<token>") };
        let mut request = json!({"method":"GET","path":"/link-protect","external_path":"/link-protect"});
        if !shown_query.is_empty() { request["query"] = json!(shown_query); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":[],"notify":[]});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F06\"} 0") {
                return Err(format!("F06 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/mail-security/goldens");
        std::fs::create_dir_all(&dir)?;
        let stem = format!("dlp-click-{label}");
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = "GET /link-protect";
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else if matches!(label, "mailbox-zero" | "mailbox-negative") {
            // D-357e-1: Go audits under mailbox <= 0 and follows the verdict (recorded);
            // Rust fails closed to the warn interstitial and writes nothing.
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            if observation["response"]["status"] != json!(200) || !text.contains("<title>Warning") {
                return Err(format!("{label}: expected the warn interstitial, got {observation}").into());
            }
            if observation["effects"][0]["after"] != observation["effects"][0]["before"] {
                return Err(format!("{label}: an unscoped click wrote an audit row").into());
            }
            eprintln!("GOLDEN-DIVERGENCE: {route_name} :: {label} (Go status {})", expected["observation"]["response"]["status"]);
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            compared?;
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup touches only this case's rows.
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM link_protect_audit;",
        )
        .await?;
    for row in &stash {
        owner.execute("INSERT INTO link_protect_audit SELECT * FROM jsonb_populate_record(NULL::link_protect_audit, $1::text::jsonb)", &[row]).await?;
    }
    owner.batch_execute("COMMIT;").await?;
    if message_id.as_str() != "" {
        owner
            .execute("DELETE FROM messages WHERE message_id=$1", &[&message_id])
            .await?;
    }
    if let (true, Some(before)) = (label == "strict-on", strict_before) {
        owner.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.link_protect_strict_mode'", &[&before]).await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F06' AND command='link_protect.click'", &[]).await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    let _=std::fs::remove_file(resolv);
    result
}

fn urlenc(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}

macro_rules! case {
    ($name:ident, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run($kind).await
        }
    };
}

case!(click_safe, "safe");
case!(click_malicious, "malicious");
case!(click_repeat, "repeat");
case!(click_missing_token, "missing-token");
case!(click_empty_token, "empty-token");
case!(click_bad_format, "bad-format");
case!(click_bad_sig, "bad-sig");
case!(click_bad_sig_encoding, "bad-sig-encoding");
case!(click_tampered, "tampered");
case!(click_expired, "expired");
case!(click_wrong_key, "wrong-key");
case!(click_dns_error, "dns-error");
case!(click_refused, "refused");
case!(click_confirm, "confirm");
case!(click_confirm_on_safe, "confirm-on-safe");
case!(click_confirm_other, "confirm-other");
case!(click_strict_on, "strict-on");
case!(click_outside_dbl_range, "outside-dbl-range");
case!(click_userinfo_decoy, "userinfo-decoy");
case!(click_bare_domain, "bare-domain");
case!(click_relative_dotdot, "relative-dotdot");
case!(click_bad_url, "bad-url");
case!(click_opaque, "opaque");
case!(click_ipv6, "ipv6");
case!(click_port_and_case, "port-and-case");
case!(click_escapes, "escapes");
case!(click_unicode, "unicode");
case!(click_bad_escape, "bad-escape");
case!(click_empty_url, "empty-url");
case!(click_ftp, "ftp");
case!(click_message_found, "message-found");
case!(click_mailbox_zero, "mailbox-zero");
case!(click_mailbox_negative, "mailbox-negative");
case!(click_foreign_message, "foreign-message");
case!(click_foreign_mailbox, "foreign-mailbox");
case!(click_no_message_id, "no-message-id");
case!(click_extra_params, "extra-params");
case!(click_double_token, "double-token");
case!(click_rotated_current, "rotated-current");
case!(click_previous_key, "previous-key");
case!(click_rotated_old_after_drain, "rotated-old-after-drain");
case!(click_v1_token_at_v2, "v1-token-at-v2");
case!(click_status_mutant, "safe-status-mutant");
