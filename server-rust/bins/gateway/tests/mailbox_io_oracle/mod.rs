//! F05 slice `mailboxes`, import and export (#425): frozen-Go oracle. Record
//! mode runs the covered Go binary behind the front door with a fake S3; replay
//! serves the same requests from Rust with no Go upstream. The observation is
//! the HTTP answer, the committed message rows, the object-store requests, the
//! audit rows and notifications. Export archives are compared entry by entry
//! (reviewed divergence for the compressed stream, see divergences.json).
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    mailbox_io::MailboxIoRoute, recovery_worker::S3Store, Body, BoxFuture, Config, Gateway,
    Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[path = "../drive_workers_oracle/fake_s3.rs"]
mod fake_s3;
mod plan;
use plan::{Fx, Target};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: MailboxIoRoute<setjoin_gateway::jmap::jwks::Jwks, S3Store>,
    changed_status: bool,
}
impl Intercept for Probe {
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

fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    claims["auth_time"] = json!(claims["iat"].clone());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn utf8_or_b64(b: &[u8]) -> Value {
    match std::str::from_utf8(b) {
        Ok(s) => json!(s),
        Err(_) => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            json!({"base64": STANDARD.encode(b)})
        }
    }
}

/// Entries of a ZIP, read from its central directory as written (no zip crate):
/// the header fields Go's writer sets and the inflated contents.
fn zip_entries(bytes: &[u8]) -> Result<Vec<Value>, BoxError> {
    use std::io::Read;
    let u16at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]) as usize;
    let u32at = |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    let eocd = bytes.len().checked_sub(22).ok_or("short zip")?;
    if u32at(eocd) != 0x0605_4b50 {
        return Err("no end record".into());
    }
    let (count, mut at) = (u16at(eocd + 10), u32at(eocd + 16) as usize);
    let mut out = Vec::new();
    for _ in 0..count {
        if u32at(at) != 0x0201_4b50 {
            return Err("bad central header".into());
        }
        let (name_len, extra_len, comment_len) = (u16at(at + 28), u16at(at + 30), u16at(at + 32));
        let (csize, size, local) = (
            u32at(at + 20) as usize,
            u32at(at + 24) as usize,
            u32at(at + 42) as usize,
        );
        let name = &bytes[at + 46..at + 46 + name_len];
        let data_at = local + 30 + u16at(local + 26) + u16at(local + 28);
        let mut inflated = Vec::new();
        flate2::read::DeflateDecoder::new(&bytes[data_at..data_at + csize])
            .read_to_end(&mut inflated)?;
        let mut crc = flate2::Crc::new();
        crc.update(&inflated);
        out.push(json!({
            "name": utf8_or_b64(name),
            "version_made_by": u16at(at + 4), "version_needed": u16at(at + 6), "flags": u16at(at + 8),
            "method": u16at(at + 10), "dos_time": u16at(at + 12), "dos_date": u16at(at + 14),
            "crc32": format!("{:08x}", u32at(at + 16)), "crc_matches": crc.sum() == u32at(at + 16),
            "size": size, "inflated_size": inflated.len(),
            "extra_len": extra_len, "comment_len": comment_len, "external_attrs": u32at(at + 38),
            "local_flags": u16at(local + 6), "local_dos_time": u16at(local + 10), "local_dos_date": u16at(local + 12),
            "data": utf8_or_b64(&inflated),
        }));
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(out)
}

/// The date of an mbox separator line is the time of the export.
fn mask_mbox_dates(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| match line.strip_prefix("From ") {
            Some(rest) if !line.starts_with("From sender") => {
                let id_end = rest.find(' ').unwrap_or(rest.len());
                format!("From {} <date>\n", &rest[..id_end])
            }
            _ => line.to_owned(),
        })
        .collect()
}

fn mask_ids(text: &str, fx: &Fx, mailboxes: &[(i64, &str)]) -> String {
    let mut out = text.to_owned();
    for (id, name) in mailboxes {
        out = out.replace(&format!("/mailboxes/{id}/"), &format!("/mailboxes/{name}/"));
    }
    out.replace(&fx.a_domain, "<domain-a-name>")
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

async fn snapshot(c: &tokio_postgres::Client, fx: &Fx) -> Result<Value, BoxError> {
    let doms = format!("({},{})", fx.a.domain, fx.b.domain);
    let mut messages = rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'message_id',g.message_id,'subject',g.subject,'from_addr',g.from_addr,'from_name',g.from_name,'to',g.to_addrs,'cc',g.cc_addrs,'bcc',g.bcc_addrs,'in_reply_to',g.in_reply_to,'references',g.references_hdr,'body_text',g.body_text,'body_html',g.body_html,'size',g.size_bytes,'raw_ref',g.raw_ref,'received_at',CASE WHEN g.received_at>now()-interval '1 day' THEN '<now>' ELSE g.received_at::text END,'sent_at',CASE WHEN g.sent_at>now()-interval '1 day' THEN '<now>' ELSE g.sent_at::text END,'is_read',g.is_read,'list_id',g.list_id,'tags',(SELECT jsonb_agg(t.name ORDER BY t.name) FROM message_tags mt JOIN tags t ON t.id=mt.tag_id WHERE mt.message_id=g.id AND mt.received_at=g.received_at))::text FROM messages g JOIN mailboxes m ON m.id=g.mailbox_id WHERE m.domain_id IN {doms} AND m.email ~ '^mbox5-(s|shared|t)@' ORDER BY g.id")).await?;
    for row in &mut messages {
        if let Some(id) = row["message_id"].as_str() {
            if id.starts_with("<imported-") {
                row["message_id"] = json!("<imported-random>");
            }
        }
    }
    Ok(json!({
        "messages": messages,
        "mailboxes": rows(c, &format!("SELECT jsonb_build_object('email',m.email,'used_bytes',m.used_bytes,'email_state',m.jmap_email_state)::text FROM mailboxes m WHERE m.domain_id IN {doms} AND m.email ~ '^mbox5-(s|shared|t)@' ORDER BY m.email")).await?,
        "tags": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'name',t.name,'total',t.total_count,'unread',t.unread_count)::text FROM tags t JOIN mailboxes m ON m.id=t.mailbox_id WHERE m.domain_id IN {doms} AND m.email ~ '^mbox5-(s|shared|t)@' ORDER BY m.email,t.name")).await?,
    }))
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind).await
}

async fn run_inner(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("mailbox-io-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let p = plan::plan(action, label);
    let fx = Fx::build(&owner, &p.perms, p.scoped).await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let s3 = fake_s3::DriveS3::start().await;
    let result = exercise(&db, &owner, &fx, &p, &s3, action, label, mutant).await;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F05' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    fx.remove(&owner).await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    db: &Db,
    owner: &tokio_postgres::Client,
    fx: &Fx,
    p: &plan::Plan,
    s3: &fake_s3::DriveS3,
    action: &str,
    label: &str,
    mutant: bool,
) -> Result<(), BoxError> {
    // Seed the stored messages of an export through the reducer's system path.
    let target_id = match p.target {
        Target::Mine => fx.s,
        Target::Shared => fx.shared,
        Target::Foreign => fx.b.mailbox,
        Target::Missing => 999_999_999,
        Target::Raw(_) => fx.s,
    };
    for seed in &p.seeds {
        let reference = format!("{:x}", Sha256::digest(&seed.body));
        let tag: Option<i64> = match seed.tag {
            Some(name) => Some(
                owner
                    .query_one(
                        "SELECT id FROM tags WHERE mailbox_id=$1 AND name=$2",
                        &[&target_id, &name],
                    )
                    .await?
                    .get(0),
            ),
            None => None,
        };
        let size = seed.body.len() as i64;
        owner.execute("SELECT import_message($1,$2,$3,'seed','seed@example.com','Seed','[]','[]','[]',NULL,NULL,'seed',NULL,$4,false,false,$5,$6::text::timestamptz)",
            &[&target_id, &tag, &seed.message_id, &size, &reference, &seed.date]).await?;
        if seed.stored {
            s3.put(&reference, &seed.body, 0);
        }
    }
    // The frozen Go process recomputes used_bytes at startup; set what it would (replay has no Go).
    owner.execute("UPDATE mailboxes SET used_bytes=COALESCE((SELECT sum(size_bytes) FROM messages WHERE mailbox_id=mailboxes.id),0) WHERE domain_id=ANY($1)", &[&vec![fx.a.domain, fx.b.domain]]).await?;
    let _ = s3.take_log();
    let go = common::go_oracle::start_named(db, s3.addr, None, "gofree-mbox5-io").await?;
    let recording = go.is_some();
    let patient = std::time::Duration::from_secs(30);
    let timeouts = setjoin_pg::Timeouts {
        pool_wait: patient,
        create: patient,
        statement: patient,
    };
    let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let store = S3Store::new(
        &format!("http://{}", s3.addr),
        "mailblobs",
        "test-access",
        "test-secret",
    )?;
    let adapter = Probe {
        inner: MailboxIoRoute {
            exec,
            worker,
            store: Arc::new(store),
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
        },
        changed_status: mutant,
    };
    let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
    for r in inventory["routes"].as_array_mut().ok_or("routes")? {
        let io = r["family"] == "F05" && (r["path"] == p.pattern);
        if io {
            r["state"] = json!(if recording { "OFF" } else { "ON" });
            r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
            r["oracle_commands"] = json!([""]);
        }
    }
    let gateway = Gateway::new(
        Config {
            upstream: go
                .as_ref()
                .map(|g| format!("http://{}", g.address).parse())
                .transpose()?,
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
    let folder = fx.folder.to_string();
    let id_text = match p.target {
        Target::Raw(r) => r.to_owned(),
        _ => target_id.to_string(),
    };
    let uri = format!(
        "/api{}{}",
        p.pattern.replace("{id}", &id_text),
        p.query.replace("__FOLDER__", &folder)
    );
    let body: Vec<u8> = {
        let marker = b"__FOLDER__";
        let mut out = Vec::new();
        let mut i = 0;
        while i < p.body.len() {
            if p.body[i..].starts_with(marker) {
                out.extend_from_slice(folder.as_bytes());
                i += marker.len();
            } else {
                out.push(p.body[i]);
                i += 1;
            }
        }
        out
    };
    let token = admin_token(fx.a.user);
    let send = || {
        let mut request = Request::builder()
            .method(p.method)
            .uri(uri.clone())
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("x-request-id", "gofree-mbox5-oracle")
            .header("authorization", format!("Bearer {token}"));
        if !p.content_type.is_empty() {
            request = request.header("content-type", p.content_type.clone());
        }
        let request = request.body(common::full(body.clone())).unwrap();
        async move { common::send(address, request).await }
    };
    if p.repeat {
        let first = send().await;
        let status = first.status().as_u16();
        let _ = common::body_bytes(first).await;
        if recording && status != 200 {
            return Err(format!("initial {action}: {status}").into());
        }
    }
    let before = snapshot(owner, fx).await?;
    let _ = s3.take_log();
    let last: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let mut alerts = db.listen("admin:alert").await?;
    let response = send().await;
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
    let raw = common::body_bytes_unchecked(response).await.to_vec();
    if recording && status != p.want {
        return Err(format!(
            "Go {action}/{label}: expected {} got {status}: {}",
            p.want,
            String::from_utf8_lossy(&raw)
        )
        .into());
    }
    let after = snapshot(owner, fx).await?;
    let s3_log = s3.take_log();
    let names = [
        (fx.s, "<target>"),
        (fx.shared, "<shared>"),
        (fx.b.mailbox, "<foreign>"),
        (fx.a.mailbox, "<admin-mailbox>"),
    ];
    let mut response_json = json!({"status": status});
    headers.remove("date");
    let mut archive = Value::Null;
    let body_value: Value = if status == 200 && action == "export" {
        let content_type = headers
            .get("content-type")
            .and_then(|v| v[0].as_str())
            .unwrap_or("")
            .to_owned();
        if content_type == "application/zip" {
            let entries = zip_entries(&raw)?;
            archive = json!({"length": raw.len(), "sha256": format!("{:x}", Sha256::digest(&raw))});
            json!({"zip_entries": entries})
        } else {
            let text = mask_mbox_dates(&String::from_utf8_lossy(&raw));
            json!({"mbox": text})
        }
    } else {
        json!(mask_ids(
            &String::from_utf8_lossy(&raw),
            fx,
            &names.iter().map(|(i, n)| (*i, *n)).collect::<Vec<_>>()
        ))
    };
    if let Some(length) = headers.get("content-length").cloned() {
        // A body this normalisation rewrites keeps its framing proof: the wire length.
        if length[0] != raw.len().to_string() {
            return Err("bad wire length".into());
        }
        headers.insert("content-length".into(), json!(["<wire-length>"]));
    }
    response_json["headers"] = Value::Object(headers);
    response_json["body"] = body_value;
    if !archive.is_null() {
        response_json["archive"] = archive;
    }
    let mut audit: Vec<Value> = rows(owner, &format!("SELECT jsonb_build_object('action',a.action,'target_type',a.target_type,'target_is_mailbox',a.target_id IS NOT NULL AND a.target_id IN ({}),'actor',u.email,'before',a.before_state,'after',a.after_state,'ip',a.ip::text,'notes',a.notes)::text FROM admin_audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.id>{last} ORDER BY a.id", names.iter().map(|(i, _)| i.to_string()).collect::<Vec<_>>().join(","))).await?;
    for row in &mut audit {
        let text = mask_ids(
            &row.to_string(),
            fx,
            &names.iter().map(|(i, n)| (*i, *n)).collect::<Vec<_>>(),
        );
        *row = serde_json::from_str(&text)?;
        if let Some(email) = row["actor"]
            .as_str()
            .map(|e| e.replace(&fx.a_domain, "<domain-a-name>"))
        {
            row["actor"] = json!(email);
        }
    }
    let mut notify = vec![];
    for event in alerts.drain(owner).await? {
        notify.push(
            json!({"channel":"admin:alert","payload":serde_json::from_str::<Value>(&event)?}),
        );
    }
    let s3_log: Vec<Value> = s3_log
        .into_iter()
        .map(|mut e| {
            if e["path"].is_string() {
                e["path"] = json!(e["path"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches('/')
                    .split_once('/')
                    .map_or(String::new(), |(_, k)| k.to_owned()));
            }
            e
        })
        .collect();
    let effects = json!([{"table":"messages+mailboxes+tags","before":mask_value(before, fx),"after":mask_value(after, fx)}, {"table":"object-store","requests":s3_log}]);
    let mut request = json!({"method":p.method,"path":p.pattern,"external_path":format!("/api{}",p.pattern),"summary":p.summary});
    if !p.query.is_empty() {
        request["query"] = json!(p.query.replace("__FOLDER__", "<folder>"));
    }
    let observation = json!({"request":request,"response":response_json,"effects":effects,"audit":audit,"notify":notify});
    if !recording {
        let metrics = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F05\"} 0")
        {
            return Err(format!("F05 replay forwarded to Go: {metrics}").into());
        }
    }
    server.abort();
    let name = format!("{action}-{label}");
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/mailboxes/goldens");
    std::fs::create_dir_all(&dir)?;
    let file = dir.join(format!("io-{name}.json"));
    let row_file = dir.join(format!("io-{name}-row-effects.json"));
    let route_name = format!("{} {}", p.method, p.pattern);
    if recording {
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        golden::record(
            &file,
            &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}),
        )?;
        golden::record(
            &row_file,
            &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
        let divergences: Value = serde_json::from_slice(&std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/conformance/mailboxes/divergences.json"),
        )?)?;
        let compared = golden::compare_reviewed(
            &route_name,
            label,
            &expected["observation"],
            &observation,
            &divergences,
        );
        if mutant {
            let error = compared.err().ok_or("planted status mutant survived")?;
            if !error.contains("/response/status") {
                return Err(format!("mutant failed outside response status: {error}").into());
            }
            eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
            return Ok(());
        }
        compared?;
        let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
        golden::compare(&expected["effects"], &observation["effects"])?;
        eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
    }
    Ok(())
}

fn mask_value(v: Value, fx: &Fx) -> Value {
    serde_json::from_str(&v.to_string().replace(&fx.a_domain, "<domain-a-name>")).expect("json")
}
