//! F17 slice `contacts` frozen-Go oracle: HTTP wire, committed rows, change
//! journal and NOTIFY for the contacts CSV/vCard import and export. Record mode
//! runs the covered Go binary behind the front door; replay serves the same
//! requests from Rust with no Go upstream.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Map, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    contacts::ContactsRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: ContactsRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    A,
    B,
}

const BOUNDARY: &str = "cal2boundary7f3a";
const BOOK_A: i64 = 971001;
const BOOK_B: i64 = 971002;
const CONTACT_1: i64 = 972001;
const CONTACT_2: i64 = 972002;
const CONTACT_B: i64 = 972003;

struct Spec {
    method: &'static str,
    pattern: &'static str,
    path: String,
    query: String,
    content_type: String,
    body: String,
    caller: Caller,
    wanted: u16,
    first: bool,
    seed: &'static str,
}

fn part(name: &str, filename: Option<&str>, content: &str) -> String {
    let file = filename
        .map(|f| format!("; filename=\"{f}\""))
        .unwrap_or_default();
    format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"{file}\r\n\r\n{content}\r\n")
}
fn form(parts: &[String]) -> String {
    format!("{}--{BOUNDARY}--\r\n", parts.concat())
}
fn upload(book: Option<i64>, file: Option<&str>, extra: &[(&str, &str)]) -> String {
    let mut parts = vec![];
    if let Some(b) = book {
        parts.push(part("addressBookId", None, &b.to_string()));
    }
    for (k, v) in extra {
        parts.push(part(k, None, v));
    }
    if let Some(f) = file {
        parts.push(part("file", Some("contacts.csv"), f));
    }
    form(&parts)
}

const CSV: &str = "First Name,Last Name,E-mail Address,Company,Mobile Phone,Notes\nDana,Import,dana@imp.test,Imp Co,+200,note one\nEli,Import,ELI@imp.test,,,\n";
const CSV_CHANGED: &str = "First Name,Last Name,E-mail Address,Company,Mobile Phone,Notes\nDana,Import,dana@imp.test,Changed Co,+201,note two\n";

fn vcf(uid: &str, name: &str, extra: &str) -> String {
    format!("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:{uid}\r\nFN:{name}\r\nN:Card;{name};;;\r\nEMAIL;TYPE=work:{uid}@v.test\r\nTEL;TYPE=cell:+300\r\nORG:Vcorp\r\nTITLE:Boss\r\nNOTE:hello\\, world\r\nADR;TYPE=home:;;1 Rd;City;ST;999;Land\r\nURL:https://v.test\r\n{extra}END:VCARD\r\n")
}

fn spec(route: &str, label: &str) -> Spec {
    let mut s = Spec {
        method: "POST",
        pattern: "/contacts/import/",
        path: String::new(),
        query: String::new(),
        content_type: format!("multipart/form-data; boundary={BOUNDARY}"),
        body: String::new(),
        caller: Caller::A,
        wanted: 200,
        first: false,
        seed: "",
    };
    let two = format!(
        "{}{}",
        vcf("cal2-v1", "Vera", ""),
        vcf("cal2-v2", "Walt", "")
    );
    match route {
        "csv-preview" => {
            s.path = "/api/contacts/import/csv/preview".into();
            s.body = upload(None, Some(CSV), &[]);
            match label {
                "cross-tenant" => s.caller = Caller::B,
                "invalid-input" => {
                    s.content_type = "application/json".into();
                    s.body = "{}".into();
                    s.wanted = 400;
                }
                "missing-file" => {
                    s.body = upload(Some(BOOK_A), None, &[]);
                    s.wanted = 400;
                }
                "empty" => {
                    s.body = upload(None, Some("  \n"), &[]);
                    s.wanted = 400;
                }
                "bad-header" => {
                    s.body = upload(None, Some("a,b\"c\n1,2\n"), &[]);
                    s.wanted = 400;
                }
                "bad-row" => s.body = upload(None, Some("Name,Email\nx,y\nbad\"quote,z\n"), &[]),
                "header-only" => s.body = upload(None, Some("Name,Email\n"), &[]),
                "bad-query" => {
                    s.query = "?x=%zz".into();
                    s.wanted = 400;
                }
                "wrong-method" => {
                    s.method = "GET";
                    s.body = String::new();
                    s.wanted = 404;
                }
                _ => {}
            }
        }
        "csv-import" => {
            s.path = "/api/contacts/import/csv".into();
            s.body = upload(Some(BOOK_A), Some(CSV), &[]);
            match label {
                "repeat" => s.first = true,
                "cross-tenant" => {
                    s.body = upload(Some(BOOK_B), Some(CSV), &[]);
                    s.wanted = 403;
                }
                "invalid-input" => {
                    s.content_type = "application/json".into();
                    s.body = "{}".into();
                    s.wanted = 400;
                }
                "missing-file" => {
                    s.body = upload(Some(BOOK_A), None, &[]);
                    s.wanted = 400;
                }
                "bad-book" => {
                    s.body = form(&[
                        part("addressBookId", None, "abc"),
                        part("file", Some("c.csv"), CSV),
                    ]);
                    s.wanted = 400;
                }
                "no-book" => {
                    s.body = upload(None, Some(CSV), &[]);
                    s.wanted = 400;
                }
                "unknown-book" => {
                    s.body = upload(Some(999999), Some(CSV), &[]);
                    s.wanted = 403;
                }
                "bad-dialect" => {
                    s.body = upload(Some(BOOK_A), Some(CSV), &[("dialect", "excel")]);
                    s.wanted = 400;
                }
                "bad-mapping" => {
                    s.body = upload(Some(BOOK_A), Some(CSV), &[("mapping", "{\"email\":\"x\"}")]);
                    s.wanted = 400;
                }
                "mapping" => {
                    s.body = upload(
                        Some(BOOK_A),
                        Some("a,b,c\nDana,Import,mapped@imp.test\n"),
                        &[("mapping", "{\"Email\":2,\"firstname\":0,\"lastName\":1}")],
                    )
                }
                "skip" => {
                    s.first = true;
                    s.body = upload(Some(BOOK_A), Some(CSV), &[("strategy", "skip")]);
                }
                "overwrite" => {
                    s.first = true;
                    s.body = upload(
                        Some(BOOK_A),
                        Some(CSV_CHANGED),
                        &[("strategy", "overwrite")],
                    );
                }
                "setjoin-dialect" => {
                    s.body = upload(
                        Some(BOOK_A),
                        Some("Display Name,E-mail Address,Notes\n'=SUM(1),sj@imp.test,'+123\n"),
                        &[("dialect", "setjoin")],
                    )
                }
                "parse-error" => s.body = upload(Some(BOOK_A), Some("a,b\nx\"y,z\n"), &[]),
                "empty" => s.body = upload(Some(BOOK_A), Some(""), &[]),
                "blank-email" => {
                    s.body = upload(
                        Some(BOOK_A),
                        Some("Name,Email\nNo Mail,\nHas Mail,hm@imp.test\nShort\n"),
                        &[],
                    )
                }
                "no-email-column" => {
                    s.body = upload(
                        Some(BOOK_A),
                        Some("Name,Notes\nOnly Name,n1\n,orphan\n"),
                        &[],
                    )
                }
                "query-wins" => {
                    s.query = format!("?addressBookId={BOOK_A}");
                    s.body = upload(Some(BOOK_B), Some(CSV), &[]);
                }
                "nul-cell" => {
                    s.body = upload(
                        Some(BOOK_A),
                        Some("Name,Email,Notes\nNul,nul@imp.test,a\u{0}b\n"),
                        &[],
                    )
                }
                _ => {}
            }
        }
        "vcf-import" => {
            s.path = "/api/contacts/import/vcf".into();
            let file = |text: &str, extra: &[(&str, &str)]| {
                let mut parts = vec![part("addressBookId", None, &BOOK_A.to_string())];
                for (k, v) in extra {
                    parts.push(part(k, None, v));
                }
                parts.push(part("file", Some("c.vcf"), text));
                form(&parts)
            };
            s.body = file(&two, &[]);
            match label {
                "repeat" => s.first = true,
                "cross-tenant" => {
                    s.body = upload(Some(BOOK_B), Some(&two), &[]);
                    s.wanted = 403;
                }
                "invalid-input" => {
                    s.content_type = "text/plain".into();
                    s.body = "x".into();
                    s.wanted = 400;
                }
                "missing-uid" => {
                    s.body = file(
                        &format!(
                            "{}BEGIN:VCARD\r\nFN:No Uid\r\nEND:VCARD\r\n",
                            vcf("cal2-v3", "Xena", "")
                        ),
                        &[],
                    )
                }
                "rename" => {
                    s.first = true;
                    s.body = file(&two, &[("strategy", "rename")]);
                }
                "overwrite" => {
                    s.first = true;
                    s.body = file(&two, &[("strategy", "overwrite")]);
                }
                "skip" => {
                    s.first = true;
                    s.body = file(&two, &[("strategy", "skip")]);
                }
                "dates" => {
                    s.body = file(
                        &vcf(
                            "cal2-v4",
                            "Yuri",
                            "BDAY:19900203\r\nANNIVERSARY:20100405\r\n",
                        ),
                        &[],
                    )
                }
                "bad-date" => s.body = file(&vcf("cal2-v5", "Zed", "BDAY:00000101\r\n"), &[]),
                _ => {}
            }
        }
        "csv-export" => {
            s.method = "GET";
            s.pattern = "/contacts/export/";
            s.path = "/api/contacts/export/csv".into();
            s.query = format!("?addressBookId={BOOK_A}");
            s.content_type = String::new();
            match label {
                "cross-tenant" => {
                    s.query = format!("?addressBookId={BOOK_B}");
                    s.wanted = 403;
                }
                "invalid-input" => {
                    s.query = "?addressBookId=0".into();
                    s.wanted = 400;
                }
                "empty-book" => s.seed = "empty-book",
                "bad-json" => {
                    s.seed = "bad-json";
                    s.wanted = 500;
                }
                "wrong-method" => {
                    s.method = "POST";
                    s.wanted = 404;
                }
                _ => {}
            }
        }
        "vcf-export" => {
            s.method = "GET";
            s.pattern = "/contacts/export/";
            s.path = "/api/contacts/export/vcf".into();
            s.query = format!("?addressBookId={BOOK_A}");
            s.content_type = String::new();
            match label {
                "cross-tenant" => {
                    s.query = format!("?addressBookId={BOOK_B}");
                    s.wanted = 403;
                }
                "invalid-input" => {
                    s.query = String::new();
                    s.wanted = 400;
                }
                "contact" => s.query = format!("?contactId={CONTACT_1}"),
                "contact-foreign" => {
                    s.query = format!("?contactId={CONTACT_B}");
                    s.wanted = 403;
                }
                "contact-missing" => {
                    s.query = "?contactId=999999".into();
                    s.wanted = 403;
                }
                "bad-contact" => {
                    s.query = "?contactId=-4".into();
                    s.wanted = 400;
                }
                "bad-json" => {
                    s.seed = "bad-json";
                    s.wanted = 500;
                }
                "long-line" => s.seed = "long-line",
                _ => {}
            }
        }
        other => panic!("unknown contacts route {other}"),
    }
    s
}

fn mask_ids(text: &str, ids: &[(i64, String)]) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let run = &text[start..i];
            match run
                .parse::<i64>()
                .ok()
                .filter(|_| run.len() >= 5)
                .and_then(|n| ids.iter().find(|(id, _)| *id == n))
            {
                Some((_, label)) => out.push_str(label),
                None => out.push_str(run),
            }
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn mask_numbers(v: &mut Value, ids: &[(i64, String)]) {
    match v {
        Value::Number(n) => {
            if let Some((_, label)) = n
                .as_i64()
                .filter(|n| *n >= 100000)
                .and_then(|n| ids.iter().find(|(id, _)| *id == n))
            {
                *v = Value::String(label.clone());
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask_numbers(x, ids)),
        Value::Object(m) => m.iter_mut().for_each(|(_, x)| mask_numbers(x, ids)),
        _ => {}
    }
}

fn mask_value(v: &mut Value, f: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask_value(x, f)),
        Value::Object(m) => m.iter_mut().for_each(|(_, x)| mask_value(x, f)),
        _ => {}
    }
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

async fn snapshot(c: &tokio_postgres::Client, a: i64, b: i64) -> Result<Value, BoxError> {
    let who = format!("CASE x.mailbox_id WHEN {a} THEN 'a' WHEN {b} THEN 'b' END");
    Ok(json!({
        "contacts": rows(c, &format!("SELECT jsonb_build_object('book',CASE k.addressbook_id WHEN {BOOK_A} THEN 'a' WHEN {BOOK_B} THEN 'b' END,'uid',k.vcard_uid,'display',k.display_name,'first',k.first_name,'last',k.last_name,'company',k.company,'title',k.job_title,'department',k.department,'emails',k.emails,'phones',k.phones,'addresses',k.addresses,'urls',k.urls,'impps',k.instant_msgs,'notes',k.notes,'birthday',k.birthday,'anniversary',k.anniversary,'categories',k.categories,'etag_set',k.etag<>'')::text FROM contacts k WHERE k.addressbook_id IN ({BOOK_A},{BOOK_B}) ORDER BY k.addressbook_id, k.vcard_uid")).await?,
        "addressbooks": rows(c, &format!("SELECT jsonb_build_object('owner',{who},'name',x.name,'state',x.jmap_state)::text FROM addressbooks x WHERE x.id IN ({BOOK_A},{BOOK_B}) ORDER BY x.id")).await?,
        "journal": rows(c, &format!("SELECT jsonb_build_object('owner',{who},'datatype',x.datatype,'state',x.state_seq,'op',x.op,'uid',x.resource_uid)::text FROM jmap_changes_journal x WHERE x.mailbox_id IN ({a},{b}) ORDER BY x.mailbox_id, x.state_seq, x.resource_uid")).await?,
    }))
}

pub async fn run(route: &str, label: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(route, label, mutant).await
}

async fn run_inner(route: &str, label: &str, mutant: bool) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("cal2-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "cal2-owner").await?;
    let b = fixture::account(&owner, "cal2-other").await?;
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let domains = [
        (domain_of(a.domain).await?, "host-a.test"),
        (domain_of(b.domain).await?, "host-b.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domains {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    for sequence in ["addressbooks", "contacts"] {
        owner.batch_execute(&format!("SELECT setval(pg_get_serial_sequence('{sequence}','id'), greatest(980000, (SELECT last_value FROM {sequence}_id_seq)))")).await?;
    }
    owner.batch_execute(&format!(
        "DELETE FROM addressbooks WHERE id IN ({BOOK_A},{BOOK_B}) OR mailbox_id IN ({},{});\
         INSERT INTO addressbooks(id,mailbox_id,name,is_default) VALUES({BOOK_A},{},'cal2-a-book',true),({BOOK_B},{},'cal2-b-book',true)",
        a.mailbox, b.mailbox, a.mailbox, b.mailbox
    )).await?;
    owner.batch_execute(&format!(
        "INSERT INTO contacts(id,addressbook_id,vcard_uid,display_name,first_name,last_name,company,job_title,department,emails,phones,addresses,urls,notes,categories,birthday) VALUES\
         ({CONTACT_1},{BOOK_A},'cal2-seed-1','Alice Seed','Alice','Seed','=Evil Corp','Engineer','Sales','[{{\"type\":\"work\",\"address\":\"alice@seed.test\"}}]','[{{\"type\":\"work\",\"number\":\"+100\"}}]','[{{\"type\":\"home\",\"street\":\"1 Main St\",\"city\":\"Town\",\"region\":\"R\",\"code\":\"123\",\"country\":\"X\"}}]','[{{\"type\":\"work\",\"value\":\"https://seed.test\"}}]','line1\nline2, with comma','{{friends,work}}','1990-02-03'),\
         ({CONTACT_2},{BOOK_A},'cal2-seed-2','Bob Seed','Bob','Seed',NULL,NULL,NULL,'[{{\"type\":\"home\",\"value\":\"bob@seed.test\"}}]','[{{\"type\":\"home\",\"value\":\"+101\"}}]','[]','[]',NULL,'{{}}',NULL),\
         ({CONTACT_B},{BOOK_B},'cal2-other-1','Carol Other','Carol','Other',NULL,NULL,NULL,'[]','[]','[]','[]',NULL,'{{}}',NULL)"
    )).await?;
    let spec = spec(route, label);
    match spec.seed {
        "empty-book" => {
            owner
                .batch_execute(&format!(
                    "DELETE FROM contacts WHERE addressbook_id={BOOK_A}"
                ))
                .await?;
        }
        "bad-json" => {
            owner.batch_execute(&format!("INSERT INTO contacts(addressbook_id,vcard_uid,display_name,emails) VALUES({BOOK_A},'cal2-badjson','Zed Bad','[1]')")).await?;
        }
        "long-line" => {
            owner.batch_execute(&format!("INSERT INTO contacts(addressbook_id,vcard_uid,display_name,notes) VALUES({BOOK_A},'cal2-long','Long Line','{}')", "\u{e9}".repeat(100))).await?;
        }
        _ => {}
    }
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F17'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let ids: Vec<(i64, String)> = vec![
        (a.user, "<user-a>".into()),
        (b.user, "<user-b>".into()),
        (a.mailbox, "<mailbox-a>".into()),
        (b.mailbox, "<mailbox-b>".into()),
        (BOOK_A, "<book-a>".into()),
        (BOOK_B, "<book-b>".into()),
        (CONTACT_1, "<contact-1>".into()),
        (CONTACT_2, "<contact-2>".into()),
        (CONTACT_B, "<contact-b>".into()),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named_with_env(&db, s3, "gofree-cal2-http", &[]).await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map(|e| e.with_audit_keys("22".repeat(32), String::new()))
        .map_err(|e| e.0)?;
        let adapter = Probe {
            inner: ContactsRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F17" && r["slice"] == "contacts" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
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
        let token = common::recovery_token(if spec.caller == Caller::A { a.user } else { b.user });
        let send = || {
            let uri = format!("{}{}", spec.path, spec.query);
            let mut request = Request::builder()
                .method(spec.method)
                .uri(uri)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("x-request-id", "gofree-cal2-oracle")
                .header("authorization", format!("Bearer {token}"));
            if !spec.content_type.is_empty() {
                request = request.header("content-type", spec.content_type.clone());
            }
            let body = spec.body.clone();
            async move { Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await) }
        };
        if spec.first {
            let first = send().await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && status != 200 {
                return Err(format!("initial {route}: {status} {data:?}").into());
            }
        }
        let before = snapshot(&owner, a.mailbox, b.mailbox).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut notices_a = db.listen(&format!("contact:{}", a.mailbox)).await?;
        let mut notices_b = db.listen(&format!("contact:{}", b.mailbox)).await?;
        let response = send().await?;
        let status = response.status().as_u16();
        let mut headers = Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if recording && status != spec.wanted {
            return Err(format!("Go {route}/{label}: expected {}, got {status}: {raw}", spec.wanted).into());
        }
        let after = snapshot(&owner, a.mailbox, b.mailbox).await?;
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            row["id"] = json!("<audit>");
        }
        let mut notify = vec![];
        for (channel, listener) in [("a", &mut notices_a), ("b", &mut notices_b)] {
            for event in listener.drain(&owner).await? {
                let payload: Value = serde_json::from_str(&event).unwrap_or(Value::String(event));
                notify.push(json!({"mailbox":channel,"payload":payload}));
            }
        }
        for row in &mut notify {
            mask_numbers(row, &ids);
        }
        let mask = |text: &str| {
            let text = names(&mask_ids(text, &ids));
            // The REV of an exported card is the row's own `updated_at`.
            let mut out = String::new();
            let mut rest = text.as_str();
            while let Some(at) = rest.find("REV:") {
                let (head, tail) = rest.split_at(at + 4);
                out.push_str(head);
                let stamp = tail.get(..16).filter(|t| t.len() == 16 && t.as_bytes()[8] == b'T' && t.ends_with('Z'));
                if stamp.is_some() {
                    out.push_str("<updated>");
                    rest = &tail[16..];
                } else {
                    rest = tail;
                }
            }
            out.push_str(rest);
            out
        };
        let text = mask(&raw);
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let mut snapshots = (before, after);
        for s in [&mut snapshots.0, &mut snapshots.1] {
            mask_value(s, &mask);
        }
        for row in &mut audit {
            mask_value(row, &mask);
        }
        let effects = json!([{"table":"f17-contacts","before":snapshots.0,"after":snapshots.1}]);
        let mut request = json!({"method":"*","concrete_method":spec.method,"path":"/contacts/import/","external_path":spec.path});
        request["path"] = json!(if spec.pattern == "/contacts/export/" { "/contacts/export/" } else { "/contacts/import/" });
        if !spec.body.is_empty() {
            request["body"] = json!(mask(&spec.body));
        }
        if !spec.query.is_empty() {
            request["query"] = json!(mask(&spec.query));
        }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F17\"} 0") {
                return Err(format!("F17 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{route}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/contacts/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("* {} {route}", request["path"].as_str().unwrap());
        let mutator = matches!(route, "csv-import" | "vcf-import");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            if mutator {
                record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
            }
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
            if row_file.exists() {
                let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
                golden::compare(&expected["effects"], &observation["effects"])?;
            }
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .batch_execute(&format!(
            "DELETE FROM contacts WHERE addressbook_id IN (SELECT id FROM addressbooks WHERE mailbox_id IN ({0},{1}));\
             DELETE FROM jmap_changes_journal WHERE mailbox_id IN ({0},{1});\
             DELETE FROM addressbooks WHERE mailbox_id IN ({0},{1});",
            a.mailbox, b.mailbox
        ))
        .await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F17' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
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
