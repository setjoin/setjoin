//! F02 SCIM (#375) frozen-Go oracle: HTTP wire (SCIM bodies, errors, headers),
//! committed rows, welcome-mail delivery, token usage and the authserver
//! revocation calls. Record mode runs the covered Go binary behind the front door
//! (SCIM_ENABLED=true); replay serves the same requests from Rust, Go absent.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    scim::ScimRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable,
    TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

mod spec;
use spec::{spec, Tok};

const INTERNAL_KEY: &str = "scim-oracle-internal-key";

struct Probe {
    inner: ScimRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct World {
    pub unique: String,
    pub domain: String,
    pub src_a: i64,
    pub gen_a: i64,
    pub src_b: i64,
    pub gen_b: i64,
    pub alice: i64,
    pub bob: i64,
    pub carol: i64,
    pub group_a: i64,
    pub group_b: i64,
    pub tokens: Vec<(Tok, String)>,
}
impl World {
    pub fn token(&self, tok: Tok) -> Option<&str> {
        self.tokens
            .iter()
            .find(|(t, _)| *t == tok)
            .map(|(_, v)| v.as_str())
    }
}

async fn provision(
    owner: &tokio_postgres::Client,
    source: i64,
    generation: i64,
    external: &str,
    email: &str,
    name: (&str, &str, &str),
    department: &str,
) -> Result<i64, BoxError> {
    let payload = json!({
        "operation":"upsert","email":email,"displayName":name.0,"firstName":name.1,
        "lastName":name.2,"jobTitle":"Engineer","phone":"100","department":department,
        "enabled":true,"managerSubject":"","expectedUserId":0,"replaceAll":true
    })
    .to_string();
    let raw: String = owner
        .query_one(
            "SELECT identity_source_scim_apply($1,$2,gen_random_uuid(),$3,$4::text::jsonb)::text",
            &[&source, &generation, &external, &payload],
        )
        .await?
        .get(0);
    let result: Value = serde_json::from_str(&raw)?;
    result["userId"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("provision {external}: {raw}").into())
}

async fn source(owner: &tokio_postgres::Client, key: &str) -> Result<(i64, i64), BoxError> {
    let row = owner
        .query_one(
            "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state) VALUES($1,$1,'scim','{\"provision_lifecycle\":true,\"stable_immutable_subject\":true}'::jsonb,'active') RETURNING id,generation",
            &[&key],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

fn mask_text(text: &str, world: &World, ids: &[(i64, &str)]) -> String {
    let mut out = text
        .replace(&world.domain, "scim.test")
        .replace(&world.unique, "<u>");
    for (id, name) in ids {
        out = out
            .replace(&format!("\"id\":\"{id}\""), &format!("\"id\":\"{name}\""))
            .replace(&format!("/{id}\""), &format!("/{name}\""))
            .replace(&format!("/{id}?"), &format!("/{name}?"))
            .replace(&format!("User {id} "), &format!("User {name} "))
            .replace(&format!("Group {id} "), &format!("Group {name} "))
            .replace(
                &format!("\"user_id\":{id}"),
                &format!("\"user_id\":\"{name}\""),
            );
    }
    // Create and replace answer with the wall clock.
    let mut result = String::new();
    let bytes = out.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 20 <= bytes.len()
            && is_timestamp(&bytes[i..i + 20])
            && !out[i..].starts_with("2026-10-01")
        {
            result.push_str("<time>");
            i += 20;
        } else {
            let ch = out[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    result
}
/// Row and header values: numbers name their kind by key, strings use the text mask.
fn mask_value(v: &Value, world: &World, ids: &[(i64, &str)], key: &str) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, x)| (k.clone(), mask_value(x, world, ids, k)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|x| mask_value(x, world, ids, key))
                .collect(),
        ),
        Value::Number(n) => match (key, n.as_i64()) {
            ("source", Some(id)) if id == world.src_a => json!("<source-a>"),
            ("source", Some(id)) if id == world.src_b => json!("<source-b>"),
            ("id" | "user" | "user_id" | "target_id" | "actor_id", Some(id)) => ids
                .iter()
                .find(|(i, _)| *i == id)
                .map_or_else(|| v.clone(), |(_, name)| json!(name)),
            ("domain_id" | "mailbox_id", Some(_)) => json!("<id>"),
            _ => v.clone(),
        },
        Value::String(_)
            if matches!(
                key,
                "occurred_at" | "created_at" | "sync_at" | "expires_at" | "not_before"
            ) =>
        {
            json!("<timestamp>")
        }
        Value::String(_) if matches!(key, "checksum" | "prev_checksum") => json!("<checksum>"),
        Value::String(text) => {
            let mut text = text.clone();
            for (id, name) in ids {
                text = text.replace(
                    &format!("system:welcome:{id}"),
                    &format!("system:welcome:{name}"),
                );
            }
            let text = text
                .replace(&format!("-s{}@", world.src_a), "-s<source-a>@")
                .replace(&format!("-s{}@", world.src_b), "-s<source-b>@");
            json!(mask_text(&text, world, ids))
        }
        _ => v.clone(),
    }
}
fn is_timestamp(b: &[u8]) -> bool {
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    b.len() == 20
        && b.iter().zip(shape).all(|(x, s)| match s {
            b'd' => x.is_ascii_digit(),
            other => x == other,
        })
}

async fn names(
    owner: &tokio_postgres::Client,
    world: &World,
    sources: &[i64],
) -> Result<Vec<(i64, String)>, BoxError> {
    let mut out = vec![];
    for (id, name) in [
        (world.alice, "<alice>"),
        (world.bob, "<bob>"),
        (world.carol, "<carol>"),
        (world.group_a, "<group-a>"),
        (world.group_b, "<group-b>"),
    ] {
        out.push((id, name.to_owned()));
    }
    for row in owner
        .query(
            "SELECT l.user_id,l.external_subject FROM user_identity_links l WHERE l.source_id=ANY($1) AND l.external_subject LIKE 'new-%'",
            &[&sources],
        )
        .await?
    {
        let ext: String = row.get(1);
        out.push((row.get(0), format!("<{ext}>")));
    }
    for row in owner
        .query(
            "SELECT id,scim_external_id FROM distribution_groups WHERE scim_source_id=ANY($1) AND scim_external_id LIKE 'new-%'",
            &[&sources],
        )
        .await?
    {
        let ext: String = row.get(1);
        out.push((row.get(0), format!("<group-{ext}>")));
    }
    Ok(out)
}

async fn snapshot(owner: &tokio_postgres::Client, sources: &[i64]) -> Result<Value, BoxError> {
    let q = |sql: &'static str| {
        let owner = owner;
        async move {
            let rows = owner.query(sql, &[&sources]).await?;
            rows.iter()
                .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(BoxError::from)
        }
    };
    Ok(json!({
        "users": q("SELECT jsonb_build_object('id',u.id,'source',l.source_id,'subject',l.external_subject,'state',l.state,'username',u.username,'email',u.email,'display',u.display_name,'first',u.first_name,'last',u.last_name,'title',u.job_title,'phone',u.phone,'enabled',u.enabled,'department',d.path)::text FROM user_identity_links l JOIN users u ON u.id=l.user_id LEFT JOIN departments d ON d.id=u.department_id WHERE l.source_id=ANY($1) ORDER BY l.source_id,l.external_subject").await?,
        "groups": q("SELECT jsonb_build_object('id',g.id,'source',g.scim_source_id,'external',g.scim_external_id,'display',m.display_name,'email',m.email,'members',COALESCE((SELECT jsonb_agg(l.external_subject ORDER BY l.external_subject) FROM distribution_group_members dgm JOIN mailboxes mb ON mb.id=dgm.mailbox_id JOIN user_identity_links l ON l.user_id=mb.user_id AND l.source_id=g.scim_source_id WHERE dgm.group_id=g.id),'[]'::jsonb))::text FROM distribution_groups g JOIN mailboxes m ON m.id=g.mailbox_id WHERE g.scim_source_id=ANY($1) ORDER BY g.scim_source_id,g.scim_external_id").await?,
        "welcome": q("SELECT jsonb_build_object('user',mb.user_id,'subject',m.subject,'from',m.from_addr,'to',m.to_addrs,'raw_ref',m.raw_ref)::text FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.raw_ref LIKE 'system:welcome:%' AND mb.user_id IN (SELECT user_id FROM user_identity_links WHERE source_id=ANY($1)) ORDER BY mb.user_id").await?,
        "tokens": q("SELECT jsonb_build_object('source',source_id,'name',regexp_replace(name,'-[0-9a-f]{32}$',''),'used',last_used_at IS NOT NULL)::text FROM scim_tokens WHERE source_id=ANY($1) ORDER BY name").await?,
    }))
}

/// Every case shares the `scim_upsert_group` email domain (first primary/local
/// domain), the `feature.identity_model_v2` toggle and the audit window, so cases
/// run one at a time within this binary (#421; same pattern as #362/#368/#389).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind).await
}

async fn run_inner(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(mut db) = Db::for_case("scim-http") else {
        return Ok(());
    };
    let _ = &mut db;
    let owner = db.connect().await?;
    let unique: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    let domain = format!("scim-{unique}.test");
    // Foreign-key order for removal: record what the case creates.
    let toggle: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.identity_model_v2'",
            &[],
        )
        .await?;
    let domain_id: i64 = owner
        .query_one(
            "INSERT INTO domains(name,is_local) VALUES($1,TRUE) RETURNING id",
            &[&domain],
        )
        .await?
        .get(0);
    // Group ids must never coincide with user ids in recorded bodies.
    owner.batch_execute("SELECT setval('distribution_groups_id_seq', GREATEST((SELECT last_value FROM distribution_groups_id_seq), 5000000))").await?;
    let (src_a, gen_a) = source(&owner, &format!("scim:oracle-a-{unique}")).await?;
    let (src_b, gen_b) = source(&owner, &format!("scim:oracle-b-{unique}")).await?;
    let email = |n: &str| format!("{n}-{unique}@{domain}");
    let alice = provision(
        &owner,
        src_a,
        gen_a,
        "ext-alice",
        &email("alice"),
        ("Alice <A>", "Alice", "Anderson"),
        "",
    )
    .await?;
    let bob = provision(
        &owner,
        src_a,
        gen_a,
        "ext-bob",
        &email("bob"),
        ("Bob B", "Bob", "Brown"),
        "",
    )
    .await?;
    let carol = provision(
        &owner,
        src_b,
        gen_b,
        "ext-carol",
        &email("carol"),
        ("Carol C", "Carol", "Clark"),
        "",
    )
    .await?;
    let group_a: i64 = owner
        .query_one(
            "SELECT scim_upsert_group($1,$2,'ext-group-a','Team <A>')",
            &[&src_a, &gen_a],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT scim_apply_group_members($1,$2,'ext-group-a',ARRAY['ext-alice'],TRUE)",
            &[&src_a, &gen_a],
        )
        .await?;
    let group_b: i64 = owner
        .query_one(
            "SELECT scim_upsert_group($1,$2,'ext-group-b','Team B')",
            &[&src_b, &gen_b],
        )
        .await?
        .get(0);
    owner
        .execute(
            "SELECT scim_apply_group_members($1,$2,'ext-group-b',ARRAY['ext-carol'],TRUE)",
            &[&src_b, &gen_b],
        )
        .await?;
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             UPDATE users SET created_at='2026-10-01T12:00:00Z',updated_at='2026-10-01T12:00:01.25Z' WHERE id={alice}; \
             UPDATE users SET created_at='2026-10-01T12:00:02Z',updated_at='2026-10-01T12:00:03Z' WHERE id={bob}; \
             UPDATE users SET created_at='2026-10-01T12:00:04Z',updated_at='2026-10-01T12:00:05Z' WHERE id={carol}; \
             UPDATE distribution_groups SET created_at='2026-10-01T12:00:06Z' WHERE id IN ({group_a},{group_b}); COMMIT;"
        ))
        .await?;
    // Tokens: one per case shape, all secrets random per run.
    let mut tokens = vec![];
    let mut token_ids = vec![];
    for (tok, source_id, key, policy, expires, legacy) in [
        (
            Tok::A,
            src_a,
            format!("scim:oracle-a-{unique}"),
            "soft",
            None,
            false,
        ),
        (
            Tok::Hard,
            src_a,
            format!("scim:oracle-a-{unique}"),
            "hard",
            None,
            false,
        ),
        (
            Tok::B,
            src_b,
            format!("scim:oracle-b-{unique}"),
            "soft",
            None,
            false,
        ),
        (
            Tok::Expired,
            src_a,
            format!("scim:oracle-a-{unique}"),
            "soft",
            Some("2020-01-01T00:00:00Z"),
            false,
        ),
        (
            Tok::Legacy,
            src_a,
            format!("scim:oracle-a-{unique}"),
            "soft",
            None,
            true,
        ),
    ] {
        let secret = hex(&Sha256::digest(format!("{unique}-{tok:?}").as_bytes()));
        let hash = bcrypt::hash(&secret, 4)?;
        let name = format!("{tok:?}-{unique}");
        if legacy {
            owner
                .execute("INSERT INTO scim_tokens(name,token_hash,deletion_policy,created_by,source_id) VALUES($1,$2,$3,'oracle',$4)", &[&name, &hash, &policy, &source_id])
                .await?;
        } else {
            let lookup = hex(&Sha256::digest(secret.as_bytes()));
            owner
                .execute(
                    "SELECT scim_token_create($1,$2,$3,$4::text::timestamptz,$5,'oracle',$6)",
                    &[&key, &name, &hash, &expires, &policy, &lookup],
                )
                .await?;
        }
        tokens.push((tok, secret));
        token_ids.push(name);
    }
    let world = World {
        unique: unique.clone(),
        domain: domain.clone(),
        src_a,
        gen_a,
        src_b,
        gen_b,
        alice,
        bob,
        carol,
        group_a,
        group_b,
        tokens,
    };
    let sources = [src_a, src_b];
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);

    let result = async {
        let case = spec(action, label, &world);
        // The authserver peer records Go's and Rust's revocation calls identically.
        let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
        let sink = calls.clone();
        let authserver = common::fake_upstream(move |req| {
            let sink = sink.clone();
            async move {
                let (parts, body) = req.into_parts();
                use http_body_util::BodyExt;
                let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                sink.lock().unwrap().push(json!({
                    "method": parts.method.as_str(),
                    "path": parts.uri.path(),
                    "authorization": parts.headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""),
                    "content_type": parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or(""),
                    "body": String::from_utf8_lossy(&bytes),
                }));
                Response::new(common::full(""))
            }
        })
        .await;
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named_with_env(
            &db,
            s3,
            "gofree-dirsync3-http",
            &[
                // Go's request pool: the owner credential, except for the case that
                // proves what the RLS-bound application role does to member writes.
                ("DB_DSN", if label == "rls-members" { db.app.as_deref().unwrap_or(&db.dsn).to_owned() } else { db.dsn.clone() }),
                ("SCIM_ENABLED", "true".into()),
                ("SCIM_RATE_LIMIT", "100000".into()),
                ("SCIM_AUTHSERVER_URL", format!("http://{authserver}")),
                ("INTERNAL_API_KEY", INTERNAL_KEY.into()),
            ],
        )
        .await?;
        let recording = go.is_some();
        let dsn = if label == "rls-members" { db.app.as_deref().unwrap_or(&db.dsn).to_owned() } else { db.dsn.clone() };
        let mk = |dsn: &str| -> Result<ScopedExecutor, BoxError> {
            Ok(ScopedExecutor::from_dsn(dsn, 4).map_err(|e| e.0)?.with_audit_keys("22".repeat(32), String::new()))
        };
        let adapter = Probe {
            inner: ScimRoute {
                exec: mk(&dsn)?,
                worker: mk(&db.dsn)?,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                authserver_url: format!("http://{authserver}"),
                internal_key: INTERNAL_KEY.into(),
            },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F02" && r["slice"] == "scim" {
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

        let send = |request: &spec::Request| {
            let mut builder = Request::builder()
                .method(request.method)
                .uri(&request.target)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("x-request-id", "gofree-dirsync3-oracle");
            if let Some(ct) = &request.content_type {
                builder = builder.header("content-type", ct.as_str());
            }
            match &request.auth {
                spec::Auth::Token(tok) => {
                    builder = builder.header("authorization", format!("Bearer {}", world.token(*tok).unwrap_or("missing")));
                }
                spec::Auth::Raw(value) => builder = builder.header("authorization", value.as_str()),
                spec::Auth::None => {}
            }
            let request = builder.body(common::full(request.body.clone()));
            async move { Ok::<_, BoxError>(common::send(address, request?).await) }
        };
        if label == "repeat" {
            let first = send(&case.request).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            let initial = if action == "groups-delete" { 204 } else { case.status };
            if recording && status != initial {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
            wait_effects(&owner, &sources, &calls, &case, false).await?;
            calls.lock().unwrap().clear();
        }
        let before = snapshot(&owner, &sources).await?;
        let before_calls = calls.lock().unwrap().len();
        let response = send(&case.request).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        wait_effects(&owner, &sources, &calls, &case, true).await?;
        let after = snapshot(&owner, &sources).await?;
        let revokes: Vec<Value> = {
            let all = calls.lock().unwrap();
            all.iter().skip(before_calls.min(all.len())).cloned().collect()
        };
        if recording && status != case.status {
            return Err(format!("Go {action}/{label}: expected {}, got {status}: {raw}", case.status).into());
        }
        let ids_owned = names(&owner, &world, &sources).await?;
        let ids: Vec<(i64, &str)> = ids_owned.iter().map(|(i, n)| (*i, n.as_str())).collect();
        let mask = |v: &Value| -> Result<Value, BoxError> { Ok(mask_value(v, &world, &ids, "")) };
        let mut text = mask_text(&raw, &world, &ids);
        let mut headers = Value::Object(headers);
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() {
                return Err("bad wire length".into());
            }
            *length = json!([text.len().to_string()]);
        }
        if let Some(location) = headers.get_mut("location") {
            // The sync cursor names the source: show the decoded form.
            let masked = location[0].as_str().unwrap_or("").to_owned();
            *location = json!([unmask_sync(&masked, &world)]);
        }
        let headers = mask(&headers)?;
        let effects = json!([{"table":"scim","before":mask(&before)?,"after":mask(&after)?}]);
        let audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&audit_start])
            .await?
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        let audit: Vec<Value> = audit
            .into_iter()
            .map(|mut row| {
                row["id"] = json!("<audit>");
                if let Some(at) = row.get_mut("created_at") { *at = json!("<timestamp>"); }
                mask_value(&row, &world, &ids, "")
            })
            .collect();
        let mut request = json!({"method": case.method_name, "path": case.pattern, "external_path": case.pattern});
        if !case.query_label.is_empty() {
            request["query"] = json!(mask_text(&case.query_label, &world, &ids));
        }
        if !case.body_label.is_empty() {
            request["body"] = json!(mask_text(&case.body_label, &world, &ids));
        }
        if !case.request.content_type.as_deref().is_some_and(|c| c == "application/scim+json") {
            request["content_type"] = json!(case.request.content_type);
        }
        let revokes = mask(&Value::Array(revokes))?;
        text = text.replace("\r", "");
        let observation = json!({
            "request": request,
            "response": {"status": status, "headers": headers, "body": text},
            "effects": effects,
            "audit": audit,
            "notify": revokes,
        });
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F02\"} 0") {
                return Err(format!("F02 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/scim/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{} {}", case.method_name, case.pattern);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = common::golden_doc(&file, "observation", &observation);
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.expect_err("planted status mutant survived");
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            compared?;
            let expected: Value = common::golden_doc(&row_file, "effects", &observation["effects"]);
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;

    cleanup(
        &owner,
        &world,
        &sources,
        audit_start,
        &token_ids,
        domain_id,
        toggle,
    )
    .await?;
    result
}

fn unmask_sync(location: &str, world: &World) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let Some(token) = location.strip_prefix("/scim/v2/Users?syncToken=") else {
        return location.to_owned();
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(token) else {
        return location.to_owned();
    };
    let text =
        String::from_utf8_lossy(&bytes).replace(&format!("\"{}\"", world.src_a), "\"<source-a>\"");
    format!("/scim/v2/Users?syncToken={text}")
}

/// Wait for the asynchronous effects Go starts after answering: welcome mail and
/// revocation calls. After the settle window nothing unexpected may have arrived.
async fn wait_effects(
    owner: &tokio_postgres::Client,
    sources: &[i64],
    calls: &Arc<Mutex<Vec<Value>>>,
    case: &spec::Case,
    check: bool,
) -> Result<(), BoxError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        let welcomed: i64 = owner
            .query_one("SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.raw_ref LIKE 'system:welcome:%' AND mb.user_id IN (SELECT user_id FROM user_identity_links WHERE source_id=ANY($1) AND external_subject LIKE 'new-%')", &[&sources])
            .await?
            .get(0);
        let need = if check { case.welcome } else { 0 };
        if (welcomed >= need as i64 || tokio::time::Instant::now() >= deadline)
            && (calls.lock().unwrap().len() >= case.revokes
                || !check
                || tokio::time::Instant::now() >= deadline)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    Ok(())
}

async fn cleanup(
    owner: &tokio_postgres::Client,
    world: &World,
    sources: &[i64],
    audit_start: i64,
    token_names: &[String],
    domain: i64,
    toggle: bool,
) -> Result<(), BoxError> {
    let users: Vec<i64> = owner
        .query(
            "SELECT user_id FROM user_identity_links WHERE source_id=ANY($1)",
            &[&sources],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .execute(
            "DELETE FROM scim_tokens WHERE name=ANY($1)",
            &[&token_names],
        )
        .await?;
    for group in owner
        .query(
            "SELECT id FROM distribution_groups WHERE scim_source_id=ANY($1)",
            &[&sources],
        )
        .await?
    {
        let id: i64 = group.get(0);
        let (src, generation): (i64, i64) = owner.query_one("SELECT scim_source_id, (SELECT generation FROM identity_sources WHERE id=scim_source_id) FROM distribution_groups WHERE id=$1", &[&id]).await.map(|r| (r.get(0), r.get(1)))?;
        owner
            .execute(
                "SELECT scim_delete_group($1,$2,$3)",
                &[&src, &generation, &id],
            )
            .await?;
    }
    let mailboxes: Vec<i64> = owner
        .query("SELECT id FROM mailboxes WHERE user_id=ANY($1)", &[&users])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    // Membership rows go before users/mailboxes: an orphan row breaks the backup restore.
    owner
        .execute(
            "DELETE FROM distribution_group_members WHERE mailbox_id=ANY($1) \
             OR group_id IN (SELECT id FROM distribution_groups WHERE scim_source_id=ANY($2))",
            &[&mailboxes, &sources],
        )
        .await?;
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; \
             DELETE FROM mailbox_audit_log WHERE mailbox_id=ANY(ARRAY[{}]::bigint[]); COMMIT;",
            mailboxes.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
        ))
        .await?;
    owner
        .execute(
            "DELETE FROM messages WHERE mailbox_id=ANY($1)",
            &[&mailboxes],
        )
        .await?;
    // Source-owned rows first (generic over every table that references the source).
    for row in owner
        .query("SELECT c.conrelid::regclass::text, a.attname FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey) WHERE c.confrelid='identity_sources'::regclass AND c.contype='f'", &[])
        .await?
    {
        let (table, column): (String, String) = (row.get(0), row.get(1));
        owner
            .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM {table} WHERE {column}=ANY(ARRAY[{},{}]::bigint[]); COMMIT;", sources[0], sources[1]))
            .await?;
    }
    // Ordinary deletes: the mailbox/user cascades (folders, journals, claims, lifecycle rows)
    // run, so no orphan survives to break the mailctl backup restore (#421).
    owner
        .batch_execute(&format!(
            "BEGIN; DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE user_id=ANY(ARRAY[{users}]::bigint[])); \
             DELETE FROM mailboxes WHERE user_id=ANY(ARRAY[{users}]::bigint[]); \
             DELETE FROM users WHERE id=ANY(ARRAY[{users}]::bigint[]); COMMIT;",
            users = users
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ))
        .await?;
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM identity_sources WHERE id=ANY(ARRAY[{},{}]::bigint[]); COMMIT;",
            sources[0], sources[1],
        ))
        .await?;
    owner
        .execute("DELETE FROM domains WHERE id=$1", &[&domain])
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.identity_model_v2'",
            &[&toggle],
        )
        .await?;
    let _ = world;
    Ok(())
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
