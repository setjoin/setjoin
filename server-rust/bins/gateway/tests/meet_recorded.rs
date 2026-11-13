//! #285: F13 golden routes recorded from frozen Go through the front door.
//! Recording runs Go behind an empty route table; replay unsets Go and serves
//! the routes natively. LiveKit is only configured, never contacted.
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use meet_fixture::{
    audit_rows, cleanup, events, ledger, normalize_instance, observe, snapshot, token, Ids,
};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::collections::BTreeMap;

macro_rules! cases {
    ($($name:ident = $route:literal, $case:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run($route, $case, false).await
        }
    )*};
}
macro_rules! rejects_status {
    ($($name:ident = $route:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            reject_status($route).await
        }
    )*};
}

cases! {
    list_success = "list", "success";
    list_foreign = "list", "foreign";
    list_invalid = "list", "invalid";
    list_disabled = "list", "disabled";
    list_unconfigured = "list", "unconfigured";
    get_success = "get", "success";
    get_foreign = "get", "foreign";
    get_invalid = "get", "invalid";
    get_missing = "get", "missing";
    by_slug_success = "by_slug", "success";
    by_slug_foreign = "by_slug", "foreign";
    by_slug_invalid = "by_slug", "invalid";
    create_success = "create", "success";
    create_foreign = "create", "foreign";
    create_invalid = "create", "invalid";
    create_repeat = "create", "repeat";
    create_empty_title = "create", "empty_title";
    create_bad_window = "create", "bad_window";
    create_bad_time = "create", "bad_time";
    create_wrong_type = "create", "wrong_type";
    create_go_json = "create", "go_json";
    create_folded = "create", "folded";
    create_unowned_event = "create", "unowned_event";
    create_disabled = "create", "disabled";
    create_language = "create", "language";
    lock_success = "lock", "success";
    lock_foreign = "lock", "foreign";
    lock_invalid = "lock", "invalid";
    lock_repeat = "lock", "repeat";
    lock_bad_body = "lock", "bad_body";
    lock_missing = "lock", "missing";
    lock_commit_before = "lock", "commit_before";
    lock_commit_after = "lock", "commit_after";
    settings_success = "settings", "success";
    settings_foreign = "settings", "foreign";
    settings_invalid = "settings", "invalid";
    settings_repeat = "settings", "repeat";
    settings_bad_body = "settings", "bad_body";
    role_success = "role", "success";
    role_foreign = "role", "foreign";
    role_invalid = "role", "invalid";
    role_repeat = "role", "repeat";
    role_bad_role = "role", "bad_role";
    role_bad_body = "role", "bad_body";
    role_ended = "role", "ended";
}
rejects_status! {
    list_rejects_status = "list";
    create_rejects_status = "create";
    get_rejects_status = "get";
    by_slug_rejects_status = "by_slug";
    lock_rejects_status = "lock";
    settings_rejects_status = "settings";
    role_rejects_status = "role";
}

#[tokio::test]
async fn rejects_no_audit() -> Result<(), BoxError> {
    reject_effect("no-audit").await
}
#[tokio::test]
async fn rejects_no_notify() -> Result<(), BoxError> {
    reject_effect("no-notify").await
}
#[tokio::test]
async fn rejects_double_bump() -> Result<(), BoxError> {
    reject_effect("double-bump").await
}
#[tokio::test]
async fn rejects_no_tenant_filter() -> Result<(), BoxError> {
    reject_effect("no-tenant-filter").await
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn route_spec(route: &str) -> (&'static str, &'static str, bool) {
    match route {
        "list" => ("GET", "/meet", false),
        "create" => ("POST", "/meet", true),
        "get" => ("GET", "/meet/{id}", false),
        "by_slug" => ("GET", "/meet/by-slug/{slug}", false),
        "lock" => ("POST", "/meet/{id}/lock", true),
        "settings" => ("POST", "/meet/{id}/settings", true),
        "role" => ("POST", "/meet/{id}/role", true),
        _ => unreachable!("unknown meet route"),
    }
}

/// The status frozen Go answers for each case; a recording that disagrees
/// is a broken fixture, never a golden.
fn expected_status(route: &str, case: &str) -> u16 {
    let (_, _, writing) = route_spec(route);
    match case {
        "disabled" => 404,
        "commit_before" | "commit_after" => 503,
        "unconfigured" => 503,
        "invalid" if route == "list" => 200,
        "invalid" if route == "by_slug" => 404,
        "invalid" => 400,
        "missing" if route == "get" => 404,
        "missing" => 403,
        "bad_body" | "bad_time" | "wrong_type" | "go_json" | "language" => 400,
        "empty_title" | "bad_window" | "unowned_event" | "bad_role" => 422,
        "foreign" if matches!(route, "create" | "lock" | "settings" | "role") => 403,
        _ if route == "create" => 201,
        _ if writing => 204,
        _ => 200,
    }
}

struct Run {
    exec: bool,
}

async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    run_inner(route, case, mutant, None, Run { exec: false }).await
}

async fn reject_status(route: &str) -> Result<(), BoxError> {
    let err = run(route, "success", true)
        .await
        .expect_err("actual HTTP status mutant must fail");
    assert!(err.to_string().contains("/response/status"), "{err}");
    let (method, canonical, _) = route_spec(route);
    println!("MUTANT-REJECTED: {method} {canonical} :: changed-status");
    Ok(())
}

async fn reject_effect(kind: &str) -> Result<(), BoxError> {
    let (route, case, pointer) = match kind {
        "no-audit" => ("create", "success", "/audit"),
        "no-notify" => ("lock", "success", "/notify"),
        "double-bump" => ("lock", "success", "/effects"),
        _ => ("lock", "foreign", "/response/status"),
    };
    let err = run_inner(route, case, false, Some(kind), Run { exec: false })
        .await
        .expect_err("actual SQL mutant must fail the immutable recording");
    assert!(err.to_string().contains(pointer), "{kind}: {err}");
    let (method, canonical, _) = route_spec(route);
    println!("MUTANT-REJECTED: {method} {canonical} :: {kind}");
    Ok(())
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::meet::MeetRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let reply = self.0.handle(r, c);
        Box::pin(async move {
            let mut reply = reply.await;
            *reply.status_mut() = hyper::StatusCode::from_u16(599).unwrap();
            reply
        })
    }
}

/// A private schema ahead of `public` on the request connection's search path.
async fn plant_mutant(
    c: &tokio_postgres::Client,
    db: &Db,
    kind: &str,
    owner: i64,
) -> Result<(String, String), BoxError> {
    let schema = format!("gofree_meet1_mutant_{owner}");
    ledger(&format!(
        "Plan private {kind} SQL mutant schema {schema}, assigned DB only"
    ))?;
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app;"
    ))
    .await?;
    let sql = match kind {
        "no-audit" => format!("CREATE FUNCTION {schema}.audit_write(bigint,text,text,bigint,jsonb,jsonb,inet,text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'"),
        "no-notify" => format!("CREATE FUNCTION {schema}.app_notify(text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'"),
        // The push seam also writes the channel's change counter a second time.
        "double-bump" => {
            let mut definition: String = c
                .query_one("SELECT pg_get_functiondef('public.notify_meet_state(bigint,text,jsonb,text[])'::regprocedure)", &[])
                .await?
                .get(0);
            definition = definition.replacen("public.notify_meet_state", &format!("{schema}.notify_meet_state"), 1);
            definition = definition.replacen(
                "v_payload := ",
                "UPDATE public.chat_channels SET change_seq=change_seq+1 WHERE id=(SELECT chat_channel_id FROM public.meetings WHERE id=p_meeting_id); v_payload := ",
                1,
            );
            definition
        }
        // Authority lookup that ignores the caller: every actor reads as host.
        "no-tenant-filter" => format!("CREATE FUNCTION {schema}.meeting_member_role(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$"),
        _ => return Err("unknown SQL mutant".into()),
    };
    if let Err(e) = c.batch_execute(&sql).await {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        return Err(e.into());
    }
    let app = db.app.as_deref().unwrap_or(&db.dsn);
    Ok((
        format!(
            "{app}{}options=-csearch_path%3D{schema}%2Cpublic",
            if app.contains('?') { "&" } else { "?" }
        ),
        schema,
    ))
}

async fn run_inner(
    route: &str,
    case: &str,
    mutant: bool,
    mutation: Option<&str>,
    _run: Run,
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    if mutation.is_some() || mutant {
        if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
            return Err("cannot record a planted mutant".into());
        }
    }
    let Some(db) = Db::for_case("meet1") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet1-owner").await?;
    let b = fixture::account(&c, "meet1-foreign").await?;
    let toggle: Option<bool> = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.meet'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let mut mutant_schema = None;
    let mut commit_wire = None;
    let result = std::panic::AssertUnwindSafe(async {
        let (method, canonical, writing) = route_spec(route);
        c.execute(
            "INSERT INTO feature_toggles(key,enabled) VALUES('feature.meet',$1) ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled",
            &[&(case != "disabled")],
        )
        .await?;
        // Seed one meeting per principal through the canonical reducer.
        let mut seeded = BTreeMap::new();
        for (who, user) in [("owner", a.user), ("foreign", b.user)] {
            let created: Value = serde_json::from_str(
                &c.query_one(
                    "SELECT meeting_create($1,$2)::text",
                    &[&user, &format!("Meet1 seed {who}")],
                )
                .await?
                .get::<_, String>(0),
            )?;
            seeded.insert(who, created);
        }
        let own_id = seeded["owner"]["meetingId"].as_i64().unwrap();
        let foreign_id = seeded["foreign"]["meetingId"].as_i64().unwrap();
        let own_slug = seeded["owner"]["slug"].as_str().unwrap().to_owned();
        let foreign_slug = seeded["foreign"]["slug"].as_str().unwrap().to_owned();
        let foreign_channel = seeded["foreign"]["chatChannelId"].as_i64().unwrap();
        if case == "ended" {
            c.execute(
                "UPDATE meetings SET state='ended', ended_at=now() WHERE id=$1",
                &[&own_id],
            )
            .await?;
        }
        if route == "role" {
            c.execute(
                "INSERT INTO meeting_participants(meeting_id,user_id,identity,role) VALUES($1,$2,'u:'||$2::bigint::text,'member')",
                &[&own_id, &b.user],
            )
            .await?;
        }
        let mut worker_app = db.app.clone();
        if let Some(kind) = mutation {
            let (dsn, schema) = plant_mutant(&c, &db, kind, a.user).await?;
            worker_app = Some(dsn);
            mutant_schema = Some(schema);
        }
        if let Some(cut) = match case {
            "commit_before" => Some(common::commit::CommitCut::BeforeCommit),
            "commit_after" => Some(common::commit::CommitCut::AfterCommit),
            _ => None,
        } {
            if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
                return Err("cannot record a COMMIT-loss case".into());
            }
            ledger("Plan gofree-meet1 COMMIT-loss proxy on the assigned application DB")?;
            let (dsn, task) = common::commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
            worker_app = Some(dsn);
            commit_wire = Some(task);
        }
        let go_env: Vec<(&str, String)> = if case == "unconfigured" {
            vec![]
        } else {
            vec![
                ("LIVEKIT_API_KEY", "meet1-key".into()),
                ("LIVEKIT_API_SECRET", "meet1-secret".into()),
                ("LIVEKIT_URL", "ws://127.0.0.1:1".into()),
            ]
        };
        let unused = common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let oracle_db = Db {
            dsn: db.dsn.clone(),
            direct: db.direct.clone(),
            app: db.app.clone(),
        };
        let oracle =
            common::go_oracle::start_named_with_env(&oracle_db, unused, "gofree-meet1", &go_env)
                .await?;
        let recording = oracle.is_some();
        let (actor, other) = if matches!(case, "foreign") && matches!(route, "list") {
            (&b, &a)
        } else {
            (&a, &b)
        };
        // After seeding, so only the request's own effects are observed.
        let audit_start: i64 = c
            .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
            .await?
            .get(0);
        let mut listeners = Vec::new();
        for channel in [
            format!("meet:{}", a.user),
            format!("meet:{}", b.user),
            format!("chat:{}", a.user),
            format!("chat:{}", b.user),
        ] {
            listeners.push((channel.clone(), db.listen(&channel).await?));
        }
        let baseline = snapshot(&c, &a, &b).await?;
        let adapter = setjoin_gateway::meet::MeetRoute::new(
            setjoin_pg::ScopedExecutor::from_dsn(worker_app.as_deref().unwrap_or(&db.dsn), 1)
                .map_err(|e| e.0)?
                .with_audit_keys("22".repeat(32), String::new()),
            std::sync::Arc::new(common::recovery_keys()),
            "mailserver".into(),
            if case == "unconfigured" {
                setjoin_gateway::meet_livekit::LiveKit::unconfigured()
            } else {
                setjoin_gateway::meet_livekit::LiveKit::new(
                    "meet1-key",
                    "meet1-secret",
                    "ws://127.0.0.1:1",
                    false,
                    false,
                )
            },
        );
        let routes = if recording {
            RouteTable::proxy_all()
        } else if mutant {
            RouteTable::proxy_all().with(ChangedStatus(adapter))
        } else {
            RouteTable::proxy_all().with(adapter)
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

        let target_id = if matches!(case, "foreign") && route != "list" && route != "create" {
            foreign_id
        } else if case == "missing" {
            i64::MAX
        } else {
            own_id
        };
        let target_slug = if case == "foreign" { &foreign_slug } else { &own_slug };
        let mut request_path = match route {
            "list" => "/api/meet".to_owned(),
            "create" => "/api/meet".to_owned(),
            "by_slug" => format!(
                "/api/meet/by-slug/{}",
                if case == "invalid" { "no-such-slug" } else { target_slug }
            ),
            "get" => format!("/api/meet/{target_id}"),
            other => format!("/api/meet/{target_id}/{other}"),
        };
        if case == "invalid" && matches!(route, "get" | "lock" | "settings" | "role") {
            request_path = request_path.replacen(&target_id.to_string(), "bad", 1);
        }
        if route == "list" && case == "invalid" {
            request_path.push_str("?limit=bad&offset=bad");
        }
        let identity = format!("u:{}", b.user);
        let mut body = match route {
            "create" => json!({"title":"Meet1 created","scheduledStart":"2026-11-20T10:00:00Z","scheduledEnd":"2026-11-20T11:00:00Z","guestAllowed":true}).to_string(),
            "lock" => json!({"locked":true}).to_string(),
            "settings" => json!({"guestAllowed":true}).to_string(),
            "role" => json!({"identity":identity,"role":"cohost"}).to_string(),
            _ => String::new(),
        };
        match (route, case) {
            ("create", "foreign") => {
                body = json!({"title":"Meet1 spoof","chatChannelId":foreign_channel,"ownerUserId":b.user,"userId":b.user}).to_string()
            }
            ("create", "invalid" | "language") => body = "{".into(),
            ("create", "empty_title") => body = json!({"title":"   "}).to_string(),
            ("create", "bad_window") => body = json!({"title":"Meet1 window","scheduledStart":"2026-11-20T11:00:00Z","scheduledEnd":"2026-11-20T10:00:00Z"}).to_string(),
            ("create", "bad_time") => body = json!({"title":"Meet1 time","scheduledStart":"tomorrow"}).to_string(),
            ("create", "wrong_type") => body = json!({"title":5}).to_string(),
            ("create", "go_json") => body = r#"{"TITLE":"Go json","title":null,"future":1e400} trailing"#.into(),
            ("create", "folded") => body = r#"{"TiTlE":"Folded","GUESTALLOWED":null,"guestAllowed":true}"#.into(),
            ("create", "unowned_event") => body = json!({"title":"Meet1 event","calendarEventId":999999999}).to_string(),
            ("lock" | "settings" | "role", "invalid") => body = "{".into(),
            ("lock", "bad_body") => body = json!({"locked":"yes"}).to_string(),
            ("settings", "bad_body") => body = json!({"guestAllowed":"yes"}).to_string(),
            ("role", "bad_body") => body = json!({"identity":5,"role":"cohost"}).to_string(),
            ("role", "bad_role") => body = json!({"identity":identity,"role":"king"}).to_string(),
            _ => {}
        }
        let send = |body: String| {
            let token = token(actor.user, "meet1-oracle");
            let language = if case == "language" { "zh-CN, en;q=0.8" } else { "en" };
            let uri = request_path.clone();
            async move {
                common::send(
                    addr,
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("content-type", "application/json")
                        .header("x-request-id", "meet1-oracle")
                        .header("accept-language", language)
                        .body(common::full(body))
                        .unwrap(),
                )
                .await
            }
        };
        let ids = Ids::load(&c, &a, &b).await?;
        let first = if case == "repeat" {
            let response = send(body.clone()).await;
            let mut first = observe(response).await?;
            first["effects"] = snapshot(&c, &a, &b).await?;
            first["audit"] = audit_rows(&c, audit_start, &a, &b).await?;
            first["notify"] = events(&mut listeners, &c).await?;
            Some(first)
        } else {
            None
        };
        let response = send(body.clone()).await;
        let mut observed = observe(response).await?;
        let status = observed["response"]["status"].as_u64().unwrap() as u16;
        if !recording {
            let metrics = common::send(
                addr,
                Request::builder().uri("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !mutant
                && (!metrics.contains("setjoin_gateway_proxied_to_go_total 0")
                    || !metrics.contains("setjoin_gateway_proxied_to_go_by_family_total{family=\"F13\"} 0"))
            {
                return Err(format!("native Go proxy counters: {metrics}").into());
            }
        }
        server.abort();
        let _ = server.await;
        if mutation.is_none() && !mutant {
            let want = expected_status(route, case);
            if status != want {
                return Err(format!("HTTP status expected {want}, got {status}: {observed}").into());
            }
        }
        let ids = ids.with_new(&c, &a, &b).await?;
        let (mut effects, mut audit, notify) = if writing {
            (
                snapshot(&c, &a, &b).await?,
                audit_rows(&c, audit_start, &a, &b).await?,
                events(&mut listeners, &c).await?,
            )
        } else {
            let _ = events(&mut listeners, &c).await?;
            (json!({}), json!([]), json!([]))
        };
        if !writing {
            let after = snapshot(&c, &a, &b).await?;
            if after != baseline {
                return Err("read-only route changed committed rows".into());
            }
        }
        let mut notify = notify;
        let canonical_path = canonical.to_owned();
        let actual_path = request_path.split('?').next().unwrap().strip_prefix("/api").unwrap().to_owned();
        for v in [&mut observed["response"]["body"], &mut effects, &mut audit, &mut notify] {
            normalize_instance(v, &actual_path, &canonical_path);
            ids.normalize(v, "", "");
        }
        let mut first = first;
        if let Some(first) = first.as_mut() {
            normalize_instance(&mut first["response"]["body"], &actual_path, &canonical_path);
            ids.normalize(&mut first["response"]["body"], "", "");
            for key in ["effects", "audit", "notify"] {
                ids.normalize(&mut first[key], "", "");
            }
        }
        let mut observation = json!({
            "request": {"method": method, "path": canonical},
            "response": observed["response"],
            "effects": effects, "audit": audit, "notify": notify,
        });
        if let Some(first) = first {
            observation["first"] = first;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/conformance/meet/goldens/{route}-{case}.json"
        ));
        let rows = |o: &Value| json!([o["effects"], o["audit"], o["notify"]]);
        let label = format!("{method} {canonical}");
        if case.starts_with("commit_") {
            let committed = case == "commit_after";
            let cut = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                commit_wire.take().ok_or("COMMIT proxy")?,
            )
            .await???;
            if (cut == common::commit::CommitCut::AfterCommit) != committed {
                return Err("wrong wire cut".into());
            }
            let operation = observation["response"]["headers"]["x-operation-id"]
                .as_str()
                .ok_or("Unknown lost operation ID")?;
            if operation.len() != 32 || !operation.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid operation ID".into());
            }
            let receipt: bool = c
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F13' AND command='meeting_lock')",
                    &[&operation],
                )
                .await?
                .get(0);
            if receipt != committed {
                return Err("receipt did not resolve the actual commit".into());
            }
            if committed {
                // The acknowledged-lost commit still carries Go's whole business effect.
                let lock: Value = serde_json::from_slice(&std::fs::read(path.with_file_name("lock-success.json"))?)?;
                for key in ["effects", "audit", "notify"] {
                    setjoin_conformance::golden::compare(&lock["observation"][key], &observation[key])?;
                }
            } else {
                let mut seed = baseline.clone();
                ids.normalize(&mut seed, "", "");
                setjoin_conformance::golden::compare(&seed, &observation["effects"])?;
                if observation["audit"] != json!([]) || observation["notify"] != json!([]) {
                    return Err("aborted commit left effects".into());
                }
            }
            ledger("Reaped gofree-meet1 COMMIT-loss proxy; HTTP Unknown resolved from receipt without replay")?;
            return Ok(());
        }
        if recording {
            let want = expected_status(route, case);
            if status != want {
                return Err(format!("unexpected Go status {status}, expected {want}: {observation:#}").into());
            }
            if writing {
                setjoin_conformance::golden::record(
                    &path.with_file_name(format!("{route}-{case}-row-effects.json")),
                    &json!({"format":1,"route":label,"case":format!("{route}-{case}-row-effects"),
                        "go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":rows(&observation)}),
                )?;
            }
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"route":label,"case":format!("{route}-{case}"),
                    "go_source":std::env::var("GOFREE_GO_SOURCE")?,
                    "normalization":["fixture identities","generated ids, slugs, room names and timestamps; chat and core audit chains verified"],
                    "observation":observation}),
            )?;
        } else {
            let expected: Value = common::golden_doc(&path, "observation", &observation);
            setjoin_conformance::golden::compare(&expected["observation"], &observation)?;
            if writing {
                let recorded: Value = serde_json::from_slice(&std::fs::read(
                    path.with_file_name(format!("{route}-{case}-row-effects.json")),
                )?)?;
                setjoin_conformance::golden::compare(&recorded["effects"], &rows(&observation))?;
            }
            println!("GOLDEN-REPLAY: {label} :: {route}-{case}");
        }
        let _ = (other, &baseline);
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    if let Some(task) = commit_wire {
        task.abort();
        let _ = task.await;
        ledger("Reaped failed gofree-meet1 COMMIT proxy")?;
    }
    if let Some(schema) = mutant_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        ledger(&format!("Removed private SQL mutant schema {schema}"))?;
    }
    cleanup(&c, &[&a, &b]).await?;
    match toggle {
        Some(v) => {
            c.execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.meet'",
                &[&v],
            )
            .await?;
        }
        None => {
            c.execute("DELETE FROM feature_toggles WHERE key='feature.meet'", &[])
                .await?;
        }
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
