//! #416 frozen-Go mux/SPA responses, recorded through the real front door.
mod common;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[path = "catchall_oracle/assets.rs"]
mod assets;
static SERIAL: Mutex<()> = Mutex::new(());

/// Native-only faults injected through a shadowing schema on the catch-all's executor
/// (the verifier reads the real tables): T9 toggle read, T8 entitlement read.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Toggle,
    Entitlement,
}
#[derive(Clone)]
struct Case {
    website: bool,
    headers: Vec<(&'static str, String)>,
    auth: bool,
    foreign: bool,
    enabled: bool,
    configured: bool,
    entitled: bool,
    fault: Fault,
    name: &'static str,
    method: &'static str,
    uri: &'static str,
}
fn cases() -> Vec<Case> {
    let c = |name, method, uri| Case {
        name,
        method,
        uri,
        website: false,
        headers: vec![],
        auth: false,
        foreign: false,
        enabled: true,
        configured: false,
        entitled: true,
        fault: Fault::None,
    };
    vec![
        c("root_unknown", "GET", "/catchall-unknown"),
        c("mux_clean_get", "GET", "/a//b/../c?x=1&y=%20"),
        c("mux_clean_post", "POST", "/a/./b"),
        c("mux_clean_reserved", "GET", "/a//b;c,d"),
        c("mux_inner_encoded_slash", "GET", "/api/%63hat"),
        c("mux_clean_head", "HEAD", "/api//phantom"),
        c("mux_encoded_clean", "GET", "/a//%2e/%2f"),
        c("mux_encoded_dot", "GET", "/%2e%2e/phantom"),
        c("mux_api_slash", "GET", "/api?q=1"),
        c("mux_api_slash_post", "POST", "/api"),
        c("mux_inner_slash", "GET", "/api/chat?q=2"),
        c("mux_legacy_post", "POST", "/chat/phantom?a=1"),
        c(
            "mux_legacy_absolute",
            "POST",
            "http://mail.test/chat/phantom?x=%26",
        ),
        c("mux_legacy_options", "OPTIONS", "/drive/phantom"),
        c("mux_legacy_unknown", "POST", "/unknown"),
        c("mux_api_unknown", "GET", "/api/unknown"),
        c("mux_api_literal_wrong_method", "POST", "/api/docs"),
        c("mux_api_wrong_method", "PATCH", "/api/admin/users"),
        c("mux_api_unknown_head", "HEAD", "/api/unknown"),
        c("mux_root_head", "HEAD", "/unknown"),
        c("mux_bare_get", "GET", "/chat/phantom"),
        c("mux_bare_meet", "GET", "/meet"),
        c("mux_alias_body", "PUT", "/meet?x=%26"),
        c("mux_connect", "CONNECT", "/a//b"),
        Case {
            auth: true,
            foreign: true,
            ..c("root_foreign", "GET", "/catchall-unknown")
        },
        c("api_unknown", "GET", "/api/phantom"),
        Case {
            headers: vec![("authorization", "Basic Zm9vOmJhcg==".into())],
            ..c("api_basic", "GET", "/api/phantom")
        },
        Case {
            headers: vec![("cookie", "access_token=".into())],
            ..c("api_empty_cookie", "GET", "/api/phantom")
        },
        Case {
            headers: vec![("authorization", "Basic Zm9vOmJhcg==".into())],
            ..c("mux_legacy_basic", "POST", "/chat/phantom")
        },
        c("mux_connect_authority", "CONNECT", "mail.test:443"),
        Case {
            auth: true,
            foreign: true,
            ..c("api_foreign", "GET", "/api/phantom")
        },
        c("api_invalid", "PATCH", "/api/phantom"),
        c("chat_anonymous", "GET", "/api/chat/phantom"),
        Case {
            auth: true,
            ..c("chat_unknown", "GET", "/api/chat/phantom")
        },
        Case {
            auth: true,
            foreign: true,
            ..c("chat_foreign", "GET", "/api/chat/phantom")
        },
        Case {
            auth: true,
            ..c("chat_invalid", "POST", "/api/chat/channels/123")
        },
        Case {
            auth: true,
            enabled: false,
            ..c("chat_disabled", "GET", "/api/chat/phantom")
        },
        Case {
            auth: true,
            ..c("chat_encoded_mount", "GET", "/%61pi/chat/phantom")
        },
        c("drive_anonymous", "GET", "/api/drive/phantom"),
        Case {
            auth: true,
            ..c("drive_unknown", "GET", "/api/drive/phantom")
        },
        Case {
            auth: true,
            foreign: true,
            ..c("drive_foreign", "GET", "/api/drive/phantom")
        },
        Case {
            auth: true,
            ..c("drive_invalid", "PATCH", "/api/drive/spaces")
        },
        Case {
            auth: true,
            enabled: false,
            ..c("drive_disabled", "GET", "/api/drive/phantom")
        },
        c("meet_anonymous", "GET", "/api/meet/phantom/path"),
        Case {
            auth: true,
            configured: true,
            ..c("meet_unknown", "GET", "/api/meet/phantom/path")
        },
        Case {
            auth: true,
            foreign: true,
            configured: true,
            ..c("meet_foreign", "GET", "/api/meet/phantom/path")
        },
        Case {
            auth: true,
            configured: true,
            ..c("meet_invalid", "PATCH", "/api/meet/phantom/path")
        },
        Case {
            auth: true,
            enabled: false,
            ..c("meet_disabled", "GET", "/api/meet/phantom/path")
        },
        Case {
            auth: true,
            ..c("meet_unconfigured", "GET", "/api/meet/phantom/path")
        },
        Case {
            auth: true,
            entitled: false,
            ..c("chat_not_entitled", "GET", "/api/chat/phantom")
        },
        Case {
            auth: true,
            entitled: false,
            ..c("drive_not_entitled", "GET", "/api/drive/phantom")
        },
        Case {
            auth: true,
            configured: true,
            entitled: false,
            ..c("meet_not_entitled", "GET", "/api/meet/phantom/path")
        },
        Case {
            auth: true,
            entitled: false,
            fault: Fault::Entitlement,
            ..c("chat_not_entitled_read_fault", "GET", "/api/chat/phantom")
        },
        Case {
            auth: true,
            fault: Fault::Toggle,
            ..c("chat_toggle_read_fault", "GET", "/api/chat/phantom")
        },
        c("meet_exact_anonymous", "PATCH", "/api/meet"),
        Case {
            auth: true,
            configured: true,
            ..c("meet_exact_unknown", "PATCH", "/api/meet")
        },
        Case {
            auth: true,
            foreign: true,
            configured: true,
            ..c("meet_exact_foreign", "PATCH", "/api/meet")
        },
        Case {
            auth: true,
            configured: true,
            ..c("meet_exact_invalid", "DELETE", "/api/meet")
        },
        Case {
            website: true,
            ..c("spa_root", "GET", "/")
        },
        Case {
            website: true,
            ..c("spa_setup", "GET", "/")
        },
        Case {
            website: true,
            ..c("spa_setup_head", "HEAD", "/")
        },
        Case {
            website: true,
            ..c("spa_page", "GET", "/settings/mail")
        },
        Case {
            website: true,
            ..c("spa_directory", "GET", "/meet")
        },
        Case {
            website: true,
            ..c("spa_missing_asset", "GET", "/_app/immutable/missing.js")
        },
        Case {
            website: true,
            ..c("spa_missing_other", "GET", "/missing.js")
        },
        Case {
            website: true,
            ..c("spa_asset", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            ..c("spa_head", "HEAD", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            ..c("spa_json", "GET", "/_app/version.json")
        },
        Case {
            website: true,
            ..c("spa_css", "GET", "/style.css")
        },
        Case {
            website: true,
            ..c("spa_xml", "GET", "/feed.xml")
        },
        Case {
            website: true,
            ..c("spa_model", "GET", "/meet/mediapipe/model.tflite")
        },
        Case {
            website: true,
            headers: vec![("accept-encoding", "gzip".into())],
            ..c("spa_gzip", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("accept-encoding", "gzip;q=0.2, br;q=0.5".into())],
            ..c("spa_brotli", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("accept-encoding", "identity;q=1, br;q=.3".into())],
            ..c("spa_identity_preferred", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("accept-encoding", "*;q=.4".into())],
            ..c("spa_wildcard", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("accept-encoding", "*;q=0".into())],
            ..c("spa_refused", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![
                ("range", "bytes=2-8".into()),
                ("accept-encoding", "br".into()),
            ],
            ..c("spa_range", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("range", "bytes=-8".into())],
            ..c("spa_suffix", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("range", "bytes=99999-".into())],
            ..c("spa_bad_range", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![
                ("range", "bytes=0-5".into()),
                ("accept-encoding", "identity;q=0,gzip".into()),
            ],
            ..c("spa_range_refused", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("if-none-match", assets::etag())],
            ..c("spa_etag", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("if-none-match", format!("W/{}", assets::etag()))],
            ..c("spa_weak_etag", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("if-modified-since", "Tue, 14 Nov 2023 22:13:20 GMT".into())],
            ..c("spa_since", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("if-match", "\"wrong\"".into())],
            ..c("spa_if_match", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            ..c("spa_post", "POST", "/unknown")
        },
        Case {
            website: true,
            ..c("spa_manifest", "GET", "/static-representations.v1.json")
        },
        Case {
            website: true,
            ..c("spa_direct_sidecar", "GET", "/_app/immutable/app.js.gz")
        },
        Case {
            website: true,
            ..c("spa_encoded_parent", "GET", "/%2e%2e/secret")
        },
        Case {
            website: true,
            ..c("spa_encoded_slash", "GET", "/settings%2fmail")
        },
        Case {
            website: true,
            headers: vec![("range", "bytes=0-2,8-10".into())],
            ..c("spa_extra_multipart", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("range", "bytes=0-2499,0-2499".into())],
            ..c("spa_extra_range_oversize", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("range", "bytes=99999-,0-5".into())],
            ..c("spa_extra_range_partial", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("range", "bytes=wrong".into())],
            ..c("spa_extra_range_invalid", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![
                ("range", "bytes=0-5".into()),
                ("if-range", "\"wrong\"".into()),
            ],
            ..c("spa_extra_if_range", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![(
                "if-unmodified-since",
                "Tue, 14 Nov 2000 22:13:20 GMT".into(),
            )],
            ..c("spa_extra_unmodified", "GET", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            headers: vec![("accept-encoding", "gzip".into())],
            ..c("spa_extra_head_gzip", "HEAD", "/_app/immutable/app.js")
        },
        Case {
            website: true,
            ..c(
                "spa_extra_legacy_cache",
                "GET",
                "/chat/unfurl/image/phantom",
            )
        },
        Case {
            website: true,
            ..c("spa_extra_admin_cache", "GET", "/admin/identity/v2/people")
        },
    ]
}
fn path(c: &Case) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/catchall/goldens/{}.json",
        c.name.strip_suffix("_read_fault").unwrap_or(c.name)
    ))
}
async fn run(name: &str) -> Result<(), BoxError> {
    run_inner(name, false).await
}
async fn run_inner(name: &str, mutant: bool) -> Result<(), BoxError> {
    assert!(
        !mutant || std::env::var_os("GOFREE_RECORD_GO_BINARY").is_none(),
        "mutants never record"
    );
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case(name) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let actor = if name.starts_with("spa_setup") {
        None
    } else {
        Some(setjoin_conformance::fixture::account(&owner, "catchall").await?)
    };
    let foreign = if name.starts_with("spa_setup") {
        None
    } else {
        Some(setjoin_conformance::fixture::account(&owner, "catchall-foreign").await?)
    };
    let result = std::panic::AssertUnwindSafe(async {
        for case in cases().into_iter().filter(|c| c.name == name || (name == "mux_paths" && c.name.starts_with("mux_"))) {
            if case.fault != Fault::None && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
                continue; // native-only: Go reads toggles from memory; its reducer cannot be shadowed
            }
            let app = if case.name.starts_with("chat_") {Some("chat")} else if case.name.starts_with("drive_") {Some("drive")} else if case.name.starts_with("meet_") {Some("meet")} else {None};
            let old = if let Some(app)=app {
                let key=format!("feature.{app}");
                let old=owner.query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key]).await?.map(|r|r.get::<_,bool>(0));
                owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=$2", &[&key,&case.enabled]).await?;
                Some((key,old))
            } else {None};
            let user = if case.foreign {foreign.as_ref().map_or(1,|a|a.user)} else {actor.as_ref().map_or(1,|a|a.user)};
            let blocked = if case.entitled { None } else { Some(app.ok_or("an entitlement case needs an app")?) };
            if let Some(name) = blocked {
                owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,$2,false)", &[&user, &name]).await?;
            }
            let fault_schema = if case.fault == Fault::None {
                None
            } else {
                let id: String = owner.query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[]).await?.get(0);
                if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid fault schema ID".into()); }
                let schema = format!("gofree_catchall_fault_{id}");
                let body = match case.fault {
                    Fault::Toggle => format!("CREATE VIEW {schema}.feature_toggles AS SELECT key, CASE WHEN key='feature.chat' THEN (1/(length(key)-length(key)))::boolean ELSE enabled END AS enabled FROM public.feature_toggles; GRANT SELECT ON {schema}.feature_toggles TO PUBLIC;"),
                    _ => format!("CREATE FUNCTION {schema}.check_user_app_entitlement(bigint,text) RETURNS boolean LANGUAGE plpgsql AS $f$BEGIN RAISE EXCEPTION 'gofree catchall entitlement fault'; END$f$; GRANT EXECUTE ON FUNCTION {schema}.check_user_app_entitlement(bigint,text) TO PUBLIC;"),
                };
                owner.batch_execute(&format!("CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; {body}")).await?;
                Some(schema)
            };
            let base = db.app.as_deref().unwrap_or(&db.dsn).to_owned();
            let dsn = match &fault_schema {
                Some(schema) => {
                    if base.contains("options=") { return Err("fault DSN already has options".into()); }
                    format!("{base}{}options=-csearch_path%3D{schema}%2Cpublic", if base.contains('?') {'&'} else {'?'})
                }
                None => base,
            };
            let response=observe(case.clone(), &db, &owner, &dsn, user, mutant).await;
            if let Some(schema) = fault_schema {
                owner.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
            }
            if let Some(name) = blocked {
                owner.execute("DELETE FROM user_app_entitlements WHERE user_id=$1 AND app=$2", &[&user, &name]).await?;
                owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={user} AND action='app_blocked';COMMIT;")).await?;
            }
            if let Some((key,old))=old {match old {Some(v)=>{owner.execute("UPDATE feature_toggles SET enabled=$2 WHERE key=$1",&[&key,&v]).await?;},None=>{owner.execute("DELETE FROM feature_toggles WHERE key=$1",&[&key]).await?;}}}
            response?;
        }
        Ok(())
    }).catch_unwind().await;
    if let Some(actor) = actor {
        setjoin_conformance::fixture::remove(&owner, &actor).await?;
    }
    if let Some(foreign) = foreign {
        setjoin_conformance::fixture::remove(&owner, &foreign).await?;
    }
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
async fn observe(c: Case, db: &Db, owner: &tokio_postgres::Client, dsn: &str, user: i64, mutant: bool) -> Result<(), BoxError> {
    let s3 = common::fake_upstream(|_| async { Response::builder().body(common::full("<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")).unwrap() }).await;
    let mut extra = if c.configured {
        vec![
            ("LIVEKIT_URL", "http://127.0.0.1:1".into()),
            ("LIVEKIT_API_KEY", "catchall-key".into()),
            ("LIVEKIT_API_SECRET", "catchall-secret".into()),
        ]
    } else {
        vec![]
    };
    let website = if c.website {
        Some(assets::website(c.name)?)
    } else {
        None
    };
    if let Some(site) = &website {
        extra.push((
            "WEBSITE_DIR",
            format!(
                "/evidence/{}",
                site.0.file_name().unwrap().to_str().unwrap()
            ),
        ));
    }
    let go = common::go_oracle::start_named_with_env(db, s3, "gofree-catchall", &extra).await?;
    let exec = setjoin_pg::ScopedExecutor::from_dsn(dsn, 2)
        .map_err(|e| e.0)?;
    let mut catchall = setjoin_gateway::catchall::CatchallRoute::new().with_auth(
        exec,
        Arc::new(common::recovery_keys()),
        "mailserver".into(),
    );
    catchall.meet_configured = c.configured;
    if let Some(site) = &website {
        catchall.website = Some(Arc::new(setjoin_static::website::Website::load(&site.0)?));
    }
    let table = if mutant {
        RouteTable::proxy_all().with_catchall(ChangeStatus(catchall))
    } else {
        RouteTable::proxy_all().with_catchall(catchall)
    };
    let gateway = Gateway::new(
        Config {
            upstream: go
                .as_ref()
                .map(|g| format!("http://{}", g.address).parse().unwrap()),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: None,
        },
        table,
    )?;
    let gateway = if go.is_some() {
        gateway.with_enabled(false)
    } else {
        gateway
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(gateway.serve_until(listener, async {
        let _ = stopped.await;
    }));
    let audit_floor: i64 = owner
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let mut request = Request::builder()
        .method(c.method)
        .uri(c.uri)
        .header("host", "mail.test")
        .header("x-request-id", "catchall-test");
    if c.auth {
        request = request.header(
            "authorization",
            format!("Bearer {}", common::recovery_token(user)),
        );
    }
    for (name, value) in &c.headers {
        request = request.header(*name, value);
    }
    let response = common::send(addr, request.body(common::full(""))?).await;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        if !matches!(
            name.as_str(),
            "date" | "transfer-encoding" | "content-length"
        ) || (c.website && name.as_str() == "content-length")
        {
            headers.insert(name.to_string(), json!(value.to_str()?));
        }
    }
    let mut bytes = common::body_bytes(response).await.to_vec();
    let audit = if c.entitled { json!([]) } else { app_blocked_rows(owner, audit_floor, user).await? };
    if let Some(content_type) = headers.get("content-type").and_then(Value::as_str) {
        if let Some(boundary) = content_type.strip_prefix("multipart/byteranges; boundary=") {
            assert!(
                boundary.len() == 60 && boundary.bytes().all(|b| b.is_ascii_hexdigit()),
                "unexpected Go multipart boundary"
            );
            let boundary = boundary.to_owned();
            headers.insert(
                "content-type".into(),
                json!("multipart/byteranges; boundary=<boundary>"),
            );
            bytes = String::from_utf8(bytes)?
                .replace(&boundary, "<boundary>")
                .into_bytes();
        }
    }
    let logical = if c.name.starts_with("api_") {
        "/api/"
    } else if c.name.starts_with("chat_") {
        "/chat/"
    } else if c.name.starts_with("drive_") {
        "/drive/"
    } else if c.name.starts_with("meet_exact_") {
        "/meet"
    } else if c.name.starts_with("meet_") {
        "/meet/"
    } else {
        "/"
    };
    let route = format!("* {logical}");
    let mut observation = json!({"request":{"method":"*","path":logical,"wire_method":c.method,"wire_path":c.uri},"response":{"status":status,"headers":headers,"body":String::from_utf8_lossy(&bytes)},"effects":[],"audit":audit,"notify":[]});
    if c.website {
        use sha2::{Digest, Sha256};
        observation["response"]["body_sha256"] = json!(format!("{:x}", Sha256::digest(&bytes)));
    }
    if go.is_none() {
        let response = common::send(
            addr,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        assert!(
            metrics
                .lines()
                .any(|line| line == "setjoin_gateway_proxied_to_go_total 0"),
            "{metrics}"
        );
    }
    let _ = stop.send(());
    task.await?;
    if c.fault == Fault::Toggle {
        let text = String::from_utf8_lossy(&bytes);
        if status != 503
            || !text.contains("\"detail\":\"service unavailable\"")
            || headers.get("content-type").and_then(Value::as_str) != Some("application/problem+json")
        {
            return Err(format!("{}: expected the fail-closed 503, got {status} {text}", c.name).into());
        }
        println!("FAULT-REPLAY: * /chat/ :: {}", c.name);
        return Ok(());
    }
    if go.is_some() {
        std::fs::create_dir_all(path(&c).parent().unwrap())?;
        golden::record(
            &path(&c),
            &json!({"format":1,"route":route,"case":c.name,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path(&c))?)?;
        let comparison = golden::compare(&expected["observation"], &observation);
        if mutant {
            assert!(comparison.is_err(), "oracle accepted changed HTTP status");
            println!("MUTANT-REJECTED: {route} :: changed-status");
        } else {
            comparison?;
            println!("GOLDEN-REPLAY: {route} :: {}", c.name);
        }
    }
    Ok(())
}
#[tokio::test]
async fn root_unknown() -> Result<(), BoxError> {
    run("root_unknown").await
}

macro_rules! case_test { ($($name:ident),+ $(,)?) => { $(#[tokio::test] async fn $name() -> Result<(),BoxError> { run(stringify!($name)).await })+ }; }
case_test!(
    mux_clean_get,
    mux_clean_post,
    mux_clean_head,
    mux_encoded_clean,
    mux_encoded_dot,
    mux_api_slash,
    mux_api_slash_post,
    mux_inner_slash,
    mux_legacy_post,
    mux_legacy_options,
    mux_legacy_unknown,
    mux_api_unknown,
    mux_api_literal_wrong_method,
    mux_api_wrong_method,
    mux_api_unknown_head,
    mux_root_head,
    mux_bare_get,
    mux_bare_meet,
    mux_alias_body,
    mux_connect
);

case_test!(
    root_foreign,
    api_unknown,
    api_foreign,
    api_invalid,
    chat_anonymous,
    chat_unknown,
    chat_foreign,
    chat_invalid,
    chat_disabled,
    chat_encoded_mount,
    drive_anonymous,
    drive_unknown,
    drive_foreign,
    drive_invalid,
    drive_disabled,
    meet_anonymous,
    meet_unknown,
    meet_foreign,
    meet_invalid,
    meet_disabled,
    meet_unconfigured,
    meet_exact_anonymous,
    meet_exact_unknown,
    meet_exact_foreign,
    meet_exact_invalid
);

struct ChangeStatus(setjoin_gateway::catchall::CatchallRoute);
impl setjoin_gateway::Intercept for ChangeStatus {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        setjoin_gateway::Intercept::matches(&self.0, r)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = setjoin_gateway::Intercept::handle(&self.0, r, c);
        Box::pin(async move {
            let mut reply = future.await;
            *reply.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            reply
        })
    }
}
macro_rules! mutant_test {
    ($name:ident,$case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run_inner($case, true).await
        }
    };
}
mutant_test!(root_status_mutant, "root_unknown");
mutant_test!(api_status_mutant, "api_unknown");
mutant_test!(chat_status_mutant, "chat_unknown");
mutant_test!(drive_status_mutant, "drive_unknown");
mutant_test!(meet_status_mutant, "meet_unknown");
mutant_test!(meet_exact_status_mutant, "meet_exact_unknown");

case_test!(
    spa_root,
    spa_page,
    spa_directory,
    spa_missing_asset,
    spa_missing_other,
    spa_asset,
    spa_head,
    spa_json,
    spa_css,
    spa_model,
    spa_gzip,
    spa_brotli,
    spa_identity_preferred,
    spa_wildcard,
    spa_refused,
    spa_range,
    spa_suffix,
    spa_bad_range,
    spa_range_refused,
    spa_etag,
    spa_weak_etag,
    spa_since,
    spa_if_match,
    spa_post,
    spa_manifest,
    spa_direct_sidecar,
    spa_encoded_parent,
    spa_encoded_slash
);

case_test!(spa_setup, spa_setup_head);

case_test!(
    spa_extra_multipart,
    spa_extra_range_oversize,
    spa_extra_range_partial,
    spa_extra_range_invalid,
    spa_extra_if_range,
    spa_extra_unmodified,
    spa_extra_head_gzip,
    spa_extra_legacy_cache,
    spa_extra_admin_cache
);

case_test!(
    api_basic,
    api_empty_cookie,
    mux_legacy_basic,
    mux_connect_authority
);

case_test!(spa_xml);

case_test!(mux_legacy_absolute);

case_test!(mux_clean_reserved, mux_inner_encoded_slash);

/// Go writes the app_blocked row after its 403 (best effort): poll briefly for it.
async fn app_blocked_rows(owner: &tokio_postgres::Client, after: i64, user: i64) -> Result<Value, BoxError> {
    for _ in 0..50 {
        let rows = owner
            .query("SELECT jsonb_build_object('action',action,'target_type',target_type,'notes',notes)::text FROM admin_audit_log WHERE id>$1 AND user_id=$2 ORDER BY id", &[&after, &user])
            .await?;
        if !rows.is_empty() {
            let values = rows
                .iter()
                .map(|r| serde_json::from_str::<Value>(r.get::<_, &str>(0)))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Value::Array(values));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(json!([]))
}
#[tokio::test]
async fn chat_not_entitled() -> Result<(), BoxError> {
    run("chat_not_entitled").await
}
#[tokio::test]
async fn drive_not_entitled() -> Result<(), BoxError> {
    run("drive_not_entitled").await
}
#[tokio::test]
async fn meet_not_entitled() -> Result<(), BoxError> {
    run("meet_not_entitled").await
}
#[tokio::test]
async fn chat_not_entitled_read_fault() -> Result<(), BoxError> {
    run("chat_not_entitled_read_fault").await
}
#[tokio::test]
async fn chat_toggle_read_fault() -> Result<(), BoxError> {
    run("chat_toggle_read_fault").await
}
