//! Frozen-Go SSE recordings at the real front door; native replay has no Go upstream.
mod common;
mod jmap_sse_lifetime;
#[tokio::test]
async fn sse_periodic_authorization() -> Result<(), common::BoxError> {
    jmap_sse_lifetime::run().await
}
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{collections::BTreeMap, time::Duration};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn sse_initial_state() -> Result<(), BoxError> {
    run("initial-state").await
}

#[tokio::test]
async fn sse_cookie_same_origin() -> Result<(), BoxError> {
    run("cookie-same-origin").await
}
#[tokio::test]
async fn sse_cookie_matching_authority() -> Result<(), BoxError> {
    run("cookie-matching-authority").await
}

macro_rules! auth_tests { ($($name:ident=$case:literal;)*) => { $(#[tokio::test] async fn $name()->Result<(),BoxError>{run($case).await})* } }
auth_tests! {
 sse_auth_missing="auth-missing";
 sse_auth_query_only="auth-query-only";
 sse_auth_invalid="auth-invalid";
 sse_auth_refresh="auth-refresh";
 sse_auth_scoped="auth-scoped";
 sse_auth_no_iat="auth-no-iat";
 sse_auth_expired="auth-expired";
 sse_auth_foreign_cookie="auth-foreign-cookie";
 sse_auth_foreign_bearer="auth-foreign-bearer";
 sse_auth_quoted_cookie="auth-quoted-cookie";
 sse_auth_first_cookie="auth-first-cookie";
 sse_auth_bearer_precedence="auth-bearer-precedence";
 sse_auth_empty_bearer="auth-empty-bearer";
 sse_auth_lower_bearer="auth-lower-bearer";
 sse_auth_invalid_cookie_origin="auth-invalid-cookie-origin";
 sse_auth_no_mailbox="auth-no-mailbox";
}

#[tokio::test]
async fn sse_streamed_notifications() -> Result<(), BoxError> {
    run("streamed-notifications").await
}

auth_tests! {
 sse_params_email="params-email";
 sse_params_unknown="params-unknown";
 sse_params_comma="params-comma";
 sse_params_wildcard="params-wildcard";
 sse_params_duplicate="params-duplicate";
 sse_params_bad_escape="params-bad-escape";
 sse_params_semicolon="params-semicolon";
 sse_params_ping="params-ping";
 sse_params_unknown_live="params-unknown-live";
 sse_params_bad_ping="params-bad-ping";
 sse_params_negative_ping="params-negative-ping";
 sse_params_last_event_id="params-last-event-id";
 sse_cross_tenant="cross-tenant";
}

auth_tests! {
 sse_prod_empty_origin="prod-empty";
 sse_prod_pinned_origin="prod-pinned";
 sse_prod_foreign_origin="prod-foreign";
 sse_raw_json="raw-json";
}

auth_tests! {
 sse_guest_state="guest-state";
 sse_guest_topology="guest-topology";
 sse_guest_disabled="guest-disabled";
 sse_guest_expired="guest-expired";
 sse_guest_feature_off="guest-feature-off";
 sse_guest_without_claim="guest-without-claim";
 sse_guest_claim_only="guest-claim-only";
 sse_revoke_all="revoke-all";
 sse_revoke_jti="revoke-jti";
 sse_revoke_family="revoke-family";
 sse_revoked_handshake="revoked-handshake";
}

auth_tests! {
 sse_resource_presence="resource-presence";
 sse_resource_budget="resource-budget";
 sse_write_deadline="write-deadline";
 sse_head="head";
}

async fn run(case: &str) -> Result<(), BoxError> {
    run_inner(case, false).await
}
async fn run_inner(case: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case(case) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let foreign = fixture::account(&owner, "jmap5-foreign").await?;
    let account = if case.starts_with("guest-") && case != "guest-claim-only" {
        mailboxless(&owner).await?
    } else {
        fixture::account(&owner, "jmap5").await?
    };
    let saved_chat: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .get(0);
    let saved_guest: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    let result = async {
        if case.starts_with("resource-"){owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.chat'",&[]).await?;}
        if case.starts_with("guest-")&&case!="guest-claim-only" {
            let status=if case=="guest-disabled"{"disabled"}else{"active"};
            owner.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status,expires_at) VALUES($1,'guest@test','inviter@test',$2,$3,CASE WHEN $4 THEN now()-interval '1 hour' ELSE NULL END)",&[&account.user,&account.domain,&status,&(case=="guest-expired")]).await?;
    owner.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",&[&(case!="guest-feature-off")]).await?;
            for (app,enabled) in [("drive",true),("meet",true),("chat",false)] {owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,$2,$3) ON CONFLICT(user_id,app) DO UPDATE SET enabled=excluded.enabled",&[&account.user,&app,&enabled]).await?;}
        }
        if case=="revoked-handshake" {owner.execute("INSERT INTO session_revocations(user_id,scope,reason,not_before,expires_at) VALUES($1,'all','jmap5',now(),now()+interval '10 minutes')",&[&account.user]).await?;}
        if case=="cross-tenant" {owner.execute("UPDATE mailboxes SET jmap_email_state=999,jmap_mailbox_state=888,jmap_thread_state=777 WHERE id=$1",&[&foreign.mailbox]).await?;}
        let unused = common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let go_env=if case.starts_with("prod-"){vec![("HTTP_MODE","proxy".to_owned())]}else{vec![]};
        let oracle = common::go_oracle::start_named_with_env(&db,unused,"gofree-jmap5",&go_env).await?;
        let recording = oracle.is_some();
        let routes = if recording { RouteTable::proxy_all() } else {
            let commands = std::sync::Arc::new(setjoin_gateway::jmap::JmapCommands { services: None,
                exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn),4)?, worker:None,
                keys:common::recovery_keys(), issuer:"mailserver".into(), denylist:None,
            });
            let mut ws = setjoin_gateway::jmap::push::WebSocketRoute::new(commands,db.direct.clone());
            if case.starts_with("prod-"){ws.production=true;ws.allowed_host="mail.test".into();}
            let presence=setjoin_gateway::jmap::presence::PresenceRoute{commands:ws.commands.clone(),registry:ws.registry.clone()};
            let sse=setjoin_gateway::jmap::sse::EventSourceRoute::new(&ws);
            let table=if mutant{RouteTable::proxy_all().with(StatusMutant(std::sync::Arc::new(sse)))}else{RouteTable::proxy_all().with(sse)};
            table.with(ws).with(presence)
        };
        let inventory:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
        if !recording && !inventory["routes"].as_array().unwrap().iter().any(|r|r["path"]=="/jmap/eventsource"&&r["state"]=="ON"&&r["upstream"]=="local-rust"){return Err("bundled SSE route is not ON".into())}
        let gateway = Gateway::new(Config {
            upstream: oracle.as_ref().map(|o| format!("http://{}",o.address).parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(30), edge_limit: None,
        }, routes)?.with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let observation = async {
            let before_presence=if case=="resource-presence"{Some(jmap_sse_lifetime::resources::presence(address,account.user).await?)}else{None};
            let before=rows(&owner,&account,&foreign).await?;
            let extra=match case {
                c if c.starts_with("guest-")&&c!="guest-without-claim"=>json!({"acct":"guest"}),
                "auth-refresh"=>json!({"typ":"refresh"}),"auth-scoped"=>json!({"scp":"drive"}),
                "auth-no-iat"=>json!({"iat":null}),"auth-expired"=>json!({"exp":1}),_=>json!({}),
            };
            let token=common::recovery_token_with(if case=="auth-no-mailbox" {i64::MAX} else {account.user},extra);
            let query=match case {
                "streamed-notifications"|"raw-json"|"resource-presence"|"resource-budget"=>"closeafter=no".into(),
                "write-deadline"=>"ping=1".into(),
                "auth-query-only"=>format!("closeafter=state&access_token={token}"),
                "params-email"=>"closeafter=state&types=Email".into(),
                "params-unknown"=>"closeafter=state&types=Unknown".into(),
                "params-comma"=>"closeafter=state&types=,,".into(),
                "params-wildcard"=>"closeafter=state&types=%20*%20".into(),
                "params-duplicate"=>"closeafter=state&types=Email&types=Task".into(),
                "params-bad-escape"=>"closeafter=state&types=%ZZ&types=Email".into(),
                "params-semicolon"=>"closeafter=state&types=Task;ignored=x&types=Email".into(),
                "params-ping"|"guest-topology"=>"ping=1".into(),
                c if c.starts_with("revoke-")=>"closeafter=no".into(),
                "params-unknown-live"=>"types=Unknown&ping=1".into(),
                "params-bad-ping"=>"closeafter=state&ping=not-an-integer".into(),
                "params-negative-ping"=>"closeafter=no&ping=-1".into(),
                "cross-tenant"=>format!("closeafter=state&accountId={}&user_id={}&mailbox_id={}",foreign.mailbox,foreign.user,foreign.mailbox),
                _=>"closeafter=state".into(),
            };
            let mut request = Request::builder().method(if case=="head"{"HEAD"}else{"GET"}).uri(format!("http://{address}/jmap/eventsource?{query}"));
            match case {
                "auth-missing"|"auth-query-only"=>{},
                "prod-empty"|"prod-pinned"|"prod-foreign"=>{request=request.header("cookie",format!("access_token={token}"));if case!="prod-empty"{request=request.header("origin",if case=="prod-pinned"{"https://mail.test"}else{"https://foreign.test"});}},
                "auth-invalid"=>{request=request.header("authorization","Bearer invalid");},
                // The legacy recording predates Host preservation from absolute
                // request authority: Go saw the upstream host and rejected it.
                // Replay that mismatched pair explicitly, retaining its golden.
                "cookie-same-origin"=>{request=request.header("host","legacy-upstream.test").header("cookie",format!("access_token={token}")).header("origin",format!("http://{address}"));},
                "cookie-matching-authority"=>{request=request.header("host","mail.test").header("cookie",format!("access_token={token}")).header("origin","http://mail.test");},
                "auth-quoted-cookie"=>{request=request.header("cookie",format!("access_token=\"{token}\""));},
                "auth-first-cookie"=>{request=request.header("cookie",format!("access_token=bad; access_token={token}"));},
                "auth-foreign-cookie"|"auth-invalid-cookie-origin"=>{request=request.header("cookie",format!("access_token={}",if case=="auth-foreign-cookie"{token.as_str()}else{"bad"})).header("origin","https://foreign.test");},
                "auth-bearer-precedence"=>{request=request.header("authorization",format!("Bearer {token}")).header("cookie","access_token=bad");},
                "auth-empty-bearer"=>{request=request.header("authorization","Bearer ").header("cookie",format!("access_token={token}"));},
                "auth-lower-bearer"=>{request=request.header("authorization","bearer bad").header("cookie",format!("access_token={token}"));},
                _=>{request=request.header("authorization",format!("Bearer {token}"));},
            }
            if case=="params-last-event-id" {request=request.header("last-event-id","999999");}
            if case=="auth-foreign-bearer" {request=request.header("origin","https://foreign.test");}
            let request=request.body(common::full(""))?;
            let response = common::send(address,request).await;
            let status = response.status().as_u16();
            let headers:BTreeMap<_,_> = response.headers().iter()
                .filter(|(k,_)|!matches!(k.as_str(),"date"|"content-length"|"x-request-id"|"connection"|"transfer-encoding"))
                .map(|(k,v)|(k.to_string(),v.to_str().unwrap().to_owned())).collect();
            let mut terminal=Value::Null; let mut resources=Value::Null;
            let mut body=if case.starts_with("resource-") {
                let observed=jmap_sse_lifetime::resources::observe(case,address,&account,response,before_presence).await?;
                resources=observed.1; observed.0
            } else if case=="write-deadline" {
                let mut stream=Frames {body:response.into_body(),buffer:Vec::new()};let mut frames=stream.next().await?;frames+=&stream.next().await?;
                if !recording {tokio::time::pause();tokio::time::advance(Duration::from_secs(121)).await;tokio::time::resume();}
                terminal=json!(stream.terminal_kind(if recording{Duration::from_secs(130)}else{Duration::from_secs(5)}).await?);frames
            } else if case.starts_with("revoke-") {
                let mut stream=Frames {body:response.into_body(),buffer:Vec::new()};
                let mut frames=stream.next().await?;
                for payload in ["malformed".to_owned(),json!({"user_id":foreign.user,"scope":"jti","jti":"blobs1-test"}).to_string(),json!({"user_id":account.user,"scope":"jti","jti":"other"}).to_string(),json!({"user_id":account.user,"scope":"all","not_before":"bad"}).to_string()] {owner.query("SELECT pg_notify('session_revoke',$1)",&[&payload]).await?;}
                owner.query("SELECT pg_notify($1,$2)",&[&format!("chat:{}",account.user),&r#"{"marker":"not-revoked"}"#]).await?;
                frames+=&stream.next().await?;
                let scope=&case[7..];
                let jti=(scope=="jti").then_some("blobs1-test");let family=(scope=="family").then_some("blobs1-test");
                owner.execute("INSERT INTO session_revocations(user_id,scope,reason,jti,family_id,not_before,expires_at) VALUES($1,$2,'jmap5',$3,$4,now(),now()+interval '10 minutes')",&[&account.user,&scope,&jti,&family]).await?;
                let before:String=owner.query_one("SELECT to_jsonb(now())::text",&[]).await?.get(0);
                let payload=json!({"user_id":account.user,"scope":scope,"jti":"blobs1-test","family_id":"blobs1-test","not_before":serde_json::from_str::<String>(&before)?}).to_string();
                owner.query("SELECT pg_notify('session_revoke',$1)",&[&payload]).await?;
                stream.ended(Duration::from_secs(10)).await?;
                terminal=json!(true);frames
            } else if case=="guest-topology" {
                let mut stream=Frames {body:response.into_body(),buffer:Vec::new()};
                let mut frames=stream.next().await?;
                for prefix in ["chat","tag","calendar","contact","task"] {owner.query("SELECT pg_notify($1,$2)",&[&format!("{prefix}:{}",if prefix=="chat"{account.user}else{0}),&r#"{"secret":"denied"}"#]).await?;}
                for prefix in ["drive-watch","meet"] {owner.query("SELECT pg_notify($1,$2)",&[&format!("{prefix}:{}",account.user),&r#"{"marker":"guest"}"#]).await?;frames+=&stream.next().await?;}
                frames
            } else if ["params-ping","params-unknown-live","params-negative-ping"].contains(&case) {
                let mut stream=Frames {body:response.into_body(),buffer:Vec::new()};
                let mut frames=stream.next().await?;
                if case=="params-ping" {frames+=&stream.next().await?;}
                else {
                    if case=="params-negative-ping" {tokio::time::sleep(Duration::from_millis(1100)).await;}
                    owner.query("SELECT pg_notify($1,$2)",&[&format!("chat:{}",account.user),&r#"{"marker":"alive"}"#]).await?;
                    frames+=&stream.next().await?;
                }
                frames
            } else if case=="raw-json" {
                let mut stream=Frames {body:response.into_body(),buffer:Vec::new()};
                let mut frames=stream.next().await?;
                for payload in ["null","[1,true]"," {\n  \"marker\": \"<>&雪\"\n}","1e999"] {
                    owner.query("SELECT pg_notify($1,$2)",&[&format!("chat:{}",account.user),&payload]).await?;
                    frames+=&stream.next().await?;
                }
                frames
            } else if case=="streamed-notifications" {
                let mut stream=Frames {body:response.into_body(),buffer:Vec::new()};
                let mut frames=stream.next().await?;
                for channel in ["tag","calendar","contact","task","chat","meet","drive-watch"] {
                    owner.query("SELECT pg_notify($1,$2)",&[&format!("{channel}:{}",if ["tag","calendar","contact","task"].contains(&channel){foreign.mailbox}else{foreign.user}),&r#"{"secret":"foreign"}"#]).await?;
                }
                let own=format!("tag:{}",account.mailbox);
                for payload in ["broken",r#"{"type":"offline.wipe","why":"SSE Go drops controls"}"#,r#"{"state":999999}"#] {owner.query("SELECT pg_notify($1,$2)",&[&own,&payload]).await?;}
                frames+=&stream.next().await?;
                owner.batch_execute("BEGIN").await?;
                for (prefix,payload) in [("calendar",r#"{"event":"rsvp","event_id":9}"#),("contact",r#"{"contact_id":null}"#),("task",r#"{"task_id":null}"#)] {
                    owner.query("SELECT pg_notify($1,$2)",&[&format!("{prefix}:{}",account.mailbox),&payload]).await?;
                }
                owner.batch_execute("COMMIT").await?;
                frames+=&stream.next().await?;
                for prefix in ["chat","meet","drive-watch"] {
                    owner.query("SELECT pg_notify($1,$2)",&[&format!("{prefix}:{}",account.user),&"not json"]).await?;
                    owner.query("SELECT pg_notify($1,$2)",&[&format!("{prefix}:{}",account.user),&" { \"marker\" : \"own\" } "]).await?;
                    frames+=&stream.next().await?;
                }
                frames
            } else {
                let bytes=tokio::time::timeout(Duration::from_secs(10),response.into_body().collect()).await??.to_bytes();
                String::from_utf8(bytes.to_vec())?
            };
            body=body.replace(&format!("\"{}\"",account.mailbox),"\"<mailbox>\"");
            if rows(&owner,&account,&foreign).await?!=before {return Err("SSE changed persisted mailbox/user/message/tag/journal/audit/receipt rows".into())}
            common::problem_bytes::check_if_problem(headers.get("content-type").map(String::as_str),body.as_bytes());
            if !recording {
                let response=common::send(address,Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
                let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;
                if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n"){return Err(format!("native SSE used Go: {metrics}").into())}
            }
            let mut observation=json!({"request":{"method":"GET","path":"/jmap/eventsource"},"response":{"status":status,"headers":headers,"body":body},"effects":{},"audit":[],"notify":[]});
            if !terminal.is_null(){observation["response"]["closed"]=terminal;}
            if !resources.is_null(){observation["response"]["resources"]=resources;}
            if case=="head"{observation["request"]["actual_method"]=json!("HEAD");}
            Ok::<Value,BoxError>(observation)
        }.await;
        server.abort(); let _ = server.await;
        let observation = observation?;
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/jmap/sse/{case}.json"));
        if recording {
            golden::record(&path,&json!({"format":1,"route":"GET /jmap/eventsource","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture mailbox id"],"observation":observation}))?;
        } else {
            let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;
            if mutant {
                match golden::compare(&expected["observation"],&observation) {
                    Err(error) if error.contains("/response/status")&&observation["response"]["status"]==418=>println!("MUTANT-REJECTED: GET /jmap/eventsource :: status"),
                    Err(error)=>return Err(format!("mutant failed for wrong reason: {error}").into()),
                    Ok(())=>return Err("SSE status mutant survived".into()),
                }
            }else{golden::compare(&expected["observation"],&observation)?;println!("GOLDEN-REPLAY: GET /jmap/eventsource :: {case}");}
        }
        Ok::<_,BoxError>(())
    }.await;
    owner
        .execute(
            "DELETE FROM session_revocations WHERE user_id=$1",
            &[&account.user],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
            &[&saved_guest],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&saved_chat],
        )
        .await?;
    fixture::remove(&owner, &account).await?;
    fixture::remove(&owner, &foreign).await?;
    result
}

struct Frames {
    body: hyper::body::Incoming,
    buffer: Vec<u8>,
}
impl Frames {
    async fn ended(&mut self, duration: Duration) -> Result<(), BoxError> {
        let kind = self.terminal_kind(duration).await?;
        if kind != "clean" {
            return Err(format!("expected clean close, got {kind}").into());
        }
        Ok(())
    }
    async fn terminal_kind(&mut self, duration: Duration) -> Result<String, BoxError> {
        tokio::time::timeout(duration, async {
            loop {
                if let Some(end) = self.buffer.windows(2).position(|b| b == b"\n\n") {
                    let frame = String::from_utf8(self.buffer.drain(..end + 2).collect())?;
                    if !frame.starts_with("event: ping\n") {
                        return Err(format!("unexpected frame before close: {frame}").into());
                    }
                } else {
                    match self.body.frame().await {
                        None if self.buffer.is_empty() => {
                            return Ok::<_, BoxError>("clean".to_owned())
                        }
                        None => return Err("partial SSE event at close".into()),
                        Some(Err(error)) => {
                            let mut cause: Option<&(dyn std::error::Error + 'static)> =
                                Some(&error);
                            let mut truncated = error.is_incomplete_message();
                            while let Some(err) = cause {
                                truncated |= err
                                    .downcast_ref::<std::io::Error>()
                                    .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof);
                                cause = err.source();
                            }
                            if truncated && self.buffer.is_empty() {
                                return Ok("abrupt".to_owned());
                            }
                            return Err(error.into());
                        }
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                self.buffer.extend_from_slice(&data)
                            }
                        }
                    }
                }
            }
        })
        .await?
    }
    async fn next(&mut self) -> Result<String, BoxError> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|b| b == b"\n\n") {
                return Ok(String::from_utf8(self.buffer.drain(..end + 2).collect())?);
            }
            let frame = tokio::time::timeout(Duration::from_secs(15), self.body.frame())
                .await?
                .ok_or("SSE stream ended before expected frame")??;
            if let Ok(data) = frame.into_data() {
                self.buffer.extend_from_slice(&data);
            }
        }
    }
}

async fn rows(
    owner: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    for (table, predicate, order) in [
        ("users", "id=ANY($1)", "id"),
        ("mailboxes", "user_id=ANY($1)", "id"),
        ("messages", "mailbox_id=ANY($1)", "id,received_at"),
        ("tags", "mailbox_id=ANY($1)", "id"),
        (
            "jmap_changes_journal",
            "mailbox_id=ANY($1)",
            "mailbox_id,datatype,state_seq,entity_id",
        ),
        ("mailbox_audit_log", "mailbox_id=ANY($1)", "id"),
    ] {
        let ids = if ["users", "mailboxes"].contains(&table) {
            vec![a.user, b.user]
        } else {
            vec![a.mailbox, b.mailbox]
        };
        let sql =
            format!("SELECT to_jsonb(r)::text FROM {table} r WHERE {predicate} ORDER BY {order}");
        let values: Vec<Value> = owner
            .query(&sql, &[&ids])
            .await?
            .iter()
            .map(|r| serde_json::from_str(r.get::<_, &str>(0)))
            .collect::<Result<_, _>>()?;
        out.insert(table.into(), json!(values));
    }
    let receipts:Vec<String>=owner.query("SELECT to_jsonb(r)::text FROM rust_operation_receipts r WHERE family='jmap' ORDER BY operation_id",&[]).await?.iter().map(|r|r.get(0)).collect();
    out.insert("receipts".into(), json!(receipts));
    Ok(out.into())
}

async fn mailboxless(owner: &tokio_postgres::Client) -> Result<fixture::Account, BoxError> {
    let domain:i64=owner.query_one("INSERT INTO domains(name,is_local) VALUES('guest-'||gen_random_uuid()::text||'.test',false) RETURNING id",&[]).await?.get(0);
    let user:i64=owner.query_one("INSERT INTO users(username,domain_id,email,display_name,password_hash) SELECT 'jmap5@'||name,id,'jmap5@'||name,'JMAP5 Guest','x' FROM domains WHERE id=$1 RETURNING id",&[&domain]).await?.get(0);
    Ok(fixture::Account {
        domain,
        user,
        mailbox: 0,
        inbox: 0,
        label: 0,
        two_labels: 0,
        inbox_only: 0,
    })
}

#[tokio::test]
async fn sse_public_registry_evicts_targets_and_releases_budget() -> Result<(), BoxError> {
    jmap_sse_lifetime::registry::eviction().await
}
#[tokio::test]
async fn sse_legacy_profile_shape_is_verified_natively() -> Result<(), BoxError> {
    jmap_sse_lifetime::registry::legacy().await
}

#[tokio::test]
async fn sse_executable_serves_without_go() -> Result<(), BoxError> {
    jmap_sse_lifetime::registry::executable().await
}
#[tokio::test]
async fn sse_status_mutant_is_rejected() -> Result<(), BoxError> {
    run_inner("initial-state", true).await
}
struct StatusMutant(std::sync::Arc<dyn setjoin_gateway::Intercept>);
impl setjoin_gateway::Intercept for StatusMutant {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn shutdown(&self) {
        self.0.shutdown();
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let response = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = response.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}
