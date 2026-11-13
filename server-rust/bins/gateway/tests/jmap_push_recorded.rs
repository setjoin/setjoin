//! Frozen-Go live push sessions replayed through the public front door.
mod common;
#[path = "jmap_push_lifetime/mod.rs"]
mod lifetime;
#[path = "jmap_push_lifetime/registry.rs"]
mod registry_tests;
use common::BoxError;
use futures_util::{SinkExt, StreamExt};
use hyper::Response;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::jmap::{push::WebSocketRoute, JmapCommands};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{sync::Arc, time::Duration};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

macro_rules! lifetime_cases { ($($name:ident=$case:literal;)*)=>{$(
    #[tokio::test] async fn $name()->Result<(),BoxError> {lifetime::run($case).await}
)*} }
lifetime_cases! {
    security_revocation_jti="revoke-jti";
    security_revocation_family="revoke-family";
    security_revocation_all="revoke-all";
    security_device_revoked="device";
    security_guest_subscription_belts="guest-topology";
    security_guest_without_mailbox="guest-no-mailbox";
    security_production_empty_origin="prod-empty";
    security_production_pinned_origin="prod-pin";
    security_invalid_handshake_key="bad-key";
    security_connection_limit="limit";
    security_message_limit="size";
    security_keepalive_ping="ping";
    security_idle_timeout="idle";
    security_token_expiry="expiry";
}

#[tokio::test]
async fn websocket_controls() -> Result<(), BoxError> {
    run("controls").await
}

#[tokio::test]
async fn websocket_user_notifications() -> Result<(), BoxError> {
    run("user-notifications").await
}

#[tokio::test]
async fn websocket_state_batches() -> Result<(), BoxError> {
    run("state-batches").await
}

#[tokio::test]
async fn websocket_request_envelopes() -> Result<(), BoxError> {
    run("requests").await
}

#[tokio::test]
async fn websocket_reference_formats() -> Result<(), BoxError> {
    run("reference-formats").await
}

#[tokio::test]
async fn websocket_native_email_batch() -> Result<(), BoxError> {
    run("native-email").await
}

#[tokio::test]
async fn websocket_repeated_write_effects() -> Result<(), BoxError> {
    run("write-repeat-v2").await
}

async fn snapshot(c: &tokio_postgres::Client, a: &fixture::Account) -> Result<Value, BoxError> {
    let s = fixture::snapshot(c, a.mailbox).await?;
    let mut tags = serde_json::Map::new();
    let mut names = std::collections::BTreeMap::new();
    for row in c
        .query(
            "SELECT id,name FROM tags WHERE mailbox_id=$1",
            &[&a.mailbox],
        )
        .await?
    {
        let id: i64 = row.get(0);
        let name: String = row.get(1);
        names.insert(id, name.clone());
        let (unread, state) = s.tags[&id];
        tags.insert(name, json!({"unread":unread,"state":state}));
    }
    let name = |id: i64| {
        if id == a.two_labels {
            "<two-labels>".to_owned()
        } else if id == a.inbox_only {
            "<inbox-only>".into()
        } else {
            names.get(&id).cloned().unwrap_or_else(|| id.to_string())
        }
    };
    let mut messages: Vec<Value> = s
        .is_read
        .iter()
        .map(|(id, read)| json!({"id":name(*id),"is_read":read}))
        .collect();
    messages.sort_by_key(|m| m["id"].as_str().unwrap().to_owned());
    let journal:Vec<Value>=s.journal.iter().map(|j|json!({"datatype":j.datatype,"state_seq":j.state_seq,"entity_id":name(j.entity_id),"op":j.op})).collect();
    Ok(json!({"messages":messages,"tags":tags,"email_state":s.email_state,"journal":journal}))
}

async fn audits(c: &tokio_postgres::Client, a: &fixture::Account) -> Result<Value, BoxError> {
    let mut out = Vec::new();
    for row in c
        .query(
            "SELECT to_jsonb(a)::text FROM mailbox_audit_log a WHERE mailbox_id=$1 ORDER BY id",
            &[&a.mailbox],
        )
        .await?
    {
        let mut value: Value = serde_json::from_str(row.get::<_, &str>(0))?;
        assert_eq!(value["mailbox_id"], a.mailbox);
        assert_eq!(value["actor_user_id"], a.user);
        value["id"] = json!("<audit-id>");
        value["occurred_at"] = json!("<timestamp>");
        value["mailbox_id"] = json!("<mailbox>");
        value["actor_user_id"] = json!("<user>");
        if let Some(op) = value.pointer_mut("/details/operation") {
            let text = op.as_str().ok_or("operation must be text")?;
            if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid operation receipt".into());
            }
            *op = json!("<operation-id>");
        }
        out.push(value);
    }
    Ok(json!(out))
}

#[tokio::test]
async fn presence_tracks_multiple_connections() -> Result<(), BoxError> {
    run("presence-connections").await
}

macro_rules! auth_cases { ($($name:ident = $case:literal;)*) => { $(
    #[tokio::test] async fn $name() -> Result<(),BoxError> { run($case).await }
)* } }
auth_cases! {
    handshake_invalid_cookie = "auth-invalid-cookie";
    handshake_bearer_is_not_cookie = "auth-bearer-only";
    handshake_query_is_not_cookie = "auth-query-only";
    handshake_refresh_denied = "auth-refresh";
    handshake_scoped_denied = "auth-scoped";
    handshake_missing_iat_denied = "auth-no-iat";
    handshake_expired_denied = "auth-expired";
    handshake_foreign_origin_denied = "auth-origin";
    handshake_invalid_version = "auth-version";
    handshake_active_guest = "auth-guest";
    handshake_inactive_guest = "auth-guest-inactive";
    presence_app_denial = "presence-app-denied";
    presence_invalid_ids = "presence-invalid";
    presence_raw_id_keys = "presence-keys";
    presence_bad_query_escape = "presence-bad-query";
    presence_bad_query_semicolon = "presence-semicolon";
    presence_guest_denies_nonmember = "presence-guest-denied";
    presence_guest_sees_comember = "presence-guest-comember";
}

async fn presence_observation(
    address: std::net::SocketAddr,
    account: &fixture::Account,
    foreign: &fixture::Account,
    case: &str,
) -> Result<Value, BoxError> {
    let query = match case {
        "presence-invalid" => "userIds=broken".into(),
        "presence-bad-query" => "userIds=%ZZ".into(),
        "presence-semicolon" => "userIds=1;ignored=2".into(),
        "presence-keys" => format!(
            "userIds={},000{},%2B{},0",
            account.user, account.user, account.user
        ),
        _ => format!(
            "userIds={},{},9223372036854775807",
            account.user, foreign.user
        ),
    };
    let extra = if case.starts_with("presence-guest") {
        json!({"acct":"guest"})
    } else {
        json!({})
    };
    let response = common::send(
        address,
        hyper::Request::builder()
            .uri(format!("http://{address}/api/chat/presence?{query}"))
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    common::recovery_token_with(account.user, extra)
                ),
            )
            .body(common::full(""))
            .unwrap(),
    )
    .await;
    let status = response.status().as_u16();
    let headers: std::collections::BTreeMap<_, _> = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "x-request-id" | "connection"
            )
        })
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
        .collect();
    let mut body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    if status == 200 {
        let mut value: Value = serde_json::from_str(&body)?;
        if body != value.to_string() + "\n" {
            return Err("presence map is not Go's sorted encoding".into());
        }
        let map = value.as_object_mut().ok_or("presence map")?;
        for (key, name) in [
            (format!("000{}", account.user), "<padded>"),
            (format!("+{}", account.user), "<signed>"),
            (account.user.to_string(), "<self>"),
            (foreign.user.to_string(), "<foreign>"),
        ] {
            if let Some(v) = map.remove(&key) {
                map.insert(name.to_owned(), v);
            }
        }
        body = value.to_string() + "\n";
    }
    Ok(
        json!({"request":{"method":"GET","path":"/chat/presence"},"response":{"status":status,"headers":headers,"body":body},"effects":{},"audit":[],"notify":[]}),
    )
}

async fn mailboxless_fixture(owner: &tokio_postgres::Client) -> Result<fixture::Account, BoxError> {
    let domain:i64=owner.query_one("INSERT INTO domains(name,is_local) VALUES('guest-'||gen_random_uuid()::text||'.test',false) RETURNING id",&[]).await?.get(0);
    let user:i64=owner.query_one("INSERT INTO users(username,domain_id,email,display_name,password_hash) SELECT 'jmap4@'||name,id,'jmap4@'||name,'JMAP4 Guest','x' FROM domains WHERE id=$1 RETURNING id",&[&domain]).await?.get(0);
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

async fn presence(address: std::net::SocketAddr, user: i64) -> Result<bool, BoxError> {
    let response = common::send(
        address,
        hyper::Request::builder()
            .uri(format!("http://{address}/api/chat/presence?userIds={user}"))
            .header(
                "authorization",
                format!("Bearer {}", common::recovery_token(user)),
            )
            .body(common::full(""))
            .unwrap(),
    )
    .await;
    let status = response.status();
    let bytes = common::body_bytes(response).await;
    if status != 200 {
        return Err(format!("presence {status}: {}", String::from_utf8_lossy(&bytes)).into());
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    value[&user.to_string()]
        .as_bool()
        .ok_or("missing presence key".into())
}

async fn run(case: &str) -> Result<(), BoxError> {
    run_with_mutant(case, false).await
}

struct StatusMutant<T>(T);
impl<T: setjoin_gateway::Intercept> setjoin_gateway::Intercept for StatusMutant<T> {
    fn matches(&self, r: &hyper::Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn shutdown(&self) {
        self.0.shutdown()
    }
    fn handle(
        &self,
        r: hyper::Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let pending = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = pending.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}
#[tokio::test]
async fn websocket_rejects_status_mutant() -> Result<(), BoxError> {
    let error = run_with_mutant("controls", true)
        .await
        .expect_err("socket oracle must reject status mutation");
    assert!(error.to_string().contains("418"), "{error}");
    println!("MUTANT-REJECTED: GET /jmap/ws :: changed-status");
    Ok(())
}
#[tokio::test]
async fn presence_rejects_status_mutant() -> Result<(), BoxError> {
    let error = run_with_mutant("presence-connections", true)
        .await
        .expect_err("presence oracle must reject status mutation");
    assert!(error.to_string().contains("presence 418"), "{error}");
    println!("MUTANT-REJECTED: GET /chat/presence :: changed-status");
    Ok(())
}

async fn run_with_mutant(case: &str, mutant: bool) -> Result<(), BoxError> {
    let _lock = SERIAL.lock().await;
    let Some(db) = Db::for_case(case) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = if case.starts_with("presence-guest") {
        mailboxless_fixture(&owner).await?
    } else {
        fixture::account(&owner, "jmap4").await?
    };
    let foreign = fixture::account(&owner, "jmap4-foreign").await?;
    if case == "state-batches" {
        owner.execute("UPDATE mailboxes SET jmap_email_state=11,jmap_mailbox_state=12,jmap_thread_state=13 WHERE id=$1",&[&account.mailbox]).await?;
    }
    let guest = case.starts_with("presence-guest") || case.starts_with("auth-guest");
    if guest {
        let status = if case == "auth-guest-inactive" {
            "disabled"
        } else {
            "active"
        };
        owner.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,'guest@test','inviter@test',$2,$3)",&[&account.user,&account.domain,&status]).await?;
    }
    let old_guests: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    if case.starts_with("presence-guest") || case == "auth-guest-inactive" {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",
                &[],
            )
            .await?;
        owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'chat',true) ON CONFLICT(user_id,app) DO UPDATE SET enabled=true",&[&account.user]).await?;
    }
    let channel = if case == "presence-guest-comember" {
        let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,created_by,visibility) VALUES('channel','jmap4-presence',$1,'private') RETURNING id",&[&foreign.user]).await?.get(0);
        owner
            .execute(
                "INSERT INTO chat_channel_members(channel_id,user_id) VALUES($1,$2),($1,$3)",
                &[&channel, &account.user, &foreign.user],
            )
            .await?;
        Some(channel)
    } else {
        None
    };
    let old_chat: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.chat'",
            &[],
        )
        .await?;
    let audit_level: Option<String> = if case == "presence-app-denied" {
        Some(
            owner
                .query_one("SELECT level FROM audit_policy WHERE id=1", &[])
                .await?
                .get(0),
        )
    } else {
        None
    };
    let result = async {
        if case=="presence-app-denied" {
            owner.execute("UPDATE audit_policy SET level='full' WHERE id=1",&[]).await?;
            owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'chat',false) ON CONFLICT(user_id,app) DO UPDATE SET enabled=false",&[&account.user]).await?;
        }
        let unused = common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let oracle = common::go_oracle::start_named(&db, unused, None, "gofree-jmap4").await?;
        let recording = oracle.is_some();
        if recording && mutant{return Err("cannot record mutant".into())}
        let routes = if recording { RouteTable::proxy_all() } else {
            let commands = Arc::new(JmapCommands { services: None, worker: None,
                exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?,
                keys: common::recovery_keys(), issuer: "mailserver".into(), denylist: None,
            });
            let ws = WebSocketRoute::new(commands.clone(), db.direct.clone());
            let registry = ws.registry.clone();
            let presence=setjoin_gateway::jmap::presence::PresenceRoute { commands, registry };
            if mutant && case=="controls" {RouteTable::proxy_all().with(StatusMutant(ws)).with(presence)}
            else if mutant {RouteTable::proxy_all().with(ws).with(StatusMutant(presence))}
            else{RouteTable::proxy_all().with(ws).with(presence)}
        };
        let inventory: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
        if !recording {
            for route in inventory["routes"].as_array().unwrap() {
                if matches!(route["path"].as_str(),Some("/jmap/ws"|"/chat/presence")) && (route["state"]!="ON" || route["upstream"]!="local-rust") {return Err("bundled push/presence route is not ON".into())}
            }
        }
        let gateway = Gateway::new(Config {
            upstream: oracle.as_ref().map(|o| format!("http://{}",o.address).parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(30), edge_limit: None,
        }, routes)?.with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let observation = async {
            let before=if case.starts_with("write-repeat") {Some((snapshot(&owner,&account).await?,snapshot(&owner,&foreign).await?))} else {None};
            let mut effects=json!({});let mut audit=json!([]);let mut notify=json!([]);
            let mut listener=if case.starts_with("write-repeat") {Some(db.listen(&format!("tag:{}",account.mailbox)).await?)} else {None};
            let ws_user=if case.starts_with("presence-guest") {foreign.user} else {account.user};
            let mut frames = if case == "presence-connections" { vec![presence(address,account.user).await?.to_string()] } else { Vec::new() };
            let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
            let extra = match case {
                "auth-refresh" => json!({"typ":"refresh"}), "auth-scoped" => json!({"scp":"drive"}),
                "auth-no-iat" => json!({"iat":null}), "auth-expired" => json!({"exp":1}),
                "auth-guest" => json!({"acct":"guest"}), _ => json!({}),
            };
            let token = common::recovery_token_with(ws_user,extra);
            match case {
                "auth-bearer-only" => { request.headers_mut().insert("authorization",format!("Bearer {token}").parse()?); }
                "auth-query-only" => { *request.uri_mut()=format!("ws://{address}/jmap/ws?access_token={token}").parse()?; }
                "auth-invalid-cookie" => { request.headers_mut().insert("cookie","access_token=%%%bad".parse()?); }
                _ => { request.headers_mut().insert("cookie",format!("access_token={token}").parse()?); }
            }
            if case == "auth-origin" { request.headers_mut().insert("origin","https://evil.test".parse()?); }
            if case == "auth-version" { request.headers_mut().insert("sec-websocket-version","12".parse()?); }
            let (mut socket, response) = match tokio_tungstenite::connect_async(request).await {
                Ok(pair) => pair,
                Err(tokio_tungstenite::tungstenite::Error::Http(response)) if case.starts_with("auth-") => {
                    common::problem_bytes::check_if_problem(response.headers().get("content-type").and_then(|v|v.to_str().ok()),response.body().as_deref().unwrap_or_default());
                    let headers: std::collections::BTreeMap<_,_> = response.headers().iter().filter(|(k,_)| !matches!(k.as_str(),"date"|"content-length"|"x-request-id"|"connection")).map(|(k,v)|(k.as_str().to_owned(),v.to_str().unwrap().to_owned())).collect();
                    return Ok::<Value,BoxError>(json!({"request":{"method":"GET","path":"/jmap/ws"},"response":{"status":response.status().as_u16(),"headers":headers,"body":String::from_utf8(response.body().clone().unwrap_or_default())?},"effects":{},"audit":[],"notify":[]}));
                }
                Err(error) => return Err(error.into()),
            };
            let controls = if case == "controls" {
                vec![r#"{"@type":"WebSocketPushEnable"}"#, r#"{"@type":"WebSocketPushDisable"}"#, r#"{"@type":"invented"}"#]
            } else { vec![r#"{"@type":"ready"}"#] };
            for text in controls {
                socket.send(Message::Text(text.into())).await?;
                if text.contains("Enable") { continue }
                let message = tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("socket ended")??;
                if case != "presence-connections" { frames.push(message.into_text()?.to_string()); }
            }
            if case.starts_with("presence-")&&case!="presence-connections" {
                let mut observed=presence_observation(address,&account,&foreign,case).await?;
                if case=="presence-app-denied" {
                    let second=presence_observation(address,&account,&foreign,case).await?;
                    observed["response"]["repeat"]=second["response"].clone();
                    let mut rows=Vec::new();
                    for row in owner.query("SELECT to_jsonb(a)::text, checksum=public.audit_row_hash(id,occurred_at,user_id,ip,action,target_type,target_id,before_state,after_state,notes,(SELECT checksum FROM admin_audit_log p WHERE p.id<a.id ORDER BY p.id DESC LIMIT 1)) FROM admin_audit_log a WHERE user_id=$1 ORDER BY id",&[&account.user]).await? {
                        if !row.get::<_,bool>(1){return Err("invalid denial audit checksum".into())}
                        let mut value:Value=serde_json::from_str(row.get::<_,&str>(0))?;
                        if value["id"].as_i64().is_none_or(|n|n<=0){return Err("invalid denial audit id".into())}
                        value["id"]=json!("<audit>");value["occurred_at"]=json!("<timestamp>");value["user_id"]=json!("<self>");value["checksum"]=json!("<verified-checksum>");rows.push(value);
                    }
                    if rows.len()!=2{return Err(format!("expected one audit per denial, got {}",rows.len()).into())}
                    observed["audit"]=json!(rows);
                    observed["effects"]=json!({"own":snapshot(&owner,&account).await?,"foreign":snapshot(&owner,&foreign).await?});
                }
                socket.close(None).await?;
                return Ok(observed)
            }
            if case == "presence-connections" {
                let mut second = format!("ws://{address}/jmap/ws").into_client_request()?;
                second.headers_mut().insert("cookie",format!("access_token={}",common::recovery_token(account.user)).parse()?);
                let (mut second,_) = tokio_tungstenite::connect_async(second).await?;
                second.send(Message::Text(r#"{"@type":"ready"}"#.into())).await?;
                tokio::time::timeout(Duration::from_secs(10),second.next()).await?.ok_or("second socket ended")??;
                frames.push(presence(address,account.user).await?.to_string());
                socket.close(None).await?;
                let _ = tokio::time::timeout(Duration::from_secs(10),socket.next()).await?;
                frames.push(presence(address,account.user).await?.to_string());
                second.close(None).await?;
                let _ = tokio::time::timeout(Duration::from_secs(10),second.next()).await?;
                let deadline = tokio::time::Instant::now()+Duration::from_secs(10);
                loop {
                    if !presence(address,account.user).await? { frames.push("false".into()); break }
                    if tokio::time::Instant::now()>=deadline { return Err("last socket stayed online".into()) }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            if case == "user-notifications" {
                frames.clear();
                for channel in ["chat", "meet", "drive-watch"] {
                    // A marker for someone else's live rail must never reach this socket.
                    let other = format!("{channel}:{}",foreign.user);
                    owner.query("SELECT pg_notify($1,$2)", &[&other, &r#"{"secret":"foreign"}"#]).await?;
                    let own = format!("{channel}:{}",account.user);
                    // Invalid JSON on a raw rail is ignored, without closing the connection.
                    owner.query("SELECT pg_notify($1,$2)", &[&own, &"malformed"]).await?;
                    owner.query("SELECT pg_notify($1,$2)", &[&own, &r#"{"marker":"own"}"#]).await?;
                    let message = tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("socket ended")??;
                    frames.push(message.into_text()?.to_string());
                }
            }
            if case == "state-batches" {
                frames.clear();
                let own=format!("tag:{}",account.mailbox);
                let other=format!("tag:{}",foreign.mailbox);
                owner.query("SELECT pg_notify($1,$2)",&[&other,&r#"{"state":999999}"#]).await?;
                owner.batch_execute("BEGIN").await?;
                for (name,payload) in [("tag",r#"{"state":999}"#),("calendar",r#"{"event":"rsvp","event_id":9}"#),("contact",r#"{"contact_id":null}"#),("task",r#"{"task_id":null}"#)] {
                    let channel=format!("{name}:{}",account.mailbox);
                    owner.query("SELECT pg_notify($1,$2)",&[&channel,&payload]).await?;
                }
                owner.batch_execute("COMMIT").await?;
                let frame=tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("missing batched state")??.into_text()?.to_string();
                frames.push(frame.replace(&format!("\"{}\"",account.mailbox),"\"<mailbox>\""));
                owner.batch_execute("BEGIN").await?;
                for payload in [r#"{"type":"offline.wipe","why":"fixture"}"#,r#"{"state":1000}"#] {
                    owner.query("SELECT pg_notify($1,$2)",&[&own,&payload]).await?;
                }
                owner.batch_execute("COMMIT").await?;
                for _ in 0..2 {
                    let frame=tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("missing control/state")??.into_text()?.to_string();
                    frames.push(frame.replace(&format!("\"{}\"",account.mailbox),"\"<mailbox>\""));
                }
            }
            if case == "requests" || case == "reference-formats" {
                frames.clear();
                let core="urn:ietf:params:jmap:core";
                let scripts:Vec<String>=if case=="reference-formats" {vec![r##"{"@type":"Request","id":"formats","using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"rows":[{"z":1,"a":2}],"big":9007199254740993,"exp":1e21},"raw"],["Core/echo",{"literal":{"z":3,"a":4},"#copied":{"RESULTOf":"raw","NAME":"Core/echo","PATH":"/rows/-0"}},"fold"],["Core/echo",{"#large":{"resultOf":"raw","name":"Core/echo","path":"/big"},"#exp":{"resultOf":"raw","name":"Core/echo","path":"/exp"},"literal":{"z":3,"a":4}},"number"]]}"##.to_owned()]} else {vec![

                    json!({"@type":"Request","id":"no-using"}),
                    json!({"@type":"Request","id":"mail-cap","using":[core],"methodCalls":[["Email/query",{},"q"]]}),
                    json!({"@type":"Request","id":"unknown","using":[core],"methodCalls":[["Does/notExist",{},"u"]]}),
                    json!({"@type":"Request","id":"core-cap","using":["unknown"],"methodCalls":[["Core/echo",{},"e"]]}),
                    json!({"@type":"Request","id":"empty","using":[core],"methodCalls":[]}),
                    json!({"@type":"Request","id":"array","using":[core],"methodCalls":[["Core/echo",[1,2],"a"]]}),
                    json!({"@type":"Request","id":"chain","using":[core],"methodCalls":[
                        ["Core/echo",{"rows":[{"ids":["x","y"]},{"ids":["z"]}]},"a"],
                        ["Core/echo",{"#ids":{"resultOf":"a","name":"Core/echo","path":"/rows/*/ids"}},"b"],
                        ["Core/echo",{"#x":{"resultOf":"missing","name":"Core/echo","path":""}},"c"],
                        ["Core/echo",{"ids":[],"#ids":{"resultOf":"a","name":"Core/echo","path":"/rows"}},"d"],
                        ["Core/echo",{"#x":{"resultOf":"b","name":"Wrong","path":"/ids"}},"e"]]}),
                    json!({"@type":"Request","id":"many","using":[core],"methodCalls":vec![json!(["Core/echo",{},"m"]);33]}),
                ]
                .into_iter().map(|v|v.to_string()).collect()};
                // Go ignores an invalid JSON frame and a known-field type mismatch entirely.
                socket.send(Message::Text("{".into())).await?;
                socket.send(Message::Text(r#"{"@type":"WebSocketPushDisable","dataTypes":7}"#.into())).await?;
                for script in scripts {
                    socket.send(Message::Text(script.to_string().into())).await?;
                    let mut frame=tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("missing Request reply")??.into_text()?.to_string();
                    if let Some(start)=frame.find("\"sessionState\":\"").map(|at|at+16) {
                        let end=start+frame[start..].find('"').ok_or("session token end")?;
                        let value=&frame[start..end];
                        if value!="unavailable" {
                            let dash=value.rfind('-').ok_or("session token components")?;
                            frame.replace_range(start+dash+1..end,"<timestamp>");
                        }
                    }
                    frames.push(frame);
                }
            }
            if case == "native-email" {
                frames.clear();
                let script=json!({"@type":"Request","id":"native","using":["urn:ietf:params:jmap:mail","urn:ietf:params:jmap:core"],"methodCalls":[
                    ["Email/query",{"accountId":account.mailbox.to_string(),"filter":{"inMailbox":account.inbox.to_string()},"limit":2},"query"],
                    ["Core/echo",{"ok":true},"echo"],
                    ["Email/changes",{"accountId":foreign.mailbox.to_string(),"sinceState":"0"},"foreign"],
                    ["Email/changes",{"accountId":account.mailbox.to_string(),"sinceState":"broken"},"invalid"]]});
                socket.send(Message::Text(script.to_string().into())).await?;
                let mut frame=tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("missing native response")??.into_text()?.to_string();
                for (id,name) in [(account.mailbox,"<mailbox>"),(account.two_labels,"<two-labels>"),(account.inbox_only,"<inbox-only>")] {
                    frame=frame.replace(&format!("\"{id}\""),&format!("\"{name}\""));
                }
                if let Some(start)=frame.find("\"sessionState\":\"").map(|at|at+16) {
                    let end=start+frame[start..].find('"').ok_or("session token end")?;
                    if let Some(dash)=frame[start..end].rfind('-') { frame.replace_range(start+dash+1..end,"<timestamp>"); }
                }
                frames.push(frame);
            }
            if case.starts_with("write-repeat") {
                frames.clear();
                for index in 0..3 {
                    let patch=if index==2 {json!({"keywords/$seen":false})} else {json!({"keywords":{"$seen":true}})};
                    let script=json!({"@type":"Request","id":format!("write-{index}"),"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":account.mailbox.to_string(),"update":{account.two_labels.to_string():patch}},"set"]]});
                    socket.send(Message::Text(script.to_string().into())).await?;
                    let (mut response,mut pushed)=(false,index!=0);
                    while !response||!pushed {
                        let mut frame=tokio::time::timeout(Duration::from_secs(10),socket.next()).await?.ok_or("write response/push missing")??.into_text()?.to_string();
                        let v:Value=serde_json::from_str(&frame)?;
                        frame=frame.replace(&format!("\"updated\":[{}]",account.two_labels),"\"updated\":[\"<two-labels>\"]");
                        response|=v["@type"]=="Response";pushed|=v["@type"]=="StateChange";
                        for (id,name) in [(account.mailbox,"<mailbox>"),(account.two_labels,"<two-labels>")] {frame=frame.replace(&format!("\"{id}\""),&format!("\"{name}\""));}
                        if let Some(start)=frame.find("\"sessionState\":\"").map(|at|at+16) {let end=start+frame[start..].find('"').ok_or("session end")?;if let Some(dash)=frame[start..end].rfind('-') {frame.replace_range(start+dash+1..end,"<timestamp>");}}
                        frames.push(frame);
                    }
                }
                // The two concurrent Go writers may race Response versus StateChange.
                // Keep each stream's order, while comparing both kinds and their bytes.
                frames.sort_by_key(|frame|frame.starts_with("{\"@type\":\"StateChange\""));
                let (own_before,foreign_before)=before.expect("write fixture");
                effects=json!({"own":{"before":own_before,"after":snapshot(&owner,&account).await?},"foreign":{"before":foreign_before,"after":snapshot(&owner,&foreign).await?,"audit":audits(&owner,&foreign).await?}});
                audit=audits(&owner,&account).await?;
                notify=json!(listener.as_mut().expect("write listener").drain(&owner).await?);
            }
            if case != "presence-connections" { socket.close(None).await?; }
            Ok::<Value,BoxError>(json!({"request":{"method":"GET","path":if case == "presence-connections" { "/chat/presence" } else { "/jmap/ws" }},
                "response":{"status":if case == "presence-connections" { 200 } else { response.status().as_u16() },"frames":frames},
                "effects":effects,"audit":audit,"notify":notify}))
        }.await;
        let proxy_check=async {
            if !recording {
                let response=common::send(address,hyper::Request::builder().uri(format!("http://{address}/_gateway/metrics")).body(common::full(""))?).await;
                let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;
                if !metrics.contains("setjoin_gateway_proxied_to_go_total 0\n"){return Err(format!("native route used Go: {metrics}").into())}
            }
            Ok::<_,BoxError>(())
        }.await;
        server.abort(); let _ = server.await;
        let observation = observation?;
        proxy_check?;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/jmap/push/ws-{case}.json"));
        let label = if case.starts_with("presence-") { "GET /chat/presence" } else { "GET /jmap/ws" };
        if recording {
            golden::record(&path,&json!({"format":1,"route":label,"case":format!("ws-{case}"),
                "go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":[],"observation":observation}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
            let divergences:Value=serde_json::from_str(include_str!("../../../tests/conformance/jmap/divergences.json"))?;
            golden::compare_reviewed(label,&format!("ws-{case}"),&expected["observation"],&observation,&divergences)?;
            println!("GOLDEN-REPLAY: {label} :: ws-{case}");
        }
        Ok::<_,BoxError>(())
    }.await;
    if let Some(level) = audit_level {
        owner
            .execute("UPDATE audit_policy SET level=$1 WHERE id=1", &[&level])
            .await?;
        owner
            .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
            .await?;
        owner
            .execute(
                "DELETE FROM admin_audit_log WHERE user_id=$1",
                &[&account.user],
            )
            .await?;
        owner.batch_execute("COMMIT").await?;
    }
    if let Some(channel) = channel {
        owner
            .execute("DELETE FROM chat_channels WHERE id=$1", &[&channel])
            .await?;
    }
    fixture::remove(&owner, &account).await?;
    fixture::remove(&owner, &foreign).await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
            &[&old_chat],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
            &[&old_guests],
        )
        .await?;
    drop(owner);
    result
}
