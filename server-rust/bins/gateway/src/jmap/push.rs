//! RFC 8887 transport over the shared JMAP command authority and push hub.
use super::{token::KeySource, JmapCommands};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use setjoin_authz::push::{PushAuthError, PushIdentity};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{MailboxAuthContext, Type};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_tungstenite::{
    tungstenite::{
        self,
        protocol::{frame::coding::CloseCode, CloseFrame, Role},
        Message,
    },
    WebSocketStream,
};

pub struct WebSocketRoute<K: KeySource + 'static> {
    pub commands: Arc<JmapCommands<K>>,
    pub hub: Arc<super::hub::PushHub>,
    pub registry: setjoin_jmap::connections::ConnectionRegistry,
    pub production: bool,
    pub allowed_host: String,
    pub worker: Option<setjoin_pg::workers::WorkerDatabase>,
    pub max_clients: usize,
    pub(super) clients: Arc<AtomicUsize>,
    devices: Arc<super::device_cache::DeviceCache>,
}
impl<K: KeySource + 'static> WebSocketRoute<K> {
    pub fn with_device_cache(mut self,devices:Arc<super::device_cache::DeviceCache>)->Self{self.devices=devices;self}

    pub fn new(commands: Arc<JmapCommands<K>>, direct_dsn: String) -> Self {
        Self {
            commands,
            hub: super::hub::PushHub::new(direct_dsn),
            registry: Default::default(),
            production: false,
            allowed_host: String::new(),
            worker: None,
            max_clients: 1000,
            clients: Arc::new(AtomicUsize::new(0)),
            devices: Default::default(),
        }
    }
}
pub(super) struct Permit(pub(super) Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<K: KeySource + 'static> Intercept for WebSocketRoute<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD) && r.uri().path() == "/jmap/ws"
    }
    fn shutdown(&self) {
        self.registry.shutdown();
    }
    fn handle(
        &self,
        mut request: Request<Body>,
        context: RequestContext,
    ) -> BoxFuture<Response<Body>> {
        let (commands, hub, registry, clients, devices, worker) = (
            self.commands.clone(),
            self.hub.clone(),
            self.registry.clone(),
            self.clients.clone(),
            self.devices.clone(),
            self.worker.clone(),
        );
        let (production, allowed_host, max) = (
            self.production,
            self.allowed_host.clone(),
            if self.max_clients == 0 {
                1000
            } else {
                self.max_clients
            },
        );
        Box::pin(async move {
            // Identity #331 owns these key profiles. Header inspection chooses
            // a transport only; it grants no authority to unverified claims.
            if unported_identity(request.headers()) {
                return context.upstream.forward(request, &context.identity).await;
            }
            // Go's outer guest belt reads the ordinary credential before the
            // push handler reads its cookie. It must not lend the cookie identity
            // any authority from a different Authorization header.
            let candidate = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::to_owned)
                .or_else(|| cookie(request.headers()));
            if let Some(candidate) = candidate {
                match setjoin_authz::push::authenticate_detailed(
                    &commands.exec,
                    &commands.keys,
                    &commands.issuer,
                    &candidate,
                )
                .await
                {
                    Ok(identity) if identity.is_guest() => {
                        if !enabled(&commands.exec, "feature.guest_accounts").await {
                            return plain(
                                &request,
                                &context,
                                StatusCode::NOT_FOUND,
                                "404 page not found\n",
                            );
                        }
                    }
                    Err(PushAuthError::GuestInactive) => {
                        return problem_response(&request, &context, 401, "Unauthorized", "")
                    }
                    Err(PushAuthError::GuestUnavailable) => {
                        return problem_response(&request, &context, 503, "service unavailable", "")
                    }
                    _ => {}
                }
            }
            let host = request
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let origin = request
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok());
            let origin_host = origin.and_then(origin_host);
            let allowed = match origin {
                None => !production,
                Some(_) => origin_host.is_some_and(|h| {
                    h == host || (!allowed_host.is_empty() && h.eq_ignore_ascii_case(&allowed_host))
                }),
            };
            if !allowed {
                return plain(
                    &request,
                    &context,
                    StatusCode::FORBIDDEN,
                    "origin not allowed\n",
                );
            }
            // Retain Go's load/check/add shape; the count includes authentication
            // work and remains held for the entire upgraded connection.
            if clients.load(Ordering::SeqCst) >= max {
                return plain(
                    &request,
                    &context,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "too many connections\n",
                );
            }
            clients.fetch_add(1, Ordering::SeqCst);
            let permit = Permit(clients);
            let Some(token) = cookie(request.headers()) else {
                return plain(
                    &request,
                    &context,
                    StatusCode::UNAUTHORIZED,
                    "missing access_token\n",
                );
            };
            let Some(identity) = setjoin_authz::push::authenticate(
                &commands.exec,
                &commands.keys,
                &commands.issuer,
                &token,
            )
            .await
            else {
                return plain(
                    &request,
                    &context,
                    StatusCode::UNAUTHORIZED,
                    "invalid token\n",
                );
            };
            if cache_denies(&commands, &identity)
                || setjoin_authz::push::revoked(&commands.exec, &identity).await
            {
                return plain(
                    &request,
                    &context,
                    StatusCode::UNAUTHORIZED,
                    "invalid token\n",
                );
            }
            let has = |name: &str, want: &str| {
                request
                    .headers()
                    .get_all(name)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(','))
                    .any(|v| v.trim().eq_ignore_ascii_case(want))
            };
            let error = if !has("connection", "upgrade") {
                Some((400, "Bad Request\n"))
            } else if !has("upgrade", "websocket") {
                Some((426, "Upgrade Required\n"))
            } else if request.method() != Method::GET {
                Some((405, "Method Not Allowed\n"))
            } else if !has("sec-websocket-version", "13") {
                Some((400, "Bad Request\n"))
            } else if origin_host.is_some_and(|h| !h.eq_ignore_ascii_case(host)) {
                Some((403, "Forbidden\n"))
            } else {
                use base64::Engine;
                let valid = request
                    .headers()
                    .get("sec-websocket-key")
                    .and_then(|v| {
                        base64::engine::general_purpose::STANDARD
                            .decode(v.as_bytes())
                            .ok()
                    })
                    .is_some_and(|v| v.len() == 16);
                if valid {
                    None
                } else {
                    Some((400, "Bad Request\n"))
                }
            };
            if let Some((status, body)) = error {
                let mut response = plain(
                    &request,
                    &context,
                    StatusCode::from_u16(status).unwrap(),
                    body,
                );
                response
                    .headers_mut()
                    .insert("sec-websocket-version", "13".parse().unwrap());
                if status == 426 {
                    response
                        .headers_mut()
                        .insert("upgrade", "websocket".parse().unwrap());
                }
                return response;
            }
            let mut handshake = Request::builder()
                .method("GET")
                .uri(request.uri())
                .body(())
                .expect("request head");
            *handshake.headers_mut() = request.headers().clone();
            handshake
                .headers_mut()
                .insert("sec-websocket-version", "13".parse().unwrap());
            let Ok(response) = tungstenite::handshake::server::create_response(&handshake) else {
                return plain(&request, &context, StatusCode::BAD_REQUEST, "Bad Request\n");
            };
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(upgraded) = upgrade.await else { return };
                let config = tungstenite::protocol::WebSocketConfig::default()
                    .read_buffer_size(4096)
                    .write_buffer_size(4096)
                    .max_message_size(Some(10 * 1024 * 1024))
                    .max_frame_size(Some(10 * 1024 * 1024));
                let mut socket = WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    Role::Server,
                    Some(config),
                )
                .await;
                let user = identity.user_id();
                let mailbox = commands
                    .exec
                    .read(
                        "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary LIMIT 1",
                        &[(&user, Type::INT8)],
                    )
                    .await
                    .ok()
                    .and_then(|r| r.first().map(|r| r.get::<_, i64>(0)));
                let Some(mailbox) = mailbox else { return }; // Frozen Go WS (unlike SSE) closes mailbox-less guests.
                let (Ok(actor), Ok(mailbox_id)) = (ActorId::new(user), MailboxId::new(mailbox))
                else {
                    return;
                };
                let scope = MailboxAuthContext::from_authenticated_session(
                    actor,
                    mailbox_id,
                    Generation(1),
                );
                let mut channels = ["tag", "calendar", "contact", "task"]
                    .map(|name| format!("{name}:{mailbox}"))
                    .to_vec();
                channels.push("session_revoke".into());
                for (app, prefix) in [("drive", "drive-watch"), ("chat", "chat"), ("meet", "meet")]
                {
                    if app_allowed(&commands.exec, &identity, app).await {
                        channels.push(format!("{prefix}:{user}"));
                    }
                }
                let drive_alarm = app_allowed(&commands.exec, &identity, "drive").await
                    && drive_admin(&commands.exec, &scope).await;
                if drive_alarm {
                    channels.push("drive-alarm".into());
                }
                let chat = channels.contains(&format!("chat:{user}"));
                let admitted = channels.clone();
                let Ok(mut subscription) = hub.subscribe(channels).await else {
                    return;
                };
                let (close, mut closed) = tokio::sync::watch::channel(false);
                let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                    let _ = close.send(true);
                });
                let _connection = registry.register(user, Some(mailbox), chat, close.clone());
                let _session = commands.denylist.as_ref().and_then(|d| {
                    chrono::DateTime::from_timestamp(identity.issued_at(), 0).map(|iat| {
                        d.register_session(
                            user,
                            iat,
                            identity.token_id(),
                            identity.token_family(),
                            close,
                        )
                    })
                });
                // A revoke between authentication and LISTEN/registration cannot
                // escape through a missed notification or a stale cache snapshot.
                if cache_denies(&commands, &identity)
                    || setjoin_authz::push::revoked(&commands.exec, &identity).await
                {
                    return;
                }
                let mut batch = Vec::new();
                let mut deadline = None;
                let mut pong = tokio::time::Instant::now();
                let mut ping = tokio::time::interval_at(
                    pong + Duration::from_secs(30),
                    Duration::from_secs(30),
                );
                let mut revalidate = tokio::time::interval_at(
                    pong + Duration::from_secs(300),
                    Duration::from_secs(300),
                );
                loop {
                    let message = tokio::select! {
                        _=closed.changed()=>break,
                        _=tokio::time::sleep_until(pong+Duration::from_secs(70))=>break,
                        _=ping.tick()=>{if socket.send(Message::Ping(Vec::new().into())).await.is_err(){break}continue},
                        _=revalidate.tick()=>{
                            let mut allowed=chrono::Utc::now().timestamp()<identity.expires_at();
                            for channel in &admitted {
                                let app=if channel.starts_with("chat:"){Some("chat")}else if channel.starts_with("meet:"){Some("meet")}else if channel.starts_with("drive-"){Some("drive")}else{None};
                                if let Some(app)=app {allowed &=app_allowed(&commands.exec,&identity,app).await;}
                            }
                            if drive_alarm {allowed &=drive_admin(&commands.exec,&scope).await;}
                            if !allowed {let _=socket.close(Some(CloseFrame{code:CloseCode::Policy,reason:"authorization changed".into()})).await;break}
                            continue
                        },
                        _=tokio::time::sleep_until(deadline.unwrap_or_else(||tokio::time::Instant::now()+Duration::from_secs(3600))),if deadline.is_some()=>{
                            for frame in state_frames(&commands.exec,&scope,&batch).await {if socket.send(Message::Text(frame.into())).await.is_err(){return}}
                            batch.clear();deadline=None;continue
                        },
                        event=subscription.events.recv()=>{
                            let Some(event)=event else {break};
                            if event.channel=="session_revoke" {
                                if revoked_payload(&event.payload,&identity) {let _=socket.send(Message::Text("{\"@type\":\"SessionRevoked\"}\n".into())).await;break}
                                continue
                            }
                            if ["tag:","calendar:","contact:","task:"].iter().any(|p|event.channel.starts_with(p)) {batch.push(event.payload);deadline.get_or_insert_with(||tokio::time::Instant::now()+Duration::from_millis(20));continue}
                            let Some(payload)=super::reply::go_compact(&event.payload) else {continue};
                            let kind=if event.channel.starts_with("chat:"){"ChatEvent"}else if event.channel.starts_with("meet:"){"MeetEvent"}else if event.channel=="drive-alarm"{"DriveAlarm"}else{"DriveWatch"};
                            if socket.send(Message::Text(format!("{{\"@type\":\"{kind}\",\"event\":{payload}}}\n").into())).await.is_err(){break}continue
                        },
                        message=socket.next()=>match message {
                            Some(Ok(message))=>message,
                            Some(Err(tungstenite::Error::Capacity(_)))=>{let _=socket.close(Some(CloseFrame{code:CloseCode::Size,reason:"".into()})).await;break},
                            _=>break,
                        }
                    };
                    let data = match message {
                        Message::Pong(_) => {
                            pong = tokio::time::Instant::now();
                            continue;
                        }
                        Message::Ping(_) => {
                            let _ = socket.flush().await;
                            continue;
                        }
                        Message::Close(_) => {
                            let _ = socket.flush().await;
                            break;
                        }
                        Message::Text(text) => text.as_bytes().to_vec(),
                        Message::Binary(data) => data.to_vec(),
                        _ => continue,
                    };
                    if cache_denies(&commands, &identity)
                        || setjoin_authz::push::revoked(&commands.exec, &identity).await
                    {
                        if commands.denylist.as_ref().is_some_and(|d| !d.loaded()) {
                            let _ = socket
                                .close(Some(CloseFrame {
                                    code: CloseCode::Restart,
                                    reason: "session verification unavailable".into(),
                                }))
                                .await;
                            break;
                        }
                        continue;
                    }
                    if devices
                        .revoked(&commands.exec, worker.as_ref(), identity.device_id())
                        .await
                    {
                        let _ = socket
                            .close(Some(CloseFrame {
                                code: CloseCode::Policy,
                                reason: "device access revoked".into(),
                            }))
                            .await;
                        break;
                    }
                    let Some(env) = super::ws_request::decode(&data) else {
                        continue;
                    };
                    let reply=match env.kind.as_str() {
                        "WebSocketPushEnable"=>continue,"WebSocketPushDisable"=>r#"{"@type":"error"}"#.to_owned(),
                        "Request"=>{
                            if super::ws_request::needs_go(&commands,&identity,&env).await {
                                match super::ws_request::forward_unported(&data,&token,&env,&context).await {Ok(reply)=>reply,Err(())=>break}
                            } else {super::ws_request::execute(&commands,&identity,&env,&context).await}
                        },
                        _=>r#"{"@type":"error","type":"urn:ietf:params:jmap:error:unknownType","status":400,"detail":"unknown @type"}"#.to_owned(),
                    };
                    if socket.send(Message::Text(reply.into())).await.is_err() {
                        break;
                    }
                }
            });
            response.map(|_| {
                Full::new(bytes::Bytes::new())
                    .map_err(|n| match n {})
                    .boxed()
            })
        })
    }
}
pub(super) fn cache_denies<K: KeySource>(commands: &JmapCommands<K>, identity: &PushIdentity) -> bool {
    commands.denylist.as_ref().is_some_and(|d| {
        !d.loaded()
            || chrono::DateTime::from_timestamp(identity.issued_at(), 0).is_none_or(|iat| {
                d.is_revoked(
                    identity.user_id(),
                    identity.token_id(),
                    identity.token_family(),
                    iat,
                )
            })
    })
}
pub(super) async fn enabled(exec: &setjoin_pg::ScopedExecutor, key: &str) -> bool {
    exec.read(
        "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
        &[(&key, Type::TEXT)],
    )
    .await
    .is_ok_and(|r| r[0].get::<_, bool>(0))
}
pub(super) async fn app_allowed(
    exec: &setjoin_pg::ScopedExecutor,
    identity: &PushIdentity,
    app: &str,
) -> bool {
    !identity.is_guest()
        || exec
            .read(
                "SELECT check_user_app_entitlement($1,$2)",
                &[(&identity.user_id(), Type::INT8), (&app, Type::TEXT)],
            )
            .await
            .is_ok_and(|r| r[0].get::<_, bool>(0))
}
async fn drive_admin(exec: &setjoin_pg::ScopedExecutor, scope: &MailboxAuthContext) -> bool {
    let user = scope.actor().get();
    exec.read_user_scoped(
        scope.actor(),
        "SELECT drive_has_admin_perm($1,'drive.view') OR drive_has_admin_perm($1,'drive.manage')",
        &[(&user, Type::INT8)],
    )
    .await
    .is_ok_and(|r| r[0].get::<_, bool>(0))
}
pub(super) fn origin_host(raw: &str) -> Option<&str> {
    if raw.trim() != raw || raw.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    let rest = raw
        .split_once("://")
        .map(|(_, rest)| rest)
        .or_else(|| raw.strip_prefix("//"))?;
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let parsed = if raw.starts_with("//") {
        url::Url::parse(&format!("http:{raw}"))
    } else {
        url::Url::parse(raw)
    }
    .ok()?;
    parsed.host_str()?;
    Some(host)
}
pub(super) fn revoked_payload(payload: &str, identity: &PushIdentity) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return false;
    };
    if value.get("user_id").and_then(|v| v.as_i64()) != Some(identity.user_id()) {
        return false;
    }
    match value.get("scope").and_then(|v| v.as_str()).unwrap_or("") {
        "jti" => value
            .get("jti")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty() && v == identity.token_id()),
        "family" => value
            .get("family_id")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty() && v == identity.token_family()),
        "all" => value
            .get("not_before")
            .and_then(|v| v.as_str())
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .is_some_and(|v| identity.issued_at() <= v.timestamp()),
        _ => false,
    }
}

pub(super) fn cookie(headers: &hyper::HeaderMap) -> Option<String> {
    for value in headers.get_all("cookie") {
        for part in value.to_str().ok()?.split(';') {
            if let Some(("access_token", value)) = part.trim().split_once('=') {
                let value = value.trim().trim_matches('"');
                return (!value.is_empty()).then(|| value.to_owned());
            }
        }
    }
    None
}

pub(super) fn unported_identity(headers: &hyper::HeaderMap) -> bool {
    use base64::Engine;
    let ordinary = setjoin_authz::token::extract(headers);
    [ordinary, cookie(headers)]
        .into_iter()
        .flatten()
        .any(|token| {
            let Some(header) = token.split('.').next() else {
                return false;
            };
            let Some(value) = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header)
                .ok()
                .and_then(|h| serde_json::from_slice::<serde_json::Value>(&h).ok())
            else {
                return false;
            };
            matches!(value["alg"].as_str(), Some("HS256" | "SM2"))
        })
}

pub(super) fn plain(
    request: &Request<Body>,
    context: &RequestContext,
    status: hyper::StatusCode,
    body: &'static str,
) -> Response<Body> {
    let mut nonce = [0; 16];
    let _ = getrandom::getrandom(&mut nonce);
    let id = super::reply::request_id(request.headers().get("x-request-id"), nonce);
    let mut response = super::reply::response(body.into(), context.identity.proto, id);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    response
}

pub(super) async fn state_frames(
    exec: &setjoin_pg::ScopedExecutor,
    scope: &setjoin_pg::MailboxAuthContext,
    payloads: &[String],
) -> Vec<String> {
    use serde_json::{json, Value};
    let (mut valid, mut calendar, mut contact, mut task) = (false, false, false, false);
    let mut frames = Vec::new();
    for payload in payloads {
        let Ok(Value::Object(value)) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        if value
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|s| matches!(s, "offline.wipe" | "capsChanged" | "MailWorkEvent"))
        {
            frames.push(payload.clone());
            continue;
        }
        valid |= value.contains_key("state");
        let event = value.get("event").and_then(Value::as_str).unwrap_or("");
        calendar |= event.contains("event")
            || event.starts_with("calendar")
            || matches!(event, "rsvp" | "itip_reply" | "itip_cancel")
            || value.contains_key("calendar_id")
            || value.contains_key("event_id");
        contact |= value.contains_key("contact_id");
        task |= value.contains_key("task_id");
    }
    if valid || calendar || contact || task {
        let tokens = setjoin_jmap::push_state::tokens(exec, scope).await;
        let mut changed = json!({"Email":tokens[0],"Mailbox":tokens[1],"Thread":tokens[2]});
        if calendar {
            changed["Calendar"] = json!(tokens[3]);
            changed["CalendarEvent"] = json!(tokens[3]);
        }
        if contact {
            changed["Contact"] = json!(tokens[4]);
        }
        if task {
            changed["Task"] = json!(tokens[5]);
        }
        frames.push(
            json!({"@type":"StateChange","changed":{scope.mailbox().decimal():changed}})
                .to_string(),
        );
    }
    frames
}

pub(super) fn problem_response(
    request: &Request<Body>,
    context: &RequestContext,
    status: u16,
    detail: &str,
    instance: &str,
) -> Response<Body> {
    let mut nonce = [0; 16];
    let _ = getrandom::getrandom(&mut nonce);
    let id = super::reply::request_id(request.headers().get("x-request-id"), nonce);
    let body = crate::problem::Problem::new(status, detail)
        .instance(instance)
        .body();
    let mut response = super::reply::response(body, context.identity.proto, id);
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("fixed status");
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}
