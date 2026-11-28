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
    pub sync_hub: Option<Arc<super::sync_hub::SyncWakeupHub>>,
    pub(super) disable_sync_hub: bool,
    pub(super) direct_dsn: String,
    pub(super) lazy_sync_hub: Arc<std::sync::Mutex<Option<Arc<super::sync_hub::SyncWakeupHub>>>>,
    pub registry: setjoin_jmap::connections::ConnectionRegistry,
    pub production: bool,
    pub allowed_host: String,
    pub worker: Option<setjoin_pg::workers::WorkerDatabase>,
    pub max_clients: usize,
    pub(super) clients: Arc<AtomicUsize>,
    devices: Arc<super::device_cache::DeviceCache>,
}
impl<K: KeySource + 'static> WebSocketRoute<K> {
    pub fn with_device_cache(mut self, devices: Arc<super::device_cache::DeviceCache>) -> Self {
        self.devices = devices;
        self
    }

    pub fn with_listen_hub(mut self, hub: setjoin_pg::ListenHub) -> Self {
        let worker_exec = self
            .commands
            .worker
            .clone()
            .unwrap_or_else(|| self.commands.exec.clone());
        self.disable_sync_hub = false;
        self.sync_hub = Some(super::sync_hub::SyncWakeupHub::with_listen_hub(
            hub.clone(),
            self.commands.exec.clone(),
            worker_exec,
        ));
        self.hub = super::hub::PushHub::with_listen_hub(hub);
        self
    }

    pub fn with_sync_hub(mut self, sync_hub: Arc<super::sync_hub::SyncWakeupHub>) -> Self {
        self.disable_sync_hub = false;
        self.sync_hub = Some(sync_hub);
        self
    }

    pub fn without_sync_hub(mut self) -> Self {
        self.disable_sync_hub = true;
        self.sync_hub = None;
        self
    }

    pub(super) fn resolve_sync_hub(&self) -> Option<Arc<super::sync_hub::SyncWakeupHub>> {
        if self.disable_sync_hub {
            return None;
        }
        if let Some(hub) = &self.sync_hub {
            return Some(hub.clone());
        }
        resolve_lazy_sync_hub(&self.lazy_sync_hub, &self.direct_dsn, &self.commands)
    }

    pub fn new(commands: Arc<JmapCommands<K>>, direct_dsn: String) -> Self {
        Self {
            commands,
            hub: super::hub::PushHub::new(direct_dsn.clone()),
            sync_hub: None,
            disable_sync_hub: false,
            direct_dsn,
            lazy_sync_hub: Arc::new(std::sync::Mutex::new(None)),
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

pub(super) fn resolve_lazy_sync_hub<K: KeySource + 'static>(
    slot: &std::sync::Mutex<Option<Arc<super::sync_hub::SyncWakeupHub>>>,
    direct_dsn: &str,
    commands: &JmapCommands<K>,
) -> Option<Arc<super::sync_hub::SyncWakeupHub>> {
    if direct_dsn.trim().is_empty() {
        return None;
    }
    let mut guard = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = guard.as_ref() {
        return Some(existing.clone());
    }
    let worker_exec = commands
        .worker
        .clone()
        .unwrap_or_else(|| commands.exec.clone());
    let created = super::sync_hub::SyncWakeupHub::from_direct_dsn(
        direct_dsn,
        commands.exec.clone(),
        worker_exec,
    )?;
    *guard = Some(created.clone());
    Some(created)
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
        if let Some(hub) = &self.sync_hub {
            hub.shutdown();
        }
        if let Some(hub) = self
            .lazy_sync_hub
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            hub.shutdown();
        }
    }
    fn handle(
        &self,
        mut request: Request<Body>,
        context: RequestContext,
    ) -> BoxFuture<Response<Body>> {
        let (commands, hub, sync_hub, registry, clients, devices, worker) = (
            self.commands.clone(),
            self.hub.clone(),
            self.resolve_sync_hub(),
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
            // #356a: HS256/SM2 and ES256 push credentials share one verifier
            // (`setjoin_authz::push` with the configured legacy keys). Header
            // shape never selects a path and grants no authority.
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
                let mailbox = match setjoin_authz::policy_gate::lookup_primary_mailbox_lifecycle(
                    &commands.exec,
                    user,
                )
                .await
                {
                    Ok(Some((mb, true))) => mb,
                    // Frozen Go WS (unlike SSE) closes mailbox-less guests; Wave 1.4 (#542)
                    // also closes mailboxes whose lifecycle access is blocked.
                    Ok(Some((_, false))) => {
                        let _ = socket
                            .close(Some(CloseFrame {
                                code: CloseCode::Policy,
                                reason: "mailbox access suspended".into(),
                            }))
                            .await;
                        return;
                    }
                    _ => return,
                };
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
                let (restart_tx, mut restart_rx) =
                    tokio::sync::watch::channel::<Option<&'static str>>(None);
                // Keep a clone of `restart_tx` alive for the full socket lifetime
                // so when `sync_hub` is `None` (legacy fallback), `restart_rx`
                // never resolves to `Err(RecvError)` and closes the socket.
                let _restart_tx_keepalive = restart_tx.clone();
                let restart_close: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(move |r| {
                    let _ = restart_tx.send(Some(r));
                });
                let (hub_guard, mut hub_control_rx, hub_wakeups, mut hub_ephemeral_rx) =
                    match sync_hub.as_ref().map(|sh| {
                        sh.register_connection(
                            user,
                            Some(mailbox),
                            identity.is_guest(),
                            restart_close,
                        )
                        .split()
                    }) {
                        Some((g, c, w, e)) => (Some(g), Some(c), Some(w), Some(e)),
                        None => (None, None, None, None),
                    };
                let (attach_reply_tx, mut attach_reply_rx) =
                    tokio::sync::mpsc::channel::<String>(16);
                let attach_sem = Arc::new(tokio::sync::Semaphore::new(4));
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
                        biased;
                        _=closed.changed()=>break,
                        res = restart_rx.changed(), if hub_guard.is_some() => {
                            if res.is_ok() {
                                let reason = restart_rx.borrow().unwrap_or("connection restart required");
                                let _ = socket
                                    .close(Some(CloseFrame {
                                        code: CloseCode::Restart,
                                        reason: reason.into(),
                                    }))
                                    .await;
                                break;
                            }
                            continue;
                        }
                        ctrl = async {
                            match hub_control_rx.as_mut() {
                                Some(rx) => rx.recv().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            let Some(ctrl) = ctrl else { continue };
                            match ctrl {
                                super::sync_hub::ControlMessage::ScopeRevoked(ev) => {
                                    if socket.send(Message::Text(ev.to_ws_frame().into())).await.is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                super::sync_hub::ControlMessage::SessionRevoked => {
                                    let _ = socket.send(Message::Text("{\"@type\":\"SessionRevoked\"}\n".into())).await;
                                    break;
                                }
                                super::sync_hub::ControlMessage::OfflineWipe(payload) => {
                                    if socket.send(Message::Text(payload.into())).await.is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                super::sync_hub::ControlMessage::Restart(reason) => {
                                    let _ = socket
                                        .close(Some(CloseFrame {
                                            code: CloseCode::Restart,
                                            reason: reason.into(),
                                        }))
                                        .await;
                                    break;
                                }
                            }
                        }
                        reply = attach_reply_rx.recv() => {
                            if let Some(reply) = reply {
                                if socket.send(Message::Text(reply.into())).await.is_err() {
                                    break;
                                }
                            }
                            continue;
                        }
                        wakeup = async {
                            match hub_wakeups.as_ref() {
                                Some(w) => w.next_one().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            if socket.send(Message::Text(wakeup.to_ws_frame().into())).await.is_err() {
                                break;
                            }
                            continue;
                        }
                        ephem = async {
                            match hub_ephemeral_rx.as_mut() {
                                Some(rx) => rx.recv().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            if let Some(payload) = ephem {
                                if socket
                                    .send(Message::Text(
                                        format!("{{\"@type\":\"ChatEvent\",\"event\":{payload}}}\n")
                                            .into(),
                                    ))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            continue;
                        }
                        _=tokio::time::sleep_until(pong+Duration::from_secs(70))=>break,
                        _=ping.tick()=>{if socket.send(Message::Ping(Vec::new().into())).await.is_err(){break}continue},
                        _=revalidate.tick()=>{
                            let mut allowed=identity.expires_at().is_some_and(|exp|chrono::Utc::now().timestamp()<exp);
                            allowed &= setjoin_authz::policy_gate::check_mailbox_lifecycle(&commands.exec, mailbox).await.unwrap_or(false);
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
                    if !setjoin_authz::policy_gate::check_mailbox_lifecycle(&commands.exec, mailbox)
                        .await
                        .unwrap_or(false)
                    {
                        let _ = socket
                            .close(Some(CloseFrame {
                                code: CloseCode::Policy,
                                reason: "mailbox access suspended".into(),
                            }))
                            .await;
                        break;
                    }
                    let Some(env) = super::ws_request::decode(&data) else {
                        continue;
                    };
                    let reply=match env.kind.as_str() {
                        "WebSocketPushEnable"=>continue,"WebSocketPushDisable"=>r#"{"@type":"error"}"#.to_owned(),
                        "ScopeAttach" => {
                            let Some(raw_scopes) = env.scopes else {
                                let err = super::ws_request::request_error(
                                    &env.id,
                                    "invalidArguments",
                                    "scopes array is required",
                                );
                                if socket.send(Message::Text(err.into())).await.is_err() {
                                    break;
                                }
                                continue;
                            };
                            let (Some(sh), Some(conn_id)) = (sync_hub.clone(), hub_guard.as_ref().map(|c| c.id)) else {
                                let err = super::ws_request::request_error_status(
                                    &env.id,
                                    "serverFail",
                                    503,
                                    "sync wakeup hub unavailable",
                                );
                                if socket.send(Message::Text(err.into())).await.is_err() {
                                    break;
                                }
                                continue;
                            };
                            let Ok(permit) = attach_sem.clone().try_acquire_owned() else {
                                let err = super::ws_request::request_error_status(
                                    &env.id,
                                    "limit",
                                    429,
                                    "too many concurrent ScopeAttach requests",
                                );
                                if socket.send(Message::Text(err.into())).await.is_err() {
                                    break;
                                }
                                continue;
                            };
                            let attach_op_seq = sh.begin_attach_op(conn_id);
                            let reply_tx = attach_reply_tx.clone();
                            let req_id = env.id.clone();
                            let cmds = commands.clone();
                            let ident = identity.clone();
                            let restart_cb = _restart_tx_keepalive.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let mut valid = Vec::with_capacity(raw_scopes.len());
                                let mut invalid_denied = Vec::new();
                                for rs in raw_scopes {
                                    if let Some(kind) = super::sync_hub::ScopeKind::parse(&rs.scope_kind) {
                                        valid.push(super::sync_hub::ScopeDescriptor {
                                            kind,
                                            raw_id: rs.scope_id,
                                        });
                                    } else {
                                        invalid_denied.push(serde_json::json!({
                                            "scopeKind": rs.scope_kind,
                                            "scopeId": rs.scope_id,
                                            "reason": "invalid_scope_kind"
                                        }));
                                    }
                                }
                                let outcome = sh
                                    .attach_scopes_with_seq_checked(
                                        conn_id,
                                        &valid,
                                        attach_op_seq,
                                        || async {
                                            cache_denies(&cmds, &ident)
                                                || setjoin_authz::push::revoked(&cmds.exec, &ident)
                                                    .await
                                        },
                                    )
                                    .await;
                                // Session revocation is verified BEFORE installing scopes into
                                // `scope_index` so a revoked session never becomes routable.
                                if outcome.session_revoked {
                                    let _ = restart_cb.send(Some("session revoked during attach"));
                                    return;
                                }
                                let mut res = outcome.result;
                                if invalid_denied.is_empty() {
                                    let _ = reply_tx
                                        .send(super::sync_hub::format_scope_attach_response(
                                            &req_id, &res,
                                        ))
                                        .await;
                                } else {
                                    let attached: Vec<serde_json::Value> = res
                                        .attached
                                        .drain(..)
                                        .map(|s| {
                                            serde_json::json!({
                                                "scopeKind": s.kind.as_str(),
                                                "scopeId": s.raw_id
                                            })
                                        })
                                        .collect();
                                    let mut denied: Vec<serde_json::Value> = res
                                        .denied
                                        .drain(..)
                                        .map(|d| {
                                            serde_json::json!({
                                                "scopeKind": d.scope_kind.as_str(),
                                                "scopeId": d.scope_id,
                                                "reason": d.reason
                                            })
                                        })
                                        .collect();
                                    denied.extend(invalid_denied);
                                    let mut obj = serde_json::Map::new();
                                    obj.insert("@type".into(), serde_json::json!("ScopeAttachResponse"));
                                    if !req_id.is_empty() {
                                        obj.insert("requestId".into(), serde_json::json!(req_id));
                                    }
                                    obj.insert("attached".into(), serde_json::Value::Array(attached));
                                    obj.insert("denied".into(), serde_json::Value::Array(denied));
                                    let _ = reply_tx.send(serde_json::Value::Object(obj).to_string()).await;
                                }
                            });
                            continue;
                        }
                        "ScopeDetach" => {
                            let Some(raw_scopes) = env.scopes else {
                                let err = super::ws_request::request_error(
                                    &env.id,
                                    "invalidArguments",
                                    "scopes array is required",
                                );
                                if socket.send(Message::Text(err.into())).await.is_err() {
                                    break;
                                }
                                continue;
                            };
                            let detached = if let Some(hc) = hub_guard.as_ref() {
                                let valid: Vec<super::sync_hub::ScopeDescriptor> = raw_scopes
                                    .into_iter()
                                    .filter_map(|rs| {
                                        super::sync_hub::ScopeKind::parse(&rs.scope_kind).map(
                                            |kind| super::sync_hub::ScopeDescriptor {
                                                kind,
                                                raw_id: rs.scope_id,
                                            },
                                        )
                                    })
                                    .collect();
                                hc.detach_scopes(&valid)
                            } else {
                                Vec::new()
                            };
                            super::sync_hub::format_scope_detach_response(&env.id, &detached)
                        }
                        "Request" => super::ws_request::execute(&commands, &identity, &env).await,
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
pub(super) fn cache_denies<K: KeySource>(
    commands: &JmapCommands<K>,
    identity: &PushIdentity,
) -> bool {
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
    crate::policy_composition::user_read(
        exec,
        scope.actor(),
        "SELECT drive_has_admin_perm($1,'drive.view') OR drive_has_admin_perm($1,'drive.manage')",
        &[(&user, Type::INT8)],
    )
    .await
    .is_ok_and(|r| r.first().and_then(|row| row.try_get::<_, bool>(0).ok()) == Some(true))
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
        let tokens = super::push_tokens(exec, scope).await;
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
