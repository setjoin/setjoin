//! JMAP RFC 8620 EventSource transport. Shares identity, state and connections with WS.
use super::{push::WebSocketRoute, token::KeySource, JmapCommands};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::{BodyExt, StreamBody};
use hyper::{Method, Request, Response, StatusCode};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{MailboxAuthContext, Type};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

pub struct EventSourceRoute<K: KeySource + 'static> {
    pub commands: Arc<JmapCommands<K>>,
    pub hub: Arc<super::hub::PushHub>,
    pub registry: setjoin_jmap::connections::ConnectionRegistry,
    clients: Arc<AtomicUsize>,
    max_clients: usize,
    production: bool,
    allowed_host: String,
}
impl<K: KeySource + 'static> EventSourceRoute<K> {
    pub fn new(ws: &WebSocketRoute<K>) -> Self {
        Self {
            commands: ws.commands.clone(),
            hub: ws.hub.clone(),
            registry: ws.registry.clone(),
            clients: ws.clients.clone(),
            max_clients: ws.max_clients,
            production: ws.production,
            allowed_host: ws.allowed_host.clone(),
        }
    }
}
impl<K: KeySource + 'static> Intercept for EventSourceRoute<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD) && r.uri().path() == "/jmap/eventsource"
    }
    fn shutdown(&self) {
        self.registry.shutdown();
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.commands.clone();
        let hub = self.hub.clone();
        let registry = self.registry.clone();
        let clients = self.clients.clone();
        let max = if self.max_clients == 0 {
            1000
        } else {
            self.max_clients
        };
        let production = self.production;
        let allowed_host = self.allowed_host.clone();
        Box::pin(async move {
            let write_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            let bearer = r
                .headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer "))
                .map(str::to_owned);
            let from_cookie = bearer.is_none();
            let token = bearer.or_else(|| super::push::cookie(r.headers()));
            let Some(token) = token.filter(|s| !s.is_empty()) else {
                return super::push::plain(
                    &r,
                    &c,
                    StatusCode::UNAUTHORIZED,
                    "missing access_token\n",
                );
            };
            // Only the selected credential chooses the unported #331 profile.
            // An unused ambient cookie must not redirect a verified Bearer request.
            let mut selected = hyper::HeaderMap::new();
            if let Ok(value) = format!("Bearer {token}").parse() {
                selected.insert("authorization", value);
                if super::push::unported_identity(&selected) {
                    return c.upstream.forward(r, &c.identity).await;
                }
            }
            let authenticated = setjoin_authz::push::authenticate_detailed(
                &commands.exec,
                &commands.keys,
                &commands.issuer,
                &token,
            )
            .await;
            match &authenticated {
                Err(setjoin_authz::push::PushAuthError::GuestInactive) => {
                    return super::push::problem_response(&r, &c, 401, "Unauthorized", "")
                }
                Err(setjoin_authz::push::PushAuthError::GuestUnavailable) => {
                    return super::push::problem_response(&r, &c, 503, "service unavailable", "")
                }
                Ok(identity)
                    if identity.is_guest()
                        && !super::push::enabled(&commands.exec, "feature.guest_accounts")
                            .await =>
                {
                    return super::push::plain(
                        &r,
                        &c,
                        StatusCode::NOT_FOUND,
                        "404 page not found\n",
                    )
                }
                _ => {}
            }
            if from_cookie {
                let host = r
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                let allowed = match r.headers().get("origin").and_then(|h| h.to_str().ok()) {
                    None | Some("") => !production,
                    Some(origin) => super::push::origin_host(origin).is_some_and(|h| {
                        h == host
                            || (!allowed_host.is_empty() && h.eq_ignore_ascii_case(&allowed_host))
                    }),
                };
                if !allowed {
                    return super::push::plain(
                        &r,
                        &c,
                        StatusCode::FORBIDDEN,
                        "origin not allowed\n",
                    );
                }
            }
            let Ok(auth) = authenticated else {
                return super::push::plain(&r, &c, StatusCode::UNAUTHORIZED, "invalid token\n");
            };
            if super::push::cache_denies(&commands, &auth)
                || setjoin_authz::push::revoked(&commands.exec, &auth).await
            {
                return super::push::plain(&r, &c, StatusCode::UNAUTHORIZED, "invalid token\n");
            }
            let over = clients.fetch_add(1, Ordering::SeqCst) >= max;
            let permit = super::push::Permit(clients);
            if over {
                return super::push::plain(
                    &r,
                    &c,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "too many connections\n",
                );
            }
            let user = auth.user_id();
            let Ok(actor) = ActorId::new(user) else {
                return super::push::plain(&r, &c, StatusCode::FORBIDDEN, "no primary mailbox\n");
            };
            let mailbox = if auth.is_guest() {
                None
            } else {
                commands
                    .exec
                    .read(
                        "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary LIMIT 1",
                        &[(&user, Type::INT8)],
                    )
                    .await
                    .ok()
                    .and_then(|r| r.first().map(|r| r.get::<_, i64>(0)))
            };
            if !auth.is_guest() && mailbox.is_none() {
                return super::push::plain(&r, &c, StatusCode::FORBIDDEN, "no primary mailbox\n");
            }
            let scope = mailbox
                .and_then(|m| MailboxId::new(m).ok())
                .map(|m| MailboxAuthContext::from_authenticated_session(actor, m, Generation(1)));
            let mut channels = Vec::new();
            if let Some(mailbox) = mailbox {
                channels.extend(
                    ["tag", "calendar", "contact", "task"].map(|p| format!("{p}:{mailbox}")),
                );
            }
            channels.push("session_revoke".into());
            for (app, prefix) in [("drive", "drive-watch"), ("chat", "chat"), ("meet", "meet")] {
                if super::push::app_allowed(&commands.exec, &auth, app).await {
                    channels.push(format!("{prefix}:{user}"));
                }
            }
            if super::push::app_allowed(&commands.exec, &auth, "drive").await
                && drive_admin(&commands.exec, actor).await
            {
                channels.push("drive-alarm".into());
            }
            let subscription = hub.subscribe(channels.clone()).await;
            let (close, mut closed) = tokio::sync::watch::channel(false);
            let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                let _ = close.send(true);
            });
            let connection = registry.register(
                user,
                mailbox,
                channels.contains(&format!("chat:{user}")),
                close.clone(),
            );
            let session = commands.denylist.as_ref().and_then(|d| {
                chrono::DateTime::from_timestamp(auth.issued_at(), 0).map(|iat| {
                    d.register_session(user, iat, auth.token_id(), auth.token_family(), close)
                })
            });
            if *closed.borrow()
                || super::push::cache_denies(&commands, &auth)
                || setjoin_authz::push::revoked(&commands.exec, &auth).await
            {
                return super::push::plain(&r, &c, StatusCode::UNAUTHORIZED, "invalid token\n");
            }
            let filter_raw = query(r.uri().query().unwrap_or(""), "types");
            let filter: Option<HashSet<String>> =
                if filter_raw.trim().is_empty() || filter_raw.trim() == "*" {
                    None
                } else {
                    Some(
                        filter_raw
                            .split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    )
                };
            let ping_secs = query(r.uri().query().unwrap_or(""), "ping")
                .parse::<i64>()
                .unwrap_or(0);
            let ping_nanos = ping_secs.wrapping_mul(1_000_000_000);
            let mut initial = String::new();
            if let Some(scope) = &scope {
                let tokens = setjoin_jmap::push_state::tokens(&commands.exec, scope).await;
                let data = serde_json::json!({"@type":"StateChange","changed":{scope.mailbox().decimal():{"Email":tokens[0],"Mailbox":tokens[1],"Thread":tokens[2],"Calendar":tokens[3],"CalendarEvent":tokens[3],"Contact":tokens[4],"Task":tokens[5]}}});
                initial = state_event(&data.to_string(), filter.as_ref()).unwrap_or_default();
            }
            let close_after = query(r.uri().query().unwrap_or(""), "closeafter") == "state";
            let (send, receive) = tokio::sync::mpsc::channel::<
                Result<hyper::body::Frame<bytes::Bytes>, crate::BoxError>,
            >(1);
            let aborted = Arc::new(AtomicBool::new(false));
            let output = StreamOutput {
                send,
                deadline: write_deadline,
                aborted: aborted.clone(),
            };
            let task = tokio::spawn(async move {
                let (_permit, _connection, _session) = (permit, connection, session);
                let Ok(mut subscription) = subscription else {
                    return;
                };
                if !initial.is_empty() && !write(&output, &mut closed, initial).await {
                    return;
                }
                if close_after {
                    return;
                }
                if ping_secs > 0 && ping_nanos <= 0 {
                    let _ = output
                        .send
                        .send(Err(
                            std::io::Error::other("non-positive ping interval").into()
                        ))
                        .await;
                    return;
                }
                let mut ping = if ping_secs > 0 {
                    let duration = Duration::from_nanos(ping_nanos as u64);
                    let mut timer =
                        tokio::time::interval_at(tokio::time::Instant::now() + duration, duration);
                    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    Some(timer)
                } else {
                    None
                };
                let mut revalidate = tokio::time::interval_at(
                    tokio::time::Instant::now() + Duration::from_secs(300),
                    Duration::from_secs(300),
                );
                revalidate.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    let event = tokio::select! {
                        _=output.send.closed()=>break,
                        _=closed.changed()=>break,
                        _=revalidate.tick()=>{
                            if chrono::Utc::now().timestamp()>=auth.expires_at(){break}
                            let mut allowed=true;
                            for channel in &channels {
                                let app=if channel.starts_with("chat:"){Some("chat")}else if channel.starts_with("meet:"){Some("meet")}else if channel.starts_with("drive-"){Some("drive")}else{None};
                                if let Some(app)=app {allowed &=super::push::app_allowed(&commands.exec,&auth,app).await;}
                            }
                            if channels.iter().any(|c|c=="drive-alarm"){allowed &=drive_admin(&commands.exec,actor).await;}
                            if !allowed{break}continue
                        },
                        _=async {match &mut ping {Some(timer)=>{timer.tick().await;},None=>std::future::pending().await}}=>{if !write(&output,&mut closed,format!("event: ping\ndata: {{\"interval\":{ping_secs}}}\n\n")).await{break}continue},
                        event=subscription.events.recv()=>match event {Some(e)=>e,None=>break},
                    };
                    if event.channel == "session_revoke" {
                        if super::push::revoked_payload(&event.payload, &auth) {
                            break;
                        }
                        continue;
                    }
                    if ["tag:", "calendar:", "contact:", "task:"]
                        .iter()
                        .any(|p| event.channel.starts_with(p))
                    {
                        let mut batch = vec![event.payload];
                        let end = tokio::time::Instant::now() + Duration::from_millis(20);
                        let mut pending = Vec::new();
                        loop {
                            tokio::select! {
                                _=output.send.closed()=>return,
                                _=closed.changed()=>return,
                                _=tokio::time::sleep_until(end)=>break,
                                next=subscription.events.recv()=>match next {
                                    Some(e) if e.channel=="session_revoke"=>{if super::push::revoked_payload(&e.payload,&auth){return}},
                                    Some(e) if ["tag:","calendar:","contact:","task:"].iter().any(|p|e.channel.starts_with(p))=>batch.push(e.payload),
                                    Some(e)=>{let cap=if e.channel=="drive-alarm"{8}else{16};if pending.iter().filter(|p:&&super::hub::Event|p.channel==e.channel).count()<cap{pending.push(e)}},None=>return,
                                }
                            }
                        }
                        if let Some(scope) = &scope {
                            for frame in
                                super::push::state_frames(&commands.exec, scope, &batch).await
                            {
                                if frame.starts_with("{\"@type\":\"StateChange\"") {
                                    if let Some(event) = state_event(&frame, filter.as_ref()) {
                                        if !write(&output, &mut closed, event).await {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        for e in pending {
                            if let Some(frame) = raw(&e) {
                                if !write(&output, &mut closed, frame).await {
                                    return;
                                }
                            }
                        }
                    } else if let Some(frame) = raw(&event) {
                        if !write(&output, &mut closed, frame).await {
                            break;
                        }
                    }
                }
            });
            let stream = futures_util::stream::unfold(
                (receive, StreamTask(task), aborted, false),
                |(mut receive, task, aborted, done)| async move {
                    if done {
                        return None;
                    }
                    match receive.recv().await {
                        Some(frame) => Some((frame, (receive, task, aborted, false))),
                        None if aborted.load(Ordering::SeqCst) => Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "SSE write deadline expired",
                            )
                            .into()),
                            (receive, task, aborted, true),
                        )),
                        None => None,
                    }
                },
            );
            let mut nonce = [0; 16];
            let _ = getrandom::getrandom(&mut nonce);
            let id = super::reply::request_id(r.headers().get("x-request-id"), nonce);
            let mut response = super::reply::response(String::new(), c.identity.proto, id);
            *response.body_mut() = StreamBody::new(stream).boxed();
            for (key, value) in [
                ("content-type", "text/event-stream"),
                ("cache-control", "no-cache"),
                ("connection", "keep-alive"),
                ("x-accel-buffering", "no"),
            ] {
                response.headers_mut().insert(key, value.parse().unwrap());
            }
            response
        })
    }
}

struct StreamTask(tokio::task::JoinHandle<()>);
impl Drop for StreamTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
type StreamFrame = Result<hyper::body::Frame<bytes::Bytes>, crate::BoxError>;
struct StreamOutput {
    send: tokio::sync::mpsc::Sender<StreamFrame>,
    deadline: tokio::time::Instant,
    aborted: Arc<AtomicBool>,
}
impl Drop for StreamOutput {
    fn drop(&mut self) {
        if tokio::time::Instant::now() >= self.deadline {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }
}
async fn write(
    output: &StreamOutput,
    closed: &mut tokio::sync::watch::Receiver<bool>,
    data: String,
) -> bool {
    if *closed.borrow() || tokio::time::Instant::now() >= output.deadline {
        return false;
    }
    tokio::select! {
     biased;
     _=tokio::time::sleep_until(output.deadline)=>false,
     _=closed.changed()=>false,
     result=output.send.send(Ok(hyper::body::Frame::data(bytes::Bytes::from(data))))=>result.is_ok(),
    }
}
async fn drive_admin(exec: &setjoin_pg::ScopedExecutor, actor: ActorId) -> bool {
    exec.read_user_scoped(
        actor,
        "SELECT drive_has_admin_perm($1,'drive.view') OR drive_has_admin_perm($1,'drive.manage')",
        &[(&actor.get(), Type::INT8)],
    )
    .await
    .is_ok_and(|r| r[0].get::<_, bool>(0))
}

fn raw(event: &super::hub::Event) -> Option<String> {
    let name = if event.channel.starts_with("chat:") {
        "chat"
    } else if event.channel.starts_with("meet:") {
        "meet"
    } else if event.channel == "drive-alarm" {
        "drive-alarm"
    } else if event.channel.starts_with("drive-watch:") {
        "drive-watch"
    } else {
        return None;
    };
    let data = serde_json::from_str::<&serde_json::value::RawValue>(&event.payload).ok()?;
    Some(format!("event: {name}\ndata: {}\n\n", data.get()))
}
fn query(raw: &str, key: &str) -> String {
    for field in raw.split('&') {
        if field.contains(';') {
            continue;
        }
        let b = field.as_bytes();
        let mut i = 0;
        let mut valid = true;
        while i < b.len() {
            if b[i] == b'%' {
                if i + 2 >= b.len()
                    || !b[i + 1].is_ascii_hexdigit()
                    || !b[i + 2].is_ascii_hexdigit()
                {
                    valid = false;
                    break;
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        if !valid {
            continue;
        }
        if let Some((k, v)) = url::form_urlencoded::parse(field.as_bytes()).next() {
            if k == key {
                return v.into_owned();
            }
        }
    }
    String::new()
}

fn state_event(frame: &str, filter: Option<&HashSet<String>>) -> Option<String> {
    let mut data: serde_json::Value = serde_json::from_str(frame).ok()?;
    let accounts = data.get_mut("changed")?.as_object_mut()?;
    for changed in accounts.values_mut() {
        let changed = changed.as_object_mut()?;
        if let Some(filter) = filter {
            changed.retain(|k, _| filter.contains(k));
        }
        if changed.is_empty() {
            return None;
        }
    }
    Some(format!("event: state\ndata: {data}\n\n"))
}
