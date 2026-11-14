//! Chat presence: authenticated user scope, independent of mailbox ownership.
use super::{token::KeySource, JmapCommands};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response, StatusCode};
use setjoin_contracts::ids::ActorId;
use setjoin_jmap::connections::ConnectionRegistry;
use setjoin_pg::Type;
use std::{collections::HashSet, sync::Arc};

pub struct PresenceRoute<K: KeySource + 'static> {
    pub commands: Arc<JmapCommands<K>>,
    pub registry: ConnectionRegistry,
}
impl<K: KeySource + 'static> Intercept for PresenceRoute<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD) && r.uri().path() == "/api/chat/presence"
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.commands.clone();
        let registry = self.registry.clone();
        Box::pin(async move {
            // The shared HTTP conditional-access/device interceptor is #420's
            // unported shape. No request writes before this whole-request handoff.
            if !setjoin_authz::push::http_admission_allowed(&commands.exec).await {
                return c.upstream.forward(r, &c.identity).await;
            }
            let Some(token) = setjoin_authz::token::extract(r.headers()) else {
                return super::push::problem_response(&r, &c, 401, "Unauthorized", "");
            };
            let identity = match setjoin_authz::push::authenticate_detailed(
                &commands.exec,
                &commands.keys,
                &commands.issuer,
                &token,
            )
            .await
            {
                Ok(identity) => identity,
                Err(setjoin_authz::push::PushAuthError::GuestUnavailable) => {
                    return super::push::problem_response(&r, &c, 503, "service unavailable", "")
                }
                Err(_) => return super::push::problem_response(&r, &c, 401, "Unauthorized", ""),
            };
            if setjoin_authz::push::revoked(&commands.exec, &identity).await {
                return super::push::problem_response(&r, &c, 401, "Unauthorized", "");
            }
            if (identity.is_guest() && !enabled(&commands.exec, "feature.guest_accounts").await)
                || !enabled(&commands.exec, "feature.chat").await
            {
                return super::push::plain(&r, &c, StatusCode::NOT_FOUND, "404 page not found\n");
            }
            let user = identity.user_id();
            let Ok(actor) = ActorId::new(user) else {
                return super::push::problem_response(&r, &c, 401, "Unauthorized", "");
            };
            let mut nonce = [0; 16];
            let _ = getrandom::getrandom(&mut nonce);
            let id = super::reply::request_id(r.headers().get("x-request-id"), nonce);
            let language = crate::chat_channels::problem_language(r.headers());
            if !commands
                .exec
                .read(
                    "SELECT check_user_app_entitlement($1,'chat')",
                    &[(&user, Type::INT8)],
                )
                .await
                .is_ok_and(|r| r[0].get::<_, bool>(0))
            {
                let _ = commands
                    .exec
                    .audit_app_blocked(actor, "chat", &c.identity.client_ip.to_string())
                    .await;
                let body = crate::problem::Problem::new(
                    403,
                    "Access to this application is not permitted for your account.",
                )
                .kind("https://setjoin.com/errors/forbidden")
                .instance("/chat/presence")
                .body();
                let mut response = super::reply::response(body, c.identity.proto, id);
                *response.status_mut() = StatusCode::FORBIDDEN;
                response
                    .headers_mut()
                    .insert("content-type", "application/problem+json".parse().unwrap());
                response
                    .headers_mut()
                    .insert("content-language", language.parse().unwrap());
                return response;
            }
            let raw = query(r.uri().query().unwrap_or(""));
            let mut ids = Vec::new();
            let mut keys = Vec::new();
            for key in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let Ok(value) = key.parse::<i64>() else {
                    return crate::chat_channels::problem(
                        400,
                        "invalid userIds",
                        "/chat/presence",
                        &c,
                        id,
                        &language,
                    );
                };
                ids.push(value);
                keys.push(key.to_owned());
            }
            let mut admitted = HashSet::new();
            if identity.is_guest() && !ids.is_empty() {
                match commands.exec.read_user_scoped(actor,"SELECT DISTINCT m2.user_id FROM chat_channel_members m1 JOIN chat_channel_members m2 ON m2.channel_id=m1.channel_id WHERE m1.user_id=$1 AND m2.user_id=ANY($2)",&[(&user,Type::INT8),(&ids,Type::INT8_ARRAY)]).await {
                    Ok(rows)=>{admitted.extend(rows.iter().map(|r|r.get::<_,i64>(0)));},
                    Err(_)=>return crate::chat_channels::problem(500,"presence scope lookup failed","/chat/presence",&c,id,&language),
                }
            }
            let mut out = serde_json::Map::new();
            for (key, user) in keys.into_iter().zip(ids) {
                out.insert(
                    key,
                    serde_json::Value::Bool(
                        (!identity.is_guest() || admitted.contains(&user))
                            && registry.is_online(user),
                    ),
                );
            }
            super::reply::response(
                serde_json::Value::Object(out).to_string() + "\n",
                c.identity.proto,
                id,
            )
        })
    }
}

/// Go's URL.Query discards an invalid pair while retaining other pairs.
fn query(raw: &str) -> String {
    for field in raw.split('&') {
        if field.contains(';') || !valid_escapes(field.as_bytes()) {
            continue;
        }
        if let Some((key, value)) = url::form_urlencoded::parse(field.as_bytes()).next() {
            if key == "userIds" {
                return value.into_owned();
            }
        }
    }
    String::new()
}
fn valid_escapes(bytes: &[u8]) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            if at + 2 >= bytes.len() || !bytes[at + 1..at + 3].iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            at += 3;
        } else {
            at += 1
        }
    }
    true
}

async fn enabled(exec: &setjoin_pg::ScopedExecutor, key: &str) -> bool {
    exec.read(
        "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
        &[(&key, Type::TEXT)],
    )
    .await
    .is_ok_and(|r| r[0].get::<_, bool>(0))
}
