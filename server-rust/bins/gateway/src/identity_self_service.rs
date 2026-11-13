//! Mailserver-local F21 self-service HTTP boundary (#494).
use crate::mailboxes::{bare, body, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use serde_json::json;
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

/// Owner-approved security fix 2026-11-05 (#547): every self-service JSON body (test-imap,
/// migration start, webhook, app password, read receipt) is read through this cap. Frozen Go's
/// decoders had none.
pub const BODY_CAP: usize = 1 << 20;
pub(crate) fn body_cap() -> usize {
    if setjoin_contracts::mutants::on("self-service-body-uncapped") {
        usize::MAX
    } else {
        BODY_CAP
    }
}

/// Resolves a webhook URL's host at registration (#547). Delivery still dials through
/// `PublicOnly`; this refuses a name that points inside before it is stored.
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: String) -> BoxFuture<Option<Vec<std::net::IpAddr>>>;
}
/// The system resolver, five seconds at most.
pub struct SystemResolver;
impl HostResolver for SystemResolver {
    fn resolve(&self, host: String) -> BoxFuture<Option<Vec<std::net::IpAddr>>> {
        Box::pin(async move {
            let found = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 0)),
            )
            .await
            .ok()?
            .ok()?;
            Some(found.map(|a| a.ip()).collect())
        })
    }
}
/// A name must resolve, and every address it resolves to must be public; a literal IP was
/// already judged by `valid_public_http`.
async fn resolves_public(resolver: &dyn HostResolver, url: &str) -> bool {
    if setjoin_contracts::mutants::on("webhook-register-no-dns") {
        return true;
    }
    let Ok(host) = setjoin_authz::go_url::parse_url_host(url) else {
        return false;
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    match resolver.resolve(host).await {
        Some(ips) if !ips.is_empty() => ips.into_iter().all(|ip| !setjoin_authz::ssrf::blocked(ip)),
        _ => false,
    }
}

pub struct IdentitySelfServiceRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    /// Dedicated DB_WORKER_DSN pool for delegate-side ownership reads.
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// Go-compatible webhook secret custody, shared with the delivery runtime.
    pub webhook_codec: setjoin_platform::webhook_secret::SecretCodec,
    pub migration_runner: Option<crate::migration::Runner>,
    /// Registration-time DNS check for webhook URLs (#547).
    pub webhook_resolver: Arc<dyn HostResolver>,
}

#[derive(Default)]
struct WebhookBody {
    url:String,
    events:Vec<Option<String>>,
    scope:String,
}
impl<'de> serde::Deserialize<'de> for WebhookBody {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value=WebhookBody;
            fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str("a JSON object")}
            fn visit_unit<E:serde::de::Error>(self)->Result<WebhookBody,E> {Ok(WebhookBody::default())}
            fn visit_map<M:MapAccess<'de>>(self,mut map:M)->Result<WebhookBody,M::Error> {
                let mut body=WebhookBody::default();
                while let Some(key)=map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "url"=>if let Some(value)=map.next_value::<Option<String>>()? {body.url=value;},
                        // Go JSON null clears a slice, including a duplicate
                        // field that previously supplied a nonempty array.
                        "eventtypes"=>body.events=map.next_value::<Option<Vec<Option<String>>>>()?.unwrap_or_default(),
                        "scope"=>if let Some(value)=map.next_value::<Option<String>>()? {body.scope=value;},
                        _=>{let _:serde::de::IgnoredAny=map.next_value()?;}
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

body!(ReadReceiptBody {
    message: String = "messageid",
    consent: bool = "consent"
});

body!(AppCreateBody {
    name: String = "name",
    label: String = "label"
});

#[derive(Default)]
struct DlpBody {
    recipients: Option<Vec<Option<String>>>,
    subject: String,
    text: String,
    html: String,
}
impl<'de> serde::Deserialize<'de> for DlpBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = DlpBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<DlpBody, E> {
                Ok(DlpBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<DlpBody, M::Error> {
                let mut body = DlpBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "recipients" => body.recipients = map.next_value()?,
                        "subject" => {
                            if let Some(value) = map.next_value::<Option<String>>()? {
                                body.subject = value;
                            }
                        }
                        "bodytext" => {
                            if let Some(value) = map.next_value::<Option<String>>()? {
                                body.text = value;
                            }
                        }
                        "bodyhtml" => {
                            if let Some(value) = map.next_value::<Option<String>>()? {
                                body.html = value;
                            }
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

impl<K: KeySource + 'static> Intercept for IdentitySelfServiceRoute<K> {
    fn requires_session(&self, _: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        let path = r.uri().path();
        crate::identity_migration::matches(r)
            || crate::identity_smime::matches(r)
            || (matches!(*r.method(), Method::GET | Method::HEAD)
            && (crate::inventory::path_score("/auth/me/org-chart", path).is_some()
                || crate::inventory::path_score("/auth/me/webhooks", path).is_some()
                || crate::inventory::path_score("/auth/me/mailtips", path).is_some()))
            || (*r.method() == Method::POST
                && (crate::inventory::path_score("/auth/me/dlp-check", path).is_some()
                    || crate::inventory::path_score("/auth/me/read-receipt", path).is_some()))
            || (matches!(*r.method(), Method::GET | Method::HEAD | Method::POST)
                && (crate::inventory::path_score("/auth/me/app-passwords", path).is_some()
                    || crate::inventory::path_score("/auth/me/webhooks", path).is_some()))
            || (*r.method() == Method::DELETE
                && (crate::inventory::path_score("/auth/me/app-passwords/{id}", path).is_some()
                    || crate::inventory::path_score("/auth/me/webhooks/{id}", path).is_some()))
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_mailserver_identity_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let worker = self.worker.clone();
        let webhook_codec = self.webhook_codec.clone();
        let migration_runner = self.migration_runner.clone();
        let resolver = self.webhook_resolver.clone();
        Box::pin(async move {
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let admission=if crate::identity_migration::matches(&r) {
                setjoin_authz::authorize_mailserver_identity_request(&exec,&keys,&issuer,r.headers(),c.identity.proto).await
            }else{
                setjoin_authz::authorize_request(&exec,&keys,&issuer,r.headers(),c.identity.proto).await
            };
            let Some(auth)=admission else {return bare(401,"Unauthorized",&c,&id);};
            if crate::identity_migration::matches(&r) {
                return crate::identity_migration::handle(&exec,auth.context(),r,&c,id,operation,migration_runner.as_ref()).await;
            }
            if crate::identity_smime::matches(&r) {
                return crate::identity_smime::handle(&exec, auth.context(), r, &c, id, operation).await;
            }
            if crate::inventory::path_score("/auth/me/webhooks/{id}", r.uri().path()).is_some() {
                // Frozen Go ignores ParseInt's error (including saturation).
                let target = crate::admin_identity_input::atoi(&crate::mailboxes::segment(r.uri().path(), 4));
                return match setjoin_identity::self_service::webhook_delete(
                    &exec, auth.context(), target, operation,
                ).await {
                    CommandOutcome::Committed(true) => {
                        let mut reply = crate::jmap::reply::response(String::new(), c.identity.proto, id);
                        *reply.status_mut() = hyper::StatusCode::NO_CONTENT;
                        reply.headers_mut().remove(hyper::header::CONTENT_TYPE);
                        reply
                    }
                    CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                    // Go discards the SQL error and inspects an empty command tag.
                    _ => bare(404, "not found", &c, &id),
                };
            }
            if crate::inventory::path_score("/auth/me/webhooks", r.uri().path()).is_some() {
                if r.method() == Method::POST {
                    // `requireWebhookCap` runs after auth and before the handler reads the body.
                    match setjoin_identity::self_service::webhook_count(&exec, auth.context()).await {
                        Err(_) => return bare(503, "unable to verify webhook subscription budget", &c, &id),
                        Ok(n) if n >= setjoin_identity::self_service::MAX_WEBHOOK_SUBSCRIPTIONS_PER_USER => {
                            return bare(
                                409,
                                &format!(
                                    "webhook subscription limit reached ({}); remove one before creating another",
                                    setjoin_identity::self_service::MAX_WEBHOOK_SUBSCRIPTIONS_PER_USER
                                ),
                                &c, &id,
                            );
                        }
                        Ok(_) => {}
                    }
                    let Ok(input) = crate::admin_identity_input::first::<WebhookBody>(&mut r, body_cap()).await else {
                        return bare(400, "url and eventTypes required", &c, &id);
                    };
                    if input.url.is_empty() || input.events.is_empty() {
                        return bare(400, "url and eventTypes required", &c, &id);
                    }
                    if !input.scope.is_empty() && input.scope != "self" {
                        return bare(400, "self-service webhooks require self scope", &c, &id);
                    }
                    let events = input.events.into_iter().map(Option::unwrap_or_default).collect::<Vec<_>>();
                    let mut seen = std::collections::HashSet::new();
                    for event in &events {
                        if !setjoin_platform::webhooks::is_known_event_type(event) {
                            return bare(400, "unknown event type", &c, &id);
                        }
                        if !seen.insert(event) {
                            return bare(400, "duplicate event type", &c, &id);
                        }
                    }
                    if !setjoin_authz::ssrf::valid_public_http(&input.url)
                        || !resolves_public(&*resolver, &input.url).await
                    {
                        return bare(400, "webhook URL must be http(s) and point to a public host", &c, &id);
                    }
                    let Ok(secret) = setjoin_platform::webhook_secret::generate_secret() else {
                        return bare(500, "secret sealing failed", &c, &id);
                    };
                    let Ok(sealed) = webhook_codec.seal(&secret) else {
                        return bare(500, "secret sealing failed", &c, &id);
                    };
                    return match setjoin_identity::self_service::webhook_create(
                        &exec, auth.context(), &input.url, &json!(events).to_string(),
                        &sealed, webhook_codec.active_key_id(), operation,
                    ).await {
                        CommandOutcome::Committed(created) => {
                            let body = setjoin_identity::issuance::object(&[
                                ("id", json!(created)), ("scope", json!("self")),
                                ("secret", json!(secret)), ("url", json!(input.url)),
                            ]) + "\n";
                            let mut response = crate::jmap::reply::response(body, c.identity.proto, id);
                            *response.status_mut() = hyper::StatusCode::CREATED;
                            response
                        }
                        CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                        _ => bare(500, "create failed", &c, &id),
                    };
                }
                return match setjoin_identity::self_service::webhooks(&exec, auth.context()).await {
                    Ok(body) => crate::jmap::reply::response(body, c.identity.proto, id),
                    Err(_) => bare(500, "database error", &c, &id),
                };
            }
            if crate::inventory::path_score("/auth/me/read-receipt", r.uri().path()).is_some() {
                let Ok(input) =
                    crate::admin_identity_input::first::<ReadReceiptBody>(&mut r, body_cap()).await
                else {
                    return bare(400, "invalid body", &c, &id);
                };
                // ParseInt's ignored range error saturates a positive overflow.
                let message = crate::admin_identity_input::atoi(&input.message);
                if message <= 0 {
                    return bare(400, "invalid messageId", &c, &id);
                }
                return match setjoin_identity::self_service::read_receipt(
                    &exec,
                    auth.context(),
                    message,
                    input.consent,
                    operation,
                )
                .await
                {
                    Some(CommandOutcome::Committed(body)) => {
                        crate::jmap::reply::response(body, c.identity.proto, id)
                    }
                    Some(CommandOutcome::Unknown { operation }) => {
                        unknown_outcome(operation, &c, &id)
                    }
                    _ => bare(500, "database error", &c, &id),
                };
            }
            if crate::inventory::path_score("/auth/me/mailtips", r.uri().path()).is_some() {
                let recipients =
                    crate::admin_identity_input::query(r.uri(), "recipients").unwrap_or_default();
                let from = crate::admin_identity_input::query(r.uri(), "from").unwrap_or_default();
                let body = setjoin_identity::self_service::mailtips(
                    &exec,
                    &worker,
                    auth.context(),
                    &recipients,
                    &from,
                )
                .await;
                return crate::jmap::reply::response(body, c.identity.proto, id);
            }
            if crate::inventory::path_score("/auth/me/org-chart", r.uri().path()).is_some() {
                let mut target = auth.context().user_id();
                if let Some(raw) =
                    crate::admin_identity_input::query(r.uri(), "userId").filter(|s| !s.is_empty())
                {
                    if !auth
                        .context()
                        .has_permission(&exec, "users.read")
                        .await
                        .unwrap_or(false)
                    {
                        return bare(403, "users.read permission required", &c, &id);
                    }
                    // fmt.Sscanf(%d) accepts leading space and a decimal prefix.
                    let raw = raw.trim_start_matches(|ch: char| ch != '\n' && ch.is_whitespace());
                    let offset = usize::from(raw.starts_with(['+', '-']));
                    let end = offset
                        + raw.as_bytes()[offset..]
                            .iter()
                            .take_while(|b| b.is_ascii_digit())
                            .count();
                    let Ok(parsed) = raw[..end].parse::<i64>() else {
                        return bare(400, "invalid userId", &c, &id);
                    };
                    target = parsed;
                }
                return match setjoin_identity::self_service::org_chart(
                    &exec,
                    auth.context(),
                    target,
                )
                .await
                {
                    Some(body) => crate::jmap::reply::response(body, c.identity.proto, id),
                    None => bare(
                        403,
                        "cannot view org chart for users in other domains",
                        &c,
                        &id,
                    ),
                };
            }
            if crate::inventory::path_score("/auth/me/dlp-check", r.uri().path()).is_some() {
                use setjoin_identity::self_service as db;
                if !db::advisory_enabled(&exec, "feature.dlp").await {
                    return crate::jmap::reply::response(
                        "{\"violated\":false}\n".into(),
                        c.identity.proto,
                        id,
                    );
                }
                let Ok(input) =
                    crate::admin_identity_input::first::<DlpBody>(&mut r, 2 << 20).await
                else {
                    return bare(400, "invalid body", &c, &id);
                };
                let Some(mailbox) = db::primary_mailbox(&exec, auth.context()).await else {
                    return bare(500, "database error", &c, &id);
                };
                let recipients = input.recipients.map(|xs| {
                    xs.into_iter()
                        .map(Option::unwrap_or_default)
                        .collect::<Vec<_>>()
                });
                let body = db::dlp_check(
                    &exec,
                    auth.context(),
                    mailbox,
                    &json!(recipients).to_string(),
                    &input.subject,
                    &input.text,
                    &input.html,
                )
                .await
                .unwrap_or_else(|| "{\"violated\":false}\n".into());
                return crate::jmap::reply::response(body, c.identity.proto, id);
            }
            if r.method() == Method::DELETE {
                let Ok(target) = crate::mailboxes::segment(r.uri().path(), 4).parse::<i64>() else {
                    return bare(400, "invalid id", &c, &id);
                };
                return match setjoin_identity::self_service::app_password_revoke(
                    &exec,
                    auth.context(),
                    target,
                    operation,
                )
                .await
                {
                    CommandOutcome::Committed(true) => {
                        let mut reply =
                            crate::jmap::reply::response(String::new(), c.identity.proto, id);
                        *reply.status_mut() = hyper::StatusCode::NO_CONTENT;
                        reply.headers_mut().remove(hyper::header::CONTENT_TYPE);
                        reply
                    }
                    CommandOutcome::Committed(false) => bare(404, "not found", &c, &id),
                    CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                    CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                };
            }
            if r.method() == Method::POST {
                // Go accepts the first value; the body is capped (#547).
                let Ok(input) =
                    crate::admin_identity_input::first::<AppCreateBody>(&mut r, body_cap()).await
                else {
                    return bare(400, "name is required", &c, &id);
                };
                if input.name.is_empty() {
                    return bare(400, "name is required", &c, &id);
                }
                let Ok(outcome) = setjoin_identity::self_service::app_password_create(
                    &exec,
                    auth.context(),
                    &input.name,
                    &input.label,
                    operation,
                )
                .await
                else {
                    return bare(500, "token generation failed", &c, &id);
                };
                return match outcome {
                    CommandOutcome::Committed(token) => {
                        let body = setjoin_identity::issuance::object(&[
                            ("name", json!(input.name)),
                            ("token", json!(token)),
                        ]) + "\n";
                        let mut reply = crate::jmap::reply::response(body, c.identity.proto, id);
                        *reply.status_mut() = hyper::StatusCode::CREATED;
                        reply
                    }
                    CommandOutcome::RolledBack(Rejection::Statement(error))
                        if error.sqlstate.as_deref() == Some("BZ015") =>
                    {
                        bare(409, "maximum 10 app passwords reached", &c, &id)
                    }
                    CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                    CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                };
            }
            match setjoin_identity::self_service::app_passwords(&exec, auth.context()).await {
                Ok(body) => crate::jmap::reply::response(body, c.identity.proto, id),
                Err(_) => bare(500, "database error", &c, &id),
            }
        })
    }
}
