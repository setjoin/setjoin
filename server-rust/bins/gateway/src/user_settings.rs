//! F19 User mail settings and profile HTTP adapter. The four-slice map and each slice's
//! contract live in the `setjoin-user-settings` DOX. Every route here is gated by Go's
//! `requireAuth` only: the verified token's user is the one principal, and path ids, query
//! strings and bodies name targets but never grant authority. A missing or failed token
//! check forwards the untouched request to Go, as every family adapter does, so Go keeps
//! answering 401 and any state it alone can judge.
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use setjoin_user_settings::{prefs, profile, security, settings as db, sync};
use std::fmt;
use std::sync::Arc;

pub struct UserSettingsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

impl<K: KeySource + 'static> UserSettingsRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self { exec, keys, issuer }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    ImapGet,
    ImapPut,
    ViewGet,
    ViewPut,
    UndoGet,
    UndoPut,
    NewsletterGet,
    NewsletterPut,
    SignatureList,
    SignaturePut,
    SignatureDelete,
    NotificationGet,
    NotificationPut,
    VipGet,
    VipPut,
    VacationGet,
    VacationPut,
    DelegationGet,
    DelegationPut,
    SyncPut,
    SessionsList,
    SessionRevoke,
    SessionsRevokeAll,
    DevicesList,
    LoginHistory,
    SecureAccount,
    SecurityScore,
    ProfileUpdate,
    QuotaGet,
}

/// Method/pattern table; the first column is the method predicate. Later slices append rows.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let put = *method == Method::PUT;
    let table: [(bool, &str, Action); 29] = [
        (reads, "/api/settings/imap", Action::ImapGet),
        (put, "/api/settings/imap", Action::ImapPut),
        (reads, "/api/settings/view", Action::ViewGet),
        (put, "/api/settings/view", Action::ViewPut),
        (reads, "/api/settings/undo-send", Action::UndoGet),
        (put, "/api/settings/undo-send", Action::UndoPut),
        (
            reads,
            "/api/settings/newsletter-bundles",
            Action::NewsletterGet,
        ),
        (
            put,
            "/api/settings/newsletter-bundles",
            Action::NewsletterPut,
        ),
        (
            reads,
            "/api/settings/signatures-list",
            Action::SignatureList,
        ),
        (put, "/api/settings/signatures", Action::SignaturePut),
        (
            *method == Method::DELETE,
            "/api/settings/signatures/{id}",
            Action::SignatureDelete,
        ),
        (
            reads,
            "/api/user/notification-preferences",
            Action::NotificationGet,
        ),
        (
            put,
            "/api/user/notification-preferences",
            Action::NotificationPut,
        ),
        (reads, "/api/user/vip-senders", Action::VipGet),
        (put, "/api/user/vip-senders", Action::VipPut),
        (reads, "/api/user/automatic-replies", Action::VacationGet),
        (put, "/api/user/automatic-replies", Action::VacationPut),
        (
            reads,
            "/api/user/approval-delegation",
            Action::DelegationGet,
        ),
        (put, "/api/user/approval-delegation", Action::DelegationPut),
        (put, "/api/user/offline/sync-preferences", Action::SyncPut),
        (reads, "/api/user/sessions", Action::SessionsList),
        (
            *method == Method::DELETE,
            "/api/user/sessions/{id}",
            Action::SessionRevoke,
        ),
        (
            *method == Method::POST,
            "/api/user/sessions/revoke-all",
            Action::SessionsRevokeAll,
        ),
        (reads, "/api/user/devices", Action::DevicesList),
        (reads, "/api/user/login-history", Action::LoginHistory),
        (
            *method == Method::POST,
            "/api/user/sign-ins/secure-account",
            Action::SecureAccount,
        ),
        (reads, "/api/user/security-score", Action::SecurityScore),
        (
            *method == Method::POST,
            "/api/user/profile",
            Action::ProfileUpdate,
        ),
        (reads, "/api/user/quota", Action::QuotaGet),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

// ---- Go's `json.NewDecoder(r.Body).Decode(&v)` ----

/// A decoded struct: `null` leaves the zero value, keys match case-insensitively, a `null`
/// field keeps its zero value and unknown keys are skipped.
macro_rules! fields {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        #[allow(dead_code)]
        struct $name { $($field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<$name, E> {
                        Ok($name::default())
                    }
                    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<$name, M::Error> {
                        let mut body = $name::default();
                        while let Some(key) = map.next_key::<String>()? {
                            match crate::guests_input::fold(&key).as_str() {
                                $($key => {
                                    if let Some(value) = map.next_value::<Option<$ty>>()? {
                                        body.$field = value;
                                    }
                                })+
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
    };
}

/// `[]int64`: a `null` element is 0 (Go's zero value).
struct Ids(Vec<i64>);
impl<'de> serde::Deserialize<'de> for Ids {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let list = <Vec<Option<i64>>>::deserialize(decoder)?;
        Ok(Ids(list
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect()))
    }
}
/// `[]string`: a `null` element is "".
struct Texts(Vec<String>);
impl<'de> serde::Deserialize<'de> for Texts {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let list = <Vec<Option<String>>>::deserialize(decoder)?;
        Ok(Texts(
            list.into_iter().map(Option::unwrap_or_default).collect(),
        ))
    }
}

fields!(ImapBody {
    expose_all: Option<bool> = "exposeall",
    show_subscribed_only: Option<bool> = "showsubscribedonly",
    exposed_tag_ids: Option<Ids> = "exposedtagids",
    folder_separator: Option<String> = "folderseparator",
});
fields!(DelayBody {
    delay: i64 = "undosenddelay",
});
fields!(NewsletterBody {
    bundle: Option<bool> = "bundlenewsletters",
    lists: Option<Texts> = "optedoutlists",
});
fields!(SignatureBody {
    alias: String = "alias_email",
    html: String = "signature_html",
    text: String = "signature_text",
    is_default: String = "is_default",
    default_for: String = "default_for",
});

fields!(ProfileBody {
    display_name: String = "display_name",
});
fields!(PrefsBody {
    push_enabled: bool = "push_enabled",
    push_sound: String = "push_sound",
    stop_push: bool = "stop_push_when_desktop_online",
    dnd_start: Option<String> = "dnd_start",
    dnd_end: Option<String> = "dnd_end",
    dnd_days: i64 = "dnd_days",
    mail: String = "mail_notifications",
    calendar: bool = "calendar_reminders",
    task: bool = "task_reminders",
    policy: String = "read_receipt_policy",
    chat: String = "chat_notifications",
});
fields!(NotificationBody {
    fingerprint: Option<String> = "device_fingerprint",
    prefs: PrefsBody = "preferences",
});
fields!(VipBody {
    email: String = "email",
    vip: bool = "vip",
});
fields!(VacationBody {
    enabled: bool = "enabled",
    subject: String = "subject",
    body_internal: String = "body_internal",
    body_internal_html: String = "body_internal_html",
    body_external: String = "body_external",
    body_external_html: String = "body_external_html",
    start_date: Option<String> = "start_date",
    end_date: Option<String> = "end_date",
    external_audience: String = "external_audience",
});
fields!(DelegationBody {
    enabled: bool = "enabled",
    delegate: i64 = "delegate_user_id",
    name: String = "delegate_name",
    email: String = "delegate_email",
    starts_at: Option<String> = "starts_at",
    ends_at: Option<String> = "ends_at",
});

/// The first JSON value of the body, bounded by `cap` bytes (Go's `MaxBytesReader` or, when
/// Go reads without one, a generous bound); whatever follows the value is ignored. `None` is
/// Go's decode error.
async fn first_value(r: &mut Request<Body>, cap: usize) -> Option<Vec<u8>> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() <= cap {
        match r.body_mut().frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            Some(Err(_)) => return None,
            None => break,
        }
    }
    bytes.truncate(cap);
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut stream =
        serde_json::Deserializer::from_slice(&fixed).into_iter::<serde::de::IgnoredAny>();
    match stream.next() {
        Some(Ok(_)) => {
            let end = stream.byte_offset();
            let start = fixed
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
                .unwrap_or(0);
            Some(fixed[start..end].to_vec())
        }
        _ => None,
    }
}

async fn decode_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
    cap: usize,
) -> Option<T> {
    serde_json::from_slice(&first_value(r, cap).await?).ok()
}

/// Go's `decodeSyncPreferences`: a 4 KiB body of exactly one object whose keys are all known
/// (case-insensitively), then the value checks. `None` is any decode or validation error.
async fn sync_body(r: &mut Request<Body>) -> Option<sync::SyncPut> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.ok()?.into_data() {
            bytes.extend_from_slice(&data);
        }
        if bytes.len() > 4 << 10 {
            return None;
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<serde_json::Value>();
    let value = stream.next()?.ok()?;
    if stream.next().is_some() {
        return None;
    }
    let mut out = sync::SyncPut {
        opt_in: false,
        window_days: 0,
        background: false,
        network: String::new(),
        prefetch: String::new(),
    };
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if value.is_null() {
                    // Known or not: unknown keys fail below, null leaves the zero value.
                    if !matches!(
                        crate::guests_input::fold(&key).as_str(),
                        "optin"
                            | "windowdays"
                            | "backgroundsyncenabled"
                            | "automaticnetwork"
                            | "attachmentprefetch"
                    ) {
                        return None;
                    }
                    continue;
                }
                match crate::guests_input::fold(&key).as_str() {
                    "optin" => out.opt_in = value.as_bool()?,
                    "windowdays" => out.window_days = value.as_i64()?,
                    "backgroundsyncenabled" => out.background = value.as_bool()?,
                    "automaticnetwork" => out.network = value.as_str()?.to_owned(),
                    "attachmentprefetch" => out.prefetch = value.as_str()?.to_owned(),
                    _ => return None,
                }
            }
        }
        _ => return None,
    }
    sync::valid(&out).then_some(out)
}

/// Go's `WriteJSON(map[string]string{"status": ...})`.
fn status_body(status: &str) -> String {
    setjoin_user_settings::done(format!(
        "{{\"status\":{}}}",
        setjoin_user_settings::s(status)
    ))
}

/// Go reads these bodies without a cap; the front door bounds them at 16 MiB like its peers.
const UNCAPPED: usize = 16 << 20;
/// `maxSignatureBodyBytes`.
const SIGNATURE_BODY: usize = 128 << 10;

impl<K: KeySource + 'static> Intercept for UserSettingsRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(auth) = setjoin_authz::authorize_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let json = |body: String, status: u16| {
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response
            };
            // `WriteHeader(200)` then `Encode`: no Content-Type is set, so Go sniffs text.
            let raw_ok = || {
                let mut response = json(db::ok_body(), 200);
                response.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                response
            };
            let failed = |e: CommandOutcome<(), setjoin_pg::StatementFailure>| match e {
                CommandOutcome::Committed(()) => raw_ok(),
                CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
            };
            let path = r.uri().path().to_owned();
            // Go's `{"status":"saved"}` after a reducer or upsert; `business` lists the
            // reducer SQLSTATEs Go answers with a fixed 400 (every other failure is its 500).
            let saved = |outcome: CommandOutcome<(), setjoin_pg::StatementFailure>,
                         business: Option<(&[&str], &str)>| match outcome {
                CommandOutcome::Committed(()) => json(prefs::saved_body(), 200),
                CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
                    if business.is_some_and(|(codes, _)| {
                        e.sqlstate.as_deref().is_some_and(|c| codes.contains(&c))
                    }) =>
                {
                    bare(400, business.map_or("", |b| b.1), &c, &id)
                }
                CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
            };
            match what {
                Action::ImapGet => json(db::imap_get(&exec, actor).await, 200),
                Action::ImapPut => {
                    let Some(body) = decode_body::<ImapBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid json", &c, &id);
                    };
                    let body = db::ImapPut {
                        expose_all: body.expose_all,
                        show_subscribed_only: body.show_subscribed_only,
                        exposed_tag_ids: body.exposed_tag_ids.map(|ids| ids.0),
                        folder_separator: body.folder_separator,
                    };
                    failed(db::imap_put(&exec, actor, &body, operation).await)
                }
                Action::ViewGet => json(db::view_get(&exec, actor).await, 200),
                Action::ViewPut => {
                    let Some(raw) = first_value(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid json", &c, &id);
                    };
                    // `map[string]interface{}`: an object or `null`, nothing else.
                    let value = match serde_json::from_slice::<serde_json::Value>(&raw) {
                        Ok(v @ (serde_json::Value::Object(_) | serde_json::Value::Null)) => v,
                        _ => return bare(400, "invalid json", &c, &id),
                    };
                    if let Some(window) = value.get("offlineWindow") {
                        if !window.as_str().is_some_and(db::valid_offline_window) {
                            return bare(400, "invalid offlineWindow", &c, &id);
                        }
                    }
                    let prefs = setjoin_user_settings::go_marshal(&value);
                    failed(db::view_put(&exec, actor, &prefs, operation).await)
                }
                Action::UndoGet => json(db::undo_get(&exec, actor).await, 200),
                Action::UndoPut => {
                    let Some(body) = decode_body::<DelayBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid json", &c, &id);
                    };
                    let delay = db::clamp_delay(body.delay);
                    match db::undo_put(&exec, actor, delay, operation).await {
                        CommandOutcome::Committed(()) => json(db::undo_body(delay), 200),
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::NewsletterGet => json(db::newsletter_get(&exec, actor).await, 200),
                Action::NewsletterPut => {
                    let Some(body) = decode_body::<NewsletterBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid json", &c, &id);
                    };
                    let mut patch = serde_json::Map::new();
                    if let Some(bundle) = body.bundle {
                        patch.insert("bundleNewsletters".into(), bundle.into());
                    }
                    if let Some(lists) = body.lists {
                        patch.insert("newsletterOptouts".into(), lists.0.into());
                    }
                    let patch =
                        setjoin_user_settings::go_marshal(&serde_json::Value::Object(patch));
                    failed(db::newsletter_put(&exec, actor, &patch, operation).await)
                }
                Action::SignatureList => match db::signature_list(&exec, actor).await {
                    Ok(body) => json(body, 200),
                    Err(_) => bare(500, "database error", &c, &id),
                },
                Action::SignaturePut => {
                    let Some(body) = decode_body::<SignatureBody>(&mut r, SIGNATURE_BODY).await
                    else {
                        return bare(400, "invalid json", &c, &id);
                    };
                    if body.alias.is_empty() {
                        return bare(400, "alias_email is required", &c, &id);
                    }
                    if body.alias.len() > 320 {
                        return bare(400, "alias_email is too long", &c, &id);
                    }
                    if body.html.len() > 64 << 10 {
                        return bare(400, "signature_html is too long", &c, &id);
                    }
                    if body.text.len() > 8 << 10 {
                        return bare(400, "signature_text is too long", &c, &id);
                    }
                    match db::signature_others(&exec, actor, &body.alias).await {
                        Ok(others) if others >= db::MAX_SIGNATURES => {
                            return bare(400, "signature limit reached", &c, &id);
                        }
                        Ok(_) => {}
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    let default_for = if body.default_for.is_empty() {
                        "none"
                    } else {
                        body.default_for.as_str()
                    };
                    if !matches!(default_for, "new" | "reply" | "both" | "none") {
                        return bare(400, "invalid default_for", &c, &id);
                    }
                    match db::signature_put(
                        &exec,
                        actor,
                        &body.alias,
                        &body.html,
                        &body.text,
                        body.is_default == "true",
                        default_for,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(true) => raw_ok(),
                        CommandOutcome::Committed(false) => {
                            bare(400, "signature limit reached", &c, &id)
                        }
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::NotificationGet => match prefs::notification_get(&exec, actor).await {
                    Ok(body) => json(body, 200),
                    Err(_) => bare(500, "database error", &c, &id),
                },
                Action::NotificationPut => {
                    let Some(body) = decode_body::<NotificationBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let fingerprint = match body.fingerprint.as_deref() {
                        Some(raw) if !raw.is_empty() => match prefs::go_uuid(raw) {
                            Some(parsed) => Some(parsed),
                            None => return bare(400, "invalid device_fingerprint", &c, &id),
                        },
                        _ => None,
                    };
                    let p = body.prefs;
                    if !p.policy.is_empty() && !prefs::valid_read_receipt_policy(&p.policy) {
                        return bare(400, "invalid read_receipt_policy", &c, &id);
                    }
                    if !p.chat.is_empty() && !prefs::valid_chat_notifications(&p.chat) {
                        return bare(400, "invalid chat_notifications", &c, &id);
                    }
                    let put = prefs::NotificationPut {
                        fingerprint,
                        push_enabled: p.push_enabled,
                        push_sound: p.push_sound,
                        stop_push_when_desktop_online: p.stop_push,
                        dnd_start: p.dnd_start,
                        dnd_end: p.dnd_end,
                        dnd_days: p.dnd_days,
                        mail_notifications: p.mail,
                        calendar_reminders: p.calendar,
                        task_reminders: p.task,
                        read_receipt_policy: p.policy,
                        chat_notifications: p.chat,
                    };
                    saved(
                        prefs::notification_put(&exec, actor, &put, operation).await,
                        None,
                    )
                }
                Action::VipGet => match prefs::vip_get(&exec, actor).await {
                    Ok(body) => json(body, 200),
                    Err(_) => bare(500, "database error", &c, &id),
                },
                Action::VipPut => {
                    let Some(body) = decode_body::<VipBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if body.email.trim().is_empty() {
                        return bare(400, "email required", &c, &id);
                    }
                    saved(
                        prefs::vip_put(&exec, actor, &body.email, body.vip, operation).await,
                        None,
                    )
                }
                Action::VacationGet => {
                    if prefs::primary_mailbox(&exec, actor).await.is_none() {
                        return bare(404, "mailbox not found", &c, &id);
                    }
                    match prefs::vacation_get(&exec, actor).await {
                        Ok(body) => json(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::VacationPut => {
                    let Some(mut body) = decode_body::<VacationBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if body.external_audience.is_empty() {
                        body.external_audience = "all".into();
                    }
                    if !prefs::valid_external_audience(&body.external_audience) {
                        return bare(400, "invalid external_audience", &c, &id);
                    }
                    if prefs::primary_mailbox(&exec, actor).await.is_none() {
                        return bare(404, "mailbox not found", &c, &id);
                    }
                    let put = prefs::VacationPut {
                        enabled: body.enabled,
                        subject: body.subject,
                        body_internal: body.body_internal,
                        body_internal_html: body.body_internal_html,
                        body_external: body.body_external,
                        body_external_html: body.body_external_html,
                        start_date: body.start_date,
                        end_date: body.end_date,
                        external_audience: body.external_audience,
                    };
                    saved(
                        prefs::vacation_put(&exec, actor, &put, operation).await,
                        Some((&["BZ046", "BZ047"], "invalid automatic-reply settings")),
                    )
                }
                Action::DelegationGet => match prefs::delegation_get(&exec, actor).await {
                    Ok(body) => json(body, 200),
                    Err(_) => bare(500, "database error", &c, &id),
                },
                Action::DelegationPut => {
                    let Some(body) = decode_body::<DelegationBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let (mut delegate, mut starts, mut ends) = (None, None, None);
                    if body.enabled && body.delegate != 0 {
                        delegate = Some(body.delegate);
                        starts = body.starts_at;
                        ends = body.ends_at;
                    }
                    saved(
                        prefs::delegation_put(&exec, actor, delegate, &starts, &ends, operation)
                            .await,
                        Some((&["BZ119"], "invalid approval-delegation settings")),
                    )
                }
                Action::SyncPut => {
                    // Go's `http.NotFound`: the route is deliberately absent while a gate is closed.
                    let absent = || {
                        let mut response = json("404 page not found\n".into(), 404);
                        response.headers_mut().insert(
                            "content-type",
                            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                        );
                        response.headers_mut().insert(
                            "x-content-type-options",
                            hyper::header::HeaderValue::from_static("nosniff"),
                        );
                        response
                    };
                    let user = actor.user_id();
                    let Ok(flags) = sync::toggles(&exec).await else {
                        return c.upstream.forward(r, &c.identity).await;
                    };
                    if !flags[0] || !flags[1] {
                        return absent();
                    }
                    let Some(mailbox) = sync::primary_mailbox(&exec, user).await else {
                        return absent();
                    };
                    let Some(device) = sync::device(&exec, user, auth.device_id()).await else {
                        return absent();
                    };
                    let current =
                        sync::capabilities(&exec, actor, mailbox, device, [flags[2], flags[3]])
                            .await;
                    if matches!(sync::mode(&current), "off" | "") {
                        return absent();
                    }
                    let Some(request) = sync_body(&mut r).await else {
                        return bare(400, "invalid sync preferences", &c, &id);
                    };
                    if request.window_days > i64::from(i32::MAX) {
                        return bare(500, "sync preferences update failed", &c, &id);
                    }
                    match sync::put(&exec, actor, device, &request, operation).await {
                        CommandOutcome::Committed(()) => {
                            let refreshed = sync::capabilities(
                                &exec,
                                actor,
                                mailbox,
                                device,
                                [flags[2], flags[3]],
                            )
                            .await;
                            let wrapped = serde_json::json!({ "effectiveCapabilities": refreshed });
                            json(
                                setjoin_user_settings::done(setjoin_user_settings::go_marshal(
                                    &wrapped,
                                )),
                                200,
                            )
                        }
                        CommandOutcome::RolledBack(rejection) => {
                            let instance = path.strip_prefix("/api").unwrap_or(&path).to_owned();
                            crate::offline::classified(&rejection, &c, &id, &instance)
                                .unwrap_or_else(|| {
                                    bare(500, "sync preferences update failed", &c, &id)
                                })
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::SessionsList => {
                    match security::sessions_list(&exec, actor, auth.token_id()).await {
                        Ok(body) => json(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::DevicesList => json(security::devices_list(&exec, actor).await, 200),
                Action::LoginHistory => {
                    // Go's `ParseLimitOffset(r, 50, 200)`: Atoi errors are ignored, the ceiling applies.
                    let uri = r.uri();
                    let number = |name: &str| {
                        crate::admin_identity_input::query(uri, name)
                            .map_or(0, |v| crate::admin_identity_input::atoi(&v))
                    };
                    let limit = match number("limit") {
                        n if n <= 0 || n > 200 => 50,
                        n => n,
                    };
                    let offset = number("offset").clamp(0, 1_000_000);
                    let outcome =
                        crate::admin_identity_input::query(uri, "outcome").unwrap_or_default();
                    match security::login_history(
                        &exec,
                        actor,
                        auth.token_id(),
                        &outcome,
                        limit,
                        offset,
                    )
                    .await
                    {
                        Ok(body) => json(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::ProfileUpdate => {
                    let Some(body) = decode_body::<ProfileBody>(&mut r, UNCAPPED).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let name = profile::trim(&body.display_name);
                    if name.is_empty() {
                        return bare(400, "display name is required", &c, &id);
                    }
                    if name.chars().count() > profile::MAX_NAME_RUNES {
                        return bare(400, "display name is too long", &c, &id);
                    }
                    match profile::profile_update(&exec, actor, name, operation).await {
                        CommandOutcome::Committed(()) => json(profile::updated_body(name), 200),
                        CommandOutcome::RolledBack(_) => {
                            bare(500, "failed to update profile", &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::QuotaGet => match profile::quota_get(&exec, actor).await {
                    Some(body) => json(body, 200),
                    None => bare(500, "database error", &c, &id),
                },
                Action::SecurityScore => json(security::security_score(&exec, actor).await, 200),
                Action::SessionRevoke => {
                    let target = segment(&path, 4);
                    if target.is_empty() {
                        return bare(400, "session id required", &c, &id);
                    }
                    match security::session_revoke(&exec, actor, &target, operation).await {
                        CommandOutcome::Committed(security::Revoked::Revoked) => {
                            json(status_body("revoked"), 200)
                        }
                        CommandOutcome::Committed(security::Revoked::NotFound) => {
                            bare(404, "not found", &c, &id)
                        }
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::SessionsRevokeAll => {
                    match security::sessions_revoke_all(&exec, actor, operation).await {
                        CommandOutcome::Committed(()) => json(status_body("revoked-all"), 200),
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::SecureAccount => {
                    let ip = c.identity.client_ip.to_string();
                    match security::secure_account(&exec, actor, &ip, operation).await {
                        CommandOutcome::Committed(()) => json(status_body("secured"), 200),
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::SignatureDelete => {
                    let Ok(target) = segment(&path, 4).parse::<i64>() else {
                        return bare(400, "invalid signature id", &c, &id);
                    };
                    match db::signature_delete(&exec, actor, target, operation).await {
                        CommandOutcome::Committed(true) => {
                            let mut response = json(String::new(), 204);
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::Committed(false) => {
                            bare(404, "signature not found", &c, &id)
                        }
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
            }
        })
    }
}
