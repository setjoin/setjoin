//! F17 slice `calendar-booking` HTTP adapter: calendar subscriptions, batch
//! free/busy and the booking pages (owner surface and the public one).
//!
//! The authenticated routes act only for the verified token's user and primary
//! mailbox; request fields name targets and never grant authority. The public
//! booking routes carry no caller identity: the reducers self-scope by slug and
//! token hash and run on the worker credential, exactly as Go's worker-pool
//! calls do. See the crate DOX for the contract.
use crate::problem::Problem;
use crate::recovery_worker::ObjectStore;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor, StatementFailure};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// The first fetch of a new subscription runs detached from the request. The
/// calendar-subscription-sync worker (a later slice) provides it; while none is
/// installed the create route stays with Go.
pub trait SubscriptionKick: Send + Sync + 'static {
    fn kick(&self, subscription: i64, calendar: i64, url: String);
}

pub struct CalendarRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    /// The BYPASSRLS credential of the public booking reducers.
    pub worker: ScopedExecutor,
    /// Plain-`INSERT` credential of the outbound queue.
    pub queue: Option<WorkerDatabase>,
    pub keys: Arc<K>,
    pub issuer: String,
    pub store: Option<Arc<dyn ObjectStore>>,
    /// `https://<hostname>`, the base of the verification link.
    pub public_base: String,
    pub kick: Option<Arc<dyn SubscriptionKick>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    PageList,
    PagePut,
    PageDelete,
    Meta,
    Slots,
    Book,
    Confirm,
    Cancel,
    FreeBusy,
    SubscriptionList,
    SubscriptionCreate,
    SubscriptionDelete,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let get = *method == Method::GET;
    let post = *method == Method::POST;
    let table: [(bool, &str, Action); 12] = [
        (get, "/api/booking/pages", Action::PageList),
        (
            *method == Method::PUT,
            "/api/booking/pages",
            Action::PagePut,
        ),
        (
            *method == Method::DELETE,
            "/api/booking/pages",
            Action::PageDelete,
        ),
        (get, "/api/public/booking/{slug}", Action::Meta),
        (get, "/api/public/booking/{slug}/slots", Action::Slots),
        (post, "/api/public/booking/{slug}/book", Action::Book),
        (post, "/api/public/booking/confirm", Action::Confirm),
        (post, "/api/public/booking/cancel", Action::Cancel),
        (post, "/api/calendar/free-busy", Action::FreeBusy),
        (get, "/api/calendar/subscriptions", Action::SubscriptionList),
        (
            post,
            "/api/calendar/subscriptions",
            Action::SubscriptionCreate,
        ),
        (
            *method == Method::DELETE,
            "/api/calendar/subscriptions/{id}",
            Action::SubscriptionDelete,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

fn decode(segment: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(segment))
}

/// Go's `r.URL.Query().Get(name)`: first match; a pair with a bad escape or a
/// semicolon is dropped.
fn query_get(raw: Option<&str>, name: &str) -> String {
    fn unquote(text: &str) -> Option<String> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16));
                    let (a, b) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2)));
                    out.push((a? * 16 + b?) as u8);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Some(crate::guests_input::go_utf8(&out))
    }
    for pair in raw.unwrap_or("").split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (unquote(key), unquote(value)) else {
            continue;
        };
        if key == name {
            return value;
        }
    }
    String::new()
}

// ---- Go's `json.NewDecoder(...).Decode(&struct)` ----

macro_rules! fields {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
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

/// `null` entries of a map or slice decode to the zero value, as in Go.
#[derive(Default)]
struct Texts(BTreeMap<String, String>);
impl<'de> serde::Deserialize<'de> for Texts {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let map = <BTreeMap<String, Option<String>>>::deserialize(decoder)?;
        Ok(Texts(
            map.into_iter()
                .map(|(k, v)| (k, v.unwrap_or_default()))
                .collect(),
        ))
    }
}
#[derive(Default)]
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

fields!(BookBody {
    start: String = "start",
    email: String = "email",
    name: String = "name",
    answers: Option<Texts> = "answers",
    website: String = "website",
});
fields!(TokenBody {
    token: String = "token"
});
fields!(FreeBusyBody {
    user_ids: Ids = "user_ids",
    room_ids: Ids = "room_ids",
    start: String = "start",
    end: String = "end",
});
fields!(SubscribeBody {
    url: String = "url",
    name: String = "name"
});

enum BodyError {
    TooLarge,
    Invalid,
}

/// Go's `http.MaxBytesReader(w, r.Body, cap)` plus a one-value `Decoder`: the
/// first value must end inside the cap; whatever follows is ignored.
async fn first_value(r: &mut Request<Body>, cap: usize) -> Result<Vec<u8>, BodyError> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() <= cap {
        match r.body_mut().frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            Some(Err(_)) => return Err(BodyError::Invalid),
            None => break,
        }
    }
    let capped = bytes.len() > cap;
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
            Ok(fixed[start..end].to_vec())
        }
        Some(Err(e)) if e.is_eof() && capped => Err(BodyError::TooLarge),
        _ => Err(BodyError::Invalid),
    }
}

async fn decode_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
    cap: usize,
) -> Result<T, BodyError> {
    let raw = first_value(r, cap).await?;
    serde_json::from_slice(&raw).map_err(|_| BodyError::Invalid)
}

// ---- responses ----

struct Out<'a> {
    c: &'a RequestContext,
    id: String,
    path: String,
    language: String,
}

impl Out<'_> {
    fn ok(&self, body: String) -> Response<Body> {
        crate::jmap::reply::response(body, self.c.identity.proto, self.id.clone())
    }
    fn status(&self, status: u16, body: String) -> Response<Body> {
        let mut r = self.ok(body);
        *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        r
    }
    fn problem_response(&self, status: u16, body: String, language: bool) -> Response<Body> {
        let mut r = self.status(status, body);
        r.headers_mut().insert(
            "content-type",
            hyper::header::HeaderValue::from_static("application/problem+json"),
        );
        if language {
            if let Ok(v) = hyper::header::HeaderValue::from_str(&self.language) {
                r.headers_mut().insert("content-language", v);
            }
        }
        r
    }
    /// Go's `WriteProblemStatus`: no instance, no language.
    fn bare(&self, status: u16, detail: &str) -> Response<Body> {
        self.problem_response(status, Problem::new(status, detail).body(), false)
    }
    /// Go's `WriteProblem`: the request path and the negotiated language.
    fn problem(&self, status: u16, detail: &str) -> Response<Body> {
        self.problem_response(
            status,
            Problem::new(status, detail).instance(&self.path).body(),
            true,
        )
    }
    fn unknown(&self, operation: String) -> Response<Body> {
        let mut r = self.bare(503, "operation outcome unknown");
        r.headers_mut()
            .insert("x-operation-id", operation.parse().expect("operation"));
        r
    }
    /// Go's `reducererr.WriteClassified`, or the fixed 500 when the code is not
    /// a client-actionable one. `public` collapses not-found into the fixed 404.
    fn reducer(&self, f: &StatementFailure, public: bool) -> Response<Body> {
        let (status, fallback, remediation) = match f.sqlstate.as_deref() {
            Some("BZ134") => {
                if public {
                    return self.bare(404, "not found");
                }
                (
                    404,
                    "notFound",
                    "Refresh the target identifier and retry only if the resource still exists.",
                )
            }
            Some("BZ135") => (
                400,
                "invalidArguments",
                "Correct the request fields and retry.",
            ),
            Some("BZ136" | "BZ137") => (
                409,
                "conflict",
                "Refresh current state, resolve the conflict, and retry.",
            ),
            _ => return self.problem(500, "request failed"),
        };
        let code = f.sqlstate.as_deref().unwrap_or("");
        let kind = format!(
            "https://setjoin.com/problems/reducer/{}",
            code.to_ascii_lowercase()
        );
        self.problem_response(
            status,
            Problem::new(status, fallback)
                .kind(&kind)
                .instance(&self.path)
                .remediation(remediation)
                .code(code)
                .retryable(false)
                .body(),
            true,
        )
    }
    fn rolled_back(&self, e: &Rejection<StatementFailure>, public: bool) -> Response<Body> {
        match e {
            Rejection::Statement(f) | Rejection::Body(f) => self.reducer(f, public),
            _ => self.problem(500, "request failed"),
        }
    }
    fn json(&self, status: u16, body: String) -> Response<Body> {
        self.status(status, body)
    }
}

impl<K: KeySource + 'static> Intercept for CalendarRoute<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool { !matches!(action(r.method(), r.uri().path()), Some(Action::Meta | Action::Slots | Action::Book | Action::Confirm | Action::Cancel)) }
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
        let this = Self {
            exec: self.exec.clone(),
            worker: self.worker.clone(),
            queue: self.queue.clone(),
            keys: self.keys.clone(),
            issuer: self.issuer.clone(),
            store: self.store.clone(),
            public_base: self.public_base.clone(),
            kick: self.kick.clone(),
        };
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let path = r.uri().path().to_owned();
            let public = matches!(
                what,
                Action::Meta | Action::Slots | Action::Book | Action::Confirm | Action::Cancel
            );
            let auth = if public {
                None
            } else {
                match setjoin_authz::authorize_request(
                    &this.exec,
                    &this.keys,
                    &this.issuer,
                    r.headers(),
                    c.identity.proto,
                )
                .await
                {
                    Some(auth) => Some(auth),
                    None => return c.upstream.forward(r, &c.identity).await,
                }
            };
            let Some(operation) = crate::jmap::random() else {
                let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), [0; 16]);
                return crate::jmap::reply::response(
                    Problem::new(503, "service unavailable").body(),
                    c.identity.proto,
                    id,
                );
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let out = Out {
                c: &c,
                id,
                path: decode(path.strip_prefix("/api").unwrap_or(&path)),
                language: crate::chat_channels::problem_language(r.headers()),
            };
            match what {
                Action::PageList | Action::PagePut | Action::PageDelete => {
                    let auth = auth.expect("authenticated");
                    match setjoin_calendar::booking_enabled(&this.exec).await {
                        Ok(true) => {}
                        Ok(false) => return out.bare(404, "not found"),
                        Err(_) => return c.upstream.forward(r, &c.identity).await,
                    }
                    let actor = auth.context();
                    match what {
                        Action::PageList => {
                            match setjoin_calendar::page_list(&this.exec, actor).await {
                                Ok(text) => out.ok(text),
                                Err(_) => out.bare(500, "database error"),
                            }
                        }
                        Action::PagePut => {
                            let Ok(raw) = first_value(&mut r, 16 << 10).await else {
                                return out.bare(400, "invalid JSON");
                            };
                            let Ok(page) = String::from_utf8(raw) else {
                                return out.problem(500, "request failed");
                            };
                            match setjoin_calendar::page_upsert(&this.exec, actor, &page, operation)
                                .await
                            {
                                CommandOutcome::Committed(text) => out.ok(text),
                                CommandOutcome::RolledBack(e) => out.rolled_back(&e, false),
                                CommandOutcome::Unknown { operation } => {
                                    out.unknown(setjoin_pg::operation_hex(operation))
                                }
                            }
                        }
                        _ => {
                            let Ok(page) = query_get(r.uri().query(), "id").parse::<i64>() else {
                                return out.bare(400, "id is required");
                            };
                            match setjoin_calendar::page_delete(&this.exec, actor, page, operation)
                                .await
                            {
                                CommandOutcome::Committed(text) => out.ok(text),
                                CommandOutcome::RolledBack(e) => out.rolled_back(&e, false),
                                CommandOutcome::Unknown { operation } => {
                                    out.unknown(setjoin_pg::operation_hex(operation))
                                }
                            }
                        }
                    }
                }
                Action::Meta | Action::Slots | Action::Book | Action::Confirm | Action::Cancel => {
                    this.public(what, r, &c, &out, &path).await
                }
                Action::FreeBusy => {
                    this.free_busy(r, &c, &out, auth.expect("authenticated"))
                        .await
                }
                Action::SubscriptionList => {
                    let auth = auth.expect("authenticated");
                    match setjoin_calendar::subscriptions(&this.exec, auth.context()).await {
                        Ok(rows) => out.json(200, render_subscriptions(&rows)),
                        Err(_) => out.bare(500, "database error"),
                    }
                }
                Action::SubscriptionDelete => {
                    let auth = auth.expect("authenticated");
                    let segment = path.split('/').nth(4).unwrap_or("");
                    let Ok(subscription) = decode(segment).parse::<i64>() else {
                        return out.bare(400, "invalid id");
                    };
                    match setjoin_calendar::unsubscribe(
                        &this.exec,
                        auth.context(),
                        subscription,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(true) => {
                            let mut response = out.ok(String::new());
                            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::Committed(false) => out.bare(404, "subscription not found"),
                        CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            out.unknown(setjoin_pg::operation_hex(operation))
                        }
                    }
                }
                Action::SubscriptionCreate => {
                    let auth = auth.expect("authenticated");
                    this.subscribe(r, &c, &out, auth.context(), operation).await
                }
            }
        })
    }
}

fn render_subscriptions(rows: &[setjoin_calendar::Subscription]) -> String {
    use crate::problem::go_string as s;
    let optional = |value: &Option<String>| value.as_deref().map_or("null".to_owned(), s);
    let items: Vec<String> = rows
        .iter()
        .map(|row| {
            format!(
                "{{\"id\":{},\"calendarId\":{},\"calendarName\":{},\"url\":{},\"lastFetchAt\":{},\"lastStatus\":{},\"lastError\":{},\"refreshIntervalMinutes\":{}}}",
                row.id,
                s(&row.calendar_id),
                s(&row.calendar_name),
                s(&row.url),
                optional(&row.last_fetch_at),
                s(&row.last_status),
                optional(&row.last_error),
                row.refresh_interval_minutes
            )
        })
        .collect();
    format!("{{\"subscriptions\":[{}]}}\n", items.join(","))
}

impl<K: KeySource + 'static> CalendarRoute<K> {
    async fn public(
        &self,
        what: Action,
        mut r: Request<Body>,
        c: &RequestContext,
        out: &Out<'_>,
        path: &str,
    ) -> Response<Body> {
        match setjoin_calendar::booking_enabled(&self.exec).await {
            Ok(true) => {}
            Ok(false) => return out.bare(404, "not found"),
            Err(_) => return c.upstream.forward(r, &c.identity).await,
        }
        let decoded = decode(path);
        let slug = decode(path.split('/').nth(4).unwrap_or(""));
        // Go's dispatch tests the path suffix, not the matched pattern.
        let what = match (what, r.method()) {
            (Action::Meta, _) if decoded.ends_with("/slots") => Action::Slots,
            (other, _) => other,
        };
        match what {
            Action::Meta => match setjoin_calendar::public_get(&self.worker, &slug).await {
                Ok(Some(text)) => out.ok(text),
                Ok(None) => out.bare(404, "not found"),
                Err(f) => out.reducer(&f, true),
            },
            Action::Slots => {
                let from = query_get(r.uri().query(), "from");
                let to = query_get(r.uri().query(), "to");
                if from.is_empty() || to.is_empty() {
                    return out.problem(400, "from and to are required");
                }
                match setjoin_calendar::slots(&self.worker, &slug, &from, &to).await {
                    Ok(text) => out.ok(text),
                    Err(f) => out.reducer(&f, true),
                }
            }
            Action::Book => {
                let body = match decode_body::<BookBody>(&mut r, 16 << 10).await {
                    Ok(body) => body,
                    Err(BodyError::TooLarge) => return out.bare(413, "request body too large"),
                    Err(BodyError::Invalid) => return out.bare(400, "invalid JSON"),
                };
                const SUCCESS: &str = "{\"ok\":true,\"verificationSent\":true}";
                if !body.website.is_empty() {
                    return out.ok(SUCCESS.into());
                }
                let Some((token, hash)) = crate::booking_mail::token() else {
                    return out.problem(500, "request failed");
                };
                let answers = match &body.answers {
                    None => "null".to_owned(),
                    Some(Texts(map)) => {
                        let items: Vec<String> = map
                            .iter()
                            .map(|(k, v)| {
                                format!(
                                    "{}:{}",
                                    crate::problem::go_string(k),
                                    crate::problem::go_string(v)
                                )
                            })
                            .collect();
                        format!("{{{}}}", items.join(","))
                    }
                };
                let ip = c.identity.client_ip.to_string();
                match setjoin_calendar::create(
                    &self.worker,
                    &slug,
                    &body.start,
                    &body.email,
                    &body.name,
                    &answers,
                    &hash,
                    Some(&ip),
                )
                .await
                {
                    Ok(text) => {
                        let created: serde_json::Value =
                            serde_json::from_str(&text).unwrap_or_default();
                        let field = |name: &str| created[name].as_str().unwrap_or("").to_owned();
                        if let Some(queue) = &self.queue {
                            crate::booking_mail::verification(
                                self.store.as_deref(),
                                queue,
                                &self.public_base,
                                &field("ownerEmail"),
                                &body.email,
                                &field("pageTitle"),
                                &token,
                            )
                            .await;
                        }
                        out.ok(SUCCESS.into())
                    }
                    Err(f) => out.reducer(&f, true),
                }
            }
            Action::Confirm => {
                let body = match decode_body::<TokenBody>(&mut r, 16 << 10).await {
                    Ok(body) => body,
                    Err(BodyError::TooLarge) => return out.bare(413, "request body too large"),
                    Err(BodyError::Invalid) => return out.bare(400, "invalid JSON"),
                };
                let Some((cancel_token, cancel_hash)) = crate::booking_mail::token() else {
                    return out.problem(500, "request failed");
                };
                match setjoin_calendar::confirm(
                    &self.worker,
                    &crate::booking_mail::sha256_hex(&body.token),
                    &cancel_hash,
                )
                .await
                {
                    Ok(text) => {
                        // Invite and owner heads-up leave detached from the request.
                        if let Some(queue) = self.queue.clone() {
                            let store = self.store.clone();
                            let payload = text.clone();
                            tokio::spawn(async move {
                                let value: serde_json::Value =
                                    serde_json::from_str(&payload).unwrap_or_default();
                                let field =
                                    |name: &str| value[name].as_str().unwrap_or("").to_owned();
                                crate::booking_mail::send_invite(
                                    store.as_deref(),
                                    &queue,
                                    &payload,
                                )
                                .await;
                                crate::booking_mail::owner_notice(
                                    store.as_deref(),
                                    &queue,
                                    &field("ownerEmail"),
                                    &field("bookerEmail"),
                                    &field("pageTitle"),
                                    &field("slotStart"),
                                )
                                .await;
                            });
                        }
                        out.ok(format!(
                            "{{\"cancelToken\":\"{cancel_token}\",\"ok\":true}}"
                        ))
                    }
                    Err(f) => out.reducer(&f, true),
                }
            }
            _ => {
                let body = match decode_body::<TokenBody>(&mut r, 16 << 10).await {
                    Ok(body) => body,
                    Err(BodyError::TooLarge) => return out.bare(413, "request body too large"),
                    Err(BodyError::Invalid) => return out.bare(400, "invalid JSON"),
                };
                match setjoin_calendar::cancel(
                    &self.worker,
                    &crate::booking_mail::sha256_hex(&body.token),
                )
                .await
                {
                    Ok(text) => out.ok(text),
                    Err(f) => out.reducer(&f, true),
                }
            }
        }
    }

    async fn free_busy(
        &self,
        mut r: Request<Body>,
        c: &RequestContext,
        out: &Out<'_>,
        auth: setjoin_authz::Authorized,
    ) -> Response<Body> {
        // Go mounts the route only while CalDAV is on and gates it by the
        // calendar entitlement; a refusal and its audit stay with Go.
        match setjoin_calendar::caldav_enabled(&self.exec).await {
            Ok(true) => {}
            _ => return c.upstream.forward(r, &c.identity).await,
        }
        match setjoin_calendar::entitled(&self.exec, auth.context()).await {
            Ok(true) => {}
            _ => return c.upstream.forward(r, &c.identity).await,
        }
        let error = |status: u16, text: &str| {
            out.json(
                status,
                format!("{{\"error\":{}}}\n", crate::problem::go_string(text)),
            )
        };
        let body = match decode_body::<FreeBusyBody>(&mut r, 64 << 10).await {
            Ok(body) => body,
            Err(_) => return error(400, "invalid request body"),
        };
        let (users, rooms) = (body.user_ids.0, body.room_ids.0);
        if users.is_empty() && rooms.is_empty() {
            return error(400, "at least one user_id or room_id is required");
        }
        if users.len() + rooms.len() > 100 {
            return error(400, "batch is limited to 100 entities per request");
        }
        if body.start.is_empty() {
            return error(400, "start is required");
        }
        if body.end.is_empty() {
            return error(400, "end is required");
        }
        let start = match crate::go_time::parse_rfc3339(&body.start) {
            Ok(t) => t,
            Err(e) => return error(400, &format!("invalid start: {e}")),
        };
        let end = match crate::go_time::parse_rfc3339(&body.end) {
            Ok(t) => t,
            Err(e) => return error(400, &format!("invalid end: {e}")),
        };
        if start >= end {
            return error(400, "start must be before end");
        }
        if end.signed_duration_since(start) > chrono::Duration::hours(366 * 24) {
            return error(400, "free/busy window is limited to 366 days per request");
        }
        let (Ok(from), Ok(to)) = (
            crate::guests_input::timestamp(&body.start),
            crate::guests_input::timestamp(&body.end),
        ) else {
            return error(500, "free/busy query failed");
        };
        let mut ids = users;
        ids.extend(rooms.iter().copied());
        let text =
            match setjoin_calendar::free_busy(&self.exec, auth.context(), &ids, &from, &to).await {
                Ok(text) => text,
                Err(_) => return error(500, "free/busy query failed"),
            };
        let Ok(serde_json::Value::Array(results)) =
            serde_json::from_str::<serde_json::Value>(&text)
        else {
            return error(500, "failed to parse free/busy data");
        };
        let mut rendered = Vec::new();
        for result in &results {
            let Some(entry) = result.as_object() else {
                return error(500, "failed to parse free/busy data");
            };
            let text = |name: &str| match entry.get(name) {
                None | Some(serde_json::Value::Null) => Ok(String::new()),
                Some(serde_json::Value::String(s)) => Ok(s.clone()),
                _ => Err(()),
            };
            let (Ok(entity), Ok(mut email), Ok(mut kind)) =
                (text("entity_id"), text("email"), text("type"))
            else {
                return error(500, "failed to parse free/busy data");
            };
            let intervals = match entry.get("intervals") {
                None | Some(serde_json::Value::Null) => "null".to_owned(),
                Some(serde_json::Value::Array(list)) => {
                    let mut items = Vec::new();
                    for item in list {
                        let Some(item) = item.as_object() else {
                            return error(500, "failed to parse free/busy data");
                        };
                        let time = |name: &str| -> Result<String, ()> {
                            match item.get(name) {
                                Some(serde_json::Value::String(s)) => {
                                    let parsed =
                                        crate::go_time::parse_rfc3339(s).map_err(|_| ())?;
                                    Ok(crate::go_time::format_rfc3339_nano(&parsed))
                                }
                                // A JSON null leaves Go's zero time.
                                None | Some(serde_json::Value::Null) => {
                                    Ok("0001-01-01T00:00:00Z".to_owned())
                                }
                                _ => Err(()),
                            }
                        };
                        let status = match item.get("status") {
                            None | Some(serde_json::Value::Null) => Ok(String::new()),
                            Some(serde_json::Value::String(s)) => Ok(s.clone()),
                            _ => Err(()),
                        };
                        let (Ok(start), Ok(end), Ok(status)) = (time("start"), time("end"), status)
                        else {
                            return error(500, "failed to parse free/busy data");
                        };
                        items.push(format!(
                            "{{\"start\":\"{start}\",\"end\":\"{end}\",\"status\":{}}}",
                            crate::problem::go_string(&status)
                        ));
                    }
                    format!("[{}]", items.join(","))
                }
                _ => return error(500, "failed to parse free/busy data"),
            };
            if let Some(found) = setjoin_calendar::entity_email(&self.exec, &entity).await {
                if !found.is_empty() {
                    email = found;
                }
            }
            if rooms.iter().any(|rid| rid.to_string() == entity) {
                kind = "room".into();
            }
            if kind.is_empty() {
                kind = "user".into();
            }
            rendered.push(format!(
                "{{\"entity_id\":{},\"email\":{},\"type\":{},\"intervals\":{intervals}}}",
                crate::problem::go_string(&entity),
                crate::problem::go_string(&email),
                crate::problem::go_string(&kind),
            ));
        }
        out.json(200, format!("{{\"results\":[{}]}}\n", rendered.join(",")))
    }

    async fn subscribe(
        &self,
        mut r: Request<Body>,
        c: &RequestContext,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
        operation: [u8; 16],
    ) -> Response<Body> {
        let Some(kick) = self.kick.clone() else {
            return c.upstream.forward(r, &c.identity).await;
        };
        // `perUserResourceCap`: runs before the handler reads the body.
        match setjoin_calendar::subscription_count(&self.exec, actor).await {
            Err(_) => return out.bare(503, "unable to verify calendar subscription budget"),
            Ok(n) if n >= setjoin_calendar::MAX_SUBSCRIPTIONS_PER_USER => return out.bare(
                409,
                &format!(
                    "calendar subscription limit reached ({}); remove one before creating another",
                    setjoin_calendar::MAX_SUBSCRIPTIONS_PER_USER
                ),
            ),
            Ok(_) => {}
        }
        let body = match read_unbounded::<SubscribeBody>(&mut r).await {
            Ok(body) => body,
            Err(()) => return out.bare(400, "invalid request body"),
        };
        let trimmed = body.url.trim_matches(go_space);
        let feed = normalize_webcal(trimmed);
        if feed.is_empty() {
            return out.bare(400, "url is required");
        }
        if !crate::ssrf::valid_url(&feed) {
            return out.bare(400, "couldn't reach that URL");
        }
        let mut name = body.name.trim_matches(go_space).to_owned();
        if name.is_empty() {
            name = "Subscribed calendar".into();
        }
        let name_bytes = name.as_bytes();
        let name = if name_bytes.len() > 200 {
            // Go slices bytes; a cut inside a rune is rejected by the database.
            match std::str::from_utf8(&name_bytes[..200]) {
                Ok(text) => text.to_owned(),
                Err(_) => return out.bare(500, "database error"),
            }
        } else {
            name
        };
        match setjoin_calendar::subscribe(&self.exec, actor, &name, &feed, operation).await {
            CommandOutcome::Committed((subscription, calendar)) => {
                kick.kick(subscription, calendar, feed.clone());
                out.json(
                    201,
                    format!(
                        "{{\"calendarId\":\"{calendar}\",\"id\":{subscription},\"status\":\"pending\",\"url\":{}}}\n",
                        crate::problem::go_string(&feed)
                    ),
                )
            }
            CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
            CommandOutcome::Unknown { operation } => {
                out.unknown(setjoin_pg::operation_hex(operation))
            }
        }
    }
}

/// Go's `strings.TrimSpace` whitespace (Unicode `White_Space`).
fn go_space(c: char) -> bool {
    c.is_whitespace()
}

fn normalize_webcal(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix("webcal://") {
        format!("https://{rest}")
    } else if let Some(rest) = raw.strip_prefix("webcals://") {
        format!("https://{rest}")
    } else {
        raw.to_owned()
    }
}

/// `json.NewDecoder(r.Body).Decode(&req)` with no byte cap.
async fn read_unbounded<T: serde::de::DeserializeOwned>(r: &mut Request<Body>) -> Result<T, ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}
