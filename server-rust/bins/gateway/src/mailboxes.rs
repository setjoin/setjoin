//! F05 slice `mailboxes` HTTP adapter: admin mailbox and folder CRUD plus the
//! mailbox lifecycle/purge console. See the crate DOX for the contract. Every
//! route is gated like Go's `requireMailPerm`/`requireUsersCreate`/
//! `requireUsersDelete`/`requireMailExport` from the live governed grants.
use crate::admin_identity_input::{atoi, query};
use crate::problem::Problem;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_mailboxes::mailboxes as db;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor, StatementFailure};
use std::fmt;
use std::sync::Arc;

pub struct MailboxesRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    /// The `setjoin_worker` credential: delete and the lifecycle reducers.
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    List,
    Create,
    Get,
    Update,
    Delete,
    Folders,
    FolderCreate,
    FolderUpdate,
    FolderDelete,
    LifecyclePreview,
    Retained,
    Parity,
    Transition,
    PurgeSchedule,
    PurgeApproval,
    PurgeExecute,
    PurgeCancel,
}

/// Method/pattern table; the first column is the method predicate.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 17] = [
        (reads, "/api/admin/mailboxes", Action::List),
        (
            *method == Method::POST,
            "/api/admin/mailboxes",
            Action::Create,
        ),
        (reads, "/api/admin/mailboxes/{id}", Action::Get),
        (
            *method == Method::PUT,
            "/api/admin/mailboxes/{id}",
            Action::Update,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/mailboxes/{id}",
            Action::Delete,
        ),
        (reads, "/api/admin/mailboxes/{id}/folders", Action::Folders),
        (
            *method == Method::POST,
            "/api/admin/mailboxes/{id}/folders",
            Action::FolderCreate,
        ),
        (
            *method == Method::PUT,
            "/api/admin/mailboxes/{id}/folders/{folderId}",
            Action::FolderUpdate,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/mailboxes/{id}/folders/{folderId}",
            Action::FolderDelete,
        ),
        (
            reads,
            "/api/admin/mailboxes/{id}/lifecycle/preview",
            Action::LifecyclePreview,
        ),
        (reads, "/api/admin/mailboxes/retained", Action::Retained),
        (
            reads,
            "/api/admin/mailboxes/lifecycle/parity",
            Action::Parity,
        ),
        (
            *method == Method::POST,
            "/api/admin/mailboxes/{id}/lifecycle",
            Action::Transition,
        ),
        (
            *method == Method::POST,
            "/api/admin/mailboxes/{id}/purge",
            Action::PurgeSchedule,
        ),
        (
            *method == Method::POST,
            "/api/admin/mailbox-purge-approvals/{id}",
            Action::PurgeApproval,
        ),
        (
            *method == Method::POST,
            "/api/admin/mailbox-purges/{id}/execute",
            Action::PurgeExecute,
        ),
        (
            *method == Method::POST,
            "/api/admin/mailbox-purges/{id}/cancel",
            Action::PurgeCancel,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
pub(crate) fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

/// Go `json.NewDecoder(r.Body).Decode(&struct)`: case-folded keys, null keeps
/// the zero value, unknown keys ignored.
macro_rules! body {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        pub(crate) struct $name { $(pub(crate) $field: $ty),+ }
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

pub(crate) use body;

body!(CreateBody {
    user_id: i64 = "userid",
    email: String = "email",
    display_name: String = "displayname",
    kind: String = "type",
    quota_bytes: Option<i64> = "quotabytes"
});
body!(UpdateBody {
    display_name: Option<String> = "displayname",
    quota_bytes: Option<i64> = "quotabytes",
    enabled: Option<bool> = "enabled",
    litigation_hold: Option<bool> = "litigationhold",
    deleted_purge_days: Option<i64> = "deletedpurgedays",
    spam_purge_days: Option<i64> = "spampurgedays"
});
body!(FolderBody {
    name: String = "name",
    parent_id: Option<i64> = "parentid"
});
body!(RenameBody {
    name: String = "name"
});

/// Go's `DisallowUnknownFields` decoder: case-folded keys, `null` keeps the
/// zero value, any key no field matches is an error.
macro_rules! strict {
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
                                _ => return Err(serde::de::Error::custom("unknown field")),
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
strict!(TransitionBody {
    action: String = "action",
    expected_generation: String = "expectedgeneration",
    idempotency_key: String = "idempotencykey",
    reason: String = "reason",
    target_user_id: String = "targetuserid",
    evidence_kind: String = "evidencekind",
    identity_link_id: String = "identitylinkid",
    link_generation: String = "linkgeneration",
    source_key_digest: String = "sourcekeydigest",
    delivery: String = "delivery",
    redirect_address: String = "redirectaddress"
});
strict!(PurgeBody {
    expected_generation: String = "expectedgeneration",
    preview_digest: String = "previewdigest",
    idempotency_key: String = "idempotencykey",
    reason: String = "reason",
    approver_user_id: String = "approveruserid"
});
strict!(ApprovalBody {
    decision: String = "decision",
    comment: String = "comment"
});
strict!(KeyedBody {
    idempotency_key: String = "idempotencykey",
    reason: String = "reason"
});

/// Go's `decodeMailboxLifecycleJSON`: one value of at most 64 KiB, nothing after
/// it. `Err` carries the problem detail Go answers with.
async fn strict_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
) -> Result<T, &'static str> {
    use http_body_util::BodyExt;
    const INVALID: &str = "invalid mailbox lifecycle request";
    const CAP: usize = 64 << 10;
    let mut bytes = Vec::new();
    let mut over = false;
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| INVALID)?;
        if let Ok(data) = frame.into_data() {
            let room = CAP - bytes.len();
            if data.len() > room {
                bytes.extend_from_slice(&data[..room]);
                over = true;
                break;
            }
            bytes.extend_from_slice(&data);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<T>();
    let value = match stream.next() {
        Some(Ok(value)) => value,
        _ => return Err(INVALID),
    };
    // Go decodes the first value, then a second Decode must see EOF: running into the
    // 64 KiB cap while looking for it is an error of that second read.
    let rest = &fixed[stream.byte_offset()..];
    if !over
        && rest
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        Ok(value)
    } else {
        Err("mailbox lifecycle request must contain one JSON object")
    }
}

/// `github.com/google/uuid` `Parse`, to the canonical lowercase form.
pub(crate) fn parse_uuid(s: &str) -> Option<String> {
    let mut s = s.as_bytes();
    match s.len() {
        36 => {}
        45 => {
            if !s[..9].eq_ignore_ascii_case(b"urn:uuid:") {
                return None;
            }
            s = &s[9..];
        }
        38 => s = &s[1..],
        32 => {
            let mut bytes = [0u8; 16];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = hex(s[i * 2])? << 4 | hex(s[i * 2 + 1])?;
            }
            return Some(format_uuid(&bytes));
        }
        _ => return None,
    }
    if s[8] != b'-' || s[13] != b'-' || s[18] != b'-' || s[23] != b'-' {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, x) in [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34]
        .into_iter()
        .enumerate()
    {
        bytes[i] = hex(s[x])? << 4 | hex(s[x + 1])?;
    }
    Some(format_uuid(&bytes))
}
fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}
fn format_uuid(b: &[u8; 16]) -> String {
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    )
}
const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub(crate) async fn json_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
) -> Result<T, ()> {
    crate::admin_identity_input::first(r, 1 << 20).await
}

/// Go's `validate.CanonicalEmail` for the addresses whose `net/mail` parse is
/// certain: dot-atom local part and dot-separated ASCII domain. `Ok(None)`
/// means "an address this adapter does not judge": the request goes to Go.
fn canonical_email(email: &str) -> Result<Option<String>, &'static str> {
    if email.len() > 254 {
        return Err("email exceeds 254 characters");
    }
    if email.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("email contains control character");
    }
    let atext = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~-".contains(&b);
    let simple_domain = |d: &str| {
        d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    };
    let Some(at) = email.rfind('@') else {
        // No '@': both parses fail. Only plain tokens are judged here.
        return if email.bytes().all(|b| atext(b) || b == b'.') {
            Err("invalid email format")
        } else {
            Ok(None)
        };
    };
    let (local, domain) = (&email[..at], &email[at + 1..]);
    if at >= 1 {
        if local.contains("..") {
            return Err("local-part contains consecutive dots");
        }
        if local.starts_with('.') {
            return Err("local-part starts with a dot");
        }
        if local.ends_with('.') {
            return Err("local-part ends with a dot");
        }
    }
    let plain_local = !local.is_empty() && local.bytes().all(|b| atext(b) || b == b'.');
    if !plain_local || domain.is_empty() || !simple_domain(domain) || local.contains('@') {
        return Ok(None);
    }
    if domain.split('.').any(str::is_empty) {
        return Err("invalid email format");
    }
    if !domain.contains('.') {
        return Err("domain must contain at least one dot");
    }
    if domain.contains('_') {
        return Err("domain contains underscore");
    }
    Ok(Some(email.to_owned()))
}

fn nonempty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

pub(crate) fn language(r: &Request<Body>) -> String {
    let tag = r
        .headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|v| v.split([',', ';']).next().unwrap_or("").trim().to_owned());
    let ok = |t: &str| {
        let mut parts = t.split('-');
        let first = parts.next().unwrap_or("");
        (1..=8).contains(&first.len())
            && first.bytes().all(|b| b.is_ascii_alphabetic())
            && parts
                .all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    };
    match tag {
        Some(t) if ok(&t) => t,
        _ => "en".into(),
    }
}

pub(crate) fn render(
    problem: Problem<'_>,
    language: Option<&str>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let status = problem.status;
    let mut r = crate::jmap::reply::response(problem.body(), c.identity.proto, id.to_owned());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    if let Some(lang) = language.and_then(|l| l.parse().ok()) {
        r.headers_mut().insert("content-language", lang);
    }
    r
}

/// Go's `WriteProblemStatus`: a minimal problem, empty instance, no language.
pub(crate) fn bare(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(Problem::new(status, detail), None, c, id)
}

pub(crate) fn unknown_outcome(
    operation: setjoin_contracts::ids::OperationId,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let mut response = bare(503, "operation outcome unknown", c, id);
    response.headers_mut().insert(
        "x-operation-id",
        setjoin_pg::operation_hex(operation)
            .parse()
            .expect("operation"),
    );
    response
}

impl<K: KeySource + 'static> Intercept for MailboxesRoute<K> {
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
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
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
            let Ok(authority) = setjoin_mailboxes::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            let required: &[&str] = match what {
                Action::List | Action::Get | Action::Folders => &setjoin_mailboxes::MAIL_CONSOLE,
                Action::LifecyclePreview
                | Action::Retained
                | Action::Parity
                | Action::Transition
                | Action::PurgeSchedule
                | Action::PurgeApproval
                | Action::PurgeExecute
                | Action::PurgeCancel => &setjoin_mailboxes::USERS_DELETE,
                _ => &setjoin_mailboxes::USERS_CREATE,
            };
            if !authority.allows_any(required) {
                let _ = setjoin_mailboxes::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let scope = authority.domain_scope();
            let head = r.method() == Method::HEAD;
            let lang = language(&r);
            let reply = |body: String| {
                // net/http buffers 2 KiB of a handler's output; a larger single
                // write is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let full = |status: u16, detail: &str| {
                render(
                    Problem::new(status, detail).instance(&go_path),
                    Some(&lang),
                    &c,
                    &id,
                )
            };
            let database = || full(500, "database error");
            let status_only = |status: u16| {
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response.headers_mut().remove("content-type");
                response
            };
            let created = |id_value: i64| {
                let mut response = reply(format!("{{\"id\":{id_value}}}\n"));
                *response.status_mut() = hyper::StatusCode::CREATED;
                response
            };
            // A refusal decided by a reducer, or the database failing.
            let refused = |e: &Rejection<StatementFailure>| match setjoin_mailboxes::problem_of(e) {
                Some(p) => full(p.status, &p.detail),
                None => database(),
            };
            // Go's `inDomainScope`: `Err` is the response to send.
            let in_scope = async |mailbox: i64| -> Result<(), Response<Body>> {
                if scope == 0 {
                    return Ok(());
                }
                match db::domain_of(&exec, mailbox).await {
                    Ok(None) => Err(full(404, "mailbox not found")),
                    Ok(Some(d)) if d != scope => {
                        Err(full(403, "access denied: mailbox not in domain scope"))
                    }
                    Ok(Some(_)) => Ok(()),
                    Err(_) => Err(database()),
                }
            };
            let target = |index: usize| segment(&path, index);
            match what {
                Action::List => {
                    let (mut limit, mut offset) = (
                        query(r.uri(), "limit").map_or(0, |v| atoi(&v)),
                        query(r.uri(), "offset").map_or(0, |v| atoi(&v)),
                    );
                    if limit <= 0 || limit > 100 {
                        limit = 50;
                    }
                    offset = offset.clamp(0, 1_000_000);
                    let q = query(r.uri(), "q").unwrap_or_default();
                    let user = query(r.uri(), "user_id").unwrap_or_default();
                    let filter = if !user.is_empty() {
                        db::Filter::User(atoi(&user))
                    } else if !q.is_empty() {
                        db::Filter::Search(&q)
                    } else {
                        db::Filter::None
                    };
                    match db::list(&exec, scope, filter, limit, offset).await {
                        Ok(body) => reply(body),
                        Err(_) => database(),
                    }
                }
                Action::Get => {
                    let Ok(mailbox) = target(4).parse::<i64>() else {
                        return full(400, "invalid mailbox id");
                    };
                    match db::get(&exec, scope, mailbox).await {
                        Ok(Some(body)) => reply(body),
                        Ok(None) => full(404, "mailbox not found"),
                        Err(_) => database(),
                    }
                }
                Action::Create => {
                    let Ok(body) = json_body::<CreateBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.user_id <= 0 || body.email.is_empty() {
                        return full(400, "userId and email required");
                    }
                    let email = match canonical_email(&body.email) {
                        Ok(Some(email)) => email,
                        Ok(None) => return c.upstream.forward(r, &c.identity).await,
                        Err(detail) => return full(400, detail),
                    };
                    let display = if body.display_name.is_empty() {
                        email.clone()
                    } else {
                        body.display_name
                    };
                    let kind = if body.kind.is_empty() {
                        "personal".to_owned()
                    } else {
                        body.kind
                    };
                    if kind != "personal" {
                        return full(
                            400,
                            "mailbox type must be personal; groups, shared, and resource mailboxes are created via their own endpoints",
                        );
                    }
                    match db::is_guest(&exec, body.user_id).await {
                        Err(_) => return database(),
                        Ok(true) => {
                            return full(
                                409,
                                "guest accounts are managed via the guest console (/admin/guests), not the generic user endpoints",
                            )
                        }
                        Ok(false) => {}
                    }
                    let domain = match db::user_domain(&exec, body.user_id).await {
                        Ok(Some(d)) => d,
                        _ => return full(400, "user not found"),
                    };
                    if scope > 0 && domain != scope {
                        return full(403, "user is not in your domain scope");
                    }
                    let quota = body.quota_bytes.filter(|q| *q > 0);
                    match db::create(
                        &exec,
                        actor,
                        body.user_id,
                        &email,
                        &display,
                        quota,
                        scope,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(Some(mailbox)) => created(mailbox),
                        CommandOutcome::Committed(None) => full(400, "user not found"),
                        CommandOutcome::RolledBack(_) => database(),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Update => {
                    let Ok(mailbox) = target(4).parse::<i64>() else {
                        return full(400, "invalid mailbox id");
                    };
                    let Ok(body) = json_body::<UpdateBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    // pgx refuses a Go int outside int4 before anything is sent.
                    let int4 = |v: Option<i64>| v.map(i32::try_from).transpose();
                    let (Ok(deleted), Ok(spam)) =
                        (int4(body.deleted_purge_days), int4(body.spam_purge_days))
                    else {
                        return database();
                    };
                    let patch = db::Patch {
                        display_name: body.display_name.as_deref(),
                        quota_bytes: body.quota_bytes,
                        enabled: body.enabled,
                        litigation_hold: body.litigation_hold,
                        deleted_purge_days: deleted,
                        spam_purge_days: spam,
                    };
                    match db::update(&exec, actor, mailbox, scope, &patch, operation).await {
                        CommandOutcome::Committed(true) => status_only(204),
                        CommandOutcome::Committed(false) => full(404, "mailbox not found"),
                        CommandOutcome::RolledBack(_) => database(),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Delete => {
                    let Ok(mailbox) = target(4).parse::<i64>() else {
                        return full(400, "invalid mailbox id");
                    };
                    match db::lifecycle_enabled(&worker).await {
                        Err(_) => return database(),
                        Ok(true) => {
                            return full(
                                409,
                                "direct mailbox deletion is disabled; detach and retain the mailbox, then use the independently approved purge workflow",
                            )
                        }
                        Ok(false) => {}
                    }
                    if scope > 0 {
                        match db::domain_of(&exec, mailbox).await {
                            Err(_) => return database(),
                            Ok(None) => return full(404, "mailbox not found"),
                            Ok(Some(d)) if d != scope => {
                                return full(403, "access denied: mailbox not in domain scope")
                            }
                            Ok(Some(_)) => {}
                        }
                    }
                    match db::delete(&worker, actor, mailbox, scope, operation).await {
                        CommandOutcome::Committed(true) => status_only(204),
                        CommandOutcome::Committed(false) => {
                            full(403, "access denied: mailbox not in domain scope")
                        }
                        CommandOutcome::RolledBack(_) => database(),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Folders => {
                    let mailbox = atoi(&target(4));
                    if mailbox <= 0 {
                        return full(400, "invalid mailbox id");
                    }
                    if let Err(response) = in_scope(mailbox).await {
                        return response;
                    }
                    match db::folders(&exec, mailbox).await {
                        Ok(body) => reply(body),
                        Err(_) => database(),
                    }
                }
                Action::FolderCreate => {
                    let mailbox = atoi(&target(4));
                    if mailbox <= 0 {
                        return full(400, "invalid mailbox id");
                    }
                    if let Err(response) = in_scope(mailbox).await {
                        return response;
                    }
                    let Ok(body) = json_body::<FolderBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.name.is_empty() {
                        return full(400, "name required");
                    }
                    match db::folder_create(
                        &exec,
                        actor,
                        mailbox,
                        scope,
                        body.parent_id,
                        &body.name,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(folder) => created(folder),
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::FolderUpdate | Action::FolderDelete => {
                    let (mailbox, folder) = (atoi(&target(4)), atoi(&target(6)));
                    if mailbox <= 0 || folder <= 0 {
                        return full(400, "invalid id");
                    }
                    if let Err(response) = in_scope(mailbox).await {
                        return response;
                    }
                    let outcome = if what == Action::FolderUpdate {
                        let Ok(body) = json_body::<RenameBody>(&mut r).await else {
                            return full(400, "invalid JSON");
                        };
                        if body.name.is_empty() {
                            return full(400, "name required");
                        }
                        db::folder_update(
                            &exec, actor, mailbox, scope, folder, &body.name, operation,
                        )
                        .await
                    } else {
                        db::folder_delete(&exec, actor, mailbox, scope, folder, operation).await
                    };
                    match outcome {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::LifecyclePreview
                | Action::Retained
                | Action::Parity
                | Action::Transition
                | Action::PurgeSchedule
                | Action::PurgeApproval
                | Action::PurgeExecute
                | Action::PurgeCancel => {
                    let headers = r.headers().clone();
                    // Go's `writeMailboxLifecycleRaw`: the reducer's jsonb text, no newline (the
                    // gateway's middleware still adds `Cache-Control: no-store`).
                    let raw = |body: String| {
                        // Same 2 KiB net/http buffering rule as `reply`.
                        let chunked = body.len() > 2048 && !head;
                        let mut response =
                            crate::jmap::reply::response(body, c.identity.proto, id.clone());
                        if chunked {
                            response.headers_mut().insert(
                                "transfer-encoding",
                                hyper::header::HeaderValue::from_static("chunked"),
                            );
                        }
                        response
                    };
                    let classified = |e: &StatementFailure, fallback: &str| {
                        match setjoin_mailboxes::lifecycle::classify_failure(e) {
                            Some(k) => render(
                                Problem::new(k.status, &k.detail)
                                    .kind(&format!(
                                        "https://setjoin.com/problems/reducer/{}",
                                        k.code.to_ascii_lowercase()
                                    ))
                                    .instance(&go_path)
                                    .remediation(k.remediation)
                                    .code(&k.code)
                                    .retryable(false),
                                Some(&lang),
                                &c,
                                &id,
                            ),
                            None => bare(500, fallback, &c, &id),
                        }
                    };
                    let rolled = |e: &Rejection<StatementFailure>, fallback: &str| match e {
                        Rejection::Statement(f) | Rejection::Body(f) => classified(f, fallback),
                        _ => bare(500, fallback, &c, &id),
                    };
                    let bad = |detail: &str| bare(400, detail, &c, &id);
                    let header = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned()
                    };
                    // Go's `mailboxLifecycleID`: a positive int64 path value.
                    let positive =
                        |index: usize| target(index).parse::<i64>().ok().filter(|n| *n > 0);
                    let reason_ok = |reason: &str| {
                        reason.len() >= 8
                            && reason.len() <= 1024
                            && !reason.contains(['\r', '\n', '\0'])
                            && header("x-audit-reason").trim() == reason
                    };
                    let key_of = |body_key: &str| -> Result<String, &'static str> {
                        let header_key = header("idempotency-key").trim().to_owned();
                        if header_key.is_empty() || body_key != header_key {
                            return Err("body idempotencyKey must exactly match Idempotency-Key");
                        }
                        match parse_uuid(&header_key) {
                            Some(k) if k != NIL_UUID => Ok(k),
                            _ => Err("invalid Idempotency-Key"),
                        }
                    };
                    const BAD_ID: &str = "invalid mailbox lifecycle identifier";
                    const BAD_REASON: &str =
                        "body reason must exactly match X-Audit-Reason and contain 8-1024 safe characters";
                    match what {
                        Action::LifecyclePreview => {
                            let Some(mailbox) = positive(4) else {
                                return bad(BAD_ID);
                            };
                            match setjoin_mailboxes::lifecycle::preview(
                                &worker,
                                actor.user_id(),
                                mailbox,
                            )
                            .await
                            {
                                Ok(body) => raw(body),
                                Err(e) => classified(&e, "mailbox lifecycle preview failed"),
                            }
                        }
                        Action::Retained => {
                            match setjoin_mailboxes::lifecycle::retained(
                                &worker,
                                actor.user_id(),
                                scope,
                            )
                            .await
                            {
                                Ok(body) => raw(body),
                                Err(e) => classified(&e, "retained mailbox list failed"),
                            }
                        }
                        Action::Parity => match setjoin_mailboxes::lifecycle::parity(&worker).await
                        {
                            Ok(body) => raw(body),
                            Err(_) => bare(500, "mailbox lifecycle parity report failed", &c, &id),
                        },
                        Action::Transition => {
                            let Some(mailbox) = positive(4) else {
                                return bad(BAD_ID);
                            };
                            let body = match strict_body::<TransitionBody>(&mut r).await {
                                Ok(b) => b,
                                Err(detail) => return bad(detail),
                            };
                            if !reason_ok(&body.reason) {
                                return bad(BAD_REASON);
                            }
                            let key = match key_of(&body.idempotency_key) {
                                Ok(k) => k,
                                Err(detail) => return bad(detail),
                            };
                            let generation = match body.expected_generation.parse::<i64>() {
                                Ok(g) if g > 0 => g,
                                _ => return bad("invalid expectedGeneration"),
                            };
                            if !matches!(
                                body.action.as_str(),
                                "suspend" | "resume" | "detach_retain" | "reconnect"
                            ) {
                                return bad("invalid mailbox lifecycle action");
                            }
                            let optional = |raw: &str| -> Result<Option<i64>, ()> {
                                if raw.is_empty() {
                                    return Ok(None);
                                }
                                match raw.parse::<i64>() {
                                    Ok(v) if v > 0 => Ok(Some(v)),
                                    _ => Err(()),
                                }
                            };
                            let (Ok(target_user), Ok(link), Ok(link_generation)) = (
                                optional(&body.target_user_id),
                                optional(&body.identity_link_id),
                                optional(&body.link_generation),
                            ) else {
                                return bad("invalid reconnect evidence");
                            };
                            if !body.delivery.is_empty()
                                && body.delivery != "accepting"
                                && body.delivery != "rejecting"
                            {
                                return bad("invalid delivery mode");
                            }
                            if !body.redirect_address.is_empty() {
                                return bad("redirect delivery is not available");
                            }
                            let digest = setjoin_mailboxes::lifecycle::TransitionRequest {
                                action: body.action.clone(),
                                expected_generation: body.expected_generation.clone(),
                                idempotency_key: body.idempotency_key.clone(),
                                reason: body.reason.clone(),
                                target_user_id: body.target_user_id.clone(),
                                evidence_kind: body.evidence_kind.clone(),
                                identity_link_id: body.identity_link_id.clone(),
                                link_generation: body.link_generation.clone(),
                                source_key_digest: body.source_key_digest.clone(),
                                delivery: body.delivery.clone(),
                                redirect_address: body.redirect_address.clone(),
                            }
                            .digest();
                            let request = setjoin_mailboxes::lifecycle::Transition {
                                mailbox,
                                key: &key,
                                action: &body.action,
                                generation,
                                digest: &digest,
                                reason: &body.reason,
                                target: target_user,
                                evidence_kind: nonempty(&body.evidence_kind),
                                link_id: link,
                                link_generation,
                                source_key_digest: nonempty(&body.source_key_digest),
                                auth_time: actor.auth_time(),
                                delivery: nonempty(&body.delivery),
                            };
                            match setjoin_mailboxes::lifecycle::transition(
                                &worker, actor, &request, operation,
                            )
                            .await
                            {
                                CommandOutcome::Committed(body) => raw(body),
                                CommandOutcome::RolledBack(e) => {
                                    rolled(&e, "mailbox lifecycle transition failed")
                                }
                                CommandOutcome::Unknown { operation } => {
                                    unknown_outcome(operation, &c, &id)
                                }
                            }
                        }
                        Action::PurgeSchedule => {
                            let Some(mailbox) = positive(4) else {
                                return bad(BAD_ID);
                            };
                            let body = match strict_body::<PurgeBody>(&mut r).await {
                                Ok(b) => b,
                                Err(detail) => return bad(detail),
                            };
                            if !reason_ok(&body.reason) {
                                return bad(BAD_REASON);
                            }
                            let key = match key_of(&body.idempotency_key) {
                                Ok(k) => k,
                                Err(detail) => return bad(detail),
                            };
                            let generation = body
                                .expected_generation
                                .parse::<i64>()
                                .ok()
                                .filter(|g| *g > 0);
                            let approver =
                                body.approver_user_id.parse::<i64>().ok().filter(|a| *a > 0);
                            let (Some(generation), Some(approver), 64) =
                                (generation, approver, body.preview_digest.len())
                            else {
                                return bad("invalid purge schedule request");
                            };
                            let digest = setjoin_mailboxes::lifecycle::PurgeRequest {
                                expected_generation: body.expected_generation.clone(),
                                preview_digest: body.preview_digest.clone(),
                                idempotency_key: body.idempotency_key.clone(),
                                reason: body.reason.clone(),
                                approver_user_id: body.approver_user_id.clone(),
                            }
                            .digest();
                            let preview = body.preview_digest.to_lowercase();
                            let request = setjoin_mailboxes::lifecycle::Purge {
                                mailbox,
                                key: &key,
                                generation,
                                preview_digest: &preview,
                                digest: &digest,
                                reason: &body.reason,
                                approver,
                            };
                            match setjoin_mailboxes::lifecycle::purge_schedule(
                                &worker, actor, &request, operation,
                            )
                            .await
                            {
                                CommandOutcome::Committed(body) => raw(body),
                                CommandOutcome::RolledBack(e) => {
                                    rolled(&e, "mailbox purge scheduling failed")
                                }
                                CommandOutcome::Unknown { operation } => {
                                    unknown_outcome(operation, &c, &id)
                                }
                            }
                        }
                        Action::PurgeApproval => {
                            let Some(request_id) = positive(3 + 1) else {
                                return bad(BAD_ID);
                            };
                            let body = match strict_body::<ApprovalBody>(&mut r).await {
                                Ok(b) => b,
                                // Go's `!decode(..) || ...` writes the decode problem and then, the
                                // condition being true, the decision problem into the same response.
                                Err(detail) => {
                                    let mut response = bad(detail);
                                    crate::problem::set_body(
                                        &mut response,
                                        Problem::new(400, detail).body()
                                            + &Problem::new(400, "invalid purge approval decision")
                                                .body(),
                                    );
                                    return response;
                                }
                            };
                            if (body.decision != "approve" && body.decision != "deny")
                                || body.comment.len() > 1024
                            {
                                return bad("invalid purge approval decision");
                            }
                            match setjoin_mailboxes::lifecycle::purge_approval(
                                &worker,
                                actor,
                                request_id,
                                &body.decision,
                                &body.comment,
                                operation,
                            )
                            .await
                            {
                                CommandOutcome::Committed(body) => raw(body),
                                CommandOutcome::RolledBack(e) => {
                                    rolled(&e, "mailbox purge approval failed")
                                }
                                CommandOutcome::Unknown { operation } => {
                                    unknown_outcome(operation, &c, &id)
                                }
                            }
                        }
                        _ => {
                            // purge execute / cancel
                            let purge = match parse_uuid(&target(4)) {
                                Some(p) if p != NIL_UUID => p,
                                _ => return bad("invalid purge request id"),
                            };
                            let body = match strict_body::<KeyedBody>(&mut r).await {
                                Ok(b) => b,
                                Err(detail) => return bad(detail),
                            };
                            if !reason_ok(&body.reason) {
                                return bad(BAD_REASON);
                            }
                            let key = match key_of(&body.idempotency_key) {
                                Ok(k) => k,
                                Err(detail) => return bad(detail),
                            };
                            let digest = setjoin_mailboxes::lifecycle::keyed_digest(
                                &body.idempotency_key,
                                &body.reason,
                            );
                            let outcome = if what == Action::PurgeExecute {
                                setjoin_mailboxes::lifecycle::purge_execute(
                                    &worker, actor, &purge, &key, &digest, operation,
                                )
                                .await
                            } else {
                                setjoin_mailboxes::lifecycle::purge_cancel(
                                    &worker,
                                    actor,
                                    &purge,
                                    &key,
                                    &digest,
                                    &body.reason,
                                    operation,
                                )
                                .await
                            };
                            match outcome {
                                CommandOutcome::Committed(body) => raw(body),
                                CommandOutcome::RolledBack(e) => rolled(
                                    &e,
                                    if what == Action::PurgeExecute {
                                        "mailbox purge execution failed"
                                    } else {
                                        "mailbox purge cancellation failed"
                                    },
                                ),
                                CommandOutcome::Unknown { operation } => {
                                    unknown_outcome(operation, &c, &id)
                                }
                            }
                        }
                    }
                }
            }
        })
    }
}

/// Go sees the `/api`-stripped request path, decoded.
pub(crate) fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_of_the_slice_is_recognised_once() {
        use Action::*;
        let cases = [
            ("GET", "/api/admin/mailboxes", List),
            ("POST", "/api/admin/mailboxes", Create),
            ("GET", "/api/admin/mailboxes/7", Get),
            ("PUT", "/api/admin/mailboxes/7", Update),
            ("DELETE", "/api/admin/mailboxes/7", Delete),
            ("GET", "/api/admin/mailboxes/7/folders", Folders),
            ("POST", "/api/admin/mailboxes/7/folders", FolderCreate),
            ("PUT", "/api/admin/mailboxes/7/folders/3", FolderUpdate),
            ("DELETE", "/api/admin/mailboxes/7/folders/3", FolderDelete),
            (
                "GET",
                "/api/admin/mailboxes/7/lifecycle/preview",
                LifecyclePreview,
            ),
            ("GET", "/api/admin/mailboxes/retained", Retained),
            ("GET", "/api/admin/mailboxes/lifecycle/parity", Parity),
            ("POST", "/api/admin/mailboxes/7/lifecycle", Transition),
            ("POST", "/api/admin/mailboxes/7/purge", PurgeSchedule),
            (
                "POST",
                "/api/admin/mailbox-purge-approvals/7",
                PurgeApproval,
            ),
            ("POST", "/api/admin/mailbox-purges/x/execute", PurgeExecute),
            ("POST", "/api/admin/mailbox-purges/x/cancel", PurgeCancel),
        ];
        for (method, path, want) in cases {
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            assert_eq!(action(&method, path), Some(want), "{method} {path}");
        }
        // Import and export stay with Go until their MIME and ZIP streams are ported.
        assert_eq!(action(&Method::POST, "/api/admin/mailboxes/7/import"), None);
        assert_eq!(action(&Method::GET, "/api/admin/mailboxes/7/export"), None);
        assert_eq!(action(&Method::PATCH, "/api/admin/mailboxes/7"), None);
    }

    #[test]
    fn uuid_parse_matches_google_uuid() {
        let want = Some("5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10".to_owned());
        for text in [
            "5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10",
            "urn:uuid:5F0C1A52-8D3E-4B7A-9C61-0E2D4F6A8B10",
            "URN:UUID:5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10",
            "{5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10}",
            // Go drops only the first character of a 38-byte value and ignores the last.
            "{5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10X",
            "5f0c1a528d3e4b7a9c610e2d4f6a8b10",
        ] {
            assert_eq!(parse_uuid(text), want, "{text}");
        }
        assert_eq!(parse_uuid("5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b1"), None);
        assert_eq!(parse_uuid("5f0c1a52x8d3e-4b7a-9c61-0e2d4f6a8b10"), None);
        assert_eq!(parse_uuid("gf0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10"), None);
    }

    #[test]
    fn email_model_matches_validate_canonical_email() {
        assert_eq!(
            canonical_email("a.b+c@example.test"),
            Ok(Some("a.b+c@example.test".into()))
        );
        assert_eq!(canonical_email("not-an-email"), Err("invalid email format"));
        assert_eq!(
            canonical_email("a..b@example.test"),
            Err("local-part contains consecutive dots")
        );
        assert_eq!(
            canonical_email(".ab@example.test"),
            Err("local-part starts with a dot")
        );
        assert_eq!(
            canonical_email("ab.@example.test"),
            Err("local-part ends with a dot")
        );
        assert_eq!(
            canonical_email("ab@localhost"),
            Err("domain must contain at least one dot")
        );
        assert_eq!(
            canonical_email("ab@ex_ample.test"),
            Err("domain contains underscore")
        );
        assert_eq!(
            canonical_email("ab@exa mple.test"),
            Ok(None),
            "judged by Go"
        );
        assert_eq!(
            canonical_email("\"a b\"@example.test"),
            Ok(None),
            "judged by Go"
        );
        assert_eq!(
            canonical_email("Name <a@example.test>"),
            Ok(None),
            "judged by Go"
        );
        assert_eq!(
            canonical_email(&"x".repeat(255)),
            Err("email exceeds 254 characters")
        );
    }
}
