//! F13 `golden-routes` (#285): meeting create/list/get/by-slug and the three
//! void host controls. Frozen Go is the oracle; LiveKit stays a peripheral.
use crate::chat_channels::{
    bool_field, decode_fields, number_field, optional_field, problem, problem_language, read_body,
    strings_field, text_field, ReadError,
};
use crate::meet_livekit::{parse_uuid, parse_webhook, GrantSpec, LiveKit, WEBHOOK_MAX_BODY};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Go's `breakoutEmptyTimeout`/`breakoutDepartureTimeout` (D12): 24 h each.
const BREAKOUT_TIMEOUT: u32 = 86400;

#[path = "meet_b.rs"]
mod b;
#[path = "meet_c.rs"]
mod c;

pub struct MeetRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// Go's `meet.Config`: LiveKit key pair and URL, egress and ASR presence.
    pub livekit: LiveKit,
    /// Go's per-process admitted re-mint window (second layer; the reducer's
    /// durable fence is the first). Bounded, expiring, never authority.
    mints: Arc<MintFence>,
    /// Go's per-process checkpoint refresh budget (never authority).
    throttle: Arc<b::Throttle>,
    /// The cross-tenant worker credential (BYPASSRLS) for the admin registry
    /// read; defaults to the request executor until the native-RLS flip.
    worker: ScopedExecutor,
}

impl<K: KeySource + 'static> MeetRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String, livekit: LiveKit) -> Self {
        Self {
            worker: exec.clone(),
            exec,
            keys,
            issuer,
            livekit,
            mints: Arc::default(),
            throttle: Arc::default(),
        }
    }

    /// Pin the checkpoint-refresh throttle clock (oracle tests on a slow host, #421).
    pub fn with_pinned_checkpoint_throttle(mut self) -> Self {
        self.throttle = Arc::new(b::Throttle::pinned());
        self
    }

    /// Serve the admin recordings registry from the worker credential.
    pub fn with_worker(mut self, worker: ScopedExecutor) -> Self {
        self.worker = worker;
        self
    }
}

const ADMITTED_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_WINDOWS: usize = 4096;

/// Go's `admittedMintFence`: the first admitted mint per join request opens a
/// 15 minute window; a full store of live windows refuses new first mints.
#[derive(Default)]
struct MintFence(Mutex<HashMap<i64, Instant>>);

impl MintFence {
    fn allow(&self, request: i64) -> bool {
        let at = Instant::now();
        let mut open = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(first) = open.get(&request) {
            return at.duration_since(*first) <= ADMITTED_WINDOW;
        }
        if open.len() >= MAX_WINDOWS {
            open.retain(|_, first| at.duration_since(*first) <= ADMITTED_WINDOW);
            if open.len() >= MAX_WINDOWS {
                return false;
            }
        }
        open.insert(request, at);
        true
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Create,
    List,
    BySlug,
    Get,
    Lock,
    Settings,
    Role,
    Join,
    Kick,
    End,
    Knock,
    Decide,
    BreakoutOpen,
    BreakoutAssign,
    BreakoutClose,
    BreakoutJoin,
    RecStart,
    RecStop,
    CapStart,
    CapStop,
    Prepare,
    Ready,
    PresStart,
    Page,
    Presenter,
    Source,
    Degrade,
    Recover,
    PresEnd,
    Revoke,
    Checkpoint,
    AnnCommit,
    AnnRead,
    PublicCreate,
    PublicPoll,
    Webhook,
    LocalLease,
    LocalHeartbeat,
    LocalStop,
    LocalRegister,
    SemPackage,
    SemReplay,
    AdminRecordings,
}

fn kind(method: &Method, path: &str) -> Option<Kind> {
    use crate::inventory::path_score as hit;
    let get = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let delete = *method == Method::DELETE;
    if let Some(found) = kind_b(get, post, delete, path) {
        return Some(found);
    }
    if let Some(found) = kind_c(get, post, path) {
        return Some(found);
    }
    if get && hit("/api/meet", path).is_some() {
        Some(Kind::List)
    } else if post && hit("/api/meet", path).is_some() {
        Some(Kind::Create)
    } else if get && hit("/api/meet/by-slug/{slug}", path).is_some() {
        Some(Kind::BySlug)
    } else if get && hit("/api/meet/{id}", path).is_some() {
        Some(Kind::Get)
    } else if post && hit("/api/meet/{id}/lock", path).is_some() {
        Some(Kind::Lock)
    } else if post && hit("/api/meet/{id}/settings", path).is_some() {
        Some(Kind::Settings)
    } else if post && hit("/api/meet/{id}/role", path).is_some() {
        Some(Kind::Role)
    } else if post && hit("/api/meet/webhook", path).is_some() {
        Some(Kind::Webhook)
    } else if post && hit("/api/meet/{id}/join", path).is_some() {
        Some(Kind::Join)
    } else if post && hit("/api/meet/{id}/kick", path).is_some() {
        Some(Kind::Kick)
    } else if post && hit("/api/meet/{id}/end", path).is_some() {
        Some(Kind::End)
    } else if post && hit("/api/meet/{id}/knock", path).is_some() {
        Some(Kind::Knock)
    } else if post && hit("/api/meet/{id}/requests/{reqId}", path).is_some() {
        Some(Kind::Decide)
    } else if post && hit("/api/meet/{id}/breakouts", path).is_some() {
        Some(Kind::BreakoutOpen)
    } else if post && hit("/api/meet/{id}/breakouts/assign", path).is_some() {
        Some(Kind::BreakoutAssign)
    } else if post && hit("/api/meet/{id}/breakouts/close", path).is_some() {
        Some(Kind::BreakoutClose)
    } else if post && hit("/api/meet/{id}/breakouts/join", path).is_some() {
        Some(Kind::BreakoutJoin)
    } else if post && hit("/api/public/meet/{slug}/join-request", path).is_some() {
        Some(Kind::PublicCreate)
    } else if get && hit("/api/public/meet/{slug}/join-request/{id}", path).is_some() {
        Some(Kind::PublicPoll)
    } else {
        None
    }
}

/// The #288 sub-router-c routes (the catch-alls and asrbot stay with Go).
fn kind_c(get: bool, post: bool, path: &str) -> Option<Kind> {
    use crate::inventory::path_score as hit;
    if post && hit("/api/meet/{id}/local/lease", path).is_some() {
        Some(Kind::LocalLease)
    } else if post && hit("/api/meet/{id}/local/{rid}/heartbeat", path).is_some() {
        Some(Kind::LocalHeartbeat)
    } else if post && hit("/api/meet/{id}/local/{rid}/stop", path).is_some() {
        Some(Kind::LocalStop)
    } else if post && hit("/api/meet/{id}/local/{rid}/register", path).is_some() {
        Some(Kind::LocalRegister)
    } else if get && hit("/api/meet/{id}/semantic/{rid}/package", path).is_some() {
        Some(Kind::SemPackage)
    } else if get && hit("/api/meet/{id}/semantic/{rid}/replay", path).is_some() {
        Some(Kind::SemReplay)
    } else if get && hit("/api/admin/meet/recordings", path).is_some() {
        Some(Kind::AdminRecordings)
    } else {
        None
    }
}

/// The #287 sub-router-b routes.
fn kind_b(get: bool, post: bool, delete: bool, path: &str) -> Option<Kind> {
    use crate::inventory::path_score as hit;
    let verb = |name: &str| {
        post && hit(
            &format!("/api/meet/{{id}}/presentation/{{pid}}/{name}"),
            path,
        )
        .is_some()
    };
    if post && hit("/api/meet/{id}/recording", path).is_some() {
        Some(Kind::RecStart)
    } else if delete && hit("/api/meet/{id}/recording", path).is_some() {
        Some(Kind::RecStop)
    } else if post && hit("/api/meet/{id}/captions", path).is_some() {
        Some(Kind::CapStart)
    } else if delete && hit("/api/meet/{id}/captions", path).is_some() {
        Some(Kind::CapStop)
    } else if post && hit("/api/meet/{id}/presentation", path).is_some() {
        Some(Kind::Prepare)
    } else if verb("ready") {
        Some(Kind::Ready)
    } else if verb("start") {
        Some(Kind::PresStart)
    } else if verb("page") {
        Some(Kind::Page)
    } else if verb("presenter") {
        Some(Kind::Presenter)
    } else if verb("source") {
        Some(Kind::Source)
    } else if verb("degrade") {
        Some(Kind::Degrade)
    } else if verb("recover") {
        Some(Kind::Recover)
    } else if verb("end") {
        Some(Kind::PresEnd)
    } else if verb("revoke") {
        Some(Kind::Revoke)
    } else if verb("annotation") {
        Some(Kind::AnnCommit)
    } else if get && hit("/api/meet/{id}/presentation/{pid}/checkpoint", path).is_some() {
        Some(Kind::Checkpoint)
    } else if get && hit("/api/meet/{id}/presentation/{pid}/annotation", path).is_some() {
        Some(Kind::AnnRead)
    } else {
        None
    }
}

impl<K: KeySource + 'static> Intercept for MeetRoute<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool { !matches!(kind(r.method(), r.uri().path()), Some(Kind::Webhook | Kind::PublicCreate | Kind::PublicPoll)) }
    fn matches(&self, r: &Request<Body>) -> bool {
        kind(r.method(), r.uri().path()).is_some()
    }
    fn admits_member(&self, h: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_user_request(&exec, &keys, &issuer, &h, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let (livekit, mints) = (self.livekit.clone(), self.mints.clone());
        let throttle = self.throttle.clone();
        let worker = self.worker.clone();
        Box::pin(async move {
            let language = problem_language(r.headers());
            let id = crate::jmap::reply::request_id(
                r.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            // Go's StripPrefix rejects an encoded spelling of the API mount.
            if r.uri()
                .path()
                .split('/')
                .nth(1)
                .is_some_and(|segment| segment != "api")
            {
                let mut reply = crate::jmap::reply::response(
                    "404 page not found\n".into(),
                    c.identity.proto,
                    id,
                );
                *reply.status_mut() = hyper::StatusCode::NOT_FOUND;
                reply.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                return reply;
            }
            let Some(kind) = kind(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            // The webhook and the guest lobby carry no caller identity: LiveKit's
            // signed token and the lobby secret are their only credentials.
            match kind {
                Kind::Webhook => return webhook(&exec, &livekit, r, &c, id).await,
                Kind::PublicCreate | Kind::PublicPoll => {
                    return public(&exec, &livekit, &mints, kind, r, &c, id, &language).await
                }
                _ => {}
            }
            let Some(auth) = setjoin_authz::authorize_user_request(
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
            if kind == Kind::AdminRecordings {
                // Go mounts this under adminLimit and drive.view only: no
                // feature.meet, entitlement or LiveKit gate.
                let decoded = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
                    .into_owned();
                let path = decoded.strip_prefix("/api").unwrap_or(&decoded).to_owned();
                return c::registry(&exec, &worker, auth.context(), &r, &c, id, &language, &path)
                    .await;
            }
            match setjoin_meet::enabled(&exec).await {
                Ok(true) => {}
                Ok(false) => {
                    let mut reply = problem(404, "not found", "", &c, id, &language);
                    reply.headers_mut().remove("content-language");
                    return reply;
                }
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            }
            let decoded =
                String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path())).into_owned();
            let path = decoded.strip_prefix("/api").unwrap_or(&decoded).to_owned();
            let entitled=tokio::time::timeout(setjoin_authz::precheck_timeout(),
                setjoin_meet::entitled(&exec,auth.context())).await;
            if !matches!(entitled,Ok(Ok(true))) {
                let actor=setjoin_contracts::ids::ActorId::new(auth.context().user_id()).expect("verified actor");
                let ip=c.identity.client_ip.to_string();
                let _=tokio::time::timeout(setjoin_authz::precheck_timeout(),
                    exec.audit_app_blocked(actor,"meet",&ip)).await;
                let detail="Access to this application is not permitted for your account.";
                let mut response=problem(403,detail,&path,&c,id,&language);
                crate::problem::set_body(&mut response,crate::problem::Problem::new(403,detail)
                    .kind("https://setjoin.com/errors/forbidden").instance(&path).body());
                return response;
            }
            if !livekit.configured() {
                return unconfigured(&path, &c, id, &language);
            }
            let segments: Vec<&str> = r.uri().path().split('/').collect();
            let unescaped = |i: usize| {
                String::from_utf8_lossy(&crate::inventory::unescape(segments[i])).into_owned()
            };
            let actor = auth.context();
            match kind {
                Kind::List => read(
                    setjoin_meet::list(&exec, actor).await,
                    &path,
                    &c,
                    id,
                    &language,
                ),
                Kind::BySlug => read(
                    setjoin_meet::by_slug(&exec, actor, &unescaped(4)).await,
                    &path,
                    &c,
                    id,
                    &language,
                ),
                Kind::Get => {
                    let Ok(meeting) = unescaped(3).parse::<i64>() else {
                        return problem(400, "invalid meeting id", &path, &c, id, &language);
                    };
                    read(
                        setjoin_meet::get(&exec, actor, meeting).await,
                        &path,
                        &c,
                        id,
                        &language,
                    )
                }
                Kind::Create => {
                    let Ok(fields) = body_fields(&mut r).await else {
                        return problem(400, "invalid JSON", &path, &c, id, &language);
                    };
                    let Ok(meeting) = new_meeting(&fields) else {
                        return problem(400, "invalid JSON", &path, &c, id, &language);
                    };
                    let Some(operation) = crate::jmap::random() else {
                        return problem(500, "request failed", &path, &c, id, &language);
                    };
                    match setjoin_meet::create(&exec, actor, &meeting, operation).await {
                        setjoin_pg::CommandOutcome::Committed(raw) => {
                            match crate::jmap::reply::go_compact(&raw) {
                                Some(body) => {
                                    let mut reply = crate::jmap::reply::response(
                                        body + "\n",
                                        c.identity.proto,
                                        id,
                                    );
                                    *reply.status_mut() = hyper::StatusCode::CREATED;
                                    reply
                                }
                                None => problem(500, "request failed", &path, &c, id, &language),
                            }
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => void(
                            setjoin_pg::CommandOutcome::Unknown { operation },
                            &path,
                            &c,
                            id,
                            &language,
                        ),
                        setjoin_pg::CommandOutcome::RolledBack(e) => void(
                            setjoin_pg::CommandOutcome::RolledBack(e),
                            &path,
                            &c,
                            id,
                            &language,
                        ),
                    }
                }
                Kind::Join
                | Kind::Kick
                | Kind::End
                | Kind::Knock
                | Kind::Decide
                | Kind::BreakoutOpen
                | Kind::BreakoutAssign
                | Kind::BreakoutClose
                | Kind::BreakoutJoin => {
                    let ctx = Authed {
                        exec: &exec,
                        livekit: &livekit,
                        actor,
                        path: &path,
                        c: &c,
                        id: id.clone(),
                        language: &language,
                        throttle: &throttle,
                    };
                    let (meeting_text, request_text) =
                        (unescaped(3), segments.get(5).map(|_| unescaped(5)));
                    return ctx
                        .run(kind, &meeting_text, request_text.as_deref(), r)
                        .await;
                }
                Kind::Lock | Kind::Settings | Kind::Role => {
                    let Ok(meeting) = unescaped(3).parse::<i64>() else {
                        return problem(400, "invalid meeting id", &path, &c, id, &language);
                    };
                    let Ok(fields) = body_fields(&mut r).await else {
                        return problem(400, "invalid JSON", &path, &c, id, &language);
                    };
                    let Some(operation) = crate::jmap::random() else {
                        return problem(500, "request failed", &path, &c, id, &language);
                    };
                    let result = match kind {
                        Kind::Lock => match bool_field(&fields, "LOCKED") {
                            Ok(v) => setjoin_meet::lock(&exec, actor, meeting, v, operation).await,
                            Err(()) => {
                                return problem(400, "invalid JSON", &path, &c, id, &language)
                            }
                        },
                        Kind::Settings => match bool_field(&fields, "GUESTALLOWED") {
                            Ok(v) => {
                                setjoin_meet::set_guest_allowed(&exec, actor, meeting, v, operation)
                                    .await
                            }
                            Err(()) => {
                                return problem(400, "invalid JSON", &path, &c, id, &language)
                            }
                        },
                        _ => match (text_field(&fields, "IDENTITY"), text_field(&fields, "ROLE")) {
                            (Ok(identity), Ok(role)) => {
                                setjoin_meet::set_role(
                                    &exec, actor, meeting, &identity, &role, operation,
                                )
                                .await
                            }
                            _ => return problem(400, "invalid JSON", &path, &c, id, &language),
                        },
                    };
                    void(result, &path, &c, id, &language)
                }
                Kind::RecStart
                | Kind::RecStop
                | Kind::CapStart
                | Kind::CapStop
                | Kind::Prepare
                | Kind::Ready
                | Kind::PresStart
                | Kind::Page
                | Kind::Presenter
                | Kind::Source
                | Kind::Degrade
                | Kind::Recover
                | Kind::PresEnd
                | Kind::Revoke
                | Kind::Checkpoint
                | Kind::AnnCommit
                | Kind::AnnRead => {
                    let ctx = Authed {
                        exec: &exec,
                        livekit: &livekit,
                        actor,
                        path: &path,
                        c: &c,
                        id: id.clone(),
                        language: &language,
                        throttle: &throttle,
                    };
                    let (meeting_text, pres_text) =
                        (unescaped(3), segments.get(5).map(|_| unescaped(5)));
                    return ctx
                        .run_b(kind, &meeting_text, pres_text.as_deref(), r)
                        .await;
                }
                Kind::LocalLease
                | Kind::LocalHeartbeat
                | Kind::LocalStop
                | Kind::LocalRegister
                | Kind::SemPackage
                | Kind::SemReplay => {
                    let ctx = Authed {
                        exec: &exec,
                        livekit: &livekit,
                        actor,
                        path: &path,
                        c: &c,
                        id: id.clone(),
                        language: &language,
                        throttle: &throttle,
                    };
                    let (meeting_text, recording_text) =
                        (unescaped(3), segments.get(5).map(|_| unescaped(5)));
                    return ctx
                        .run_c(kind, &meeting_text, recording_text.as_deref(), r)
                        .await;
                }
                Kind::Webhook | Kind::PublicCreate | Kind::PublicPoll | Kind::AdminRecordings => {
                    unreachable!("served before the meet gates")
                }
            }
        })
    }
}

async fn body_fields(r: &mut Request<Body>) -> Result<crate::chat::Fields, ()> {
    // Go's DecodeJSON reports every failure (including the size cap) as 400.
    let bytes = match read_body(r).await {
        Ok(v) => v,
        Err(ReadError::TooLarge | ReadError::Transport) => return Err(()),
    };
    decode_fields(&bytes)
}

fn new_meeting(fields: &crate::chat::Fields) -> Result<setjoin_meet::NewMeeting, ()> {
    let time = |key| -> Result<Option<String>, ()> {
        let value = optional_field::<String>(fields, key)?;
        if let Some(text) = &value {
            // time.Time.UnmarshalJSON accepts only strict RFC 3339 with 'T' and 'Z'.
            let b = text.as_bytes();
            let strict =
                b.get(10) == Some(&b'T') && !text.contains(['t', 'z']) && !text.contains(":60");
            if !strict || chrono::DateTime::parse_from_rfc3339(text).is_err() {
                return Err(());
            }
        }
        Ok(value)
    };
    Ok(setjoin_meet::NewMeeting {
        title: text_field(fields, "TITLE")?,
        start: time("SCHEDULEDSTART")?,
        end: time("SCHEDULEDEND")?,
        chat_channel: optional_field(fields, "CHATCHANNELID")?,
        calendar_event: optional_field(fields, "CALENDAREVENTID")?,
        guest_allowed: optional_field(fields, "GUESTALLOWED")?,
    })
}

fn read(
    result: Result<String, setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match result {
        Ok(raw) => match crate::jmap::reply::go_compact(&raw) {
            Some(body) => crate::jmap::reply::response(body + "\n", c.identity.proto, id),
            None => problem(500, "request failed", path, c, id, language),
        },
        Err(error) => failure(&error, path, c, id, language),
    }
}

fn void(
    result: setjoin_pg::CommandOutcome<(), setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match result {
        setjoin_pg::CommandOutcome::Committed(()) => {
            let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
            response.headers_mut().remove("content-type");
            response
        }
        setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
            let mut response = problem(503, "meet command outcome unknown", path, c, id, language);
            response.headers_mut().insert(
                "x-operation-id",
                setjoin_pg::operation_hex(operation)
                    .parse()
                    .expect("opaque operation ID"),
            );
            response
        }
        setjoin_pg::CommandOutcome::RolledBack(error) => match &error {
            setjoin_pg::Rejection::Body(e) | setjoin_pg::Rejection::Statement(e) => {
                failure(e, path, c, id, language)
            }
            _ => problem(500, "request failed", path, c, id, language),
        },
    }
}

pub(crate) fn unconfigured(path: &str, c: &RequestContext, id: String, language: &str) -> Response<Body> {
    unconfigured_with(
        "meet is not configured (LIVEKIT_* missing)",
        path,
        c,
        id,
        language,
    )
}

fn unconfigured_with(
    detail: &str,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let mut response = problem(503, detail, path, c, id, language);
    let raw = crate::problem::Problem::new(503, detail)
        .kind("https://setjoin.com/errors/service-unavailable")
        .instance(path)
        .body();
    crate::problem::set_body(&mut response, raw);
    response
}

/// Go's `bzSlug` table plus the shared reducererr class projection for the
/// BZ codes the F13 reducers raise.
fn failure(
    error: &setjoin_pg::StatementFailure,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let Some(code) = error.sqlstate.as_deref() else {
        return problem(500, "request failed", path, c, id, language);
    };
    let (status, slug, detail) = match code {
        "BZ185" => (404, Some("not-found"), "notFound"),
        "BZ186" => (403, Some("forbidden"), "forbidden"),
        "BZ187" => (403, Some("meeting-locked"), "forbidden"),
        "BZ188" | "BZ189" => (422, Some("invalid-arguments"), "unprocessable"),
        "BZ190" => (409, Some("conflict"), "conflict"),
        "BZ199" => (403, Some("recording-guest-exclusion"), "forbidden"),
        "BZ200" => (409, Some("recording-conflict"), "conflict"),
        "BZ201" => (422, Some("breakout-invalid"), "unprocessable"),
        "BZ329" => (409, Some("stateMismatch"), "stateMismatch"),
        "BZ272" => (404, Some("presentation-not-found"), "notFound"),
        "BZ273" => (403, Some("presentation-forbidden"), "forbidden"),
        "BZ274" => (409, Some("stale-presenter-generation"), "conflict"),
        "BZ275" => (409, Some("presentation-lifecycle"), "conflict"),
        "BZ276" => (422, Some("presentation-invalid-arguments"), "unprocessable"),
        "BZ277" => (403, Some("annotation-not-admitted"), "forbidden"),
        "BZ278" => (409, Some("semantic-recording-conflict"), "conflict"),
        "BZ279" => (409, Some("semantic-segment-conflict"), "conflict"),
        "BZ280" => (409, Some("sjrec-package-conflict"), "conflict"),
        "BZ281" => (422, Some("semantic-export-invalid"), "unprocessable"),
        "BZ282" => (409, Some("local-capture-lease-conflict"), "conflict"),
        "BZ283" => (422, Some("local-capture-invalid"), "unprocessable"),
        "BZ284" => (403, Some("local-package-not-admitted"), "forbidden"),
        // Class-only projection: no slug table entry, so no type or code.
        "BZ215" => (403, None, "forbidden"),
        _ => return problem(500, "request failed", path, c, id, language),
    };
    match slug {
        Some(slug) => meet_problem(status, detail, slug, code, path, c, id, language),
        None => problem(status, detail, path, c, id, language),
    }
}

fn meet_problem(
    status: u16,
    detail: &str,
    slug: &str,
    code: &str,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let mut response = problem(status, detail, path, c, id, language);
    let kind = format!("https://setjoin.com/problems/meet/{slug}");
    let body = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path)
        .code(code)
        .body();
    crate::problem::set_body(&mut response, body);
    response
}

/// `httputil.WriteProblemStatus`: no instance, no Content-Language.
fn plain(status: u16, detail: &str, c: &RequestContext, id: String) -> Response<Body> {
    let mut reply = problem(status, detail, "", c, id, "en");
    reply.headers_mut().remove("content-language");
    reply
}

fn json_reply(status: u16, body: String, c: &RequestContext, id: String) -> Response<Body> {
    let mut reply = crate::jmap::reply::response(body, c.identity.proto, id);
    *reply.status_mut() = hyper::StatusCode::from_u16(status).expect("static status");
    reply
}

fn empty_reply(status: u16, c: &RequestContext, id: String) -> Response<Body> {
    let mut reply = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *reply.status_mut() = hyper::StatusCode::from_u16(status).expect("static status");
    reply.headers_mut().remove("content-type");
    reply
}

/// A committed command's value, or the reply for an unknown or rolled-back one.
fn committed<T>(
    outcome: setjoin_pg::CommandOutcome<T, setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Result<T, Response<Body>> {
    match outcome {
        setjoin_pg::CommandOutcome::Committed(v) => Ok(v),
        setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
            let mut response = problem(503, "meet command outcome unknown", path, c, id, language);
            response.headers_mut().insert(
                "x-operation-id",
                setjoin_pg::operation_hex(operation)
                    .parse()
                    .expect("opaque operation ID"),
            );
            Err(response)
        }
        setjoin_pg::CommandOutcome::RolledBack(error) => Err(match &error {
            setjoin_pg::Rejection::Body(e) | setjoin_pg::Rejection::Statement(e) => {
                failure(e, path, c, id, language)
            }
            _ => problem(500, "request failed", path, c, id, language),
        }),
    }
}

/// An authenticated, entitled, LiveKit-configured request for the routes that
/// call the room controller. The verified user is the only identity.
struct Authed<'a> {
    exec: &'a ScopedExecutor,
    livekit: &'a LiveKit,
    actor: &'a setjoin_authz::AuthContext,
    path: &'a str,
    c: &'a RequestContext,
    id: String,
    language: &'a str,
    throttle: &'a b::Throttle,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Envelope {
    #[serde(rename = "roomName")]
    room_name: String,
}

impl Authed<'_> {
    fn problem(&self, status: u16, detail: &str) -> Response<Body> {
        problem(
            status,
            detail,
            self.path,
            self.c,
            self.id.clone(),
            self.language,
        )
    }

    fn plain(&self, status: u16, detail: &str) -> Response<Body> {
        plain(status, detail, self.c, self.id.clone())
    }

    fn commit<T>(
        &self,
        outcome: setjoin_pg::CommandOutcome<T, setjoin_pg::StatementFailure>,
    ) -> Result<T, Response<Body>> {
        committed(outcome, self.path, self.c, self.id.clone(), self.language)
    }

    /// A raw reducer JSON value in Go's compact form with a trailing newline.
    fn json(&self, status: u16, raw: &str) -> Response<Body> {
        match crate::jmap::reply::go_compact(raw) {
            Some(body) => json_reply(status, body + "\n", self.c, self.id.clone()),
            None => self.problem(500, "request failed"),
        }
    }

    fn grant(&self, text: &str) -> Result<GrantSpec, Response<Body>> {
        serde_json::from_str::<Option<GrantSpec>>(text)
            .map(Option::unwrap_or_default)
            .map_err(|_| self.plain(500, "internal error"))
    }

    fn mint(&self, spec: &GrantSpec) -> Result<(String, String), Response<Body>> {
        self.livekit
            .mint(spec)
            .map_err(|()| self.plain(500, "internal error"))
    }

    async fn fields(&self, r: &mut Request<Body>) -> Result<crate::chat::Fields, Response<Body>> {
        body_fields(r)
            .await
            .map_err(|()| self.problem(400, "invalid JSON"))
    }

    async fn run(
        &self,
        kind: Kind,
        meeting: &str,
        request: Option<&str>,
        mut r: Request<Body>,
    ) -> Response<Body> {
        match self.dispatch(kind, meeting, request, &mut r).await {
            Ok(reply) | Err(reply) => reply,
        }
    }

    async fn dispatch(
        &self,
        kind: Kind,
        meeting: &str,
        request: Option<&str>,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let (exec, actor, livekit) = (self.exec, self.actor, self.livekit);
        let operation = || crate::jmap::random().ok_or_else(|| self.problem(500, "request failed"));
        let meeting_id = || {
            meeting
                .parse::<i64>()
                .map_err(|_| self.problem(400, "invalid meeting id"))
        };
        let compact = |raw: &str| {
            crate::jmap::reply::go_compact(raw).ok_or_else(|| self.problem(500, "request failed"))
        };
        match kind {
            Kind::Join => {
                let meeting = meeting_id()?;
                let (spec, envelope) =
                    self.commit(setjoin_meet::join(exec, actor, meeting, operation()?).await)?;
                let spec = self.grant(&spec)?;
                let parsed: Envelope = serde_json::from_str(&envelope)
                    .map_err(|_| self.plain(500, "internal error"))?;
                // A breakout redirect needs the generous child-room timeouts.
                let created = if spec.room != parsed.room_name {
                    livekit
                        .create_room(&spec.room, BREAKOUT_TIMEOUT, BREAKOUT_TIMEOUT)
                        .await
                } else {
                    livekit.create_room(&spec.room, 300, 20).await
                };
                if created.is_err() {
                    return Err(self.plain(502, "could not prepare the meeting room"));
                }
                let (token, expires) = self.mint(&spec)?;
                Ok(json_reply(
                    200,
                    format!(
                        "{{\"captionsConfigured\":{},\"expiresAt\":\"{expires}\",\"meeting\":{},\"recordingActive\":{},\"token\":\"{token}\",\"wsPath\":\"/rtc\"}}\n",
                        livekit.captions_configured(),
                        compact(&envelope)?,
                        spec.recording_active
                    ),
                    self.c,
                    self.id.clone(),
                ))
            }
            Kind::Kick => {
                let meeting = meeting_id()?;
                let fields = self.fields(r).await?;
                let identity = text_field(&fields, "IDENTITY")
                    .map_err(|()| self.problem(400, "invalid JSON"))?;
                let room = self.commit(
                    setjoin_meet::kick(exec, actor, meeting, &identity, operation()?).await,
                )?;
                if livekit.remove_participant(&room, &identity).await.is_err() {
                    return Err(self.plain(502, "kicked, but eviction failed; will be retried"));
                }
                Ok(empty_reply(204, self.c, self.id.clone()))
            }
            Kind::End => {
                let meeting = meeting_id()?;
                let room =
                    self.commit(setjoin_meet::end(exec, actor, meeting, operation()?).await)?;
                // Law 1: stop every in-flight recording before the room is deleted.
                // Errors are logged, never fatal: the worker's stop leg retries.
                if livekit.egress() {
                    match setjoin_meet::stopping_egress_ids(exec, actor, meeting).await {
                        Ok(ids) => {
                            for egress in ids {
                                if livekit.stop_egress(&egress).await.is_err() {
                                    eprintln!("meet: StopEgress at end failed: {egress}");
                                }
                            }
                        }
                        Err(_) => eprintln!("meet: stopping-recordings query at end failed"),
                    }
                }
                match setjoin_meet::breakout_rooms(exec, actor, meeting).await {
                    Ok(children) => {
                        for child in children {
                            if livekit.delete_room(&child).await.is_err() {
                                eprintln!("meet: breakout child DeleteRoom at end failed: {child}");
                            }
                        }
                    }
                    Err(_) => eprintln!("meet: breakout child-room query at end failed"),
                }
                if livekit.delete_room(&room).await.is_err() {
                    return Err(self.plain(502, "ended, but eviction failed; will be retried"));
                }
                Ok(empty_reply(204, self.c, self.id.clone()))
            }
            Kind::Knock => {
                let meeting = meeting_id()?;
                let not_found = || {
                    meet_problem(
                        404,
                        "meeting not found",
                        "not-found",
                        "BZ185",
                        self.path,
                        self.c,
                        self.id.clone(),
                        self.language,
                    )
                };
                let (slug, name) = match setjoin_meet::knock_lookup(exec, actor, meeting).await {
                    Ok(Some(found)) => found,
                    Ok(None) => return Err(not_found()),
                    Err(_) => return Err(self.plain(500, "internal error")),
                };
                let out = self.commit(
                    setjoin_meet::knock_create(exec, actor, &slug, &name, operation()?).await,
                )?;
                Ok(self.json(201, &out))
            }
            Kind::Decide => {
                // The meeting id is not parsed: both reducers derive it from the request.
                let request = request
                    .and_then(|v| v.parse::<i64>().ok())
                    .ok_or_else(|| self.problem(400, "invalid request id"))?;
                let fields = self.fields(r).await?;
                let action = text_field(&fields, "ACTION")
                    .map_err(|()| self.problem(400, "invalid JSON"))?;
                match action.as_str() {
                    "admit" => {
                        let out = self.commit(
                            setjoin_meet::admit(exec, actor, request, operation()?).await,
                        )?;
                        Ok(self.json(200, &out))
                    }
                    "deny" => {
                        self.commit(setjoin_meet::deny(exec, actor, request, operation()?).await)?;
                        Ok(empty_reply(204, self.c, self.id.clone()))
                    }
                    _ => Err(self.problem(400, "action must be \"admit\" or \"deny\"")),
                }
            }
            Kind::BreakoutOpen => {
                // The toggle gates open only, before the id parses.
                match setjoin_meet::flag(exec, "feature.meet_breakouts", false).await {
                    Ok(true) => {}
                    Ok(false) => return Err(self.plain(404, "not found")),
                    Err(_) => return Err(self.plain(500, "internal error")),
                }
                let meeting = meeting_id()?;
                let fields = self.fields(r).await?;
                let invalid = |()| self.problem(400, "invalid JSON");
                let count = number_field(&fields, "COUNT").map_err(invalid)?;
                let titles = strings_field(&fields, "TITLES").map_err(invalid)?;
                let auto = bool_field(&fields, "AUTOASSIGN").map_err(invalid)?;
                let out = self.commit(
                    setjoin_meet::breakout_open(
                        exec,
                        actor,
                        meeting,
                        count,
                        &titles,
                        auto,
                        operation()?,
                    )
                    .await,
                )?;
                // Pre-create every child room; a failure is logged and healed at join.
                #[derive(serde::Deserialize)]
                struct Row {
                    #[serde(rename = "roomName", default)]
                    room_name: String,
                }
                for row in serde_json::from_str::<Vec<Row>>(&out).unwrap_or_default() {
                    if livekit
                        .create_room(&row.room_name, BREAKOUT_TIMEOUT, BREAKOUT_TIMEOUT)
                        .await
                        .is_err()
                    {
                        eprintln!("meet: breakout CreateRoom failed: {}", row.room_name);
                    }
                }
                let body = format!("{{\"breakouts\":{}}}\n", compact(&out)?);
                Ok(json_reply(201, body, self.c, self.id.clone()))
            }
            Kind::BreakoutAssign => {
                let meeting = meeting_id()?;
                let fields = self.fields(r).await?;
                let invalid = |()| self.problem(400, "invalid JSON");
                let target = number_field(&fields, "TARGETUSERID").map_err(invalid)?;
                let breakout = optional_field::<i64>(&fields, "BREAKOUTID").map_err(invalid)?;
                let room = self.commit(
                    setjoin_meet::breakout_assign(
                        exec,
                        actor,
                        meeting,
                        target,
                        breakout,
                        operation()?,
                    )
                    .await,
                )?;
                if livekit
                    .remove_participant(&room, &format!("u:{target}"))
                    .await
                    .is_err()
                {
                    return Err(self.plain(
                        502,
                        "assigned, but the move could not be confirmed; will be retried",
                    ));
                }
                Ok(empty_reply(204, self.c, self.id.clone()))
            }
            Kind::BreakoutClose => {
                let meeting = meeting_id()?;
                let out = self.commit(
                    setjoin_meet::breakout_close(exec, actor, meeting, operation()?).await,
                )?;
                let rooms: Vec<String> =
                    serde_json::from_str(&out).map_err(|_| self.plain(500, "internal error"))?;
                // Every room is attempted even if an earlier one fails.
                let mut failed = false;
                for room in rooms {
                    if livekit.delete_room(&room).await.is_err() {
                        eprintln!("meet: breakout DeleteRoom failed: {room}");
                        failed = true;
                    }
                }
                if failed {
                    return Err(self.plain(
                        502,
                        "closed, but some rooms could not be evicted; will be retried",
                    ));
                }
                Ok(empty_reply(204, self.c, self.id.clone()))
            }
            Kind::BreakoutJoin => {
                let meeting = meeting_id()?;
                let fields = self.fields(r).await?;
                let breakout = optional_field::<i64>(&fields, "BREAKOUTID")
                    .map_err(|()| self.problem(400, "invalid JSON"))?;
                let spec = self.commit(
                    setjoin_meet::breakout_join(exec, actor, meeting, breakout, operation()?).await,
                )?;
                let spec = self.grant(&spec)?;
                if livekit
                    .create_room(&spec.room, BREAKOUT_TIMEOUT, BREAKOUT_TIMEOUT)
                    .await
                    .is_err()
                {
                    return Err(self.plain(502, "could not prepare the breakout room"));
                }
                let (token, expires) = self.mint(&spec)?;
                Ok(json_reply(
                    200,
                    format!(
                        "{{\"expiresAt\":\"{expires}\",\"recordingActive\":{},\"token\":\"{token}\",\"wsPath\":\"/rtc\"}}\n",
                        spec.recording_active
                    ),
                    self.c,
                    self.id.clone(),
                ))
            }
            _ => unreachable!("not a room-controller route"),
        }
    }
}

/// POST /meet/webhook: LiveKit's signed fact channel. Facts never authorize;
/// anything that cannot be a fact for one of our rooms answers 200 so LiveKit
/// does not retry it forever.
async fn webhook(
    exec: &ScopedExecutor,
    livekit: &LiveKit,
    mut r: Request<Body>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let ok = |c: &RequestContext, id: String| empty_reply(200, c, id);
    let authorization = r
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = match read_body(&mut r).await {
        Ok(body) => body,
        Err(ReadError::TooLarge) => return plain(413, "webhook body too large", c, id),
        Err(ReadError::Transport) => return plain(401, "invalid webhook signature", c, id),
    };
    debug_assert!(body.len() <= WEBHOOK_MAX_BODY);
    let invalid = || plain(401, "invalid webhook signature", c, id.clone());
    if !livekit.verify_webhook(authorization.as_deref(), &body) {
        return invalid();
    }
    let Ok(event) = parse_webhook(&body) else {
        return invalid();
    };
    if matches!(
        event.event.as_str(),
        "egress_started" | "egress_updated" | "egress_ended"
    ) {
        let Some(info) = event.egress else {
            return ok(c, id);
        };
        let Some(room) = parse_uuid(&info.room_name) else {
            return ok(c, id);
        };
        return match setjoin_meet::recording_event(
            exec,
            &room,
            &info.egress_id,
            &event.event,
            &info.info_json,
        )
        .await
        {
            Ok(()) => ok(c, id),
            Err(_) => plain(500, "internal error", c, id),
        };
    }
    if !matches!(
        event.event.as_str(),
        "participant_joined" | "participant_left" | "room_started" | "room_finished"
    ) {
        return ok(c, id);
    }
    let Some(room) = parse_uuid(&event.room) else {
        return ok(c, id);
    };
    match setjoin_meet::participant_event(exec, &room, &event.event, &event.participant).await {
        Ok(()) => ok(c, id),
        Err(_) => plain(500, "internal error", c, id),
    }
}

/// The guest lobby: create and poll a join request. No caller identity; the
/// SECURITY DEFINER reducers self-scope by slug and secret.
#[allow(clippy::too_many_arguments)]
async fn public(
    exec: &ScopedExecutor,
    livekit: &LiveKit,
    mints: &MintFence,
    kind: Kind,
    mut r: Request<Body>,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match setjoin_meet::enabled(exec).await {
        Ok(true) => {}
        Ok(false) => return plain(404, "not found", c, id),
        Err(_) => return c.upstream.forward(r, &c.identity).await,
    }
    let decoded = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path())).into_owned();
    let path = decoded.strip_prefix("/api").unwrap_or(&decoded).to_owned();
    let segments: Vec<String> = r
        .uri()
        .path()
        .split('/')
        .map(|s| String::from_utf8_lossy(&crate::inventory::unescape(s)).into_owned())
        .collect();
    let slug = segments[4].clone();
    if kind == Kind::PublicCreate {
        match setjoin_meet::flag(exec, "meet.guest_access", true).await {
            Ok(true) => {}
            Ok(false) => return plain(404, "not found", c, id),
            Err(_) => return c.upstream.forward(r, &c.identity).await,
        }
        // Go's MaxBytesReader(4 KiB) plus a one-value Decoder: the first JSON
        // value must complete inside the cap; anything after it is ignored.
        let mut raw = Vec::new();
        {
            use http_body_util::BodyExt;
            while raw.len() < 4096 {
                match r.body_mut().frame().await {
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            raw.extend_from_slice(data);
                        }
                    }
                    Some(Err(_)) => return plain(400, "invalid JSON", c, id),
                    None => break,
                }
            }
        }
        raw.truncate(4096);
        let Ok(name) =
            first_value_fields(&raw).and_then(|fields| text_field(&fields, "DISPLAYNAME"))
        else {
            return plain(400, "invalid JSON", c, id);
        };
        return match setjoin_meet::public_create(exec, &slug, &name).await {
            Ok(out) => match crate::jmap::reply::go_compact(&out) {
                Some(body) => json_reply(201, body + "\n", c, id),
                None => problem(500, "request failed", &path, c, id, language),
            },
            Err(e) => failure(&e, &path, c, id, language),
        };
    }
    let Ok(request) = segments[6].parse::<i64>() else {
        return problem(400, "invalid request id", &path, c, id, language);
    };
    let secret = r
        .headers()
        .get("x-meet-lobby-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let out = match setjoin_meet::public_poll(exec, &slug, request, &secret).await {
        Ok(out) => out,
        Err(e) => return failure(&e, &path, c, id, language),
    };
    match strip_and_mint(livekit, mints, request, &out) {
        Ok(body) => json_reply(200, body, c, id),
        Err(()) => plain(500, "internal error", c, id),
    }
}

/// `json.NewDecoder(r).Decode(&struct)`: only the first value, no trailing check.
fn first_value_fields(bytes: &[u8]) -> Result<crate::chat::Fields, ()> {
    use serde::Deserialize;
    let text = crate::chat::go_json_text(bytes);
    let mut d = serde_json::Deserializer::from_str(&text);
    crate::chat::Fields::deserialize(&mut d).map_err(|_| ())
}

/// Go's `stripAndMintPoll`: pass every reducer key through, except the grant,
/// which is consumed to mint a token inside the admitted window.
fn strip_and_mint(
    livekit: &LiveKit,
    mints: &MintFence,
    request: i64,
    out: &str,
) -> Result<String, ()> {
    use serde_json::value::RawValue;
    let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str::<Option<_>>(out)
        .map_err(|_| ())?
        .unwrap_or_default();
    let mut extra: BTreeMap<&str, String> = BTreeMap::new();
    if let Some(grant) = fields.remove("grant") {
        if !mints.allow(request) {
            return Ok("{\"state\":\"expired\"}\n".into());
        }
        let spec: GrantSpec = serde_json::from_str::<Option<GrantSpec>>(grant.get())
            .map_err(|_| ())?
            .unwrap_or_default();
        let (token, expires) = livekit.mint(&spec)?;
        extra.insert("token", serde_json::Value::String(token).to_string());
        extra.insert("wsPath", "\"/rtc\"".into());
        extra.insert("expiresAt", serde_json::Value::String(expires).to_string());
    }
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in fields {
        merged.insert(k, crate::jmap::reply::go_compact(v.get()).ok_or(())?);
    }
    for (k, v) in extra {
        merged.insert(k.into(), v);
    }
    let body = merged
        .iter()
        .map(|(k, v)| format!("{}:{v}", serde_json::Value::String(k.clone())))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!("{{{body}}}\n"))
}
