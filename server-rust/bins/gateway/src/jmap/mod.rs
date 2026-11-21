//! Native JMAP commands, HTTP peripherals and submission (#215/#216/#315/#316/#317).
//!
//! Claims qualified `POST /jmap` shapes and mounted undo/recall actions through
//! one shared security chain:
//! CSRF, ES256/JWKS verification, guest/session checks, security gates and
//! primary-mailbox scope. Retired `feature.rust_mark_read` and
//! `feature.rust_inbox_list` flags do not affect command dispatch. The
//! specialized mark-read and inbox-list adapters remain qualified native paths;
//! general Email/set and Email/query use their JMAP1 adapters.
//!
//! Ownership comes from the verified identity; `accountId` is only compared
//! with it (R2). Each request has one writer: a deferred shape forwards whole
//! before any write. Each required admission read gets one bounded attempt.

pub(super) mod account;
pub mod batch;
pub mod blob;
pub mod changes;
pub mod device_cache;
mod download;
pub mod envelope;
pub mod family;
pub mod gates;
pub mod get;
pub mod http;
pub mod hub;
mod identity;
mod imip;
pub mod limit;
pub mod list;
pub mod mailbox_set;
pub mod other;
pub mod presence;
pub mod push;
pub mod query;
mod recovery;
pub mod reply;
pub mod seen;
pub mod set;
pub mod submission;
pub mod sse;
mod messages;
pub mod messages_zip;
mod submission_actions;
mod submission_input;
pub mod transfer;
mod upload;
pub mod ws_request;
pub use setjoin_authz::{csrf, jwks, token};

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use setjoin_contracts::command::{CommandEnvelope, OperationResult, SetMessageSeen};
use setjoin_contracts::ids::{ActorId, Digest, Generation, MailboxId, MessageId, OperationId};
use setjoin_jmap::{
    email_batch, email_changes, email_get, email_set, nudge_dismiss, query_email, query_email_list,
    read_paged, set_message_seen, set_message_seen_empty, ChangesError, EmailBatch, EmailGet,
    EmailSet, EmptySeen, GetOutcome, Paged, SeenEffect, SetOutcome, SetPhase,
};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, Type};
use sha2::{Digest as _, Sha256};

use crate::routes::{BoxFuture, Intercept, RequestContext};
use crate::Body;

use self::reply::Outcome;
use self::token::KeySource;

/// Focus bodies >64 KiB forward untouched; `POST /jmap` allows up to 10 MB (`maxSizeRequest`).
pub(super) const FOCUS_BODY_CAP: usize = 64 * 1024;
const JMAP_BODY_CAP: usize = 10_000_000;
const COMMAND_DEADLINE: Duration = Duration::from_secs(10);
/// Each pre-command database read (security gates, caller) gets at most this
/// long; past it the request is forwarded to Go untouched (review item 1).
/// The executor's own bounds (`setjoin_pg::Timeouts`) apply inside it.
/// Default bound; the effective one is `setjoin_authz::precheck_timeout()`.
pub const PRECHECK_TIMEOUT: Duration = setjoin_authz::PRECHECK_TIMEOUT;

/// The authority generation of every envelope this route builds. The
/// lifecycle compares the envelope's [`setjoin_contracts::authority::AuthorityKey`]
/// with the executor's current one, and a generation is how a later
/// re-authorization would make an older envelope stale. Here both keys are
/// built from the same authorization read in the same request, and Go has
/// no authority generation to mirror (revocation is the session denylist,
/// checked by that read before the command runs), so the generation is a
/// constant: it can only detect a mismatch between two values this function
/// constructed together, never a newer authorization.
const REQUEST_AUTHORITY_GENERATION: Generation = Generation(1);

pub struct JmapServices {
    pub worker: ScopedExecutor,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
    pub continuity_boot: Option<String>,
    /// Continuity/get|present signer, loaded together with `continuity_boot` (#377).
    pub continuity_signer: Option<Arc<family::ContinuitySigner>>,
    pub attachment_signer: Option<Arc<transfer::Signer>>,
    pub grace: i32,
    pub quota: i64,
    pub hostname: String,
    pub max_upload: i64,
}
impl JmapServices {
    pub fn new(worker: ScopedExecutor, hostname: String, max_upload: i64) -> Self {
        Self {
            worker,
            hostname,
            max_upload,
            store: None,
            continuity_boot: None,
            continuity_signer: None,
            attachment_signer: None,
            grace: 1440,
            quota: 0,
        }
    }
    pub fn from_env(worker: ScopedExecutor) -> Self {
        let mut services = Self::new(
            worker,
            std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into()),
            std::env::var("MAX_UPLOAD_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(52428800),
        );
        services.attachment_signer = transfer::Signer::from_env().map(Arc::new);
        match recovery::continuity_from_env() {
            Some((boot, signer)) => {
                services.continuity_boot = Some(boot);
                services.continuity_signer = Some(Arc::new(signer));
            }
            None => {
                eprintln!(
                    "setjoin-gateway: continuity signing key unavailable; Continuity/* stays with Go"
                );
                crate::metrics::CONTINUITY_SIGNER_MISSING
                    .store(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        services.store = crate::recovery_worker::S3Store::from_env()
            .ok()
            .map(Arc::new);
        services.grace = std::env::var("BLOB_RECLAIM_GRACE_MINUTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(1440);
        services.quota = std::env::var("BLOB_USER_QUOTA_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        services
    }
}

pub struct JmapCommands<K: KeySource = jwks::Jwks> {
    pub services: Option<Arc<JmapServices>>,
    pub exec: ScopedExecutor,
    /// Cross-mailbox submission fan-out uses DB_WORKER_DSN (fallback DB_DSN).
    pub worker: Option<ScopedExecutor>,
    pub keys: K,
    /// Go's `JWT_ISSUER` (default `mailserver`).
    pub issuer: String,
    /// Optional process-local worker mirror; absence retains per-request DB admission.
    pub denylist: Option<Arc<crate::workers::SessionDenylist>>,
}

/// The route-table entry; cheap to clone.
pub struct JmapRoute<K: KeySource + 'static = jwks::Jwks>(pub Arc<JmapCommands<K>>);

impl<K: KeySource + 'static> Intercept for JmapRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, req: &Request<Body>) -> bool {
        (req.method() == Method::POST
            && (req.uri().path() == "/jmap"
                || submission_actions::target(req.uri().path()).is_some()))
            || messages::target(req.method(), req.uri().path()).is_some()
            || (self.0.services.is_some() && http::matches(req.method(), req.uri().path()))
    }

    fn handle(&self, req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        let route = self.0.clone();
        Box::pin(async move { route.serve(req, ctx).await })
    }
}

const NOT_CLAIMED: &str = "not a supported JMAP Email request";

/// Deferred to Go before any batch write occurred.
pub struct DeferToGo(pub &'static str);

pub(super) enum BatchOutcome {
    Response(Vec<ws_request::Call>),
    Problem {
        status: u16,
        kind: &'static str,
        detail: String,
    },
}

/// Strictly-typed `POST /jmap` request envelope matching Go's `encoding/json` decode.
#[derive(Default)]
struct HttpBatchRequest {
    using: Vec<String>,
    calls: Vec<ws_request::Call>,
}

impl<'de> serde::Deserialize<'de> for HttpBatchRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = HttpBatchRequest;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JMAP HTTP batch request")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(HttpBatchRequest::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Self::Value, M::Error> {
                let mut req = HttpBatchRequest::default();
                while let Some(key) = m.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "using" => {
                            req.using = m
                                .next_value::<Option<Vec<Option<String>>>>()?
                                .unwrap_or_default()
                                .into_iter()
                                .map(Option::unwrap_or_default)
                                .collect();
                        }
                        "methodcalls" => {
                            req.calls = m
                                .next_value::<Option<Vec<ws_request::Call>>>()?
                                .unwrap_or_default();
                        }
                        "createdids" => {
                            m.next_value::<Option<BTreeMap<String, Option<String>>>>()?;
                        }
                        _ => {
                            m.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(req)
            }
        }
        d.deserialize_any(Fields)
    }
}

/// The command a single JMAP call is expressible as.
enum Claimed {
    Echo { raw_args: String },
    Identity(identity::Request),
    Blob(blob::Request),
    Other(other::OtherRequest),
    MailboxSet(mailbox_set::Request),
    Seen(seen::SeenRequest),
    List(list::ListRequest),
    /// #315: no feature toggle; the inventory entry is the switch.
    Changes(changes::ChangesRequest),
    Get(get::GetRequest),
    Query(query::QueryRequest),
    Set(set::SetRequest),
    Batch(batch::BatchRequest),
    Paged(batch::PagedRequest),
    Dismiss(batch::DismissRequest),
    Receipt(batch::ReceiptRequest),
    Submission(submission::SubmissionRequest),
    /// #369-#377: a registered per-family method; it resolves `accountId` itself, in Go's order.
    Family(family::Request),
}

fn claim_call(
    name: &str,
    raw_args: &str,
    client_id: &str,
    services: Option<&JmapServices>,
) -> Option<Claimed> {
    match name {
        "Core/echo" => Some(Claimed::Echo {
            raw_args: raw_args.to_owned(),
        }),
        "Identity/get" | "Identity/changes" => {
            identity::classify_call(name, raw_args, client_id).map(Claimed::Identity)
        }
        "Mailbox/set" | "Identity/set" => {
            mailbox_set::classify_call(name, raw_args, client_id).map(Claimed::MailboxSet)
        }
        "Email/set" => seen::classify_call(name, raw_args, client_id)
            .map(Claimed::Seen)
            .or_else(|| set::classify_call(raw_args, client_id).map(Claimed::Set)),
        "Email/query" => list::classify_call(name, raw_args, client_id)
            .map(Claimed::List)
            .or_else(|| query::classify_call(raw_args, client_id).map(Claimed::Query)),
        "Email/changes" => changes::classify_call(raw_args, client_id).map(Claimed::Changes),
        "Email/get" => get::classify_call(raw_args, client_id).map(Claimed::Get),
        "Email/recover" | "Email/purge" => {
            batch::classify_batch_call(name, raw_args, client_id).map(Claimed::Batch)
        }
        "Email/deletedQuery" | "Email/bundles" | "Email/nudges" => {
            batch::classify_paged_call(name, raw_args, client_id).map(Claimed::Paged)
        }
        "Email/nudgeDismiss" => {
            batch::classify_dismiss_call(name, raw_args, client_id).map(Claimed::Dismiss)
        }
        "Email/recoveryReceipt" => {
            batch::classify_receipt_call(name, raw_args, client_id).map(Claimed::Receipt)
        }
        "EmailSubmission/get"
        | "EmailSubmission/query"
        | "EmailSubmission/cancel"
        | "EmailSubmission/set" => {
            submission::classify_call(name, raw_args, client_id).map(Claimed::Submission)
        }
        "Blob/get" | "Blob/copy" | "Blob/lookup" => {
            blob::classify_call(name, raw_args, client_id).map(Claimed::Blob)
        }
        "Mailbox/get"
        | "Mailbox/query"
        | "Mailbox/changes"
        | "Mailbox/queryChanges"
        | "Thread/get"
        | "Thread/changes"
        | "SearchSnippet/get" => {
            other::classify_call(name, raw_args, client_id).map(Claimed::Other)
        }
        _ => family::classify_call(name, raw_args, client_id, services).map(Claimed::Family),
    }
}

fn has_top_ref(val: &serde_json::Value, key: &str) -> bool {
    val.as_object().is_some_and(|map| {
        map.keys()
            .any(|k| k.starts_with('#') && k[1..].eq_ignore_ascii_case(key))
    })
}

fn is_mutator_or_audited(claimed: &Claimed) -> bool {
    match claimed {
        Claimed::Seen(_)
        | Claimed::Set(_)
        | Claimed::Batch(_)
        | Claimed::Dismiss(_)
        | Claimed::MailboxSet(_)
        | Claimed::Get(_) => true,
        Claimed::Submission(req) => matches!(
            req.args,
            submission::Arguments::Set(Ok(_)) | submission::Arguments::Cancel(Ok(_))
        ),
        Claimed::Family(req) => !matches!(
            req.method.name.rsplit('/').next(),
            Some(
                "get"
                    | "query"
                    | "changes"
                    | "queryChanges"
                    | "list"
                    | "lookup"
                    | "freeBusy"
                    | "queryFreeSlots"
                    | "galSearch"
                    | "directoryTree"
                    | "directoryMembers"
                    | "directorySearch"
                    | "findDuplicates"
                    | "expand"
                    | "present"
                    | "delegateList"
                    | "resourceList"
            )
        ),
        _ => false,
    }
}

/// Either the buffered body, an oversized 10 MB rejection, or a stream to forward.
enum Buffered {
    Whole(Bytes),
    TooLarge,
    Forward(Body),
}

impl<K: KeySource> JmapCommands<K> {
    async fn serve(&self, mut req: Request<Body>, ctx: RequestContext) -> Response<Body> {
        if http::matches(req.method(), req.uri().path()) {
            if let Some(response) = self.try_http(&mut req, &ctx).await {
                return response;
            }
            return ctx.upstream.forward(req, &ctx.identity).await;
        }
        if submission_actions::target(req.uri().path()).is_some() {
            return self.serve_action(req, ctx).await;
        }
        if let Some((route, id)) = messages::target(req.method(), req.uri().path()) {
            return self.serve_message(route, id, req, ctx).await;
        }
        let (parts, body) = req.into_parts();
        // Auth-first: unauthenticated or revoked requests forward untouched
        // without buffering up to 10 MB or returning Rust HTTP 400 errors.
        let Some(authorized) = self.preauth_http(&parts.headers, ctx.identity.proto).await else {
            return ctx
                .upstream
                .forward(Request::from_parts(parts, body), &ctx.identity)
                .await;
        };
        let forward_body = match buffer_with_cap(body, JMAP_BODY_CAP, false).await {
            Buffered::Whole(bytes) => match self.execute_http(&parts, &bytes, &ctx, &authorized).await
            {
                Ok(resp) => return resp,
                Err(reason) => {
                    if log_served() && reason != NOT_CLAIMED {
                        eprintln!("setjoin-gateway: /jmap route deferred to Go: {reason}");
                    }
                    Full::new(bytes).map_err(|n| match n {}).boxed()
                }
            },
            Buffered::TooLarge => {
                let req_id = reply::request_id(
                    parts.headers.get("x-request-id"),
                    random().unwrap_or([0; 16]),
                );
                return reply::problem_response(
                    400,
                    "notJSON",
                    "invalid JSON in request body",
                    ctx.identity.proto,
                    req_id,
                );
            }
            Buffered::Forward(rest) => rest,
        };
        ctx.upstream
            .forward(Request::from_parts(parts, forward_body), &ctx.identity)
            .await
    }

    async fn preauth_http(
        &self,
        headers: &hyper::http::HeaderMap,
        proto: &str,
    ) -> Option<setjoin_authz::Authorized> {
        let authorized = setjoin_authz::authorize_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            headers,
            proto,
        )
        .await?;
        let identity = authorized.context();
        if let Some(denylist) = &self.denylist {
            let issued = chrono::DateTime::from_timestamp(authorized.issued_at(), 0)?;
            if denylist.is_revoked(
                identity.user_id(),
                authorized.token_id(),
                authorized.token_family(),
                issued,
            ) {
                return None;
            }
            if !denylist.loaded() {
                let cae = tokio::time::timeout(
                    PRECHECK_TIMEOUT,
                    self.exec.read(
                        "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'),false)",
                        &[],
                    ),
                )
                .await
                .ok()?
                .ok()?;
                if cae[0].get::<_, bool>(0) {
                    return None;
                }
            }
        }
        Some(authorized)
    }

    async fn execute_http(
        &self,
        parts: &hyper::http::request::Parts,
        bytes: &Bytes,
        ctx: &RequestContext,
        authorized: &setjoin_authz::Authorized,
    ) -> Result<Response<Body>, &'static str> {
        let cleaned = crate::guests_input::go_json_bytes(bytes);
        let req: HttpBatchRequest = match serde_json::from_slice(&cleaned) {
            Ok(req) => req,
            Err(_) => {
                let req_id = reply::request_id(
                    parts.headers.get("x-request-id"),
                    random().ok_or("rng unavailable")?,
                );
                return Ok(reply::problem_response(
                    400,
                    "notJSON",
                    "invalid JSON in request body",
                    ctx.identity.proto,
                    req_id,
                ));
            }
        };
        let identity = authorized.context();
        let (request_random, outcome) = self
            .execute_batch_verified(
                identity.user_id(),
                identity.mailbox_id(),
                identity.email(),
                &req.using,
                &req.calls,
                true,
            )
            .await
            .map_err(|DeferToGo(reason)| reason)?;
        let request_id = reply::request_id(
            parts.headers.get("x-request-id"),
            request_random.unwrap_or([0; 16]),
        );
        match outcome {
            BatchOutcome::Problem {
                status,
                kind,
                detail,
            } => Ok(reply::problem_response(
                status,
                kind,
                &detail,
                ctx.identity.proto,
                request_id,
            )),
            BatchOutcome::Response(responses) => {
                let body =
                    reply::http_batch_response(&authorized.session_state().encode(), &responses);
                Ok(reply::response(body, ctx.identity.proto, request_id))
            }
        }
    }

    /// Shared preflight + RNG reservation + batch execution engine for HTTP & WS.
    pub(super) async fn execute_batch_verified(
        &self,
        user_id: i64,
        primary_mailbox: i64,
        email: &str,
        using: &[String],
        calls: &[ws_request::Call],
        need_request_random: bool,
    ) -> Result<(Option<[u8; 16]>, BatchOutcome), DeferToGo> {
        if using.is_empty() {
            let req_rand = if need_request_random {
                Some(random().ok_or(DeferToGo("rng unavailable"))?)
            } else {
                None
            };
            return Ok((
                req_rand,
                BatchOutcome::Problem {
                    status: 400,
                    kind: "notRequest",
                    detail: "'using' array must not be empty".into(),
                },
            ));
        }
        if calls.len() > 32 {
            let req_rand = if need_request_random {
                Some(random().ok_or(DeferToGo("rng unavailable"))?)
            } else {
                None
            };
            return Ok((
                req_rand,
                BatchOutcome::Problem {
                    status: 400,
                    kind: "requestTooLarge",
                    detail: format!("maxCallsInRequest of 32 exceeded ({} calls)", calls.len()),
                },
            ));
        }
        self.preflight_batch(user_id, primary_mailbox, using, calls)
            .await
            .map_err(DeferToGo)?;
        let request_random = if need_request_random {
            Some(random().ok_or(DeferToGo("rng unavailable"))?)
        } else {
            None
        };
        let mut operations = Vec::with_capacity(calls.len());
        for _ in 0..calls.len() {
            operations.push(random().ok_or(DeferToGo("rng unavailable"))?);
        }
        let outcome = self
            .execute_batch(user_id, primary_mailbox, email, using, calls, &operations)
            .await?;
        Ok((request_random, outcome))
    }

    async fn preflight_batch(
        &self,
        user_id: i64,
        primary_mailbox: i64,
        using: &[String],
        calls: &[ws_request::Call],
    ) -> Result<(), &'static str> {
        let primary_auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(user_id).map_err(|_| "ids")?,
            MailboxId::new(primary_mailbox).map_err(|_| "ids")?,
            REQUEST_AUTHORITY_GENERATION,
        );
        let mut saw_mutator = false;
        for call in calls {
            // Go validates in order and exits on size/capability errors before later calls.
            if call.args.get().len() > 2_000_000
                || !using
                    .iter()
                    .any(|c| c == ws_request::capability(&call.name))
            {
                break;
            }
            if call.name.is_empty()
                || call.name.len() > 128
                || (call.name != "Core/echo" && !ws_request::registered(&call.name))
            {
                continue;
            }
            let val: serde_json::Value =
                serde_json::from_str(call.args.get()).map_err(|_| "invalid call args")?;
            if !val.is_object() && !val.is_null() {
                continue;
            }
            if call.name == "Core/echo" {
                continue;
            }
            let stripped = envelope::dummy_stripped_args(call.args.get());
            if call.name == "EmailSubmission/set" && stripped.is_some() {
                return Err("EmailSubmission/set # reference deferred to Go");
            }
            let check_args = stripped.as_deref().unwrap_or(call.args.get());
            let claimed = claim_call(&call.name, check_args, &call.id, self.services.as_deref())
                .ok_or(NOT_CLAIMED)?;
            match &claimed {
                Claimed::Identity(_) | Claimed::Blob(_) => {
                    if self.services.is_none() {
                        return Err("JMAP services unavailable");
                    }
                }
                Claimed::Set(_) => {
                    if has_top_ref(&val, "create")
                        || has_top_ref(&val, "update")
                        || has_top_ref(&val, "destroy")
                    {
                        return Err("Email/set # reference deferred to Go");
                    }
                }
                Claimed::Batch(_) => {
                    if has_top_ref(&val, "ids") {
                        return Err("batch #ids deferred to Go");
                    }
                }
                Claimed::Changes(_) => {
                    if has_top_ref(&val, "maxChanges") {
                        return Err("Email/changes #maxChanges deferred to Go");
                    }
                }
                Claimed::Other(_) => {
                    if call.name == "Mailbox/query" && has_top_ref(&val, "position") {
                        return Err("Mailbox/query #position deferred to Go");
                    }
                }
                Claimed::Paged(_) => {
                    if has_top_ref(&val, "position") {
                        return Err("paged #position deferred to Go");
                    }
                }
                Claimed::Receipt(_) => {
                    if gates::toggle_state(&self.exec, batch::RECEIPTS_FLAG).await != Some(false) {
                        return Err("client recovery receipts are Go's while enabled");
                    }
                }
                Claimed::Submission(req) => {
                    if req.early_error().is_none()
                        && matches!(req.args, submission::Arguments::Set(Ok(_)))
                    {
                        if let Ok(resolved) = account::resolve_account(
                            &self.exec,
                            user_id,
                            &req.raw_account_id,
                            family::Gate::Submit,
                        )
                        .await
                        {
                            let pre = tokio::time::timeout(
                                PRECHECK_TIMEOUT,
                                req.needs_preprocessing(&self.exec, &resolved.auth),
                            )
                            .await;
                            if !matches!(pre, Ok(Ok(false))) {
                                return Err("unported MIME preprocessing (#328)");
                            }
                        }
                    }
                }
                Claimed::Get(get_req) => {
                    if let get::GetArgs::Valid {
                        raw_account_id,
                        ids,
                        bad,
                        properties,
                        too_many,
                    } = &get_req.args
                    {
                        if !*too_many {
                            let has_acct_ref = has_top_ref(&val, "accountId");
                            let has_ids_ref = has_top_ref(&val, "ids");
                            let has_props_ref = has_top_ref(&val, "properties");
                            if has_acct_ref && saw_mutator {
                                return Err("Email/get #accountId after mutator deferred to Go");
                            }
                            let target = if has_acct_ref {
                                Some((primary_mailbox, primary_auth.clone()))
                            } else {
                                match account::resolve_account(
                                    &self.exec,
                                    user_id,
                                    raw_account_id,
                                    family::Gate::Read,
                                )
                                .await
                                {
                                    Ok(resolved) => Some((resolved.mailbox, resolved.auth)),
                                    Err(_) => None,
                                }
                            };
                            if let Some((target_mailbox, target_auth)) = target {
                                if has_ids_ref || has_acct_ref || has_props_ref {
                                    let encrypted = tokio::time::timeout(
                                        PRECHECK_TIMEOUT,
                                        self.exec.read_scoped(
                                            &target_auth,
                                            "SELECT EXISTS(SELECT 1 FROM messages WHERE mailbox_id=$1 AND NOT is_deleted AND crypto_type='smime-encrypted')",
                                            &[(&target_mailbox, Type::INT8)],
                                        ),
                                    )
                                    .await;
                                    if !matches!(encrypted, Ok(Ok(ref rows)) if rows.first().is_some_and(|r| !r.get::<_, bool>(0)))
                                    {
                                        return Err("encrypted mail or precheck failed");
                                    }
                                } else {
                                    let ids_param: Option<Vec<i64>> =
                                        (!ids.is_empty() || !bad.is_empty())
                                            .then(|| ids.clone());
                                    let encrypted = tokio::time::timeout(
                                        PRECHECK_TIMEOUT,
                                        self.exec.read_scoped(
                                            &target_auth,
                                            "SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(jmap_email_get($1,$2::bigint[],$3::text[])->'list') e WHERE e->>'cryptoType'='smime-encrypted')",
                                            &[
                                                (&target_mailbox, Type::INT8),
                                                (&ids_param, Type::INT8_ARRAY),
                                                (properties, Type::TEXT_ARRAY),
                                            ],
                                        ),
                                    )
                                    .await;
                                    if !matches!(encrypted, Ok(Ok(ref rows)) if rows.first().is_some_and(|r| !r.get::<_, bool>(0)))
                                    {
                                        return Err("encrypted mail: Go decrypts on read");
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            if is_mutator_or_audited(&claimed) {
                saw_mutator = true;
            }
        }
        Ok(())
    }

    async fn execute_batch(
        &self,
        user_id: i64,
        primary_mailbox: i64,
        email: &str,
        using: &[String],
        calls: &[ws_request::Call],
        operations: &[[u8; 16]],
    ) -> Result<BatchOutcome, DeferToGo> {
        let mut responses: Vec<ws_request::Call> = Vec::with_capacity(calls.len());
        let mut mutated = false;
        for (idx, call) in calls.iter().enumerate() {
            if call.args.get().len() > 2_000_000 {
                return Ok(BatchOutcome::Problem {
                    status: 400,
                    kind: "requestTooLarge",
                    detail: format!("method call '{}' exceeds 2 MB limit", call.name),
                });
            }
            let cap = ws_request::capability(&call.name);
            if !using.iter().any(|s| s == cap) {
                return Ok(BatchOutcome::Problem {
                    status: 400,
                    kind: "unknownCapability",
                    detail: format!("Capability not declared in 'using': {cap}"),
                });
            }
            let (name, args) = match ws_request::references(call.args.get(), &responses) {
                Err((kind, detail)) => ("error".to_owned(), ws_request::method_error(kind, &detail)),
                Ok(resolved_args) => {
                    if call.name.is_empty() || call.name.len() > 128 {
                        (
                            "error".into(),
                            ws_request::method_error("unknownMethod", "invalid method name"),
                        )
                    } else if call.name != "Core/echo" && !ws_request::registered(&call.name) {
                        ("error".into(), ws_request::method_error("unknownMethod", ""))
                    } else if !matches!(
                        serde_json::from_str::<serde_json::Value>(&resolved_args),
                        Ok(serde_json::Value::Object(_) | serde_json::Value::Null)
                    ) {
                        (
                            "error".into(),
                            ws_request::method_error(
                                "invalidArguments",
                                "args must be a JSON object",
                            ),
                        )
                    } else if call.name == "Core/echo" {
                        (
                            "Core/echo".into(),
                            reply::go_compact(&resolved_args).unwrap_or_else(|| "null".into()),
                        )
                    } else {
                        match self
                            .execute_call(
                                user_id,
                                primary_mailbox,
                                email,
                                &call.name,
                                &resolved_args,
                                &call.id,
                                operations[idx],
                                &mut mutated,
                            )
                            .await
                        {
                            Ok(pair) => pair,
                            Err(reason) => {
                                if !mutated {
                                    return Err(DeferToGo(reason));
                                }
                                ("error".into(), ws_request::server_fail())
                            }
                        }
                    }
                }
            };
            let args = reply::go_compact(&args).unwrap_or(args);
            responses.push(ws_request::Call {
                name,
                args: RawValue::from_string(args).expect("response JSON"),
                id: call.id.clone(),
            });
        }
        Ok(BatchOutcome::Response(responses))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_call(
        &self,
        user_id: i64,
        primary_mailbox: i64,
        email: &str,
        method_name: &str,
        raw_args: &str,
        client_id: &str,
        operation: [u8; 16],
        mutated: &mut bool,
    ) -> Result<(String, String), &'static str> {
        let claimed =
            claim_call(method_name, raw_args, client_id, self.services.as_deref())
                .ok_or(NOT_CLAIMED)?;
        let primary_auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(user_id).map_err(|_| "ids")?,
            MailboxId::new(primary_mailbox).map_err(|_| "ids")?,
            REQUEST_AUTHORITY_GENERATION,
        );
        let digest_bytes: [u8; 32] = Sha256::digest(raw_args.as_bytes()).into();
        let digest = Digest(digest_bytes);

        let seen = match claimed {
            Claimed::Identity(request) => {
                let services = self.services.as_ref().ok_or("JMAP services")?;
                let (m, json) =
                    identity::response_call(&self.exec, &services.worker, &primary_auth, &request)
                        .await;
                return Ok((m.into(), json));
            }
            Claimed::Blob(request) => {
                let services = self
                    .services
                    .as_ref()
                    .ok_or("JMAP worker credential unavailable")?;
                let (m, json) =
                    blob::response_call(&services.worker, &primary_auth, &request).await;
                return Ok((m.into(), json));
            }
            Claimed::Echo { raw_args } => {
                let compact = reply::go_compact(&raw_args).ok_or("echo JSON")?;
                return Ok(("Core/echo".into(), compact));
            }
            Claimed::Family(request) => {
                if !matches!(
                    request.method.name.rsplit('/').next(),
                    Some(
                        "get"
                            | "query"
                            | "changes"
                            | "queryChanges"
                            | "list"
                            | "lookup"
                            | "freeBusy"
                            | "queryFreeSlots"
                            | "galSearch"
                            | "directoryTree"
                            | "directoryMembers"
                            | "directorySearch"
                            | "findDuplicates"
                            | "expand"
                            | "present"
                            | "delegateList"
                            | "resourceList"
                    )
                ) {
                    *mutated = true;
                }
                let cx = family::Cx::new(
                    &self.exec,
                    self.services.as_deref(),
                    &primary_auth,
                    user_id,
                    primary_mailbox,
                    request.method,
                    &request.args,
                )
                .with_email(email);
                let (m, json) = family::serve_call(&cx).await;
                return Ok((m.into(), json));
            }
            Claimed::Receipt(_) => {
                // Check toggle BEFORE resolve_account, matching recovery_receipt.go:97.
                let enabled = gates::toggle_state(&self.exec, batch::RECEIPTS_FLAG)
                    .await
                    .ok_or("toggle unreadable")?;
                if enabled {
                    return Err("client recovery receipts are Go's while enabled");
                }
                return Ok((
                    "error".into(),
                    reply::jmap_error_json("forbidden", 500, "client recovery receipts are disabled"),
                ));
            }
            Claimed::MailboxSet(request) => {
                let (create, update, destroy, bad) = match request.args {
                    mailbox_set::MailboxSetArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    mailbox_set::MailboxSetArgs::Valid {
                        create,
                        update,
                        destroy,
                        bad,
                    } => (create, update, destroy, bad),
                };
                // Identity/set rejects ANY delegated account (Gate::Personal); Mailbox/set uses Gate::Mutate.
                let gate = if request.method == "Identity/set" {
                    family::Gate::Personal
                } else {
                    family::Gate::Mutate
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &request.raw_account_id,
                    gate,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                *mutated = true;
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: (),
                };
                let outcome = if request.method == "Identity/set" {
                    setjoin_jmap::identity::set(
                        &self.exec,
                        &resolved.auth,
                        &envelope,
                        &create,
                        &update,
                        &destroy,
                    )
                    .await
                } else {
                    setjoin_jmap::mailbox_set::set(
                        &self.exec,
                        &resolved.auth,
                        &envelope,
                        &create,
                        &update,
                        &destroy,
                    )
                    .await
                };
                return match outcome {
                    SetOutcome::Done(raw) => {
                        let result = set::add_not_destroyed(
                            &set::merged(&raw).ok_or("mailbox set object")?,
                            &bad,
                        )
                        .ok_or("mailbox destroy errors")?;
                        Ok((request.method.into(), result))
                    }
                    SetOutcome::Failed(f) => Ok((
                        "error".into(),
                        reply::failure_json(f).ok_or("mailbox set failed")?,
                    )),
                    SetOutcome::Forward => Ok((
                        "error".into(),
                        reply::jmap_error_json("serverFail", 500, "database error"),
                    )),
                    SetOutcome::Unknown { operation } => Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    )),
                };
            }
            Claimed::Other(request) => {
                let (read, bad, too_many) = match request.args {
                    other::OtherArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    other::OtherArgs::Valid {
                        read,
                        bad,
                        too_many,
                    } => (read, bad, too_many),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &request.raw_account_id,
                    family::Gate::Read,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                if too_many {
                    return Ok((
                        "error".into(),
                        reply::jmap_error_json("requestTooLarge", 400, "too many ids requested"),
                    ));
                }
                if read
                    .since_state()
                    .is_some_and(|s| !changes::since_state_is_well_formed(s))
                {
                    return Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "cannotCalculateChanges",
                            400,
                            "client must resync (malformed sinceState)",
                        ),
                    ));
                }
                let raw = setjoin_jmap::mailbox::read(&self.exec, &resolved.auth, &read).await;
                return match raw {
                    Ok(raw) => Ok((
                        request.method.into(),
                        get::add_not_found(&raw, &bad).ok_or("mailbox get result")?,
                    )),
                    Err(e) if e.sqlstate.as_deref() == Some("BZ040") => Ok((
                        "error".into(),
                        reply::jmap_error_json("invalidArguments", 400, &e.message),
                    )),
                    Err(e) => {
                        let f = match setjoin_jmap::classify_failure(&e) {
                            setjoin_jmap::Failure::Forward => setjoin_jmap::Failure::ServerFail,
                            f => f,
                        };
                        Ok(("error".into(), reply::failure_json(f).ok_or("mailbox read")?))
                    }
                };
            }
            Claimed::Submission(request) => {
                if let Some(err) = request.early_error() {
                    return Ok((
                        "error".into(),
                        reply::jmap_error_json(err.kind, err.status, &err.detail),
                    ));
                }
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &request.raw_account_id,
                    family::Gate::Submit,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                if matches!(request.args, submission::Arguments::Set(Ok(_))) {
                    let pre = tokio::time::timeout(
                        PRECHECK_TIMEOUT,
                        request.needs_preprocessing(&self.exec, &resolved.auth),
                    )
                    .await
                    .map_err(|_| "MIME preprocessing lookup timed out (#328)")?
                    .map_err(|_| "MIME preprocessing lookup failed (#328)")?;
                    if pre {
                        return Err("unported MIME preprocessing (#328)");
                    }
                }
                if matches!(
                    request.args,
                    submission::Arguments::Set(Ok(_)) | submission::Arguments::Cancel(Ok(_))
                ) {
                    *mutated = true;
                }
                let (m, json) = submission::response_call(
                    &self.exec,
                    &resolved.auth,
                    self.worker.as_ref().unwrap_or(&self.exec),
                    request,
                    operation,
                    digest_bytes,
                )
                .await;
                return Ok((m.into(), json));
            }
            Claimed::Changes(request) => {
                let (raw_account_id, since_state, max_changes) = match request.args {
                    changes::ChangesArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    changes::ChangesArgs::Valid {
                        raw_account_id,
                        since_state,
                        max_changes,
                    } => (raw_account_id, since_state, max_changes),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &raw_account_id,
                    family::Gate::Read,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                if !changes::since_state_is_well_formed(&since_state) {
                    return Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "cannotCalculateChanges",
                            400,
                            "client must resync (malformed sinceState)",
                        ),
                    ));
                }
                return match email_changes(&self.exec, &resolved.auth, &since_state, max_changes)
                    .await
                {
                    Ok(raw) => Ok(("Email/changes".into(), raw)),
                    Err(ChangesError::CannotCalculateChanges) => Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "cannotCalculateChanges",
                            400,
                            "client must resync (sinceState too old)",
                        ),
                    )),
                    Err(ChangesError::AccountNotFound) => Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "accountNotFound",
                            400,
                            "accountId does not match an existing account",
                        ),
                    )),
                    Err(ChangesError::Other) => Err("changes read failed"),
                };
            }
            Claimed::Set(request) => {
                let (raw_account_id, phase) = match request.args {
                    set::SetArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    set::SetArgs::Valid {
                        raw_account_id,
                        phase,
                    } => (raw_account_id, phase),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &raw_account_id,
                    family::Gate::Mutate,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                *mutated = true;
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmailSet,
                };
                let patches;
                let set_phase = match &phase {
                    set::Phase::Update(json) => {
                        patches = json.as_str();
                        SetPhase::Update(patches)
                    }
                    set::Phase::Destroy { ids, .. } => SetPhase::Destroy(ids),
                };
                let outcome = email_set(
                    &self.exec,
                    &envelope,
                    &resolved.auth,
                    Instant::now() + COMMAND_DEADLINE,
                    set_phase,
                )
                .await;
                return match outcome {
                    SetOutcome::Done(raw) => {
                        let merged = set::merged(&raw).ok_or("set reply not JSON")?;
                        let result = match &phase {
                            set::Phase::Destroy { bad, .. } => {
                                set::add_not_destroyed(&merged, bad).ok_or("set reply not JSON")?
                            }
                            set::Phase::Update(_) => merged,
                        };
                        Ok(("Email/set".into(), result))
                    }
                    SetOutcome::Failed(failure) => Ok((
                        "error".into(),
                        reply::failure_json(failure).ok_or("email set failed")?,
                    )),
                    SetOutcome::Forward => Err("email set rolled back"),
                    SetOutcome::Unknown { operation } => Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    )),
                };
            }
            Claimed::Batch(request) => {
                let (ids, bad) = match &request.args {
                    batch::BatchArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, msg),
                        ));
                    }
                    batch::BatchArgs::Valid { ids, bad } => (ids.clone(), bad.clone()),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &request.raw_account_id,
                    family::Gate::Mutate,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                *mutated = true;
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmailBatch,
                };
                let outcome = email_batch(
                    &self.exec,
                    &envelope,
                    &resolved.auth,
                    Instant::now() + COMMAND_DEADLINE,
                    request.op,
                    &ids,
                )
                .await;
                return match outcome {
                    SetOutcome::Done(raw) => {
                        let result = request.result(&raw, &bad).ok_or("batch reply not JSON")?;
                        Ok((request.method().into(), result))
                    }
                    SetOutcome::Failed(failure) => Ok((
                        "error".into(),
                        reply::failure_json(failure).ok_or("email batch failed")?,
                    )),
                    SetOutcome::Forward => Err("email batch rolled back"),
                    SetOutcome::Unknown { operation } => Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    )),
                };
            }
            Claimed::Dismiss(request) => {
                let thread_id = match &request.args {
                    batch::DismissArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, msg),
                        ));
                    }
                    batch::DismissArgs::Valid { thread_id } => thread_id.clone(),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &request.raw_account_id,
                    family::Gate::Mutate,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                let enabled = gates::toggle_state(&self.exec, gates::NUDGES_FLAG)
                    .await
                    .ok_or("toggle unreadable")?;
                if !enabled {
                    return Ok(("Email/nudgeDismiss".into(), request.off()));
                }
                *mutated = true;
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmailBatch,
                };
                return match nudge_dismiss(
                    &self.exec,
                    &envelope,
                    &resolved.auth,
                    Instant::now() + COMMAND_DEADLINE,
                    &thread_id,
                )
                .await
                {
                    SetOutcome::Done(raw) => {
                        let result = request.result(&raw).ok_or("dismiss reply not JSON")?;
                        Ok(("Email/nudgeDismiss".into(), result))
                    }
                    SetOutcome::Failed(failure) => Ok((
                        "error".into(),
                        reply::failure_json(failure).ok_or("dismiss failed")?,
                    )),
                    SetOutcome::Forward => Err("dismiss rolled back"),
                    SetOutcome::Unknown { operation } => Ok((
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    )),
                };
            }
            Claimed::Paged(request) => {
                let (limit, position) = match request.args {
                    batch::PagedArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    batch::PagedArgs::Valid { limit, position } => (limit, position),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &request.raw_account_id,
                    family::Gate::Read,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                if request.which == Paged::Nudges {
                    let enabled = gates::toggle_state(&self.exec, gates::NUDGES_FLAG)
                        .await
                        .ok_or("toggle unreadable")?;
                    if !enabled {
                        return Ok(("Email/nudges".into(), request.nudges_off()));
                    }
                }
                return match read_paged(
                    &self.exec,
                    &resolved.auth,
                    request.which,
                    limit,
                    position,
                )
                .await
                {
                    Ok(raw) => {
                        let result = request
                            .result(&raw, position)
                            .ok_or("paged reply not JSON")?;
                        Ok((request.method().into(), result))
                    }
                    Err(failure) => Ok((
                        "error".into(),
                        reply::failure_json(setjoin_jmap::classify_failure(&failure))
                            .ok_or("paged read failed")?,
                    )),
                };
            }
            Claimed::Query(request) => {
                let (raw_account_id, filter, sort, position, limit) = match request.args {
                    query::QueryArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    query::QueryArgs::Valid {
                        raw_account_id,
                        filter,
                        sort,
                        position,
                        limit,
                    } => (raw_account_id, filter, sort, position, limit),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &raw_account_id,
                    family::Gate::Read,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                let Ok(position) = position else {
                    return Ok((
                        "error".into(),
                        reply::jmap_error_json("serverFail", 500, "database error"),
                    ));
                };
                return match query_email(
                    &self.exec,
                    &resolved.auth,
                    filter.as_deref(),
                    sort.as_deref(),
                    position,
                    limit,
                )
                .await
                {
                    Ok(raw) => Ok(("Email/query".into(), raw)),
                    Err(failure) => Ok((
                        "error".into(),
                        reply::failure_json(setjoin_jmap::classify_failure(&failure))
                            .ok_or("email query read failed")?,
                    )),
                };
            }
            Claimed::Get(request) => {
                let (raw_account_id, ids, bad, properties, too_many) = match request.args {
                    get::GetArgs::Invalid(msg) => {
                        return Ok((
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        ));
                    }
                    get::GetArgs::Valid {
                        raw_account_id,
                        ids,
                        bad,
                        properties,
                        too_many,
                    } => (raw_account_id, ids, bad, properties, too_many),
                };
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &raw_account_id,
                    family::Gate::Read,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                if too_many {
                    return Ok((
                        "error".into(),
                        reply::jmap_error_json("requestTooLarge", 400, "too many ids requested"),
                    ));
                }
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmailGet,
                };
                let id_slice = (!ids.is_empty() || !bad.is_empty()).then_some(ids.as_slice());
                let outcome = email_get(
                    &self.exec,
                    &envelope,
                    &resolved.auth,
                    Instant::now() + COMMAND_DEADLINE,
                    id_slice,
                    properties.as_deref(),
                )
                .await;
                let raw = match outcome {
                    GetOutcome::Served(raw) => {
                        *mutated = true;
                        raw
                    }
                    GetOutcome::Failed(failure) => {
                        *mutated = true;
                        return Ok((
                            "error".into(),
                            reply::failure_json(failure).ok_or("email get failed")?,
                        ));
                    }
                    GetOutcome::Encrypted => return Err("encrypted mail: Go decrypts on read"),
                    GetOutcome::Forward => return Err("email get not served"),
                };
                let result = get::add_not_found(&raw, &bad).ok_or("get reply not JSON")?;
                return Ok(("Email/get".into(), result));
            }
            Claimed::List(list) => {
                let raw_acct = list.account_id.to_string();
                let resolved = match account::resolve_account(
                    &self.exec,
                    user_id,
                    &raw_acct,
                    family::Gate::Read,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return Ok(("error".into(), e.json())),
                };
                let page = query_email_list(&self.exec, &resolved.auth, &list.query)
                    .await
                    .map_err(|_| "inbox list read failed")?;
                if log_served() {
                    eprintln!(
                        "setjoin-gateway: inbox list served by Rust mailbox={} tag={} position={} ids={}",
                        resolved.mailbox,
                        list.query.tag,
                        list.query.position,
                        page.ids.len()
                    );
                }
                return Ok((
                    "Email/query".into(),
                    list::result_json(resolved.mailbox, list.query.position, &page),
                ));
            }
            Claimed::Seen(seen) => seen,
        };

        let raw_acct = seen.account_id.to_string();
        let resolved = match account::resolve_account(
            &self.exec,
            user_id,
            &raw_acct,
            family::Gate::Mutate,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return Ok(("error".into(), e.json())),
        };
        *mutated = true;
        let mailbox = resolved.mailbox;
        let mailbox_id = MailboxId::new(mailbox).map_err(|_| "ids")?;
        let message_id = MessageId::new(seen.message_id).map_err(|_| "ids")?;
        let deadline = Instant::now() + COMMAND_DEADLINE;
        let reply = match seen.seen {
            seen::SeenValue::Flag(value) => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: SetMessageSeen {
                        mailbox: mailbox_id,
                        message: message_id,
                        seen: value,
                    },
                };
                set_message_seen(&self.exec, &envelope, &resolved.auth, deadline).await
            }
            seen::SeenValue::EmptyString => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmptySeen {
                        mailbox: mailbox_id,
                        message: message_id,
                    },
                };
                set_message_seen_empty(&self.exec, &envelope, &resolved.auth, deadline).await
            }
        };
        let outcome = match &reply.result {
            OperationResult::Accepted(SeenEffect::Changed {
                old_state,
                email_state,
            }) => Outcome::Updated {
                old_state: *old_state,
                new_state: *email_state,
            },
            OperationResult::Accepted(SeenEffect::Unchanged { email_state }) => Outcome::Updated {
                old_state: *email_state,
                new_state: *email_state,
            },
            OperationResult::Accepted(SeenEffect::NotFound { email_state }) => Outcome::NotFound {
                state: *email_state,
            },
            OperationResult::Accepted(SeenEffect::NotUpdated {
                email_state,
                set_error,
            }) => Outcome::NotUpdated {
                state: *email_state,
                set_error,
            },
            OperationResult::Rejected => {
                eprintln!(
                    "{}",
                    rolled_back_line(reply.operation.0, reply.rejection.as_ref())
                );
                Outcome::Failed
            }
            OperationResult::Unknown | OperationResult::Pending => Outcome::Unknown {
                operation: reply.operation.0,
            },
        };
        if log_served() {
            eprintln!(
                "setjoin-gateway: mark-read served by Rust mailbox={mailbox} message={} outcome={outcome:?}",
                seen.message_id
            );
        }
        let (name, args) = reply::seen_call(mailbox, seen.message_id, outcome);
        Ok((name.into(), args))
    }
}

/// Focus body reader: forwards >64 KiB bodies untouched.
pub(super) async fn buffer_focus(body: Body) -> Result<Bytes, Body> {
    match buffer_with_cap(body, FOCUS_BODY_CAP, true).await {
        Buffered::Whole(bytes) => Ok(bytes),
        Buffered::Forward(rest) => Err(rest),
        Buffered::TooLarge => unreachable!("forward_on_limit is true"),
    }
}

/// Reads at most `cap` bytes; past that returns `TooLarge` or `Forward` (when
/// `forward_on_limit` is true), and on trailers or stream error returns `Forward`.
async fn buffer_with_cap(mut body: Body, cap: usize, forward_on_limit: bool) -> Buffered {
    let mut buf = BytesMut::new();
    loop {
        match body.frame().await {
            None => return Buffered::Whole(buf.freeze()),
            Some(Err(e)) => return Buffered::Forward(Prefixed::boxed(buf.freeze(), None, Some(e))),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    buf.extend_from_slice(&data);
                    if buf.len() > cap {
                        return if forward_on_limit {
                            Buffered::Forward(Prefixed::boxed(buf.freeze(), Some(body), None))
                        } else {
                            Buffered::TooLarge
                        };
                    }
                }
                Err(trailers) => {
                    let rest = Prefixed {
                        prefix: Some(trailers),
                        rest: Some(body),
                        error: None,
                    };
                    return Buffered::Forward(Prefixed::boxed(
                        buf.freeze(),
                        Some(rest.boxed()),
                        None,
                    ));
                }
            },
        }
    }
}

/// A body that yields one frame, then the rest of another body (or an error).
struct Prefixed {
    prefix: Option<Frame<Bytes>>,
    rest: Option<Body>,
    error: Option<crate::BoxError>,
}

impl Prefixed {
    fn boxed(prefix: Bytes, rest: Option<Body>, error: Option<crate::BoxError>) -> Body {
        Prefixed {
            prefix: (!prefix.is_empty()).then(|| Frame::data(prefix)),
            rest,
            error,
        }
        .boxed()
    }
}

impl hyper::body::Body for Prefixed {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        if let Some(frame) = self.prefix.take() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if let Some(e) = self.error.take() {
            return Poll::Ready(Some(Err(e)));
        }
        match self.rest.as_mut() {
            Some(rest) => std::pin::Pin::new(rest).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }
}

/// `GATEWAY_LOG_ROUTES=1`: one stderr line per request Rust serves (rollout
/// observability; off by default).
fn log_served() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("GATEWAY_LOG_ROUTES").as_deref() == Ok("1"))
}

/// The stderr line for a rolled-back command: operation ID plus the
/// rejection's kind and SQLSTATE ([`setjoin_pg::Rejection::log_summary`]);
/// never PostgreSQL's message text or row values.
fn rolled_back_line(
    operation: [u8; 16],
    rejection: Option<&setjoin_pg::Rejection<setjoin_pg::StatementFailure>>,
) -> String {
    let summary = rejection.map_or_else(|| "unknown".to_owned(), |r| r.log_summary());
    format!(
        "setjoin-gateway: mark-read rolled back operation={} {summary}",
        reply::hex(&operation)
    )
}

/// 16 bytes from the OS RNG; `None` (never a panic) when it cannot be read.
pub(crate) fn random() -> Option<[u8; 16]> {
    random_from("/dev/urandom")
}

fn random_from(path: &str) -> Option<[u8; 16]> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .ok()?;
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unreadable entropy source is an answer, not a panic (review item
    /// 2): the route then forwards the request to Go.
    #[test]
    fn an_unreadable_rng_is_none_not_a_panic() {
        assert_eq!(random_from("/nonexistent/setjoin-rng"), None);
        let a = random_from("/dev/urandom").expect("urandom");
        let b = random_from("/dev/urandom").expect("urandom");
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;
    use setjoin_pg::{Rejection, StatementFailure};

    /// Review item 4: the rollback log line names the operation and the
    /// SQLSTATE, never PostgreSQL's message (which can quote row values).
    #[test]
    fn rollback_log_line_has_operation_and_sqlstate_only() {
        let r = Rejection::Statement(StatementFailure {
            hint: None,
            sqlstate: Some("P0001".into()),
            message: "boom: Key (subject)=(Payroll 2026) is secret".into(),
        });
        let line = rolled_back_line([0xab; 16], Some(&r));
        assert_eq!(
            line,
            "setjoin-gateway: mark-read rolled back operation=abababababababababababababababab statement sqlstate=P0001"
        );
        assert!(!line.contains("Payroll"));
        assert_eq!(
            rolled_back_line([0; 16], None),
            "setjoin-gateway: mark-read rolled back operation=00000000000000000000000000000000 unknown"
        );
    }
}
