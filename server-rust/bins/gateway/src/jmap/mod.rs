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
mod messages;
pub mod messages_zip;
pub mod other;
pub mod presence;
pub mod push;
pub mod query;
mod recovery;
pub mod reply;
pub mod seen;
pub mod set;
mod smime_decrypt;
mod smime_outbound;
pub mod sse;
pub mod submission;
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
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use setjoin_contracts::command::{CommandEnvelope, OperationResult, SetMessageSeen};
use setjoin_contracts::ids::{ActorId, Digest, Generation, MailboxId, MessageId, OperationId};
use setjoin_jmap::{
    email_batch, email_changes, email_get, email_set_batch, nudge_dismiss, query_email,
    query_email_list, read_paged, set_message_seen, set_message_seen_empty, snooze_message,
    ChangesError, EmailBatch, EmailGet, EmailSet, EmptySeen, GetOutcome, Paged, SeenEffect,
    SetBatch, SetBatchOutcome, SetOutcome, SnoozeOutcome,
};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
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
    pub decrypt_limiter: Option<Arc<limit::Limiter>>,
    pub encrypt_algorithm: setjoin_smtp::smime::EncryptAlgorithm,
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
            decrypt_limiter: Some(Arc::new(limit::Limiter::new(120, 60))),
            encrypt_algorithm: setjoin_smtp::smime::EncryptAlgorithm::from_env(),
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
                    "setjoin-gateway: continuity signing key unavailable; Continuity/* disabled"
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
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
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
    Echo {
        raw_args: String,
    },
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

/// Either the buffered body, an oversized 10 MB rejection, or an unreadable stream.
enum Buffered {
    Whole(Bytes),
    TooLarge,
    BadStream,
}

impl<K: KeySource> JmapCommands<K> {
    async fn serve(&self, req: Request<Body>, ctx: RequestContext) -> Response<Body> {
        if http::matches(req.method(), req.uri().path()) {
            return self.try_http(req, &ctx).await;
        }
        if submission_actions::target(req.uri().path()).is_some() {
            return self.serve_action(req, ctx).await;
        }
        if let Some((route, id)) = messages::target(req.method(), req.uri().path()) {
            return self.serve_message(route, id, req, ctx).await;
        }
        // Auth-first: admit via shared deny policy before reading/buffering body.
        let (req, authorized) = match self.admit_http(req, &ctx, crate::deny::Scope::Member).await {
            Ok(ok) => ok,
            Err(response) => return response,
        };
        let (parts, body) = req.into_parts();
        match buffer_with_cap(body, JMAP_BODY_CAP).await {
            Buffered::Whole(bytes) => self.execute_http(&parts, &bytes, &ctx, &authorized).await,
            Buffered::TooLarge | Buffered::BadStream => {
                let req_id = reply::request_id(
                    parts.headers.get("x-request-id"),
                    random_bytes().unwrap_or([0; 16]),
                );
                reply::problem_response(
                    400,
                    "notJSON",
                    "invalid JSON in request body",
                    ctx.identity.proto,
                    req_id,
                )
            }
        }
    }

    pub(super) async fn admit_http(
        &self,
        req: Request<Body>,
        ctx: &RequestContext,
        scope: crate::deny::Scope,
    ) -> Result<(Request<Body>, setjoin_authz::Authorized), Response<Body>> {
        let authorized =
            match crate::deny::admit(&self.exec, &self.keys, &self.issuer, &req, scope).await {
                Ok(authorized) => authorized,
                Err(refusal) => return Err(crate::deny::answer(refusal, req, ctx).await),
            };
        let identity = authorized.context();
        if let Some(denylist) = &self.denylist {
            let Some(issued) = chrono::DateTime::from_timestamp(authorized.issued_at(), 0) else {
                return Err(crate::admission::problem(
                    req.headers(),
                    &ctx.identity,
                    503,
                    "service unavailable",
                ));
            };
            if denylist.is_revoked(
                identity.user_id(),
                authorized.token_id(),
                authorized.token_family(),
                issued,
            ) {
                return Err(crate::deny::native_or_unauthorized(
                    crate::deny::Refusal::Revoked,
                    req.headers(),
                    ctx,
                ));
            }
            if !denylist.loaded() {
                let cae = tokio::time::timeout(
                    PRECHECK_TIMEOUT,
                    self.exec.read(
                        "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'),false)",
                        &[],
                    ),
                )
                .await;
                match cae {
                    Ok(Ok(rows)) if rows.first().is_some_and(|r| r.get::<_, bool>(0)) => {
                        return Err(crate::admission::revoked_problem(
                            req.headers(),
                            &ctx.identity,
                            "Session verification unavailable — re-authenticate.",
                        ));
                    }
                    Ok(Ok(_)) => {}
                    _ => {
                        return Err(crate::admission::problem(
                            req.headers(),
                            &ctx.identity,
                            503,
                            "service unavailable",
                        ));
                    }
                }
            }
        }
        Ok((req, authorized))
    }

    async fn execute_http(
        &self,
        parts: &hyper::http::request::Parts,
        bytes: &Bytes,
        ctx: &RequestContext,
        authorized: &setjoin_authz::Authorized,
    ) -> Response<Body> {
        let cleaned = crate::guests_input::go_json_bytes(bytes);
        let req: HttpBatchRequest = match serde_json::from_slice(&cleaned) {
            Ok(req) => req,
            Err(_) => {
                let req_id = reply::request_id(
                    parts.headers.get("x-request-id"),
                    random_bytes().unwrap_or([0; 16]),
                );
                return reply::problem_response(
                    400,
                    "notJSON",
                    "invalid JSON in request body",
                    ctx.identity.proto,
                    req_id,
                );
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
            .await;
        let request_id = reply::request_id(
            parts.headers.get("x-request-id"),
            request_random.unwrap_or([0; 16]),
        );
        match outcome {
            BatchOutcome::Problem {
                status,
                kind,
                detail,
            } => reply::problem_response(status, kind, &detail, ctx.identity.proto, request_id),
            BatchOutcome::Response(responses) => {
                let body =
                    reply::http_batch_response(&authorized.session_state().encode(), &responses);
                reply::response(body, ctx.identity.proto, request_id)
            }
        }
    }

    /// Shared RNG reservation + batch execution engine for HTTP & WS.
    pub(super) async fn execute_batch_verified(
        &self,
        user_id: i64,
        primary_mailbox: i64,
        email: &str,
        using: &[String],
        calls: &[ws_request::Call],
        need_request_random: bool,
    ) -> (Option<[u8; 16]>, BatchOutcome) {
        let server_fail = || BatchOutcome::Problem {
            status: 500,
            kind: "serverFail",
            detail: "internal error".into(),
        };
        if using.is_empty() {
            let req_rand = if need_request_random {
                let Ok(r) = random_bytes() else {
                    return (None, server_fail());
                };
                Some(r)
            } else {
                None
            };
            return (
                req_rand,
                BatchOutcome::Problem {
                    status: 400,
                    kind: "notRequest",
                    detail: "'using' array must not be empty".into(),
                },
            );
        }
        if calls.len() > 32 {
            let req_rand = if need_request_random {
                let Ok(r) = random_bytes() else {
                    return (None, server_fail());
                };
                Some(r)
            } else {
                None
            };
            return (
                req_rand,
                BatchOutcome::Problem {
                    status: 400,
                    kind: "requestTooLarge",
                    detail: format!("maxCallsInRequest of 32 exceeded ({} calls)", calls.len()),
                },
            );
        }
        let request_random = if need_request_random {
            let Ok(r) = random_bytes() else {
                return (None, server_fail());
            };
            Some(r)
        } else {
            None
        };
        let mut operations = Vec::with_capacity(calls.len());
        for _ in 0..calls.len() {
            let Ok(op) = random_bytes() else {
                return (request_random, server_fail());
            };
            operations.push(op);
        }
        let outcome = self
            .execute_batch(user_id, primary_mailbox, email, using, calls, &operations)
            .await;
        (request_random, outcome)
    }

    async fn execute_batch(
        &self,
        user_id: i64,
        primary_mailbox: i64,
        email: &str,
        using: &[String],
        calls: &[ws_request::Call],
        operations: &[[u8; 16]],
    ) -> BatchOutcome {
        let mut responses: Vec<ws_request::Call> = Vec::with_capacity(calls.len());
        for (idx, call) in calls.iter().enumerate() {
            if call.args.get().len() > 2_000_000 {
                return BatchOutcome::Problem {
                    status: 400,
                    kind: "requestTooLarge",
                    detail: format!("method call '{}' exceeds 2 MB limit", call.name),
                };
            }
            let cap = ws_request::capability(&call.name);
            if !using.iter().any(|s| s == cap) {
                return BatchOutcome::Problem {
                    status: 400,
                    kind: "unknownCapability",
                    detail: format!("Capability not declared in 'using': {cap}"),
                };
            }
            let (name, args) = match ws_request::references(call.args.get(), &responses) {
                Err((kind, detail)) => {
                    ("error".to_owned(), ws_request::method_error(kind, &detail))
                }
                Ok(resolved_args) => {
                    if call.name.is_empty() || call.name.len() > 128 {
                        (
                            "error".into(),
                            ws_request::method_error("unknownMethod", "invalid method name"),
                        )
                    } else if call.name != "Core/echo" && !ws_request::registered(&call.name) {
                        (
                            "error".into(),
                            ws_request::method_error("unknownMethod", ""),
                        )
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
                        self.execute_call(
                            user_id,
                            primary_mailbox,
                            email,
                            &call.name,
                            &resolved_args,
                            &call.id,
                            operations[idx],
                        )
                        .await
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
        BatchOutcome::Response(responses)
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
    ) -> (String, String) {
        let Some(claimed) = claim_call(method_name, raw_args, client_id, self.services.as_deref())
        else {
            return ("error".into(), ws_request::server_fail());
        };
        let (Ok(actor_id), Ok(primary_mailbox_id)) =
            (ActorId::new(user_id), MailboxId::new(primary_mailbox))
        else {
            return ("error".into(), ws_request::server_fail());
        };
        let primary_auth = MailboxAuthContext::from_authenticated_session(
            actor_id,
            primary_mailbox_id,
            REQUEST_AUTHORITY_GENERATION,
        );
        let digest_bytes: [u8; 32] = Sha256::digest(raw_args.as_bytes()).into();
        let digest = Digest(digest_bytes);

        let seen = match claimed {
            Claimed::Identity(request) => {
                let Some(services) = self.services.as_ref() else {
                    return ("error".into(), ws_request::server_fail());
                };
                let (m, json) =
                    identity::response_call(&self.exec, &services.worker, &primary_auth, &request)
                        .await;
                return (m.into(), json);
            }
            Claimed::Blob(request) => {
                let Some(services) = self.services.as_ref() else {
                    return ("error".into(), ws_request::server_fail());
                };
                let (m, json) =
                    blob::response_call(&services.worker, &primary_auth, &request).await;
                return (m.into(), json);
            }
            Claimed::Echo { raw_args } => {
                let compact = reply::go_compact(&raw_args).unwrap_or(raw_args);
                return ("Core/echo".into(), compact);
            }
            Claimed::Family(request) => {
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
                return (m.into(), json);
            }
            Claimed::Receipt(request) => {
                return self
                    .execute_recovery_receipt(user_id, &request.raw_args, operation, digest_bytes)
                    .await;
            }
            Claimed::MailboxSet(request) => {
                let (create, update, destroy, bad) = match request.args {
                    mailbox_set::MailboxSetArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
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
                        let Some(merged) = set::merged(&raw) else {
                            return ("error".into(), ws_request::server_fail());
                        };
                        let Some(result) = set::add_not_destroyed(&merged, &bad) else {
                            return ("error".into(), ws_request::server_fail());
                        };
                        (request.method.into(), result)
                    }
                    SetOutcome::Failed(f) => ("error".into(), reply::failure_or_server_fail(f)),
                    SetOutcome::Forward => (
                        "error".into(),
                        reply::jmap_error_json("serverFail", 500, "database error"),
                    ),
                    SetOutcome::Unknown { operation } => (
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    ),
                };
            }
            Claimed::Other(request) => {
                let (read, bad, too_many) = match request.args {
                    other::OtherArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                if too_many {
                    return (
                        "error".into(),
                        reply::jmap_error_json("requestTooLarge", 400, "too many ids requested"),
                    );
                }
                if read
                    .since_state()
                    .is_some_and(|s| !changes::since_state_is_well_formed(s))
                {
                    return (
                        "error".into(),
                        reply::jmap_error_json(
                            "cannotCalculateChanges",
                            400,
                            "client must resync (malformed sinceState)",
                        ),
                    );
                }
                let raw = setjoin_jmap::mailbox::read(&self.exec, &resolved.auth, &read).await;
                return match raw {
                    Ok(raw) => match get::add_not_found(&raw, &bad) {
                        Some(result) => (request.method.into(), result),
                        None => ("error".into(), ws_request::server_fail()),
                    },
                    Err(e) if e.sqlstate.as_deref() == Some("BZ040") => (
                        "error".into(),
                        reply::jmap_error_json("invalidArguments", 400, &e.message),
                    ),
                    Err(e) => (
                        "error".into(),
                        reply::failure_or_server_fail(setjoin_jmap::classify_failure(&e)),
                    ),
                };
            }
            Claimed::Submission(request) => {
                if let Some(err) = request.early_error() {
                    return (
                        "error".into(),
                        reply::jmap_error_json(err.kind, err.status, &err.detail),
                    );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                let (m, json) = submission::response_call(
                    &self.exec,
                    &resolved.auth,
                    self.worker.as_ref().unwrap_or(&self.exec),
                    self.services.as_deref(),
                    request,
                    operation,
                    digest_bytes,
                )
                .await;
                return (m.into(), json);
            }
            Claimed::Changes(request) => {
                let (raw_account_id, since_state, max_changes) = match request.args {
                    changes::ChangesArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                if !changes::since_state_is_well_formed(&since_state) {
                    return (
                        "error".into(),
                        reply::jmap_error_json(
                            "cannotCalculateChanges",
                            400,
                            "client must resync (malformed sinceState)",
                        ),
                    );
                }
                return match email_changes(&self.exec, &resolved.auth, &since_state, max_changes)
                    .await
                {
                    Ok(raw) => ("Email/changes".into(), raw),
                    Err(ChangesError::CannotCalculateChanges) => (
                        "error".into(),
                        reply::jmap_error_json(
                            "cannotCalculateChanges",
                            400,
                            "client must resync (sinceState too old)",
                        ),
                    ),
                    Err(ChangesError::AccountNotFound) => (
                        "error".into(),
                        reply::jmap_error_json(
                            "accountNotFound",
                            400,
                            "accountId does not match an existing account",
                        ),
                    ),
                    Err(ChangesError::Other) => ("error".into(), ws_request::server_fail()),
                };
            }
            Claimed::Set(request) => {
                let (raw_account_id, create, ordinary_update, snooze_updates, destroy) =
                    match request.args {
                        set::SetArgs::Invalid(msg) => {
                            return (
                                "error".into(),
                                reply::jmap_error_json("invalidArguments", 400, &msg),
                            );
                        }
                        set::SetArgs::Valid {
                            raw_account_id,
                            create,
                            ordinary_update,
                            snooze_updates,
                            destroy,
                        } => (
                            raw_account_id,
                            create,
                            ordinary_update,
                            snooze_updates,
                            destroy,
                        ),
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
                    Err(e) => return ("error".into(), e.json()),
                };
                let gated_create = if let Some(raw_create) = create.as_deref() {
                    let worker = self
                        .services
                        .as_ref()
                        .map(|s| &s.worker)
                        .or(self.worker.as_ref());
                    match set::gate_attachment_blob_ownership(worker, user_id, raw_create).await {
                        Ok(gated) => Some(gated),
                        Err(()) => return ("error".into(), ws_request::server_fail()),
                    }
                } else {
                    None
                };
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: resolved.auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmailSet,
                };
                let mut snooze_updated = Vec::new();
                let mut snooze_not_updated = Vec::new();
                let deadline = Instant::now() + COMMAND_DEADLINE;
                for (id_str, until) in &snooze_updates {
                    let Ok(msg_id) = id_str.parse::<i64>() else {
                        snooze_not_updated.push((
                            id_str.clone(),
                            r#"{"description":"invalid message id","type":"invalidArguments"}"#
                                .to_owned(),
                        ));
                        continue;
                    };
                    match snooze_message(
                        &self.exec,
                        &envelope,
                        &resolved.auth,
                        deadline,
                        msg_id,
                        until,
                    )
                    .await
                    {
                        SnoozeOutcome::Committed => snooze_updated.push(id_str.clone()),
                        SnoozeOutcome::Failed(_) => snooze_not_updated.push((
                            id_str.clone(),
                            r#"{"description":"snooze failed","type":"invalidArguments"}"#
                                .to_owned(),
                        )),
                        SnoozeOutcome::Unknown => {
                            return (
                                "error".into(),
                                reply::jmap_error_json(
                                    "serverFail",
                                    500,
                                    &format!(
                                        "commit outcome unknown; look up operation {}",
                                        reply::hex(&envelope.operation.0)
                                    ),
                                ),
                            );
                        }
                    }
                }
                let batch = SetBatch {
                    create: gated_create.as_ref().map(|g| g.filtered_json.as_str()),
                    update: ordinary_update.as_deref(),
                    destroy: destroy.as_ref().map(|(ids, _)| ids.as_slice()),
                };
                let outcome = email_set_batch(
                    &self.exec,
                    &envelope,
                    &resolved.auth,
                    Instant::now() + COMMAND_DEADLINE,
                    batch,
                )
                .await;
                return match outcome {
                    SetBatchOutcome::Done(parts) => {
                        let empty_denied = std::collections::BTreeMap::new();
                        let denied = gated_create.as_ref().map_or(&empty_denied, |g| &g.denied);
                        let bad = destroy.as_ref().map_or(&[][..], |(_, b)| b.as_slice());
                        let Some(result) = set::merge_response(
                            &parts,
                            denied,
                            bad,
                            ordinary_update.is_some(),
                            &snooze_updated,
                            &snooze_not_updated,
                        ) else {
                            return ("error".into(), ws_request::server_fail());
                        };
                        ("Email/set".into(), result)
                    }
                    SetBatchOutcome::Failed(failure) => {
                        ("error".into(), reply::failure_or_server_fail(failure))
                    }
                    SetBatchOutcome::Unknown { operation } => (
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    ),
                };
            }
            Claimed::Batch(request) => {
                let (ids, bad) = match &request.args {
                    batch::BatchArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                if ids.is_empty() && bad.is_empty() {
                    return ("error".into(), ws_request::server_fail());
                }
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
                        let Some(result) = request.result(&raw, &bad) else {
                            return ("error".into(), ws_request::server_fail());
                        };
                        (request.method().into(), result)
                    }
                    SetOutcome::Failed(failure) => {
                        ("error".into(), reply::failure_or_server_fail(failure))
                    }
                    SetOutcome::Forward => ("error".into(), ws_request::server_fail()),
                    SetOutcome::Unknown { operation } => (
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    ),
                };
            }
            Claimed::Dismiss(request) => {
                let thread_id = match &request.args {
                    batch::DismissArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                let Some(enabled) = gates::toggle_state(&self.exec, gates::NUDGES_FLAG).await
                else {
                    return ("error".into(), ws_request::server_fail());
                };
                if !enabled {
                    return ("Email/nudgeDismiss".into(), request.off());
                }
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
                        let Some(result) = request.result(&raw) else {
                            return ("error".into(), ws_request::server_fail());
                        };
                        ("Email/nudgeDismiss".into(), result)
                    }
                    SetOutcome::Failed(failure) => {
                        ("error".into(), reply::failure_or_server_fail(failure))
                    }
                    SetOutcome::Forward => ("error".into(), ws_request::server_fail()),
                    SetOutcome::Unknown { operation } => (
                        "error".into(),
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                        ),
                    ),
                };
            }
            Claimed::Paged(request) => {
                let (limit, position) = match request.args {
                    batch::PagedArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                if request.which == Paged::Nudges {
                    let Some(enabled) = gates::toggle_state(&self.exec, gates::NUDGES_FLAG).await
                    else {
                        return ("error".into(), ws_request::server_fail());
                    };
                    if !enabled {
                        return ("Email/nudges".into(), request.nudges_off());
                    }
                }
                return match read_paged(&self.exec, &resolved.auth, request.which, limit, position)
                    .await
                {
                    Ok(raw) => {
                        let Some(result) = request.result(&raw, position) else {
                            return ("error".into(), ws_request::server_fail());
                        };
                        (request.method().into(), result)
                    }
                    Err(failure) => (
                        "error".into(),
                        reply::failure_or_server_fail(setjoin_jmap::classify_failure(&failure)),
                    ),
                };
            }
            Claimed::Query(request) => {
                let (raw_account_id, filter, sort, position, limit) = match request.args {
                    query::QueryArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                let Ok(position) = position else {
                    return (
                        "error".into(),
                        reply::jmap_error_json("serverFail", 500, "database error"),
                    );
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
                    Ok(raw) => ("Email/query".into(), raw),
                    Err(failure) => (
                        "error".into(),
                        reply::failure_or_server_fail(setjoin_jmap::classify_failure(&failure)),
                    ),
                };
            }
            Claimed::Get(request) => {
                let (raw_account_id, ids, bad, properties, too_many) = match request.args {
                    get::GetArgs::Invalid(msg) => {
                        return (
                            "error".into(),
                            reply::jmap_error_json("invalidArguments", 400, &msg),
                        );
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
                    Err(e) => return ("error".into(), e.json()),
                };
                if too_many {
                    return (
                        "error".into(),
                        reply::jmap_error_json("requestTooLarge", 400, "too many ids requested"),
                    );
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
                    GetOutcome::Served(raw) => raw,
                    GetOutcome::Failed(failure) => {
                        return ("error".into(), reply::failure_or_server_fail(failure));
                    }
                    GetOutcome::Forward => return ("error".into(), ws_request::server_fail()),
                };
                let key_worker = self
                    .services
                    .as_ref()
                    .map(|s| &s.worker)
                    .or(self.worker.as_ref())
                    .unwrap_or(&self.exec);
                let raw = smime_decrypt::decrypt_email_result(
                    &self.exec,
                    key_worker,
                    self.services.as_ref().and_then(|s| s.store.as_deref()),
                    self.services
                        .as_ref()
                        .and_then(|s| s.decrypt_limiter.as_deref()),
                    &resolved.auth,
                    &raw,
                )
                .await;
                let Some(result) = get::add_not_found(&raw, &bad) else {
                    return ("error".into(), ws_request::server_fail());
                };
                return ("Email/get".into(), result);
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
                    Err(e) => return ("error".into(), e.json()),
                };
                let Ok(page) = query_email_list(&self.exec, &resolved.auth, &list.query).await
                else {
                    return ("error".into(), ws_request::server_fail());
                };
                if log_served() {
                    eprintln!(
                        "setjoin-gateway: inbox list served by Rust mailbox={} tag={} position={} ids={}",
                        resolved.mailbox,
                        list.query.tag,
                        list.query.position,
                        page.ids.len()
                    );
                }
                return (
                    "Email/query".into(),
                    list::result_json(resolved.mailbox, list.query.position, &page),
                );
            }
            Claimed::Seen(seen) => seen,
        };

        let raw_acct = seen.account_id.to_string();
        let resolved =
            match account::resolve_account(&self.exec, user_id, &raw_acct, family::Gate::Mutate)
                .await
            {
                Ok(r) => r,
                Err(e) => return ("error".into(), e.json()),
            };
        let mailbox = resolved.mailbox;
        let (Ok(mailbox_id), Ok(message_id)) =
            (MailboxId::new(mailbox), MessageId::new(seen.message_id))
        else {
            return ("error".into(), ws_request::server_fail());
        };
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
        (name.into(), args)
    }
}

pub(super) enum FocusBodyError {
    TooLarge,
    Invalid,
}

/// Focus body reader: enforces 64 KiB cap (`413`) and rejects unreadable streams (`400`).
pub(super) async fn buffer_focus(mut body: Body) -> Result<Bytes, FocusBodyError> {
    let mut buf = BytesMut::new();
    loop {
        match body.frame().await {
            None => return Ok(buf.freeze()),
            Some(Err(_)) => return Err(FocusBodyError::Invalid),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    buf.extend_from_slice(&data);
                    if buf.len() > FOCUS_BODY_CAP {
                        return Err(FocusBodyError::TooLarge);
                    }
                }
                Err(_) => return Err(FocusBodyError::Invalid),
            },
        }
    }
}

/// Reads at most `cap` bytes; past that returns `TooLarge`, and on stream errors returns `BadStream`.
async fn buffer_with_cap(mut body: Body, cap: usize) -> Buffered {
    let mut buf = BytesMut::new();
    loop {
        match body.frame().await {
            None => return Buffered::Whole(buf.freeze()),
            Some(Err(_)) => return Buffered::BadStream,
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    buf.extend_from_slice(&data);
                    if buf.len() > cap {
                        return Buffered::TooLarge;
                    }
                }
                Err(_) => continue,
            },
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

/// 16 bytes from the OS RNG; `Err(())` (never a panic) when unavailable.
pub(super) fn random_bytes() -> Result<[u8; 16], ()> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| ())?;
    Ok(b)
}

/// 16 bytes from the OS RNG; `None` (never a panic) when it cannot be read.
pub(crate) fn random() -> Option<[u8; 16]> {
    random_bytes().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_produces_unique_tokens() {
        let a = random_bytes().expect("getrandom");
        let b = random_bytes().expect("getrandom");
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
