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

pub mod batch;
pub mod blob;
pub mod changes;
pub mod device_cache;
mod download;
pub mod envelope;
pub mod gates;
pub mod get;
pub mod http;
pub mod hub;
mod identity;
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

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use hyper::{Method, Request, Response};
use setjoin_contracts::command::{CommandEnvelope, OperationResult, SetMessageSeen};
use setjoin_contracts::ids::{ActorId, Digest, Generation, MailboxId, MessageId, OperationId};
use setjoin_jmap::{
    email_batch, email_changes, email_get, email_set, nudge_dismiss, query_email, query_email_list,
    read_paged, set_message_seen, set_message_seen_empty, ChangesError, EmailBatch, EmailGet,
    EmailSet, EmptySeen, GetOutcome, Paged, SeenEffect, SetOutcome, SetPhase,
};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
use sha2::{Digest as _, Sha256};

use crate::routes::{BoxFuture, Intercept, RequestContext};
use crate::Body;

use self::reply::Outcome;
use self::token::KeySource;

/// A mark-read body is a few hundred bytes; anything past this is forwarded.
const BODY_CAP: usize = 64 * 1024;
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
        services.continuity_boot = recovery::boot_from_env();
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

/// The command a body is exactly expressible as.
enum Claimed {
    Echo(envelope::SingleCall),
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
}

/// The command a body is exactly expressible as, most specific shape first.
fn claim(bytes: &[u8]) -> Option<Claimed> {
    identity::classify(bytes)
        .map(Claimed::Identity)
        .or_else(|| mailbox_set::classify_identity(bytes).map(Claimed::MailboxSet))
        .or_else(|| seen::classify(bytes).map(Claimed::Seen))
        .or_else(|| list::classify(bytes).map(Claimed::List))
        .or_else(|| changes::classify(bytes).map(Claimed::Changes))
        .or_else(|| get::classify(bytes).map(Claimed::Get))
        .or_else(|| claim_general(bytes))
}

/// The general shapes beyond the specialized mark-read and inbox-list adapters.
fn claim_general(bytes: &[u8]) -> Option<Claimed> {
    if let Some(request) = submission::classify(bytes) {
        return Some(Claimed::Submission(request));
    }
    if let Some(request) = blob::classify(bytes) {
        return Some(Claimed::Blob(request));
    }
    envelope::single_call_with_capability(bytes, "Core/echo", "urn:ietf:params:jmap:core")
        .map(Claimed::Echo)
        .or_else(|| {
            other::classify(bytes)
                .map(Claimed::Other)
                .or_else(|| mailbox_set::classify(bytes).map(Claimed::MailboxSet))
                .or_else(|| {
                    query::classify(bytes)
                        .map(Claimed::Query)
                        .or_else(|| set::classify(bytes).map(Claimed::Set))
                        .or_else(|| batch::classify_batch(bytes).map(Claimed::Batch))
                        .or_else(|| batch::classify_paged(bytes).map(Claimed::Paged))
                        .or_else(|| batch::classify_dismiss(bytes).map(Claimed::Dismiss))
                        .or_else(|| batch::classify_receipt(bytes).map(Claimed::Receipt))
                })
        })
}

/// Either the buffered body or a request that must go to Go as it is.
enum Buffered {
    Whole(Bytes),
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
        let bytes = match buffer(body).await {
            Buffered::Whole(b) => b,
            Buffered::Forward(rest) => {
                return ctx
                    .upstream
                    .forward(Request::from_parts(parts, rest), &ctx.identity)
                    .await;
            }
        };
        match self.try_serve(&parts, &bytes, &ctx).await {
            Ok(resp) => return resp,
            Err(reason) if log_served() && reason != NOT_CLAIMED => {
                eprintln!("setjoin-gateway: /jmap route deferred to Go: {reason}");
            }
            Err(_) => {}
        }
        let body = Full::new(bytes).map_err(|n| match n {}).boxed();
        ctx.upstream
            .forward(Request::from_parts(parts, body), &ctx.identity)
            .await
    }

    /// `Ok` only when Rust served the request; `Err(reason)` = forward to Go.
    async fn try_serve(
        &self,
        parts: &hyper::http::request::Parts,
        bytes: &Bytes,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, &'static str> {
        claim(bytes).ok_or(NOT_CLAIMED)?;
        let authorized = setjoin_authz::authorize_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            &parts.headers,
            ctx.identity.proto,
        )
        .await
        .ok_or("authorization preconditions not met")?;
        self.execute_authorized(parts, bytes, ctx, &authorized)
            .await
    }

    /// Same command authority for the authenticated WebSocket transport.
    async fn execute_authorized(
        &self,
        parts: &hyper::http::request::Parts,
        bytes: &Bytes,
        ctx: &RequestContext,
        authorized: &setjoin_authz::Authorized,
    ) -> Result<Response<Body>, &'static str> {
        let claimed = claim(bytes).ok_or(NOT_CLAIMED)?;
        let identity = authorized.context();
        if let Some(denylist) = &self.denylist {
            let issued =
                chrono::DateTime::from_timestamp(authorized.issued_at(), 0).ok_or("token iat")?;
            if denylist.is_revoked(
                    identity.user_id(),
                    authorized.token_id(),
                    authorized.token_family(),
                    issued,
                )
            {
                return Err("session denylist revoked");
            }
            // Go trusts a negative cold cache when CAE is off. HTTP's outer
            // runtime gate owns its terminal denial; retain the same cold
            // condition here for authenticated socket batches.
            if !denylist.loaded() {
                let cae=tokio::time::timeout(setjoin_authz::precheck_timeout(),self.exec.read(
                    "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'),false)",&[])).await
                    .map_err(|_|"session denylist cold")?.map_err(|_|"session denylist cold")?;
                if cae[0].get::<_,bool>(0){return Err("session denylist cold");}
            }
        }
        let mailbox = identity.mailbox_id();
        let state = authorized.session_state();
        if let Claimed::Submission(request) = &claimed {
            if let Some(error) = request.early_error() {
                let request_id = reply::request_id(
                    parts.headers.get("x-request-id"),
                    random().ok_or("rng unavailable")?,
                );
                return Ok(reply::response(
                    reply::method_error(
                        &state.encode(),
                        error.kind,
                        error.status,
                        &error.detail,
                        &request.client_id,
                    ),
                    ctx.identity.proto,
                    request_id,
                ));
            }
        }
        let account_id = match &claimed {
            Claimed::Echo(_) | Claimed::Blob(_) | Claimed::Identity(_) => mailbox,
            Claimed::Other(r) => r.account_id,
            Claimed::MailboxSet(r) => r.account_id,
            Claimed::Seen(seen) => seen.account_id,
            Claimed::List(list) => list.account_id,
            Claimed::Changes(changes) => changes.account_id,
            Claimed::Get(get) => get.account_id,
            Claimed::Query(query) => query.account_id,
            Claimed::Set(set) => set.account_id,
            Claimed::Batch(batch) => batch.account_id,
            Claimed::Paged(paged) => paged.account_id,
            Claimed::Dismiss(dismiss) => dismiss.account_id,
            Claimed::Submission(request) => request.account_id,
            // Go answers before it reads the account.
            Claimed::Receipt(_) => mailbox,
        };
        if account_id != mailbox {
            // Go's `parseAccountID`: a mailbox the caller neither owns nor
            // holds a delegate grant on is `accountNotFound`. Delegated
            // accounts (per-method gate classes) stay Go's.
            let client_id = match &claimed {
                Claimed::Other(r) => &r.client_id,
                Claimed::MailboxSet(r) => &r.client_id,
                Claimed::Seen(seen) => &seen.client_id,
                Claimed::List(list) => &list.client_id,
                Claimed::Changes(changes) => &changes.client_id,
                Claimed::Get(get) => &get.client_id,
                Claimed::Query(query) => &query.client_id,
                Claimed::Set(set) => &set.client_id,
                Claimed::Batch(batch) => &batch.client_id,
                Claimed::Paged(paged) => &paged.client_id,
                Claimed::Dismiss(dismiss) => &dismiss.client_id,
                Claimed::Submission(request) => &request.client_id,
                _ => return Err("accountId is not the caller's primary mailbox"),
            };
            let delegated = tokio::time::timeout(
                PRECHECK_TIMEOUT,
                self.exec.read(
                    "SELECT EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=$1 AND user_id=$2)",
                    &[
                        (&account_id, setjoin_pg::Type::INT8),
                        (&identity.user_id(), setjoin_pg::Type::INT8),
                    ],
                ),
            )
            .await
            .map_err(|_| "delegate lookup timed out")?
            .map_err(|_| "delegate lookup failed")?;
            if delegated
                .first()
                .ok_or("delegate lookup")?
                .get::<_, bool>(0)
            {
                return Err("delegated account");
            }
            let request_random = random().ok_or("rng unavailable")?;
            let request_id = reply::request_id(parts.headers.get("x-request-id"), request_random);
            let body = reply::method_error(
                &state.encode(),
                "accountNotFound",
                400,
                "accountId does not match authenticated user",
                client_id,
            );
            return Ok(reply::response(body, ctx.identity.proto, request_id));
        }

        // All randomness is drawn before anything runs, so an unreadable
        // RNG forwards the untouched request instead of failing mid-way.
        let (Some(operation), Some(request_random)) = (random(), random()) else {
            return Err("rng unavailable");
        };
        let request_id = reply::request_id(parts.headers.get("x-request-id"), request_random);

        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(identity.user_id()).map_err(|_| "ids")?,
            MailboxId::new(mailbox).map_err(|_| "ids")?,
            REQUEST_AUTHORITY_GENERATION,
        );
        let seen = match claimed {
            Claimed::Identity(request) => {
                let services = self.services.as_ref().ok_or("JMAP services")?;
                let body = identity::response(
                    &self.exec,
                    &services.worker,
                    &auth,
                    &state.encode(),
                    &request,
                )
                .await
                .ok_or("identity response")?;
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Blob(request) => {
                let services = self
                    .services
                    .as_ref()
                    .ok_or("JMAP worker credential unavailable")?;
                let body = blob::response(&services.worker, &auth, &state.encode(), &request)
                    .await
                    .ok_or("blob JSON")?;
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Echo(request) => {
                let body = reply::method_response(
                    &state.encode(),
                    "Core/echo",
                    &request.raw_args,
                    &request.client_id,
                )
                .ok_or("echo JSON")?;
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::MailboxSet(request) => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: Digest(Sha256::digest(bytes).into()),
                    command: (),
                };
                let outcome = if request.method == "Identity/set" {
                    setjoin_jmap::identity::set(
                        &self.exec,
                        &auth,
                        &envelope,
                        &request.create,
                        &request.update,
                        &request.destroy,
                    )
                    .await
                } else {
                    setjoin_jmap::mailbox_set::set(
                        &self.exec,
                        &auth,
                        &envelope,
                        &request.create,
                        &request.update,
                        &request.destroy,
                    )
                    .await
                };
                let body = match outcome {
                    SetOutcome::Done(raw) => {
                        let result = set::add_not_destroyed(
                            &set::merged(&raw).ok_or("mailbox set object")?,
                            &request.bad,
                        )
                        .ok_or("mailbox destroy errors")?;
                        let mut body = reply::method_response(
                            &state.encode(),
                            request.method,
                            &result,
                            &request.client_id,
                        )
                        .ok_or("mailbox set reply")?;
                        // ExecuteBatch collects successful creations into the
                        // top-level RFC 8620 createdIds map, even for one call.
                        let value: serde_json::Value =
                            serde_json::from_str(&result).map_err(|_| "mailbox set result")?;
                        if let Some(created) =
                            value.get("created").and_then(serde_json::Value::as_object)
                        {
                            let ids: serde_json::Map<String, serde_json::Value> = created
                                .iter()
                                .filter_map(|(key, value)| {
                                    value
                                        .get("id")
                                        .and_then(serde_json::Value::as_str)
                                        .map(|id| {
                                            (key.clone(), serde_json::Value::String(id.to_owned()))
                                        })
                                })
                                .collect();
                            if !ids.is_empty() {
                                body.truncate(body.len() - 2);
                                body.push_str(",\"createdIds\":");
                                body.push_str(
                                    &reply::go_compact(&serde_json::Value::Object(ids).to_string())
                                        .ok_or("created IDs")?,
                                );
                                body.push_str("}\n");
                            }
                        }
                        body
                    }
                    SetOutcome::Failed(f) => {
                        reply::failure_error(&state.encode(), f, &request.client_id)
                            .ok_or("mailbox set failed")?
                    }
                    SetOutcome::Forward => reply::method_error(
                        &state.encode(),
                        "serverFail",
                        500,
                        "database error",
                        &request.client_id,
                    ),
                    SetOutcome::Unknown { operation } => reply::method_error(
                        &state.encode(),
                        "serverFail",
                        500,
                        &format!(
                            "commit outcome unknown; look up operation {}",
                            reply::hex(&operation.0)
                        ),
                        &request.client_id,
                    ),
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Other(request) => {
                if request.too_many {
                    return Ok(reply::response(
                        reply::method_error(
                            &state.encode(),
                            "requestTooLarge",
                            400,
                            "too many ids requested",
                            &request.client_id,
                        ),
                        ctx.identity.proto,
                        request_id,
                    ));
                }
                if request
                    .read
                    .since_state()
                    .is_some_and(|s| !changes::since_state_is_well_formed(s))
                {
                    return Ok(reply::response(
                        reply::method_error(
                            &state.encode(),
                            "cannotCalculateChanges",
                            400,
                            "client must resync (malformed sinceState)",
                            &request.client_id,
                        ),
                        ctx.identity.proto,
                        request_id,
                    ));
                }
                let raw = setjoin_jmap::mailbox::read(&self.exec, &auth, &request.read).await;
                let body = match raw {
                    Ok(raw) => reply::method_response(
                        &state.encode(),
                        request.method,
                        &get::add_not_found(&raw, &request.bad).ok_or("mailbox get result")?,
                        &request.client_id,
                    )
                    .ok_or("mailbox reply")?,
                    // Go's shared reducer projection passes BZ040's public
                    // validation message through as invalidArguments.
                    Err(e) if e.sqlstate.as_deref() == Some("BZ040") => reply::method_error(
                        &state.encode(),
                        "invalidArguments",
                        400,
                        &e.message,
                        &request.client_id,
                    ),
                    Err(e) => reply::failure_error(
                        &state.encode(),
                        match setjoin_jmap::classify_failure(&e) {
                            setjoin_jmap::Failure::Forward => setjoin_jmap::Failure::ServerFail,
                            f => f,
                        },
                        &request.client_id,
                    )
                    .ok_or("mailbox read")?,
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Seen(seen) => seen,
            Claimed::Submission(request) => {
                if tokio::time::timeout(
                    setjoin_authz::precheck_timeout(),
                    request.needs_preprocessing(&self.exec, &auth),
                )
                .await
                .map_err(|_| "MIME preprocessing lookup timed out (#328)")?
                .map_err(|_| "MIME preprocessing lookup failed (#328)")?
                {
                    return Err("unported MIME preprocessing (#328)");
                }
                let body = submission::response(
                    &self.exec,
                    &auth,
                    self.worker.as_ref().unwrap_or(&self.exec),
                    request,
                    &state.encode(),
                    operation,
                    Sha256::digest(bytes).into(),
                )
                .await;
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Changes(request) => {
                let session = state.encode();
                let body = if !changes::since_state_is_well_formed(&request.since_state) {
                    reply::method_error(
                        &session,
                        "cannotCalculateChanges",
                        400,
                        "client must resync (malformed sinceState)",
                        &request.client_id,
                    )
                } else {
                    match email_changes(
                        &self.exec,
                        &auth,
                        &request.since_state,
                        request.max_changes,
                    )
                    .await
                    {
                        Ok(raw) => reply::method_response(
                            &session,
                            "Email/changes",
                            &raw,
                            &request.client_id,
                        )
                        .ok_or("changes reply not JSON")?,
                        Err(ChangesError::CannotCalculateChanges) => reply::method_error(
                            &session,
                            "cannotCalculateChanges",
                            400,
                            "client must resync (sinceState too old)",
                            &request.client_id,
                        ),
                        Err(ChangesError::AccountNotFound) => reply::method_error(
                            &session,
                            "accountNotFound",
                            400,
                            "accountId does not match an existing account",
                            &request.client_id,
                        ),
                        Err(ChangesError::Other) => return Err("changes read failed"),
                    }
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Set(request) => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: Digest(Sha256::digest(bytes).into()),
                    command: EmailSet,
                };
                let patches;
                let phase = match &request.phase {
                    set::Phase::Update(json) => {
                        patches = json.as_str();
                        SetPhase::Update(patches)
                    }
                    set::Phase::Destroy { ids, .. } => SetPhase::Destroy(ids),
                };
                let outcome = email_set(
                    &self.exec,
                    &envelope,
                    &auth,
                    Instant::now() + COMMAND_DEADLINE,
                    phase,
                )
                .await;
                let session = state.encode();
                let body = match outcome {
                    SetOutcome::Done(raw) => {
                        let merged = set::merged(&raw).ok_or("set reply not JSON")?;
                        let result = match &request.phase {
                            set::Phase::Destroy { bad, .. } => {
                                set::add_not_destroyed(&merged, bad).ok_or("set reply not JSON")?
                            }
                            set::Phase::Update(_) => merged,
                        };
                        reply::method_response(&session, "Email/set", &result, &request.client_id)
                            .ok_or("set reply not JSON")?
                    }
                    SetOutcome::Failed(failure) => {
                        reply::failure_error(&session, failure, &request.client_id)
                            .ok_or("email set failed")?
                    }
                    SetOutcome::Forward => return Err("email set rolled back"),
                    SetOutcome::Unknown { operation } => reply::method_error(
                        &session,
                        "serverFail",
                        500,
                        &format!(
                            "commit outcome unknown; look up operation {}",
                            reply::hex(&operation.0)
                        ),
                        &request.client_id,
                    ),
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Batch(request) => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: Digest(Sha256::digest(bytes).into()),
                    command: EmailBatch,
                };
                let outcome = email_batch(
                    &self.exec,
                    &envelope,
                    &auth,
                    Instant::now() + COMMAND_DEADLINE,
                    request.op,
                    &request.ids,
                )
                .await;
                let session = state.encode();
                let body = match outcome {
                    SetOutcome::Done(raw) => {
                        let result = request.result(&raw).ok_or("batch reply not JSON")?;
                        reply::method_response(
                            &session,
                            request.method(),
                            &result,
                            &request.client_id,
                        )
                        .ok_or("batch reply not JSON")?
                    }
                    SetOutcome::Failed(failure) => {
                        reply::failure_error(&session, failure, &request.client_id)
                            .ok_or("email batch failed")?
                    }
                    SetOutcome::Forward => return Err("email batch rolled back"),
                    SetOutcome::Unknown { operation } => reply::method_error(
                        &session,
                        "serverFail",
                        500,
                        &format!(
                            "commit outcome unknown; look up operation {}",
                            reply::hex(&operation.0)
                        ),
                        &request.client_id,
                    ),
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Receipt(request) => {
                let enabled = gates::toggle_state(&self.exec, batch::RECEIPTS_FLAG)
                    .await
                    .ok_or("toggle unreadable")?;
                if enabled {
                    return Err("client recovery receipts are Go's while enabled");
                }
                let body = reply::method_error(
                    &state.encode(),
                    "forbidden",
                    500,
                    "client recovery receipts are disabled",
                    &request.client_id,
                );
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Dismiss(request) => {
                let session = state.encode();
                let enabled = gates::toggle_state(&self.exec, gates::NUDGES_FLAG)
                    .await
                    .ok_or("toggle unreadable")?;
                let body = if !enabled {
                    reply::method_response(
                        &session,
                        "Email/nudgeDismiss",
                        &request.off(),
                        &request.client_id,
                    )
                    .ok_or("dismiss reply")?
                } else {
                    let envelope = CommandEnvelope {
                        operation: OperationId(operation),
                        authority: auth.authority(),
                        binding: setjoin_db::lifecycle::accepted_contract(),
                        payload_digest: Digest(Sha256::digest(bytes).into()),
                        command: EmailBatch,
                    };
                    match nudge_dismiss(
                        &self.exec,
                        &envelope,
                        &auth,
                        Instant::now() + COMMAND_DEADLINE,
                        &request.thread_id,
                    )
                    .await
                    {
                        SetOutcome::Done(raw) => {
                            let result = request.result(&raw).ok_or("dismiss reply not JSON")?;
                            reply::method_response(
                                &session,
                                "Email/nudgeDismiss",
                                &result,
                                &request.client_id,
                            )
                            .ok_or("dismiss reply not JSON")?
                        }
                        SetOutcome::Failed(failure) => {
                            reply::failure_error(&session, failure, &request.client_id)
                                .ok_or("dismiss failed")?
                        }
                        SetOutcome::Forward => return Err("dismiss rolled back"),
                        SetOutcome::Unknown { operation } => reply::method_error(
                            &session,
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                reply::hex(&operation.0)
                            ),
                            &request.client_id,
                        ),
                    }
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Paged(request) => {
                let session = state.encode();
                if request.which == Paged::Nudges {
                    let enabled = gates::toggle_state(&self.exec, gates::NUDGES_FLAG)
                        .await
                        .ok_or("toggle unreadable")?;
                    if !enabled {
                        let body = reply::method_response(
                            &session,
                            "Email/nudges",
                            &request.nudges_off(),
                            &request.client_id,
                        )
                        .ok_or("nudges reply")?;
                        return Ok(reply::response(body, ctx.identity.proto, request_id));
                    }
                }
                let body = match read_paged(
                    &self.exec,
                    &auth,
                    request.which,
                    request.limit,
                    request.position,
                )
                .await
                {
                    Ok(raw) => {
                        let result = request.result(&raw).ok_or("paged reply not JSON")?;
                        reply::method_response(
                            &session,
                            request.method(),
                            &result,
                            &request.client_id,
                        )
                        .ok_or("paged reply not JSON")?
                    }
                    Err(failure) => reply::failure_error(
                        &session,
                        setjoin_jmap::classify_failure(&failure),
                        &request.client_id,
                    )
                    .ok_or("paged read failed")?,
                };
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Query(request) => {
                let raw = query_email(
                    &self.exec,
                    &auth,
                    request.filter.as_deref(),
                    request.sort.as_deref(),
                    request.position,
                    request.limit,
                )
                .await;
                let raw = match raw {
                    Ok(raw) => raw,
                    Err(failure) => {
                        let body = reply::failure_error(
                            &state.encode(),
                            setjoin_jmap::classify_failure(&failure),
                            &request.client_id,
                        )
                        .ok_or("email query read failed")?;
                        return Ok(reply::response(body, ctx.identity.proto, request_id));
                    }
                };
                let body = reply::method_response(
                    &state.encode(),
                    "Email/query",
                    &raw,
                    &request.client_id,
                )
                .ok_or("query reply not JSON")?;
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::Get(request) => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: Digest(Sha256::digest(bytes).into()),
                    command: EmailGet,
                };
                let ids = (!request.ids.is_empty() || !request.bad.is_empty())
                    .then_some(request.ids.as_slice());
                let outcome = email_get(
                    &self.exec,
                    &envelope,
                    &auth,
                    Instant::now() + COMMAND_DEADLINE,
                    ids,
                    request.properties.as_deref(),
                )
                .await;
                let raw = match outcome {
                    GetOutcome::Served(raw) => raw,
                    GetOutcome::Failed(failure) => {
                        let body =
                            reply::failure_error(&state.encode(), failure, &request.client_id)
                                .ok_or("email get failed")?;
                        return Ok(reply::response(body, ctx.identity.proto, request_id));
                    }
                    GetOutcome::Encrypted => return Err("encrypted mail: Go decrypts on read"),
                    GetOutcome::Forward => return Err("email get not served"),
                };
                let result = get::add_not_found(&raw, &request.bad).ok_or("get reply not JSON")?;
                let body = reply::method_response(
                    &state.encode(),
                    "Email/get",
                    &result,
                    &request.client_id,
                )
                .ok_or("get reply not JSON")?;
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
            Claimed::List(list) => {
                // A read: nothing to commit, so any failure forwards the
                // whole request to Go, which answers it as today.
                let page = query_email_list(&self.exec, &auth, &list.query)
                    .await
                    .map_err(|_| "inbox list read failed")?;
                if log_served() {
                    eprintln!(
                        "setjoin-gateway: inbox list served by Rust mailbox={mailbox} tag={} position={} ids={}",
                        list.query.tag,
                        list.query.position,
                        page.ids.len()
                    );
                }
                let body = list::body(
                    &state.encode(),
                    mailbox,
                    list.query.position,
                    &list.client_id,
                    &page,
                );
                return Ok(reply::response(body, ctx.identity.proto, request_id));
            }
        };
        let mailbox_id = MailboxId::new(mailbox).map_err(|_| "ids")?;
        let message_id = MessageId::new(seen.message_id).map_err(|_| "ids")?;
        let digest = Digest(Sha256::digest(bytes).into());
        let deadline = Instant::now() + COMMAND_DEADLINE;
        let reply = match seen.seen {
            seen::SeenValue::Flag(value) => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: SetMessageSeen {
                        mailbox: mailbox_id,
                        message: message_id,
                        seen: value,
                    },
                };
                set_message_seen(&self.exec, &envelope, &auth, deadline).await
            }
            seen::SeenValue::EmptyString => {
                let envelope = CommandEnvelope {
                    operation: OperationId(operation),
                    authority: auth.authority(),
                    binding: setjoin_db::lifecycle::accepted_contract(),
                    payload_digest: digest,
                    command: EmptySeen {
                        mailbox: mailbox_id,
                        message: message_id,
                    },
                };
                set_message_seen_empty(&self.exec, &envelope, &auth, deadline).await
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
            // The reducer's per-item error, committed as Go commits it and
            // answered as Go's per-item `notUpdated` entry.
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
            // Pending is never a terminal answer of the executor; treat it
            // like Unknown: not success, look the operation up.
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
        let body = reply::body(
            &state.encode(),
            mailbox,
            seen.message_id,
            &seen.client_id,
            outcome,
        );
        Ok(reply::response(body, ctx.identity.proto, request_id))
    }
}

/// Reads at most [`BODY_CAP`] bytes; past that (or on trailers or a broken
/// body) the bytes read so far and the rest of the stream are handed back
/// unchanged for forwarding.
async fn buffer(mut body: Body) -> Buffered {
    let mut buf = BytesMut::new();
    loop {
        match body.frame().await {
            None => return Buffered::Whole(buf.freeze()),
            Some(Err(e)) => return Buffered::Forward(Prefixed::boxed(buf.freeze(), None, Some(e))),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    buf.extend_from_slice(&data);
                    if buf.len() > BODY_CAP {
                        return Buffered::Forward(Prefixed::boxed(buf.freeze(), Some(body), None));
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
