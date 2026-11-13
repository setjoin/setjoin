//! Qualified recovery adapters. F16 defaults ON; unmet whole-request
//! preconditions and the gateway kill switch preserve Go fallback.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use serde::Deserialize;
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use sha2::{Digest as _, Sha256};

use crate::routes::{BoxFuture, Intercept, RequestContext};
use crate::Body;

const FEATURE: &str = "feature.client_recovery_ingest";

/// Dependencies of the staged read. `control_plane_ready` is true only when
/// the caller has established Go's storage, continuity and flag prerequisites.
pub struct RecoveryCommands<K: KeySource> {
    pub exec: ScopedExecutor,
    /// The reducer is executable by the worker credential, not the app pool.
    pub worker_exec: ScopedExecutor,
    pub keys: K,
    pub issuer: String,
    pub denylist: Option<Arc<crate::workers::SessionDenylist>>,
    pub control_plane_ready: bool,
    /// Required before claiming a staged abort. No mutation can fall back to Go.
    pub store: Option<Arc<dyn crate::recovery_worker::ObjectStore>>,
}

pub struct RecoveryRoute<K: KeySource + 'static>(pub Arc<RecoveryCommands<K>>);

impl<K: KeySource + 'static> Intercept for RecoveryRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, req: &Request<Body>) -> bool {
        (matches!(*req.method(), Method::GET | Method::HEAD)
            && req.uri().path() == "/api/recovery/incidents")
            || (req.method() == Method::DELETE && abort_target(req.uri().path()).is_some())
            || (req.method() == Method::POST && fork_target(req.uri().path()).is_some())
            || (req.method() == Method::POST && commit_target(req.uri().path()).is_some())
            || (req.method() == Method::PUT && chunk_target(req.uri().path()).is_some())
    }

    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let commands = self.0.clone();
        Box::pin(async move { commands.authorize(&headers, scheme).await.is_some() })
    }

    fn handle(&self, mut req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        Box::pin(async move {
            if let Some(response) = commands.try_serve(&mut req, &ctx).await {
                return response;
            }
            ctx.upstream.forward(req, &ctx.identity).await
        })
    }
}

impl<K: KeySource> RecoveryCommands<K> {
    pub(crate) async fn authorize(
        &self,
        headers: &hyper::HeaderMap,
        scheme: &str,
    ) -> Option<setjoin_authz::Authorized> {
        if !self.control_plane_ready {
            return None;
        }
        let authorized = setjoin_authz::authorize(
            &self.exec,
            &self.keys,
            &self.issuer,
            headers,
            scheme,
            FEATURE,
        )
        .await?;
        let identity = authorized.context();
        if let Some(denylist) = &self.denylist {
            let issued = chrono::DateTime::from_timestamp(authorized.issued_at(), 0)?;
            if !denylist.loaded()
                || denylist.is_revoked(
                    identity.user_id(),
                    authorized.token_id(),
                    authorized.token_family(),
                    issued,
                )
            {
                return None;
            }
        }
        Some(authorized)
    }

    async fn try_commit(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
        actor: &setjoin_authz::AuthContext,
    ) -> Option<Response<Body>> {
        use tokio::io::AsyncWriteExt;
        let store = self.store.as_ref()?;
        let operation = crate::jmap::random()?;
        let request_id =
            crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
        let (raw_session, raw_item) = commit_target(req.uri().path())?;
        let Some(session) = decoded_uuid(raw_session) else {
            return Some(problem(
                400,
                "invalid recovery identifier",
                ctx.identity.proto,
                request_id,
            ));
        };
        let item = String::from_utf8(crate::inventory::unescape(raw_item)).unwrap_or_default();
        let failed = || {
            problem(
                400,
                "mail recovery operation failed",
                ctx.identity.proto,
                request_id.clone(),
            )
        };
        if item.is_empty() || item.len() > 256 || item.contains(['/', '\0', '\r', '\n']) {
            return Some(failed());
        }
        let Ok(Some(meta)) =
            setjoin_blobs::item_for_commit(&self.worker_exec, actor, &session, &item).await
        else {
            return Some(failed());
        };
        if meta.status == "verified" {
            let value = serde_json::json!({"itemId":item,"status":"verified","objectRef":meta.object_ref,"replayed":true});
            return Some(crate::jmap::reply::response(
                go_json(&value),
                ctx.identity.proto,
                request_id,
            ));
        }
        let Ok(chunks) =
            setjoin_blobs::item_chunks(&self.worker_exec, actor, &session, &item).await
        else {
            return Some(failed());
        };
        let path = std::env::temp_dir().join(format!(
            "setjoin-recovery-item-{}",
            crate::jmap::reply::hex(&operation)
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let Ok(mut file) = options.open(&path).await else {
            return Some(failed());
        };
        let temporary = OwnedTemporary(path);
        let mut full = Sha256::new();
        let mut offset = 0i64;
        for chunk in &chunks {
            if chunk.start != offset || chunk.size <= 0 || chunk.size > 256 << 10 {
                return Some(failed());
            }
            let Ok(bytes) = store.read(&chunk.key, chunk.size as usize + 1).await else {
                return Some(failed());
            };
            if bytes.len() != chunk.size as usize
                || format!("{:x}", Sha256::digest(&bytes)) != chunk.digest
            {
                return Some(failed());
            }
            if file.write_all(&bytes).await.is_err() {
                return Some(failed());
            }
            full.update(&bytes);
            offset += i64::from(chunk.size);
        }
        if offset != meta.size || format!("{:x}", full.finalize()) != meta.digest {
            return Some(failed());
        }
        if file.flush().await.is_err() {
            return Some(failed());
        }
        let content_type = if meta.role == "raw" {
            "message/rfc822"
        } else {
            "application/octet-stream"
        };
        if store
            .put_file(&meta.digest, &temporary.0, meta.size as u64, content_type)
            .await
            .is_err()
        {
            return Some(failed());
        }
        Some(
            match setjoin_blobs::verify_item(
                &self.worker_exec,
                actor,
                &session,
                &item,
                &meta.digest,
                operation,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => {
                    for chunk in chunks {
                        if store.remove(&chunk.key).await.is_err() {
                            eprintln!("verified recovery chunk cleanup deferred");
                        }
                    }
                    match serde_json::from_str::<serde_json::Value>(&raw) {
                        Ok(mut value) => {
                            value["objectRef"] = meta.digest.into();
                            crate::jmap::reply::response(
                                go_json(&value),
                                ctx.identity.proto,
                                request_id,
                            )
                        }
                        Err(_) => failed(),
                    }
                }
                setjoin_pg::CommandOutcome::RolledBack(rejection) => {
                    eprintln!(
                        "recovery item verification rejected: {}",
                        rejection.log_summary()
                    );
                    rejection_response(
                        &rejection,
                        req,
                        ctx,
                        request_id,
                        "mail recovery operation failed",
                        400,
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut response = problem(
                        503,
                        "recovery upload outcome unknown",
                        ctx.identity.proto,
                        request_id,
                    );
                    response.headers_mut().insert(
                        "x-operation-id",
                        setjoin_pg::operation_hex(operation)
                            .parse()
                            .expect("operation hex"),
                    );
                    response
                }
            },
        )
    }

    async fn try_chunk(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
        actor: &setjoin_authz::AuthContext,
    ) -> Option<Response<Body>> {
        let store = self.store.as_ref()?;
        let operation = crate::jmap::random()?;
        let request_id =
            crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
        let (raw_session, raw_item) = chunk_target(req.uri().path())?;
        let Some(session) = decoded_uuid(raw_session) else {
            return Some(problem(
                400,
                "invalid recovery identifier",
                ctx.identity.proto,
                request_id,
            ));
        };
        let item = String::from_utf8(crate::inventory::unescape(raw_item)).unwrap_or_default();
        let failed = || {
            problem(
                400,
                "mail recovery operation failed",
                ctx.identity.proto,
                request_id.clone(),
            )
        };
        if item.is_empty() || item.len() > 256 || item.contains(['/', '\0', '\r', '\n']) {
            return Some(failed());
        }
        let Some(range) = req
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(setjoin_blobs::parse_chunk_range)
            .filter(|range| range.fits_chunk_limit())
        else {
            return Some(failed());
        };
        let mut bytes = Vec::new();
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(frame) = frame else {
                return Some(failed());
            };
            if let Some(data) = frame.data_ref() {
                if bytes.len() + data.len() > 256 << 10 {
                    return Some(failed());
                }
                bytes.extend_from_slice(data);
            }
        }
        if bytes.len() as i64 != range.end - range.start + 1 {
            return Some(failed());
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let Ok(Some(upload)) =
            setjoin_blobs::upload_item(&self.worker_exec, actor, &session, &item).await
        else {
            return Some(failed());
        };
        if range.total != upload.size || !upload.available {
            return Some(failed());
        }
        match setjoin_blobs::chunk_at(&self.worker_exec, actor, &session, &item, range.start).await
        {
            Ok(Some(existing)) => {
                return Some(
                    if existing.size as usize == bytes.len() && existing.digest == digest {
                        empty_204(ctx, request_id)
                    } else {
                        failed()
                    },
                )
            }
            Err(_) => return Some(failed()),
            Ok(None) => {}
        }
        if range.start != upload.next_offset {
            return Some(failed());
        }
        let key = format!(
            "recovery-quarantine/{}/{session}/{:x}/{}-{digest}",
            upload.incident,
            Sha256::digest(item.as_bytes()),
            range.start
        );
        if store
            .put(&key, &bytes, "application/octet-stream")
            .await
            .is_err()
        {
            return Some(failed());
        }
        // From the first storage write onward no outcome can forward to Go.
        let record = setjoin_blobs::ChunkRecord {
            session: &session,
            item: &item,
            start: range.start,
            size: bytes.len() as i32,
            digest: &digest,
            key: &key,
        };
        Some(
            match setjoin_blobs::record_chunk(&self.worker_exec, actor, record, operation).await {
                setjoin_pg::CommandOutcome::Committed(_) => empty_204(ctx, request_id),
                setjoin_pg::CommandOutcome::RolledBack(rejection) => {
                    // Go keeps the content-addressed object if any raced row exists;
                    // failed probes also retain it. Delete only a proven orphan.
                    if matches!(
                        setjoin_blobs::chunk_at(
                            &self.worker_exec,
                            actor,
                            &session,
                            &item,
                            range.start
                        )
                        .await,
                        Ok(None)
                    ) {
                        let _ = store.remove(&key).await;
                    }
                    eprintln!(
                        "recovery chunk record rejected: {}",
                        rejection.log_summary()
                    );
                    rejection_response(
                        &rejection,
                        req,
                        ctx,
                        request_id,
                        "mail recovery operation failed",
                        400,
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut response = problem(
                        503,
                        "recovery upload outcome unknown",
                        ctx.identity.proto,
                        request_id,
                    );
                    response.headers_mut().insert(
                        "x-operation-id",
                        setjoin_pg::operation_hex(operation)
                            .parse()
                            .expect("operation hex"),
                    );
                    response
                }
            },
        )
    }

    async fn try_serve(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
    ) -> Option<Response<Body>> {
        let authorized = self.authorize(req.headers(), ctx.identity.proto).await?;
        let identity = authorized.context();
        if req.method() == Method::POST && commit_target(req.uri().path()).is_some() {
            return self.try_commit(req, ctx, identity).await;
        }
        if req.method() == Method::PUT {
            return self.try_chunk(req, ctx, identity).await;
        }
        if req.method() == Method::POST {
            self.store.as_ref()?;
            let operation = crate::jmap::random()?;
            let request_id =
                crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
            let Some(artifact) = setjoin_blobs::recovery_uuid(fork_target(req.uri().path())?)
            else {
                return Some(problem(
                    400,
                    "invalid recovery identifier",
                    ctx.identity.proto,
                    request_id,
                ));
            };
            let mut bytes = Vec::new();
            let mut oversized = false;
            while let Some(frame) = req.body_mut().frame().await {
                let Ok(frame) = frame else {
                    return Some(problem(
                        400,
                        "invalid recovery request",
                        ctx.identity.proto,
                        request_id,
                    ));
                };
                if let Some(data) = frame.data_ref() {
                    let remaining = (1 << 20usize) - bytes.len();
                    bytes.extend_from_slice(&data[..data.len().min(remaining)]);
                    if data.len() > remaining {
                        oversized = true;
                        break;
                    }
                }
            }
            let mut decoder = serde_json::Deserializer::from_slice(&bytes);
            let Ok(value) = ForkRequest::deserialize(&mut decoder) else {
                return Some(problem(
                    400,
                    "invalid recovery request",
                    ctx.identity.proto,
                    request_id,
                ));
            };
            if oversized || decoder.end().is_err() {
                return Some(problem(
                    400,
                    "recovery request must contain exactly one JSON object",
                    ctx.identity.proto,
                    request_id,
                ));
            }
            let Some(device) = setjoin_blobs::recovery_uuid(&value.device_id) else {
                return Some(problem(
                    400,
                    "invalid recovery device id",
                    ctx.identity.proto,
                    request_id,
                ));
            };
            return Some(
                match setjoin_blobs::fork_consent(
                    &self.worker_exec,
                    identity,
                    &artifact,
                    &device,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(json) => {
                        crate::jmap::reply::response(json, ctx.identity.proto, request_id)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(rejection) => {
                        eprintln!(
                            "recovery fork consent rejected: {}",
                            rejection.log_summary()
                        );
                        rejection_response(
                            &rejection,
                            req,
                            ctx,
                            request_id,
                            "recovery control operation failed",
                            500,
                        )
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        let mut response = problem(
                            503,
                            "recovery upload outcome unknown",
                            ctx.identity.proto,
                            request_id,
                        );
                        response.headers_mut().insert(
                            "x-operation-id",
                            setjoin_pg::operation_hex(operation)
                                .parse()
                                .expect("operation hex"),
                        );
                        response
                    }
                },
            );
        }
        if req.method() == Method::DELETE {
            let store = self.store.as_ref()?;
            // All fallible prerequisites finish before issuing the command.
            let operation = crate::jmap::random()?;
            let request_id =
                crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
            let Some(session) = setjoin_blobs::recovery_uuid(abort_target(req.uri().path())?)
            else {
                return Some(problem(
                    400,
                    "invalid recovery identifier",
                    ctx.identity.proto,
                    request_id,
                ));
            };
            let result =
                setjoin_blobs::abort_upload(&self.worker_exec, identity, &session, operation).await;
            return Some(match result {
                setjoin_pg::CommandOutcome::Committed(keys) => {
                    for key in keys {
                        if store.remove(&key).await.is_err() {
                            eprintln!("aborted recovery chunk cleanup deferred");
                        }
                    }
                    let mut response =
                        crate::jmap::reply::response(String::new(), ctx.identity.proto, request_id);
                    *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                    response.headers_mut().remove("content-type");
                    response
                }
                setjoin_pg::CommandOutcome::RolledBack(rejection) => {
                    eprintln!("recovery abort rejected: {}", rejection.log_summary());
                    rejection_response(
                        &rejection,
                        req,
                        ctx,
                        request_id,
                        "recovery upload abort failed",
                        500,
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut response = problem(
                        503,
                        "recovery upload outcome unknown",
                        ctx.identity.proto,
                        request_id,
                    );
                    response.headers_mut().insert(
                        "x-operation-id",
                        setjoin_pg::operation_hex(operation)
                            .parse()
                            .expect("operation hex"),
                    );
                    response
                }
            });
        }
        let json = setjoin_blobs::user_incidents(&self.worker_exec, identity)
            .await
            .ok()?;
        let request_id = crate::jmap::reply::request_id(
            req.headers().get("x-request-id"),
            crate::jmap::random()?,
        );
        Some(crate::jmap::reply::response(
            json,
            ctx.identity.proto,
            request_id,
        ))
    }
}

fn abort_target(path: &str) -> Option<&str> {
    path.strip_prefix("/api/recovery/uploads/")
        .filter(|target| !target.is_empty() && !target.contains('/'))
}

fn fork_target(path: &str) -> Option<&str> {
    path.strip_prefix("/api/recovery/artifacts/")?
        .strip_suffix("/fork-consent")
        .filter(|target| !target.is_empty() && !target.contains('/'))
}

pub(crate) fn problem(
    status: u16,
    detail: &str,
    scheme: &str,
    request_id: String,
) -> Response<Body> {
    let status = hyper::StatusCode::from_u16(status).expect("fixed problem status");
    let title = crate::problem::title(status.as_u16());
    problem_body(status,format!("{{\"type\":\"about:blank\",\"title\":\"{title}\",\"status\":{},\"detail\":{},\"instance\":\"\"}}\n",status.as_u16(),serde_json::to_string(detail).expect("problem detail")),scheme,request_id)
}

fn problem_body(
    status: hyper::StatusCode,
    body: String,
    scheme: &str,
    request_id: String,
) -> Response<Body> {
    let mut response = crate::jmap::reply::response(body, scheme, request_id);
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    response
}

pub(crate) fn rejection_response(
    rejection: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    req: &Request<Body>,
    ctx: &RequestContext,
    request_id: String,
    fallback: &str,
    fallback_status: u16,
) -> Response<Body> {
    let state = match rejection {
        setjoin_pg::Rejection::Statement(error) | setjoin_pg::Rejection::Body(error) => {
            error.sqlstate.as_deref()
        }
        _ => None,
    };
    let (code, detail, status, remediation) = match state {
        Some("BZ002") => (
            "BZ002",
            "access denied",
            403,
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        // Go's shared classifier preserves this historic send-address wording
        // even for a recovery fork authorization error.
        Some("BZ003") => (
            "BZ003",
            "not authorized to send from this address",
            403,
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        Some("BZ251") => (
            "BZ251",
            "invalidArguments",
            400,
            "Correct the request fields and retry.",
        ),
        _ => return problem(fallback_status, fallback, ctx.identity.proto, request_id),
    };
    let instance = req
        .uri()
        .path()
        .strip_prefix("/api")
        .unwrap_or(req.uri().path());
    let status = hyper::StatusCode::from_u16(status).expect("classified status");
    let title = crate::problem::title(status.as_u16());
    let body=format!("{{\"type\":\"https://setjoin.com/problems/reducer/{}\",\"title\":\"{title}\",\"status\":{},\"detail\":{},\"instance\":{},\"remediation\":{},\"code\":\"{code}\",\"retryable\":false}}\n",code.to_ascii_lowercase(),status.as_u16(),serde_json::to_string(detail).expect("fixed detail"),serde_json::to_string(instance).expect("path string"),serde_json::to_string(remediation).expect("fixed remediation"));
    let mut response = problem_body(status, body, ctx.identity.proto, request_id);
    response.headers_mut().insert(
        "content-language",
        hyper::header::HeaderValue::from_static("en"),
    );
    response
}

#[derive(Default)]
struct ForkRequest {
    device_id: String,
}

// encoding/json matches field names without ASCII case and processes duplicate
// fields in wire order. JSON null leaves an existing string unchanged.
impl<'de> Deserialize<'de> for ForkRequest {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = ForkRequest;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a recovery fork request")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ForkRequest::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Self::Value, M::Error> {
                let mut result = ForkRequest::default();
                while let Some(name) = fields.next_key::<String>()? {
                    if !name.eq_ignore_ascii_case("deviceId") {
                        return Err(serde::de::Error::unknown_field(&name, &["deviceId"]));
                    }
                    if let Some(value) = fields.next_value::<Option<String>>()? {
                        result.device_id = value;
                    }
                }
                Ok(result)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

fn chunk_target(path: &str) -> Option<(&str, &str)> {
    let (session, item) = path
        .strip_prefix("/api/recovery/uploads/")?
        .split_once("/items/")?;
    (!session.is_empty() && !session.contains('/') && !item.is_empty() && !item.contains('/'))
        .then_some((session, item))
}
fn decoded_uuid(raw: &str) -> Option<String> {
    setjoin_blobs::recovery_uuid(&String::from_utf8(crate::inventory::unescape(raw)).ok()?)
}
fn empty_204(ctx: &RequestContext, request_id: String) -> Response<Body> {
    let mut response = crate::jmap::reply::response(String::new(), ctx.identity.proto, request_id);
    *response.status_mut() = hyper::StatusCode::NO_CONTENT;
    response.headers_mut().remove("content-type");
    response
}

fn commit_target(path: &str) -> Option<(&str, &str)> {
    chunk_target(path.strip_suffix("/commit")?)
}
struct OwnedTemporary(std::path::PathBuf);
impl Drop for OwnedTemporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
pub(crate) fn go_json(value: &serde_json::Value) -> String {
    let value = serde_json::to_string(value).expect("JSON value");
    value
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        + "\n"
}
