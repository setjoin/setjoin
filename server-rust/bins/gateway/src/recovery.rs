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
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, req: &Request<Body>) -> bool {
        (matches!(*req.method(), Method::GET | Method::HEAD)
            && req.uri().path() == "/api/recovery/incidents")
            || (req.method() == Method::DELETE && abort_target(req.uri().path()).is_some())
            || (req.method() == Method::POST && fork_target(req.uri().path()).is_some())
            || (req.method() == Method::POST && commit_target(req.uri().path()).is_some())
            || (req.method() == Method::PUT && chunk_target(req.uri().path()).is_some())
    }

    fn admits_member(&self, headers: hyper::HeaderMap, _scheme: &'static str) -> BoxFuture<bool> {
        let commands = self.0.clone();
        Box::pin(async move {
            commands
                .admits_member(&headers, "GET", "/api/recovery")
                .await
        })
    }

    fn handle(&self, req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        Box::pin(async move { commands.try_serve(req, &ctx).await })
    }
}

impl<K: KeySource> RecoveryCommands<K> {
    pub(crate) async fn admits_member(
        &self,
        headers: &hyper::HeaderMap,
        method: &str,
        path: &str,
    ) -> bool {
        setjoin_authz::admit(
            &self.exec,
            &self.keys,
            &self.issuer,
            headers,
            method,
            path,
            setjoin_authz::Scope::Member,
        )
        .await
        .is_ok()
    }

    /// Auth -> Denylist -> Enabled(404) admission shared by recovery routes.
    /// `extra_ready` lets `GET /api/recovery/incidents` run with `store: None`
    /// while storage-backed endpoints require `store.is_some()` (and `BeginRoute`
    /// requires `keys.is_some()`).
    pub(crate) async fn admit_route(
        &self,
        req: Request<Body>,
        ctx: &RequestContext,
        extra_ready: bool,
    ) -> Result<(Request<Body>, setjoin_authz::Authorized), Response<Body>> {
        let authorized = match crate::deny::admit(
            &self.exec,
            &self.keys,
            &self.issuer,
            &req,
            crate::deny::Scope::Member,
        )
        .await
        {
            Ok(authorized) => authorized,
            Err(refusal) => return Err(crate::deny::answer(refusal, req, ctx).await),
        };
        if let Some(denylist) = &self.denylist {
            let identity = authorized.context();
            let issued = chrono::DateTime::from_timestamp(authorized.issued_at(), 0)
                .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
            if denylist.is_revoked(
                identity.user_id(),
                authorized.token_id(),
                authorized.token_family(),
                issued,
            ) {
                return Err(crate::admission::revoked_problem(
                    req.headers(),
                    &ctx.identity,
                    "Session has been revoked. Sign in again.",
                ));
            }
            if !denylist.loaded() {
                let cae = tokio::time::timeout(
                    setjoin_authz::precheck_timeout(),
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
        let feature_on = tokio::time::timeout(
            setjoin_authz::precheck_timeout(),
            setjoin_authz::gates::route_enabled(&self.exec, FEATURE),
        )
        .await
        .unwrap_or(false);
        if !self.control_plane_ready || !extra_ready || !feature_on {
            let request_id = crate::jmap::reply::request_id(
                req.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            return Err(problem(
                404,
                "client-assisted recovery is disabled",
                ctx.identity.proto,
                request_id,
            ));
        }
        Ok((req, authorized))
    }

    pub(crate) async fn worker_read_contract(
        &self,
        contract: &'static setjoin_pg::SqlContract,
        values: &[&(dyn setjoin_pg::ToSql + Sync)],
    ) -> Result<Vec<setjoin_pg::Row>, setjoin_pg::StatementFailure> {
        let wp =
            self.worker_exec
                .try_worker_pool()
                .ok_or_else(|| setjoin_pg::StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "worker pool unavailable".into(),
                })?;
        let mut tx = wp.begin_repeatable_read_only().await?;
        let rows = tx.query_contract(contract, values).await;
        let _ = tx.rollback().await;
        rows
    }

    pub(crate) fn tx_factory(&self) -> Option<setjoin_authz::principals::TxFactory> {
        crate::policy_composition::tx_factory_from_executors(&self.exec, Some(&self.worker_exec))
    }

    async fn try_commit(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
        factory: &setjoin_authz::principals::TxFactory,
        user: &setjoin_authz::principals::UserPrincipal,
    ) -> Response<Body> {
        use tokio::io::AsyncWriteExt;
        let Some(store) = self.store.as_ref() else {
            let id = crate::jmap::reply::request_id(
                req.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            return problem(
                404,
                "client-assisted recovery is disabled",
                ctx.identity.proto,
                id,
            );
        };
        let Some(operation) = crate::jmap::random() else {
            let id = crate::jmap::reply::request_id(req.headers().get("x-request-id"), [0; 16]);
            return problem(
                400,
                "mail recovery operation failed",
                ctx.identity.proto,
                id,
            );
        };
        let request_id =
            crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
        let Some((raw_session, raw_item)) = commit_target(req.uri().path()) else {
            return problem(404, "not found", ctx.identity.proto, request_id);
        };
        let Some(session) = decoded_uuid(raw_session) else {
            return problem(
                400,
                "invalid recovery identifier",
                ctx.identity.proto,
                request_id,
            );
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
            return failed();
        }
        let uid = user.user().get();
        let Ok(Some(meta)) = self
            .worker_read_contract(
                &setjoin_blobs::sql::ITEM_FOR_COMMIT,
                &[&session, &uid, &item],
            )
            .await
            .map(|rows| setjoin_blobs::decode_item_for_commit(&rows))
        else {
            return failed();
        };
        if meta.status == "verified" {
            let value = serde_json::json!({"itemId":item,"status":"verified","objectRef":meta.object_ref,"replayed":true});
            return crate::jmap::reply::response(go_json(&value), ctx.identity.proto, request_id);
        }
        let Ok(chunks) = self
            .worker_read_contract(&setjoin_blobs::sql::ITEM_CHUNKS, &[&session, &uid, &item])
            .await
            .map(|rows| setjoin_blobs::decode_item_chunks(&rows))
        else {
            return failed();
        };
        let path = std::env::temp_dir().join(format!(
            "setjoin-recovery-item-{}",
            crate::jmap::reply::hex(&operation)
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let Ok(mut file) = options.open(&path).await else {
            return failed();
        };
        let temporary = OwnedTemporary(path);
        let mut full = Sha256::new();
        let mut offset = 0i64;
        for chunk in &chunks {
            if chunk.start != offset || chunk.size <= 0 || chunk.size > 256 << 10 {
                return failed();
            }
            let Ok(bytes) = store.read(&chunk.key, chunk.size as usize + 1).await else {
                return failed();
            };
            if bytes.len() != chunk.size as usize
                || format!("{:x}", Sha256::digest(&bytes)) != chunk.digest
            {
                return failed();
            }
            if file.write_all(&bytes).await.is_err() {
                return failed();
            }
            full.update(&bytes);
            offset += i64::from(chunk.size);
        }
        if offset != meta.size || format!("{:x}", full.finalize()) != meta.digest {
            return failed();
        }
        if file.flush().await.is_err() {
            return failed();
        }
        let content_type = if meta.role == "raw" {
            "message/rfc822"
        } else {
            "application/octet-stream"
        };
        // Stage assembled bytes FIRST under tmp/blob-upload/*, then atomically
        // reactivate + enqueue delayed blob.promote_verify inside
        // blob_gc_reactivate_v2() if previously 'purging' (#551). Keep staging_key
        // through mail_recovery_upload_item_verify() as well so even a late purging
        // transition is fenced atomically.
        let staging_key = format!(
            "{}{}",
            crate::blob_retention::BLOB_STAGING_PREFIX,
            crate::jmap::reply::hex(&operation)
        );
        if store
            .put_file(&staging_key, &temporary.0, meta.size as u64, content_type)
            .await
            .is_err()
        {
            return failed();
        }
        let staging_opt = Some(staging_key.as_str());
        let Ok(react_rows) = self
            .worker_exec
            .protocol_query(
                "SELECT public.blob_gc_reactivate_v2($1, $2)::text",
                &[
                    (&meta.digest, setjoin_pg::Type::TEXT),
                    (&staging_opt, setjoin_pg::Type::TEXT),
                ],
            )
            .await
        else {
            // Leave staging_key intact on an ambiguous DB error so a committed
            // blob.promote_verify keeps its bytes; 24h sweep reaps if uncommitted.
            return failed();
        };
        let was_purging = react_rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|v| v.get("was_purging").and_then(serde_json::Value::as_bool))
            .unwrap_or(false);
        if store
            .put_file(&meta.digest, &temporary.0, meta.size as u64, content_type)
            .await
            .is_err()
        {
            if !was_purging {
                let _ = store
                    .delete_blob_checked(&staging_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                    .await;
            }
            return failed();
        }
        let verify_outcome = setjoin_blobs::verify_item(
            factory,
            user,
            &session,
            &item,
            &meta.digest,
            Some(&staging_key),
            operation,
        )
        .await;
        if !was_purging {
            let still_fenced = self
                .worker_exec
                .protocol_query(
                    "SELECT EXISTS ( \
                        SELECT 1 FROM public.work_items \
                         WHERE kind = $1 \
                           AND status IN ('pending', 'leased') \
                           AND payload->>'staging_key' = $2 \
                    )",
                    &[
                        (
                            &crate::blob_retention::WORK_KIND_PROMOTE_VERIFY,
                            setjoin_pg::Type::TEXT,
                        ),
                        (&staging_key, setjoin_pg::Type::TEXT),
                    ],
                )
                .await
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
                .unwrap_or(true);
            if !still_fenced {
                let _ = store
                    .delete_blob_checked(&staging_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                    .await;
            }
        }
        match verify_outcome {
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
        }
    }

    async fn try_chunk(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
        factory: &setjoin_authz::principals::TxFactory,
        user: &setjoin_authz::principals::UserPrincipal,
    ) -> Response<Body> {
        let Some(store) = self.store.as_ref() else {
            let id = crate::jmap::reply::request_id(
                req.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            return problem(
                404,
                "client-assisted recovery is disabled",
                ctx.identity.proto,
                id,
            );
        };
        let Some(operation) = crate::jmap::random() else {
            let id = crate::jmap::reply::request_id(req.headers().get("x-request-id"), [0; 16]);
            return problem(
                400,
                "mail recovery operation failed",
                ctx.identity.proto,
                id,
            );
        };
        let request_id =
            crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
        let Some((raw_session, raw_item)) = chunk_target(req.uri().path()) else {
            return problem(404, "not found", ctx.identity.proto, request_id);
        };
        let Some(session) = decoded_uuid(raw_session) else {
            return problem(
                400,
                "invalid recovery identifier",
                ctx.identity.proto,
                request_id,
            );
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
            return failed();
        }
        let Some(range) = req
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(setjoin_blobs::parse_chunk_range)
            .filter(|range| range.fits_chunk_limit())
        else {
            return failed();
        };
        let mut bytes = Vec::new();
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(frame) = frame else {
                return failed();
            };
            if let Some(data) = frame.data_ref() {
                if bytes.len() + data.len() > 256 << 10 {
                    return failed();
                }
                bytes.extend_from_slice(data);
            }
        }
        if bytes.len() as i64 != range.end - range.start + 1 {
            return failed();
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let uid = user.user().get();
        let Ok(Some(upload)) = self
            .worker_read_contract(&setjoin_blobs::sql::UPLOAD_ITEM, &[&session, &uid, &item])
            .await
            .map(|rows| setjoin_blobs::decode_upload_item(&rows))
        else {
            return failed();
        };
        if range.total != upload.size || !upload.available {
            return failed();
        }
        match self
            .worker_read_contract(
                &setjoin_blobs::sql::CHUNK_AT,
                &[&session, &uid, &item, &range.start],
            )
            .await
            .map(|rows| setjoin_blobs::decode_existing_chunk(&rows))
        {
            Ok(Some(existing)) => {
                return if existing.size as usize == bytes.len() && existing.digest == digest {
                    empty_204(ctx, request_id)
                } else {
                    failed()
                };
            }
            Err(_) => return failed(),
            Ok(None) => {}
        }
        if range.start != upload.next_offset {
            return failed();
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
            return failed();
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
        match setjoin_blobs::record_chunk(factory, user, record, operation).await {
            setjoin_pg::CommandOutcome::Committed(_) => empty_204(ctx, request_id),
            setjoin_pg::CommandOutcome::RolledBack(rejection) => {
                // Go keeps the content-addressed object if any raced row exists;
                // failed probes also retain it. Delete only a proven orphan.
                if matches!(
                    self.worker_read_contract(
                        &setjoin_blobs::sql::CHUNK_AT,
                        &[&session, &uid, &item, &range.start],
                    )
                    .await
                    .map(|rows| setjoin_blobs::decode_existing_chunk(&rows)),
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
        }
    }

    async fn try_serve(&self, req: Request<Body>, ctx: &RequestContext) -> Response<Body> {
        let is_incidents = matches!(*req.method(), Method::GET | Method::HEAD)
            && req.uri().path() == "/api/recovery/incidents";
        let (mut req, authorized) = match self
            .admit_route(req, ctx, is_incidents || self.store.is_some())
            .await
        {
            Ok(ok) => ok,
            Err(response) => return response,
        };
        let Some(factory) = self.tx_factory() else {
            let id = crate::jmap::reply::request_id(
                req.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            return problem(503, "service unavailable", ctx.identity.proto, id);
        };
        let Ok(user) = factory
            .mint_user_from_authorized(&authorized, &ctx.identity.client_ip.to_string())
            .await
        else {
            let id = crate::jmap::reply::request_id(
                req.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            return problem(
                500,
                "recovery control operation failed",
                ctx.identity.proto,
                id,
            );
        };
        if req.method() == Method::POST && commit_target(req.uri().path()).is_some() {
            return self.try_commit(&mut req, ctx, &factory, &user).await;
        }
        if req.method() == Method::PUT {
            return self.try_chunk(&mut req, ctx, &factory, &user).await;
        }
        if req.method() == Method::POST {
            if self.store.is_none() {
                let id = crate::jmap::reply::request_id(
                    req.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                return problem(
                    404,
                    "client-assisted recovery is disabled",
                    ctx.identity.proto,
                    id,
                );
            }
            let Some(operation) = crate::jmap::random() else {
                let id = crate::jmap::reply::request_id(req.headers().get("x-request-id"), [0; 16]);
                return problem(
                    500,
                    "recovery control operation failed",
                    ctx.identity.proto,
                    id,
                );
            };
            let request_id =
                crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
            let Some(raw_artifact) = fork_target(req.uri().path()) else {
                return problem(404, "not found", ctx.identity.proto, request_id);
            };
            let Some(artifact) = setjoin_blobs::recovery_uuid(raw_artifact) else {
                return problem(
                    400,
                    "invalid recovery identifier",
                    ctx.identity.proto,
                    request_id,
                );
            };
            let mut bytes = Vec::new();
            let mut oversized = false;
            while let Some(frame) = req.body_mut().frame().await {
                let Ok(frame) = frame else {
                    return problem(
                        400,
                        "invalid recovery request",
                        ctx.identity.proto,
                        request_id,
                    );
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
                return problem(
                    400,
                    "invalid recovery request",
                    ctx.identity.proto,
                    request_id,
                );
            };
            if oversized || decoder.end().is_err() {
                return problem(
                    400,
                    "recovery request must contain exactly one JSON object",
                    ctx.identity.proto,
                    request_id,
                );
            }
            let Some(device) = setjoin_blobs::recovery_uuid(&value.device_id) else {
                return problem(
                    400,
                    "invalid recovery device id",
                    ctx.identity.proto,
                    request_id,
                );
            };
            return match setjoin_blobs::fork_consent(&factory, &user, &artifact, &device, operation)
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
                        &req,
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
            };
        }
        if req.method() == Method::DELETE {
            let Some(store) = self.store.as_ref() else {
                let id = crate::jmap::reply::request_id(
                    req.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                return problem(
                    404,
                    "client-assisted recovery is disabled",
                    ctx.identity.proto,
                    id,
                );
            };
            // All fallible prerequisites finish before issuing the command.
            let Some(operation) = crate::jmap::random() else {
                let id = crate::jmap::reply::request_id(req.headers().get("x-request-id"), [0; 16]);
                return problem(500, "recovery upload abort failed", ctx.identity.proto, id);
            };
            let request_id =
                crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
            let Some(raw_session) = abort_target(req.uri().path()) else {
                return problem(404, "not found", ctx.identity.proto, request_id);
            };
            let Some(session) = setjoin_blobs::recovery_uuid(raw_session) else {
                return problem(
                    400,
                    "invalid recovery identifier",
                    ctx.identity.proto,
                    request_id,
                );
            };
            let result = setjoin_blobs::abort_upload(&factory, &user, &session, operation).await;
            return match result {
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
                        &req,
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
            };
        }
        let request_id = crate::jmap::reply::request_id(
            req.headers().get("x-request-id"),
            crate::jmap::random().unwrap_or([0; 16]),
        );
        match setjoin_blobs::user_incidents(&factory, &user).await {
            Ok(json) => crate::jmap::reply::response(json, ctx.identity.proto, request_id),
            Err(err) => rejection_response(
                &setjoin_pg::Rejection::Statement(err),
                &req,
                ctx,
                request_id,
                "recovery control operation failed",
                500,
            ),
        }
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
