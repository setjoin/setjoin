//! Qualified blob adapter; F16 defaults ON with whole-request Go fallback.
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;

use crate::{recovery_worker::S3Store, Body, BoxFuture, Intercept, RequestContext};

pub struct BlobCommands<K: KeySource> {
    pub exec: ScopedExecutor,
    pub worker_exec: ScopedExecutor,
    pub keys: K,
    pub issuer: String,
    pub store: Arc<S3Store>,
}

pub struct BlobRoute<K: KeySource + 'static>(pub Arc<BlobCommands<K>>);

impl<K: KeySource + 'static> Intercept for BlobRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, req: &Request<Body>) -> bool {
        // Go's `/blobs/{sha256}` claims exactly one non-empty escaped segment; any other
        // spelling is the API mux's 404/405 and belongs to the catch-all (#357).
        matches!(*req.method(), Method::GET | Method::HEAD | Method::PUT)
            && req
                .uri()
                .path()
                .strip_prefix("/api/blobs/")
                .is_some_and(|hash| !hash.is_empty() && !hash.contains('/'))
    }

    fn handle(&self, req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        Box::pin(async move {
            if req.method() == Method::PUT {
                commands.try_upload(req, ctx).await
            } else {
                commands.try_serve(req, ctx).await
            }
        })
    }
}

impl<K: KeySource> BlobCommands<K> {
    async fn try_serve(&self, req: Request<Body>, ctx: RequestContext) -> Response<Body> {
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
            Err(refusal) => return crate::deny::answer(refusal, req, &ctx).await,
        };
        let raw = req
            .uri()
            .path()
            .strip_prefix("/api/blobs/")
            .unwrap_or_default();
        if raw.is_empty() || raw.contains('/') {
            // `matches` excludes these spellings; never reached through the route table.
            return crate::surface::unregistered(&req, ctx.identity.proto);
        }
        // Go ServeMux keeps escaped segment boundaries, then PathValue decodes the selected
        // hash. A hash that is not UTF-8 fails Go's ownership query (Postgres rejects the
        // parameter): handler.go:541-544 `internal error` (recorded: invalid-utf8).
        let Ok(hash) = String::from_utf8(crate::inventory::unescape(raw)) else {
            return text(&req, &ctx, 500, "internal error\n");
        };
        match setjoin_blobs::blob_owned(&self.worker_exec, authorized.context(), &hash).await {
            Ok(true) => {}
            Ok(false) => return text(&req, &ctx, 404, "blob not found\n"),
            // handler.go:541-544: the ownership read failed.
            Err(_) => return text(&req, &ctx, 500, "internal error\n"),
        }
        let object = match self
            .store
            .download(
                &hash,
                req.headers()
                    .get("range")
                    .is_none_or(|v| v.as_bytes().is_empty()),
            )
            .await
        {
            Ok(blob) => blob,
            // Stat or GET failed before any body: handler.go:574-583
            // (native test: go357_storage_get_failure_is_not_found; Go Stat=HEAD/ReadFull=GET falls through to ServeContent 500 on split HEAD=200/GET=403).
            Err(crate::recovery_worker::BlobReadError::Unavailable) => {
                return text(&req, &ctx, 404, "blob not found\n")
            }
            // `download` never yields this (short bodies fall back to streaming).
            Err(crate::recovery_worker::BlobReadError::Incomplete) => {
                return text(&req, &ctx, 500, "internal error\n")
            }
        };
        let request_id = crate::jmap::reply::request_id(
            req.headers().get("x-request-id"),
            crate::jmap::random().unwrap_or([0; 16]),
        );
        let mut response =
            crate::jmap::reply::response(String::new(), ctx.identity.proto, request_id.clone());
        response.headers_mut().insert(
            "content-security-policy",
            hyper::header::HeaderValue::from_static("default-src 'none'; sandbox"),
        );
        let (total, buffered) = match object {
            crate::recovery_worker::BlobDownload::Buffered {
                bytes,
                content_type,
                cached,
            } => {
                let total = bytes.len() as u64;
                if let Ok(value) = hyper::header::HeaderValue::from_bytes(content_type.as_bytes()) {
                    response.headers_mut().insert("content-type", value);
                }
                let bytes = bytes::Bytes::from(bytes);
                // Frozen Go's first small non-ranged read writes directly,
                // bypassing ServeContent and all conditional headers.
                if !cached {
                    response
                        .headers_mut()
                        .insert("content-length", total.into());
                    *response.body_mut() = Full::new(if req.method() == Method::HEAD {
                        bytes::Bytes::new()
                    } else {
                        bytes
                    })
                    .map_err(|n| match n {})
                    .boxed();
                    return response;
                }
                (total, Some(bytes))
            }
            crate::recovery_worker::BlobDownload::Streaming {
                size,
                content_type,
                modified,
            } => {
                if let Ok(value) = hyper::header::HeaderValue::from_bytes(content_type.as_bytes()) {
                    response.headers_mut().insert("content-type", value);
                }
                if let Some(modified) = modified
                    .and_then(|v| chrono::DateTime::parse_from_rfc2822(&v).ok())
                    .filter(|v| v.timestamp() != 0)
                {
                    let stamp = modified
                        .with_timezone(&chrono::Utc)
                        .format("%a, %d %b %Y %H:%M:%S GMT")
                        .to_string();
                    if let Ok(value) = hyper::header::HeaderValue::from_str(&stamp) {
                        response.headers_mut().insert("last-modified", value);
                    }
                }
                (size, None)
            }
        };
        crate::blob_content::serve_ranges(
            &req,
            response,
            self.store.clone(),
            &hash,
            total,
            buffered,
        )
        .await
        .unwrap_or_else(|_| text(&req, &ctx, 500, "internal error\n"))
    }
}

impl<K: KeySource> BlobCommands<K> {
    async fn try_upload(&self, mut req: Request<Body>, ctx: RequestContext) -> Response<Body> {
        use crate::recovery_worker::ObjectStore;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        let actor = match crate::deny::admit(
            &self.exec,
            &self.keys,
            &self.issuer,
            &req,
            crate::deny::Scope::Member,
        )
        .await
        {
            Ok(actor) => actor,
            Err(refusal) => return crate::deny::answer(refusal, req, &ctx).await,
        };
        // Go's retention registry (#301): applied after the upload when `WORM_MODE` is set.
        let worm = match crate::blob_retention::config() {
            crate::blob_retention::Config::Off => None,
            crate::blob_retention::Config::On(worm) => Some(worm),
            // Go refuses to start with this configuration, so no Go answer exists:
            // fail closed without storing (owner decision D-357f-2).
            crate::blob_retention::Config::Invalid => {
                return text(&req, &ctx, 500, "upload failed\n");
            }
        };
        // A failed OS RNG leaves no idempotency key: Go's generic upload failure.
        let Some(operation) = crate::jmap::random() else {
            return text(&req, &ctx, 500, "upload failed\n");
        };
        let request_id =
            crate::jmap::reply::request_id(req.headers().get("x-request-id"), operation);
        let reply = |status: u16, body: &str| {
            let mut response =
                crate::jmap::reply::response(body.into(), ctx.identity.proto, request_id.clone());
            *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
            response.headers_mut().remove("content-type");
            if !body.is_empty() {
                response.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
            }
            response
        };
        let hash = req
            .uri()
            .path()
            .strip_prefix("/api/blobs/")
            .unwrap_or_default();
        if hash.is_empty() || hash.contains('/') {
            // `matches` excludes these spellings; never reached through the route table.
            return crate::surface::unregistered(&req, ctx.identity.proto);
        }
        let hash = String::from_utf8(crate::inventory::unescape(hash)).unwrap_or_default();
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return reply(400, "invalid blob ID\n");
        }
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let temp_key = format!(
            "{}{}",
            crate::blob_retention::BLOB_STAGING_PREFIX,
            crate::jmap::reply::hex(&operation)
        );
        let path = std::env::temp_dir().join(format!(
            "setjoin-blob-upload-{}",
            crate::jmap::reply::hex(&operation)
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let Ok(mut file) = options.open(&path).await else {
            return reply(500, "upload failed\n");
        };
        let temporary = UploadTemporary(path);
        let mut hasher = Sha256::new();
        let mut size = 0i64;
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(frame) = frame else {
                return reply(500, "upload failed\n");
            };
            if let Ok(data) = frame.into_data() {
                size += data.len() as i64;
                if size > 100 << 20 || file.write_all(&data).await.is_err() {
                    return reply(500, "upload failed\n");
                }
                hasher.update(&data);
            }
        }
        if file.flush().await.is_err()
            || self
                .store
                .put_file(&temp_key, &temporary.0, size as u64, &content_type)
                .await
                .is_err()
        {
            return reply(500, "upload failed\n");
        }
        if format!("{:x}", hasher.finalize()) != hash {
            let _ = self
                .store
                .delete_blob_checked(&temp_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                .await;
            return reply(400, "sha256 mismatch\n");
        }
        // Durable-first WORM arming (#549/#551): enqueue `blob.worm_arm` (run_at = now() + 30s)
        // BEFORE `blob_upload_account` commits `blob.promote_recover`, so a crash between
        // `blob_upload_account` and `blob.worm_arm` enqueue can never let `BlobPromoteConsumer`
        // publish canonical bytes without an armed WORM job. If enqueue fails, abort before
        // accounting/promote (HTTP 500).
        let worm_armed = if let Some(worm) = &worm {
            let retain_until = crate::blob_retention::retain_until(chrono::Utc::now(), worm.days);
            let payload = crate::blob_retention::WormArmPayload {
                sha256: hash.clone(),
                object_key: hash.clone(),
                mode: worm.mode.clone(),
                retain_days: worm.days,
                retain_until: retain_until.clone(),
                version_id: None,
            };
            let Ok(payload_text) = serde_json::to_string(&payload) else {
                let _ = self
                    .store
                    .delete_blob_checked(&temp_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                    .await;
                return reply(500, "upload failed\n");
            };
            let idem = crate::blob_retention::worm_idempotency_key(&hash, &retain_until);
            let delay_secs = 300.0_f64;
            let priority = 0_i16;
            let max_attempts = crate::blob_retention::WORM_MAX_ATTEMPTS;
            let kind = crate::blob_retention::WORK_KIND_WORM_ARM;
            let Ok(rows) = self
                .worker_exec
                .protocol_query(
                    "SELECT work_item_id, coalesced \
                     FROM public.work_enqueue($1, $2::text::jsonb, $3, now() + make_interval(secs => $4), $5, $6)",
                    &[
                        (&kind, setjoin_pg::Type::TEXT),
                        (&payload_text, setjoin_pg::Type::TEXT),
                        (&idem, setjoin_pg::Type::TEXT),
                        (&delay_secs, setjoin_pg::Type::FLOAT8),
                        (&priority, setjoin_pg::Type::INT2),
                        (&max_attempts, setjoin_pg::Type::INT4),
                    ],
                )
                .await
            else {
                let _ = self
                    .store
                    .delete_blob_checked(&temp_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                    .await;
                return reply(500, "upload failed\n");
            };
            let Some(work_item_id) = rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()) else {
                let _ = self
                    .store
                    .delete_blob_checked(&temp_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                    .await;
                return reply(500, "upload failed\n");
            };
            Some((work_item_id, worm.mode.clone(), retain_until))
        } else {
            None
        };
        let (promote_work_item_id, verify_work_item_id) = match setjoin_blobs::account_upload(
            &self.exec,
            actor.context(),
            &hash,
            &self.store.blob_reference(&hash),
            size,
            &content_type,
            Some(&temp_key),
            operation,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(raw) => {
                let parsed = serde_json::from_str::<serde_json::Value>(&raw).ok();
                let promote_id = parsed
                    .as_ref()
                    .and_then(|v| v.get("promoteWorkItemId"))
                    .and_then(serde_json::Value::as_i64);
                let verify_id = parsed
                    .as_ref()
                    .and_then(|v| v.get("verifyWorkItemId"))
                    .and_then(serde_json::Value::as_i64);
                (promote_id, verify_id)
            }
            setjoin_pg::CommandOutcome::RolledBack(error) => {
                if let Some((work_item_id, _, _)) = worm_armed {
                    let _ = self
                        .worker_exec
                        .protocol_query(
                            "SELECT public.work_cancel_pending($1)",
                            &[(&work_item_id, setjoin_pg::Type::INT8)],
                        )
                        .await;
                }
                let _ = self
                    .store
                    .delete_blob_checked(&temp_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                    .await;
                return if error.log_summary().contains("BZ001") {
                    reply(413, "storage quota exceeded\n")
                } else {
                    reply(500, "upload failed\n")
                };
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut response = reply(503, "upload outcome unknown\n");
                if let Ok(value) =
                    setjoin_pg::operation_hex(operation).parse::<hyper::header::HeaderValue>()
                {
                    response.headers_mut().insert("x-operation-id", value);
                }
                return response;
            }
        };
        let promoted = self.store.promote(&temp_key, &hash).await;
        if promoted.is_err() {
            // Only cancel `blob.worm_arm` and delete `temp_key` when no delayed
            // `blob.promote_verify` owns `temp_key` AND `blob.promote_recover` was
            // cancelled while still pending. If `promote_recover` was already leased
            // (or `promote_verify` exists), keep `blob.worm_arm` armed so the worker
            // promotes and locks the object durably.
            let cancelled_recover = self
                .settle_promote_recover(promote_work_item_id, verify_work_item_id, &hash, &temp_key)
                .await;
            if verify_work_item_id.is_none() && cancelled_recover {
                if let Some((work_item_id, _, _)) = worm_armed {
                    let _ = self
                        .worker_exec
                        .protocol_query(
                            "SELECT public.work_cancel_pending($1)",
                            &[(&work_item_id, setjoin_pg::Type::INT8)],
                        )
                        .await;
                }
            }
            return reply(500, "upload failed\n");
        }
        let _ = self
            .settle_promote_recover(promote_work_item_id, verify_work_item_id, &hash, &temp_key)
            .await;
        if let Some((work_item_id, mode, retain_until)) = worm_armed {
            // Fast path: apply inline; cancel the deferred work item ONLY after
            // `blob_gc_record_worm_lock` succeeds durably. On either apply or record
            // failure, expedite `blob.worm_arm` for `WormArmConsumer` while returning HTTP 201.
            match crate::blob_retention::apply_until(&*self.store, &mode, &hash, &retain_until)
                .await
            {
                Ok(()) => {
                    let recorded = self
                        .worker_exec
                        .protocol_statement(
                            "SELECT public.blob_gc_record_worm_lock($1, $2::text::timestamptz, 'worm_put_apply')",
                            &[
                                (&hash, setjoin_pg::Type::TEXT),
                                (&retain_until, setjoin_pg::Type::TEXT),
                            ],
                        )
                        .await;
                    if recorded.is_ok() {
                        let _ = self
                            .worker_exec
                            .protocol_query(
                                "SELECT public.work_cancel_pending($1)",
                                &[(&work_item_id, setjoin_pg::Type::INT8)],
                            )
                            .await;
                    } else {
                        eprintln!(
                            "worm lock record failed key={hash}; expediting blob.worm_arm for durable retry"
                        );
                        let _ = self
                            .worker_exec
                            .protocol_query(
                                "SELECT public.work_expedite($1)",
                                &[(&work_item_id, setjoin_pg::Type::INT8)],
                            )
                            .await;
                    }
                }
                Err(e) => {
                    eprintln!("retention policy apply failed key={hash}: {e}");
                    let _ = self
                        .worker_exec
                        .protocol_query(
                            "SELECT public.work_expedite($1)",
                            &[(&work_item_id, setjoin_pg::Type::INT8)],
                        )
                        .await;
                }
            }
        }
        reply(201, "")
    }

    /// Cancels a pending `blob.promote_recover` item iff still unleased, and
    /// permanently deletes all versions of `temp_key` ONLY when no delayed
    /// `blob.promote_verify` owns it and `promote_recover` was cancelled.
    async fn settle_promote_recover(
        &self,
        promote_work_item_id: Option<i64>,
        verify_work_item_id: Option<i64>,
        hash: &str,
        temp_key: &str,
    ) -> bool {
        use crate::recovery_worker::ObjectStore;
        let cancelled_recover = match promote_work_item_id {
            Some(wid) => setjoin_blobs::complete_promote_recover(&self.exec, wid, hash, temp_key)
                .await
                .unwrap_or(false),
            None => true,
        };
        if verify_work_item_id.is_none() && cancelled_recover {
            let _ = self
                .store
                .delete_blob_checked(temp_key, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                .await;
        }
        cancelled_recover
    }
}

/// `http.Error`: the text and newline as text/plain under Go's middleware envelope.
fn text(req: &Request<Body>, ctx: &RequestContext, status: u16, body: &str) -> Response<Body> {
    let request_id = crate::jmap::reply::request_id(
        req.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let mut response = crate::jmap::reply::response(body.into(), ctx.identity.proto, request_id);
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("static status");
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

struct UploadTemporary(std::path::PathBuf);
impl Drop for UploadTemporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
