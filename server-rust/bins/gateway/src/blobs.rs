//! Qualified blob adapter; F16 defaults ON with whole-request Go fallback.
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;

use crate::{Body, BoxFuture, Intercept, RequestContext, recovery_worker::S3Store};

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

    fn handle(&self, mut req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        Box::pin(async move {
            if req.method() == Method::PUT {
                if let Some(response) = commands.try_upload(&mut req, &ctx).await {
                    return response;
                }
            } else if let Some(response) = commands.try_serve(&req, &ctx).await {
                return response;
            }
            ctx.upstream.forward(req, &ctx.identity).await
        })
    }
}

impl<K: KeySource> BlobCommands<K> {
    async fn try_serve(&self, req: &Request<Body>, ctx: &RequestContext) -> Option<Response<Body>> {
        // `None` is left only for an authorize refusal (#354 B7 owns that answer).
        let authorized = setjoin_authz::authorize_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            req.headers(),
            ctx.identity.proto,
        )
        .await?;
        let raw = req.uri().path().strip_prefix("/api/blobs/").unwrap_or_default();
        if raw.is_empty() || raw.contains('/') {
            // `matches` excludes these spellings; never reached through the route table.
            return Some(crate::surface::unregistered(req, ctx.identity.proto));
        }
        // Go ServeMux keeps escaped segment boundaries, then PathValue decodes the selected
        // hash. A hash that is not UTF-8 fails Go's ownership query (Postgres rejects the
        // parameter): handler.go:541-544 `internal error` (recorded: invalid-utf8).
        let Ok(hash) = String::from_utf8(crate::inventory::unescape(raw)) else {
            return Some(text(req, ctx, 500, "internal error\n"));
        };
        match setjoin_blobs::blob_owned(&self.worker_exec, authorized.context(), &hash).await {
            Ok(true) => {}
            Ok(false) => return Some(text(req, ctx, 404, "blob not found\n")),
            // handler.go:541-544: the ownership read failed.
            Err(_) => return Some(text(req, ctx, 500, "internal error\n")),
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
            // Stat or GET failed before any body: handler.go:574-583 (recorded: storage-get-fails).
            Err(crate::recovery_worker::BlobReadError::Unavailable) => {
                return Some(text(req, ctx, 404, "blob not found\n"))
            }
            // `download` never yields this (short bodies fall back to streaming).
            Err(crate::recovery_worker::BlobReadError::Incomplete) => {
                return Some(text(req, ctx, 500, "internal error\n"))
            }
        };
        let request_id = crate::jmap::reply::request_id(
            req.headers().get("x-request-id"),
            crate::jmap::random().unwrap_or([0; 16]),
        );
        let mut response =
            crate::jmap::reply::response(String::new(), ctx.identity.proto, request_id);
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
                    return Some(response);
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
        // Only the multipart boundary's RNG can fail here.
        Some(
            crate::blob_content::serve_ranges(req, response, self.store.clone(), &hash, total, buffered)
                .await
                .unwrap_or_else(|_| text(req, ctx, 500, "internal error\n")),
        )
    }
}

impl<K: KeySource> BlobCommands<K> {
    async fn try_upload(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
    ) -> Option<Response<Body>> {
        use crate::recovery_worker::ObjectStore;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        // Go's retention registry (#301): applied after the upload when `WORM_MODE` is set.
        let worm = crate::blob_retention::config();
        let actor = setjoin_authz::authorize_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            req.headers(),
            ctx.identity.proto,
        )
        .await?;
        let worm = match worm {
            crate::blob_retention::Config::Off => None,
            crate::blob_retention::Config::On(worm) => Some(worm),
            // Go refuses to start with this configuration, so no Go answer exists:
            // fail closed without storing (owner decision D-357f-2).
            crate::blob_retention::Config::Invalid => {
                return Some(text(req, ctx, 500, "upload failed\n"));
            }
        };
        // A failed OS RNG leaves no idempotency key: Go's generic upload failure.
        let Some(operation) = crate::jmap::random() else {
            return Some(text(req, ctx, 500, "upload failed\n"));
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
        let hash = req.uri().path().strip_prefix("/api/blobs/").unwrap_or_default();
        if hash.is_empty() || hash.contains('/') {
            // `matches` excludes these spellings; never reached through the route table.
            return Some(crate::surface::unregistered(req, ctx.identity.proto));
        }
        let hash = String::from_utf8(crate::inventory::unescape(hash)).unwrap_or_default();
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Some(reply(400, "invalid blob ID\n"));
        }
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let temp_key = format!("tmp/upload/{}", crate::jmap::reply::hex(&operation));
        let path = std::env::temp_dir().join(format!(
            "setjoin-blob-upload-{}",
            crate::jmap::reply::hex(&operation)
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let Ok(mut file) = options.open(&path).await else {
            return Some(reply(500, "upload failed\n"));
        };
        let temporary = UploadTemporary(path);
        let mut hasher = Sha256::new();
        let mut size = 0i64;
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(frame) = frame else {
                return Some(reply(500, "upload failed\n"));
            };
            if let Ok(data) = frame.into_data() {
                size += data.len() as i64;
                if size > 100 << 20 || file.write_all(&data).await.is_err() {
                    return Some(reply(500, "upload failed\n"));
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
            return Some(reply(500, "upload failed\n"));
        }
        if format!("{:x}", hasher.finalize()) != hash {
            let _ = self.store.remove(&temp_key).await;
            return Some(reply(400, "sha256 mismatch\n"));
        }
        match setjoin_blobs::account_upload(
            &self.exec,
            actor.context(),
            &hash,
            &self.store.blob_reference(&hash),
            size,
            &content_type,
            operation,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(_) => {}
            setjoin_pg::CommandOutcome::RolledBack(error) => {
                let _ = self.store.remove(&temp_key).await;
                return Some(if error.log_summary().contains("BZ001") {
                    reply(413, "storage quota exceeded\n")
                } else {
                    reply(500, "upload failed\n")
                });
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut response = reply(503, "upload outcome unknown\n");
                if let Ok(value) =
                    setjoin_pg::operation_hex(operation).parse::<hyper::header::HeaderValue>()
                {
                    response.headers_mut().insert("x-operation-id", value);
                }
                return Some(response);
            }
        }
        let promoted = self.store.promote(&temp_key, &hash).await;
        let _ = self.store.remove(&temp_key).await;
        if promoted.is_err() {
            return Some(reply(500, "upload failed\n"));
        }
        if let Some(worm) = &worm {
            // Non-fatal: the blob is stored; the cleanup tick retries the lock.
            if let Err(e) = crate::blob_retention::apply(&*self.store, worm, &hash).await {
                eprintln!("retention policy apply failed key={hash}: {e}");
                crate::blob_retention::note_retry(&hash);
            }
        }
        Some(reply(201, ""))
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
