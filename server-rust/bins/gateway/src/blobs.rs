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
        matches!(*req.method(), Method::GET | Method::HEAD | Method::PUT)
            && req
                .uri()
                .path()
                .strip_prefix("/api/blobs/")
                .is_some_and(|h| !h.is_empty() && !h.contains('/'))
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
        let request_id = crate::jmap::reply::request_id(
            req.headers().get("x-request-id"),
            crate::jmap::random().unwrap_or([0; 16]),
        );
        let text_reply = |status: hyper::StatusCode, body: &'static str| {
            let mut response =
                crate::jmap::reply::response(body.into(), ctx.identity.proto, request_id.clone());
            *response.status_mut() = status;
            response.headers_mut().insert(
                "content-type",
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        };
        let hash = req.uri().path().strip_prefix("/api/blobs/").unwrap_or("");
        // Go ServeMux keeps escaped segment boundaries, then PathValue decodes
        // the selected hash. Decode only after matching the single segment.
        let Ok(hash) = String::from_utf8(crate::inventory::unescape(hash)) else {
            return text_reply(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal error\n");
        };
        let Ok(owned) =
            setjoin_blobs::blob_owned(&self.worker_exec, authorized.context(), &hash).await
        else {
            return text_reply(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal error\n");
        };
        if !owned {
            return text_reply(hyper::StatusCode::NOT_FOUND, "blob not found\n");
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
            Err(crate::recovery_worker::BlobReadError::Incomplete) => {
                return text_reply(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal error\n");
            }
            Err(crate::recovery_worker::BlobReadError::Unavailable) => {
                return text_reply(hyper::StatusCode::NOT_FOUND, "blob not found\n");
            }
        };
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
                response.headers_mut().insert(
                    "content-type",
                    content_type.parse().unwrap_or_else(|_| {
                        hyper::header::HeaderValue::from_static("application/octet-stream")
                    }),
                );
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
                response.headers_mut().insert(
                    "content-type",
                    content_type.parse().unwrap_or_else(|_| {
                        hyper::header::HeaderValue::from_static("application/octet-stream")
                    }),
                );
                if let Some(modified) = modified
                    .and_then(|v| chrono::DateTime::parse_from_rfc2822(&v).ok())
                    .filter(|v| v.timestamp() != 0)
                {
                    if let Ok(value) = modified
                        .with_timezone(&chrono::Utc)
                        .format("%a, %d %b %Y %H:%M:%S GMT")
                        .to_string()
                        .parse()
                    {
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
        .unwrap_or_else(|_| {
            text_reply(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
        })
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
        // Go's retention registry (#301): applied after the upload when `WORM_MODE` is
        // set; a configuration Go would refuse to start with stays with Go (#415).
        let worm = match crate::blob_retention::config() {
            crate::blob_retention::Config::Off => None,
            crate::blob_retention::Config::On(worm) => Some(worm),
            crate::blob_retention::Config::Invalid => {
                return ctx.upstream.forward(req, &ctx.identity).await;
            }
        };
        let Some(operation) = crate::jmap::random() else {
            let request_id =
                crate::jmap::reply::request_id(req.headers().get("x-request-id"), [0; 16]);
            let mut response = crate::jmap::reply::response(
                "upload failed\n".into(),
                ctx.identity.proto,
                request_id,
            );
            *response.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(
                "content-type",
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            return response;
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
        let hash = req.uri().path().strip_prefix("/api/blobs/").unwrap_or("");
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
        let temp_key = format!("tmp/upload/{}", crate::jmap::reply::hex(&operation));
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
            let _ = self.store.remove(&temp_key).await;
            return reply(400, "sha256 mismatch\n");
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
                return if error.log_summary().contains("BZ001") {
                    reply(413, "storage quota exceeded\n")
                } else {
                    reply(500, "upload failed\n")
                };
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut response = reply(503, "upload outcome unknown\n");
                response.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation)
                        .parse()
                        .expect("operation hex"),
                );
                return response;
            }
        }
        let promoted = self.store.promote(&temp_key, &hash).await;
        let _ = self.store.remove(&temp_key).await;
        if promoted.is_err() {
            return reply(500, "upload failed\n");
        }
        if let Some(worm) = &worm {
            // Non-fatal: the blob is stored; the cleanup tick retries the lock.
            if let Err(e) = crate::blob_retention::apply(&*self.store, worm, &hash).await {
                eprintln!("retention policy apply failed key={hash}: {e}");
                crate::blob_retention::note_retry(&hash);
            }
        }
        reply(201, "")
    }
}

struct UploadTemporary(std::path::PathBuf);
impl Drop for UploadTemporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
