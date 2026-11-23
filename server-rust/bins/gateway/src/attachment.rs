//! Native exact-blob bearer route. Every continuation rechecks live authority.
use crate::{Body, BoxFuture, Intercept, RequestContext, recovery_worker::S3Store};
use hyper::{Method, Request, Response};
use setjoin_pg::{ScopedExecutor, Type};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct AttachmentCommands {
    pub exec: ScopedExecutor,
    pub worker_exec: ScopedExecutor,
    pub issuer: String,
    pub secret: Vec<u8>,
    pub previous_secret: Option<Vec<u8>>,
    pub store: Arc<S3Store>,
}
pub struct AttachmentRoute(pub Arc<AttachmentCommands>);
impl Intercept for AttachmentRoute {
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        // Must stay false: SessionAdmission rejects HS256+HKDF mail-attachment tokens
        // with 401 before AttachmentRoute runs; RuntimeAccess::check handles Proof::attachment.
        false
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD)
            && r.uri()
                .path()
                .strip_prefix("/mail-attachment/")
                .is_some_and(|t| !t.is_empty() && !t.contains('/'))
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        Box::pin(async move { commands.serve(r, &c).await })
    }
}
impl AttachmentCommands {
    async fn serve(&self, r: Request<Body>, c: &RequestContext) -> Response<Body> {
        let a = match setjoin_authz::admit_attachment(
            &self.exec,
            r.headers(),
            &self.issuer,
            &[
                &self.secret,
                self.previous_secret.as_deref().unwrap_or_default(),
            ],
        )
        .await
        {
            Ok(a) => a,
            Err(refusal) => return crate::deny::answer(refusal, r, c).await,
        };
        let user = a.identity.user_id();
        let claim = &a.claims["attachment"];
        let device = &a.claims["device"];
        let target = r
            .uri()
            .path()
            .strip_prefix("/mail-attachment/")
            .unwrap_or("");
        let request_id = crate::jmap::reply::request_id(
            r.headers().get("x-request-id"),
            crate::jmap::random().unwrap_or([0; 16]),
        );
        let problem = |status: u16, detail: &str| {
            let mut res = crate::jmap::reply::response(
                crate::problem::Problem::new(status, detail).body(),
                c.identity.proto,
                request_id.clone(),
            );
            *res.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
            res.headers_mut().insert(
                "content-type",
                hyper::header::HeaderValue::from_static("application/problem+json"),
            );
            res
        };
        let hash = String::from_utf8(crate::inventory::unescape(target)).ok();
        if hash
            .as_deref()
            .is_none_or(|h| Some(h) != claim["sha256"].as_str())
        {
            return problem(401, "invalid attachment transfer token");
        }
        let hash = hash.unwrap();
        let valid_hash = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let (
            Some(account),
            Some(mailbox),
            Some(device_id),
            Some(fingerprint),
            Some(origin),
            Some(origin_iat),
        ) = (
            claim["account_id"].as_i64().filter(|v| *v > 0),
            claim["mailbox_id"].as_i64().filter(|v| *v > 0),
            claim["device_id"].as_i64().filter(|v| *v > 0),
            claim["device_fingerprint"].as_str(),
            claim["origin_jti"].as_str().filter(|s| !s.is_empty()),
            claim["origin_iat"].as_i64().filter(|v| *v > 0),
        )
        else {
            return problem(401, "Unauthorized");
        };
        if !valid_hash || device["id"] != fingerprint {
            return problem(401, "Unauthorized");
        }
        let fingerprint_bytes = fingerprint.as_bytes();
        if !device["platform"].is_null() && !device["platform"].is_string() {
            return problem(401, "Unauthorized");
        }
        let platform = device["platform"].as_str().unwrap_or("");
        let family = a.claims["fam"].as_str().unwrap_or("");
        let Ok(rows)=self.worker_exec.read("SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'),false) AND COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.connectivity_aware_sync'),false), EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND expires_at>now() AND ((scope='all' AND not_before>=to_timestamp($2::float8)) OR (scope='jti' AND jti=$3) OR (scope='family' AND family_id=$4 AND $4<>''))), (SELECT id FROM user_devices WHERE user_id=$1 AND fingerprint_hash=sha256($5::bytea) AND platform=$6 AND NOT wipe_requested ORDER BY id LIMIT 1)",&[(&user,Type::INT8),(&(origin_iat as f64),Type::FLOAT8),(&origin,Type::TEXT),(&family,Type::TEXT),(&fingerprint_bytes,Type::BYTEA),(&platform,Type::TEXT)]).await else {
            return problem(503, "service unavailable");
        };
        let Some(row) = rows.first() else {
            return problem(503, "service unavailable");
        };
        if !row.get::<_, bool>(0) {
            return problem(404, "Not Found");
        }
        if row.get::<_, bool>(1) {
            return problem(401, "Unauthorized");
        }
        if !matches!(platform, "desktop" | "ios" | "android")
            || row.get::<_, Option<i64>>(2) != Some(device_id)
        {
            return problem(403, "Forbidden");
        }
        let Some((raw, policy)) = self
            .worker_exec
            .read(
                "SELECT offline_effective_policy_snapshot($1,$2)::text",
                &[(&mailbox, Type::INT8), (&device_id, Type::INT8)],
            )
            .await
            .ok()
            .and_then(|rows| {
                let raw: String = rows.first()?.try_get(0).ok()?;
                let policy: serde_json::Value = serde_json::from_str(&raw).ok()?;
                Some((raw, policy))
            })
        else {
            return problem(409, "Conflict");
        };
        if policy["syncQoS"]["mode"] == "off" {
            return problem(404, "Not Found");
        }
        if policy["allowed"] != true
            || policy["syncQoS"]["mode"] != "execute"
            || policy["syncQoS"]["effective"]["automaticNetwork"] == "never"
            || claim["policy_generation"] != format!("{:x}", Sha256::digest(raw.as_bytes()))
        {
            return problem(409, "Conflict");
        }
        let scope = a.identity.database_scope();
        let delegated = if account != scope.mailbox().get()
            && setjoin_authz::mailbox::can_read(&self.exec, &scope, account)
                .await
                .unwrap_or(false)
        {
            account
        } else {
            0
        };
        let Ok(Some((size, content_type))) =
            setjoin_blobs::attachment_metadata(&self.worker_exec, &a.identity, &hash, delegated)
                .await
        else {
            return problem(404, "Not Found");
        };
        // This route always stats live S3 metadata, even when a normal blob
        // GET populated the process's small-object cache.
        if self.store.stat_size(&hash).await.ok().flatten() != Some(size as u64) {
            let mut response = crate::jmap::reply::response(
                "404 page not found\n".into(),
                c.identity.proto,
                request_id,
            );
            *response.status_mut() = hyper::StatusCode::NOT_FOUND;
            response.headers_mut().insert(
                "content-type",
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            return response;
        }
        let mut response =
            crate::jmap::reply::response(String::new(), c.identity.proto, request_id.clone());
        let content_type = content_type.parse().unwrap_or_else(|_| {
            hyper::header::HeaderValue::from_static("application/octet-stream")
        });
        let headers = response.headers_mut();
        headers.insert("content-type", content_type);
        headers.insert(
            "content-length",
            hyper::header::HeaderValue::from(size as u64),
        );
        headers.insert(
            "content-disposition",
            format!("attachment; filename=\"{hash}\"")
                .parse()
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("attachment")),
        );
        headers.insert(
            "etag",
            format!("\"{hash}\"")
                .parse()
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("\"\"")),
        );
        headers.insert(
            "accept-ranges",
            hyper::header::HeaderValue::from_static("bytes"),
        );
        headers.insert(
            "content-security-policy",
            hyper::header::HeaderValue::from_static("default-src 'none'; sandbox"),
        );
        headers.insert(
            "cache-control",
            hyper::header::HeaderValue::from_static(
                "private, max-age=31536000, immutable, no-transform",
            ),
        );
        crate::blob_content::serve_ranges(
            &r,
            response,
            self.store.clone(),
            &hash,
            size as u64,
            None,
        )
        .await
        .unwrap_or_else(|_| problem(500, "Internal Server Error"))
    }
}
