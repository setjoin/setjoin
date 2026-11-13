use crate::recovery_worker::ObjectStore;
use http_body_util::BodyExt;
// Office HTTP edge. Reducers resolve launch tokens and current file authority.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_pg::ScopedExecutor;
pub struct OfficeRoute {
    exec: ScopedExecutor,
    store: Option<std::sync::Arc<crate::recovery_worker::S3Store>>,
    proof: std::sync::Arc<crate::office_provider::ProofVerifier>,
}
impl OfficeRoute {
    pub fn new(
        exec: ScopedExecutor,
        store: Option<std::sync::Arc<crate::recovery_worker::S3Store>>,
    ) -> Self {
        Self {
            exec,
            store,
            proof: std::sync::Arc::new(crate::office_provider::ProofVerifier::new()),
        }
    }
    pub fn with_proof(mut self, proof: crate::office_provider::ProofVerifier) -> Self {
        self.proof = std::sync::Arc::new(proof);
        self
    }
}
impl Intercept for OfficeRoute {
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD | Method::POST)
            && [
                "/api/office/wopi/files/{id}",
                "/api/office/wopi/files/{id}/contents",
            ]
            .iter()
            .any(|p| crate::inventory::path_score(p, r.uri().path()).is_some())
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let exec = self.exec.clone();
        let store = self.store.clone();
        let proof = self.proof.clone();
        Box::pin(async move {
            let request_id = request_id(&r);
            let flags=exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false) AND coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.office_editing'),false)",&[]).await;
            match flags {
                Ok(rows) if rows.first().is_some_and(|r| r.get::<_, bool>(0)) => {}
                Ok(_) => return problem(404, "not found", &c, request_id.clone()),
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            }
            // Go's PathValue decodes one segment, never a path separator.
            let segments: Vec<_> = r.uri().path().split('/').collect();
            let contents = segments.len() == 7;
            let target = decoded_path(segments.get(5).copied().unwrap_or(""));
            let id = target.parse::<i64>().unwrap_or(0);
            if id <= 0 {
                return problem(400, "invalid WOPI file id", &c, request_id.clone());
            }
            let token =
                query_value(r.uri().query().unwrap_or(""), "access_token").unwrap_or_default();
            if token.is_empty() || token.len() > 4096 {
                return problem(404, "file not found", &c, request_id.clone());
            }
            let p = match setjoin_office::projection(&exec, id, &token).await {
                Ok(p) => p,
                Err(e) => {
                    return reducer_problem(&e, r.uri().path(), false, &c, request_id.clone())
                }
            };
            if p["proofMode"] != "test_disabled"
                && (p["proofDiscoveryUrl"].as_str().unwrap_or("").is_empty()
                    || p["wopiPublicBaseUrl"].as_str().unwrap_or("").is_empty()
                    || !proof
                        .verify(
                            &r,
                            &token,
                            p["proofDiscoveryUrl"].as_str().unwrap_or(""),
                            p["wopiPublicBaseUrl"].as_str().unwrap_or(""),
                        )
                        .await)
            {
                return problem(404, "file not found", &c, request_id.clone());
            }
            if contents && store.is_none() {
                return c.upstream.forward(r, &c.identity).await;
            }
            if r.method() == Method::POST && contents {
                let token = token.to_owned();
                return put_file(r, c, exec, p, token, store).await;
            }
            if r.method() == Method::POST && !contents {
                let value = header(&r, "x-wopi-lock");
                if value.is_empty() || value.len() > 4096 {
                    return problem(400, "X-WOPI-Lock is required", &c, request_id.clone());
                }
                let operation = header(&r, "x-wopi-override").trim().to_uppercase();
                let old = Some(header(&r, "x-wopi-oldlock")).filter(|v| !v.is_empty());
                let Some(id) = crate::jmap::random() else {
                    return problem(500, "request failed", &c, request_id.clone());
                };
                let response =
                    match setjoin_office::lock(&exec, &p, &token, &operation, value, old, id).await
                    {
                        setjoin_pg::CommandOutcome::Committed(out) => {
                            let mut reply = crate::jmap::reply::response(
                                String::new(),
                                c.identity.proto,
                                request_id.clone(),
                            );
                            reply.headers_mut().remove("content-type");
                            if out["conflict"] == true {
                                *reply.status_mut() = hyper::StatusCode::CONFLICT;
                                reply.headers_mut().insert(
                                    "x-wopi-lock",
                                    out["currentLock"].as_str().unwrap_or("").parse().unwrap(),
                                );
                                reply.headers_mut().insert(
                                    "x-wopi-lockfailurereason",
                                    "The file is locked by another editor session"
                                        .parse()
                                        .unwrap(),
                                );
                            }
                            reply
                        }
                        setjoin_pg::CommandOutcome::RolledBack(reason) => {
                            let e = match reason {
                                setjoin_pg::Rejection::Body(e)
                                | setjoin_pg::Rejection::Statement(e) => e,
                                _ => setjoin_pg::StatementFailure {
                                    sqlstate: None,
                                    hint: None,
                                    message: "Office command failed".into(),
                                },
                            };
                            reducer_problem(&e, r.uri().path(), false, &c, request_id.clone())
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            let mut reply =
                                problem(503, "commit outcome unknown", &c, request_id.clone());
                            reply.headers_mut().insert(
                                "x-operation-id",
                                crate::jmap::reply::hex(&operation.0).parse().unwrap(),
                            );
                            reply
                        }
                    };
                return response;
            }
            if contents {
                let chunks = p["manifest"].as_array().cloned().unwrap_or_default();
                let size = p["size"].as_i64().unwrap_or(-1);
                if chunks.is_empty()
                    || chunks
                        .iter()
                        .try_fold(0i64, |sum, c| sum.checked_add(c["size"].as_i64()?))
                        != Some(size)
                {
                    return problem(
                        500,
                        "Office file content is unavailable",
                        &c,
                        request_id.clone(),
                    );
                }
                let Some(store) = store else {
                    return problem(
                        500,
                        "Office file content is unavailable",
                        &c,
                        request_id.clone(),
                    );
                };
                // Go buffers a small response before committing its head. An abort in
                // that buffer reaches the front door as 502, without a successful body.
                if size <= 2048 || r.method() == Method::HEAD {
                    let mut bytes = Vec::new();
                    for chunk in &chunks {
                        let n = chunk["size"].as_u64().unwrap_or(0) as usize;
                        let part = match store
                            .read_prefix(chunk["storageRef"].as_str().unwrap_or(""), n)
                            .await
                        {
                            Ok(v) => v,
                            Err(_) => {
                                return crate::proxy::status(
                                    hyper::StatusCode::BAD_GATEWAY,
                                    "bad gateway\n",
                                )
                            }
                        };
                        if part.len() != n
                            || setjoin_office::token_hash_bytes(&part)
                                != chunk["sha256"].as_str().unwrap_or("")
                        {
                            return crate::proxy::status(
                                hyper::StatusCode::BAD_GATEWAY,
                                "bad gateway\n",
                            );
                        }
                        if r.method() != Method::HEAD {
                            bytes.extend_from_slice(&part);
                        }
                    }
                    let mut reply = crate::jmap::reply::response(
                        String::new(),
                        c.identity.proto,
                        request_id.clone(),
                    );
                    *reply.body_mut() = http_body_util::Full::new(bytes::Bytes::from(bytes))
                        .map_err(|never| match never {})
                        .boxed();
                    reply.headers_mut().insert(
                        "content-type",
                        p["contentType"]
                            .as_str()
                            .unwrap_or("application/octet-stream")
                            .parse()
                            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
                    );
                    reply
                        .headers_mut()
                        .insert("content-length", size.to_string().parse().unwrap());
                    reply.headers_mut().insert(
                        "x-wopi-itemversion",
                        p["versionId"].to_string().parse().unwrap(),
                    );
                    return reply;
                }
                let body = futures_util::stream::unfold(
                    (store, chunks, 0usize, false),
                    |(store, chunks, index, failed)| async move {
                        if failed {
                            return Some((
                                Err::<hyper::body::Frame<bytes::Bytes>, crate::BoxError>(
                                    "Office chunk verification failed".into(),
                                ),
                                (store, chunks, chunks_len_sentinel(), false),
                            ));
                        }
                        if index >= chunks.len() {
                            return None;
                        }
                        let chunk = &chunks[index];
                        let key = chunk["storageRef"].as_str().unwrap_or("");
                        let size = chunk["size"].as_u64().unwrap_or(0) as usize;
                        let bytes = match store.read_prefix(key, size).await {
                            Ok(b) => b,
                            Err(e) => {
                                return Some((
                                    Err(e.into()),
                                    (store, chunks, chunks_len_sentinel(), false),
                                ))
                            }
                        };
                        let valid = bytes.len() >= size
                            && setjoin_office::token_hash_bytes(&bytes[..bytes.len().min(size)])
                                == chunk["sha256"].as_str().unwrap_or("");
                        let data = bytes::Bytes::copy_from_slice(&bytes[..bytes.len().min(size)]);
                        Some((
                            Ok(hyper::body::Frame::data(data)),
                            (store, chunks, index + 1, !valid),
                        ))
                    },
                );
                let mut response = crate::jmap::reply::response(
                    String::new(),
                    c.identity.proto,
                    request_id.clone(),
                );
                *response.body_mut() = ChunkBody(std::sync::Mutex::new(Box::pin(body))).boxed();
                response.headers_mut().insert(
                    "content-type",
                    p["contentType"]
                        .as_str()
                        .unwrap_or("application/octet-stream")
                        .parse()
                        .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
                );
                response
                    .headers_mut()
                    .insert("content-length", size.to_string().parse().unwrap());
                response.headers_mut().insert(
                    "x-wopi-itemversion",
                    p["versionId"].to_string().parse().unwrap(),
                );
                return response;
            }
            let value = serde_json::json!({"BaseFileName":p["name"],"OwnerId":p["spaceId"].to_string(),"Size":p["size"],"UserId":p["actorUserId"].to_string(),"UserFriendlyName":"Setjoin user","Version":p["versionId"].to_string(),"SupportsLocks":true,"SupportsUpdate":true,"UserCanWrite":p["canWrite"],"ReadOnly":p["canWrite"]==false});
            crate::jmap::reply::response(
                crate::recovery::go_json(&value),
                c.identity.proto,
                request_id.clone(),
            )
        })
    }
}

fn problem(status: u16, detail: &str, c: &RequestContext, request_id: String) -> Response<Body> {
    let title = crate::problem::title(status);
    let body=format!("{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":\"\"}}\n",serde_json::to_string(title).unwrap(),serde_json::to_string(detail).unwrap());
    let mut response = crate::jmap::reply::response(body, c.identity.proto, request_id);
    *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

pub(crate) fn reducer_problem(
    e: &setjoin_pg::StatementFailure,
    path: &str,
    admin: bool,
    c: &RequestContext,
    request_id: String,
) -> Response<Body> {
    let (status, detail, slug) = match e.sqlstate.as_deref() {
        Some("BZ321") => (404, "notFound", "not-found"),
        Some("BZ322") => (400, "invalidArguments", "invalid-arguments"),
        Some("BZ323") => (403, "forbidden", "forbidden"),
        Some("BZ324") => (
            409,
            "stateMismatch",
            if admin {
                "state-mismatch"
            } else {
                "session-stale"
            },
        ),
        Some("BZ325") => (409, "conflict", "lock-conflict"),
        Some("BZ326") => (409, "stateMismatch", "replay-conflict"),
        Some("BZ327") => (409, "conflict", "provider-unavailable"),
        // Office uses the shared classifier for Drive errors, without Drive's
        // route-specific quota/lock status overrides or Office error slugs.
        Some("BZ139") => (404, "notFound", ""),
        Some("BZ140" | "BZ253") => (403, "forbidden", ""),
        Some("BZ141" | "BZ144") => (422, "unprocessable", ""),
        Some(
            "BZ142" | "BZ143" | "BZ145" | "BZ146" | "BZ147" | "BZ149" | "BZ150" | "BZ254" | "BZ255"
            | "BZ256",
        ) => (409, "conflict", ""),
        Some("BZ148") => (507, "overQuota", ""),
        Some("BZ252") => (400, "invalidArguments", ""),
        _ => (500, "request failed", ""),
    };
    let mut response = problem(status, detail, c, request_id);
    let title = crate::problem::title(status);
    let kind = if slug.is_empty() {
        "about:blank".to_owned()
    } else {
        format!("https://setjoin.com/problems/office/{slug}")
    };
    let code = if slug.is_empty() {
        String::new()
    } else {
        format!(
            ",\"code\":{}",
            serde_json::to_string(e.sqlstate.as_ref().unwrap()).unwrap()
        )
    };
    let body = format!(
        "{{\"type\":{},\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}{code}}}\n",
        serde_json::to_string(&kind).unwrap(),
        serde_json::to_string(title).unwrap(),
        serde_json::to_string(detail).unwrap(),
        serde_json::to_string(
            decoded_path(path)
                .strip_prefix("/api")
                .unwrap_or(&decoded_path(path))
        )
        .unwrap()
    );
    *response.body_mut() = http_body_util::Full::new(bytes::Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    response
        .headers_mut()
        .insert("content-language", "en".parse().unwrap());
    response
}

fn chunks_len_sentinel() -> usize {
    usize::MAX
}

type ChunkStream = std::pin::Pin<
    Box<
        dyn futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, crate::BoxError>>
            + Send,
    >,
>;
struct ChunkBody(std::sync::Mutex<ChunkStream>);
impl hyper::body::Body for ChunkBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.get_mut()
            .0
            .get_mut()
            .expect("body mutex")
            .as_mut()
            .poll_next(cx)
    }
}

pub(crate) fn command_result<T>(
    out: setjoin_pg::CommandOutcome<T, setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    request_id: &str,
) -> Result<T, Response<Body>> {
    match out {
        setjoin_pg::CommandOutcome::Committed(v) => Ok(v),
        setjoin_pg::CommandOutcome::RolledBack(reason) => {
            let e = match reason {
                setjoin_pg::Rejection::Body(e) | setjoin_pg::Rejection::Statement(e) => e,
                _ => setjoin_pg::StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "Office command failed".into(),
                },
            };
            Err(reducer_problem(
                &e,
                path,
                path.starts_with("/api/admin/"),
                c,
                request_id.into(),
            ))
        }
        setjoin_pg::CommandOutcome::Unknown { operation } => {
            let mut reply = problem(503, "commit outcome unknown", c, request_id.into());
            reply.headers_mut().insert(
                "x-operation-id",
                crate::jmap::reply::hex(&operation.0).parse().unwrap(),
            );
            Err(reply)
        }
    }
}
async fn put_file(
    mut r: Request<Body>,
    c: RequestContext,
    exec: ScopedExecutor,
    p: setjoin_office::Launch,
    token: String,
    store: Option<std::sync::Arc<crate::recovery_worker::S3Store>>,
) -> Response<Body> {
    use sha2::{Digest, Sha256};
    let path = decoded_path(r.uri().path());
    let request_id = request_id(&r);
    if p["canWrite"] != true {
        return problem(403, "file is read-only", &c, request_id.clone());
    }
    match setjoin_office::callback_allowed(&exec, &p, &token).await {
        Ok(true) => {}
        Ok(false) => {
            return problem(
                403,
                "Office write authority is no longer current",
                &c,
                request_id.clone(),
            )
        }
        Err(e) => return reducer_problem(&e, &path, false, &c, request_id.clone()),
    }
    let Some(store) = store else {
        return problem(500, "Office save staging failed", &c, request_id.clone());
    };
    let mut whole = Sha256::new();
    let mut manifest = Vec::new();
    let mut buffer = Vec::with_capacity(4 << 20);
    let mut total = 0i64;
    while let Some(frame) = r.body_mut().frame().await {
        let Ok(frame) = frame else {
            return problem(
                400,
                "Office save body could not be read",
                &c,
                request_id.clone(),
            );
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let mut slice = data.as_ref();
        while !slice.is_empty() {
            let take = slice.len().min((4 << 20) - buffer.len());
            buffer.extend_from_slice(&slice[..take]);
            slice = &slice[take..];
            if total + buffer.len() as i64 > 200 << 20 {
                return problem(413, "Office save exceeds 200 MiB", &c, request_id.clone());
            }
            if buffer.len() == 4 << 20 {
                whole.update(&buffer);
                total += buffer.len() as i64;
                match stage_chunk(&exec, &p, &store, &buffer, &path, &c, &request_id).await {
                    Ok(sha) => manifest.push(serde_json::json!({"sha256":sha,"size":buffer.len()})),
                    Err(reply) => return reply,
                }
                buffer.clear();
            }
        }
    }
    if !buffer.is_empty() {
        whole.update(&buffer);
        total += buffer.len() as i64;
        match stage_chunk(&exec, &p, &store, &buffer, &path, &c, &request_id).await {
            Ok(sha) => manifest.push(serde_json::json!({"sha256":sha,"size":buffer.len()})),
            Err(reply) => return reply,
        }
    }
    let sha = format!("{:x}", whole.finalize());
    let supplied = header(&r, "x-setjoin-operation-key").trim();
    let key = if supplied.is_empty() {
        setjoin_office::token_hash(&format!(
            "{}:{}:{sha}",
            p["launchId"].as_str().unwrap_or(""),
            p["versionId"]
        ))
    } else {
        supplied.to_owned()
    };
    let lock = r
        .headers()
        .get("x-wopi-lock")
        .filter(|v| !v.is_empty())
        .map(|v| setjoin_office::token_hash_bytes(v.as_bytes()));
    let manifest = serde_json::to_string(&manifest).unwrap();
    let Some(operation) = crate::jmap::random() else {
        return problem(500, "Office save result invalid", &c, request_id.clone());
    };
    let result = setjoin_office::save(
        &exec,
        &p,
        setjoin_office::Save {
            token: &token,
            key: &key,
            sha: &sha,
            size: total,
            manifest: &manifest,
            lock,
        },
        operation,
    )
    .await;
    match command_result(result, &path, &c, &request_id) {
        Ok(value) => {
            let mut reply = crate::jmap::reply::response(
                crate::recovery::go_json(&value),
                c.identity.proto,
                request_id.clone(),
            );
            if let Some(v) = value.get("versionId") {
                reply
                    .headers_mut()
                    .insert("x-wopi-itemversion", v.to_string().parse().unwrap());
            }
            reply
        }
        Err(reply) => reply,
    }
}
async fn stage_chunk(
    exec: &ScopedExecutor,
    p: &setjoin_office::Launch,
    store: &std::sync::Arc<crate::recovery_worker::S3Store>,
    bytes: &[u8],
    path: &str,
    c: &RequestContext,
    request_id: &str,
) -> Result<String, Response<Body>> {
    let Some(operation) = crate::jmap::random() else {
        return Err(problem(
            500,
            "Office save staging failed",
            c,
            request_id.into(),
        ));
    };
    let key = format!("tmp/upload/{}", crate::jmap::reply::hex(&operation));
    let sha = setjoin_office::token_hash_bytes(bytes);
    if store
        .put(&key, bytes, "application/octet-stream")
        .await
        .is_err()
    {
        return Err(problem(
            500,
            "Office save staging failed",
            c,
            request_id.into(),
        ));
    }
    let from = key.clone();
    let target = store.clone();
    let outcome = setjoin_office::commit_chunk(
        exec,
        p,
        &sha,
        bytes.len() as i32,
        operation,
        move |to| async move {
            target
                .promote(&from, &to)
                .await
                .map_err(|_| setjoin_pg::StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "Office copy failed".into(),
                })
        },
    )
    .await;
    let _ = store.remove(&key).await;
    command_result(outcome, path, c, request_id)?;
    Ok(sha)
}

pub struct OfficeAdminRoute<K: setjoin_authz::token::KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: std::sync::Arc<K>,
    pub issuer: String,
    pub provider_client: Option<reqwest::Client>,
}
impl<K: setjoin_authz::token::KeySource + 'static> Intercept for OfficeAdminRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        (matches!(*r.method(), Method::GET | Method::HEAD)
            && crate::inventory::path_score("/api/admin/office", r.uri().path()).is_some())
            || (matches!(*r.method(), Method::PUT | Method::POST | Method::DELETE)
                && [
                    "/api/admin/office/providers/{providerId}",
                    "/api/admin/office/providers/{providerId}/qualify",
                    "/api/admin/office/providers/{providerId}/activate",
                ]
                .iter()
                .any(|p| crate::inventory::path_score(p, r.uri().path()).is_some()))
    }
    fn admits_member(&self, h: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let exec = self.exec.clone();
        let keys = self.keys.clone();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &h, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let exec = self.exec.clone();
        let keys = self.keys.clone();
        let issuer = self.issuer.clone();
        let provider_client = self.provider_client.clone();
        Box::pin(async move {
            let request_id = request_id(&r);
            let Some(auth) = setjoin_authz::authorize_request(
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
            let actor = auth.context();
            let user = actor.user_id();
            let perm = if matches!(*r.method(), Method::GET | Method::HEAD) {
                "office.view|office.manage"
            } else {
                "office.manage"
            };
            let permission = if actor.signed_admin() {
                match exec.read("SELECT drive_has_admin_perm($1,'office.manage') OR ($2 AND drive_has_admin_perm($1,'office.view'))",&[(&user,setjoin_pg::Type::INT8),(&(perm.contains('|')),setjoin_pg::Type::BOOL)]).await{Ok(rows)=>rows[0].get(0),Err(_)=>return c.upstream.forward(r,&c.identity).await}
            } else {
                false
            };
            if !permission {
                let path = r
                    .uri()
                    .path()
                    .strip_prefix("/api")
                    .unwrap_or(r.uri().path());
                let email = verified_email(r.headers());
                let before =
                    serde_json::json!({"actor":email,"target":path,"missingPermission":perm})
                        .to_string();
                if let Some(operation) = crate::jmap::random() {
                    let _ = setjoin_office::console_denied(&exec, actor, &before, path, operation)
                        .await;
                }
                return problem(403, "Forbidden", &c, request_id.clone());
            }

            if !matches!(*r.method(), Method::GET | Method::HEAD)
                && header(&r, "x-audit-reason").is_empty()
            {
                let required = exec
                    .read(
                        "SELECT 'office'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
                        &[],
                    )
                    .await
                    .ok()
                    .and_then(|rows| rows.first().map(|r| r.get::<_, bool>(0)))
                    .unwrap_or(false);
                if required {
                    if let Some(operation) = crate::jmap::random() {
                        let _ = setjoin_office::reason_missing(
                            &exec,
                            actor,
                            &c.identity.client_ip.to_string(),
                            operation,
                        )
                        .await;
                    }
                    return problem(400, "reason_required", &c, request_id.clone());
                }
            }
            if r.method() == Method::DELETE {
                let provider = provider_id(r.uri().path());
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &c, request_id.clone());
                };
                let out = setjoin_office::remove(
                    &exec,
                    actor,
                    &provider,
                    header(&r, "x-audit-reason"),
                    operation,
                )
                .await;
                return match command_result(out, r.uri().path(), &c, &request_id) {
                    Ok(v) => crate::jmap::reply::response(
                        v.to_string(),
                        c.identity.proto,
                        request_id.clone(),
                    ),
                    Err(reply) => reply,
                };
            }
            if r.method() == Method::POST && decoded_path(r.uri().path()).ends_with("/qualify") {
                let path = decoded_path(r.uri().path());
                let reason = header(&r, "x-audit-reason").to_owned();
                let provider = provider_id(r.uri().path());
                let body = match admin_body(
                    r,
                    &[
                        "expectedgeneration",
                        "syntheticreceiptid",
                        "builddigest",
                        "routerevision",
                    ],
                    &c,
                    &request_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(reply) => return reply,
                };
                let receipt = body
                    .get("syntheticreceiptid")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                if receipt <= 0 {
                    return problem(
                        400,
                        "syntheticReceiptId must be positive",
                        &c,
                        request_id.clone(),
                    );
                }
                let generation = body
                    .get("expectedgeneration")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let target =
                    match setjoin_office::qualification_target(&exec, actor, &provider, generation)
                        .await
                    {
                        Ok(t) => t,
                        Err(e) => return reducer_problem(&e, &path, true, &c, request_id.clone()),
                    };
                if target["providerId"].as_str().is_none_or(|v| v.is_empty())
                    || target["generation"].as_i64().unwrap_or(0) <= 0
                    || target["configSha256"].as_str().unwrap_or("").len() != 64
                {
                    return problem(
                        500,
                        "Office qualification target is invalid",
                        &c,
                        request_id.clone(),
                    );
                }
                let (checks, fingerprint) = match crate::office_provider::qualify_with_client(
                    &target,
                    provider_client.as_ref(),
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        return problem(
                            409,
                            &format!("Office provider qualification failed: {e}"),
                            &c,
                            request_id.clone(),
                        )
                    }
                };
                let revision = body
                    .get("routerevision")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
                    .max(1);
                let build = body
                    .get("builddigest")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.is_empty());
                let checks = checks.to_string();
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &c, request_id.clone());
                };
                let out = setjoin_office::qualify(
                    &exec,
                    actor,
                    setjoin_office::Qualification {
                        provider: target["providerId"].as_str().unwrap(),
                        generation: target["generation"].as_i64().unwrap(),
                        profile: target["profile"].as_str().unwrap_or(""),
                        config_sha: target["configSha256"].as_str().unwrap(),
                        checks: &checks,
                        fingerprint: &fingerprint,
                        build,
                        route_revision: revision,
                        receipt,
                        reason: &reason,
                    },
                    operation,
                )
                .await;
                return match command_result(out, &path, &c, &request_id) {
                    Ok(v) => crate::jmap::reply::response(
                        v.to_string(),
                        c.identity.proto,
                        request_id.clone(),
                    ),
                    Err(reply) => reply,
                };
            }
            if r.method() == Method::POST {
                let path = decoded_path(r.uri().path());
                let reason = header(&r, "x-audit-reason").to_owned();
                let provider = provider_id(r.uri().path());
                let body = match admin_body(
                    r,
                    &["expectedgeneration", "qualificationid", "scope"],
                    &c,
                    &request_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(reply) => return reply,
                };
                let Some(qualification) = body
                    .get("qualificationid")
                    .and_then(|v| v.as_str())
                    .and_then(setjoin_office::uuid)
                else {
                    return problem(
                        400,
                        "qualificationId must be a UUID",
                        &c,
                        request_id.clone(),
                    );
                };
                let scope =
                    serde_json::to_string(body.get("scope").unwrap_or(&serde_json::json!({})))
                        .unwrap();
                let generation = body
                    .get("expectedgeneration")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &c, request_id.clone());
                };
                let out = setjoin_office::activate(
                    &exec,
                    actor,
                    &provider,
                    generation,
                    &qualification,
                    &scope,
                    &reason,
                    operation,
                )
                .await;
                return match command_result(out, &path, &c, &request_id) {
                    Ok(value) => crate::jmap::reply::response(
                        value.to_string(),
                        c.identity.proto,
                        request_id.clone(),
                    ),
                    Err(reply) => reply,
                };
            }
            if r.method() == Method::PUT {
                let provider = provider_id(r.uri().path());
                let path = decoded_path(r.uri().path());
                let reason = header(&r, "x-audit-reason").to_owned();
                let body = match admin_body(
                    r,
                    &[
                        "expectedgeneration",
                        "profile",
                        "entitlementstate",
                        "buildid",
                        "config",
                    ],
                    &c,
                    &request_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(reply) => return reply,
                };
                let Some(config) = body.get("config") else {
                    return problem(400, "config is required", &c, request_id.clone());
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &c, request_id.clone());
                };
                let config = serde_json::to_string(config).unwrap();
                let out = setjoin_office::configure(
                    &exec,
                    actor,
                    setjoin_office::Configure {
                        provider: &provider,
                        generation: body
                            .get("expectedgeneration")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0),
                        profile: body.get("profile").and_then(|v| v.as_str()).unwrap_or(""),
                        entitlement: body
                            .get("entitlementstate")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                        build: body.get("buildid").and_then(|v| v.as_str()),
                        config: &config,
                        reason: &reason,
                    },
                    operation,
                )
                .await;
                return match command_result(out, &path, &c, &request_id) {
                    Ok(value) => crate::jmap::reply::response(
                        crate::jmap::reply::go_compact(&value.to_string()).unwrap(),
                        c.identity.proto,
                        request_id.clone(),
                    ),
                    Err(reply) => reply,
                };
            }
            let raw = exec
                .read(
                    "SELECT office_admin_list($1)::text",
                    &[(&user, setjoin_pg::Type::INT8)],
                )
                .await;
            match raw {
                Ok(rows) => crate::jmap::reply::response(
                    rows[0].get(0),
                    c.identity.proto,
                    request_id.clone(),
                ),
                Err(e) => reducer_problem(&e, r.uri().path(), true, &c, request_id.clone()),
            }
        })
    }
}

// Go preserves valid UTF-8 in opaque locks and audit reasons. HeaderValue's
// to_str is ASCII-only; decode the actual bytes without changing their value.
fn header<'a>(r: &'a Request<Body>, name: &str) -> &'a str {
    r.headers()
        .get(name)
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("")
}

async fn admin_body(
    mut r: Request<Body>,
    allowed: &[&str],
    c: &RequestContext,
    request_id: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Response<Body>> {
    use serde::Deserialize;
    struct Fields(serde_json::Map<String, serde_json::Value>);
    impl<'de> Deserialize<'de> for Fields {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Fields;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Fields, E> {
                    Ok(Fields(serde_json::Map::new()))
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut m: M,
                ) -> Result<Fields, M::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some((k, v)) = m.next_entry::<String, serde_json::Value>()? {
                        let k: String = k
                            .chars()
                            .map(|c| match c {
                                'K' => 'k',
                                'ſ' => 's',
                                _ => c.to_ascii_lowercase(),
                            })
                            .collect();
                        if !v.is_null()
                            && match k.as_str() {
                                "expectedgeneration" | "syntheticreceiptid" | "routerevision" => {
                                    v.as_i64().is_none()
                                }
                                "profile" | "entitlementstate" | "buildid" | "qualificationid"
                                | "builddigest" => !v.is_string(),
                                _ => false,
                            }
                        {
                            return Err(serde::de::Error::custom("invalid field type"));
                        }
                        if v.is_null()
                            && out.contains_key(&k)
                            && matches!(
                                k.as_str(),
                                "expectedgeneration"
                                    | "syntheticreceiptid"
                                    | "routerevision"
                                    | "profile"
                                    | "entitlementstate"
                                    | "qualificationid"
                                    | "builddigest"
                            )
                        {
                            continue;
                        }
                        out.insert(k, v);
                    }
                    Ok(Fields(out))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    let mut bytes = Vec::new();
    let mut limited = false;
    while let Some(frame) = r.body_mut().frame().await {
        let Ok(frame) = frame else {
            limited = true;
            break;
        };
        if let Some(data) = frame.data_ref() {
            let available = (64 << 10) - bytes.len();
            bytes.extend_from_slice(&data[..data.len().min(available)]);
            if data.len() > available {
                limited = true;
                break;
            }
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    let Ok(Fields(fields)) = Fields::deserialize(&mut decoder) else {
        return Err(problem(400, "invalid JSON body", c, request_id.to_owned()));
    };
    if fields.iter().any(|(k, v)| {
        !allowed.contains(&k.as_str())
            || (!v.is_null()
                && match k.as_str() {
                    "expectedgeneration" | "syntheticreceiptid" | "routerevision" => {
                        v.as_i64().is_none()
                    }
                    "profile" | "entitlementstate" | "buildid" | "qualificationid"
                    | "builddigest" => !v.is_string(),
                    _ => false,
                })
    }) {
        return Err(problem(400, "invalid JSON body", c, request_id.to_owned()));
    }
    if limited || decoder.end().is_err() {
        return Err(problem(
            400,
            "exactly one JSON value is required",
            c,
            request_id.to_owned(),
        ));
    }
    Ok(fields)
}

fn verified_email(headers: &hyper::HeaderMap) -> String {
    use base64::Engine;
    setjoin_authz::token::extract(headers)
        .and_then(|t| {
            t.split('.').nth(1).and_then(|s| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .ok()
            })
        })
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["email"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn query_value(raw: &str, name: &str) -> Option<String> {
    fn decode(s: &str) -> Option<String> {
        let mut out = Vec::new();
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'+' {
                out.push(b' ');
                i += 1;
            } else if bytes[i] == b'%' {
                let a = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let b = (*bytes.get(i + 2)? as char).to_digit(16)?;
                out.push((a * 16 + b) as u8);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }
    for pair in raw.split('&') {
        if pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if decode(k).as_deref() == Some(name) {
            if let Some(value) = decode(v) {
                return Some(value);
            }
        }
    }
    None
}

fn request_id(r: &Request<Body>) -> String {
    crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    )
}

fn decoded_path(raw: &str) -> String {
    String::from_utf8_lossy(&crate::inventory::unescape(raw)).into_owned()
}
fn provider_id(raw: &str) -> String {
    raw.split('/').nth(5).map(decoded_path).unwrap_or_default()
}
