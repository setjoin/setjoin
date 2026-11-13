//! The content byte plane. Authorization completes before a lazy storage stream.
use super::*;
use crate::recovery_worker::S3Store;
use setjoin_authz::AuthContext;
pub(super) fn matches(r: &Request<Body>) -> bool {
    matches!(r.method().as_str(), "GET" | "HEAD")
        && [
            "/api/drive/versions/{id}/content",
            "/api/drive/export/{token}",
        ]
        .iter()
        .any(|p| crate::inventory::path_score(p, r.uri().path()).is_some())
}
pub(super) async fn serve(
    r: Request<Body>,
    path: &str,
    exec: ScopedExecutor,
    actor: AuthContext,
    store: Option<Arc<S3Store>>,
    operation: [u8; 16],
    c: RequestContext,
    id: String,
) -> Response<Body> {
    let consuming =
        crate::inventory::path_score("/api/drive/export/{token}", r.uri().path()).is_some();
    let Some(store) = store else {
        return c.upstream.forward(r, &c.identity).await;
    };
    let version = if consuming {
        use sha2::Digest;
        let token = go_utf8(&crate::inventory::unescape(
            r.uri().path().rsplit('/').next().unwrap_or(""),
        ));
        let hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
        let outcome = setjoin_drive::part_b::simple_write(
            &exec,
            &actor,
            "consume_export",
            0,
            &json!({"tokenHash":hash}),
            operation,
        )
        .await;
        match outcome {
            setjoin_pg::CommandOutcome::Committed(v) => v["versionId"].as_i64().unwrap_or(0),
            setjoin_pg::CommandOutcome::Unknown { operation } => return unknown(operation, &c, id),
            outcome => return super::b::command_response(outcome, 200, path, &c, id),
        }
    } else {
        let raw = go_utf8(&crate::inventory::unescape(
            r.uri().path().split('/').nth(4).unwrap_or(""),
        ));
        match raw.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return problem(400, "invalid version id", Some(path), &c, id),
        }
    };
    let metadata = if consuming {
        setjoin_drive::part_b::content_metadata(&exec, &actor, version).await
    } else {
        setjoin_drive::part_b::content(&exec, &actor, version).await
    };
    let vm = match metadata {
        Ok(Some(v)) => v,
        Ok(None) => {
            return problem(
                404,
                if consuming {
                    "content not found"
                } else {
                    "version not found"
                },
                None,
                &c,
                id,
            )
        }
        Err(_) if consuming => return problem(404, "content not found", None, &c, id),
        Err(e) => return super::b::reducer_problem(&e, path, &c, id),
    };
    if !consuming && vm["classification"] != "regular" {
        let mut response = problem(
            403,
            "secure/gxp original content requires a governed export grant",
            Some(path),
            &c,
            id,
        );
        let body = crate::problem::Problem::new(
            403,
            "secure/gxp original content requires a governed export grant",
        )
        .kind("https://setjoin.com/problems/drive/export-required")
        .instance(path)
        .body();
        crate::problem::set_body(&mut response, body);
        return response;
    }
    if !consuming && vm["auditReads"] == true {
        let outcome = setjoin_drive::part_b::audit_view(
            &exec,
            &actor,
            vm["spaceId"].as_i64().unwrap_or(0),
            version,
            operation,
        )
        .await;
        if !matches!(outcome, setjoin_pg::CommandOutcome::Committed(_)) {
            return super::b::command_response(outcome, 200, path, &c, id);
        }
    }
    let size = vm["size"].as_i64().unwrap_or(0);
    let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
    response.headers_mut().insert(
        "content-type",
        vm["contentType"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("application/octet-stream")
            .replace(['\r', '\n'], " ")
            .parse()
            .unwrap_or_else(|_| {
                hyper::header::HeaderValue::from_static("application/octet-stream")
            }),
    );
    if consuming {
        let name = setjoin_drive::part_b::export_name(&exec, &actor, version).await;
        response.headers_mut().insert(
            "content-disposition",
            format!(
                "attachment; filename={}",
                serde_json::to_string(&name).unwrap()
            )
            .parse()
            .unwrap(),
        );
    } else {
        response
            .headers_mut()
            .insert("content-disposition", "inline".parse().unwrap());
        response
            .headers_mut()
            .insert("accept-ranges", "bytes".parse().unwrap());
        response.headers_mut().insert(
            "content-security-policy",
            "default-src 'none'; sandbox".parse().unwrap(),
        );
    }
    let range = if consuming {
        None
    } else {
        r.headers()
            .get("range")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
    };
    let (start, end, ranged) = if let Some(range) = range {
        match single_range(range, size) {
            Some((start, end)) => {
                *response.status_mut() = hyper::StatusCode::PARTIAL_CONTENT;
                response.headers_mut().insert(
                    "content-range",
                    format!("bytes {start}-{end}/{size}").parse().unwrap(),
                );
                (start, end, true)
            }
            None => {
                let mut error = problem(416, "invalid or multipart Range", None, &c, id);
                for key in [
                    "content-disposition",
                    "accept-ranges",
                    "content-security-policy",
                ] {
                    error
                        .headers_mut()
                        .insert(key, response.headers()[key].clone());
                }
                let value = crate::problem::Problem::new(416, "invalid or multipart Range").body();
                crate::problem::set_body(&mut error, value);
                return error;
            }
        }
    } else {
        (0, size - 1, false)
    };
    let length = if ranged { end - start + 1 } else { size };
    response
        .headers_mut()
        .insert("content-length", length.to_string().parse().unwrap());
    let mut body = stream(store, &vm["manifest"], start, end, ranged);
    if r.method() == hyper::Method::HEAD {
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
    } else {
        *response.body_mut() = body;
    }
    response
}
fn single_range(raw: &str, size: i64) -> Option<(i64, i64)> {
    let raw = raw.strip_prefix("bytes=")?;
    if raw.contains(',') {
        return None;
    }
    let (a, b) = raw.split_once('-')?;
    if a.is_empty() {
        return None;
    }
    let start = a.parse::<i64>().ok()?;
    if start < 0 || start >= size {
        return None;
    }
    let end = if b.is_empty() {
        size - 1
    } else {
        b.parse::<i64>().ok()?
    };
    if end < start {
        return None;
    }
    Some((start, end.min(size - 1)))
}
type Frames = std::pin::Pin<
    Box<
        dyn futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, crate::BoxError>>
            + Send,
    >,
>;
struct ContentBody(std::sync::Mutex<Frames>);
impl hyper::body::Body for ContentBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.get_mut()
            .0
            .get_mut()
            .expect("exclusive body polling")
            .as_mut()
            .poll_next(cx)
    }
}
pub(super) fn stream(
    store: Arc<S3Store>,
    manifest: &Value,
    start: i64,
    end: i64,
    ranged: bool,
) -> Body {
    let first = start / (4 << 20);
    let last = end / (4 << 20);
    let chunks: Vec<(String, u64, Option<(u64, u64)>)> = manifest
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(i, c)| {
            let i = i as i64;
            if i < first || i > last {
                return None;
            }
            let size = c["size"].as_i64().unwrap_or(0);
            let range = if ranged {
                Some((
                    if i == first {
                        (start % (4 << 20)) as u64
                    } else {
                        0
                    },
                    if i == last {
                        (end - i * (4 << 20)) as u64
                    } else {
                        size.saturating_sub(1) as u64
                    },
                ))
            } else {
                None
            };
            let size = range.map_or(size as u64, |(a, b)| b - a + 1);
            Some((c["key"].as_str().unwrap_or("").into(), size, range))
        })
        .collect();
    let frames = futures_util::stream::unfold(
        (store, chunks, 0usize, None::<Body>, false),
        |mut state| async move {
            loop {
                if state.4 {
                    return None;
                }
                if let Some(body) = state.3.as_mut() {
                    match body.frame().await {
                        Some(Ok(frame)) => return Some((Ok(frame), state)),
                        Some(Err(e)) => {
                            state.4 = true;
                            return Some((Err(e), state));
                        }
                        None => state.3 = None,
                    }
                } else {
                    let Some((key, size, range)) = state.1.get(state.2) else {
                        return None;
                    };
                    state.2 += 1;
                    match state.0.stream_blob(key, *size, *range).await {
                        Ok(body) => state.3 = Some(body),
                        Err(_) => {
                            state.4 = true;
                            return Some((Err("Drive content storage read failed".into()), state));
                        }
                    }
                }
            }
        },
    );
    crate::proxy::committed_body(ContentBody(std::sync::Mutex::new(Box::pin(frames))).boxed())
}

pub(super) fn frames<S>(frames: S) -> Body
where
    S: futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, crate::BoxError>>
        + Send
        + 'static,
{
    crate::proxy::committed_body(ContentBody(std::sync::Mutex::new(Box::pin(frames))).boxed())
}
