use super::{JmapCommands, http::problem, reply, token::KeySource};
use crate::{Body, RequestContext};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use setjoin_pg::MailboxAuthContext;

impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn download(
        &self,
        req: &Request<Body>,
        ctx: &RequestContext,
        auth: &MailboxAuthContext,
        id: &str,
    ) -> Response<Body> {
        let services = self.services.as_ref().unwrap();
        let fail = || problem(404, "blobNotFound", "blob not found", ctx, id);
        let segments = req.uri().path()[15..].split('/').collect::<Vec<_>>();
        let account =
            String::from_utf8_lossy(&crate::inventory::unescape(segments[0])).into_owned();
        let hash = String::from_utf8_lossy(&crate::inventory::unescape(segments[1])).into_owned();
        // Owner-approved security fix 2026-11-05 (#478): ownership is decided before the blob
        // metadata is read, so a foreign hash and an unknown hash both answer 404 (frozen Go
        // answered 403 for a known foreign hash, an existence oracle).
        if setjoin_contracts::mutants::on("download-existence-oracle") {
            let known = setjoin_jmap::http_blob::metadata(&services.worker, &hash)
                .await
                .ok()
                .flatten()
                .is_some();
            let allowed =
                setjoin_jmap::http_blob::download_allowed(&services.worker, auth, &account, &hash)
                    .await
                    .unwrap_or(false);
            if !known {
                return fail();
            }
            if !allowed {
                return problem(403, "forbidden", "access denied", ctx, id);
            }
        }
        if !setjoin_jmap::http_blob::download_allowed(&services.worker, auth, &account, &hash)
            .await
            .unwrap_or(false)
        {
            return fail();
        }
        let Some((size, ct)) = setjoin_jmap::http_blob::metadata(&services.worker, &hash)
            .await
            .ok()
            .flatten()
        else {
            return fail();
        };
        let Some(store) = &services.store else {
            return fail();
        };
        if size < 0 || store.stat_size(&hash).await.ok().flatten() != Some(size as u64) {
            return fail();
        }
        let mut response = reply::response(String::new(), ctx.identity.proto, id.into());
        let attachment = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .find(|(k, _)| k == "type")
            .is_some_and(|(_, v)| v == "application/octet-stream");
        let name = sanitize(crate::inventory::unescape(segments[2]));
        let mut disposition = if attachment {
            b"attachment; filename=\"".to_vec()
        } else {
            b"inline; filename=\"".to_vec()
        };
        disposition.extend_from_slice(&name);
        disposition.push(b'"');
        let h = response.headers_mut();
        h.insert(
            "content-type",
            ct.parse().unwrap_or_else(|_| {
                hyper::header::HeaderValue::from_static("application/octet-stream")
            }),
        );
        h.insert("content-length", size.to_string().parse().unwrap());
        if let Ok(value) = hyper::header::HeaderValue::from_bytes(&disposition) {
            h.insert("content-disposition", value);
        }
        h.insert("etag", format!("\"{hash}\"").parse().unwrap());
        h.insert("accept-ranges", "bytes".parse().unwrap());
        h.insert(
            "content-security-policy",
            "default-src 'none'; sandbox".parse().unwrap(),
        );
        h.insert(
            "cache-control",
            "private, max-age=31536000, immutable, no-transform"
                .parse()
                .unwrap(),
        );
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
        };
        let etag = format!("\"{hash}\"");
        if !header("if-match").is_empty() && !etag_matches(header("if-match"), &etag, false) {
            *response.status_mut() = hyper::StatusCode::PRECONDITION_FAILED;
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            response.headers_mut().remove("content-length");
            *response.body_mut() = full(String::new());
            return response;
        }
        if !header("if-none-match").is_empty() && etag_matches(header("if-none-match"), &etag, true)
        {
            *response.status_mut() = hyper::StatusCode::NOT_MODIFIED;
            for name in ["content-type", "content-length", "content-encoding"] {
                response.headers_mut().remove(name);
            }
            *response.body_mut() = full(String::new());
            return response;
        }
        let range = if !header("if-range").is_empty() && header("if-range") != etag {
            ""
        } else {
            header("range")
        };
        let total = size as u64;
        let mut ranges = match parse_ranges(range, total) {
            Ok(ranges) => ranges,
            Err(true) if total == 0 => Vec::new(),
            Err(overlap) => {
                if overlap {
                    response
                        .headers_mut()
                        .insert("content-range", format!("bytes */{total}").parse().unwrap());
                }
                return range_error(
                    response,
                    if overlap {
                        "invalid range: failed to overlap\n"
                    } else {
                        "invalid range\n"
                    },
                );
            }
        };
        if ranges.iter().map(|(_, len)| *len as u128).sum::<u128>() > total as u128 {
            ranges.clear();
        }
        let head = req.method() == hyper::Method::HEAD;
        let mut pieces = Vec::new();
        let (length, status) = match ranges.len() {
            0 => {
                if !head {
                    match store.stream_blob(&hash, total, None).await {
                        Ok(body) => pieces.push(body),
                        Err(_) => return fail(),
                    }
                }
                (total, 200)
            }
            1 => {
                let (start, len) = ranges[0];
                response.headers_mut().insert(
                    "content-range",
                    format!("bytes {start}-{}/{total}", start as i128 + len as i128 - 1)
                        .parse()
                        .unwrap(),
                );
                if !head && len > 0 {
                    match store
                        .stream_blob(&hash, len, Some((start, start + len - 1)))
                        .await
                    {
                        Ok(body) => pieces.push(body),
                        Err(_) => return fail(),
                    }
                }
                (len, 206)
            }
            _ => {
                let Some(a) = super::random() else {
                    return fail();
                };
                let Some(b) = super::random() else {
                    return fail();
                };
                let boundary = format!("{}{}", reply::hex(&a), &reply::hex(&b)[..28]);
                response.headers_mut().insert(
                    "content-type",
                    format!("multipart/byteranges; boundary={boundary}")
                        .parse()
                        .unwrap(),
                );
                let mut length = 0u64;
                for (index, (start, len)) in ranges.iter().copied().enumerate() {
                    let prelude = format!(
                        "{}--{boundary}\r\nContent-Range: bytes {start}-{}/{total}\r\nContent-Type: {ct}\r\n\r\n",
                        if index == 0 { "" } else { "\r\n" },
                        start as i128 + len as i128 - 1
                    );
                    length += prelude.len() as u64 + len;
                    if !head {
                        pieces.push(full(prelude));
                        if len > 0 {
                            match store
                                .stream_blob(&hash, len, Some((start, start + len - 1)))
                                .await
                            {
                                Ok(body) => pieces.push(body),
                                Err(_) => return fail(),
                            }
                        }
                    }
                }
                let end = format!("\r\n--{boundary}--\r\n");
                length += end.len() as u64;
                if !head {
                    pieces.push(full(end));
                }
                (length, 206)
            }
        };
        *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
        response
            .headers_mut()
            .insert("content-length", length.to_string().parse().unwrap());
        use futures_util::{StreamExt, TryStreamExt};
        let stream = futures_util::stream::iter(pieces.into_iter().map(BodyExt::into_data_stream))
            .flatten()
            .map_ok(hyper::body::Frame::data);
        *response.body_mut() = BodyExt::boxed(http_body_util::StreamBody::new(stream));
        response
    }
}
fn sanitize(mut name: Vec<u8>) -> Vec<u8> {
    name.retain(|c| *c >= 32 && *c != 127 && *c != b'"' && *c != b'\\');
    name.truncate(255);
    name
}

fn full(text: String) -> Body {
    Full::new(bytes::Bytes::from(text))
        .map_err(|n| match n {})
        .boxed()
}
fn range_error(mut r: Response<Body>, text: &str) -> Response<Body> {
    *r.status_mut() = hyper::StatusCode::RANGE_NOT_SATISFIABLE;
    for name in [
        "cache-control",
        "content-encoding",
        "etag",
        "last-modified",
        "content-length",
    ] {
        r.headers_mut().remove(name);
    }
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r.headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    *r.body_mut() = full(text.into());
    r
}

// Go net/http range grammar, shared behavior with the static responder.
fn parse_ranges(header: &str, size: u64) -> Result<Vec<(u64, u64)>, bool> {
    if header.is_empty() {
        return Ok(vec![]);
    }
    let Some(raw) = header.strip_prefix("bytes=") else {
        return Err(false);
    };
    let mut ranges = vec![];
    let mut no_overlap = false;
    for raw in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((start, end)) = raw.split_once('-') else {
            return Err(false);
        };
        let integer = |v: &str| {
            v.trim()
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .map(|n| n as u64)
                .ok_or(false)
        };
        if start.is_empty() {
            let len = integer(end)?.min(size);
            ranges.push((size - len, len));
            continue;
        }
        let start = integer(start)?;
        if start >= size {
            no_overlap = true;
            continue;
        }
        let end = if end.trim().is_empty() {
            size - 1
        } else {
            let end = integer(end)?;
            if end < start {
                return Err(false);
            }
            end.min(size - 1)
        };
        ranges.push((start, end - start + 1));
    }
    if no_overlap && ranges.is_empty() {
        Err(true)
    } else {
        Ok(ranges)
    }
}

fn etag_matches(mut raw: &str, expected: &str, weak: bool) -> bool {
    raw = raw.trim();
    if raw == "*" {
        return true;
    }
    loop {
        raw = raw.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == ',');
        let original = raw;
        let value = raw.strip_prefix("W/").unwrap_or(raw);
        if !value.starts_with('"') {
            return false;
        }
        let Some(end) = value[1..].find('"').map(|i| i + 1) else {
            return false;
        };
        if value.as_bytes()[1..end]
            .iter()
            .any(|b| *b < 0x21 || *b == 0x7f)
        {
            return false;
        }
        let tag = &value[..=end];
        if tag == expected && (weak || !original.starts_with("W/")) {
            return true;
        }
        raw = &value[end + 1..];
        if raw.trim().is_empty() {
            return false;
        }
    }
}
