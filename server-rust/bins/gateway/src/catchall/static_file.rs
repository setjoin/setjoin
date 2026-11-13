//! HTTP representation framing matching frozen Go's static responder/ServeContent.
use super::*;
use http_body_util::{BodyExt, StreamBody};
use setjoin_static::website::{self, Website};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub(super) async fn serve(site: &Website, r: &Request<Body>, c: &RequestContext) -> Response<Body> {
    if !matches!(*r.method(), Method::GET | Method::HEAD) {
        return plain(r, c, 404, "404 page not found\n");
    }
    let decoded = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path())).into_owned();
    let Some(mut path) = website::contained(&decoded) else {
        return plain(r, c, 404, "404 page not found\n");
    };
    if !tokio::fs::metadata(site.root.join(&path[1..]))
        .await
        .is_ok_and(|m| m.is_file())
    {
        if decoded.starts_with("/_app/") || decoded == "/favicon.ico" {
            return plain(r, c, 404, "404 page not found\n");
        }
        path = "/index.html".into();
    }
    let mut asset = site.record(&path);
    asset.path = path.clone();
    let header = |name: &str| {
        r.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    };
    let Some(selected) = website::choose(
        &asset,
        header("accept-encoding"),
        !header("range").is_empty(),
    ) else {
        let mut reply = plain(r, c, 406, "");
        reply.headers_mut().remove("content-type");
        return reply;
    };
    let mut reply = plain(r, c, 200, "");
    reply
        .headers_mut()
        .insert("vary", "Accept-Encoding".parse().unwrap());
    reply.headers_mut().remove("content-type");
    if selected.coding != "identity" {
        reply
            .headers_mut()
            .insert("content-encoding", selected.coding.parse().unwrap());
    }
    let etag = if selected.hash.is_empty() {
        String::new()
    } else {
        format!("\"sha256-{}\"", selected.hash)
    };
    if !etag.is_empty() {
        reply.headers_mut().insert("etag", etag.parse().unwrap());
    }
    let ext_type = website::content_type(&path);
    if let Some(mime) = &ext_type {
        reply
            .headers_mut()
            .insert("content-type", mime.parse().unwrap());
    }
    let file = site.root.join(selected.path.trim_start_matches('/'));
    let Ok(mut file) = tokio::fs::File::open(file).await else {
        return error(reply, 404, "404 page not found\n");
    };
    let Ok(meta) = file.metadata().await else {
        return error(reply, 404, "404 page not found\n");
    };
    let modified = meta.modified().unwrap_or(UNIX_EPOCH);
    let secs = |time: SystemTime| {
        time.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    if modified != UNIX_EPOCH {
        reply.headers_mut().insert(
            "last-modified",
            httpdate::fmt_http_date(modified).parse().unwrap(),
        );
    }
    let date = |name: &str| httpdate::parse_http_date(header(name)).ok();
    let tags = |name: &str, weak: bool| {
        header(name).split(',').map(str::trim).any(|v| {
            v == "*"
                || (!etag.is_empty()
                    && if weak {
                        v.strip_prefix("W/").unwrap_or(v) == etag
                    } else {
                        v == etag
                    })
        })
    };
    if (!header("if-match").is_empty() && !tags("if-match", false))
        || (header("if-match").is_empty()
            && date("if-unmodified-since").is_some_and(|date| secs(modified) > secs(date)))
    {
        *reply.status_mut() = StatusCode::PRECONDITION_FAILED;
        return reply;
    }
    if (!header("if-none-match").is_empty() && tags("if-none-match", true))
        || (header("if-none-match").is_empty()
            && date("if-modified-since").is_some_and(|date| secs(modified) <= secs(date)))
    {
        *reply.status_mut() = StatusCode::NOT_MODIFIED;
        reply.headers_mut().remove("content-type");
        reply.headers_mut().remove("content-encoding");
        if !etag.is_empty() {
            reply.headers_mut().remove("last-modified");
        }
        reply.headers_mut().insert(
            "cache-control",
            website::request_cache(&decoded, &path).parse().unwrap(),
        );
        return reply;
    }
    if ext_type.is_none() {
        let mut prefix = vec![0; 512];
        let n = file.read(&mut prefix).await.unwrap_or(0);
        prefix.truncate(n);
        let mime = if prefix.starts_with(b"%PDF-") {
            "application/pdf"
        } else if prefix.starts_with(b"\x89PNG\r\n\x1a\n") {
            "image/png"
        } else if prefix.iter().any(|b| matches!(*b,0..=8|11|14..=26|28..=31)) {
            "application/octet-stream"
        } else {
            "text/plain; charset=utf-8"
        };
        reply
            .headers_mut()
            .insert("content-type", mime.parse().unwrap());
    }
    let total = meta.len();
    let mut range = header("range");
    if !header("if-range").is_empty()
        && !(header("if-range") == etag
            || date("if-range").is_some_and(|date| secs(date) == secs(modified)))
    {
        range = "";
    }
    let mut ranges = match parse_ranges(range, total) {
        Ok(ranges) => ranges,
        Err(true) if total == 0 => vec![],
        Err(overlap) => {
            if overlap {
                reply
                    .headers_mut()
                    .insert("content-range", format!("bytes */{total}").parse().unwrap());
            }
            return error(
                reply,
                416,
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
    let mut pieces = std::collections::VecDeque::new();
    let length = match ranges.len() {
        0 => {
            pieces.push_back(Piece::Range(0, total));
            total
        }
        1 => {
            let (start, len) = ranges[0];
            *reply.status_mut() = StatusCode::PARTIAL_CONTENT;
            reply.headers_mut().insert(
                "content-range",
                format!("bytes {start}-{}/{total}", start as i128 + len as i128 - 1)
                    .parse()
                    .unwrap(),
            );
            pieces.push_back(Piece::Range(start, len));
            len
        }
        _ => {
            let mut random = [0; 30];
            if getrandom::getrandom(&mut random).is_err() {
                return error(reply, 500, "random source unavailable\n");
            }
            let boundary = random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let mime = reply
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_owned();
            *reply.status_mut() = StatusCode::PARTIAL_CONTENT;
            reply.headers_mut().insert(
                "content-type",
                format!("multipart/byteranges; boundary={boundary}")
                    .parse()
                    .unwrap(),
            );
            let mut size = 0;
            for (start, len) in ranges {
                let head=format!("--{boundary}\r\nContent-Range: bytes {start}-{}/{total}\r\nContent-Type: {mime}\r\n\r\n",start as i128+len as i128-1);
                size += head.len() as u64 + len + 2;
                pieces.push_back(Piece::Bytes(head.into()));
                pieces.push_back(Piece::Range(start, len));
                pieces.push_back(Piece::Bytes("\r\n".into()));
            }
            let end = format!("--{boundary}--\r\n");
            size += end.len() as u64;
            pieces.push_back(Piece::Bytes(end.into()));
            size
        }
    };
    reply
        .headers_mut()
        .insert("accept-ranges", "bytes".parse().unwrap());
    reply.headers_mut().insert(
        "cache-control",
        website::request_cache(&decoded, &path).parse().unwrap(),
    );
    if selected.coding == "identity"
        || reply.status() == StatusCode::PARTIAL_CONTENT
        || (r.method() != Method::HEAD && length <= 2048)
    {
        reply
            .headers_mut()
            .insert("content-length", length.to_string().parse().unwrap());
    }
    if r.method() == Method::HEAD {
        return reply;
    }
    let stream = futures_util::stream::try_unfold(
        (file, pieces, None),
        |(mut file, mut pieces, mut left): (_, std::collections::VecDeque<Piece>, Option<u64>)| async move {
            loop {
                if let Some(remaining) = left {
                    if remaining > 0 {
                        let mut bytes = vec![0; remaining.min(65536) as usize];
                        let n = file.read(&mut bytes).await?;
                        if n == 0 {
                            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                        }
                        bytes.truncate(n);
                        return Ok(Some((
                            hyper::body::Frame::data(bytes::Bytes::from(bytes)),
                            (file, pieces, Some(remaining - n as u64)),
                        )));
                    }
                    left = None;
                }
                match pieces.pop_front() {
                    None => return Ok::<_, std::io::Error>(None),
                    Some(Piece::Bytes(bytes)) => {
                        return Ok(Some((
                            hyper::body::Frame::data(bytes),
                            (file, pieces, left),
                        )))
                    }
                    Some(Piece::Range(start, len)) => {
                        file.seek(std::io::SeekFrom::Start(start)).await?;
                        left = Some(len);
                    }
                }
            }
        },
    );
    *reply.body_mut() = StreamBody::new(stream)
        .map_err(|e| -> crate::BoxError { Box::new(e) })
        .boxed();
    reply
}
enum Piece {
    Bytes(bytes::Bytes),
    Range(u64, u64),
}

fn error(mut reply: Response<Body>, status: u16, text: &str) -> Response<Body> {
    *reply.status_mut() = StatusCode::from_u16(status).unwrap();
    for name in [
        "etag",
        "last-modified",
        "content-encoding",
        "content-length",
    ] {
        reply.headers_mut().remove(name);
    }
    reply
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    reply
        .headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    crate::problem::set_body(&mut reply, text.into());
    reply
}
/// Go ignores a non-overlapping member if another range is satisfiable.
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
