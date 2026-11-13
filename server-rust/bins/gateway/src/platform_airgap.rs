//! Frozen Go's airgap HTTP framing, alongside the authenticated Platform store.
use crate::{Body, RequestContext};
use hyper::Response;
pub(crate) fn plain(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let mut response =
        crate::jmap::reply::response(format!("{detail}\n"), c.identity.proto, id.to_owned());
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("fixed airgap status");
    response
        .headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    response
}

use futures_util::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::{Method, Request, StatusCode};
use std::time::UNIX_EPOCH;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
pub(crate) async fn file(
    store: &setjoin_platform::airgap::Store,
    r: &Request<Body>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    if r.method() != Method::GET {
        return plain(405, "method not allowed", c, id);
    }
    let slug = crate::mailboxes::segment(r.uri().path(), 3);
    let filename = crate::mailboxes::segment(r.uri().path(), 4);
    if slug.is_empty() || filename.is_empty() {
        return plain(400, "slug and filename are required", c, id);
    }
    if [&slug, &filename]
        .iter()
        .any(|part| matches!(part.as_str(), "." | "..") || part.contains('/'))
    {
        return plain(400, "invalid path", c, id);
    }
    let Some(path) = store.file(&slug, &filename) else {
        return plain(404, "404 page not found", c, id);
    };
    let mut reply = crate::jmap::reply::response(String::new(), c.identity.proto, id.to_owned());
    reply
        .headers_mut()
        .insert("content-type", "application/octet-stream".parse().unwrap());
    let disposition = format!(
        "attachment; filename={}",
        setjoin_contracts::go_quote::quote(filename.as_bytes())
    );
    if let Ok(value) = disposition.parse() {
        reply.headers_mut().insert("content-disposition", value);
    }
    reply.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; sandbox".parse().unwrap(),
    );
    if r.uri().path().ends_with("/index.html") {
        *reply.status_mut() = StatusCode::MOVED_PERMANENTLY;
        let location = r
            .uri()
            .query()
            .map(|q| format!("./?{q}"))
            .unwrap_or_else(|| "./".into());
        reply
            .headers_mut()
            .insert("location", location.parse().unwrap());
        return reply;
    }
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(e) => return file_error(reply, e),
    };
    let meta = match file.metadata().await {
        Ok(meta) => meta,
        Err(e) => return file_error(reply, e),
    };
    if let Ok(modified) = meta.modified() {
        if modified != UNIX_EPOCH {
            reply.headers_mut().insert(
                "last-modified",
                httpdate::fmt_http_date(modified).parse().unwrap(),
            );
        }
    }
    let Some(range) = crate::blob_content::preconditions(r, &mut reply) else {
        return reply;
    };
    let total = meta.len();
    let mut ranges = match crate::blob_content::parse_ranges(&range, total) {
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
    reply
        .headers_mut()
        .insert("content-length", length.to_string().parse().unwrap());
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

fn file_error(reply: Response<Body>, error: std::io::Error) -> Response<Body> {
    let (status, text) = match error.kind() {
        std::io::ErrorKind::NotFound => (404, "404 page not found\n"),
        std::io::ErrorKind::PermissionDenied => (403, "403 Forbidden\n"),
        _ => (500, "500 Internal Server Error\n"),
    };
    self::error(reply, status, text)
}

pub(crate) async fn upload(
    store: std::sync::Arc<setjoin_platform::airgap::Store>,
    r: &mut Request<Body>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    const CAP: usize = 100 << 20;
    let boundary = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| multer::parse_boundary(v).ok());
    let (query, bad_query) = crate::mailbox_io::parse_query(r.uri().query());
    let parsed = async {
        let boundary = boundary.ok_or(())?;
        let body = std::mem::replace(
            r.body_mut(),
            http_body_util::Full::new(bytes::Bytes::new())
                .map_err(|n| match n {})
                .boxed(),
        );
        let mut total = 0usize;
        let stream = body.into_data_stream().map(|chunk| -> Result<bytes::Bytes,crate::BoxError> {
            let bytes=chunk?;
            total=total.checked_add(bytes.len()).ok_or_else(||std::io::Error::other("multipart too large"))?;
            if total>CAP{return Err(std::io::Error::other("multipart too large").into());}
            Ok(bytes)
        });
        let mut form = multer::Multipart::new(stream, boundary);
        let mut values = vec![];
        let mut file = None;
        let mut count = 0;
        while let Some(field) = form.next_field().await.map_err(|_| ())? {
            count += 1;
            if count > 1000 {
                return Err(());
            }
            let name = field.name().unwrap_or("").to_owned();
            let filename = field
                .file_name()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let bytes = field.bytes().await.map_err(|_| ())?;
            if name.is_empty() {
                continue;
            }
            match filename {
                Some(filename) => {
                    if name == "file" && file.is_none() {
                        file = Some((filename, bytes.to_vec()));
                    }
                }
                None => values.push((name, crate::guests_input::go_utf8(&bytes))),
            }
        }
        if bad_query {
            return Err(());
        }
        let value = |key: &str| {
            query
                .iter()
                .chain(values.iter())
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
                .unwrap_or_default()
        };
        Ok((value("slug"), value("metadata"), file))
    }
    .await;
    let (slug, metadata, file) = match parsed {
        Ok(value) => value,
        Err(()) => return plain(400, "file too large or invalid multipart form", c, id),
    };
    let result = tokio::task::spawn_blocking(move || store.upload(slug, metadata, file)).await;
    match result {
        Ok(Ok(bundle)) => crate::jmap::reply::response(
            setjoin_platform::airgap::Store::encode_bundle(&bundle),
            c.identity.proto,
            id.to_owned(),
        ),
        Ok(Err(error)) => plain(error.status, &error.detail, c, id),
        Err(_) => plain(500, "internal server error", c, id),
    }
}
