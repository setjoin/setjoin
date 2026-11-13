//! Go's byte-range response projection, after the caller has checked authority.
//! Object parts open lazily; dropping the response cancels its current S3 read.
use crate::{
    Body, BoxError,
    recovery_worker::{BlobReadError, S3Store},
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Frame};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

pub(crate) async fn serve_ranges(
    req: &Request<Body>,
    mut response: Response<Body>,
    store: Arc<S3Store>,
    hash: &str,
    total: u64,
    buffered: Option<Bytes>,
) -> Result<Response<Body>, BlobReadError> {
    let Some(raw) = preconditions(req, &mut response) else {
        return Ok(response);
    };
    let mut ranges = match parse_ranges(&raw, total) {
        Ok(ranges) => ranges,
        Err(true) if total == 0 => vec![],
        Err(overlap) => {
            if overlap {
                response
                    .headers_mut()
                    .insert("content-range", format!("bytes */{total}").parse().unwrap());
            }
            let text = if overlap {
                "invalid range: failed to overlap\n"
            } else {
                "invalid range\n"
            };
            *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
            for name in [
                "cache-control",
                "content-encoding",
                "etag",
                "last-modified",
                "content-length",
            ] {
                response.headers_mut().remove(name);
            }
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            response
                .headers_mut()
                .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
            response
                .headers_mut()
                .insert("content-length", text.len().into());
            *response.body_mut() = full(if req.method() == Method::HEAD {
                Bytes::new()
            } else {
                Bytes::from_static(text.as_bytes())
            });
            return Ok(response);
        }
    };
    // Go ignores a set of ranges whose combined payload exceeds the object.
    if ranges.iter().map(|(_, len)| *len as u128).sum::<u128>() > total as u128 {
        ranges.clear();
    }
    let mut pieces = vec![];
    let length = match ranges.len() {
        0 => {
            pieces.push(Piece::Object(None, total));
            total
        }
        1 => {
            let (start, len) = ranges[0];
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            response.headers_mut().insert(
                "content-range",
                format!("bytes {start}-{}/{total}", start as i128 + len as i128 - 1)
                    .parse()
                    .unwrap(),
            );
            pieces.push(Piece::Object(Some(start), len));
            len
        }
        _ => {
            let a = crate::jmap::random().ok_or(BlobReadError::Incomplete)?;
            let b = crate::jmap::random().ok_or(BlobReadError::Incomplete)?;
            let boundary = format!(
                "{}{}",
                crate::jmap::reply::hex(&a),
                &crate::jmap::reply::hex(&b)[..28]
            );
            let ct = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            response.headers_mut().insert(
                "content-type",
                format!("multipart/byteranges; boundary={boundary}")
                    .parse()
                    .unwrap(),
            );
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            let mut length = 0;
            for (index, (start, len)) in ranges.into_iter().enumerate() {
                let prelude = format!(
                    "{}--{boundary}\r\nContent-Range: bytes {start}-{}/{total}\r\nContent-Type: {ct}\r\n\r\n",
                    if index == 0 { "" } else { "\r\n" },
                    start as i128 + len as i128 - 1
                );
                length += prelude.len() as u64 + len;
                pieces.push(Piece::Bytes(Bytes::from(prelude)));
                pieces.push(Piece::Object(Some(start), len));
            }
            let end = format!("\r\n--{boundary}--\r\n");
            length += end.len() as u64;
            pieces.push(Piece::Bytes(Bytes::from(end)));
            length
        }
    };
    response
        .headers_mut()
        .insert("content-length", length.into());
    response
        .headers_mut()
        .insert("accept-ranges", "bytes".parse().unwrap());
    if req.method() == Method::HEAD {
        *response.body_mut() = full(Bytes::new());
        return Ok(response);
    }
    let hash = hash.to_owned();
    let stream = futures_util::stream::iter(pieces)
        .then(move |piece| {
            let store = store.clone();
            let hash = hash.clone();
            let buffered = buffered.clone();
            async move {
                let body = match piece {
                    Piece::Bytes(bytes) => full(bytes),
                    Piece::Object(_, 0) => full(Bytes::new()),
                    Piece::Object(start, len) => {
                        if let Some(bytes) = buffered {
                            let start = start.unwrap_or(0) as usize;
                            full(bytes.slice(start..start + len as usize))
                        } else {
                            store
                                .stream_blob(&hash, len, start.map(|s| (s, s + len - 1)))
                                .await
                                .map_err(|_| -> BoxError { "blob storage read failed".into() })?
                        }
                    }
                };
                Ok::<_, BoxError>(body.into_data_stream())
            }
        })
        .try_flatten()
        .map_ok(Frame::data);
    *response.body_mut() = LockedBody(Mutex::new(Box::pin(stream))).boxed();
    Ok(response)
}

enum Piece {
    Bytes(Bytes),
    Object(Option<u64>, u64),
}

struct LockedBody(Mutex<Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, BoxError>> + Send>>>);
impl hyper::body::Body for LockedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.lock().unwrap().as_mut().poll_next(cx)
    }
}
fn full(bytes: Bytes) -> Body {
    Full::new(bytes).map_err(|n| match n {}).boxed()
}

// Same signed-64-bit grammar as Go net/http; the error distinguishes a valid
// but disjoint set (Content-Range: bytes */size) from a malformed range.
pub(crate) fn parse_ranges(header: &str, size: u64) -> Result<Vec<(u64, u64)>, bool> {
    if header.is_empty() {
        return Ok(vec![]);
    }
    let raw = header.strip_prefix("bytes=").ok_or(false)?;
    let mut ranges = vec![];
    let mut no_overlap = false;
    for raw in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (start, end) = raw.split_once('-').ok_or(false)?;
        let start = start.trim();
        let end = end.trim();
        let integer = |v: &str| {
            v.parse::<i64>()
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
        let end = if end.is_empty() {
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

// Validator order is observable: If-Match precedes If-None-Match; both precede
// Range, and an If-Range mismatch selects the entire representation.
pub(crate) fn preconditions(req: &Request<Body>, response: &mut Response<Body>) -> Option<String> {
    let get = |name: &str| {
        req.headers()
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default()
    };
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let modified = response
        .headers()
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .and_then(http_timestamp);
    let im = get("if-match");
    let failed = if !im.is_empty() {
        !etag_matches(&im, &etag, false)
    } else {
        modified
            .zip(http_timestamp(&get("if-unmodified-since")))
            .is_some_and(|(modified, since)| modified > since)
    };
    if failed {
        *response.status_mut() = StatusCode::PRECONDITION_FAILED;
        response.headers_mut().remove("content-length");
        response
            .headers_mut()
            .insert("cache-control", "no-store".parse().unwrap());
        *response.body_mut() = full(Bytes::new());
        return None;
    }
    let inm = get("if-none-match");
    let not_modified = if !inm.is_empty() {
        etag_matches(&inm, &etag, true)
    } else {
        modified
            .zip(http_timestamp(&get("if-modified-since")))
            .is_some_and(|(modified, since)| modified <= since)
    };
    if not_modified {
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        for name in ["content-type", "content-length", "content-encoding"] {
            response.headers_mut().remove(name);
        }
        if !etag.is_empty() {
            response.headers_mut().remove("last-modified");
        }
        *response.body_mut() = full(Bytes::new());
        return None;
    }
    let range = get("range");
    let ir = get("if-range");
    let range_matches = if let Some((tag, _)) = scan_etag(&ir) {
        !tag.starts_with("W/") && tag == etag
    } else {
        modified
            .zip(http_timestamp(&ir))
            .is_some_and(|(modified, since)| modified == since)
    };
    if !range.is_empty() && !ir.is_empty() && !range_matches {
        return Some(String::new());
    }
    Some(range)
}

fn scan_etag(raw: &str) -> Option<(&str, &str)> {
    let value = raw.strip_prefix("W/").unwrap_or(raw);
    if !value.starts_with('"') {
        return None;
    }
    let end = value[1..].find('"')? + 1;
    if value.as_bytes()[1..end]
        .iter()
        .any(|b| *b < 0x21 || *b == 0x7f)
    {
        return None;
    }
    let end = raw.len() - value.len() + end + 1;
    Some((&raw[..end], &raw[end..]))
}
fn etag_matches(mut raw: &str, expected: &str, weak: bool) -> bool {
    loop {
        raw = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
        if let Some(rest) = raw.strip_prefix(',') {
            raw = rest;
            continue;
        }
        if raw.starts_with('*') {
            return true;
        }
        let Some((tag, rest)) = scan_etag(raw) else {
            return false;
        };
        if if weak {
            tag.strip_prefix("W/").unwrap_or(tag) == expected.strip_prefix("W/").unwrap_or(expected)
        } else {
            !tag.starts_with("W/") && tag == expected
        } {
            return true;
        }
        raw = rest;
    }
}

// Go accepts HTTP's three date layouts and ignores weekday/date consistency.
// chrono owns calendar validation; RFC850's 69 pivot follows Go time.Parse.
fn http_timestamp(value: &str) -> Option<i64> {
    use chrono::Datelike;
    let (text, format, obsolete) = if let Some((weekday, text)) = value.split_once(", ") {
        if ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|v| v.eq_ignore_ascii_case(weekday))
        {
            (text, "%d %b %Y %H:%M:%S GMT", false)
        } else if [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]
        .iter()
        .any(|v| v.eq_ignore_ascii_case(weekday))
        {
            (text, "%d-%b-%y %H:%M:%S GMT", true)
        } else {
            return None;
        }
    } else {
        let (weekday, text) = value.split_once(' ')?;
        if !["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            .iter()
            .any(|v| v.eq_ignore_ascii_case(weekday))
        {
            return None;
        }
        (text, "%b %e %H:%M:%S %Y", false)
    };
    let mut date = chrono::NaiveDateTime::parse_from_str(text, format).ok()?;
    if obsolete && date.year() == 2069 {
        date = date.with_year(1969)?;
    }
    Some(date.and_utc().timestamp())
}
