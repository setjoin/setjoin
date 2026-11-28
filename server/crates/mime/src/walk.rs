//! `mimeutil.WalkMIMEParts`: the fail-closed multipart framing walk. Go's
//! reader and optional leaf-body rewrite share strict framing, nesting limits
//! and error states. Rewrites preserve all original headers and boundaries.
use super::gostr::{contains, find, to_lower, trim_space};
use super::media::parse_media_type;

pub const MAX_NESTING: usize = 20;

/// Any state Go reports as an error: a caller treats it as fail-closed.
#[derive(Debug, PartialEq, Eq)]
pub struct WalkError;

type Res<T> = Result<T, WalkError>;

struct Segment<'a> {
    raw: &'a [u8],
    is_close: bool,
}

#[derive(PartialEq, Eq)]
enum Delim {
    None,
    Open,
    Close,
    DecoyClose,
}

fn skip_lwsp(b: &[u8]) -> usize {
    b.iter().take_while(|c| **c == b' ' || **c == b'\t').count()
}

fn match_eol(b: &[u8]) -> (&'static str, usize) {
    if b.starts_with(b"\r\n") {
        ("\r\n", 2)
    } else if b.starts_with(b"\n") {
        ("\n", 1)
    } else {
        ("", 0)
    }
}

fn classify(rest: &[u8]) -> (Delim, &'static str) {
    let Some(&c) = rest.first() else {
        return (Delim::None, "");
    };
    match c {
        b'-' if rest.len() >= 2 && rest[1] == b'-' => {
            let tail = &rest[2..];
            let k = skip_lwsp(tail);
            let (eol, n) = match_eol(&tail[k..]);
            if n > 0 {
                (Delim::Close, eol)
            } else if tail.len() == k {
                (Delim::Close, "")
            } else {
                (Delim::DecoyClose, "")
            }
        }
        b' ' | b'\t' => {
            let j = skip_lwsp(rest);
            let (eol, n) = match_eol(&rest[j..]);
            if n > 0 {
                (Delim::Open, eol)
            } else {
                (Delim::DecoyClose, "")
            }
        }
        b'\r' => {
            let (eol, n) = match_eol(rest);
            if n > 0 {
                (Delim::Open, eol)
            } else {
                (Delim::DecoyClose, "")
            }
        }
        b'\n' => (Delim::Open, "\n"),
        _ => (Delim::None, ""),
    }
}

fn anchored(body: &[u8], i: usize, eol: &str) -> bool {
    if i == 0 {
        return true;
    }
    if body[i - 1] != b'\n' {
        return false;
    }
    if eol == "\r\n" {
        return i >= 2 && body[i - 2] == b'\r';
    }
    true
}

fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Res<Vec<Segment<'a>>> {
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(boundary);
    let mut segs: Vec<Segment<'a>> = Vec::new();
    let (mut start, mut search) = (0usize, 0usize);
    let mut eol = "";
    while let Some(found) = find(&body[search..], &delim) {
        let i = found + search;
        if !anchored(body, i, eol) {
            search = i + delim.len();
            continue;
        }
        let (kind, conv) = classify(&body[i + delim.len()..]);
        match kind {
            Delim::Open => {
                if !conv.is_empty() {
                    if eol.is_empty() {
                        eol = conv;
                    } else if conv != eol {
                        return Err(WalkError);
                    }
                }
                segs.push(Segment {
                    raw: &body[start..i],
                    is_close: false,
                });
                start = i + delim.len();
                search = start;
            }
            Delim::Close => {
                if !conv.is_empty() {
                    if eol.is_empty() {
                        if conv == "\n" {
                            search = i + delim.len();
                            continue;
                        }
                    } else if conv != eol {
                        return Err(WalkError);
                    }
                }
                segs.push(Segment {
                    raw: &body[start..i],
                    is_close: false,
                });
                start = i + delim.len();
                segs.push(Segment {
                    raw: &body[start..],
                    is_close: true,
                });
                return Ok(segs);
            }
            Delim::DecoyClose => {
                if !segs.is_empty() {
                    return Err(WalkError);
                }
                search = i + delim.len() + 2;
            }
            Delim::None => search = i + delim.len(),
        }
    }
    Err(WalkError)
}

fn split_trailing_eol(b: &[u8]) -> &[u8] {
    if b.ends_with(b"\r\n") {
        &b[..b.len() - 2]
    } else if b.ends_with(b"\n") {
        &b[..b.len() - 1]
    } else {
        b
    }
}

/// The earliest double line ending of either convention.
fn split_part_headers(seg: &[u8]) -> Res<(&[u8], &[u8])> {
    let crlf = find(seg, b"\r\n\r\n");
    let lf = find(seg, b"\n\n");
    match (crlf, lf) {
        (Some(c), l) if l.is_none_or(|l| c < l) => Ok((&seg[..c], &seg[c + 4..])),
        (_, Some(l)) => Ok((&seg[..l], &seg[l + 2..])),
        _ => Err(WalkError),
    }
}

/// `(boundary, is_multipart)` of `ExtractBoundaryStrict`.
fn boundary_strict(content_type: &[u8]) -> Res<Option<Vec<u8>>> {
    let (media, params) = parse_media_type(content_type).map_err(|_| WalkError)?;
    if !trim_space(&media).starts_with(b"multipart/") {
        return Ok(None);
    }
    match params.get(b"boundary".as_slice()) {
        Some(b) if !b.is_empty() => Ok(Some(b.clone())),
        _ => Err(WalkError),
    }
}

/// `multipartChildContentType`: the nested container's Content-Type, if the
/// part is one.
fn child_content_type(headers: &[u8]) -> Res<Option<Vec<u8>>> {
    let raw = super::extract_header(headers, "Content-Type");
    if raw.is_empty() {
        return Ok(None);
    }
    match parse_media_type(&raw) {
        Err(()) => {
            if to_lower(trim_space(&raw)).starts_with(b"multipart/") {
                Err(WalkError)
            } else {
                Ok(None)
            }
        }
        Ok((media, params)) => {
            if !to_lower(&media).starts_with(b"multipart/") {
                return Ok(None);
            }
            if params.get(b"boundary".as_slice()).is_none_or(Vec::is_empty) {
                return Err(WalkError);
            }
            Ok(Some(raw))
        }
    }
}

/// Walk a multipart body, calling `leaf(headers, body)` for each leaf part.
/// Errors are Go's fail-closed states; leaves visited before the error stay
/// visited, as in Go.
pub fn walk_parts(content_type: &[u8], body: &[u8], leaf: &mut dyn FnMut(&[u8], &[u8])) -> Res<()> {
    let boundary = boundary_strict(content_type)?.ok_or(WalkError)?;
    walk(&boundary, body, leaf, 0)
}

/// Rewrite validated MIME leaves, preserving every header, delimiter and framing
/// newline. The walker supplies subslices of `body`; replacements apply only
/// after the complete framing walk succeeds, as in Go's WalkMIMEParts.
pub fn rewrite_parts(
    content_type: &[u8],
    body: &[u8],
    leaf: &mut impl FnMut(&[u8], &[u8]) -> Option<Vec<u8>>,
) -> Res<Vec<u8>> {
    let mut replacements = Vec::new();
    walk_parts(content_type, body, &mut |headers, bytes| {
        if let Some(replacement) = leaf(headers, bytes) {
            let start = bytes.as_ptr() as usize - body.as_ptr() as usize;
            replacements.push((start, start + bytes.len(), replacement));
        }
    })?;
    let mut output = Vec::new();
    let mut previous = 0;
    for (start, end, replacement) in replacements {
        if start < previous || end > body.len() {
            return Err(WalkError);
        }
        output.extend_from_slice(&body[previous..start]);
        output.extend(replacement);
        previous = end;
    }
    output.extend_from_slice(&body[previous..]);
    Ok(output)
}

fn walk(boundary: &[u8], body: &[u8], leaf: &mut dyn FnMut(&[u8], &[u8]), depth: usize) -> Res<()> {
    if depth >= MAX_NESTING {
        return Err(WalkError);
    }
    let segs = split_multipart(body, boundary)?;
    if segs.len() < 2 {
        return Err(WalkError);
    }
    for seg in &segs[1..] {
        if seg.is_close {
            return Ok(());
        }
        let (headers, part_body) = split_part_headers(seg.raw)?;
        if let Some(nested) = child_content_type(headers)? {
            let inner = boundary_strict(&nested)?.ok_or(WalkError)?;
            walk(&inner, part_body, leaf, depth + 1)?;
            continue;
        }
        leaf(headers, split_trailing_eol(part_body));
    }
    Ok(())
}

pub fn headers_say(headers: &[u8], needle_lower: &str) -> bool {
    contains(&to_lower(headers), needle_lower)
}
