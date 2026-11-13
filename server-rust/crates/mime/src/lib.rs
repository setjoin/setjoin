//! Port of Go's `mailserver/internal/mimeutil` (header extraction, `net/mail`
//! addresses, RFC 2047 words, charset decoding and the fail-closed multipart
//! walk) as far as message import reads it. Go strings are bytes, so every
//! function here takes and returns bytes and matches Go's results exactly,
//! including its quirks (see the crate DOX). The mailbox import route uses it
//! now; the migration runner's `importMailItem` uses the same calls.
// Go's errors carry no text any caller reads: `Err(())` is the whole answer.
#![allow(clippy::result_unit_err)]
mod addr;
mod date;
mod gostr;
mod media;
mod walk;

pub use addr::{parse_address, parse_address_list as parse_address_list_raw, Address};
pub use date::{parse_http_time, Instant};
pub use gostr::{decode_rune, to_lower, trim_space};
pub use media::{decode_charset, decode_word, parse_media_type, WordError};
pub use walk::{rewrite_parts, walk_parts, WalkError};

use gostr::{contains, equal_fold_ascii, find, trim_right_cr};

/// `mimeutil.UnfoldHeaders`.
pub fn unfold_headers(headers: &[u8]) -> Vec<u8> {
    let mut unfolded: Vec<Vec<u8>> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    for line in headers.split(|c| *c == b'\n') {
        let line = trim_right_cr(line);
        if !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
            let mut joined = trim_right_cr(&buf).to_vec();
            joined.push(b' ');
            joined.extend_from_slice(trim_space(line));
            buf = joined;
        } else {
            if !buf.is_empty() {
                unfolded.push(std::mem::take(&mut buf));
            }
            buf = line.to_vec();
        }
    }
    if !buf.is_empty() {
        unfolded.push(buf);
    }
    unfolded.join(&b'\n')
}

/// `mimeutil.ExtractHeader`: the first header named `name` (any case), its
/// folds joined, decoded only when the whole value is one encoded word.
pub fn extract_header(body: &[u8], name: &str) -> Vec<u8> {
    let name = name.to_ascii_lowercase();
    let header_end = find(body, b"\r\n\r\n").or_else(|| find(body, b"\n\n"));
    let headers = header_end.map_or(body, |end| &body[..end]);
    let headers = unfold_headers(headers);
    for line in headers.split(|c| *c == b'\n') {
        let line = trim_right_cr(line);
        let Some(i) = line.iter().position(|c| *c == b':').filter(|i| *i > 0) else {
            continue;
        };
        if equal_fold_ascii(trim_space(&line[..i]), &name) {
            let val = trim_space(&line[i + 1..]);
            return decode_word(val).unwrap_or_else(|_| val.to_vec());
        }
    }
    Vec::new()
}

/// `mimeutil.ExtractAddr`.
pub fn extract_addr(s: &[u8]) -> Vec<u8> {
    let s = trim_space(s);
    if s.is_empty() {
        return Vec::new();
    }
    if s[0] == b'<' {
        if let Some(idx) = s.iter().position(|c| *c == b'>').filter(|i| *i > 0) {
            return s[1..idx].to_vec();
        }
    }
    if let Some(idx) = s.iter().position(|c| *c == b'<') {
        if let Some(end) = s[idx..].iter().position(|c| *c == b'>').filter(|e| *e > 0) {
            return s[idx + 1..idx + end].to_vec();
        }
    }
    let is_angle = |c: &u8| *c == b'<' || *c == b'>';
    let start = s.iter().position(|c| !is_angle(c)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|c| !is_angle(c))
        .map_or(start, |e| e + 1);
    s[start..end.max(start)].to_vec()
}

/// `mimeutil.ParseFrom`: `(name, address)`.
pub fn parse_from(s: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if s.is_empty() {
        return (Vec::new(), Vec::new());
    }
    match parse_address(s) {
        Ok(a) => (a.name, a.address),
        Err(()) => (Vec::new(), extract_addr(s)),
    }
}

/// A Go string put through `encoding/json`: every invalid byte is one U+FFFD.
pub fn go_lossy(b: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (r, n) = gostr::decode_rune(rest);
        let invalid = n == 1 && r == gostr::RUNE_ERROR;
        out.push(if invalid {
            '\u{fffd}'
        } else {
            char::from_u32(r).unwrap_or('\u{fffd}')
        });
        rest = &rest[n..];
    }
    out
}

fn format_address(name: &[u8], email: &[u8]) -> String {
    let json = |b: &[u8]| serde_json::to_string(&go_lossy(b)).expect("string");
    if name.is_empty() {
        format!("{{\"email\":{}}}", json(email))
    } else {
        format!("{{\"name\":{},\"email\":{}}}", json(name), json(email))
    }
}

/// `mimeutil.ParseAddressList`: the JSON array text of `{name, email}`.
pub fn parse_address_list(s: &[u8]) -> String {
    if s.is_empty() {
        return "[]".into();
    }
    let out: Vec<String> = match addr::parse_address_list(s) {
        Ok(list) => list
            .iter()
            .map(|a| format_address(&a.name, &a.address))
            .collect(),
        Err(()) => s
            .split(|c| *c == b',')
            .map(trim_space)
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (name, email) = parse_from(p);
                format_address(&name, &email)
            })
            .collect(),
    };
    format!("[{}]", out.join(","))
}

/// The header block end and separator length the body extractors use.
fn header_split(msg: &[u8]) -> Option<(usize, usize)> {
    find(msg, b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| find(msg, b"\n\n").map(|i| (i, 2)))
}

fn multipart_body(msg: &[u8], ct: &[u8], kind: &str) -> Vec<u8> {
    let Some((end, sep)) = header_split(msg) else {
        return Vec::new();
    };
    let mut found: Vec<u8> = Vec::new();
    let needle = format!("content-type: {kind}");
    let _ = walk_parts(ct, &msg[end + sep..], &mut |headers, body| {
        if found.is_empty() && walk::headers_say(headers, &needle) {
            let part_ct = extract_header(headers, "Content-Type");
            found = decode_charset(trim_space(body), &part_ct);
        }
    });
    found
}

/// `mimeutil.ExtractBodyText`.
pub fn extract_body_text(msg: &[u8]) -> Vec<u8> {
    let Some((end, sep)) = header_split(msg) else {
        return Vec::new();
    };
    let ct = extract_header(msg, "Content-Type");
    if contains(&to_lower(&ct), "multipart") {
        return multipart_body(msg, &ct, "text/plain");
    }
    decode_charset(trim_space(&msg[end + sep..]), &ct)
}

/// `mimeutil.ExtractBodyHTML`.
pub fn extract_body_html(msg: &[u8]) -> Vec<u8> {
    let ct = extract_header(msg, "Content-Type");
    let lower = to_lower(&ct);
    if contains(&lower, "multipart") {
        return multipart_body(msg, &ct, "text/html");
    }
    if contains(&lower, "text/html") {
        if let Some((end, sep)) = header_split(msg) {
            return decode_charset(trim_space(&msg[end + sep..]), &ct);
        }
    }
    Vec::new()
}

/// Everything message import derives from a raw message, as Go's
/// `importRawMessage` does before its writes. Text fields are Go strings
/// (bytes); `to_json`/`cc_json`/`bcc_json` are JSON text.
pub struct ImportFields {
    pub message_id: Vec<u8>,
    pub subject: Vec<u8>,
    pub from_addr: Vec<u8>,
    pub from_name: Vec<u8>,
    pub to_json: String,
    pub cc_json: String,
    pub bcc_json: String,
    pub in_reply_to: Vec<u8>,
    pub references: Vec<u8>,
    pub body_text: Vec<u8>,
    pub body_html: Vec<u8>,
    pub date: Option<Instant>,
}

impl ImportFields {
    pub fn parse(raw: &[u8]) -> Self {
        // Go's importRawMessage reads ParseFrom's (name, address) into
        // (fromAddr, fromName): the stored `from_addr` is the display name and
        // `from_name` the address. Mirrored for parity (a Go bug, see the DOX).
        let (from_addr, from_name) = parse_from(&extract_header(raw, "From"));
        ImportFields {
            message_id: extract_header(raw, "Message-ID"),
            subject: extract_header(raw, "Subject"),
            from_addr,
            from_name,
            to_json: parse_address_list(&extract_header(raw, "To")),
            cc_json: parse_address_list(&extract_header(raw, "Cc")),
            bcc_json: parse_address_list(&extract_header(raw, "Bcc")),
            in_reply_to: extract_header(raw, "In-Reply-To"),
            references: extract_header(raw, "References"),
            body_text: extract_body_text(raw),
            body_html: extract_body_html(raw),
            date: Some(extract_header(raw, "Date"))
                .filter(|d| !d.is_empty())
                .and_then(|d| parse_http_time(&d)),
        }
    }
}
