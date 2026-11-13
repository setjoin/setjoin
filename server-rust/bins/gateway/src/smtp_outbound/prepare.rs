//! Frozen Go's MIME-aware egress un-rewrite, using the existing token verifier.
use crate::link_protect::{verify_token, TokenKeys};
use base64::Engine;
use regex::{Captures, Regex};
use setjoin_mime as mime;
use std::sync::LazyLock;

pub struct ForwardPreparation(pub TokenKeys);
static PROTECTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:https?://[^ \t\n\r\x0c<>"'\]]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)"#).unwrap()
});
static CSS_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)url\([ \t\n\r\x0c]*['"]?(?:https?://[^ \t\n\r\x0c()'"]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)['"]?[ \t\n\r\x0c]*\)"#).unwrap()
});
static CSS_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)@import[ \t\n\r\x0c]+["'](?:https?://[^ \t\n\r\x0c'"]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)["']"#).unwrap()
});
impl ForwardPreparation {
    fn destination(&self, token: &str) -> Option<String> {
        let claim = verify_token(token, &self.0, chrono::Utc::now().timestamp())?;
        (!claim.url.is_empty() && !claim.url.contains(['\r', '\n', '\0'])).then_some(claim.url)
    }
    fn plain(&self, data: &[u8], inert: bool) -> (Vec<u8>, usize) {
        static BYTES: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
            regex::bytes::Regex::new(r#"(?-u:(?:https?://[^ \t\n\r\x0c<>"'\]]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+))"#).unwrap()
        });
        let mut count = 0;
        let output = BYTES.replace_all(data, |captures: &regex::bytes::Captures<'_>| {
            let Some(destination) = std::str::from_utf8(&captures[1])
                .ok()
                .and_then(|token| self.destination(token))
            else {
                return captures[0].to_vec();
            };
            if inert
                && destination
                    .chars()
                    .any(|c| c < ' ' || c == '\u{7f}' || matches!(c, '<' | '>' | '"' | '\'' | '&'))
            {
                return captures[0].to_vec();
            };
            count += 1;
            destination.into_bytes()
        });
        (output.into_owned(), count)
    }
    fn full(&self, value: &str) -> Option<String> {
        let captures = PROTECTED.captures(value)?;
        if captures.get(0)?.as_str() != value {
            return None;
        }
        self.destination(&captures[1])
    }
    fn text(&self, text: &str, inert: bool) -> (String, usize) {
        let mut count = 0;
        let output = PROTECTED.replace_all(text, |captures: &Captures<'_>| {
            let Some(destination) = self.destination(&captures[1]) else {
                return captures[0].into();
            };
            if inert
                && destination
                    .chars()
                    .any(|c| c < ' ' || c == '\u{7f}' || matches!(c, '<' | '>' | '"' | '\'' | '&'))
            {
                return captures[0].into();
            };
            count += 1;
            destination
        });
        (output.into_owned(), count)
    }
    fn css(&self, text: &str) -> (String, usize) {
        let mut count = 0;
        let mut output = text.to_owned();
        for (regex, prefix, suffix) in [
            (&*CSS_URL, "url(\"", "\")"),
            (&*CSS_IMPORT, "@import \"", "\""),
        ] {
            output = regex
                .replace_all(&output, |captures: &Captures<'_>| {
                    let Some(destination) = self.destination(&captures[1]) else {
                        return captures[0].into();
                    };
                    if destination.contains(['"', '\'', '(', ')', '\\', '\r', '\n', '<', '>']) {
                        return captures[0].into();
                    };
                    count += 1;
                    format!("{prefix}{destination}{suffix}")
                })
                .into_owned();
        }
        (output, count)
    }
    fn srcset(&self, text: &str) -> (String, usize) {
        let bytes = text.as_bytes();
        let mut pos = 0;
        let mut previous = 0;
        let mut count = 0;
        let mut output = String::new();
        while pos < bytes.len() {
            while pos < bytes.len() && (bytes[pos].is_ascii_whitespace() || bytes[pos] == b',') {
                pos += 1
            }
            if pos == bytes.len() {
                break;
            };
            let start = pos;
            while pos < bytes.len() && !matches!(bytes[pos], b' ' | b'\t' | b'\n' | b'\x0c' | b'\r')
            {
                pos += 1
            }
            let mut end = pos;
            if bytes[end - 1] == b',' {
                while end > start && bytes[end - 1] == b',' {
                    end -= 1
                }
            } else {
                while pos < bytes.len() && bytes[pos] != b',' {
                    pos += 1
                }
            };
            output.push_str(&text[previous..start]);
            let value = &text[start..end];
            if let Some(destination) = self
                .full(value)
                .filter(|v| !v.contains([' ', '\t', '\n', '\x0c', '\r']) && !v.ends_with(','))
            {
                output.push_str(&destination);
                count += 1
            } else {
                output.push_str(value)
            };
            previous = end;
        }
        output.push_str(&text[previous..]);
        (output, count)
    }
    fn html(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let document = scraper::Html::parse_document(&mime::go_lossy(data));
        let mut output = String::new();
        let mut count = 0;
        let mut stack = vec![(document.tree.root(), false)];
        while let Some((node, closing)) = stack.pop() {
            match node.value() {
                scraper::Node::Element(element) => {
                    let name = element.name();
                    let void = matches!(
                        name,
                        "area"
                            | "base"
                            | "br"
                            | "col"
                            | "embed"
                            | "hr"
                            | "img"
                            | "input"
                            | "keygen"
                            | "link"
                            | "meta"
                            | "param"
                            | "source"
                            | "track"
                            | "wbr"
                    );
                    if closing {
                        if !void {
                            output.push_str("</");
                            output.push_str(name);
                            output.push('>');
                        }
                        continue;
                    }
                    output.push('<');
                    output.push_str(name);
                    for (key, value) in &element.attrs {
                        let attr = key.local.as_ref();
                        let (value, n) = if attr == "style" {
                            self.css(value)
                        } else if attr == "srcset" {
                            self.srcset(value)
                        } else if matches!(
                            attr,
                            "href"
                                | "src"
                                | "action"
                                | "formaction"
                                | "poster"
                                | "data"
                                | "background"
                                | "cite"
                                | "longdesc"
                                | "codebase"
                                | "manifest"
                                | "profile"
                        ) {
                            match self.full(value) {
                                Some(v) => (v, 1),
                                None => (value.to_string(), 0),
                            }
                        } else {
                            (value.to_string(), 0)
                        };
                        count += n;
                        output.push(' ');
                        if let Some(prefix) = &key.prefix {
                            output.push_str(prefix);
                            output.push(':')
                        };
                        output.push_str(attr);
                        output.push_str("=\"");
                        output.push_str(&escape(&value));
                        output.push('"');
                    }
                    if void {
                        output.push_str("/>");
                        continue;
                    };
                    output.push('>');
                    if matches!(name, "pre" | "listing" | "textarea")
                        && node
                            .first_child()
                            .and_then(|n| n.value().as_text())
                            .is_some_and(|t| t.starts_with('\n'))
                    {
                        output.push('\n')
                    }
                    stack.push((node, true));
                    for child in node.children().rev() {
                        stack.push((child, false));
                    }
                }
                scraper::Node::Text(text) => {
                    let parent = node
                        .parent()
                        .and_then(|n| n.value().as_element())
                        .map(|e| e.name())
                        .unwrap_or_default();
                    let (text, n) = if parent == "style" {
                        self.css(text)
                    } else if raw_text(parent) {
                        (text.to_string(), 0)
                    } else {
                        self.text(text, false)
                    };
                    count += n;
                    if parent == "style" || raw_text(parent) {
                        output.push_str(&text)
                    } else {
                        output.push_str(&escape(&text))
                    }
                }
                scraper::Node::Comment(comment) => {
                    output.push_str("<!--");
                    output.push_str(comment);
                    output.push_str("-->");
                }
                scraper::Node::Doctype(doctype) => {
                    output.push_str("<!DOCTYPE ");
                    output.push_str(doctype.name());
                    if !doctype.public_id().is_empty() {
                        output.push_str(" PUBLIC \"");
                        output.push_str(doctype.public_id());
                        output.push('"');
                        if !doctype.system_id().is_empty() {
                            output.push_str(" \"");
                            output.push_str(doctype.system_id());
                            output.push('"');
                        }
                    } else if !doctype.system_id().is_empty() {
                        output.push_str(" SYSTEM \"");
                        output.push_str(doctype.system_id());
                        output.push('"')
                    };
                    output.push('>');
                }
                _ => {
                    for child in node.children().rev() {
                        stack.push((child, false));
                    }
                }
            }
        }
        if count == 0 {
            (data.to_vec(), 0)
        } else {
            (output.into_bytes(), count)
        }
    }
    fn decoded(&self, body: &[u8], ct: &str) -> (Vec<u8>, usize) {
        if ct.contains("text/html") {
            self.html(body)
        } else {
            self.plain(body, false)
        }
    }
    fn leaf(&self, headers: &[u8], body: &[u8], ct: &str) -> Result<Option<Vec<u8>>, String> {
        if ct.contains("text/calendar")
            || !(ct.is_empty() || ct.contains("text/plain") || ct.contains("text/html"))
        {
            return Ok(None);
        }
        let cte = mime::go_lossy(&header(headers, "Content-Transfer-Encoding"))
            .to_lowercase()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let decoded = match cte.as_str() {
            "base64" => {
                let bytes = body
                    .iter()
                    .copied()
                    .filter(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
                    .collect::<Vec<_>>();
                base64_engine()
                    .decode(bytes)
                    .map_err(|_| "invalid base64 body")?
            }
            "quoted-printable" => {
                quoted_printable::decode(body, quoted_printable::ParseMode::Robust)
                    .map_err(|_| "invalid quoted-printable body")?
            }
            "" | "7bit" | "8bit" | "binary" => body.to_vec(),
            _ => return Err("unsupported transfer encoding".into()),
        };
        if !decoded
            .windows(b"/link-protect?token=".len())
            .any(|w| w == b"/link-protect?token=")
        {
            return Ok(None);
        }
        let (output, n) = self.decoded(&decoded, ct);
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(match cte.as_str() {
            "base64" => {
                let encoded = base64_engine().encode(output);
                encoded
                    .as_bytes()
                    .chunks(76)
                    .map(|chunk| std::str::from_utf8(chunk).unwrap())
                    .collect::<Vec<_>>()
                    .join("\r\n")
                    .into_bytes()
            }
            "quoted-printable" => quoted_printable::encode(output),
            _ => output,
        }))
    }
    fn message(&self, raw: &[u8]) -> Result<Vec<u8>, String> {
        let Some((end, sep)) = header_end(raw).filter(|(end, _)| valid_headers(&raw[..*end]))
        else {
            return Ok(self.plain(raw, true).0);
        };
        let headers = &raw[..end];
        let body = &raw[end + sep..];
        let ct = mime::go_lossy(&header(headers, "Content-Type")).to_lowercase();
        if ct.is_empty() && mime::trim_space(body).is_empty() {
            return Ok(self.plain(raw, true).0);
        }
        let multipart = if ct.is_empty() {
            false
        } else {
            mime::parse_media_type(ct.as_bytes())
                .map_err(|_| "invalid Content-Type")?
                .0
                .starts_with(b"multipart/")
        };
        if multipart {
            let mut error = None;
            let mut changed = false;
            let output = mime::rewrite_parts(ct.as_bytes(), raw, &mut |headers, body| {
                if error.is_some() {
                    return None;
                }
                let ct =
                    mime::go_lossy(&mime::extract_header(headers, "Content-Type")).to_lowercase();
                match self.leaf(headers, body, &ct) {
                    Ok(Some(bytes)) => {
                        changed = true;
                        Some(bytes)
                    }
                    Ok(None) => None,
                    Err(e) => {
                        error = Some(e);
                        None
                    }
                }
            })
            .map_err(|_| "invalid multipart framing")?;
            if let Some(e) = error {
                return Err(e);
            };
            return Ok(if changed { output } else { raw.to_vec() });
        }
        match self.leaf(headers, body, &ct)? {
            Some(body) => {
                let (end, sep) = rebuild_end(raw).unwrap();
                let mut output = raw[..end + sep].to_vec();
                output.extend(body);
                Ok(output)
            }
            None => Ok(raw.to_vec()),
        }
    }
}
impl setjoin_smtp::outbound::ForwardTransform for ForwardPreparation {
    fn apply(&self, raw: &[u8]) -> Result<Vec<u8>, String> {
        if self.0.current_key().is_empty() {
            Ok(raw.to_vec())
        } else {
            self.message(raw)
        }
    }
}
fn escape(text: &str) -> String {
    html_escape::encode_quoted_attribute(text)
        .replace("&quot;", "&#34;")
        .replace("&#x27;", "&#39;")
}
fn raw_text(name: &str) -> bool {
    matches!(
        name,
        "script" | "iframe" | "noembed" | "noframes" | "noscript" | "xmp" | "plaintext"
    )
}
fn base64_engine() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    )
}
fn header_end(raw: &[u8]) -> Option<(usize, usize)> {
    let cr = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let lf = raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    match (cr, lf) {
        (Some(a), Some(b)) => Some(if a.0 < b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}
fn rebuild_end(raw: &[u8]) -> Option<(usize, usize)> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))
}
fn valid_headers(raw: &[u8]) -> bool {
    let mut previous = false;
    for line in raw.split(|c| *c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if !previous {
                return false;
            }
        } else {
            let Some(colon) = line.iter().position(|c| *c == b':') else {
                return false;
            };
            if colon == 0 || !line[..colon].iter().all(|c| *c > 32 && *c < 127) {
                return false;
            }
            previous = true
        };
        if line.iter().any(|c| (*c < 32 && *c != b'\t') || *c == 127) {
            return false;
        }
    }
    true
}
fn header(raw: &[u8], name: &str) -> Vec<u8> {
    let unfolded = mime::unfold_headers(raw);
    for line in unfolded.split(|c| *c == b'\n') {
        if let Some(colon) = line.iter().position(|c| *c == b':') {
            if line[..colon].eq_ignore_ascii_case(name.as_bytes()) {
                return mime::trim_space(&line[colon + 1..]).to_vec();
            }
        }
    }
    Vec::new()
}
