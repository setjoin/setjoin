//! Inbound MIME-aware link protection, with ring's audited HMAC implementation.
use base64::Engine as _;
use regex::Regex;
use setjoin_mime as mime;
use std::sync::LazyLock;

#[derive(Clone)]
pub struct Config {
    /// The already-derived current HMAC key (Go `tokenKeyN(secret, version)`); the master
    /// secret never reaches the SMTP process (deploy renders this key).
    pub key: Vec<u8>,
    pub version: i64,
    /// Oracle clock recovered from Go-minted tokens; production leaves None.
    pub clock_unix: Option<i64>,
}
/// Go `tokenKeyN`: HMAC-SHA256(secret, "link-protect-v<version>: link-protect token hmac key").
pub fn derive_key(secret: &[u8], version: i64) -> Vec<u8> {
    let secret = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let label = format!("link-protect-v{version}: link-protect token hmac key");
    ring::hmac::sign(&secret, label.as_bytes())
        .as_ref()
        .to_vec()
}
struct Rewrite<'a> {
    config: &'a Config,
    internal: &'a [String],
    message: &'a str,
    mailbox: i64,
}
impl Config {
    pub(crate) fn rewrite(
        &self,
        raw: &[u8],
        internal: &[String],
        message: &str,
        mailbox: i64,
    ) -> Result<(Vec<u8>, usize), String> {
        Rewrite {
            config: self,
            internal,
            message,
            mailbox,
        }
        .message(raw)
    }
}
impl Rewrite<'_> {
    fn url(&self, raw: &str) -> Option<String> {
        if raw.is_empty()
            || raw.to_lowercase().starts_with("mailto:")
            || raw.starts_with('#')
            || own_redirect(raw)
        {
            return None;
        }
        let lower = raw.to_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://") || raw.starts_with("//"))
            || raw.contains(['\r', '\n', '\0'])
        {
            return None;
        }
        if let Ok(host) = setjoin_authz::go_url::parse_url_host(raw) {
            if self.internal.iter().filter(|d| !d.is_empty()).any(|d| {
                let d = d.to_lowercase();
                host == d || host.ends_with(&format!(".{d}"))
            }) {
                return None;
            }
        }
        let quote = |value: &str| {
            serde_json::to_string(value)
                .expect("JSON string")
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026")
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029")
        };
        let expires = self
            .config
            .clock_unix
            .unwrap_or_else(|| chrono::Utc::now().timestamp())
            + 30 * 24 * 60 * 60;
        let payload = format!(
            "{{\"u\":{},\"m\":{},\"b\":{},\"e\":{expires}}}",
            quote(raw),
            quote(self.message),
            if crate::mutants::on("inbound-link-wrong-mailbox") {
                0
            } else {
                self.mailbox
            }
        );
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(payload);
        let derived = if crate::mutants::on("inbound-link-wrong-version") {
            derive_key(&self.config.key, 1)
        } else {
            self.config.key.clone()
        };
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &derived);
        let signature = ring::hmac::sign(&key, encoded.as_bytes());
        Some(format!(
            "/link-protect?token={encoded}.{}",
            base64::engine::general_purpose::URL_SAFE.encode(signature)
        ))
    }
    fn plain(&self, data: &[u8]) -> (Vec<u8>, usize) {
        static URL: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
            regex::bytes::Regex::new(r#"(?-u:https?://[^ \t\n\r\x0c<>"'\]]+)"#).unwrap()
        });
        let mut count = 0;
        let out = URL.replace_all(data, |captures: &regex::bytes::Captures<'_>| {
            if let Some(url) = self.url(&mime::go_lossy(&captures[0])) {
                count += 1;
                url.into_bytes()
            } else {
                captures[0].to_vec()
            }
        });
        (out.into_owned(), count)
    }
    fn css(&self, text: &str) -> (String, usize) {
        static URL: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"(?i)url\([ \t\n\r\x0c]*['"]?((?:https?:)?//[^)'" \t\n\r\x0c]*)['"]?[ \t\n\r\x0c]*\)"#).unwrap()
        });
        static IMPORT: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"(?i)@import[ \t\n\r\x0c]+["']((?:https?:)?//[^'" \t\n\r\x0c]+)["']"#)
                .unwrap()
        });
        let mut count = 0;
        let mut output = text.to_owned();
        for (regex, prefix, suffix) in [(&*URL, "url(", ")"), (&*IMPORT, "@import \"", "\"")] {
            output = regex
                .replace_all(&output, |captures: &regex::Captures<'_>| {
                    if let Some(url) = self.url(&captures[1]) {
                        count += 1;
                        format!("{prefix}{url}{suffix}")
                    } else {
                        captures[0].to_owned()
                    }
                })
                .into_owned();
        }
        (output, count)
    }
    fn srcset(&self, text: &str) -> (String, usize) {
        let bytes = text.as_bytes();
        let (mut pos, mut last, mut count) = (0, 0, 0);
        let mut output = String::new();
        let space = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r');
        while pos < bytes.len() {
            while pos < bytes.len() && (space(bytes[pos]) || bytes[pos] == b',') {
                pos += 1;
            }
            if pos == bytes.len() {
                break;
            }
            let start = pos;
            while pos < bytes.len() && !space(bytes[pos]) {
                pos += 1;
            }
            let mut end = pos;
            if bytes[end - 1] == b',' {
                while end > start && bytes[end - 1] == b',' {
                    end -= 1;
                }
            } else {
                while pos < bytes.len() && bytes[pos] != b',' {
                    pos += 1;
                }
            }
            output.push_str(&text[last..start]);
            let value = &text[start..end];
            if let Some(url) = self.url(value) {
                output.push_str(&url);
                count += 1;
            } else {
                output.push_str(value);
            }
            last = end;
        }
        output.push_str(&text[last..]);
        (output, count)
    }
    fn html(&self, data: &[u8]) -> (Vec<u8>, usize) {
        if crate::mutants::on("inbound-no-link-html") {
            return (data.to_vec(), 0);
        }
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
                                | "lowsrc"
                        ) {
                            match self.url(value) {
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
                        (text.to_string(), 0)
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

    fn leaf(
        &self,
        headers: &[u8],
        body: &[u8],
        ct: &str,
    ) -> Result<(Option<Vec<u8>>, usize), String> {
        if ct.contains("text/calendar")
            || !(ct.is_empty() || ct.contains("text/plain") || ct.contains("text/html"))
        {
            return Ok((None, 0));
        }
        let cte = mime::go_lossy(&header(headers, "Content-Transfer-Encoding"))
            .to_lowercase()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        if crate::mutants::on("inbound-no-link-cte")
            && matches!(cte.as_str(), "base64" | "quoted-printable")
        {
            return Ok((None, 0));
        }
        let decoded = match cte.as_str() {
            "base64" => base64_engine()
                .decode(
                    body.iter()
                        .copied()
                        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                        .collect::<Vec<_>>(),
                )
                .map_err(|_| "invalid base64 body")?,
            "quoted-printable" => decode_qp(body)?,
            "" | "7bit" | "8bit" | "binary" => body.to_vec(),
            _ => return Err("unsupported transfer encoding".into()),
        };
        let (output, n) = if ct.contains("text/html") {
            self.html(&decoded)
        } else {
            self.plain(&decoded)
        };
        if n == 0 {
            return Ok((None, 0));
        }
        let encoded = match cte.as_str() {
            "base64" => base64_engine()
                .encode(output)
                .as_bytes()
                .chunks(76)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\r\n")
                .into_bytes(),
            "quoted-printable" => quoted_printable::encode(output),
            _ => output,
        };
        Ok((Some(encoded), n))
    }
    fn message(&self, raw: &[u8]) -> Result<(Vec<u8>, usize), String> {
        let (end, sep) = header_end(raw)
            .filter(|(end, _)| valid_headers(&raw[..*end]))
            .ok_or("invalid message headers")?;
        let headers = &raw[..end];
        let body = &raw[end + sep..];
        let ct = mime::go_lossy(&header(headers, "Content-Type")).to_lowercase();
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
            let mut total = 0;
            let out = mime::rewrite_parts(ct.as_bytes(), raw, &mut |headers, body| {
                if error.is_some() {
                    return None;
                }
                let ct =
                    mime::go_lossy(&mime::extract_header(headers, "Content-Type")).to_lowercase();
                match self.leaf(headers, body, &ct) {
                    Ok((bytes, n)) => {
                        total += n;
                        bytes
                    }
                    Err(e) => {
                        error = Some(e);
                        None
                    }
                }
            })
            .map_err(|_| "invalid multipart framing")?;
            if let Some(e) = error {
                return Err(e);
            }
            return Ok((if total > 0 { out } else { raw.to_vec() }, total));
        }
        match self.leaf(headers, body, &ct)? {
            (Some(body), n) => {
                let (end, sep) = rebuild_end(raw).unwrap();
                let mut out = raw[..end + sep].to_vec();
                out.extend(body);
                Ok((out, n))
            }
            _ => Ok((raw.to_vec(), 0)),
        }
    }
}
fn own_redirect(raw: &str) -> bool {
    let Ok(parsed) = setjoin_authz::go_url::go_url_parse(raw) else {
        return false;
    };
    if !parsed.host.is_empty() {
        return false;
    }
    let mut rest = if parsed.scheme.is_empty() {
        raw
    } else {
        &raw[parsed.scheme.len() + 1..]
    };
    if (!parsed.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let after = &rest[2..];
        rest = after.find('/').map_or("", |i| &after[i..]);
    } else if !parsed.scheme.is_empty() && !rest.starts_with('/') {
        return false;
    }
    let rest = rest.split('#').next().unwrap_or_default();
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    if percent_encoding::percent_decode_str(path).collect::<Vec<_>>() != b"/link-protect" {
        return false;
    }
    for pair in query.split('&') {
        if pair.contains(';') {
            continue;
        }
        let bytes = pair.as_bytes();
        if bytes.iter().enumerate().any(|(i, b)| {
            *b == b'%'
                && (i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit())
        }) {
            continue;
        }
        if let Some((key, value)) = form_urlencoded::parse(pair.as_bytes()).next() {
            if key == "token" {
                return !value.is_empty();
            }
        }
    }
    false
}

/// Go's reader admits raw high bytes but rejects raw controls and overlong
/// physical lines. Preserve its line/soft-break admission before the library:
/// quoted_printable's robust decoder otherwise silently filters high bytes.
fn decode_qp(body: &[u8]) -> Result<Vec<u8>, String> {
    if crate::mutants::on("inbound-no-link-qp-admission") {
        return quoted_printable::decode(body, quoted_printable::ParseMode::Robust)
            .map_err(|_| "invalid quoted-printable body".into());
    }
    if body
        .iter()
        .any(|b| (*b < 32 && !matches!(b, b'\t' | b'\r' | b'\n')) || *b == 127)
    {
        return Err("invalid unescaped quoted-printable byte".into());
    }
    let mut framed = Vec::with_capacity(body.len());
    for line in body.split_inclusive(|b| *b == b'\n') {
        let has_lf = line.ends_with(b"\n");
        if line.len() > 4096 || (!has_lf && line.len() == 4096) {
            return Err("quoted-printable physical line exceeds Go's reader buffer".into());
        }
        let end = line
            .iter()
            .rposition(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
            .map_or(0, |i| i + 1);
        let content = &line[..end];
        if content.windows(2).any(|w| w == b"=\r") {
            return Err("invalid quoted-printable escape before bare CR".into());
        }
        if content.ends_with(b"=") {
            let tail = &line[end..];
            let skip = tail
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t'))
                .unwrap_or(tail.len());
            let tail = &tail[skip..];
            if !(tail.starts_with(b"\n")
                || tail.starts_with(b"\r\n")
                || (!has_lf && tail.is_empty() && content.len() > 1))
            {
                return Err("invalid bytes after quoted-printable soft break".into());
            }
        }
        framed.extend_from_slice(content);
        if has_lf {
            framed.extend_from_slice(if line.ends_with(b"\r\n") {
                b"\r\n"
            } else {
                b"\n"
            });
        }
    }
    // The existing decoder owns hex decoding. Shield raw high bytes and make
    // Go's literal invalid '=' pairs explicit, so shielding cannot change them.
    static ADMISSION: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
        regex::bytes::Regex::new(r"(?-u:=[0-9A-Fa-f]{2}|=[^\r\n]|[\x80-\xff])").unwrap()
    });
    let prepared = ADMISSION.replace_all(&framed, |c: &regex::bytes::Captures<'_>| {
        if c[0].len() == 3 {
            return c[0].to_vec();
        }
        let mut out = Vec::new();
        let bytes = if c[0][0] == b'=' {
            out.extend_from_slice(b"=3D");
            &c[0][1..]
        } else {
            &c[0]
        };
        for b in bytes {
            if *b >= 128 {
                out.extend_from_slice(format!("={b:02X}").as_bytes());
            } else {
                out.push(*b);
            }
        }
        out
    });
    quoted_printable::decode(prepared, quoted_printable::ParseMode::Robust)
        .map_err(|_| "invalid quoted-printable body".into())
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
