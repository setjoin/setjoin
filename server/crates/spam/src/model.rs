//! Frozen Go `internal/spam`: keyed feature extraction and sealed FTRL-Proximal models.
use regex::bytes::Regex;
use setjoin_mime::{decode_rune, trim_space};
use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};
#[path = "spam_model/go_exp.rs"]
mod go_exp;
#[path = "spam_model/unicode15.rs"]
mod unicode15;

pub const SIZE: usize = 1 << 20;
const WORD: &str = r"[a-zA-Z][a-zA-Z0-9]{2,}";
static WORDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(WORD).unwrap());
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());
static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?-u:https?://[^\x09\x0a\x0c\x0d <>"']+)"#).unwrap());
static HTML: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:<[^>]+>)").unwrap());

fn to_lower(mut bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    while !bytes.is_empty() {
        let (r, n) = decode_rune(bytes);
        bytes = &bytes[n..];
        if r < 128 {
            out.push(if (65..=90).contains(&r) {
                (r + 32) as u8
            } else {
                r as u8
            });
            continue;
        }
        let lower = unicode15::LOWER
            .binary_search_by_key(&r, |pair| pair.0)
            .map(|i| unicode15::LOWER[i].1)
            .unwrap_or(r);
        let c = char::from_u32(lower).expect("Go Unicode scalar");
        let mut encoded = [0; 4];
        out.extend_from_slice(c.encode_utf8(&mut encoded).as_bytes());
    }
    out
}

fn count_caps(mut bytes: &[u8]) -> usize {
    let mut count = 0;
    while !bytes.is_empty() {
        let (r, n) = decode_rune(bytes);
        bytes = &bytes[n..];
        if r < 128 {
            count += usize::from((65..=90).contains(&r));
            continue;
        }
        let end = unicode15::UPPER.partition_point(|range| range.0 <= r);
        if end > 0 {
            let (lo, hi, stride) = unicode15::UPPER[end - 1];
            count += usize::from(r <= hi && (r - lo) % stride == 0);
        }
    }
    count
}

pub fn feature_key(user: i64) -> u32 {
    user.to_le_bytes()
        .iter()
        .fold(14695981039346656037u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(1099511628211)
        }) as u32
}

fn feature_index(key: u32, token: &[u8]) -> usize {
    key.to_le_bytes()
        .iter()
        .chain(token)
        .fold(2166136261u32, |h, b| {
            (h ^ u32::from(*b)).wrapping_mul(16777619)
        }) as usize
        % SIZE
}

fn headers(raw: &[u8]) -> (HashMap<Vec<u8>, Vec<u8>>, &[u8]) {
    let separator = [(b"\r\n\r\n".as_slice(), 4), (b"\n\n".as_slice(), 2)]
        .into_iter()
        .filter_map(|(sep, len)| raw.windows(len).position(|w| w == sep).map(|at| (at, len)))
        .min_by_key(|x| x.0);
    let (head, body) = separator.map_or((raw, &[][..]), |(at, len)| (&raw[..at], &raw[at + len..]));
    let mut out: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut last = Vec::new();
    for line in head.split(|b| *b == b'\n') {
        let line = line.trim_ascii_end_cr();
        if line.is_empty() {
            continue;
        }
        if matches!(line[0], b' ' | b'\t') {
            if let Some(value) = out.get_mut(&last) {
                value.push(b' ');
                value.extend_from_slice(trim_space(line));
            }
            continue;
        }
        let Some(at) = line.iter().position(|b| *b == b':').filter(|at| *at > 0) else {
            last.clear();
            continue;
        };
        last = to_lower(trim_space(&line[..at]));
        out.entry(last.clone())
            .or_insert_with(|| trim_space(&line[at + 1..]).to_vec());
    }
    (out, body)
}

// trim only CR, as bytes.TrimRight(line, "\r") in Go.
trait TrimCr {
    fn trim_ascii_end_cr(&self) -> &[u8];
}
impl TrimCr for [u8] {
    fn trim_ascii_end_cr(&self) -> &[u8] {
        let mut end = self.len();
        while end > 0 && self[end - 1] == b'\r' {
            end -= 1;
        }
        &self[..end]
    }
}

fn unescape(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < s.len() {
        if s[at] == b'%' {
            let a = (*s.get(at + 1)? as char).to_digit(16)?;
            let b = (*s.get(at + 2)? as char).to_digit(16)?;
            out.push((a * 16 + b) as u8);
            at += 3;
        } else {
            out.push(s[at]);
            at += 1;
        }
    }
    Some(out)
}

// net/url's host escaping rules differ from path/userinfo decoding. This
// parser only creates classifier tokens; it never authorizes a network dial.
fn host_byte_allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!$&'()*+,;=:[]<>\"-._~".contains(&b)
}

fn unescape_host(raw: &[u8], zone: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        let b = raw[at];
        if b == b'%' {
            let hi = (*raw.get(at + 1)? as char).to_digit(16)? as u8;
            let lo = (*raw.get(at + 2)? as char).to_digit(16)? as u8;
            let value = hi * 16 + lo;
            let percent = &raw[at..at + 3] == b"%25";
            if if zone {
                !percent && value != b' ' && !host_byte_allowed(value)
            } else {
                value < 128 && !percent
            } {
                return None;
            }
            out.push(value);
            at += 3;
        } else {
            if b < 128 && !host_byte_allowed(b) {
                return None;
            }
            out.push(b);
            at += 1;
        }
    }
    Some(out)
}

fn valid_port(suffix: &[u8]) -> bool {
    suffix.is_empty() || (suffix[0] == b':' && suffix[1..].iter().all(u8::is_ascii_digit))
}

fn parsed_host(host: &[u8]) -> Option<Vec<u8>> {
    match host.iter().rposition(|b| *b == b'[') {
        Some(0) => {
            let close = host.iter().rposition(|b| *b == b']')?;
            let suffix = &host[close + 1..];
            if !valid_port(suffix) {
                return None;
            }
            let literal = &host[1..close];
            let name = if let Some(zone) = literal.windows(3).position(|s| s == b"%25") {
                let mut name = unescape_host(&literal[..zone], false)?;
                name.extend_from_slice(&unescape_host(&literal[zone..], true)?);
                name
            } else {
                unescape_host(literal, false)?
            };
            let address = if let Some(zone) = name.iter().position(|b| *b == b'%') {
                if zone + 1 == name.len() {
                    return None;
                }
                &name[..zone]
            } else {
                &name
            };
            std::str::from_utf8(address)
                .ok()?
                .parse::<std::net::Ipv6Addr>()
                .ok()?;
            let mut out = vec![b'['];
            out.extend_from_slice(&name);
            out.push(b']');
            out.extend_from_slice(suffix);
            Some(out)
        }
        Some(_) => None,
        None => {
            if let Some(colon) = host.iter().position(|b| *b == b':') {
                // Go 1.26's default strict-colon rule for http/https.
                if !valid_port(&host[colon..]) {
                    return None;
                }
            }
            unescape_host(host, false)
        }
    }
}

/// The fields consumed from net/url.Parse, without WHATWG path/IDNA normalization.
fn url_parts(raw: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if raw.iter().any(|b| *b < 32 || *b == 127) {
        return None;
    }
    let rest = &raw[raw.windows(3).position(|s| s == b"://")? + 3..];
    let end = rest
        .iter()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority.rsplit(|b| *b == b'@').next()?;
    if let Some(at) = authority.iter().rposition(|b| *b == b'@') {
        let userinfo = &authority[..at];
        if !userinfo
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(b))
        {
            return None;
        }
        unescape(userinfo)?;
    }
    let host = to_lower(&parsed_host(host)?);
    let tail = &rest[end..];
    let path_end = tail
        .iter()
        .position(|b| matches!(b, b'?' | b'#'))
        .unwrap_or(tail.len());
    let path = unescape(&tail[..path_end])?;
    if let Some(at) = tail.iter().position(|b| *b == b'#') {
        unescape(&tail[at + 1..])?;
    }
    Some((host, path))
}

fn features(raw: &[u8], key: u32) -> Vec<usize> {
    let (headers, body) = headers(raw);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut add = |token: &[u8]| {
        let i = feature_index(key, token);
        if seen.insert(i) {
            out.push(i);
        }
    };
    let mut token = |prefix: &[u8], text: &[u8]| {
        let mut token = prefix.to_vec();
        token.extend_from_slice(text);
        add(&token);
    };
    if let Some(from) = headers.get(b"from".as_slice()).filter(|s| !s.is_empty()) {
        if let Some(addr) = EMAIL.find(from) {
            token(b"from:", &to_lower(addr.as_bytes()));
        } else {
            token(b"from:addr:", &to_lower(from));
        }
    }
    if let Some(subject) = headers.get(b"subject".as_slice()).filter(|s| !s.is_empty()) {
        for word in WORDS.find_iter(&to_lower(subject)) {
            token(b"s:", word.as_bytes());
        }
        if count_caps(subject) as f64 / subject.len() as f64 > 0.5 {
            token(b"", b"allcaps");
        }
    }
    for url in URL.find_iter(raw) {
        if let Some((host, path)) = url_parts(url.as_bytes()) {
            let parts: Vec<_> = host.split(|b| *b == b'.').collect();
            if parts.len() >= 2 {
                let mut s = parts[parts.len() - 2].to_vec();
                s.push(b'.');
                s.extend_from_slice(parts[parts.len() - 1]);
                token(b"url:", &s);
            }
            for part in path.split(|b| *b == b'/').filter(|s| !s.is_empty()) {
                token(b"path:", part);
            }
        }
    }
    if let Some(ct) = headers.get(b"content-type".as_slice()) {
        let ct = to_lower(ct);
        for (needle, name) in [
            (b"text/html".as_slice(), b"ct:html".as_slice()),
            (b"text/plain".as_slice(), b"ct:plain".as_slice()),
        ] {
            if ct.windows(needle.len()).any(|s| s == needle) {
                token(b"", name);
            }
        }
    }
    if !body.is_empty() {
        let body = to_lower(&HTML.replace_all(body, b" ".as_slice()));
        for word in WORDS.find_iter(&body) {
            token(b"w:", word.as_bytes());
        }
        for kw in [
            "viagra",
            "cialis",
            "lottery",
            "winner",
            "million",
            "prize",
            "urgent",
            "click",
            "free",
            "offer",
            "discount",
            "guaranteed",
            "act now",
            "limited time",
            "exclusive",
        ] {
            if body.windows(kw.len()).any(|s| s == kw.as_bytes()) {
                token(b"susp:", kw.as_bytes());
            }
        }
    }
    if !headers.contains_key(b"message-id".as_slice()) {
        token(b"", b"miss:mid");
    }
    if !headers.contains_key(b"date".as_slice()) {
        token(b"", b"miss:date");
    }
    out
}

pub struct Model {
    user: i64,
    w: Vec<f64>,
    z: Vec<f64>,
    n: Vec<f64>,
}
impl Model {
    pub fn new(user: i64) -> Self {
        Self {
            user,
            w: vec![0.; SIZE],
            z: vec![0.; SIZE],
            n: vec![0.; SIZE],
        }
    }
    pub fn load(user: i64, data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 16 + SIZE * 24
            || &data[..4] != b"SPM1"
            || data[4..8] != feature_key(user).to_le_bytes()
            || &data[8..12] != b"FTR2"
            || data[12..16] != (SIZE as u32).to_le_bytes()
        {
            return Err("invalid sealed spam model");
        }
        let mut model = Self::new(user);
        let mut chunks = data[16..].as_chunks::<8>().0.iter();
        for (i, table) in [&mut model.w, &mut model.z, &mut model.n]
            .into_iter()
            .enumerate()
        {
            for v in table.iter_mut() {
                *v = f64::from_le_bytes(*chunks.next().unwrap());
                if !v.is_finite() || (i == 2 && *v < 0.) {
                    return Err("invalid spam model numeric state");
                }
            }
        }
        Ok(model)
    }
    pub fn save(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + SIZE * 24);
        out.extend_from_slice(b"SPM1");
        out.extend_from_slice(&feature_key(self.user).to_le_bytes());
        out.extend_from_slice(b"FTR2");
        out.extend_from_slice(&(SIZE as u32).to_le_bytes());
        for table in [&self.w, &self.z, &self.n] {
            for v in table {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        out
    }
    fn predict(&self, features: &[usize]) -> f64 {
        let dot = features.iter().fold(0., |dot, i| dot + self.w[*i]);
        1. / (1. + go_exp::exp(-dot))
    }
    pub fn score(&self, raw: &[u8]) -> f64 {
        let f = features(raw, feature_key(self.user));
        if f.is_empty() {
            0.
        } else {
            self.predict(&f)
        }
    }
    pub fn train(&mut self, raw: &[u8], spam: bool) {
        let f = features(raw, feature_key(self.user));
        if f.is_empty() {
            return;
        }
        let g = self.predict(&f) - if spam { 1. } else { 0. };
        for i in f {
            let sigma = ((self.n[i] + g * g).sqrt() - self.n[i].sqrt()) / 0.1;
            self.z[i] += g - sigma * self.w[i];
            self.n[i] += g * g;
            self.w[i] = if self.z[i].abs() <= 0.01 {
                0.
            } else {
                let sign = if self.z[i] < 0. { -1. } else { 1. };
                (sign * 0.01 - self.z[i]) / ((1. + self.n[i].sqrt()) / 0.1 + 0.01)
            };
        }
    }
}
