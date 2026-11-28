//! Go's `mime` package as far as import reads it: `ParseMediaType`, the
//! RFC 2047 `WordDecoder.Decode` with no `CharsetReader`, and the
//! `htmlindex` body decoder (`DecodeCharset`).
use super::gostr::{to_lower, trim_left_space, trim_space};
use std::collections::BTreeMap;

fn is_tspecial(c: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&c)
}
fn is_token_char(c: u8) -> bool {
    c > 0x20 && c < 0x7f && !is_tspecial(c)
}

fn consume_token(v: &[u8]) -> (&[u8], &[u8]) {
    match v.iter().position(|c| !is_token_char(*c)) {
        Some(i) => (&v[..i], &v[i..]),
        None => (v, &[]),
    }
}

fn consume_value(v: &[u8]) -> (Vec<u8>, &[u8]) {
    if v.is_empty() {
        return (Vec::new(), v);
    }
    if v[0] != b'"' {
        let (t, rest) = consume_token(v);
        return (t.to_vec(), rest);
    }
    let mut buf = Vec::new();
    let mut i = 1;
    while i < v.len() {
        let r = v[i];
        if r == b'"' {
            return (buf, &v[i + 1..]);
        }
        if r == b'\\' && i + 1 < v.len() && is_tspecial(v[i + 1]) {
            buf.push(v[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (Vec::new(), v);
        }
        buf.push(r);
        i += 1;
    }
    (Vec::new(), v)
}

type Param<'a> = (Vec<u8>, Vec<u8>, &'a [u8]);

fn consume_media_param(v: &[u8]) -> Option<Param<'_>> {
    let rest = trim_left_space(v);
    let rest = rest.strip_prefix(b";")?;
    let rest = trim_left_space(rest);
    let (param, rest) = consume_token(rest);
    let param = to_lower(param);
    if param.is_empty() {
        return None;
    }
    let rest = trim_left_space(rest);
    let rest = rest.strip_prefix(b"=")?;
    let rest = trim_left_space(rest);
    let (value, rest2) = consume_value(rest);
    if value.is_empty() && rest2.len() == rest.len() {
        return None;
    }
    Some((param, value, rest2))
}

fn ishex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}
fn unhex(c: u8) -> u8 {
    (c as char).to_digit(16).unwrap_or(0) as u8
}

fn percent_hex_unescape(s: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    let mut out = Vec::new();
    while i < s.len() {
        if s[i] != b'%' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        if i + 2 >= s.len() || !ishex(s[i + 1]) || !ishex(s[i + 2]) {
            return None;
        }
        out.push(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
        i += 3;
    }
    Some(out)
}

fn decode2231_enc(v: &[u8]) -> Option<Vec<u8>> {
    let q = v.iter().position(|c| *c == b'\'')?;
    let (charset, v) = (&v[..q], &v[q + 1..]);
    let q2 = v.iter().position(|c| *c == b'\'')?;
    let other = &v[q2 + 1..];
    let charset = to_lower(charset);
    if charset != b"us-ascii" && charset != b"utf-8" {
        return None;
    }
    percent_hex_unescape(other)
}

pub type Params = BTreeMap<Vec<u8>, Vec<u8>>;

/// `mime.ParseMediaType`. `Err(())` is any of Go's errors; the media type is
/// all callers read besides the parameters.
pub fn parse_media_type(v: &[u8]) -> Result<(Vec<u8>, Params), ()> {
    let semi = v.iter().position(|c| *c == b';');
    let base = &v[..semi.unwrap_or(v.len())];
    let mediatype = trim_space(&to_lower(base)).to_vec();
    // checkMediaTypeDisposition
    let (typ, rest) = consume_token(&mediatype);
    if typ.is_empty() {
        return Err(());
    }
    if !rest.is_empty() {
        let rest = rest.strip_prefix(b"/").ok_or(())?;
        let (subtype, rest) = consume_token(rest);
        if subtype.is_empty() || !rest.is_empty() {
            return Err(());
        }
    }
    let mut params = Params::new();
    let mut continuation: BTreeMap<Vec<u8>, Params> = BTreeMap::new();
    let mut v = &v[base.len()..];
    while !v.is_empty() {
        v = trim_left_space(v);
        if v.is_empty() {
            break;
        }
        match consume_media_param(v) {
            None => {
                // Trailing semicolons are not an error.
                if trim_space(v) == b";" {
                    break;
                }
                return Err(());
            }
            Some((key, value, rest)) => {
                let target = match key.iter().position(|c| *c == b'*') {
                    Some(star) => continuation.entry(key[..star].to_vec()).or_default(),
                    None => &mut params,
                };
                if let Some(existing) = target.get(&key) {
                    if *existing != value {
                        return Err(());
                    }
                }
                target.insert(key, value);
                v = rest;
            }
        }
    }
    for (key, pieces) in continuation {
        let mut single = key.clone();
        single.push(b'*');
        if let Some(v) = pieces.get(&single) {
            if let Some(decoded) = decode2231_enc(v) {
                params.insert(key, decoded);
            }
            continue;
        }
        let mut buf = Vec::new();
        let mut valid = false;
        for n in 0.. {
            let mut simple = key.clone();
            simple.extend_from_slice(format!("*{n}").as_bytes());
            if let Some(v) = pieces.get(&simple) {
                valid = true;
                buf.extend_from_slice(v);
                continue;
            }
            let mut encoded = simple;
            encoded.push(b'*');
            let Some(v) = pieces.get(&encoded) else { break };
            valid = true;
            if n == 0 {
                if let Some(decoded) = decode2231_enc(v) {
                    buf.extend_from_slice(&decoded);
                }
            } else if let Some(decoded) = percent_hex_unescape(v) {
                buf.extend_from_slice(&decoded);
            }
        }
        if valid {
            params.insert(key, buf);
        }
    }
    Ok((mediatype, params))
}

/// Why `WordDecoder.Decode` failed: a charset it does not handle is told
/// apart by `net/mail`, which keeps such a word as encoded text.
#[derive(Debug, PartialEq, Eq)]
pub enum WordError {
    Invalid,
    Charset,
}

fn q_decode(s: &[u8]) -> Result<Vec<u8>, WordError> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'_' => out.push(b' '),
            b'=' => {
                if i + 2 >= s.len() || !ishex(s[i + 1]) || !ishex(s[i + 2]) {
                    return Err(WordError::Invalid);
                }
                out.push(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
                i += 2;
            }
            c if (b' '..=b'~').contains(&c) || c == b'\n' || c == b'\r' || c == b'\t' => {
                out.push(c)
            }
            _ => return Err(WordError::Invalid),
        }
        i += 1;
    }
    Ok(out)
}

fn b_decode(s: &[u8]) -> Result<Vec<u8>, WordError> {
    use base64::{
        engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig},
        Engine,
    };
    // Go's StdEncoding ignores CR and LF, requires padding and tolerates
    // non-zero trailing bits.
    let cleaned: Vec<u8> = s
        .iter()
        .copied()
        .filter(|c| *c != b'\r' && *c != b'\n')
        .collect();
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    engine.decode(cleaned).map_err(|_| WordError::Invalid)
}

/// `new(mime.WordDecoder).Decode(word)`: only UTF-8, ISO-8859-1 and US-ASCII
/// are handled, anything else is a charset error.
pub fn decode_word(word: &[u8]) -> Result<Vec<u8>, WordError> {
    if word.len() < 8
        || !word.starts_with(b"=?")
        || !word.ends_with(b"?=")
        || word.iter().filter(|c| **c == b'?').count() != 4
    {
        return Err(WordError::Invalid);
    }
    let word = &word[2..word.len() - 2];
    let q = word
        .iter()
        .position(|c| *c == b'?')
        .ok_or(WordError::Invalid)?;
    let (charset, text) = (&word[..q], &word[q + 1..]);
    if charset.is_empty() {
        return Err(WordError::Invalid);
    }
    let q = text
        .iter()
        .position(|c| *c == b'?')
        .ok_or(WordError::Invalid)?;
    let (encoding, text) = (&text[..q], &text[q + 1..]);
    if encoding.len() != 1 {
        return Err(WordError::Invalid);
    }
    let content = match encoding[0] {
        b'B' | b'b' => b_decode(text)?,
        b'Q' | b'q' => q_decode(text)?,
        _ => return Err(WordError::Invalid),
    };
    let lower = charset.to_ascii_lowercase();
    match lower.as_slice() {
        b"utf-8" => Ok(content),
        b"iso-8859-1" => Ok(content
            .iter()
            .map(|b| char::from(*b))
            .collect::<String>()
            .into_bytes()),
        b"us-ascii" => {
            let mut out = Vec::new();
            for c in content {
                if c >= 0x80 {
                    out.extend_from_slice("\u{fffd}".as_bytes());
                } else {
                    out.push(c);
                }
            }
            Ok(out)
        }
        _ => Err(WordError::Charset),
    }
}

/// `mimeutil.DecodeCharset`: the body in UTF-8 through the WHATWG decoder the
/// Content-Type's charset names; the body unchanged for a missing, plain,
/// unknown or failing charset.
pub fn decode_charset(body: &[u8], content_type: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let Ok((_, params)) = parse_media_type(content_type) else {
        return body.to_vec();
    };
    let charset = to_lower(params.get(b"charset".as_slice()).map_or(&[][..], |v| v));
    if charset.is_empty() || charset == b"utf-8" || charset == b"us-ascii" {
        return body.to_vec();
    }
    // htmlindex.Get lower-cases and trims Unicode space around the label.
    let label = trim_space(&charset);
    let Some(encoding) = encoding_rs::Encoding::for_label(label) else {
        return body.to_vec();
    };
    let (text, _) = encoding.decode_without_bom_handling(body);
    text.into_owned().into_bytes()
}
