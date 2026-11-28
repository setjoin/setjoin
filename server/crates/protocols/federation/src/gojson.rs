//! The slice of Go's `encoding/json` the s2s wire depends on, reproduced
//! byte for byte: validation (`checkValid`), top-level object member
//! extraction with Go's case-insensitive, last-wins field matching, string
//! decoding (invalid UTF-8 and lone surrogates become U+FFFD) and string and
//! raw-message encoding (HTML escaping, U+2028/U+2029, whitespace compaction).
//! Peer-controlled frames must be accepted and answered exactly as Go does.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);
impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for JsonError {}
fn err<T>(m: &str) -> Result<T, JsonError> {
    Err(JsonError(m.to_string()))
}

const MAX_DEPTH: usize = 10_000;

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Scan one value starting at `i` (after whitespace); returns the end index.
fn scan_value(b: &[u8], mut i: usize) -> Result<usize, JsonError> {
    // Explicit container stack: true = object, false = array.
    let mut stack: Vec<bool> = Vec::new();
    loop {
        // Parse a value start.
        while i < b.len() && is_ws(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            return err("unexpected end of JSON input");
        }
        match b[i] {
            b'{' => {
                if stack.len() >= MAX_DEPTH {
                    return err("exceeded max depth");
                }
                i += 1;
                skip_ws(b, &mut i);
                if i < b.len() && b[i] == b'}' {
                    i += 1;
                } else {
                    stack.push(true);
                    i = scan_key(b, i)?;
                    continue;
                }
            }
            b'[' => {
                if stack.len() >= MAX_DEPTH {
                    return err("exceeded max depth");
                }
                i += 1;
                skip_ws(b, &mut i);
                if i < b.len() && b[i] == b']' {
                    i += 1;
                } else {
                    stack.push(false);
                    continue;
                }
            }
            b'"' => i = scan_string(b, i)?,
            b't' => i = literal(b, i, b"true")?,
            b'f' => i = literal(b, i, b"false")?,
            b'n' => i = literal(b, i, b"null")?,
            b'-' | b'0'..=b'9' => i = scan_number(b, i)?,
            _ => return err("invalid character looking for beginning of value"),
        }
        // A value just completed; close containers as far as possible.
        loop {
            match stack.last() {
                None => return Ok(i),
                Some(&is_obj) => {
                    skip_ws(b, &mut i);
                    if i >= b.len() {
                        return err("unexpected end of JSON input");
                    }
                    match b[i] {
                        b',' => {
                            i += 1;
                            if is_obj {
                                skip_ws(b, &mut i);
                                i = scan_key(b, i)?;
                            }
                            break; // next value
                        }
                        b'}' if is_obj => {
                            stack.pop();
                            i += 1;
                        }
                        b']' if !is_obj => {
                            stack.pop();
                            i += 1;
                        }
                        _ => return err("invalid character after value"),
                    }
                }
            }
        }
    }
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && is_ws(b[*i]) {
        *i += 1;
    }
}

/// Key, colon; leaves `i` at the start of the value.
fn scan_key(b: &[u8], mut i: usize) -> Result<usize, JsonError> {
    if i >= b.len() || b[i] != b'"' {
        return err("invalid character looking for beginning of object key string");
    }
    i = scan_string(b, i)?;
    skip_ws(b, &mut i);
    if i >= b.len() || b[i] != b':' {
        return err("invalid character after object key");
    }
    Ok(i + 1)
}

fn literal(b: &[u8], i: usize, lit: &[u8]) -> Result<usize, JsonError> {
    if b.len() >= i + lit.len() && &b[i..i + lit.len()] == lit {
        Ok(i + lit.len())
    } else {
        err("invalid literal")
    }
}

fn scan_string(b: &[u8], mut i: usize) -> Result<usize, JsonError> {
    i += 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Ok(i + 1),
            b'\\' => {
                i += 1;
                match b.get(i) {
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 1,
                    Some(b'u') => {
                        for k in 1..=4 {
                            if !b.get(i + k).is_some_and(|c| c.is_ascii_hexdigit()) {
                                return err(
                                    "invalid character in \\u hexadecimal character escape",
                                );
                            }
                        }
                        i += 5;
                    }
                    _ => return err("invalid character in string escape code"),
                }
            }
            c if c < 0x20 => return err("invalid character in string literal"),
            _ => i += 1,
        }
    }
    err("unexpected end of JSON input")
}

fn scan_number(b: &[u8], mut i: usize) -> Result<usize, JsonError> {
    if b[i] == b'-' {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return err("invalid character in numeric literal"),
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            return err("invalid character after decimal point in numeric literal");
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !b.get(i).is_some_and(u8::is_ascii_digit) {
            return err("invalid character in exponent of numeric literal");
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    Ok(i)
}

/// Go's `json.Valid` / `checkValid`.
pub fn validate(b: &[u8]) -> Result<(), JsonError> {
    let end = scan_value(b, 0)?;
    let mut i = end;
    skip_ws(b, &mut i);
    if i != b.len() {
        return err("invalid character after top-level value");
    }
    Ok(())
}

/// One object member: the decoded key and the verbatim value bytes.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    pub key: String,
    pub value: &'a [u8],
}

/// Decode a top-level JSON document as Go decodes it into a struct: `null` is
/// a no-op (`Ok(None)`), an object yields its members in order, any other
/// value is an unmarshal type error.
pub fn object_members(b: &[u8]) -> Result<Option<Vec<Member<'_>>>, JsonError> {
    validate(b)?;
    let mut i = 0;
    skip_ws(b, &mut i);
    match b[i] {
        b'n' => return Ok(None),
        b'{' => {}
        _ => return err("json: cannot unmarshal into Go struct"),
    }
    i += 1;
    let mut out = Vec::new();
    skip_ws(b, &mut i);
    if b[i] == b'}' {
        return Ok(Some(out));
    }
    loop {
        skip_ws(b, &mut i);
        let kend = scan_string(b, i)?;
        let key = decode_string(&b[i..kend]);
        i = kend;
        skip_ws(b, &mut i);
        i += 1; // colon
        skip_ws(b, &mut i);
        let vend = scan_value(b, i)?;
        out.push(Member {
            key,
            value: &b[i..vend],
        });
        i = vend;
        skip_ws(b, &mut i);
        if b[i] == b',' {
            i += 1;
            continue;
        }
        return Ok(Some(out));
    }
}

/// Go's field matching: exact name first, then case-insensitive; later members
/// override earlier ones.
pub fn key_matches(key: &str, field: &str) -> bool {
    if key.eq_ignore_ascii_case(field) {
        return true;
    }
    // All protocol field tags are ASCII. These are the only non-ASCII
    // simple-fold equivalents of ASCII letters in Go encoding/json.foldRune.
    key.chars()
        .map(|c| match c {
            '\u{212a}' => 'K', // Kelvin sign
            '\u{017f}' => 'S', // long s
            c => c.to_ascii_uppercase(),
        })
        .eq(field.chars().map(|c| c.to_ascii_uppercase()))
}

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let mut v = 0u32;
    for &c in &b[..4] {
        v = v * 16 + (c as char).to_digit(16)?;
    }
    Some(v)
}

/// Go's `unquote` over a validated quoted string (including both quotes).
pub fn decode_string(quoted: &[u8]) -> String {
    let s = &quoted[1..quoted.len() - 1];
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'\\' => {
                i += 1;
                match s[i] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    _ => {
                        // \uXXXX
                        let r = hex4(&s[i + 1..]).unwrap_or(0xFFFD);
                        i += 4;
                        let mut ch = char::from_u32(r);
                        if (0xD800..0xE000).contains(&r) {
                            ch = None;
                            if r < 0xDC00
                                && s.get(i + 1) == Some(&b'\\')
                                && s.get(i + 2) == Some(&b'u')
                            {
                                if let Some(r2) = hex4(&s[(i + 3).min(s.len())..]) {
                                    if (0xDC00..0xE000).contains(&r2) {
                                        let dec = 0x10000 + ((r - 0xD800) << 10) + (r2 - 0xDC00);
                                        ch = char::from_u32(dec);
                                        i += 6;
                                    }
                                }
                            }
                        }
                        out.push(ch.unwrap_or('\u{FFFD}'));
                    }
                }
                i += 1;
            }
            _ => {
                // Copy a run of non-escape bytes, replacing each invalid byte.
                let start = i;
                while i < s.len() && s[i] != b'\\' {
                    i += 1;
                }
                let mut run = &s[start..i];
                loop {
                    match std::str::from_utf8(run) {
                        Ok(v) => {
                            out.push_str(v);
                            break;
                        }
                        Err(e) => {
                            let (good, rest) = run.split_at(e.valid_up_to());
                            out.push_str(std::str::from_utf8(good).unwrap());
                            out.push('\u{FFFD}');
                            run = &rest[1..];
                        }
                    }
                }
            }
        }
    }
    out
}

/// How a Go struct field of a given type reads a raw member value.
pub fn field_string(raw: &[u8]) -> Result<Option<String>, JsonError> {
    match raw[0] {
        b'n' => Ok(None),
        b'"' => Ok(Some(decode_string(raw))),
        _ => err("json: cannot unmarshal into Go struct field of type string"),
    }
}

/// `strconv.ParseInt(literal, 10, 64)` after Go's number-literal check.
pub fn field_i64(raw: &[u8]) -> Result<Option<i64>, JsonError> {
    match raw[0] {
        b'n' => Ok(None),
        b'-' | b'0'..=b'9' => std::str::from_utf8(raw)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .map(Some)
            .ok_or_else(|| {
                JsonError("json: cannot unmarshal number into Go struct field of type int64".into())
            }),
        _ => err("json: cannot unmarshal into Go struct field of type int64"),
    }
}

/// `bool` fields.
pub fn field_bool(raw: &[u8]) -> Result<Option<bool>, JsonError> {
    match raw[0] {
        b'n' => Ok(None),
        b't' => Ok(Some(true)),
        b'f' => Ok(Some(false)),
        _ => err("json: cannot unmarshal into Go struct field of type bool"),
    }
}

/// `[]string`: `null` and arrays of strings (null elements decode as "").
pub fn field_string_array(raw: &[u8]) -> Result<Option<Vec<String>>, JsonError> {
    match raw[0] {
        b'n' => Ok(None),
        b'[' => {
            let mut out = Vec::new();
            let mut i = 1;
            skip_ws(raw, &mut i);
            if raw[i] == b']' {
                return Ok(Some(out));
            }
            loop {
                skip_ws(raw, &mut i);
                let end = scan_value(raw, i)?;
                match field_string(&raw[i..end])? {
                    Some(s) => out.push(s),
                    None => out.push(String::new()),
                }
                i = end;
                skip_ws(raw, &mut i);
                if raw[i] == b',' {
                    i += 1;
                    continue;
                }
                return Ok(Some(out));
            }
        }
        _ => err("json: cannot unmarshal into Go struct field of type []string"),
    }
}

/// Append `s` as Go's `json.Marshal` encodes a string (HTML-escaped).
pub fn push_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '<' => out.extend_from_slice(b"\\u003c"),
            '>' => out.extend_from_slice(b"\\u003e"),
            '&' => out.extend_from_slice(b"\\u0026"),
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// A `json.RawMessage` as `json.Marshal` emits it: compacted (insignificant
/// whitespace dropped) with `< > &`, U+2028 and U+2029 escaped. The input must
/// already be valid JSON.
pub fn compact_escape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut in_str = false;
    let mut esc = false;
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if in_str {
            if esc {
                esc = false;
                out.push(c);
            } else if c == b'\\' {
                esc = true;
                out.push(c);
            } else if c == b'"' {
                in_str = false;
                out.push(c);
            } else if c == b'<' {
                out.extend_from_slice(b"\\u003c");
            } else if c == b'>' {
                out.extend_from_slice(b"\\u003e");
            } else if c == b'&' {
                out.extend_from_slice(b"\\u0026");
            } else if c == 0xE2
                && raw.get(i + 1) == Some(&0x80)
                && matches!(raw.get(i + 2), Some(0xA8 | 0xA9))
            {
                out.extend_from_slice(if raw[i + 2] == 0xA8 {
                    b"\\u2028"
                } else {
                    b"\\u2029"
                });
                i += 2;
            } else {
                out.push(c);
            }
        } else if c == b'"' {
            in_str = true;
            out.push(c);
        } else if !is_ws(c) {
            out.push(c);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_string_encoding() {
        let mut o = Vec::new();
        push_string(&mut o, "a<b>&\"\\\n\u{1}\u{2028}é");
        let want = [r#""a\u003cb\u003e\u0026\"\\\n\u0001\u2028"#, "é\""].concat();
        assert_eq!(String::from_utf8(o).unwrap(), want);
    }

    #[test]
    fn compaction_escapes_inside_strings_only() {
        let c = compact_escape(b"{ \"a\" : \"x y<\" , \"b\" : [1, 2] }");
        assert_eq!(c, b"{\"a\":\"x y\\u003c\",\"b\":[1,2]}");
    }

    #[test]
    fn lone_surrogates_and_invalid_utf8_decode_like_go() {
        assert_eq!(decode_string(br#""a\ud800b""#), "a\u{fffd}b");
        assert_eq!(decode_string(r#""😀""#.as_bytes()), "\u{1f600}");
        assert_eq!(decode_string(b"\"\xe2\x82x\""), "\u{fffd}\u{fffd}x");
    }

    #[test]
    fn members_are_case_insensitive_candidates_in_order() {
        let m = object_members(br#"{"Kind":"a","kind":"b"}"#)
            .unwrap()
            .unwrap();
        assert_eq!(m.len(), 2);
        assert!(key_matches(&m[0].key, "kind"));
        assert!(object_members(b"null").unwrap().is_none());
        assert!(object_members(b"[]").is_err());
        assert!(object_members(b"{\"a\":1} x").is_err());
        assert!(object_members(b"{\"a\":01}").is_err());
    }
}
