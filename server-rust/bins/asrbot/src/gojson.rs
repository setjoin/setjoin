//! The slice of Go's `encoding/json` the control API observes.
//!
//! Decoding mirrors `json.NewDecoder(r).Decode(&struct{...})`: the first value
//! must be valid JSON (depth limit 10000), trailing bytes are ignored, keys
//! match struct fields case-insensitively, `null` leaves a field unset, any
//! other non-string value for a matched field is an error, invalid UTF-8 and
//! lone surrogates become U+FFFD. Encoding mirrors `Encoder.Encode` with the
//! default HTML escaping.

const MAX_DEPTH: usize = 10_000;

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError;

/// Decode the first JSON value of `input` as an object and return the string
/// value of each requested field (`None` when absent or `null`).
pub fn decode_string_fields(
    input: &[u8],
    fields: &[&str],
) -> Result<Vec<Option<String>>, DecodeError> {
    let mut p = Parser { s: input, i: 0 };
    p.ws();
    if p.i >= p.s.len() {
        return Err(DecodeError);
    }
    let mut out: Vec<Option<String>> = vec![None; fields.len()];
    match p.s[p.i] {
        b'n' => {
            p.literal(b"null")?;
            Ok(out)
        }
        b'{' => {
            p.i += 1;
            p.ws();
            if p.peek()? == b'}' {
                return Ok(out);
            }
            let mut type_error = false;
            loop {
                p.ws();
                if p.peek()? != b'"' {
                    return Err(DecodeError);
                }
                let key = p.string()?;
                p.ws();
                if p.peek()? != b':' {
                    return Err(DecodeError);
                }
                p.i += 1;
                p.ws();
                let slot = fields.iter().position(|f| fold(f) == fold(&key));
                match (slot, p.peek()?) {
                    (Some(slot), b'"') => out[slot] = Some(p.string()?),
                    (Some(_), b'n') => p.literal(b"null")?,
                    (Some(_), _) => {
                        type_error = true;
                        p.skip_value(1)?;
                    }
                    (None, _) => p.skip_value(1)?,
                }
                p.ws();
                match p.peek()? {
                    b',' => p.i += 1,
                    b'}' => break,
                    _ => return Err(DecodeError),
                }
            }
            if type_error {
                Err(DecodeError)
            } else {
                Ok(out)
            }
        }
        // Any other valid value decodes into a struct as a type error; an
        // invalid one is a syntax error. Both are a 400 for the handlers.
        _ => Err(DecodeError),
    }
}

/// Go's `foldName` for the ASCII field names used here, including the two
/// non-ASCII code points whose simple-fold orbit contains an ASCII letter.
fn fold(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            c => c.to_lowercase().next().unwrap_or(c),
        })
        .collect()
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<u8, DecodeError> {
        self.s.get(self.i).copied().ok_or(DecodeError)
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), DecodeError> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(DecodeError)
        }
    }

    /// Parse a string at the opening quote into Go's decoded form.
    fn string(&mut self) -> Result<String, DecodeError> {
        self.i += 1;
        let mut raw: Vec<u8> = Vec::new();
        loop {
            let b = self.peek()?;
            self.i += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => raw.push(b'"'),
                        b'\\' => raw.push(b'\\'),
                        b'/' => raw.push(b'/'),
                        b'b' => raw.push(8),
                        b'f' => raw.push(12),
                        b'n' => raw.push(b'\n'),
                        b'r' => raw.push(b'\r'),
                        b't' => raw.push(b'\t'),
                        b'u' => {
                            let mut c = self.hex4()?;
                            if (0xD800..0xDC00).contains(&c) {
                                // A high surrogate pairs only with an escaped low one.
                                let save = self.i;
                                let mut low = None;
                                if self.s[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    if let Ok(l) = self.hex4() {
                                        if (0xDC00..0xE000).contains(&l) {
                                            low = Some(l);
                                        }
                                    }
                                }
                                match low {
                                    Some(l) => c = 0x10000 + ((c - 0xD800) << 10) + (l - 0xDC00),
                                    None => {
                                        self.i = save;
                                        c = 0xFFFD;
                                    }
                                }
                            } else if (0xDC00..0xE000).contains(&c) {
                                c = 0xFFFD;
                            }
                            let ch = char::from_u32(c).unwrap_or('\u{FFFD}');
                            let mut buf = [0u8; 4];
                            raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(DecodeError),
                    }
                }
                0..=0x1F => return Err(DecodeError),
                b => raw.push(b),
            }
        }
        Ok(lossy_per_byte(&raw))
    }

    fn hex4(&mut self) -> Result<u32, DecodeError> {
        let digits = self.s.get(self.i..self.i + 4).ok_or(DecodeError)?;
        let mut value = 0u32;
        for d in digits {
            value = value * 16 + (*d as char).to_digit(16).ok_or(DecodeError)?;
        }
        self.i += 4;
        Ok(value)
    }

    fn number(&mut self) -> Result<(), DecodeError> {
        if self.peek()? == b'-' {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => self.digits(),
            _ => return Err(DecodeError),
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !self.peek()?.is_ascii_digit() {
                return Err(DecodeError);
            }
            self.digits();
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !self.peek()?.is_ascii_digit() {
                return Err(DecodeError);
            }
            self.digits();
        }
        Ok(())
    }

    fn digits(&mut self) {
        while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
    }

    /// Validate and skip one value iteratively (no recursion: depth is bounded
    /// by `MAX_DEPTH` only). `depth` is the nesting of the value being read.
    fn skip_value(&mut self, depth: usize) -> Result<(), DecodeError> {
        // Stack of open containers: true for object, false for array.
        let mut stack: Vec<bool> = Vec::new();
        let mut depth = depth;
        loop {
            self.ws();
            // Read one value start.
            match self.peek()? {
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(DecodeError);
                    }
                    let object = self.s[self.i] == b'{';
                    self.i += 1;
                    self.ws();
                    let close = if object { b'}' } else { b']' };
                    if self.peek()? == close {
                        self.i += 1;
                        depth -= 1;
                    } else {
                        stack.push(object);
                        if object {
                            self.object_key()?;
                        }
                        continue;
                    }
                }
                b'"' => {
                    self.string()?;
                }
                b't' => self.literal(b"true")?,
                b'f' => self.literal(b"false")?,
                b'n' => self.literal(b"null")?,
                b'-' | b'0'..=b'9' => self.number()?,
                _ => return Err(DecodeError),
            }
            // A value ended: close containers / move to the next element.
            loop {
                let Some(&object) = stack.last() else {
                    return Ok(());
                };
                self.ws();
                match (self.peek()?, object) {
                    (b',', _) => {
                        self.i += 1;
                        self.ws();
                        if object {
                            self.object_key()?;
                        }
                        break;
                    }
                    (b'}', true) | (b']', false) => {
                        self.i += 1;
                        stack.pop();
                        depth -= 1;
                    }
                    _ => return Err(DecodeError),
                }
            }
        }
    }

    fn object_key(&mut self) -> Result<(), DecodeError> {
        self.ws();
        if self.peek()? != b'"' {
            return Err(DecodeError);
        }
        self.string()?;
        self.ws();
        if self.peek()? != b':' {
            return Err(DecodeError);
        }
        self.i += 1;
        Ok(())
    }
}

/// Replace each invalid UTF-8 byte with U+FFFD as Go's `utf8.DecodeRune` loop does.
fn lossy_per_byte(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or(""));
                out.push('\u{FFFD}');
                rest = &bad[1..];
            }
        }
    }
    out
}

/// `json.Encoder` output for a string: HTML-escaped (`<`, `>`, `&`), U+2028/2029 escaped.
pub fn encode_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room_token(input: &str) -> Result<(Option<String>, Option<String>), DecodeError> {
        let mut v = decode_string_fields(input.as_bytes(), &["room", "token"])?;
        let token = v.pop().unwrap();
        Ok((v.pop().unwrap(), token))
    }

    #[test]
    fn decodes_fields_case_insensitively_last_wins_and_ignores_trailing_bytes() {
        let got = room_token(
            r#"{"ROOM":"a","Token":"t","room":"b","extra":{"x":[1,2.5e3,true,null]}} trailing"#,
        );
        assert_eq!(got, Ok((Some("b".into()), Some("t".into()))));
    }

    #[test]
    fn null_leaves_fields_unset_and_non_strings_error() {
        assert_eq!(room_token(r#"{"room":null}"#), Ok((None, None)));
        assert_eq!(room_token("null"), Ok((None, None)));
        assert_eq!(room_token(r#"{"room":5,"token":"t"}"#), Err(DecodeError));
        assert_eq!(room_token(r#"{"room":{"a":1}}"#), Err(DecodeError));
        assert_eq!(room_token("[]"), Err(DecodeError));
        assert_eq!(room_token(""), Err(DecodeError));
        assert_eq!(room_token("  \n"), Err(DecodeError));
    }

    #[test]
    fn syntax_errors_fail_even_after_the_wanted_fields() {
        assert_eq!(
            room_token(r#"{"room":"a","token":"t","x":}"#),
            Err(DecodeError)
        );
        assert_eq!(room_token(r#"{"room":"a","token":"t",}"#), Err(DecodeError));
        assert_eq!(room_token(r#"{"room":"a""#), Err(DecodeError));
        assert_eq!(room_token(r#"{"room":"a\x"}"#), Err(DecodeError));
        assert_eq!(room_token("{\"room\":\"a\nb\"}"), Err(DecodeError));
        assert_eq!(room_token(r#"{"room":01}"#), Err(DecodeError));
    }

    #[test]
    fn strings_decode_like_go() {
        assert_eq!(
            room_token(r#"{"room":"😀é"}"#).unwrap().0.as_deref(),
            Some("\u{1F600}\u{e9}")
        );
        assert_eq!(
            room_token(r#"{"room":"\ud800x"}"#).unwrap().0.as_deref(),
            Some("\u{FFFD}x")
        );
        assert_eq!(
            room_token(r#"{"room":"\udc00"}"#).unwrap().0.as_deref(),
            Some("\u{FFFD}")
        );
        let bytes = b"{\"room\":\"a\xff\xfeb\"}";
        let v = decode_string_fields(bytes, &["room"]).unwrap();
        assert_eq!(v[0].as_deref(), Some("a\u{FFFD}\u{FFFD}b"));
        assert_eq!(
            room_token("{\"\u{212A}\":1,\"toKen\":\"t\"}")
                .unwrap()
                .1
                .as_deref(),
            Some("t")
        );
    }

    #[test]
    fn deep_nesting_is_bounded_by_gos_limit_not_the_stack() {
        let deep = |n: usize| {
            format!(
                r#"{{"room":"a","token":"t","x":{}{}}}"#,
                "[".repeat(n),
                "]".repeat(n)
            )
        };
        assert!(room_token(&deep(8000)).is_ok());
        assert_eq!(room_token(&deep(10_001)), Err(DecodeError));
    }

    #[test]
    fn encoder_matches_go_html_escaping() {
        assert_eq!(
            encode_string("a<b>&\u{2028}\u{7f}\u{1}\"\\\n\u{8}\u{c}é"),
            "\"a\\u003cb\\u003e\\u0026\\u2028\u{7f}\\u0001\\\"\\\\\\n\\b\\fé\""
        );
    }
}
