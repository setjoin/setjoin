//! Go `json.NewDecoder(r.Body).Decode(&struct)` as the F07 admin handlers see it:
//! the exact error text of a syntax or type error (the handlers echo it), the
//! first value only, case-folded keys, `null` leaves a field unset. Only what the
//! slice's request structs need: string, bool, int and `[]int64` fields.

/// A decoded JSON value; numbers keep their literal text.
#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

/// Go's `quoteChar` for a byte of the offending input.
fn quote(c: u8) -> String {
    match c {
        b'\'' => "'\\''".into(),
        b'"' => "'\"'".into(),
        7 => "'\\a'".into(),
        8 => "'\\b'".into(),
        12 => "'\\f'".into(),
        10 => "'\\n'".into(),
        13 => "'\\r'".into(),
        9 => "'\\t'".into(),
        11 => "'\\v'".into(),
        0..=0x1f | 0x7f => format!("'\\x{c:02x}'"),
        0x80..=0x9f | 0xa0 | 0xad => format!("'\\u{c:04x}'"),
        _ => format!("'{}'", char::from(c)),
    }
}

struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

type R<T> = Result<T, String>;

impl Scan<'_> {
    fn bad<T>(&self, c: u8, context: &str) -> R<T> {
        Err(format!("invalid character {} {context}", quote(c)))
    }
    fn space(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn eof() -> String {
        "unexpected EOF".into()
    }
    fn value(&mut self) -> R<J> {
        self.space();
        let Some(c) = self.peek() else {
            return Err(Self::eof());
        };
        match c {
            b'{' => {
                self.i += 1;
                self.space();
                let mut members = Vec::new();
                match self.peek() {
                    None => return Err(Self::eof()),
                    Some(b'}') => {
                        self.i += 1;
                        return Ok(J::Obj(members));
                    }
                    _ => {}
                }
                loop {
                    self.space();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b'"') => {}
                        Some(c) => {
                            return self.bad(c, "looking for beginning of object key string")
                        }
                    }
                    let key = self.string()?;
                    self.space();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b':') => self.i += 1,
                        Some(c) => return self.bad(c, "after object key"),
                    }
                    let v = self.value()?;
                    members.push((key, v));
                    self.space();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(members));
                        }
                        Some(c) => return self.bad(c, "after object key:value pair"),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                self.space();
                let mut items = Vec::new();
                match self.peek() {
                    None => return Err(Self::eof()),
                    Some(b']') => {
                        self.i += 1;
                        return Ok(J::Arr(items));
                    }
                    _ => {}
                }
                loop {
                    items.push(self.value()?);
                    self.space();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(items));
                        }
                        Some(c) => return self.bad(c, "after array element"),
                    }
                }
            }
            b'"' => Ok(J::Str(self.string()?)),
            b'-' | b'0'..=b'9' => self.number(),
            b't' => self.literal("true", J::Bool(true)),
            b'f' => self.literal("false", J::Bool(false)),
            b'n' => self.literal("null", J::Null),
            c => self.bad(c, "looking for beginning of value"),
        }
    }
    fn literal(&mut self, word: &str, value: J) -> R<J> {
        for (n, expected) in word.bytes().enumerate().skip(1) {
            self.i += 1;
            match self.peek() {
                None => return Err(Self::eof()),
                Some(c) if c == expected => {}
                Some(c) => {
                    let _ = n;
                    return self.bad(
                        c,
                        &format!("in literal {word} (expecting '{}')", char::from(expected)),
                    );
                }
            }
        }
        self.i += 1;
        Ok(value)
    }
    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }
    fn number(&mut self) -> R<J> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
            match self.peek() {
                None => return Err(Self::eof()),
                Some(b'0'..=b'9') => {}
                Some(c) => return self.bad(c, "in numeric literal"),
            }
        }
        if self.peek() == Some(b'0') {
            self.i += 1;
        } else {
            self.digits();
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            match self.peek() {
                None => return Err(Self::eof()),
                Some(b'0'..=b'9') => {
                    self.digits();
                }
                Some(c) => return self.bad(c, "after decimal point in numeric literal"),
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            match self.peek() {
                None => return Err(Self::eof()),
                Some(b'0'..=b'9') => {
                    self.digits();
                }
                Some(c) => return self.bad(c, "in exponent of numeric literal"),
            }
        }
        Ok(J::Num(
            String::from_utf8_lossy(&self.b[start..self.i]).into_owned(),
        ))
    }
    fn hex4(&mut self) -> R<u32> {
        let mut n = 0;
        for _ in 0..4 {
            self.i += 1;
            match self.peek() {
                None => return Err(Self::eof()),
                Some(c) => match char::from(c).to_digit(16) {
                    Some(d) => n = n * 16 + d,
                    None => return self.bad(c, "in \\u hexadecimal character escape"),
                },
            }
        }
        Ok(n)
    }
    fn string(&mut self) -> R<String> {
        self.i += 1; // the opening quote
        let mut raw: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(Self::eof());
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(String::from_utf8_lossy(&raw).into_owned());
                }
                b'\\' => {
                    self.i += 1;
                    let Some(e) = self.peek() else {
                        return Err(Self::eof());
                    };
                    match e {
                        b'b' => raw.push(8),
                        b'f' => raw.push(12),
                        b'n' => raw.push(10),
                        b'r' => raw.push(13),
                        b't' => raw.push(9),
                        b'\\' | b'/' | b'"' => raw.push(e),
                        b'u' => {
                            let mut r = self.hex4()?;
                            if (0xd800..0xdc00).contains(&r) {
                                // A high surrogate pairs with a following \uDC00..\uDFFF.
                                let save = self.i;
                                if self.b.get(self.i + 1) == Some(&b'\\')
                                    && self.b.get(self.i + 2) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let low = self.hex4()?;
                                    if (0xdc00..0xe000).contains(&low) {
                                        r = 0x10000 + ((r - 0xd800) << 10) + (low - 0xdc00);
                                    } else {
                                        // Go decodes the first as U+FFFD, then reads the second.
                                        self.i = save;
                                        r = 0xfffd;
                                    }
                                } else {
                                    r = 0xfffd;
                                }
                            } else if (0xdc00..0xe000).contains(&r) {
                                r = 0xfffd;
                            }
                            let ch = char::from_u32(r).unwrap_or('\u{fffd}');
                            let mut buf = [0u8; 4];
                            raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        e => return self.bad(e, "in string escape code"),
                    }
                    self.i += 1;
                }
                c if c < 0x20 => return self.bad(c, "in string literal"),
                c => {
                    raw.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

/// The first JSON value of `body` (`Decode`). `Err` carries Go's error text:
/// `EOF` for an empty body, `unexpected EOF` for a truncated one, otherwise
/// the scanner's `invalid character ...` message.
pub fn first(body: &[u8]) -> Result<J, String> {
    let mut scan = Scan { b: body, i: 0 };
    scan.space();
    if scan.peek().is_none() {
        return Err("EOF".into());
    }
    scan.value()
}

/// Decode exactly one JSON value, including the trailing EOF check used by
/// offline policy/preview requests. Ordinary Go decoders still use `first`.
pub fn one(body: &[u8]) -> Result<J, String> {
    let mut scan = Scan { b: body, i: 0 };
    scan.space();
    if scan.peek().is_none() {
        return Err("EOF".into());
    }
    let value = scan.value()?;
    scan.space();
    if scan.peek().is_some() {
        return Err("request must contain one JSON object".into());
    }
    Ok(value)
}

/// Go's `foldName` for the ASCII field names used here (the Kelvin sign and the
/// long s fold into `k` and `s`).
pub(crate) fn fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{212a}' => 'k',
            '\u{17f}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// A decoded scalar of a struct field.
#[derive(Debug, Clone, PartialEq)]
pub enum V {
    Str(String),
    Bool(bool),
    Int(i64),
}

/// The Go kind of a request struct field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Str,
    Bool,
    /// Go `int` (64-bit): the Go type name in a message is `int`.
    Int,
    /// Go `int64`.
    Int64,
}

impl Kind {
    fn go(self) -> &'static str {
        match self {
            Kind::Str => "string",
            Kind::Bool => "bool",
            Kind::Int => "int",
            Kind::Int64 => "int64",
        }
    }
}

fn describe(v: &J) -> &'static str {
    match v {
        J::Null => "null",
        J::Bool(_) => "bool",
        J::Num(_) => "number",
        J::Str(_) => "string",
        J::Arr(_) => "array",
        J::Obj(_) => "object",
    }
}

/// Decode a JSON object into scalar fields named by their JSON key. The result
/// holds one slot per schema entry (`None` when absent or `null`). `Err` is the
/// first `UnmarshalTypeError` text, produced after the whole value decoded, as
/// Go does. `go_struct` is the Go struct's name (`""` for an anonymous one).
pub fn fields(
    value: &J,
    schema: &[(&str, Kind)],
    go_struct: &str,
    go_package: &str,
) -> Result<Vec<Option<V>>, String> {
    let mut out: Vec<Option<V>> = vec![None; schema.len()];
    let members = match value {
        J::Obj(members) => members,
        J::Null => return Ok(out),
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type {go_package}{go_struct}",
                describe(other)
            ))
        }
    };
    let mut first_error: Option<String> = None;
    for (key, v) in members {
        let slot = schema
            .iter()
            .position(|(name, _)| name == key)
            .or_else(|| schema.iter().position(|(name, _)| fold(name) == fold(key)));
        let Some(slot) = slot else { continue };
        let (name, kind) = schema[slot];
        let mismatch = |value: String| {
            format!(
                "json: cannot unmarshal {value} into Go struct field {go_struct}.{name} of type {}",
                kind.go()
            )
        };
        match (kind, v) {
            (_, J::Null) => out[slot] = None,
            (Kind::Str, J::Str(s)) => out[slot] = Some(V::Str(s.clone())),
            (Kind::Bool, J::Bool(b)) => out[slot] = Some(V::Bool(*b)),
            (Kind::Int | Kind::Int64, J::Num(n)) => match n.parse::<i64>() {
                Ok(i) => out[slot] = Some(V::Int(i)),
                Err(_) => {
                    first_error.get_or_insert_with(|| mismatch(format!("number {n}")));
                }
            },
            (_, other) => {
                first_error.get_or_insert_with(|| mismatch(describe(other).into()));
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// Decode `{"<key>": [int64...]}` (the reorder body): `Ok(None)` for an absent or
/// `null` list. Elements that are `null` read as 0, as Go leaves the zero value.
pub fn int_list(value: &J, key: &str) -> Result<Option<Vec<i64>>, String> {
    let members = match value {
        J::Obj(members) => members,
        J::Null => return Ok(None),
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type struct {{ IDs []int64 \"json:\\\"{key}\\\"\" }}",
                describe(other)
            ))
        }
    };
    let mut list: Option<Vec<i64>> = None;
    let mut first_error: Option<String> = None;
    for (k, v) in members {
        if k != key && fold(k) != fold(key) {
            continue;
        }
        match v {
            J::Null => list = None,
            J::Arr(items) => {
                let mut ids = Vec::new();
                for item in items {
                    match item {
                        J::Null => ids.push(0),
                        J::Num(n) => match n.parse::<i64>() {
                            Ok(i) => ids.push(i),
                            Err(_) => {
                                first_error.get_or_insert_with(|| {
                                    format!("json: cannot unmarshal number {n} into Go struct field .{key} of type int64")
                                });
                                ids.push(0);
                            }
                        },
                        other => {
                            first_error.get_or_insert_with(|| {
                                format!(
                                    "json: cannot unmarshal {} into Go struct field .{key} of type int64",
                                    describe(other)
                                )
                            });
                            ids.push(0);
                        }
                    }
                }
                list = Some(ids);
            }
            other => {
                first_error.get_or_insert_with(|| {
                    format!(
                        "json: cannot unmarshal {} into Go struct field .{key} of type []int64",
                        describe(other)
                    )
                });
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(list),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(body: &str) -> String {
        first(body.as_bytes()).unwrap_err()
    }

    #[test]
    fn syntax_errors_read_like_go() {
        assert_eq!(err(""), "EOF");
        assert_eq!(err("  \n"), "EOF");
        assert_eq!(err("{"), "unexpected EOF");
        assert_eq!(err("{\"a\":"), "unexpected EOF");
        assert_eq!(
            err("x"),
            "invalid character 'x' looking for beginning of value"
        );
        assert_eq!(
            err("{a:1}"),
            "invalid character 'a' looking for beginning of object key string"
        );
        assert_eq!(err("{\"a\" 1}"), "invalid character '1' after object key");
        assert_eq!(
            err("{\"a\":1 \"b\"}"),
            "invalid character '\"' after object key:value pair"
        );
        assert_eq!(err("[1 2]"), "invalid character '2' after array element");
        assert_eq!(err("{\"a\":01}").is_empty(), false);
        assert_eq!(err("-x"), "invalid character 'x' in numeric literal");
        assert_eq!(
            err("1.x"),
            "invalid character 'x' after decimal point in numeric literal"
        );
        assert_eq!(
            err("1ex"),
            "invalid character 'x' in exponent of numeric literal"
        );
        assert_eq!(
            err("tru!"),
            "invalid character '!' in literal true (expecting 'e')"
        );
        assert_eq!(
            err("\"a\u{1}\""),
            "invalid character '\\x01' in string literal"
        );
        assert_eq!(
            err("\"\\q\""),
            "invalid character 'q' in string escape code"
        );
        assert_eq!(
            err("\"\\u12g4\""),
            "invalid character 'g' in \\u hexadecimal character escape"
        );
    }

    #[test]
    fn the_first_value_alone_is_read() {
        assert_eq!(first(b"{} trailing"), Ok(J::Obj(vec![])));
        assert_eq!(first(b"null junk"), Ok(J::Null));
    }

    #[test]
    fn type_errors_name_the_field_and_go_type() {
        let schema = [
            ("name", Kind::Str),
            ("priority", Kind::Int),
            ("enabled", Kind::Bool),
        ];
        let go = |body: &str| {
            fields(
                &first(body.as_bytes()).unwrap(),
                &schema,
                "policyRequest",
                "admin.",
            )
        };
        assert_eq!(
            go("{\"priority\":\"x\"}").unwrap_err(),
            "json: cannot unmarshal string into Go struct field policyRequest.priority of type int"
        );
        assert_eq!(
            go("{\"PRIORITY\":1.5}").unwrap_err(),
            "json: cannot unmarshal number 1.5 into Go struct field policyRequest.priority of type int"
        );
        assert_eq!(
            go("[1]").unwrap_err(),
            "json: cannot unmarshal array into Go value of type admin.policyRequest"
        );
        assert_eq!(go("null").unwrap(), vec![None, None, None]);
        assert_eq!(
            go("{\"name\":null,\"enabled\":true}").unwrap(),
            vec![None, None, Some(V::Bool(true))]
        );
    }
}
