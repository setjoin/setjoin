//! Go's `net/mail` address parser (Go 1.26), byte for byte: addr-spec first,
//! then display name and angle address, RFC 5322 groups, comments, RFC 2047
//! words in display names (UTF-8, ISO-8859-1 and US-ASCII only) and RFC 6532
//! multibyte characters. Errors carry no text because no caller reads it.
use super::gostr::{decode_rune, RUNE_ERROR};
use super::media::{decode_word, WordError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub name: Vec<u8>,
    pub address: Vec<u8>,
}

type Res<T> = Result<T, ()>;

struct Parser<'a> {
    s: &'a [u8],
}

fn is_vchar(r: u32) -> bool {
    (u32::from(b'!')..=u32::from(b'~')).contains(&r) || r >= 0x80
}
fn is_wsp(r: u32) -> bool {
    r == u32::from(b' ') || r == u32::from(b'\t')
}
fn is_atext(r: u32, dot: bool) -> bool {
    match char::from_u32(r) {
        Some('.') => dot,
        Some('(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"') => false,
        _ => is_vchar(r),
    }
}
fn is_qtext(r: u32) -> bool {
    r != u32::from(b'\\') && r != u32::from(b'"') && is_vchar(r)
}
fn is_dtext(r: u32) -> bool {
    !matches!(char::from_u32(r), Some('[' | ']' | '\\')) && is_vchar(r)
}
fn push_rune(out: &mut Vec<u8>, r: u32) {
    // Runes come from `decode_rune` of valid input; a valid U+FFFD is kept.
    out.extend_from_slice(
        char::from_u32(r)
            .unwrap_or('\u{fffd}')
            .to_string()
            .as_bytes(),
    );
}

/// `mail.ParseAddress`.
pub fn parse_address(s: &[u8]) -> Res<Address> {
    Parser { s }.parse_single()
}

/// `mail.ParseAddressList`.
pub fn parse_address_list(s: &[u8]) -> Res<Vec<Address>> {
    Parser { s }.parse_list()
}

impl<'a> Parser<'a> {
    fn empty(&self) -> bool {
        self.s.is_empty()
    }
    fn peek(&self) -> u8 {
        self.s[0]
    }
    fn consume(&mut self, c: u8) -> bool {
        if self.empty() || self.peek() != c {
            return false;
        }
        self.s = &self.s[1..];
        true
    }
    fn skip_space(&mut self) {
        while let Some(&c) = self.s.first() {
            if c == b' ' || c == b'\t' {
                self.s = &self.s[1..];
            } else {
                break;
            }
        }
    }
    fn skip_cfws(&mut self) -> bool {
        self.skip_space();
        while self.consume(b'(') {
            if self.consume_comment().is_none() {
                return false;
            }
            self.skip_space();
        }
        true
    }
    /// `(` already consumed. `None` when the comment never closes.
    fn consume_comment(&mut self) -> Option<Vec<u8>> {
        let mut depth = 1;
        let mut comment = Vec::new();
        while !self.empty() && depth != 0 {
            if self.peek() == b'\\' && self.s.len() > 1 {
                self.s = &self.s[1..];
            } else if self.peek() == b'(' {
                depth += 1;
            } else if self.peek() == b')' {
                depth -= 1;
            }
            if depth > 0 {
                comment.push(self.s[0]);
            }
            self.s = &self.s[1..];
        }
        (depth == 0).then_some(comment)
    }

    fn parse_list(&mut self) -> Res<Vec<Address>> {
        let mut list = Vec::new();
        loop {
            self.skip_space();
            if self.consume(b',') {
                continue;
            }
            list.extend(self.parse_address(true)?);
            if !self.skip_cfws() {
                return Err(());
            }
            if self.empty() {
                break;
            }
            if self.peek() != b',' {
                return Err(());
            }
            while self.consume(b',') {
                self.skip_space();
            }
            if self.empty() {
                break;
            }
        }
        Ok(list)
    }

    fn parse_single(&mut self) -> Res<Address> {
        let mut addrs = self.parse_address(true)?;
        if !self.skip_cfws() || !self.empty() || addrs.len() != 1 {
            return Err(());
        }
        Ok(addrs.remove(0))
    }

    fn parse_address(&mut self, handle_group: bool) -> Res<Vec<Address>> {
        self.skip_space();
        if self.empty() {
            return Err(());
        }
        if let Ok(spec) = self.consume_addr_spec() {
            let mut name = Vec::new();
            self.skip_space();
            if !self.empty() && self.peek() == b'(' {
                name = self.consume_display_name_comment()?;
            }
            return Ok(vec![Address {
                name,
                address: spec,
            }]);
        }
        let mut name = Vec::new();
        if self.peek() != b'<' {
            name = self.consume_phrase()?;
        }
        self.skip_space();
        if handle_group && self.consume(b':') {
            return self.consume_group_list();
        }
        if !self.consume(b'<') {
            return Err(());
        }
        let spec = self.consume_addr_spec()?;
        if !self.consume(b'>') {
            return Err(());
        }
        Ok(vec![Address {
            name,
            address: spec,
        }])
    }

    fn consume_group_list(&mut self) -> Res<Vec<Address>> {
        let mut group = Vec::new();
        self.skip_space();
        if self.consume(b';') {
            if !self.skip_cfws() {
                return Err(());
            }
            return Ok(group);
        }
        loop {
            self.skip_space();
            group.extend(self.parse_address(false)?);
            if !self.skip_cfws() {
                return Err(());
            }
            if self.consume(b';') {
                if !self.skip_cfws() {
                    return Err(());
                }
                break;
            }
            if !self.consume(b',') {
                return Err(());
            }
        }
        Ok(group)
    }

    fn consume_addr_spec(&mut self) -> Res<Vec<u8>> {
        let orig = self.s;
        let result = self.addr_spec_inner();
        if result.is_err() {
            self.s = orig;
        }
        result
    }

    fn addr_spec_inner(&mut self) -> Res<Vec<u8>> {
        self.skip_space();
        if self.empty() {
            return Err(());
        }
        let local = if self.peek() == b'"' {
            let q = self.consume_quoted_string()?;
            if q.is_empty() {
                return Err(());
            }
            q
        } else {
            self.consume_atom(true, false)?
        };
        if !self.consume(b'@') {
            return Err(());
        }
        self.skip_space();
        if self.empty() {
            return Err(());
        }
        let domain = if self.peek() == b'[' {
            self.consume_domain_literal()?
        } else {
            self.consume_atom(true, false)?
        };
        let mut spec = local;
        spec.push(b'@');
        spec.extend_from_slice(&domain);
        Ok(spec)
    }

    /// `decodeRFC2047Word`: `(word, is_encoded, charset_error)`.
    fn decode_word(s: &[u8]) -> (Vec<u8>, bool, bool) {
        match decode_word(s) {
            Ok(w) => (w, true, false),
            Err(WordError::Charset) => (s.to_vec(), true, true),
            Err(WordError::Invalid) => (s.to_vec(), false, false),
        }
    }

    fn consume_phrase(&mut self) -> Res<Vec<u8>> {
        let mut words: Vec<Vec<u8>> = Vec::new();
        let mut sb: Vec<u8> = Vec::new();
        let mut failed = false;
        loop {
            if !words.is_empty() && !self.skip_cfws() {
                return Err(());
            }
            self.skip_space();
            if self.empty() {
                break;
            }
            let (word, is_encoded) = if self.peek() == b'"' {
                match self.consume_quoted_string() {
                    Ok(w) => (w, false),
                    Err(()) => {
                        failed = true;
                        break;
                    }
                }
            } else {
                match self.consume_atom(true, true) {
                    Ok(atom) => {
                        let (w, enc, charset_err) = Self::decode_word(&atom);
                        if charset_err {
                            failed = true;
                            break;
                        }
                        (w, enc)
                    }
                    Err(()) => {
                        failed = true;
                        break;
                    }
                }
            };
            if is_encoded {
                sb.extend_from_slice(&word);
            } else if !sb.is_empty() {
                words.push(std::mem::take(&mut sb));
                words.push(word);
            } else {
                words.push(word);
            }
        }
        if !sb.is_empty() {
            words.push(sb);
        }
        if failed && words.is_empty() {
            return Err(());
        }
        Ok(words.join(&b' '))
    }

    fn consume_quoted_string(&mut self) -> Res<Vec<u8>> {
        let mut i = 1;
        let mut qsb = Vec::new();
        let mut escaped = false;
        loop {
            let (r, size) = decode_rune(self.s.get(i..).unwrap_or(&[]));
            if size == 0 {
                return Err(());
            }
            if size == 1 && r == RUNE_ERROR {
                return Err(());
            }
            if escaped {
                if !is_vchar(r) && !is_wsp(r) {
                    return Err(());
                }
                push_rune(&mut qsb, r);
                escaped = false;
            } else if is_qtext(r) || is_wsp(r) {
                push_rune(&mut qsb, r);
            } else if r == u32::from(b'"') {
                break;
            } else if r == u32::from(b'\\') {
                escaped = true;
            } else {
                return Err(());
            }
            i += size;
        }
        self.s = &self.s[i + 1..];
        Ok(qsb)
    }

    fn consume_atom(&mut self, dot: bool, permissive: bool) -> Res<Vec<u8>> {
        let mut i = 0;
        loop {
            let (r, size) = decode_rune(&self.s[i..]);
            if size == 1 && r == RUNE_ERROR {
                return Err(());
            }
            if size == 0 || !is_atext(r, dot) {
                break;
            }
            i += size;
        }
        if i == 0 {
            return Err(());
        }
        let atom = self.s[..i].to_vec();
        self.s = &self.s[i..];
        if !permissive
            && (atom.starts_with(b".")
                || atom.windows(2).any(|w| w == b"..")
                || atom.ends_with(b"."))
        {
            return Err(());
        }
        Ok(atom)
    }

    fn consume_domain_literal(&mut self) -> Res<Vec<u8>> {
        if !self.consume(b'[') {
            return Err(());
        }
        let start = self.s;
        let mut len = 0;
        loop {
            if self.empty() {
                return Err(());
            }
            if self.peek() == b']' {
                break;
            }
            let (r, size) = decode_rune(self.s);
            if (size == 1 && r == RUNE_ERROR) || !is_dtext(r) {
                return Err(());
            }
            len += size;
            self.s = &self.s[size..];
        }
        let dtext = &start[..len];
        if !self.consume(b']') {
            return Err(());
        }
        let ok = std::str::from_utf8(dtext)
            .ok()
            .is_some_and(|t| t.parse::<std::net::IpAddr>().is_ok());
        if !ok {
            return Err(());
        }
        let mut out = vec![b'['];
        out.extend_from_slice(dtext);
        out.push(b']');
        Ok(out)
    }

    fn consume_display_name_comment(&mut self) -> Res<Vec<u8>> {
        if !self.consume(b'(') {
            return Err(());
        }
        let comment = self.consume_comment().ok_or(())?;
        let mut words: Vec<Vec<u8>> = comment
            .split(|c| *c == b' ' || *c == b'\t')
            .filter(|w| !w.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        for word in &mut words {
            let (decoded, is_encoded, charset_err) = Self::decode_word(word);
            if charset_err {
                return Err(());
            }
            if is_encoded {
                *word = decoded;
            }
        }
        Ok(words.join(&b' '))
    }
}
