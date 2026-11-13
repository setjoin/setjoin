//! Search-filter admission mirroring go-ldap v3.4.14 `CompileFilter`.
//!
//! The Go sync accepts an operator filter only when `CompileFilter` accepts it.
//! This port reproduces that grammar (including its quirks: a lone attribute
//! with no operator, `\xx` escapes that must be two hex digits) and re-emits
//! the accepted filter as canonical RFC 4515 text in which every value byte is
//! hex-escaped, so the wire client builds the same BER Go would send.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Item {
        attr: String,
        op: &'static str,
        value: Vec<u8>,
    },
    Present(String),
    Substrings {
        attr: String,
        parts: Vec<(char, Vec<u8>)>,
    },
    Extensible {
        rule: String,
        attr: String,
        value: Vec<u8>,
        dn: bool,
    },
}

/// go-ldap `EscapeFilter`: hex-escape `( ) \ *`, NUL and every non-ASCII byte.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte > 0x7f || matches!(byte, b'(' | b')' | b'\\' | b'*' | 0) {
            out.push_str(&format!("\\{byte:02x}"));
        } else {
            out.push(byte as char);
        }
    }
    out
}

fn hex_all(value: &[u8]) -> String {
    value.iter().map(|b| format!("\\{b:02x}")).collect()
}

fn render(node: &Node) -> String {
    match node {
        Node::And(c) => format!("(&{})", c.iter().map(render).collect::<String>()),
        Node::Or(c) => format!("(|{})", c.iter().map(render).collect::<String>()),
        Node::Not(c) => format!("(!{})", render(c)),
        Node::Item { attr, op, value } => format!("({attr}{op}{})", hex_all(value)),
        Node::Present(attr) => format!("({attr}=*)"),
        Node::Substrings { attr, parts } => format!("({attr}={})", substring_text(parts)),
        Node::Extensible {
            rule,
            attr,
            value,
            dn,
        } => format!(
            "({attr}{}{}:={})",
            if *dn { ":dn" } else { "" },
            if rule.is_empty() {
                String::new()
            } else {
                format!(":{rule}")
            },
            hex_all(value)
        ),
    }
}

fn substring_text(parts: &[(char, Vec<u8>)]) -> String {
    // Go skips empty pieces, so the first element is `initial` only when the
    // value did not start with '*', and `final` only when it did not end with
    // '*'. Re-emit with explicit stars around every piece.
    let mut out = String::new();
    let has_initial = parts.first().is_some_and(|(k, _)| *k == 'i');
    if !has_initial {
        out.push('*');
    }
    for (kind, value) in parts {
        out += &hex_all(value);
        if *kind != 'f' {
            out.push('*');
        }
    }
    out
}

/// Escape decoding as go-ldap `decodeEscapedSymbols`; `None` is a compile error.
fn unescape(src: &[u8]) -> Option<Vec<u8>> {
    std::str::from_utf8(src).ok()?;
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\' {
            let pair = src.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(pair).ok()?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(src[i]);
            i += 1;
        }
    }
    Some(out)
}

fn rune_at(filter: &str, pos: usize) -> Option<char> {
    filter.get(pos..)?.chars().next()
}

fn set(filter: &str, mut pos: usize, children: &mut Vec<Node>) -> Option<usize> {
    while pos < filter.len() && filter.as_bytes()[pos] == b'(' {
        let (child, next) = node(filter, pos + 1)?;
        pos = next;
        children.push(child);
    }
    if pos == filter.len() {
        return None;
    }
    Some(pos + 1)
}

fn node(filter: &str, pos: usize) -> Option<(Node, usize)> {
    let c = rune_at(filter, pos)?;
    match c {
        '(' => {
            let (n, next) = node(filter, pos + 1)?;
            Some((n, next + 1))
        }
        '&' | '|' => {
            let mut children = vec![];
            let next = set(filter, pos + 1, &mut children)?;
            Some((
                if c == '&' {
                    Node::And(children)
                } else {
                    Node::Or(children)
                },
                next,
            ))
        }
        '!' => {
            let (child, next) = node(filter, pos + 1)?;
            Some((Node::Not(Box::new(child)), next))
        }
        _ => leaf(filter, pos),
    }
}

fn leaf(filter: &str, start: usize) -> Option<(Node, usize)> {
    #[derive(PartialEq)]
    enum State {
        Attr,
        Rule,
        Condition,
    }
    #[derive(Clone, Copy, PartialEq)]
    enum Kind {
        Eq,
        Ge,
        Le,
        Approx,
        Ext,
    }
    let mut state = State::Attr;
    let mut kind: Option<Kind> = None;
    let (mut attribute, mut rule, mut condition) = (String::new(), String::new(), Vec::<u8>::new());
    let mut dn = false;
    let mut pos = start;
    while pos < filter.len() {
        let rest = &filter[pos..];
        let c = rest.chars().next()?;
        if c == ')' {
            break;
        }
        match state {
            State::Attr => {
                if c == ':' && rest.starts_with(":dn:=") {
                    (kind, dn, state, pos) = (Some(Kind::Ext), true, State::Condition, pos + 5);
                } else if c == ':' && rest.starts_with(":dn:") {
                    (kind, dn, state, pos) = (Some(Kind::Ext), true, State::Rule, pos + 4);
                } else if c == ':' && rest.starts_with(":=") {
                    (kind, state, pos) = (Some(Kind::Ext), State::Condition, pos + 2);
                } else if c == ':' {
                    (kind, state, pos) = (Some(Kind::Ext), State::Rule, pos + 1);
                } else if c == '=' {
                    (kind, state, pos) = (Some(Kind::Eq), State::Condition, pos + 1);
                } else if rest.starts_with(">=") {
                    (kind, state, pos) = (Some(Kind::Ge), State::Condition, pos + 2);
                } else if rest.starts_with("<=") {
                    (kind, state, pos) = (Some(Kind::Le), State::Condition, pos + 2);
                } else if rest.starts_with("~=") {
                    (kind, state, pos) = (Some(Kind::Approx), State::Condition, pos + 2);
                } else {
                    attribute.push(c);
                    pos += c.len_utf8();
                }
            }
            State::Rule => {
                if c == ':' && rest.starts_with(":=") {
                    (state, pos) = (State::Condition, pos + 2);
                } else {
                    rule.push(c);
                    pos += c.len_utf8();
                }
            }
            State::Condition => {
                let mut buf = [0u8; 4];
                condition.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                pos += c.len_utf8();
            }
        }
    }
    if pos == filter.len() {
        return None;
    }
    let kind = kind?;
    let built = match kind {
        Kind::Ext => Node::Extensible {
            rule,
            attr: attribute,
            value: unescape(&condition)?,
            dn,
        },
        Kind::Eq if condition == b"*" => Node::Present(attribute),
        Kind::Eq if condition.contains(&b'*') => {
            let pieces: Vec<&[u8]> = condition.split(|b| *b == b'*').collect();
            let last = pieces.len() - 1;
            let mut parts = vec![];
            for (i, piece) in pieces.iter().enumerate() {
                if piece.is_empty() {
                    continue;
                }
                let tag = if i == 0 {
                    'i'
                } else if i == last {
                    'f'
                } else {
                    'a'
                };
                parts.push((tag, unescape(piece)?));
            }
            Node::Substrings {
                attr: attribute,
                parts,
            }
        }
        _ => Node::Item {
            attr: attribute,
            op: match kind {
                Kind::Ge => ">=",
                Kind::Le => "<=",
                Kind::Approx => "~=",
                _ => "=",
            },
            value: unescape(&condition)?,
        },
    };
    let width = rune_at(filter, pos)?.len_utf8();
    Some((built, pos + width))
}

/// `Some(canonical)` when go-ldap `CompileFilter` accepts `filter`.
pub fn compile(filter: &str) -> Option<String> {
    if !filter.starts_with('(') {
        return None;
    }
    let (n, pos) = node(filter, 1)?;
    if pos != filter.len() {
        return None;
    }
    Some(render(&n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_what_go_accepts() {
        for f in [
            "(objectClass=person)",
            "(&(objectClass=person)(modifyTimestamp>=20260101000000Z))",
            "(|(a=1)(b=2))",
            "(!(a=1))",
            "(cn=a*b*c)",
            "(cn=*)",
            "(cn=abc\\5c\\2a)",
            "(cn:dn:2.5.13.5:=x)",
        ] {
            assert!(compile(f).is_some(), "{f}");
        }
    }

    #[test]
    fn rejects_what_go_rejects() {
        for f in [
            "",
            "objectClass=person",
            "(a=1",
            "(a=1))",
            "(a)",
            "(a=\\zz)",
            "(a=\\4)",
            "(&(a=1)",
            "(=)x",
        ] {
            assert!(compile(f).is_none(), "{f}");
        }
    }

    #[test]
    fn escape_matches_go() {
        assert_eq!(escape("a(b)*\\\u{0}é"), "a\\28b\\29\\2a\\5c\\00\\c3\\a9");
    }
}
