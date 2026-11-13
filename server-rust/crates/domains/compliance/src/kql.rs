//! Frozen Go KQL grammar and bounds. SQL contains only fixed columns/operators;
//! every term is a bound text-array value. A NUL byte is refused (#436).
include!("go_print.rs");
#[derive(Debug)]
pub struct Predicate {
    pub(crate) sql: String,
    pub(crate) values: Vec<String>,
}
struct Expr {
    or: bool,
    terms: Vec<Term>,
}
struct Term {
    field: String,
    text: String,
    negate: bool,
    group: Option<Expr>,
    from: Option<String>,
    to: Option<String>,
}
struct Parser {
    input: Vec<char>,
    pos: usize,
    depth: usize,
    terms: usize,
}

pub fn parse(query: &str) -> Result<Predicate, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err("empty query".into());
    }
    if query.chars().count() > 4096 {
        return Err("query exceeds maximum length of 4096 characters".into());
    }
    // Owner-approved security fix 2026-11-05 (#436): frozen Go's advance() could not advance
    // over a NUL inside a quote and hung the request. A NUL anywhere is refused up front.
    if query.contains('\0') && !setjoin_contracts::mutants::on("kql-nul-accepted") {
        return Err("query contains a NUL character".into());
    }
    let mut p = Parser {
        input: query.chars().collect(),
        pos: 0,
        depth: 0,
        terms: 0,
    };
    let expr = p.expression()?;
    p.space();
    if p.pos < p.input.len() {
        let rest = p.input[p.pos..].iter().collect::<String>();
        return Err(format!(
            "unexpected token at position {}: {}",
            p.pos,
            go_quote(&rest)
        ));
    }
    let mut values = Vec::new();
    let sql = compile(&expr, &mut values);
    Ok(Predicate { sql, values })
}
impl Parser {
    fn peek(&self) -> char {
        self.input.get(self.pos).copied().unwrap_or('\0')
    }
    fn advance(&mut self) -> char {
        let c = self.peek();
        if self.pos < self.input.len() {
            self.pos += 1;
        }
        c
    }
    fn space(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }
    fn word(&self) -> String {
        self.input[self.pos..]
            .iter()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphabetic())
            .collect()
    }
    fn consume(&mut self, word: &str) {
        self.space();
        self.pos += word.len();
    }
    fn add(&mut self) -> Result<(), String> {
        self.terms += 1;
        if self.terms > 128 {
            Err("query exceeds maximum of 128 terms".into())
        } else {
            Ok(())
        }
    }
    fn expression(&mut self) -> Result<Expr, String> {
        let mut terms = vec![self.term()?];
        self.add()?;
        let mut or = false;
        loop {
            self.space();
            if self.pos == self.input.len() || self.peek() == ')' {
                break;
            }
            let word = self.word();
            match word.to_ascii_uppercase().as_str() {
                "AND" => {
                    if or {
                        return Err(
                            "cannot mix AND and OR at the same level; use parentheses".into()
                        );
                    }
                    self.consume(&word);
                }
                "OR" => {
                    if !or && terms.len() > 1 {
                        return Err(
                            "cannot mix AND and OR at the same level; use parentheses".into()
                        );
                    }
                    or = true;
                    self.consume(&word);
                }
                _ => {
                    if or {
                        return Err(
                            "cannot mix AND and OR at the same level; use parentheses".into()
                        );
                    }
                }
            }
            self.space();
            if self.pos == self.input.len() || self.peek() == ')' {
                break;
            }
            terms.push(self.term()?);
            self.add()?;
        }
        Ok(Expr { or, terms })
    }
    fn term(&mut self) -> Result<Term, String> {
        self.space();
        if self.pos == self.input.len() {
            return Err("unexpected end of input".into());
        }
        let mut term = Term {
            field: String::new(),
            text: String::new(),
            negate: false,
            group: None,
            from: None,
            to: None,
        };
        let word = self.word();
        if word.eq_ignore_ascii_case("NOT") {
            term.negate = true;
            self.consume(&word);
            self.space();
            if self.pos == self.input.len() || self.peek() == ')' {
                return Err("expected term after NOT".into());
            }
        }
        if self.peek() == '(' {
            self.depth += 1;
            if self.depth > 32 {
                return Err("query exceeds maximum nesting depth of 32".into());
            }
            self.advance();
            term.group = Some(self.expression()?);
            self.space();
            if self.pos == self.input.len() || self.advance() != ')' {
                return Err(format!("expected ')' at position {}", self.pos));
            }
            self.depth -= 1;
            return Ok(term);
        }
        if self.peek() == '"' {
            term.text = self.quoted();
            return Ok(term);
        }
        let word = self.word();
        let end = self.pos + word.len();
        if !word.is_empty() && self.input.get(end) == Some(&':') {
            self.consume(&word);
            self.advance();
            term.field = word.to_ascii_lowercase();
            self.space();
            term.text = if self.peek() == '"' {
                self.quoted()
            } else {
                let value = self.bare();
                if value.is_empty() {
                    return Err(format!("expected value after {}:", go_quote(&term.field)));
                }
                value
            };
            if term.field == "date" {
                (term.from, term.to) = date_range(&term.text);
            }
            return Ok(term);
        }
        term.text = self.bare();
        if term.text.is_empty() {
            return Err(format!("expected term at position {}", self.pos));
        }
        Ok(term)
    }
    fn quoted(&mut self) -> String {
        self.advance();
        let mut out = String::new();
        while self.pos < self.input.len() {
            let c = self.advance();
            if c == '"' {
                break;
            }
            if c == '\\' && self.pos < self.input.len() {
                out.push(self.advance());
            } else {
                out.push(c);
            }
        }
        out
    }
    fn bare(&mut self) -> String {
        self.space();
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.peek();
            if c.is_whitespace() || matches!(c, '(' | ')' | '"') {
                break;
            }
            let remaining = &self.input[self.pos..];
            let prefix = remaining
                .iter()
                .take(4)
                .map(char::to_ascii_uppercase)
                .collect::<String>();
            let exact = remaining.iter().collect::<String>();
            if prefix.starts_with("AND ")
                || exact == "AND"
                || prefix.starts_with("OR ")
                || exact == "OR"
                || prefix.starts_with("NOT ")
                || exact == "NOT"
            {
                let after = self.pos + 3;
                if after >= self.input.len()
                    || self.pos + 2 >= self.input.len()
                    || self.input[after - 1].is_whitespace()
                    || matches!(self.input[after - 1], '(' | ')')
                {
                    break;
                }
            }
            self.pos += 1;
        }
        self.input[start..self.pos].iter().collect()
    }
}
fn date_range(value: &str) -> (Option<String>, Option<String>) {
    let (mut from, mut to) = (None, None);
    if let Some((a, b)) = value.split_once("..") {
        if !a.trim().is_empty() {
            from = Some(a.trim().into());
        }
        if !b.trim().is_empty() {
            to = Some(b.trim().into());
        }
    }
    if from.is_none() && to.is_none() && !value.is_empty() {
        from = Some(value.into());
    }
    (from, to)
}
fn parameter(values: &mut Vec<String>, value: &str) -> String {
    values.push(value.into());
    format!("($1::text[])[{}]", values.len())
}
fn compile(expr: &Expr, values: &mut Vec<String>) -> String {
    let mut parts = Vec::new();
    for t in &expr.terms {
        let clause = if let Some(group) = &t.group {
            let inner = compile(group, values);
            if t.negate {
                format!("NOT {inner}")
            } else {
                inner
            }
        } else {
            match t.field.as_str() {
                "from" | "mailbox" => {
                    let column = if t.field == "from" {
                        "m.from_addr"
                    } else {
                        "mb.email"
                    };
                    let op = if t.negate { "NOT ILIKE" } else { "ILIKE" };
                    format!("{column} {op} '%' || {} || '%'", parameter(values, &t.text))
                }
                "subject" | "body" => {
                    let column = if t.field == "subject" {
                        "m.subject_tsv"
                    } else {
                        "m.body_tsv"
                    };
                    let op = if t.negate { "NOT @@" } else { "@@" };
                    format!(
                        "{column} {op} plainto_tsquery('simple',{})",
                        parameter(values, &t.text)
                    )
                }
                "date" => {
                    let mut clauses = Vec::new();
                    if let Some(from) = &t.from {
                        clauses.push(format!(
                            "m.received_at >= ({})::timestamptz",
                            parameter(values, from)
                        ));
                    }
                    if let Some(to) = &t.to {
                        clauses.push(format!(
                            "m.received_at <= ({})::timestamptz",
                            parameter(values, to)
                        ));
                    }
                    if clauses.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "{}({})",
                            if t.negate { "NOT " } else { "" },
                            clauses.join(" AND ")
                        )
                    }
                }
                _ => {
                    let arg = parameter(values, &t.text);
                    format!("{}(m.body_tsv @@ plainto_tsquery('simple',{arg}) OR m.subject_tsv @@ plainto_tsquery('simple',{arg}) OR m.from_tsv @@ plainto_tsquery('simple',{arg}))",if t.negate{"NOT "}else{""})
                }
            }
        };
        if !clause.is_empty() {
            parts.push(clause);
        }
    }
    if parts.is_empty() {
        "FALSE".into()
    } else {
        format!("({})", parts.join(if expr.or { " OR " } else { " AND " }))
    }
}
fn go_quote(value: &str) -> String {
    use std::fmt::Write;
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => {
                let n = c as u32;
                let printable = GO_PRINT_RANGES
                    .binary_search_by(|&(a, b)| {
                        if b < n {
                            std::cmp::Ordering::Less
                        } else if a > n {
                            std::cmp::Ordering::Greater
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok();
                if printable {
                    out.push(c)
                } else if n < 32 || n == 127 {
                    write!(out, "\\x{n:02x}").expect("string");
                } else if n < 65536 {
                    write!(out, "\\u{n:04x}").expect("string");
                } else {
                    write!(out, "\\U{n:08x}").expect("string");
                }
            }
        }
    }
    out.push('"');
    out
}
