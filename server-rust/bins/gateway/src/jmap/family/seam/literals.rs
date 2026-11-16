//! Test-only Rust tokenizer and family SQL scan, shared by the source guards
//! (`tests::family_files_use_only_the_seam` and
//! `call::db::actor_arguments_are_seam_bound`). Both read family source text,
//! so both see the tokens the compiler sees: nested block, line and doc
//! comments are dropped, char literals are told from lifetimes, and every
//! string form (plain, byte, C, raw with any `#` count, every escape, `\`
//! newline continuation) decodes. A lexing error fails closed.
//!
//! The scan does not depend on recognising macros: every SQL-looking string
//! literal is checked wherever it sits, and every occurrence of an SQL-building
//! identifier ([`SQL_IDENTS`]) must be the canonical `ident ! ( "literal" )`.
//! Only the seam's macros can make the `Sql` the seam accepts, so the literals
//! seen here are every statement a family file can run.
use std::sync::OnceLock;

use regex::Regex;

/// The reviewed core files next to the family stubs (they may use `format!`).
pub(super) const CORE_FILES: &[&str] = &["args.rs", "mod.rs", "reducer_error.rs"];

/// Identifiers that build or carry a statement. Each occurrence in a family
/// file must be `ident ! ( "one plain literal" )`; the seam macros may also be
/// imported under their own name (`use super::seam::{read_sql};`).
const SQL_IDENTS: &[&str] = &[
    "read_sql",
    "write_sql",
    "set_sql",
    "concat",
    "include_str",
    "format",
];
const SEAM_MACROS: &[&str] = &["read_sql", "write_sql", "set_sql"];
/// The tails `read_sql!`/`write_sql!` append (seam/mod.rs).
const READ_TAIL: &str = " WHERE $2::bigint>0";
const WRITE_TAIL: &str = " WHERE $2::bigint>0 AND $3::text<>''";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Token {
    /// An identifier or keyword (`r#` raw identifiers without the `r#`).
    Ident(String),
    /// `'a`, `'static`, a loop label.
    Lifetime(String),
    /// Any string literal (plain, byte, C, raw), decoded.
    Str(String),
    /// A char, byte or number literal, as written.
    Other(String),
    Punct(char),
}

fn ident_start(ch: char) -> bool {
    ch.is_alphabetic() || ch == '_'
}

fn ident_continue(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

struct Lexer {
    chars: Vec<char>,
    at: usize,
}

impl Lexer {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn line(&self, at: usize) -> usize {
        1 + self.chars[..at.min(self.chars.len())]
            .iter()
            .filter(|ch| **ch == '\n')
            .count()
    }

    fn error(&self, what: &str) -> String {
        format!("lexing error at line {}: {what}", self.line(self.at))
    }

    fn unclosed(&self, what: &str, from: usize) -> String {
        format!(
            "lexing error: {what} from line {} never closes",
            self.line(from)
        )
    }

    /// `/* … */` with nesting; `at` is on the opening `/`.
    fn block_comment(&mut self) -> Result<(), String> {
        let from = self.at;
        let mut depth = 0usize;
        while self.at < self.chars.len() {
            if self.peek(0) == Some('/') && self.peek(1) == Some('*') {
                depth += 1;
                self.at += 2;
            } else if self.peek(0) == Some('*') && self.peek(1) == Some('/') {
                depth -= 1;
                self.at += 2;
                if depth == 0 {
                    return Ok(());
                }
            } else {
                self.at += 1;
            }
        }
        Err(self.unclosed("block comment", from))
    }

    /// One escape after `\` (`at` is on the `\`); `None` for a continuation.
    fn escape(&mut self, byte: bool) -> Result<Option<char>, String> {
        self.at += 1;
        let Some(ch) = self.peek(0) else {
            return Err(self.error("escape at end of input"));
        };
        self.at += 1;
        let value = match ch {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '0' => '\0',
            '\\' => '\\',
            '"' => '"',
            '\'' => '\'',
            'x' => {
                let hex: String = (0..2).filter_map(|k| self.peek(k)).collect();
                let parsed = if hex.len() == 2 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    u8::from_str_radix(&hex, 16).ok()
                } else {
                    None
                };
                let value = parsed.ok_or_else(|| self.error("bad \\x escape"))?;
                if !byte && value > 0x7f {
                    return Err(self.error("\\x escape above 0x7f"));
                }
                self.at += 2;
                char::from(value)
            }
            'u' if !byte => {
                if self.peek(0) != Some('{') {
                    return Err(self.error("bad \\u escape"));
                }
                let mut hex = String::new();
                let mut k = 1;
                loop {
                    match self.peek(k) {
                        Some('}') => break,
                        Some('_') if !hex.is_empty() => {}
                        Some(digit) if digit.is_ascii_hexdigit() => hex.push(digit),
                        _ => return Err(self.error("bad \\u escape")),
                    }
                    k += 1;
                }
                self.at += k + 1;
                if hex.is_empty() || hex.len() > 6 {
                    return Err(self.error("bad \\u escape"));
                }
                u32::from_str_radix(&hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| self.error("bad \\u escape"))?
            }
            '\n' | '\r' => {
                if ch == '\r' && self.peek(0) != Some('\n') {
                    return Err(self.error("bare CR after \\"));
                }
                while self
                    .peek(0)
                    .is_some_and(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r'))
                {
                    self.at += 1;
                }
                return Ok(None);
            }
            other => return Err(self.error(&format!("unknown escape \\{other}"))),
        };
        Ok(Some(value))
    }

    /// A quoted string; `at` is on the opening `"`.
    fn string(&mut self, byte: bool) -> Result<String, String> {
        let from = self.at;
        self.at += 1;
        let mut out = String::new();
        while let Some(ch) = self.peek(0) {
            match ch {
                '"' => {
                    self.at += 1;
                    return Ok(out);
                }
                '\\' => {
                    if let Some(value) = self.escape(byte)? {
                        out.push(value);
                    }
                }
                ch => {
                    out.push(ch);
                    self.at += 1;
                }
            }
        }
        Err(self.unclosed("string", from))
    }

    /// A raw string; `at` is on the first `#` or the `"`.
    fn raw_string(&mut self) -> Result<String, String> {
        let from = self.at;
        let mut hashes = 0;
        while self.peek(0) == Some('#') {
            hashes += 1;
            self.at += 1;
        }
        if self.peek(0) != Some('"') {
            return Err(self.error("raw string without an opening quote"));
        }
        self.at += 1;
        let mut out = String::new();
        while let Some(ch) = self.peek(0) {
            if ch == '"' && (1..=hashes).all(|k| self.peek(k) == Some('#')) {
                self.at += 1 + hashes;
                return Ok(out);
            }
            out.push(ch);
            self.at += 1;
        }
        Err(self.unclosed("raw string", from))
    }

    /// A char or byte literal; `at` is on the opening `'`.
    fn char_literal(&mut self, byte: bool) -> Result<String, String> {
        let from = self.at;
        self.at += 1;
        match self.peek(0) {
            Some('\\') => {
                if self.escape(byte)?.is_none() {
                    return Err(self.error("continuation in a char literal"));
                }
            }
            Some('\'') | Some('\n') | None => return Err(self.error("empty char literal")),
            Some(_) => self.at += 1,
        }
        if self.peek(0) != Some('\'') {
            return Err(self.error("char literal never closes"));
        }
        self.at += 1;
        Ok(self.chars[from..self.at].iter().collect())
    }

    fn number(&mut self) -> String {
        let from = self.at;
        let hex = self.peek(0) == Some('0') && matches!(self.peek(1), Some('x' | 'X'));
        loop {
            match self.peek(0) {
                Some(ch) if ident_continue(ch) => {
                    self.at += 1;
                    if !hex
                        && matches!(ch, 'e' | 'E')
                        && matches!(self.peek(0), Some('+' | '-'))
                        && self.peek(1).is_some_and(|ch| ch.is_ascii_digit())
                    {
                        self.at += 1;
                    }
                }
                Some('.') if self.peek(1).is_some_and(|ch| ch.is_ascii_digit()) => {
                    self.at += 1;
                }
                _ => break,
            }
        }
        self.chars[from..self.at].iter().collect()
    }

    /// An identifier, or the string, raw string or byte literal it prefixes.
    fn word(&mut self) -> Result<Token, String> {
        let from = self.at;
        while self.peek(0).is_some_and(ident_continue) {
            self.at += 1;
        }
        let word: String = self.chars[from..self.at].iter().collect();
        let next = self.peek(0);
        match (word.as_str(), next) {
            ("b" | "c", Some('"')) => Ok(Token::Str(self.string(word == "b")?)),
            ("b", Some('\'')) => Ok(Token::Other(format!("b{}", self.char_literal(true)?))),
            ("r" | "br" | "cr", Some('"')) => Ok(Token::Str(self.raw_string()?)),
            ("r", Some('#')) if self.peek(1).is_some_and(ident_start) => {
                self.at += 1;
                let start = self.at;
                while self.peek(0).is_some_and(ident_continue) {
                    self.at += 1;
                }
                Ok(Token::Ident(self.chars[start..self.at].iter().collect()))
            }
            ("r" | "br" | "cr", Some('#')) => Ok(Token::Str(self.raw_string()?)),
            (_, Some('"' | '\'' | '#')) => {
                Err(self.error(&format!("reserved prefix {word}{}", next.unwrap_or(' '))))
            }
            _ => Ok(Token::Ident(word)),
        }
    }

    fn token(&mut self) -> Result<Option<Token>, String> {
        loop {
            let Some(ch) = self.peek(0) else {
                return Ok(None);
            };
            if ch.is_whitespace() {
                self.at += 1;
            } else if ch == '/' && self.peek(1) == Some('/') {
                while self.peek(0).is_some_and(|ch| ch != '\n') {
                    self.at += 1;
                }
            } else if ch == '/' && self.peek(1) == Some('*') {
                self.block_comment()?;
            } else {
                break;
            }
        }
        let ch = self.peek(0).expect("checked above");
        if ch == '"' {
            return Ok(Some(Token::Str(self.string(false)?)));
        }
        if ch == '\'' {
            let second = self.peek(1);
            let char_like =
                second == Some('\\') || (self.peek(2) == Some('\'') && second != Some('\''));
            if char_like {
                return Ok(Some(Token::Other(self.char_literal(false)?)));
            }
            if second.is_some_and(ident_start) {
                self.at += 1;
                let from = self.at;
                while self.peek(0).is_some_and(ident_continue) {
                    self.at += 1;
                }
                if self.peek(0) == Some('\'') {
                    return Err(self.error("char literal with more than one char"));
                }
                return Ok(Some(Token::Lifetime(
                    self.chars[from..self.at].iter().collect(),
                )));
            }
            return Err(self.error("stray quote"));
        }
        if ch.is_ascii_digit() {
            return Ok(Some(Token::Other(self.number())));
        }
        if ident_start(ch) {
            return self.word().map(Some);
        }
        self.at += 1;
        Ok(Some(Token::Punct(ch)))
    }
}

/// The token stream of `text`, comments dropped; `Err` on anything the
/// tokenizer cannot read the way rustc would (fail closed).
pub(super) fn tokens(text: &str) -> Result<Vec<Token>, String> {
    let mut lexer = Lexer {
        chars: text.chars().collect(),
        at: 0,
    };
    let mut found = Vec::new();
    while let Some(token) = lexer.token()? {
        found.push(token);
    }
    Ok(found)
}

/// `tokens` as one comment-free line for substring rules: a space only
/// between two word-like tokens, strings re-quoted from their decoded value.
pub(super) fn render(tokens: &[Token]) -> String {
    let mut out = String::new();
    let mut word_before = false;
    for token in tokens {
        let (text, word) = match token {
            Token::Ident(ident) => (ident.clone(), true),
            Token::Lifetime(name) => (format!("'{name}"), true),
            Token::Str(value) => (format!("{value:?}"), true),
            Token::Other(text) => (text.clone(), true),
            Token::Punct(ch) => (ch.to_string(), false),
        };
        if word && word_before {
            out.push(' ');
        }
        out.push_str(&text);
        word_before = word;
    }
    out
}

/// `tokens` without any run equal to `run`.
pub(super) fn remove_runs(tokens: &[Token], run: &[Token]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if !run.is_empty() && tokens[i..].starts_with(run) {
            i += run.len();
        } else {
            out.push(tokens[i].clone());
            i += 1;
        }
    }
    out
}

/// A string literal that may be (part of) a statement.
fn sql_like() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"\$[0-9]|(?i:\bselect\s+[a-z_][a-z0-9_.]*\s*\()|(?i:_set_(?:create|update|destroy)\b)|^\s*(?:SELECT|WITH|INSERT|UPDATE|DELETE)\b",
        )
        .expect("sql-like pattern")
    })
}

/// One anchored reducer call, placeholders only (D1 shape); the macro tail
/// is optional because a bare literal is checked as written.
fn reducer_shape() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^SELECT [a-z_][a-z0-9_]*\(\$1(?:,\$[1-9][0-9]*(?:::[a-z0-9_]+(?:\[\])?)*)*\)(?:::text)?(?: WHERE \$2::bigint>0(?: AND \$3::text<>'')?)?$",
        )
        .expect("reducer call pattern")
    })
}

/// What one family file can hand the seam.
#[derive(Debug, Default)]
pub(super) struct FamilySql {
    /// Every statement: macro expansions and SQL-looking literals.
    pub(super) statements: Vec<String>,
    /// Every rule the file breaks; non-empty means the statements are not trusted.
    pub(super) violations: Vec<String>,
}

/// Scan one family file (`name` selects the core-file allowance for `format!`).
pub(super) fn family_sql(name: &str, text: &str) -> FamilySql {
    let mut scan = FamilySql::default();
    let tokens = match tokens(text) {
        Ok(tokens) => tokens,
        Err(error) => {
            scan.violations.push(format!("{name}: {error}"));
            return scan;
        }
    };
    let core = CORE_FILES.contains(&name);
    let mut macro_literals = Vec::new();
    let mut in_use = false;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Ident(word) if word == "use" => in_use = true,
            Token::Punct(';') => in_use = false,
            _ => {}
        }
        let Token::Ident(word) = token else {
            continue;
        };
        if !SQL_IDENTS.contains(&word.as_str()) || (core && word == "format") {
            continue;
        }
        let before = index.checked_sub(1).map(|at| &tokens[at]);
        let after = tokens.get(index + 1);
        let aliased = matches!(before, Some(Token::Ident(word)) if word == "as")
            || matches!(after, Some(Token::Ident(word)) if word == "as");
        if in_use
            && SEAM_MACROS.contains(&word.as_str())
            && !aliased
            && matches!(after, Some(Token::Punct(',' | '}' | ';')))
        {
            continue;
        }
        let literal = match tokens.get(index + 1..index + 5) {
            Some(
                [Token::Punct('!'), Token::Punct('('), Token::Str(literal), Token::Punct(')')],
            ) => literal,
            _ => {
                let context = render(&tokens[index..tokens.len().min(index + 8)]);
                scan.violations.push(format!(
                    "{name}: `{word}` is not `{word}!(\"literal\")`: {context}"
                ));
                continue;
            }
        };
        macro_literals.push(index + 3);
        match word.as_str() {
            "read_sql" => scan.statements.push(format!("{literal}{READ_TAIL}")),
            "write_sql" => scan.statements.push(format!("{literal}{WRITE_TAIL}")),
            "set_sql" => {
                let valid = literal.starts_with(|ch: char| ch.is_ascii_lowercase() || ch == '_')
                    && literal
                        .chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
                if !valid {
                    scan.violations
                        .push(format!("{name}: set_sql! prefix {literal:?}"));
                    continue;
                }
                for (phase, payload) in [
                    ("create", "$3::text::jsonb"),
                    ("update", "$3::text::jsonb"),
                    ("destroy", "$3::bigint[]"),
                ] {
                    scan.statements.push(format!(
                        "SELECT {literal}_set_{phase}($1,{payload})::text{READ_TAIL}"
                    ));
                }
            }
            // `concat!`/`include_str!`/`format!`: the literal is checked on its own.
            _ => {
                macro_literals.pop();
            }
        }
    }
    for (index, token) in tokens.iter().enumerate() {
        if let Token::Str(literal) = token {
            if !macro_literals.contains(&index) && sql_like().is_match(literal) {
                scan.statements.push(literal.trim_start().to_owned());
            }
        }
    }
    let mut seen = Vec::new();
    for statement in &scan.statements {
        if !reducer_shape().is_match(statement) {
            scan.violations.push(format!(
                "{name}: SQL {:?}",
                statement.chars().take(60).collect::<String>()
            ));
        }
        if !seen.contains(statement) {
            seen.push(statement.clone());
        }
    }
    scan.statements = seen;
    scan
}

#[cfg(test)]
mod tests {
    use super::{family_sql, render, tokens, Token};

    fn strings(text: &str) -> Vec<String> {
        tokens(text)
            .expect("lexes")
            .into_iter()
            .filter_map(|token| match token {
                Token::Str(value) => Some(value),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn strings_decode_what_the_compiler_sees() {
        let text = "let a = \"\\\n      SELECT f($1,$3)\";\n\
            let b = r#\"SELECT \"g\"($1)\"#; let c = \"a\\tb\\n\\\"\\\\\\u{4_1}\\x41\";\n\
            let d = '\"'; let e: &'static str = \"x\"; // \"no\"\n/* \"no\" */\n\
            let f = br##\"a\"#b\"##; let g = b'\\''; let h = c\"z\"; let i = '\\u{1F600}';\n\
            'outer: loop { break 'outer; } let r#j = 1e-3 + 0x1F + 1.5;";
        assert_eq!(
            strings(text),
            [
                "SELECT f($1,$3)",
                "SELECT \"g\"($1)",
                "a\tb\n\"\\AA",
                "x",
                "a\"#b",
                "z"
            ]
        );
        assert!(render(&tokens(text).expect("lexes")).contains("let j=1e-3+0x1F+1.5;"));
    }

    #[test]
    fn nested_and_doc_comments_hide_nothing() {
        let text = "/* /* */ \" */\nconst S: Sql = read_sql!(\"SELECT f($1,$3)\");\n\
            /** doc \" */ //! inner \"\n/// outer \"\nconst T: &str = \"t\";";
        assert_eq!(strings(text), ["SELECT f($1,$3)", "t"]);
    }

    #[test]
    fn lexing_errors_fail_closed() {
        for bad in [
            "/* /* */",
            "\"open",
            "r#\"open\"",
            "\"\\q\"",
            "\"\\x80\"",
            "\"\\u{110000}\"",
            "\"\\u{}\"",
            "'ab'",
            "''",
            "f\"x\"",
            "br#x",
        ] {
            assert!(tokens(bad).is_err(), "{bad}");
            assert!(
                !family_sql("reminder.rs", bad).violations.is_empty(),
                "{bad}"
            );
        }
        assert!(tokens("b\"\\x80\"").is_ok(), "byte strings take any \\x");
    }

    #[test]
    fn every_sql_identifier_is_a_canonical_invocation() {
        let ok = "use super::seam::{read_sql, write_sql, set_sql};\n\
            const A: Sql = read_sql!(\"SELECT f($1,$3)::text\");\n\
            const B: Sql = super::seam::write_sql!(r\"SELECT g($1,$4)::text\");\n\
            const C: Sql = read_sql/**/!(\"SELECT h($1)::text\");\n\
            const D: SetSql = set_sql!(\"jmap_task\");";
        let scan = family_sql("reminder.rs", ok);
        assert!(scan.violations.is_empty(), "{:?}", scan.violations);
        assert_eq!(
            scan.statements,
            [
                "SELECT f($1,$3)::text WHERE $2::bigint>0",
                "SELECT g($1,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
                "SELECT h($1)::text WHERE $2::bigint>0",
                "SELECT jmap_task_set_create($1,$3::text::jsonb)::text WHERE $2::bigint>0",
                "SELECT jmap_task_set_update($1,$3::text::jsonb)::text WHERE $2::bigint>0",
                "SELECT jmap_task_set_destroy($1,$3::bigint[])::text WHERE $2::bigint>0",
            ]
        );
        for bad in [
            "read_sql!(QUERY)",
            "read_sql!(concat!(\"SELECT f(\", \"$1)\"))",
            "read_sql!(\"SELECT f($1)\" + 1)",
            "read_sql!(\"SELECT f($1)::text\",)",
            "read_sql![\"SELECT f($1)::text\"]",
            "read_sql!()",
            "use super::seam::read_sql as q;",
            "use super::seam::{write_sql as read_sql};",
            "use super::seam::read_sql;; read_sql(1)",
            "let q = read_sql;",
            "set_sql!(PREFIX)",
            "set_sql!(\"Bad Prefix\")",
            "let s = [\"a\", \"b\"].concat();",
            "let s = format!(\"{}\", 1);",
            "let s = include_str!(concat!(\"a\", \"b\"));",
            "use std::concat as c;",
        ] {
            assert!(
                !family_sql("reminder.rs", bad).violations.is_empty(),
                "{bad}"
            );
        }
        assert!(
            family_sql("mod.rs", "let s = format!(\"{}\", 1);")
                .violations
                .is_empty(),
            "core files keep format!"
        );
    }

    #[test]
    fn sql_looking_literals_are_checked_outside_macros() {
        for bad in [
            "const S: &str = \"SELECT x FROM t WHERE mailbox_id = $1\";",
            "const S: &str = \"$3,$4)::text\";",
            "const S: &str = \"x select f( y\";",
            "const S: &str = \"jmap_task_set_create\";",
            "const S: &str = \"DELETE FROM t\";",
        ] {
            assert!(
                !family_sql("reminder.rs", bad).violations.is_empty(),
                "{bad}"
            );
        }
        let scan = family_sql(
            "reminder.rs",
            "const S: &str = \"SELECT mail_work_get($1,$3,$4)::text\";",
        );
        assert!(scan.violations.is_empty());
        assert_eq!(scan.statements, ["SELECT mail_work_get($1,$3,$4)::text"]);
        assert!(family_sql(
            "reminder.rs",
            "const T: &str = \"update must be an object\";"
        )
        .statements
        .is_empty());
    }
}
