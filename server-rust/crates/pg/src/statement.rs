//! Lexical admission of command statements sent through a [`crate::ScopedTx`].
//!
//! The executor alone owns BEGIN, the tenant scope GUC and COMMIT/ROLLBACK.
//! A command statement may not change role, session or transaction state, so
//! this refuses (before anything reaches the server) a statement whose first
//! word is `SET`/`RESET` (so `SET [LOCAL] ROLE`, `SET SESSION AUTHORIZATION`),
//! transaction control, savepoints,
//! named prepared statements, `DISCARD`, `LISTEN`/`NOTIFY` commands, `DO`
//! blocks, any `set_config(` call, and more than one statement. Text inside
//! single-quoted literals, quoted identifiers and comments is ignored; text
//! inside dollar quotes is still scanned (conservative). This is defence in
//! depth: credentials, not this filter, carry privilege (never `SET ROLE`).

const REFUSED_FIRST_WORDS: [&str; 19] = [
    "set",
    "reset",
    "begin",
    "start",
    "commit",
    "end",
    "rollback",
    "abort",
    "savepoint",
    "release",
    "prepare",
    "execute",
    "deallocate",
    "discard",
    "listen",
    "unlisten",
    "notify",
    "do",
    "call",
];

/// `Ok(())` when `sql` is a single admissible command statement.
pub fn admit(sql: &str) -> Result<(), &'static str> {
    let code = strip_literals_and_comments(sql);
    let body = code.trim_end().trim_end_matches(';');
    if body.contains(';') {
        return Err("multiple statements");
    }
    let words: Vec<String> = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect();
    let Some(first) = words.first() else {
        return Err("empty statement");
    };
    if REFUSED_FIRST_WORDS.contains(&first.as_str()) {
        return Err("session, role or transaction control is owned by the executor");
    }
    if words.iter().any(|w| w == "set_config") {
        return Err("set_config is owned by the executor");
    }
    Ok(())
}

/// Blank out `'…'` literals, `"…"` identifiers, `-- …` and `/* … */` comments.
fn strip_literals_and_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                // A doubled quote inside the literal re-opens it on the next loop turn.
                for d in chars.by_ref() {
                    if d == c {
                        break;
                    }
                }
                out.push(' ');
            }
            '-' if chars.peek() == Some(&'-') => {
                for d in chars.by_ref() {
                    if d == '\n' {
                        break;
                    }
                }
                out.push(' ');
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for d in chars.by_ref() {
                    if prev == '*' && d == '/' {
                        break;
                    }
                    prev = d;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}
