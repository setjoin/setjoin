//! Lexical admission of command statements sent through a [`crate::ScopedTx`]
//! or typed capability transaction handle.
//!
//! The executor alone owns BEGIN, the tenant scope GUC and COMMIT/ROLLBACK.
//! A command statement may not change role, session or transaction state, or
//! acquire session-level advisory locks that survive pooled transactions, so
//! this refuses (before anything reaches the server):
//! - interior NUL bytes (`\0`);
//! - a statement whose first word is `SET`/`RESET` (so `SET [LOCAL] ROLE`,
//!   `SET SESSION AUTHORIZATION`), transaction control, savepoints, named
//!   prepared statements, `DISCARD`, `LISTEN`/`NOTIFY` commands, `DO` blocks,
//!   or `CALL`;
//! - any `set_config` call (including double-quoted `"set_config"`);
//! - any of the seven session-level advisory lock functions
//!   (`pg_advisory_lock`, `pg_try_advisory_lock`, `pg_advisory_unlock`,
//!   `pg_advisory_lock_shared`, `pg_try_advisory_lock_shared`,
//!   `pg_advisory_unlock_shared`, `pg_advisory_unlock_all`);
//! - more than one statement (`;`).
//!
//! Text inside single-quoted literals and SQL comments is ignored; text inside
//! dollar quotes is still scanned (conservative). This is defence in depth:
//! credentials, not this filter, carry privilege (never `SET ROLE`).

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

const REFUSED_SESSION_ADVISORY_LOCKS: [&str; 7] = [
    "pg_advisory_lock",
    "pg_try_advisory_lock",
    "pg_advisory_unlock",
    "pg_advisory_lock_shared",
    "pg_try_advisory_lock_shared",
    "pg_advisory_unlock_shared",
    "pg_advisory_unlock_all",
];

/// `Ok(())` when `sql` is a single admissible command statement.
pub fn admit(sql: &str) -> Result<(), &'static str> {
    if sql.contains('\0') {
        return Err("statement contains NUL byte");
    }
    let code = strip_literals_and_comments(sql, true);
    let body = code.trim_end().trim_end_matches(';');
    if body.contains(';') {
        return Err("multiple statements");
    }
    let words: Vec<String> = extract_words(body);
    let Some(first) = words.first() else {
        return Err("empty statement");
    };
    if REFUSED_FIRST_WORDS.contains(&first.as_str()) {
        return Err("session, role or transaction control is owned by the executor");
    }
    // Scan with double-quoted identifiers preserved so `"set_config"(...)` and
    // `"pg_advisory_lock"(...)` cannot slip past lexical admission.
    let ident_code = strip_literals_and_comments(sql, false);
    for word in extract_words(&ident_code) {
        if word == "set_config" {
            return Err("set_config is owned by the executor");
        }
        if REFUSED_SESSION_ADVISORY_LOCKS.contains(&word.as_str()) {
            return Err("session-level advisory locks are forbidden on pooled connections");
        }
    }
    Ok(())
}

/// `Ok(())` when `sql` passes [`admit`] and begins with `SELECT`.
pub fn admit_select(sql: &str) -> Result<(), &'static str> {
    admit(sql)?;
    let code = strip_literals_and_comments(sql, true);
    let first = extract_words(&code).into_iter().next().unwrap_or_default();
    if first != "select" {
        return Err("read accepts only a SELECT");
    }
    Ok(())
}

fn extract_words(code: &str) -> Vec<String> {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

/// Blank out `'…'` literals, optionally `"…"` identifiers, `-- …` and `/* … */` comments.
fn strip_literals_and_comments(sql: &str, strip_double_quotes: bool) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                // A doubled quote inside the literal re-opens it on the next loop turn.
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                }
                out.push(' ');
            }
            '"' if strip_double_quotes => {
                for d in chars.by_ref() {
                    if d == '"' {
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
