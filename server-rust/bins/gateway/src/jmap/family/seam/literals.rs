//! Test-only decoder for Rust string literals, shared by the source guards
//! (`tests::family_files_use_only_the_seam` and
//! `call::db::actor_arguments_are_seam_bound`). Both read family source text, so
//! both must see what the compiler sees: a `\`-newline continuation, escapes and
//! raw strings all decode here, and an SQL macro argument that is not a plain
//! literal is an error (fail closed), never a statement the guards skip.

fn is_ident(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// The literal starting at `at` (`"…"`, `r"…"`, `r#"…"#`, `b"…"`, `br#"…"#`):
/// its decoded value and the index after it. `None` when `at` starts none.
fn literal_at(chars: &[char], at: usize) -> Option<(String, usize)> {
    let mut i = at;
    if chars.get(i) == Some(&'b') {
        i += 1;
    }
    if chars.get(i) == Some(&'r') {
        let mut hashes = 0;
        let mut j = i + 1;
        while chars.get(j) == Some(&'#') {
            hashes += 1;
            j += 1;
        }
        if chars.get(j) != Some(&'"') {
            return None;
        }
        j += 1;
        let mut out = String::new();
        while j < chars.len() {
            if chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
                return Some((out, j + 1 + hashes));
            }
            out.push(chars[j]);
            j += 1;
        }
        return None;
    }
    if chars.get(i) != Some(&'"') {
        return None;
    }
    i += 1;
    let mut out = String::new();
    while i < chars.len() {
        match chars[i] {
            '"' => return Some((out, i + 1)),
            '\\' => {
                i += 1;
                match chars.get(i)? {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '0' => out.push('\0'),
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    '\'' => out.push('\''),
                    'x' => {
                        let hex: String = chars.get(i + 1..i + 3)?.iter().collect();
                        out.push(char::from(u8::from_str_radix(&hex, 16).ok()?));
                        i += 2;
                    }
                    'u' => {
                        let close = chars[i..].iter().position(|ch| *ch == '}')? + i;
                        let hex: String = chars[i + 2..close]
                            .iter()
                            .filter(|ch| **ch != '_')
                            .collect();
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                        i = close;
                    }
                    '\n' | '\r' => {
                        while chars.get(i + 1).is_some_and(|ch| ch.is_whitespace()) {
                            i += 1;
                        }
                    }
                    other => {
                        out.push('\\');
                        out.push(*other);
                    }
                }
                i += 1;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    None
}

/// Every string literal in `text`, decoded, skipping comments and char literals.
pub(super) fn literals(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();
        if ch == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && next == Some('*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else if ch == '\'' {
            if next == Some('\\') {
                i += 2;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                i += 1;
            } else if chars.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
        } else if ch == '"' || ((ch == 'r' || ch == 'b') && (i == 0 || !is_ident(chars[i - 1]))) {
            match literal_at(&chars, i) {
                Some((value, end)) => {
                    found.push(value);
                    i = end;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    found
}

/// The decoded literal argument of every `name!(…)` invocation (any of `names`).
/// An argument that is not exactly one plain literal (a const, `concat!`, an
/// identifier, extra tokens) is an `Err`: the guards cannot see the statement.
pub(super) fn macro_arguments(text: &str, names: &[&str]) -> Result<Vec<(String, String)>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    for name in names {
        let pattern: Vec<char> = name.chars().collect();
        let mut i = 0;
        while i + pattern.len() < chars.len() {
            if chars[i..i + pattern.len()] != pattern[..] || (i > 0 && is_ident(chars[i - 1])) {
                i += 1;
                continue;
            }
            let mut j = i + pattern.len();
            while chars.get(j).is_some_and(|ch| ch.is_whitespace()) {
                j += 1;
            }
            if chars.get(j) != Some(&'!') {
                i += 1;
                continue;
            }
            j += 1;
            while chars.get(j).is_some_and(|ch| ch.is_whitespace()) {
                j += 1;
            }
            let Some(open) = chars.get(j).filter(|ch| matches!(ch, '(' | '[' | '{')) else {
                i += 1;
                continue;
            };
            let close = match open {
                '(' => ')',
                '[' => ']',
                _ => '}',
            };
            j += 1;
            while chars.get(j).is_some_and(|ch| ch.is_whitespace()) {
                j += 1;
            }
            let context: String = chars[i..chars.len().min(i + 50)].iter().collect();
            let Some((value, mut end)) = literal_at(&chars, j) else {
                return Err(format!("unrecognized {name}! argument: {context:?}"));
            };
            while chars.get(end).is_some_and(|ch| ch.is_whitespace()) {
                end += 1;
            }
            if chars.get(end) == Some(&',') {
                end += 1;
                while chars.get(end).is_some_and(|ch| ch.is_whitespace()) {
                    end += 1;
                }
            }
            if chars.get(end) != Some(&close) {
                return Err(format!("unrecognized {name}! argument: {context:?}"));
            }
            found.push(((*name).to_owned(), value));
            i = end;
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{literals, macro_arguments};

    #[test]
    fn literals_decode_what_the_compiler_sees() {
        let text = "let a = \"\\\n      SELECT f($1,$3)\";\n\
            let b = r#\"SELECT \"g\"($1)\"#; let c = \"a\\tb\\n\\\"\\\\\\u{41}\\x41\";\n\
            let d = '\"'; let e: &'static str = \"x\"; // \"no\"\n/* \"no\" */";
        assert_eq!(
            literals(text),
            ["SELECT f($1,$3)", "SELECT \"g\"($1)", "a\tb\n\"\\AA", "x"]
        );
    }

    #[test]
    fn macro_arguments_are_literals_or_an_error() {
        let ok = "read_sql!(\"\\\n   SELECT f($1,$3)\") write_sql!(r\"SELECT g($1)\",)";
        assert_eq!(
            macro_arguments(ok, &["read_sql", "write_sql"]).expect("literals"),
            [
                ("read_sql".to_owned(), "SELECT f($1,$3)".to_owned()),
                ("write_sql".to_owned(), "SELECT g($1)".to_owned())
            ]
        );
        for bad in [
            "read_sql!(QUERY)",
            "read_sql!(concat!(\"SELECT f(\", \"$1)\"))",
            "read_sql!(\"SELECT f($1)\" + 1)",
            "read_sql!()",
        ] {
            assert!(macro_arguments(bad, &["read_sql"]).is_err(), "{bad}");
        }
        assert!(
            macro_arguments("use x::read_sql; // `read_sql!` docs", &["read_sql"])
                .expect("no invocation")
                .is_empty()
        );
    }
}
