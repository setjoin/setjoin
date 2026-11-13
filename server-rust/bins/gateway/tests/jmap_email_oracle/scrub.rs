//! Deterministic names for the values a fresh fixture generates: ids become
//! `<name>`, timestamps `<timestamp>`. Applied to JSON text so key order and
//! separators of Go's response bytes survive untouched.
use std::collections::BTreeMap;

pub type Names = BTreeMap<i64, String>;

/// Replace known ids (as numbers, strings or keys) and timestamps.
pub fn scrub(text: &str, names: &Names) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let content = &text[start..j.min(b.len())];
                out.push('"');
                match content.parse::<i64>().ok().and_then(|n| names.get(&n)) {
                    Some(name) if !content.starts_with('+') => out.push_str(name),
                    _ => out.push_str(&scrub_timestamps(content)),
                }
                out.push('"');
                i = j + 1;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let before = start.checked_sub(1).map(|k| b[k]);
                let after = b.get(i).copied();
                let word = |x: Option<u8>| {
                    x.is_some_and(|c| {
                        c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-'
                    })
                };
                let n = text[start..i]
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| names.get(&n));
                match n {
                    _ if text[..start].trim_end().ends_with("\"imap_uid_validity\":") => {
                        // Tag creation stamps this field with the wall clock's
                        // Unix seconds. Preserve its presence, normalize time.
                        out.push_str("\"<timestamp>\"");
                    }
                    Some(name) if !word(before) && !word(after) => {
                        out.push('"');
                        out.push_str(name);
                        out.push('"');
                    }
                    _ => out.push_str(&text[start..i]),
                }
            }
            _ => {
                let ch = text[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

fn digits(b: &[u8], at: usize, n: usize) -> bool {
    b.len() >= at + n && b[at..at + n].iter().all(u8::is_ascii_digit)
}

/// `YYYY-MM-DD(T| )HH:MM:SS[.f+][Z|±hh[:mm]]` anywhere in `s`.
pub fn scrub_timestamps(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let stamp = digits(b, i, 4)
            && b.get(i + 4) == Some(&b'-')
            && digits(b, i + 5, 2)
            && b.get(i + 7) == Some(&b'-')
            && digits(b, i + 8, 2)
            && matches!(b.get(i + 10), Some(b'T') | Some(b' '))
            && digits(b, i + 11, 2)
            && b.get(i + 13) == Some(&b':')
            && digits(b, i + 14, 2)
            && b.get(i + 16) == Some(&b':')
            && digits(b, i + 17, 2);
        if !stamp {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let mut j = i + 19;
        if b.get(j) == Some(&b'.') {
            j += 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        }
        match b.get(j) {
            Some(b'Z') => j += 1,
            Some(b'+') | Some(b'-') if digits(b, j + 1, 2) => {
                j += 3;
                if b.get(j) == Some(&b':') && digits(b, j + 1, 2) {
                    j += 3;
                }
            }
            _ => {}
        }
        out.push_str("<timestamp>");
        i = j;
    }
    out
}

/// The `sessionState` counters stay; the final user timestamp does not.
pub fn scrub_session_state(body: &str) -> Result<String, String> {
    scrub_named_session_state(body, "sessionState")
}

pub fn scrub_named_session_state(body: &str, name: &str) -> Result<String, String> {
    let tag = format!("\"{name}\":\"");
    let at = body.find(&tag).ok_or("no session state")? + tag.len();
    let end = at + body[at..].find('"').ok_or("unterminated sessionState")?;
    let (counters, stamp) = body[at..end]
        .rsplit_once('-')
        .ok_or("malformed sessionState")?;
    stamp.parse::<u64>().map_err(|e| e.to_string())?;
    Ok(format!(
        "{}{counters}-<timestamp>{}",
        &body[..at],
        &body[end..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_timestamps_are_named() {
        let names = Names::from([
            (900001, "<mailbox>".to_owned()),
            (900002, "<m1>".to_owned()),
        ]);
        assert_eq!(
            scrub(
                r#"{"a":"900001","b":[900002,5],"900002":{"t":"2026-01-02T03:04:05.123Z x","n":"900003"}}"#,
                &names
            ),
            r#"{"a":"<mailbox>","b":["<m1>",5],"<m1>":{"t":"<timestamp> x","n":"900003"}}"#
        );
    }
}
