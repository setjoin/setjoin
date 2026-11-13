//! REAL Go responses as templates (review item 6).
//!
//! `tests/golden/go-*.json` are the bodies mailserverd wrote on the real
//! stack (rp07 review-fix kit `capture.sh`, account 1, Go 1.26.6 build of the
//! integration tip): Go's bytes, never hand-written. A DB case re-targets a
//! golden at its own fixture by swapping the values Go wrote for the case's
//! values, key by key; every other byte (key order, separators, escaping,
//! the trailing newline) stays Go's.

/// One replacement: the value after `"key":` (a JSON string, number or
/// array, written in place without re-encoding).
pub enum Value<'a> {
    Str(&'a str),
    Num(i64),
    /// An array's inner text, e.g. `"31","30"`.
    Array(&'a str),
}

/// `golden` with the first value of each `key` replaced. Panics (test only)
/// when a key is missing, so a golden that changes shape fails loudly.
pub fn retarget(golden: &str, swaps: &[(&str, Value<'_>)]) -> String {
    let mut out = golden.to_owned();
    for (key, value) in swaps {
        let tag = format!("\"{key}\":");
        let at = out
            .find(&tag)
            .unwrap_or_else(|| panic!("golden has no {key}"))
            + tag.len();
        let rest = &out[at..];
        let len = match rest.as_bytes()[0] {
            b'"' => rest[1..].find('"').expect("closing quote") + 2,
            b'[' => rest.find(']').expect("closing bracket") + 1,
            _ => rest
                .find(|c: char| !(c.is_ascii_digit() || c == '-'))
                .expect("number end"),
        };
        let new = match value {
            Value::Str(s) => format!("\"{s}\""),
            Value::Num(n) => n.to_string(),
            Value::Array(inner) => format!("[{inner}]"),
        };
        out.replace_range(at..at + len, &new);
    }
    out
}

/// `golden` with its single per-item key (`"notUpdated":{"<id>":…`) moved
/// to `id`.
pub fn retarget_item(golden: &str, map_key: &str, id: i64) -> String {
    let tag = format!("\"{map_key}\":{{\"");
    let at = golden.find(&tag).expect("per-item map") + tag.len();
    let end = at + golden[at..].find('"').expect("item key end");
    let mut out = golden.to_owned();
    out.replace_range(at..end, &id.to_string());
    out
}

pub const SET_INVALID: &str = include_str!("../golden/go-set-invalid.json");
pub const SET_UPDATED: &str = include_str!("../golden/go-set-updated.json");
pub const SET_NOTFOUND: &str = include_str!("../golden/go-set-notfound.json");
pub const LIST_PAGE: &str = include_str!("../golden/go-list-1.json");
