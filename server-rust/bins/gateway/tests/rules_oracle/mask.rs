use crate::common;
use serde_json::{json, Value};
pub fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn timestamp_at(b: &[u8], i: usize) -> bool {
    let digits = |from: usize, n: usize| {
        b.get(from..from + n)
            .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
    };
    digits(i, 4)
        && b.get(i + 4) == Some(&b'-')
        && digits(i + 5, 2)
        && b.get(i + 7) == Some(&b'-')
        && digits(i + 8, 2)
        && matches!(b.get(i + 10), Some(b'T' | b' '))
        && digits(i + 11, 2)
        && b.get(i + 13) == Some(&b':')
        && digits(i + 14, 2)
        && b.get(i + 16) == Some(&b':')
        && digits(i + 17, 2)
}

/// Masks run-time timestamps in text (seeded `2026-10-0x` times stay readable).
pub fn mask_timestamps(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if timestamp_at(b, i) && !text[i..].starts_with("2026-10-0") {
            let mut end = i + 19;
            if b.get(end) == Some(&b'.') {
                end += 1;
                while b.get(end).is_some_and(u8::is_ascii_digit) {
                    end += 1;
                }
            }
            if b.get(end) == Some(&b'Z') {
                end += 1;
            } else if matches!(b.get(end), Some(b'+' | b'-')) && b.get(end + 3) == Some(&b':') {
                end += 6;
            }
            out.push_str("<timestamp>");
            i = end;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Replaces `"key":value` (a bare integer) by the symbolic label, for run-specific ids.
pub fn mask_ids(text: &str, names: &[(&str, i64, String)]) -> String {
    let mut out = text.to_owned();
    for (key, value, label) in names {
        for sep in [":", ": "] {
            let tag = format!("\"{key}\"{sep}{value}");
            let mut at = 0;
            while let Some(found) = out[at..].find(&tag) {
                let start = at + found;
                let end = start + tag.len();
                if out.as_bytes().get(end).is_some_and(u8::is_ascii_digit) {
                    at = end;
                    continue;
                }
                let replacement = format!("\"{key}\"{sep}\"{label}\"");
                out.replace_range(start..end, &replacement);
                at = start + replacement.len();
            }
        }
    }
    out
}

/// Masks a quoted value for a key (`"previewToken":"…"`).
pub fn mask_strings(text: &str, keys: &[&str]) -> String {
    let mut out = text.to_owned();
    for key in keys {
        for sep in [":", ": "] {
            let tag = format!("\"{key}\"{sep}\"");
            let mut at = 0;
            while let Some(found) = out[at..].find(&tag) {
                let start = at + found + tag.len();
                let Some(len) = out[start..].find('"') else {
                    break;
                };
                out.replace_range(start..start + len, "<value>");
                at = start + 7;
            }
        }
    }
    out
}
