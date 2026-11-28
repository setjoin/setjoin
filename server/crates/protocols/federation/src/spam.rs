//! The two text detectors the receiver applies to a decoded chat body, ported
//! from `shared/spam` (`DetectMixedCharset`, `DetectFakeHTML`), plus the
//! payload pre-checks that keep an undeliverable payload from aborting the
//! applier's transaction.

use crate::gojson;
use regex::{bytes::Regex as BytesRegex, Regex};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin = 0,
    Cjk = 1,
    Cyrillic = 2,
    Arabic = 3,
    Other = 4,
}

fn classify(r: char) -> Script {
    let c = r as u32;
    if (0x0400..=0x04FF).contains(&c) || (0x0500..=0x052F).contains(&c) {
        Script::Cyrillic
    } else if (0x4E00..=0x9FFF).contains(&c)
        || (0x3400..=0x4DBF).contains(&c)
        || (0x20000..=0x2A6DF).contains(&c)
        || (0x3040..=0x309F).contains(&c)
        || (0x30A0..=0x30FF).contains(&c)
        || (0xAC00..=0xD7AF).contains(&c)
    {
        Script::Cjk
    } else if (0x0600..=0x06FF).contains(&c)
        || (0x0750..=0x077F).contains(&c)
        || (0xFB50..=0xFDFF).contains(&c)
        || (0xFE70..=0xFEFF).contains(&c)
    {
        Script::Arabic
    } else if r.is_ascii_alphabetic()
        || (0x00C0..=0x024F).contains(&c)
        || (0x1E00..=0x1EFF).contains(&c)
    {
        Script::Latin
    } else {
        Script::Other
    }
}

/// `DetectMixedCharset`'s verdict (the score is not used by the receiver).
pub fn detect_mixed_charset(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let mut counts = [0usize; 5];
    let mut total = 0usize;
    for r in text.chars() {
        let s = classify(r);
        if s == Script::Other {
            continue;
        }
        counts[s as usize] += 1;
        total += 1;
    }
    if total < 5 {
        return false;
    }
    counts.iter().filter(|&&c| c > 0).count() >= 2
}

const FAKE_HTML: &[(&str, &str)] = &[
    (
        r"(?i)font-size[\t\n\f\r ]*:[\t\n\f\r ]*0[\t\n\f\r ]*(?:px|pt|em|rem)?",
        "hidden:text:font-size-zero",
    ),
    (
        r"(?i)font-size[\t\n\f\r ]*:[\t\n\f\r ]*[12]px",
        "hidden:text:tiny-font",
    ),
    (
        r"(?i)display[\t\n\f\r ]*:[\t\n\f\r ]*none",
        "hidden:text:display-none",
    ),
    (
        r"(?i)color[\t\n\f\r ]*:[\t\n\f\r ]*white",
        "hidden:text:white-on-white",
    ),
    (
        r"(?i)color[\t\n\f\r ]*:[\t\n\f\r ]*#fff(?:fff)?(?-u:\b)",
        "hidden:text:white-hex",
    ),
    (
        r"(?i)opacity[\t\n\f\r ]*:[\t\n\f\r ]*0(?-u:\b)",
        "hidden:text:opacity-zero",
    ),
    (
        r"(?i)visibility[\t\n\f\r ]*:[\t\n\f\r ]*hidden",
        "hidden:text:visibility-hidden",
    ),
    (
        r"(?i)position[\t\n\f\r ]*:[\t\n\f\r ]*absolute[\t\n\f\r ]*;[\t\n\f\r ]*left[\t\n\f\r ]*:[\t\n\f\r ]*-9999px",
        "hidden:text:offscreen-left",
    ),
    (
        r"(?i)position[\t\n\f\r ]*:[\t\n\f\r ]*absolute[\t\n\f\r ]*;[\t\n\f\r ]*left[\t\n\f\r ]*:[\t\n\f\r ]*-10000px",
        "hidden:text:offscreen-left",
    ),
    (
        r"(?i)text-indent[\t\n\f\r ]*:[\t\n\f\r ]*-9999px",
        "hidden:text:neg-indent",
    ),
    (
        r"(?i)width[\t\n\f\r ]*:[\t\n\f\r ]*0(?-u:\b).*height[\t\n\f\r ]*:[\t\n\f\r ]*0(?-u:\b)",
        "hidden:text:zero-size",
    ),
    (
        r"(?i)height[\t\n\f\r ]*:[\t\n\f\r ]*0(?-u:\b).*width[\t\n\f\r ]*:[\t\n\f\r ]*0(?-u:\b)",
        "hidden:text:zero-size",
    ),
];

fn fake_html_regexes() -> &'static Vec<(Regex, &'static str)> {
    static R: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        FAKE_HTML
            .iter()
            .map(|(p, l)| (Regex::new(p).expect("fake-html pattern"), *l))
            .collect()
    })
}

/// `DetectFakeHTML`'s distinct technique labels, in pattern order.
pub fn detect_fake_html(body: &str) -> Vec<&'static str> {
    if body.is_empty() {
        return Vec::new();
    }
    let mut seen: Vec<&'static str> = Vec::new();
    for (re, label) in fake_html_regexes() {
        if re.is_match(body) && !seen.contains(label) {
            seen.push(label);
        }
    }
    seen
}

/// `spamScanChatBody`: a quarantine verdict plus a comma-joined reason.
pub fn spam_scan_chat_body(body: &str) -> (bool, String) {
    let mut reasons: Vec<&str> = Vec::new();
    if detect_mixed_charset(body) {
        reasons.push("mixed-charset");
    }
    if body.contains('<') {
        reasons.extend(detect_fake_html(body));
    }
    if reasons.is_empty() {
        (false, String::new())
    } else {
        (true, reasons.join(","))
    }
}

/// Best-effort `body` of a stanza payload ("" when absent or malformed).
pub fn decode_chat_body(payload: Option<&[u8]>) -> String {
    string_member(payload, "body")
}

/// Best-effort `op` of a room stanza payload.
pub fn decode_room_op(payload: Option<&[u8]>) -> String {
    string_member(payload, "op")
}

fn string_member(payload: Option<&[u8]>, name: &str) -> String {
    let mut out = String::new();
    if let Some(Ok(Some(members))) = payload.map(gojson::object_members) {
        for m in members {
            if gojson::key_matches(&m.key, name) {
                if let Ok(Some(s)) = gojson::field_string(m.value) {
                    out = s;
                }
            }
        }
    }
    out
}

fn valid_pair() -> &'static BytesRegex {
    static R: OnceLock<BytesRegex> = OnceLock::new();
    R.get_or_init(|| {
        BytesRegex::new(r"\\uD[89abAB][0-9a-fA-F]\\uD[C-Fc-f][0-9a-fA-F][0-9a-fA-F]").unwrap()
    })
}

fn unsafe_stray() -> &'static BytesRegex {
    static R: OnceLock<BytesRegex> = OnceLock::new();
    R.get_or_init(|| {
        BytesRegex::new(
            r"\\u0000|\\uD[89AB][0-9A-Fa-f]|\\uD[C-F][0-9A-Fa-f][0-9A-Fa-f]|\\ud[89ab][0-9a-fA-F]\\ud[C-Fc-f][0-9a-fA-F][0-9a-fA-F]",
        )
        .unwrap()
    })
}

/// Go's literal `payloadSafeForJSONB` regexes, including their surrogate bug:
/// lowercase lone surrogates slip through; uppercase valid pairs are flagged.
/// A literal NUL or `\u0000` escape is always rejected.
pub fn payload_safe_for_jsonb(payload: &[u8]) -> bool {
    if payload.contains(&0) {
        return false;
    }
    let stripped = valid_pair().replace_all(payload, &b""[..]);
    !unsafe_stray().is_match(&stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_charset_needs_two_scripts_and_five_letters() {
        assert!(detect_mixed_charset("hello мир привет"));
        assert!(!detect_mixed_charset("hello world"));
        assert!(detect_mixed_charset("ab мир")); // exactly five meaningful letters
        assert!(!detect_mixed_charset("a мир"));
    }

    #[test]
    fn fake_html_labels_are_distinct_and_ordered() {
        let l = detect_fake_html("<p style='display: none; font-size:0'>x</p>");
        assert_eq!(
            l,
            vec!["hidden:text:font-size-zero", "hidden:text:display-none"]
        );
        assert!(detect_fake_html("plain <b>text</b>").is_empty());
    }

    #[test]
    fn jsonb_safety_matches_go_regexes() {
        assert!(payload_safe_for_jsonb(br#"{"a":"\ud83d\ude00"}"#));
        assert!(!payload_safe_for_jsonb(br#"{"a":"\u0000"}"#));
        // Frozen Go's malformed regex misses lowercase unpaired surrogates.
        // The session oracle covers the resulting PostgreSQL rejection.
        assert!(payload_safe_for_jsonb(br#"{"a":"\ud800"}"#));
        assert!(!payload_safe_for_jsonb(br#"{"a":"\uD800"}"#));
        assert!(!payload_safe_for_jsonb(b"{\"a\":\"\x00\"}"));
    }
}
