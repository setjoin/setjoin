//! Go's `jwt.NumericDate` (golang-jwt/jwt/v5 v5.3.1) as Go 1.26 computes it on
//! linux/amd64, bit for bit (#354). Shared by every first-party token path,
//! including the push verifier (#356a).
//!
//! Go source mirrored:
//! - `jwt/v5@v5.3.1/types.go:80-98` `UnmarshalJSON`: `json.Unmarshal(b, &json.Number)`,
//!   then `number.Float64()` (= `strconv.ParseFloat(s, 64)`, correctly rounded; `ErrRange`
//!   on overflow fails the token, underflow yields 0 without error).
//! - `encoding/json/decode.go:957-961` a JSON string is accepted into `json.Number` only if
//!   its unquoted content passes `isValidNumber` (`encode.go:636`); bool/object/array
//!   fail. A JSON `null` leaves the `*NumericDate` nil (UnmarshalJSON is not called).
//! - `types.go:44-47` `newNumericDateFromSeconds`: `round, frac := math.Modf(f)`
//!   (Go 1.26 `math/modf.go`: `Trunc(f)`, `Copysign(f-int, f)`), then
//!   `time.Unix(int64(round), int64(frac*1e9))` and `Truncate(TimePrecision=1s)`.
//! - `int64(float64)` is implementation-defined out of range; Go on amd64 emits
//!   `CVTTSD2SQ`, which yields `i64::MIN` for any value outside [-2^63, 2^63) (checked
//!   with the Go 1.26.6 linux/amd64 toolchain: 1e19, -1e19 and 2^63 all give MIN).
//! - `time/time.go:1655` `Unix` normalises nsec into [0,1e9); `unixTime` stores
//!   `sec + unixToInternal` (wrapping int64); `Truncate(1s)` then only zeroes nsec.
//! - `jwt/v5@v5.3.1/validator.go:175-235` compares `now.Before(exp)` and
//!   `!now.Before(nbf)` with zero leeway on those wrapped internal seconds, so an
//!   `exp` near `i64::MAX` wraps negative and is already expired.

/// `time.unixToInternal`: seconds from year 1 to 1970.
pub const UNIX_TO_INTERNAL: i64 = 62_135_596_800;
const NANOS: i64 = 1_000_000_000;

/// Go's `int64(f)` on amd64 (`CVTTSD2SQ`): truncation, `i64::MIN` when out of range or NaN.
pub fn go_int64(f: f64) -> i64 {
    if f.is_nan() || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&f) {
        i64::MIN
    } else {
        f as i64
    }
}

/// `newNumericDateFromSeconds(f).Unix()` (Truncate to 1 s included). `f` is finite.
pub fn from_seconds(f: f64) -> i64 {
    let round = f.trunc();
    let frac = (f - round).copysign(f);
    let (mut sec, mut nsec) = (go_int64(round), go_int64(frac * 1e9));
    if !(0..NANOS).contains(&nsec) {
        let n = nsec / NANOS;
        sec = sec.wrapping_add(n);
        nsec -= n * NANOS;
        if nsec < 0 {
            sec = sec.wrapping_sub(1);
        }
    }
    // Truncate(1s) keeps the internal seconds and zeroes nsec; Unix() undoes the
    // wrapping `+ unixToInternal`, so it returns `sec` unchanged.
    sec
}

/// `encoding/json.isValidNumber` (`encode.go:636`): the JSON number grammar.
pub fn is_valid_json_number(s: &str) -> bool {
    let mut s = s.as_bytes();
    if s.first() == Some(&b'-') {
        s = &s[1..];
    }
    fn digits(s: &[u8]) -> &[u8] {
        &s[s.iter().take_while(|c| c.is_ascii_digit()).count()..]
    }
    match s.first() {
        Some(b'0') => s = &s[1..],
        Some(b'1'..=b'9') => {
            s = &s[1..];
            s = digits(s);
        }
        _ => return false,
    }
    if s.len() >= 2 && s[0] == b'.' && s[1].is_ascii_digit() {
        s = &s[2..];
        s = digits(s);
    }
    if s.len() >= 2 && (s[0] == b'e' || s[0] == b'E') {
        s = &s[1..];
        if s[0] == b'+' || s[0] == b'-' {
            s = &s[1..];
            if s.is_empty() {
                return false;
            }
        }
        s = digits(s);
    }
    s.is_empty()
}

/// One claim value as the `*NumericDate` field decodes it: `Some(None)` for JSON `null`
/// (nil pointer), `Some(Some(unix_seconds))` as `NumericDate.Unix()`, `None` where Go's
/// decode fails the whole token. `raw` is the complete JSON value text.
pub fn from_json(raw: &[u8]) -> Option<Option<i64>> {
    let raw = trim_ws(raw);
    let text = match raw.first() {
        Some(b'"') => serde_json::from_slice::<String>(raw).ok()?,
        Some(b'-' | b'0'..=b'9') => std::str::from_utf8(raw).ok()?.to_owned(),
        _ if raw == b"null" => return Some(None),
        _ => return None,
    };
    if !is_valid_json_number(&text) {
        return None;
    }
    // Rust's f64 parsing is correctly rounded like strconv.ParseFloat; ±Inf is ErrRange.
    let f: f64 = text.parse().ok()?;
    if f.is_infinite() {
        return None;
    }
    Some(Some(from_seconds(f)))
}

fn internal(unix: i64) -> i64 {
    unix.wrapping_add(UNIX_TO_INTERNAL)
}
fn now_internal(now_unix: f64) -> i64 {
    internal(go_int64(now_unix.floor()))
}

/// `!now.Before(exp)` (`verifyExpiresAt`, zero leeway): the token is expired.
pub fn expired(now_unix: f64, exp: i64) -> bool {
    now_internal(now_unix) >= internal(exp)
}

/// `now.Before(nbf)` (`verifyNotBefore`, zero leeway): the token is not valid yet.
pub fn not_yet_valid(now_unix: f64, nbf: i64) -> bool {
    now_internal(now_unix) < internal(nbf)
}

/// A date claim already in a claims map: an integer is the decoded value; any other
/// JSON number goes through [`from_seconds`] (for callers that did not normalise).
pub fn claim_seconds(v: &serde_json::Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(from_seconds))
}

/// `encoding/json` (decode.go:699-701, Go 1.26) field lookup for one object key against a
/// struct field named `name`: `byExactName`, else `byFoldedName[foldName(key)]`. Every
/// key that either finds selects the field, so the per-key exact-first rule never makes
/// one spelling win over another: each matching member is decoded in input order and the
/// last one wins. `foldName` maps a non-ASCII rune to the smallest rune of its
/// `unicode.SimpleFold` orbit; no orbit of e/x/p/n/b/f/i/a/t holds a non-ASCII rune
/// (checked with Go 1.26.6), so for these names folding is ASCII case-insensitivity.
fn go_json_field_matches(key: &str, name: &str) -> bool {
    key.eq_ignore_ascii_case(name)
}

/// Rewrites `exp`/`nbf`/`iat` in `claims` to what Go decodes from the signed payload of
/// `token`: whole Unix seconds, or `null` for a nil date. Every member whose key Go maps
/// to the field (case-folded, [`go_json_field_matches`]) is decoded in order (Go fails on
/// the first bad one; the last one wins), from the raw JSON text so number parsing is
/// exact. `None` = Go rejects the token.
pub fn normalize_token_claims(
    token: &str,
    claims: &mut serde_json::Map<String, serde_json::Value>,
) -> Option<()> {
    let payload = crate::legacy_jwt::decode_segment(token.split('.').nth(1)?)?;
    let entries = top_level_entries(&payload)?;
    for key in ["exp", "nbf", "iat"] {
        let mut last = None;
        for (name, raw) in &entries {
            if go_json_field_matches(name, key) {
                last = Some(from_json(raw)?);
            }
        }
        if let Some(date) = last {
            // Go decodes every folded spelling into the one field: keep only the canonical key.
            claims.retain(|name, _| name == key || !go_json_field_matches(name, key));
            claims.insert(
                key.into(),
                date.map_or(serde_json::Value::Null, serde_json::Value::from),
            );
        }
    }
    Some(())
}

fn trim_ws(mut b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r');
    while b.first().is_some_and(ws) {
        b = &b[1..];
    }
    while b.last().is_some_and(ws) {
        b = &b[..b.len() - 1];
    }
    b
}

/// Key and raw value text of each member of a JSON object, in order, duplicates kept.
/// `None` for anything that is not a well-formed top-level object.
fn top_level_entries(b: &[u8]) -> Option<Vec<(String, &[u8])>> {
    fn ws(b: &[u8], mut i: usize) -> usize {
        while b
            .get(i)
            .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
        {
            i += 1;
        }
        i
    }
    fn string_end(b: &[u8], i: usize) -> Option<usize> {
        if b.get(i) != Some(&b'"') {
            return None;
        }
        let mut j = i + 1;
        loop {
            match b.get(j)? {
                b'\\' => j += 2,
                b'"' => return Some(j + 1),
                _ => j += 1,
            }
        }
    }
    fn value_end(b: &[u8], i: usize) -> Option<usize> {
        match b.get(i)? {
            b'"' => string_end(b, i),
            b'{' | b'[' => {
                let (mut depth, mut j) = (0usize, i);
                loop {
                    match b.get(j)? {
                        b'"' => j = string_end(b, j)?,
                        b'{' | b'[' => {
                            depth += 1;
                            j += 1;
                        }
                        b'}' | b']' => {
                            depth -= 1;
                            j += 1;
                            if depth == 0 {
                                return Some(j);
                            }
                        }
                        _ => j += 1,
                    }
                }
            }
            _ => {
                let mut j = i;
                while b.get(j).is_some_and(|c| {
                    !matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                }) {
                    j += 1;
                }
                (j > i).then_some(j)
            }
        }
    }
    let mut i = ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i = ws(b, i + 1);
    let mut out = Vec::new();
    if b.get(i) == Some(&b'}') {
        return Some(out);
    }
    loop {
        let start = i;
        i = string_end(b, i)?;
        let key: String = serde_json::from_slice(&b[start..i]).ok()?;
        i = ws(b, i);
        if b.get(i) != Some(&b':') {
            return None;
        }
        i = ws(b, i + 1);
        let start = i;
        i = value_end(b, i)?;
        out.push((key, &b[start..i]));
        i = ws(b, i);
        match b.get(i)? {
            b',' => i = ws(b, i + 1),
            b'}' => return Some(out),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values were produced by Go 1.26.6 linux/amd64 running
    /// `jwt.NumericDate.UnmarshalJSON` (v5.3.1) on each literal, then `.Unix()`,
    /// `!now.Before(d.Time)` and `now.Before(d.Time)` with `now = time.Unix(1800000000, 0)`.
    /// `None` = Go returned an error.
    const GO: &[(&str, Option<(i64, bool, bool)>)] = &[
        ("1800000900", Some((1800000900, false, true))),
        ("1800000900.5", Some((1800000900, false, true))),
        ("1800000000.9", Some((1800000000, true, false))),
        ("1799999999.9999999", Some((1800000000, true, false))),
        ("-1e-10", Some((0, true, false))),
        ("-0.5", Some((-1, true, false))),
        ("-1.5", Some((-2, true, false))),
        ("-0", Some((0, true, false))),
        ("0.9999999999999999", Some((0, true, false))),
        ("-0.9999999999999999", Some((-1, true, false))),
        ("9.21e18", Some((9210000000000000000, false, true))),
        (
            "9.2233720368547e18",
            Some((9223372036854700032, true, false)),
        ),
        ("9223372036854775807", Some((i64::MIN, true, false))),
        ("9.223372036854775807e18", Some((i64::MIN, true, false))),
        ("1e19", Some((i64::MIN, true, false))),
        ("-1e19", Some((i64::MIN, true, false))),
        ("-9.2233720368547758e18", Some((i64::MIN, true, false))),
        ("1e400", None),
        ("1e-400", Some((0, true, false))),
        ("\"1800000900\"", Some((1800000900, false, true))),
        ("\"1800000900.5\"", Some((1800000900, false, true))),
        ("\"-1\"", Some((-1, true, false))),
        ("\"1e3\"", Some((1000, true, false))),
        ("\"1E+3\"", Some((1000, true, false))),
        ("\"\"", None),
        ("\"abc\"", None),
        ("\" 1\"", None),
        ("\"1 \"", None),
        ("\"01\"", None),
        ("\"1.\"", None),
        ("\".5\"", None),
        ("\"+1\"", None),
        ("\"0x10\"", None),
        ("\"Infinity\"", None),
        ("\"NaN\"", None),
        ("\"1e400\"", None),
        ("true", None),
        ("{}", None),
        ("[]", None),
        ("1800000000.0000001", Some((1800000000, true, false))),
        ("1.8e9", Some((1800000000, true, false))),
        ("18000000005e-1", Some((1800000000, true, false))),
        ("9.2233720305e18", Some((9223372030499999744, true, false))),
        ("9223372036854775296", Some((i64::MIN, true, false))),
        ("-9223372036854775808", Some((i64::MIN, true, false))),
        (
            "9223309901258178000",
            Some((9223309901258177536, false, true)),
        ),
        (
            "9223309901258179000",
            Some((9223309901258178560, false, true)),
        ),
    ];

    #[test]
    fn matches_go_numeric_date_bit_for_bit() {
        const NOW: f64 = 1_800_000_000.0;
        for (raw, want) in GO {
            let got = from_json(raw.as_bytes()).map(|d| {
                let d = d.expect("not null");
                (d, expired(NOW, d), not_yet_valid(NOW, d))
            });
            assert_eq!(got, *want, "{raw}");
        }
        // A nil pointer, not a date: Go's decoder never calls UnmarshalJSON for null.
        assert_eq!(from_json(b"null"), Some(None));
        // A JSON escape inside the string is decoded before isValidNumber, as in Go.
        assert_eq!(from_json(b"\"\\u00318\""), Some(Some(18)));
    }

    #[test]
    fn duplicate_keys_decode_in_order_like_go() {
        // Go: {"exp":"x","exp":5} fails; {"exp":5,"exp":null} is nil;
        // {"exp":5,"exp":"7.5"} is 7 (json.Unmarshal into jwt.RegisteredClaims).
        let normalized = |payload: &str| {
            use base64::Engine;
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
            let mut claims = serde_json::from_str::<serde_json::Value>(payload)
                .unwrap()
                .as_object()
                .cloned()
                .unwrap();
            normalize_token_claims(&format!("h.{body}.s"), &mut claims)
                .map(|_| claims.get("exp").cloned())
        };
        assert_eq!(normalized(r#"{"exp":"x","exp":5}"#), None);
        assert_eq!(
            normalized(r#"{"exp":5,"exp":null}"#),
            Some(Some(serde_json::Value::Null))
        );
        assert_eq!(
            normalized(r#"{"exp":5,"exp":"7.5"}"#),
            Some(Some(serde_json::json!(7)))
        );
        assert_eq!(
            normalized(r#"{"a":{"exp":"x"},"b":["}"],"exp":"12"}"#),
            Some(Some(serde_json::json!(12)))
        );
        assert_eq!(normalized(r#"{"sub":"x"}"#), Some(None));
    }

    #[test]
    fn claim_keys_fold_case_like_go_encoding_json() {
        // Go 1.26.6 json.Unmarshal into a struct with `json:"exp"`: {"EXP":5} -> 5;
        // {"Exp":5,"exp":7} -> 7; {"exp":7,"EXP":5} -> 5; {"eXp":"x","exp":7} fails
        // (NumericDate.UnmarshalJSON error aborts the decode).
        let normalized = |payload: &str, key: &str| {
            use base64::Engine;
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
            let mut claims = serde_json::from_str::<serde_json::Value>(payload)
                .unwrap()
                .as_object()
                .cloned()
                .unwrap();
            normalize_token_claims(&format!("h.{body}.s"), &mut claims)
                .map(|_| claims.get(key).cloned())
        };
        let n = |v: i64| Some(Some(serde_json::json!(v)));
        assert_eq!(normalized(r#"{"EXP":5}"#, "exp"), n(5));
        assert_eq!(normalized(r#"{"Exp":5,"exp":7}"#, "exp"), n(7));
        assert_eq!(normalized(r#"{"exp":7,"EXP":5}"#, "exp"), n(5));
        assert_eq!(normalized(r#"{"eXp":"x","exp":7}"#, "exp"), None);
        assert_eq!(normalized(r#"{"NBF":"3","IaT":4.5}"#, "nbf"), n(3));
        assert_eq!(normalized(r#"{"NBF":"3","IaT":4.5}"#, "iat"), n(4));
        assert_eq!(normalized(r#"{"exp":7,"EXP":5}"#, "EXP"), Some(None));
        assert_eq!(normalized(r#"{"\u0045xp":6}"#, "exp"), n(6));
        assert_eq!(
            normalized(r#"{"expx":"bad","ex":"bad"}"#, "exp"),
            Some(None)
        );
    }
}
