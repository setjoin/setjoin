//! LDAP sync runtime (#380): wire client, filter admission, engines and worker.
pub mod admin;
pub mod client;
pub mod engine;
pub mod filter;
pub mod normalized;
pub mod runtime;
pub use client::*;
pub use engine::{PreviewRow, SyncResult, Worker};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn log_warn(message: &str) {
    eprintln!("setjoin-gateway: ldap-sync: {message}");
}

/// Go `identity.CanonicalizeAddress`: ASCII fold, trim, and the single
/// RFC 5322 address when one parses (display names stripped).
pub fn canonical_address(raw: &str) -> String {
    let folded = raw.trim().to_ascii_lowercase();
    match mailparse::addrparse(&folded) {
        Ok(list) if list.len() == 1 => match &list[0] {
            mailparse::MailAddr::Single(a) if !a.addr.is_empty() => a.addr.clone(),
            _ => folded,
        },
        _ => folded,
    }
}

/// Go `Duration.String()`.
pub fn go_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns == 0 {
        return "0s".into();
    }
    let frac = |value: u128, unit: u128, digits: usize| -> String {
        let whole = value / unit;
        let rest = value % unit;
        if rest == 0 {
            return whole.to_string();
        }
        let text = format!("{rest:0digits$}");
        format!("{whole}.{}", text.trim_end_matches('0'))
    };
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000 {
        return format!("{}µs", frac(ns, 1_000, 3));
    }
    if ns < 1_000_000_000 {
        return format!("{}ms", frac(ns, 1_000_000, 6));
    }
    let seconds_part = ns % 60_000_000_000;
    let total_minutes = ns / 60_000_000_000;
    let secs = format!("{}s", frac(seconds_part, 1_000_000_000, 9));
    if total_minutes == 0 {
        return secs;
    }
    let (hours, minutes) = (total_minutes / 60, total_minutes % 60);
    if hours == 0 {
        format!("{minutes}m{secs}")
    } else {
        format!("{hours}h{minutes}m{secs}")
    }
}

/// Go `fmt.Sprintf("%q", s)` for the ASCII/UTF-8 text this engine quotes.
pub fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go `json.Marshal` of a string/value: compact, HTML-escaped.
pub fn go_json_string(s: &str) -> String {
    crate::go_escape(&serde_json::to_string(s).expect("string"))
}
pub fn go_json(v: &serde_json::Value) -> String {
    crate::go_escape(&serde_json::to_string(v).expect("value"))
}

/// `time.Now().UTC().Format(time.RFC3339)`.
pub fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `time.Parse(time.RFC3339, raw)` as an instant (fractions and offsets allowed).
pub fn parse_rfc3339(raw: &str) -> Option<SystemTime> {
    let b = raw.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = b.get(from..from + len)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0i64, |n, d| n * 10 + i64::from(d - b'0')))
    };
    if b.len() < 20
        || [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]
            .iter()
            .any(|(i, c)| b[*i] != *c)
    {
        return None;
    }
    let (y, mo, d, h, mi, s) = (
        num(0, 4)?,
        num(5, 2)?,
        num(8, 2)?,
        num(11, 2)?,
        num(14, 2)?,
        num(17, 2)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let mut at = 19;
    if b[at] == b'.' {
        at += 1;
        let start = at;
        while at < b.len() && b[at].is_ascii_digit() {
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    let offset = match b.get(at)? {
        b'Z' if at + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if at + 6 == b.len() && b[at + 3] == b':' => {
            let secs = num(at + 1, 2)? * 3600 + num(at + 4, 2)? * 60;
            if *sign == b'+' {
                secs
            } else {
                -secs
            }
        }
        _ => return None,
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset;
    if secs < 0 {
        return Some(UNIX_EPOCH);
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// A random RFC 4122 version-4 UUID text (worker instance and batch ids).
pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("system randomness");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_match_go() {
        assert_eq!(go_duration(Duration::from_nanos(1_500)), "1.5µs");
        assert_eq!(go_duration(Duration::from_micros(12_345)), "12.345ms");
        assert_eq!(go_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(go_duration(Duration::from_secs(62)), "1m2s");
        assert_eq!(go_duration(Duration::from_secs(3723)), "1h2m3s");
        assert_eq!(go_duration(Duration::ZERO), "0s");
    }

    #[test]
    fn rfc3339_round_trips() {
        let now = rfc3339_now();
        assert!(parse_rfc3339(&now).is_some(), "{now}");
        assert_eq!(
            parse_rfc3339("1970-01-02T00:00:00Z"),
            Some(UNIX_EPOCH + Duration::from_secs(86_400))
        );
        assert!(parse_rfc3339("garbage").is_none());
    }

    #[test]
    fn canonical_strips_display_names_and_folds() {
        assert_eq!(
            canonical_address("  Ann <ANN@Example.Test> "),
            "ann@example.test"
        );
        assert_eq!(canonical_address("Bare@Corp"), "bare@corp");
    }

    #[test]
    fn quoting_matches_go() {
        assert_eq!(go_quote("20260101000000Z"), "\"20260101000000Z\"");
        assert_eq!(go_quote("a\"b\\"), "\"a\\\"b\\\\\"");
    }
}
