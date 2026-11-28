//! Go's `time.Parse(time.RFC3339, value)`, with Go's exact error text.
//!
//! Go tries a fast path and, when it declines, walks the layout
//! `2006-01-02T15:04:05Z07:00` element by element. Both accept the same inputs;
//! the walk is what words the error, so it is reproduced here: a malformed
//! element reports `cannot parse "<rest>" as "<element>"`, an out-of-range one
//! `: <field> out of range`, and trailing text `: extra text: "<rest>"`.
use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
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

const LAYOUT: &str = "2006-01-02T15:04:05Z07:00";

fn failure(value: &str, element: &str, rest: &str) -> String {
    format!(
        "parsing time {} as {}: cannot parse {} as {}",
        quote(value),
        quote(LAYOUT),
        quote(rest),
        quote(element)
    )
}

fn digit(s: &[u8], i: usize) -> bool {
    s.get(i).is_some_and(u8::is_ascii_digit)
}

/// Go's `getnum`: one or two digits (two when `fixed`).
fn number(s: &str, fixed: bool) -> Option<(i64, &str)> {
    let b = s.as_bytes();
    if !digit(b, 0) {
        return None;
    }
    if !digit(b, 1) {
        return if fixed {
            None
        } else {
            Some((i64::from(b[0] - b'0'), &s[1..]))
        };
    }
    Some((
        i64::from(b[0] - b'0') * 10 + i64::from(b[1] - b'0'),
        &s[2..],
    ))
}

pub fn parse_rfc3339(value: &str) -> Result<DateTime<FixedOffset>, String> {
    let range = |field: &str| format!("parsing time {}: {field} out of range", quote(value));
    let mut rest = value;
    // 2006
    let b = rest.as_bytes();
    if rest.len() < 4 || !digit(b, 0) || !(1..4).all(|i| digit(b, i)) {
        return Err(failure(value, "2006", rest));
    }
    let year: i32 = rest[..4]
        .parse()
        .map_err(|_| failure(value, "2006", rest))?;
    rest = &rest[4..];
    let take = |prefix: char, element: &str, fixed: bool, rest: &mut &str| {
        let current = *rest;
        let after = match current.strip_prefix(prefix) {
            Some(after) => after,
            None => return Err(failure(value, &prefix.to_string(), current)),
        };
        match number(after, fixed) {
            Some((n, tail)) => {
                *rest = tail;
                Ok(n)
            }
            None => Err(failure(value, element, after)),
        }
    };
    let month = take('-', "01", true, &mut rest)?;
    if !(1..=12).contains(&month) {
        return Err(range("month"));
    }
    let day = take('-', "02", true, &mut rest)?;
    let hour = take('T', "15", false, &mut rest)?;
    if hour >= 24 {
        return Err(range("hour"));
    }
    let minute = take(':', "04", true, &mut rest)?;
    if minute >= 60 {
        return Err(range("minute"));
    }
    let second = take(':', "05", true, &mut rest)?;
    if second >= 60 {
        return Err(range("second"));
    }
    let mut nanos: i64 = 0;
    let b = rest.as_bytes();
    if rest.len() >= 2 && matches!(b[0], b'.' | b',') && digit(b, 1) {
        let mut n = 2;
        while digit(b, n) {
            n += 1;
        }
        let digits = &rest[1..n.min(10)];
        nanos = digits.parse::<i64>().unwrap_or(0) * 10_i64.pow((9 - digits.len()) as u32);
        rest = &rest[n..];
    }
    // Z07:00
    let offset = if let Some(after) = rest.strip_prefix('Z') {
        rest = after;
        0
    } else {
        let b = rest.as_bytes();
        if rest.len() < 6 || b[3] != b':' {
            return Err(failure(value, "Z07:00", rest));
        }
        let (sign, hh, mm) = (b[0], &rest[1..3], &rest[4..6]);
        let (hr, mi) = match (number(hh, true), number(mm, true)) {
            (Some((h, _)), Some((m, _))) => (h, m),
            _ => return Err(failure(value, "Z07:00", rest)),
        };
        if hr > 24 {
            return Err(range("time zone offset hour"));
        }
        if mi > 60 {
            return Err(range("time zone offset minute"));
        }
        let seconds = (hr * 60 + mi) * 60;
        rest = &rest[6..];
        match sign {
            b'+' => seconds,
            b'-' => -seconds,
            _ => {
                return Err(failure(
                    value,
                    "Z07:00",
                    &value[value.len() - rest.len() - 6..],
                ))
            }
        }
    };
    if !rest.is_empty() {
        return Err(format!(
            "parsing time {}: extra text: {}",
            quote(value),
            quote(rest)
        ));
    }
    let days = NaiveDate::from_ymd_opt(year, month as u32, 1)
        .and_then(|d| d.checked_add_months(chrono::Months::new(1)))
        .map(|next| {
            use chrono::Datelike;
            next.pred_opt().map_or(0, |last| last.day() as i64)
        })
        .unwrap_or(0);
    if day < 1 || day > days {
        return Err(format!("parsing time {}: day out of range", quote(value)));
    }
    let naive = NaiveDate::from_ymd_opt(year, month as u32, day as u32)
        .and_then(|d| d.and_hms_nano_opt(hour as u32, minute as u32, second as u32, nanos as u32))
        .ok_or_else(|| failure(value, "2006", value))?;
    let zone =
        FixedOffset::east_opt(offset as i32).ok_or_else(|| failure(value, "Z07:00", rest))?;
    zone.from_local_datetime(&naive)
        .single()
        .ok_or_else(|| failure(value, "2006", value))
}

/// Go's `time.Time.MarshalJSON` (RFC 3339 with trimmed fractional seconds).
pub fn format_rfc3339_nano(time: &DateTime<FixedOffset>) -> String {
    use chrono::Timelike;
    let mut out = time.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = time.nanosecond();
    if nanos != 0 {
        let mut fraction = format!("{nanos:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        out.push('.');
        out.push_str(&fraction);
    }
    let seconds = time.offset().local_minus_utc();
    if seconds == 0 {
        out.push('Z');
    } else {
        let (sign, abs) = if seconds < 0 {
            ('-', -seconds)
        } else {
            ('+', seconds)
        };
        out.push_str(&format!("{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_error_text_for_the_common_failures() {
        assert_eq!(
            parse_rfc3339("not-a-date").unwrap_err(),
            "parsing time \"not-a-date\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"not-a-date\" as \"2006\""
        );
        assert_eq!(
            parse_rfc3339("2026-13-01T00:00:00Z").unwrap_err(),
            "parsing time \"2026-13-01T00:00:00Z\": month out of range"
        );
        assert_eq!(
            parse_rfc3339("2026-02-30T00:00:00Z").unwrap_err(),
            "parsing time \"2026-02-30T00:00:00Z\": day out of range"
        );
        assert_eq!(
            parse_rfc3339("2026-02-03T00:00:00Zjunk").unwrap_err(),
            "parsing time \"2026-02-03T00:00:00Zjunk\": extra text: \"junk\""
        );
        assert_eq!(
            parse_rfc3339("2026-02-03T00:00:00").unwrap_err(),
            "parsing time \"2026-02-03T00:00:00\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\" as \"Z07:00\""
        );
    }

    #[test]
    fn accepted_forms_marshal_like_go() {
        let t = parse_rfc3339("2026-02-03T04:05:06.5+00:00").unwrap();
        assert_eq!(format_rfc3339_nano(&t), "2026-02-03T04:05:06.5Z");
        let t = parse_rfc3339("2026-02-03T04:05:06+02:30").unwrap();
        assert_eq!(format_rfc3339_nano(&t), "2026-02-03T04:05:06+02:30");
    }
}
