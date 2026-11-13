//! Go's `http.ParseTime`: `time.Parse` over the three HTTP layouts. Only the
//! layout elements those use are implemented, with Go's quirks: a fractional
//! second is accepted after the seconds field, a day or hour may be a single
//! digit where the layout allows it, the weekday is not checked, and a zone
//! abbreviation the process does not know carries a zero offset, so the wall
//! clock is read as UTC whatever the abbreviation says.
use chrono::{NaiveDate, TimeZone, Utc};

/// Seconds and microseconds since the epoch.
pub type Instant = (i64, u32);

const SHORT_DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const LONG_DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `time.lookup`: a case-insensitive ASCII prefix match against the names.
fn lookup<'a>(names: &[&str], v: &'a [u8]) -> Option<(usize, &'a [u8])> {
    names.iter().enumerate().find_map(|(i, name)| {
        let n = name.len();
        (v.len() >= n && v[..n].eq_ignore_ascii_case(name.as_bytes())).then(|| (i, &v[n..]))
    })
}

/// `time.getnum`: one or two digits, exactly two when `fixed`.
fn getnum(v: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    if !v.first()?.is_ascii_digit() {
        return None;
    }
    if !v.get(1).is_some_and(u8::is_ascii_digit) {
        return if fixed {
            None
        } else {
            Some((i64::from(v[0] - b'0'), &v[1..]))
        };
    }
    Some((
        i64::from(v[0] - b'0') * 10 + i64::from(v[1] - b'0'),
        &v[2..],
    ))
}

fn leading_int(v: &[u8]) -> (u64, &[u8]) {
    let n = v.iter().take_while(|c| c.is_ascii_digit()).count();
    let x = v[..n].iter().fold(0u64, |a, c| {
        a.saturating_mul(10).saturating_add(u64::from(c - b'0'))
    });
    (x, &v[n..])
}

fn parse_signed_offset(v: &[u8]) -> usize {
    if v.is_empty() || (v[0] != b'-' && v[0] != b'+') {
        return 0;
    }
    let (x, rem) = leading_int(&v[1..]);
    if rem.len() == v.len() - 1 || x > 23 {
        return 0;
    }
    v.len() - rem.len()
}

/// `time.parseTimeZone`: the length of the zone abbreviation.
fn parse_time_zone(v: &[u8]) -> Option<usize> {
    if v.len() < 3 {
        return None;
    }
    if v.len() >= 4 && (&v[..4] == b"ChST" || &v[..4] == b"MeST") {
        return Some(4);
    }
    if &v[..3] == b"GMT" {
        return Some(if v.len() == 3 {
            3
        } else {
            3 + parse_signed_offset(&v[3..])
        });
    }
    if v[0] == b'+' || v[0] == b'-' {
        let n = parse_signed_offset(v);
        return (n > 0).then_some(n);
    }
    let upper = v
        .iter()
        .take(6)
        .take_while(|c| c.is_ascii_uppercase())
        .count();
    match upper {
        3 => Some(3),
        4 if v[3] == b'T' || &v[..4] == b"WITA" => Some(4),
        5 if v[4] == b'T' => Some(5),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Layout {
    Http,
    Rfc850,
    Ansic,
}

fn parse_with(text: &[u8], layout: Layout) -> Option<Instant> {
    let mut v = text;
    let literal = |v: &mut &[u8], lit: &str| -> Option<()> {
        *v = v.strip_prefix(lit.as_bytes())?;
        Some(())
    };
    let (month, day, year);
    match layout {
        Layout::Http => {
            v = lookup(&SHORT_DAYS, v)?.1;
            literal(&mut v, ", ")?;
            let (d, rest) = getnum(v, true)?;
            day = d;
            v = rest;
            literal(&mut v, " ")?;
            let (m, rest) = lookup(&MONTHS, v)?;
            month = m as i64 + 1;
            v = rest;
            literal(&mut v, " ")?;
            if v.len() < 4 || !v[..4].iter().all(u8::is_ascii_digit) {
                return None;
            }
            year = std::str::from_utf8(&v[..4]).ok()?.parse::<i64>().ok()?;
            v = &v[4..];
            literal(&mut v, " ")?;
        }
        Layout::Rfc850 => {
            v = lookup(&LONG_DAYS, v)?.1;
            literal(&mut v, ", ")?;
            let (d, rest) = getnum(v, true)?;
            day = d;
            v = rest;
            literal(&mut v, "-")?;
            let (m, rest) = lookup(&MONTHS, v)?;
            month = m as i64 + 1;
            v = rest;
            literal(&mut v, "-")?;
            if v.len() < 2 || !v[..2].iter().all(u8::is_ascii_digit) {
                return None;
            }
            let yy = i64::from(v[0] - b'0') * 10 + i64::from(v[1] - b'0');
            year = if yy >= 69 { yy + 1900 } else { yy + 2000 };
            v = &v[2..];
            literal(&mut v, " ")?;
        }
        Layout::Ansic => {
            v = lookup(&SHORT_DAYS, v)?.1;
            literal(&mut v, " ")?;
            let (m, rest) = lookup(&MONTHS, v)?;
            month = m as i64 + 1;
            v = rest;
            literal(&mut v, " ")?;
            if v.first() == Some(&b' ') {
                v = &v[1..];
            }
            let (d, rest) = getnum(v, false)?;
            day = d;
            v = rest;
            literal(&mut v, " ")?;
            year = 0; // the year follows the time in this layout
        }
    }
    let (hour, rest) = getnum(v, false)?;
    v = rest;
    literal(&mut v, ":")?;
    let (minute, rest) = getnum(v, true)?;
    v = rest;
    literal(&mut v, ":")?;
    let (second, rest) = getnum(v, true)?;
    v = rest;
    let mut micros = 0u32;
    if v.len() >= 2 && (v[0] == b'.' || v[0] == b',') && v[1].is_ascii_digit() {
        let n = 1 + v[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        let digits = &v[1..n.min(10)];
        let mut nanos = 0u32;
        for (i, d) in digits.iter().enumerate() {
            nanos += u32::from(d - b'0') * 10u32.pow(8 - i as u32);
        }
        micros = nanos / 1000;
        v = &v[n..];
    }
    match layout {
        Layout::Http => literal(&mut v, " GMT")?,
        Layout::Rfc850 => {
            literal(&mut v, " ")?;
            if v.starts_with(b"UTC") {
                v = &v[3..];
            } else {
                v = &v[parse_time_zone(v)?..];
            }
        }
        Layout::Ansic => {
            literal(&mut v, " ")?;
            if v.len() < 4 || !v[..4].iter().all(u8::is_ascii_digit) {
                return None;
            }
            // The year of the ANSIC layout comes last.
            return finish(
                std::str::from_utf8(&v[..4]).ok()?.parse().ok()?,
                month,
                day,
                hour,
                minute,
                second,
                micros,
                &v[4..],
            );
        }
    }
    finish(year, month, day, hour, minute, second, micros, v)
}

#[allow(clippy::too_many_arguments)]
fn finish(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    micros: u32,
    rest: &[u8],
) -> Option<Instant> {
    if hour >= 24 || minute >= 60 || second >= 60 || !rest.is_empty() {
        return None;
    }
    // Go checks the day against the month's length.
    let date = NaiveDate::from_ymd_opt(year as i32, month as u32, u32::try_from(day).ok()?)?;
    let at = date.and_hms_opt(hour as u32, minute as u32, second as u32)?;
    Some((Utc.from_utc_datetime(&at).timestamp(), micros))
}

/// `http.ParseTime`.
pub fn parse_http_time(text: &[u8]) -> Option<Instant> {
    [Layout::Http, Layout::Rfc850, Layout::Ansic]
        .into_iter()
        .find_map(|layout| parse_with(text, layout))
}
