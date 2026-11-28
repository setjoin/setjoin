//! Go's `internal/received`: the `Received:` chain of an RFC 822 header block as a delivery
//! trace. Input is untrusted, so this is a port of exactly what `net/textproto`'s
//! `ReadMIMEHeader`, `net/mail`'s `ParseDate` (RFC 5322 layouts, `time.Parse` quirks) and the
//! five RE2 patterns do, not a general parser. `Local` is read as UTC (the frozen
//! deployment's zone): a zone abbreviation the process does not know leaves the wall clock
//! as UTC, a numeric zone shifts it.
use regex::bytes::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

pub const MAX_HOPS: usize = 100;
pub const MAX_HEADER_BYTES: usize = 1 << 20;
const MAX_LINE_LEN: usize = 4096;

/// The names that count as "our infrastructure" (lower case).
#[derive(Clone, Default, Debug)]
pub struct Identity(pub HashSet<String>);

impl Identity {
    /// Go's `serverIdentityHostnames`: `mailserver`, the host name and each internal domain.
    pub fn from_config(hostname: &str, internal_domains: &str) -> Identity {
        let mut set = HashSet::from(["mailserver".to_owned()]);
        let clean = |s: &str| go_trim_space(s.as_bytes()).to_lowercase();
        for name in std::iter::once(hostname).chain(internal_domains.split(',')) {
            let name = clean(name);
            if !name.is_empty() {
                set.insert(name);
            }
        }
        Identity(set)
    }
    fn matches(&self, host: &str) -> bool {
        !host.is_empty() && self.0.contains(&host.to_lowercase())
    }
}

// ---- strings / unicode helpers ----

fn is_go_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// `strings.TrimSpace` over bytes: invalid UTF-8 bytes are never space and are kept.
fn go_trim_space(bytes: &[u8]) -> String {
    String::from_utf8_lossy(trim_space_bytes(bytes)).into_owned()
}
fn trim_space_bytes(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < bytes.len() {
        let width = utf8_width(&bytes[start..]);
        match std::str::from_utf8(&bytes[start..start + width])
            .ok()
            .and_then(|s| s.chars().next())
        {
            Some(c) if is_go_space(c) => start += width,
            _ => break,
        }
    }
    let mut end = bytes.len();
    while end > start {
        let mut at = end - 1;
        while at > start && end - at < 4 && (bytes[at] & 0xc0) == 0x80 {
            at -= 1;
        }
        match std::str::from_utf8(&bytes[at..end])
            .ok()
            .and_then(|s| s.chars().next())
        {
            Some(c) if is_go_space(c) => end = at,
            _ => break,
        }
    }
    &bytes[start..end]
}
/// Width of the first rune (1 for an invalid byte), as `utf8.DecodeRune`.
fn utf8_width(bytes: &[u8]) -> usize {
    for n in 1..=bytes.len().min(4) {
        if std::str::from_utf8(&bytes[..n]).is_ok() {
            return n;
        }
    }
    1
}

// ---- net/textproto ReadMIMEHeader ----

fn valid_field_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}
fn valid_value_byte(c: u8) -> bool {
    c == b'\t' || (0x20..0x7f).contains(&c) || c >= 0x80
}
fn trim_ws(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// The values of every `Received` key, in order, as `ReadMIMEHeader` stores them. A reader
/// error keeps what was read before it; with nothing read the trace is empty either way.
fn received_values(raw: &[u8]) -> Vec<Vec<u8>> {
    let raw = &raw[..raw.len().min(MAX_HEADER_BYTES)];
    if matches!(raw.first(), Some(b' ' | b'\t')) {
        return vec![];
    }
    // `bufio.Reader.ReadLine`: split on LF, drop one CR before it; a final unterminated
    // line counts, an empty tail is EOF.
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|b| *b == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        lines.push(line.strip_suffix(b"\r").unwrap_or(line));
        rest = next;
    }
    let mut out: Vec<Vec<u8>> = vec![];
    let mut i = 0;
    while i < lines.len() {
        let first = lines[i];
        i += 1;
        if first.is_empty() || !first.contains(&b':') {
            break;
        }
        let mut kv = trim_ws(first).to_vec();
        // Continuation lines: leading space or tab on the next line.
        while i < lines.len() && matches!(lines[i].first(), Some(b' ' | b'\t')) {
            kv.push(b' ');
            kv.extend_from_slice(trim_ws(lines[i]));
            i += 1;
        }
        // Go's loop also continues when the next line is whitespace only.
        let Some(colon) = kv.iter().position(|b| *b == b':') else {
            break;
        };
        let (key, value) = (&kv[..colon], &kv[colon + 1..]);
        if key.is_empty() || !key.iter().all(|c| valid_field_byte(*c) || *c == b' ') {
            break;
        }
        if !value.iter().all(|c| valid_value_byte(*c)) {
            break;
        }
        let canonical = !key.contains(&b' ') && key.eq_ignore_ascii_case(b"received");
        let start = value
            .iter()
            .position(|b| *b != b' ' && *b != b'\t')
            .unwrap_or(value.len());
        if canonical {
            out.push(value[start..].to_vec());
        }
    }
    out
}

// ---- net/mail ParseDate over time.Parse ----

#[derive(Clone, Copy, PartialEq)]
enum Zone {
    Num,
    Abbr,
    Ut,
}
#[derive(Clone, Copy)]
struct Layout {
    dow: bool,
    zero_day: bool,
    long_year: bool,
    seconds: bool,
    zone: Zone,
}
fn layouts() -> &'static Vec<Layout> {
    static ALL: OnceLock<Vec<Layout>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut all = vec![];
        for dow in [false, true] {
            for zero_day in [false, true] {
                for long_year in [true, false] {
                    for seconds in [true, false] {
                        for zone in [Zone::Num, Zone::Abbr, Zone::Ut] {
                            all.push(Layout {
                                dow,
                                zero_day,
                                long_year,
                                seconds,
                                zone,
                            });
                        }
                    }
                }
            }
        }
        all
    })
}

fn is_digit(s: &[u8], i: usize) -> bool {
    s.get(i).is_some_and(u8::is_ascii_digit)
}
/// `time.getnum`.
fn getnum(s: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    if !is_digit(s, 0) {
        return None;
    }
    if !is_digit(s, 1) {
        return if fixed {
            None
        } else {
            Some((i64::from(s[0] - b'0'), &s[1..]))
        };
    }
    Some((
        i64::from(s[0] - b'0') * 10 + i64::from(s[1] - b'0'),
        &s[2..],
    ))
}
/// `time.atoi`: optional sign, then digits only.
fn atoi(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: i64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some(if neg { -n } else { n })
}
/// `time.skip` for a literal that is one run of non-space characters or one space.
fn skip<'a>(mut value: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let mut prefix = prefix;
    while let Some(&p) = prefix.first() {
        if p == b' ' {
            if !value.is_empty() && value[0] != b' ' {
                return None;
            }
            while prefix.first() == Some(&b' ') {
                prefix = &prefix[1..];
            }
            while value.first() == Some(&b' ') {
                value = &value[1..];
            }
            continue;
        }
        if value.first() != Some(&p) {
            return None;
        }
        prefix = &prefix[1..];
        value = &value[1..];
    }
    Some(value)
}
fn lookup<'a>(names: &[&str], value: &'a [u8]) -> Option<(usize, &'a [u8])> {
    names.iter().enumerate().find_map(|(i, name)| {
        let n = name.len();
        (value.len() >= n && value[..n].eq_ignore_ascii_case(name.as_bytes()))
            .then(|| (i, &value[n..]))
    })
}
fn days_in(month: i64, year: i64) -> i64 {
    match month {
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
/// `time.parseSignedOffset`: the length consumed, 0 when it does not apply.
fn signed_offset(value: &[u8]) -> usize {
    if !matches!(value.first(), Some(b'-' | b'+')) {
        return 0;
    }
    let digits = value[1..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return 0;
    }
    match std::str::from_utf8(&value[1..1 + digits])
        .unwrap_or("")
        .parse::<u64>()
    {
        Ok(x) if x <= 23 => 1 + digits,
        _ => 0,
    }
}
/// `time.parseTimeZone`: the length of the zone name at the start of `value`.
fn parse_time_zone(value: &[u8]) -> Option<usize> {
    if value.len() < 3 {
        return None;
    }
    if value.starts_with(b"ChST") || value.starts_with(b"MeST") {
        return Some(4);
    }
    if value.starts_with(b"GMT") {
        let rest = &value[3..];
        return Some(if rest.is_empty() {
            3
        } else {
            3 + signed_offset(rest)
        });
    }
    if matches!(value[0], b'+' | b'-') {
        return Some(signed_offset(value)).filter(|n| *n > 0);
    }
    let upper = value
        .iter()
        .take(6)
        .take_while(|c| c.is_ascii_uppercase())
        .count();
    match upper {
        5 if value[4] == b'T' => Some(5),
        4 if value[3] == b'T' || value.starts_with(b"WITA") => Some(4),
        3 => Some(3),
        _ => None,
    }
}

/// Seconds since the epoch (UTC civil date) and nanoseconds.
type Instant = (i64, u32);

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_with(layout: &Layout, date: &[u8]) -> Option<Instant> {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut value = date;
    if layout.dow {
        value = lookup(&DAYS, value)?.1;
        value = skip(value, b", ")?;
    }
    let (day, rest) = getnum(value, layout.zero_day)?;
    value = skip(rest, b" ")?;
    let (month, rest) = lookup(&MONTHS, value)?;
    let month = month as i64 + 1;
    value = skip(rest, b" ")?;
    let year;
    if layout.long_year {
        if value.len() < 4 || !is_digit(value, 0) {
            return None;
        }
        year = atoi(&value[..4])?;
        value = &value[4..];
    } else {
        if value.len() < 2 {
            return None;
        }
        let y = atoi(&value[..2])?;
        value = &value[2..];
        year = if y >= 69 { y + 1900 } else { y + 2000 };
    }
    value = skip(value, b" ")?;
    let (hour, rest) = getnum(value, false)?;
    if !(0..24).contains(&hour) {
        return None;
    }
    value = skip(rest, b":")?;
    let (minute, rest) = getnum(value, true)?;
    if !(0..60).contains(&minute) {
        return None;
    }
    value = rest;
    let (mut second, mut nanos) = (0i64, 0i64);
    if layout.seconds {
        value = skip(value, b":")?;
        let (s, rest) = getnum(value, true)?;
        if !(0..60).contains(&s) {
            return None;
        }
        second = s;
        value = rest;
        // A fraction is taken even though the layout has none.
        if value.len() >= 2 && matches!(value[0], b'.' | b',') && is_digit(value, 1) {
            let mut n = 2;
            while is_digit(value, n) {
                n += 1;
            }
            let shown = n.min(10);
            let ns = atoi(&value[1..shown])?;
            nanos = ns * 10i64.pow(10 - shown as u32);
            value = &value[n..];
        }
    }
    value = skip(value, b" ")?;
    let mut offset = 0i64;
    match layout.zone {
        Zone::Num => {
            if value.len() < 5 {
                return None;
            }
            let hr = getnum(&value[1..3], true)?.0;
            let mm = getnum(&value[3..5], true)?.0;
            // Go's own range test uses `>` so a 24 hour or 60 minute offset is accepted.
            if hr > 24 || mm > 60 {
                return None;
            }
            offset = (hr * 60 + mm) * 60;
            match value[0] {
                b'+' => {}
                b'-' => offset = -offset,
                _ => return None,
            }
            value = &value[5..];
        }
        Zone::Abbr => {
            if value.starts_with(b"UTC") {
                value = &value[3..];
            } else {
                let n = parse_time_zone(value)?;
                value = &value[n..];
            }
        }
        Zone::Ut => {
            value = value.strip_prefix(b"UT")?;
        }
    }
    if !value.is_empty() {
        return None;
    }
    if day < 1 || day > days_in(month, year) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some((secs, nanos as u32))
}

/// `net/mail.ParseDate`.
fn parse_date(text: &[u8]) -> Option<Instant> {
    let text = replace_crlf(text);
    if text.contains(&b'\r') {
        return None;
    }
    let mut p: &[u8] = text.as_slice();
    let trim_sp =
        |s: &[u8]| -> usize { s.iter().take_while(|c| **c == b' ' || **c == b'\t').count() };
    p = &p[trim_sp(p)..];
    let mut date = text.clone();
    let zone_at = p.iter().position(|c| *c == b'+' || *c == b'-');
    match zone_at {
        Some(ind) if p.len() >= ind + 5 => {
            date = p[..ind + 5].to_vec();
            p = &p[ind + 5..];
        }
        _ => {
            let mut ind = p.iter().position(|c| *c == b'T');
            if ind == Some(0) {
                ind = p[1..].iter().position(|c| *c == b'T').map(|i| i + 1);
            }
            if let Some(i) = ind {
                if p.len() >= i + 5 {
                    date = p[..i + 1].to_vec();
                    p = &p[i + 1..];
                }
            }
        }
    }
    // skipCFWS: only an unterminated comment is an error.
    p = &p[trim_sp(p)..];
    while p.first() == Some(&b'(') {
        p = &p[1..];
        let mut depth = 1;
        while !p.is_empty() && depth != 0 {
            if p[0] == b'\\' && p.len() > 1 {
                p = &p[1..];
            } else if p[0] == b'(' {
                depth += 1;
            } else if p[0] == b')' {
                depth -= 1;
            }
            p = &p[1..];
        }
        if depth != 0 {
            return None;
        }
        p = &p[trim_sp(p)..];
    }
    layouts().iter().find_map(|l| parse_with(l, &date))
}
fn replace_crlf(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'\r' && text.get(i + 1) == Some(&b'\n') {
            i += 2;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

// ---- hops ----

struct Hop {
    index: usize,
    from_host: String,
    by_host: String,
    with_protocol: String,
    ip: String,
    rdns: String,
    timestamp: Option<Instant>,
    delay_ms: Option<i64>,
    tls_active: bool,
    is_our_infra: bool,
    parse_ok: bool,
    raw_line: Vec<u8>,
}

struct Patterns {
    from: Regex,
    by: Regex,
    with: Regex,
    ip: Regex,
    rdns: Regex,
}
fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        // RE2 `\s` is [\t\n\f\r ] and `\b` is the ASCII word boundary.
        let sp = r"[\t\n\f\r ]";
        let word = r"[A-Za-z0-9.\-_]";
        Patterns {
            from: Regex::new(&format!(r"(?i)(?-u:\b)from{sp}+({word}{{1,253}})")).expect("re"),
            by: Regex::new(&format!(r"(?i)(?-u:\b)by{sp}+({word}{{1,253}})")).expect("re"),
            with: Regex::new(&format!(r"(?i)(?-u:\b)with{sp}+([A-Za-z0-9()/\-]{{1,40}})"))
                .expect("re"),
            ip: Regex::new(r"\[([0-9a-fA-F:.]{3,45})\]").expect("re"),
            rdns: Regex::new(&format!(
                r"(?i)from{sp}+{word}+{sp}+\(({word}{{1,253}}){sp}"
            ))
            .expect("re"),
        }
    })
}
fn capture(re: &Regex, body: &[u8]) -> Option<String> {
    re.captures(body)
        .map(|c| String::from_utf8_lossy(&c[1]).into_owned())
}

fn parse_line(index: usize, line: &[u8]) -> Hop {
    let line = &line[..line.len().min(MAX_LINE_LEN)];
    let p = patterns();
    let (body, ts) = match line.iter().position(|b| *b == b';') {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => (line, &line[line.len()..]),
    };
    let from_host = capture(&p.from, body)
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let by_host = capture(&p.by, body)
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let with_protocol = capture(&p.with, body).unwrap_or_default();
    let upper = with_protocol.to_uppercase();
    let tls_active = upper.contains("ESMTPS") || upper.contains("TLS");
    let ip = capture(&p.ip, body).unwrap_or_default();
    let rdns = capture(&p.rdns, body)
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let timestamp = parse_date(trim_space_bytes(ts));
    let parse_ok = !from_host.is_empty() || !by_host.is_empty();
    Hop {
        index,
        from_host,
        by_host,
        with_protocol: go_trim_space(with_protocol.as_bytes()),
        ip,
        rdns,
        timestamp,
        delay_ms: None,
        tls_active,
        is_our_infra: false,
        parse_ok,
        raw_line: line.to_vec(),
    }
}

/// `time.Duration` of `a - b`, saturating, in whole milliseconds (`Milliseconds()`).
fn delay_ms(a: Instant, b: Instant) -> i64 {
    let ns = i128::from(a.0 - b.0) * 1_000_000_000 + i128::from(a.1) - i128::from(b.1);
    let ns = ns.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    ns / 1_000_000
}

/// RFC 3339 with trimmed fractional seconds; `None` outside years 0..=9999 (Go's
/// `Time.MarshalJSON` error).
fn time_json(t: Instant) -> Option<String> {
    let days = t.0.div_euclid(86_400);
    let rem = t.0.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    if !(0..=9999).contains(&y) {
        return None;
    }
    let mut out = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    if t.1 != 0 {
        out += format!(".{:09}", t.1).trim_end_matches('0');
    }
    Some(out + "Z")
}

/// `encoding/json` string for bytes: an invalid byte becomes the `\ufffd` escape.
fn json_bytes(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = utf8_width(rest);
        match std::str::from_utf8(&rest[..n]) {
            Ok(s) => out.push_str(&crate::s(s)[1..crate::s(s).len() - 1]),
            Err(_) => out.push_str("\\ufffd"),
        }
        rest = &rest[n..];
    }
    out.push('"');
    out
}

fn hop_json(h: &Hop, stamp: &Option<String>) -> String {
    let mut out = format!("{{\"index\":{}", h.index);
    for (key, value) in [
        ("fromHost", &h.from_host),
        ("byHost", &h.by_host),
        ("withProtocol", &h.with_protocol),
        ("ip", &h.ip),
        ("rdns", &h.rdns),
    ] {
        if !value.is_empty() {
            out += &format!(",\"{key}\":{}", json_bytes(value.as_bytes()));
        }
    }
    out += &format!(
        ",\"timestamp\":{},\"delayMs\":{},\"tlsActive\":{},\"isOurInfra\":{},\"parseOk\":{}",
        stamp
            .as_ref()
            .map_or("null".to_owned(), |s| format!("\"{s}\"")),
        h.delay_ms.map_or("null".to_owned(), |d| d.to_string()),
        h.tls_active,
        h.is_our_infra,
        h.parse_ok
    );
    if !h.raw_line.is_empty() {
        out += &format!(",\"rawLine\":{}", json_bytes(&h.raw_line));
    }
    out + "}"
}

/// The empty trace Go answers on any degrade.
pub fn empty_trace() -> String {
    crate::done(
        "{\"direction\":\"inbound\",\"hopCount\":0,\"totalTransitMs\":null,\"slowestHopIndex\":null,\"hops\":[]}"
            .to_owned(),
    )
}

/// `received.ParseTrace` rendered as `json.Encoder` writes it. `None` is a marshal error
/// (a timestamp outside years 0..=9999): Go has already sent 200 and writes nothing.
pub fn parse_trace(raw: &[u8], identity: &Identity) -> Option<String> {
    let mut values = received_values(raw);
    let mut truncated = false;
    if values.len() > MAX_HOPS {
        values.truncate(MAX_HOPS);
        truncated = true;
    }
    let n = values.len();
    let mut hops: Vec<Hop> = (0..n).map(|i| parse_line(i, &values[n - 1 - i])).collect();
    for i in 1..n {
        if let (Some(a), Some(b)) = (hops[i].timestamp, hops[i - 1].timestamp) {
            hops[i].delay_ms = Some(delay_ms(a, b));
        }
    }
    for i in (0..n).rev() {
        if identity.matches(&hops[i].by_host) {
            hops[i].is_our_infra = true;
        } else {
            break;
        }
    }
    let (mut total, mut have_total) = (0i64, false);
    let (mut slow_idx, mut slow_delay) = (None::<usize>, 0i64);
    for (i, h) in hops.iter().enumerate() {
        if let Some(d) = h.delay_ms {
            if d > 0 {
                total += d;
                have_total = true;
            }
            if slow_idx.is_none() || d > slow_delay {
                slow_delay = d;
                slow_idx = Some(i);
            }
        }
    }
    let mut rendered = vec![];
    for h in &hops {
        let stamp = match h.timestamp {
            Some(t) => Some(time_json(t)?),
            None => None,
        };
        rendered.push(hop_json(h, &stamp));
    }
    let mut out = format!(
        "{{\"direction\":\"inbound\",\"hopCount\":{n},\"totalTransitMs\":{},\"slowestHopIndex\":{},\"hops\":[{}]",
        if have_total { total.to_string() } else { "null".into() },
        slow_idx.map_or("null".to_owned(), |i| i.to_string()),
        rendered.join(",")
    );
    if truncated {
        out += ",\"truncated\":true";
    }
    out += "}";
    Some(crate::done(out))
}
