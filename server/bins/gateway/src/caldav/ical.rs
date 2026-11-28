//! Frozen Go's database-row iCalendar projection. Deliberately excludes the
//! organizer/attendee and VTODO fields absent from Go's eventColumns query.
use chrono::{DateTime, Utc};
use serde_json::Value;

pub(super) fn text<'a>(event: &'a Value, key: &str) -> &'a str {
    event[key].as_str().unwrap_or("")
}
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}
fn fold(mut line: &str) -> String {
    let mut out = String::new();
    while line.len() > 75 {
        let mut cut = 75;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        out.push_str(&line[..cut]);
        out.push_str("\r\n ");
        line = &line[cut..];
    }
    out.push_str(line);
    out
}
fn formatted(value: &str, layout: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc).format(layout).to_string())
        .unwrap_or_else(|_| "00010101T000000Z".into())
}
fn date(event: &Value, key: &str, layout: &str) -> String {
    formatted(text(event, key), layout)
}
fn all_day(event: &Value) -> bool {
    event["all_day"].as_bool() == Some(true)
}
fn zone_offset(name: &str, unix: i64) -> Option<i32> {
    match crate::ics::load_location(name) {
        crate::ics::Zone::Utc => matches!(name, "UTC" | "Local").then_some(0),
        crate::ics::Zone::Tz(zone) => zone.find_local_time_type(unix).ok().map(|t| t.ut_offset()),
    }
}
fn valid_tzid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/_-+.".contains(&c))
        && zone_offset(name, Utc::now().timestamp()).is_some()
}
pub(super) fn timezone(name: &str) -> Option<String> {
    let offset = zone_offset(name, Utc::now().timestamp())?;
    let sign = if offset < 0 { "-" } else { "+" };
    let offset = offset.unsigned_abs();
    let offset = format!("{sign}{:02}{:02}", offset / 3600, (offset % 3600) / 60);
    Some(super::stored_timezone(name, &offset))
}
fn rule(raw: &str) -> bool {
    let mut parts = raw.split(';');
    let mut saw_freq = false;
    for (index, part) in parts.by_ref().enumerate() {
        let Some((name, value)) = part.split_once('=') else {
            return false;
        };
        if name.is_empty()
            || !name.bytes().all(|c| c.is_ascii_alphabetic())
            || value.is_empty()
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b",.+-".contains(&c))
        {
            return false;
        }
        if index == 0 && name.eq_ignore_ascii_case("FREQ") {
            saw_freq = true;
        }
    }
    saw_freq
}
fn component(out: &mut String, event: &Value, kind: &str, recurrence: Option<(&str, bool, &str)>) {
    out.push_str(&format!(
        "BEGIN:{kind}\r\nDTSTAMP:{}\r\nSEQUENCE:0\r\n",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    for (property, key) in [
        ("UID", "uid"),
        ("SUMMARY", "title"),
        ("DESCRIPTION", "description"),
        ("LOCATION", "location"),
    ] {
        if key == "location" && kind != "VEVENT" {
            continue;
        }
        let value = text(event, key);
        if !value.is_empty() || matches!(key, "uid" | "title") {
            out.push_str(&fold(&format!("{property}:{}", escape(value))));
            out.push_str("\r\n");
        }
    }
    if kind == "VEVENT" {
        let timezone = text(event, "timezone");
        for (property, key) in [("DTSTART", "start_at"), ("DTEND", "end_at")] {
            if all_day(event) {
                out.push_str(&format!(
                    "{property};VALUE=DATE:{}\r\n",
                    date(event, key, "%Y%m%d")
                ));
            } else if !timezone.is_empty() && timezone != "UTC" && valid_tzid(timezone) {
                out.push_str(&format!(
                    "{property};TZID={timezone}:{}\r\n",
                    date(event, key, "%Y%m%dT%H%M%S")
                ));
            } else {
                out.push_str(&format!(
                    "{property}:{}\r\n",
                    date(event, key, "%Y%m%dT%H%M%SZ")
                ));
            }
        }
    } else {
        let start = date(event, "start_at", "%Y%m%dT%H%M%SZ");
        if start != "00010101T000000Z" {
            out.push_str(&format!("DTSTART:{start}\r\n"));
        }
    }
    if kind != "VJOURNAL" && !text(event, "status").is_empty() {
        out.push_str(&format!(
            "STATUS:{}\r\n",
            text(event, "status").to_uppercase()
        ));
    }
    if kind == "VEVENT" && !text(event, "transp").is_empty() {
        out.push_str(&format!(
            "TRANSP:{}\r\n",
            text(event, "transp").to_uppercase()
        ));
    }
    if kind != "VJOURNAL" && rule(text(event, "rrule")) {
        out.push_str(&format!("RRULE:{}\r\n", text(event, "rrule")));
    }
    if kind == "VEVENT" {
        for (property, key) in [("RDATE", "rdate"), ("EXDATE", "exdate")] {
            if let Some(dates) = event[key].as_array() {
                for value in dates {
                    if let Some(value) = value.as_str() {
                        let (param, layout) = if all_day(event) {
                            (";VALUE=DATE", "%Y%m%d")
                        } else {
                            ("", "%Y%m%dT%H%M%SZ")
                        };
                        out.push_str(&format!(
                            "{property}{param}:{}\r\n",
                            formatted(value, layout)
                        ));
                    }
                }
            }
        }
        if let Some((instant, day, timezone)) = recurrence {
            if day {
                let value = DateTime::parse_from_rfc3339(instant)
                    .ok()
                    .and_then(|t| {
                        let offset = zone_offset(timezone, t.timestamp()).unwrap_or(0);
                        chrono::FixedOffset::east_opt(offset)
                            .map(|offset| t.with_timezone(&offset).format("%Y%m%d").to_string())
                    })
                    .unwrap_or_default();
                out.push_str(&format!("RECURRENCE-ID;VALUE=DATE:{value}\r\n"));
            } else {
                out.push_str(&format!(
                    "RECURRENCE-ID:{}\r\n",
                    formatted(instant, "%Y%m%dT%H%M%SZ")
                ));
            }
        }
    }
    out.push_str(&format!("END:{kind}\r\n"));
}
pub(super) fn render(event: &Value, overrides: &[Value]) -> String {
    let kind = match text(event, "component_type") {
        "VTODO" => "VTODO",
        "VJOURNAL" => "VJOURNAL",
        _ => "VEVENT",
    };
    let mut out =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mailserver//CalDAV//EN\r\n");
    let name = text(event, "timezone");
    if kind != "VJOURNAL" && !name.is_empty() && name != "UTC" {
        if let Some(zone) = timezone(name) {
            out.push_str(&zone);
        }
    }
    component(&mut out, event, kind, None);
    for event_override in overrides {
        component(
            &mut out,
            event_override,
            "VEVENT",
            Some((
                text(event_override, "recurrence_override"),
                all_day(event),
                name,
            )),
        );
    }
    out.push_str("END:VCALENDAR\r\n");
    out
}
