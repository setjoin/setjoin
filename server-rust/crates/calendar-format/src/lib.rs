//! The slice of frozen Go's `caldav.ParseICalObjects` and `migration.SplitAndParseICS`
//! the calendar-subscription-sync worker uses: split a feed into components, parse
//! each the way Go does and render `migration.EventsToJSON`. Only the fields that
//! reach that JSON are rendered; migration-only fields are kept separately for
//! legacy file imports. Matching order, case rules and parse failures follow Go
//! (a prefix compares upper-cased while the strip is case-sensitive, a value that
//! fails its layout leaves the field unset).
use chrono::NaiveDate;

const ZERO_UNIX: i64 = -62_135_596_800;

#[derive(Default, Clone, Debug)]
pub struct Event {
    pub uid: String,
    pub title: String,
    pub description: String,
    pub location: String,
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub all_day: bool,
    pub timezone: String,
    pub status: String,
    pub rrule: String,
    pub component: String,
    pub migration: serde_json::Map<String,serde_json::Value>,
    pub attendees: Vec<serde_json::Value>,
    pub exdates: Vec<i64>,
    pub recurrence_id: Option<i64>,
}

/// `strings.ToUpper`: Go maps each rune through the simple case table.
fn go_upper(text: &str) -> String {
    text.chars()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

fn go_lower(text: &str) -> String {
    text.chars()
        .map(|c| {
            let mut low = c.to_lowercase();
            match (low.next(), low.next()) {
                (Some(l), None) => l,
                _ => c,
            }
        })
        .collect()
}

fn trim_space(text: &str) -> &str {
    text.trim_matches(char::is_whitespace)
}

fn split_after_newline(data: &str) -> impl Iterator<Item = &str> {
    data.split_inclusive('\n')
}

/// `migration.extractVTIMEZONE`'s result is only attached to `VTIMEZONE`, which the
/// JSON never carries, so the shared block is not materialised.
pub fn split_components(data: &str) -> Vec<String> {
    let mut components = Vec::new();
    let mut current = String::new();
    let mut in_tz = false;
    let mut depth = 0i32;
    for line in split_after_newline(data) {
        let trimmed = trim_space(line);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("BEGIN:VTIMEZONE") {
            in_tz = true;
            continue;
        }
        if trimmed.starts_with("END:VTIMEZONE") {
            in_tz = false;
            continue;
        }
        if in_tz {
            continue;
        }
        if trimmed.starts_with("BEGIN:VCALENDAR")
            || trimmed.starts_with("END:VCALENDAR")
            || trimmed.starts_with("VERSION:")
            || trimmed.starts_with("PRODID:")
        {
            continue;
        }
        if trimmed.starts_with("BEGIN:VEVENT")
            || trimmed.starts_with("BEGIN:VTODO")
            || trimmed.starts_with("BEGIN:VJOURNAL")
        {
            depth += 1;
            if depth == 1 {
                current.clear();
            }
        }
        if depth > 0 {
            current.push_str(line);
        }
        if trimmed.starts_with("END:VEVENT")
            || trimmed.starts_with("END:VTODO")
            || trimmed.starts_with("END:VJOURNAL")
        {
            if depth == 1 && !current.is_empty() {
                components.push(current.clone());
            }
            depth -= 1;
        }
    }
    components
}

fn unfold(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in data.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.push_str(line.trim_start_matches([' ', '\t']));
            }
        } else {
            out.push(line.to_owned());
        }
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
}

/// `caldav.ParseICal`: the first object of `ParseICalObjects`, or Go's error text.
pub fn parse_component(data: &str) -> Result<Event, &'static str> {
    Ok(parse_objects(data)?.remove(0))
}

pub fn parse_objects(data: &str) -> Result<Vec<Event>, &'static str> {
    let mut objects: Vec<Event> = Vec::new();
    let mut current: Option<Event> = None;
    let (mut in_tz, mut in_alarm) = (false, false);
    let mut in_component = false;
    for raw in unfold(data) {
        let line = trim_space(&raw);
        if line == "BEGIN:VTIMEZONE" {
            in_tz = true;
            continue;
        }
        if line == "END:VTIMEZONE" {
            in_tz = false;
            continue;
        }
        if in_tz {
            continue;
        }
        if matches!(line, "BEGIN:VEVENT" | "BEGIN:VTODO" | "BEGIN:VJOURNAL") {
            in_component = true;
            current = Some(Event {
                component: line.trim_start_matches("BEGIN:").to_owned(),
                ..Event::default()
            });
            continue;
        }
        if matches!(line, "END:VEVENT" | "END:VTODO" | "END:VJOURNAL") {
            in_component = false;
            if let Some(mut done) = current.take() {
                finalize(&mut done);
                objects.push(done);
            }
            continue;
        }
        if line == "BEGIN:VALARM" {
            in_alarm = true;
            continue;
        }
        if line == "END:VALARM" {
            in_alarm = false;
            continue;
        }
        if in_alarm {
            continue;
        }
        if !in_component {
            continue;
        }
        if let Some(event) = current.as_mut() {
            component_line(event, line);
        }
    }
    let Some(first) = objects.first() else {
        return Err("no VEVENT/VTODO/VJOURNAL component found");
    };
    if first.uid.is_empty() {return Err("missing UID");}
    Ok(objects)
}

fn finalize(event: &mut Event) {
    if event.title.is_empty() {
        event.title = "Untitled".into();
    }
    if event.status.is_empty() {
        event.status = match event.component.as_str() {
            "VTODO" => "needs-action",
            "VJOURNAL" => "draft",
            _ => "confirmed",
        }
        .into();
    }
}

fn strip<'a>(line: &'a str, prefix: &str) -> &'a str {
    line.strip_prefix(prefix).unwrap_or(line)
}

fn component_line(ev: &mut Event, line: &str) {
    let upper = go_upper(line);
    let is = |p: &str| upper.starts_with(p);
    if is("UID:") {
        ev.uid = unescape(strip(line, "UID:"));
    } else if is("SUMMARY:") {
        ev.title = unescape(strip(line, "SUMMARY:"));
    } else if is("DESCRIPTION:") {
        ev.description = unescape(strip(line, "DESCRIPTION:"));
    } else if is("LOCATION:") {
        ev.location = unescape(strip(line, "LOCATION:"));
    } else if is("STATUS:") {
        ev.status = go_lower(strip(line, "STATUS:"));
    } else if is("RRULE:") {
        ev.rrule = strip(line, "RRULE:").to_owned();
    } else if is("EXDATE") {
        ev.exdates.extend(recurrence_dates(line));
    } else if is("RECURRENCE-ID") {
        ev.recurrence_id=recurrence_dates(line).into_iter().next();
    } else if is("RDATE") {
        let values=recurrence_dates(line);
        ev.migration.insert("rdate".into(),serde_json::json!(values.iter().map(|v|rfc3339(*v)).collect::<Vec<_>>()));
    } else if is("ATTENDEE") {
        if let Some((name,value))=line.split_once(':') {
            let email=value.strip_prefix("mailto:").unwrap_or(value);
            let (mut cn,mut role,mut status,mut rsvp)=(String::new(),String::new(),"needs-action".to_owned(),true);
            for param in name.split(';') {
                if let Some((key,value))=param.split_once('=') {
                    match go_upper(key).as_str() {
                        "CN"=>cn=value.to_owned(),
                        "ROLE"=>role=match go_lower(value).as_str() {"req-participant"=>"required".into(),"opt-participant"=>"optional".into(),_=>go_lower(value)},
                        "PARTSTAT"=>status=go_lower(value),
                        "RSVP"=>rsvp=go_upper(value)=="TRUE",
                        _=>{},
                    }
                }
            }
            ev.attendees.push(serde_json::json!({"email":email,"name":cn,"role":role,"participationStatus":status,"expectReply":rsvp}));
        }
    } else if is("ORGANIZER") {
        if let Some((name,value))=line.split_once(':') {
            ev.migration.insert("organizer_email".into(),serde_json::json!(value.strip_prefix("mailto:").unwrap_or(value)));
            for param in name.split(';') {if let Some(cn)=param.strip_prefix("CN="){ev.migration.insert("organizer_name".into(),serde_json::json!(cn));}}
        }
    } else if is("PRIORITY:") || is("PERCENT-COMPLETE:") {
        if let Some((key,value))=line.split_once(':') {if let Ok(n)=value.parse::<i64>(){ev.migration.insert(if key=="PRIORITY"{"priority"}else{"percent_complete"}.into(),serde_json::json!(n));}}
    } else if is("COMPLETED:") {
        if let Some(t)=parse_date_time(strip(line,"COMPLETED:")){ev.migration.insert("completed_at".into(),serde_json::json!(rfc3339(t)));}
    } else if is("DUE") {
        let t=if is("DUE;VALUE=DATE:"){ev.all_day=true;parse_date(strip(line,"DUE;VALUE=DATE:"))}else if is("DUE;TZID="){line.split_once(':').and_then(|(name,value)|parse_in(value,&load_location(strip(name,"DUE;TZID="))))}else{parse_date_time(strip(line,"DUE:"))};
        if let Some(t)=t{ev.migration.insert("due_at".into(),serde_json::json!(rfc3339(t)));}
    } else if is("DTSTART;VALUE=DATE:") {
        ev.all_day = true;
        if let Some(t) = parse_date(strip(line, "DTSTART;VALUE=DATE:")) {
            ev.start = Some(t);
        }
    } else if is("DTSTART;TZID=") {
        if let Some((name, value)) = line.split_once(':') {
            let zone = strip(name, "DTSTART;TZID=");
            ev.timezone = zone.to_owned();
            if let Some(t) = parse_in(value, &load_location(zone)) {
                ev.start = Some(t);
            }
        }
    } else if is("DTSTART:") {
        if let Some(t) = parse_date_time(strip(line, "DTSTART:")) {
            ev.start = Some(t);
        }
    } else if is("DTEND;VALUE=DATE:") {
        ev.all_day = true;
        if let Some(t) = parse_date(strip(line, "DTEND;VALUE=DATE:")) {
            ev.end = Some(t);
        }
    } else if is("DTEND;TZID=") {
        if let Some((name, value)) = line.split_once(':') {
            if let Some(t) = parse_in(value, &load_location(strip(name, "DTEND;TZID="))) {
                ev.end = Some(t);
            }
        }
    } else if is("DTEND:") {
        if let Some(t) = parse_date_time(strip(line, "DTEND:")) {
            ev.end = Some(t);
        }
    } else if is("DUE;VALUE=DATE:") {
        ev.all_day = true;
    }
    // SEQUENCE, ORGANIZER, ATTENDEE, PRIORITY, PERCENT-COMPLETE, COMPLETED and the
    // other DUE forms are parsed by Go but never reach the JSON.
}

// ---- Go `time.Parse` layouts ----

struct Cursor<'a> {
    s: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn digits(&mut self, n: usize) -> Option<i64> {
        let part = self.s.get(self.at..self.at + n)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        self.at += n;
        Some(part.iter().fold(0i64, |a, d| a * 10 + i64::from(d - b'0')))
    }
    fn byte(&mut self, b: u8) -> Option<()> {
        (self.s.get(self.at) == Some(&b)).then(|| self.at += 1)
    }
    fn done(&self) -> bool {
        self.at == self.s.len()
    }
    /// Go accepts a fraction after the seconds even when the layout has none.
    fn fraction(&mut self) -> Option<()> {
        if matches!(self.s.get(self.at), Some(b'.' | b',')) && self.s.get(self.at + 1)?.is_ascii_digit() {
            self.at += 1;
            while self.s.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
        }
        Some(())
    }
}

fn civil(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    if !(1..=12).contains(&mo) || !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&s) {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(i32::try_from(y).ok()?, u32::try_from(mo).ok()?, u32::try_from(d).ok()?)?;
    Some(date.and_hms_opt(0, 0, 0)?.and_utc().timestamp() + h * 3600 + mi * 60 + s)
}

/// `20060102` plus an optional time: `(date, h, m, s)` fields in order.
fn fields(c: &mut Cursor<'_>, with_time: bool) -> Option<i64> {
    let (y, mo, d) = (c.digits(4)?, c.digits(2)?, c.digits(2)?);
    if !with_time {
        return civil(y, mo, d, 0, 0, 0);
    }
    c.byte(b'T')?;
    let (h, mi, s) = (c.digits(2)?, c.digits(2)?, c.digits(2)?);
    civil(y, mo, d, h, mi, s)
}

fn parse_date(text: &str) -> Option<i64> {
    let mut c = Cursor { s: text.as_bytes(), at: 0 };
    let t = fields(&mut c, false)?;
    c.done().then_some(t)
}

fn layout_z(text: &str) -> Option<i64> {
    let mut c = Cursor { s: text.as_bytes(), at: 0 };
    let t = fields(&mut c, true)?;
    c.fraction()?;
    c.byte(b'Z')?;
    c.done().then_some(t)
}

fn layout_offset(text: &str) -> Option<i64> {
    let mut c = Cursor { s: text.as_bytes(), at: 0 };
    let t = fields(&mut c, true)?;
    c.fraction()?;
    let sign = match c.s.get(c.at)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    c.at += 1;
    let (hh, mm) = (c.digits(2)?, c.digits(2)?);
    if hh > 24 || mm > 60 || !c.done() {
        return None;
    }
    Some(t - sign * (hh * 3600 + mm * 60))
}

fn layout_bare(text: &str) -> Option<i64> {
    let mut c = Cursor { s: text.as_bytes(), at: 0 };
    let t = fields(&mut c, true)?;
    c.fraction()?;
    c.done().then_some(t)
}

/// `caldav.parseDateTime`: fractional seconds are stripped first.
fn parse_date_time(value: &str) -> Option<i64> {
    let stripped = strip_fraction(value);
    layout_z(&stripped)
        .or_else(|| layout_offset(&stripped))
        .or_else(|| layout_bare(&stripped))
        .or_else(|| parse_date(&stripped))
}

fn strip_fraction(value: &str) -> String {
    match value.find('.') {
        Some(i) => {
            let rest = &value[i..];
            match rest.find(['Z', '+', '-']) {
                Some(next) => format!("{}{}", &value[..i], &rest[next..]),
                None => value[..i].to_owned(),
            }
        }
        None => value.to_owned(),
    }
}

/// `time.ParseInLocation("20060102T150405", value, loc)`.
fn parse_in(value: &str, zone: &Zone) -> Option<i64> {
    let mut c = Cursor { s: value.as_bytes(), at: 0 };
    let t = fields(&mut c, true)?;
    c.fraction()?;
    c.done().then(|| zone.to_utc(t))
}

// ---- `time.LoadLocation` ----

pub enum Zone {
    Utc,
    Tz(Box<tz::TimeZone>),
}

impl Zone {
    /// `time.Date`'s local-to-UTC resolution: the offset at the wall time read as UTC,
    /// re-looked-up when that offset is not valid at the resulting instant.
    fn to_utc(&self, wall: i64) -> i64 {
        let Zone::Tz(zone) = self else { return wall };
        let offset_at = |unix: i64| {
            zone.find_local_time_type(unix)
                .map(|t| i64::from(t.ut_offset()))
                .unwrap_or(0)
        };
        let mut offset = offset_at(wall);
        if offset != 0 {
            let utc = wall - offset;
            if offset_at(utc) != offset {
                offset = offset_at(utc);
            }
            return wall - offset;
        }
        wall
    }
}

fn zone_roots() -> Vec<String> {
    let mut roots = vec![
        "/usr/share/zoneinfo/".to_owned(),
        "/usr/share/lib/zoneinfo/".to_owned(),
        "/usr/lib/locale/TZ/".to_owned(),
        "/etc/zoneinfo/".to_owned(),
    ];
    if let Ok(dir) = std::env::var("ZONEINFO") {
        roots.insert(0, format!("{dir}/"));
    }
    roots
}

/// `caldav.loadLocation`: an unresolvable TZID falls back to UTC.
pub fn load_location(name: &str) -> Zone {
    if name.is_empty() || name == "UTC" || name == "Local" {
        return Zone::Utc;
    }
    if name.contains("..") || name.starts_with(['/', '\\']) {
        return Zone::Utc;
    }
    for root in zone_roots() {
        if let Ok(bytes) = std::fs::read(format!("{root}{name}")) {
            if !bytes.starts_with(b"TZif") {
                continue;
            }
            return match tz::TimeZone::from_tz_data(&bytes) {
                Ok(zone) => Zone::Tz(Box::new(zone)),
                Err(_) => Zone::Utc,
            };
        }
    }
    Zone::Utc
}

// ---- split + JSON ----

/// `migration.SplitAndParseICS`: the events and Go's count of unparsable components.
pub fn split_and_parse(data: &[u8]) -> (Vec<Event>, usize) {
    let data = setjoin_mime::go_lossy(data);
    let mut events = Vec::new();
    let mut errors = 0;
    for component in split_components(&data) {
        match parse_component(&component) {
            Ok(event) => events.push(event),
            Err(_) => errors += 1,
        }
    }
    (events, errors)
}

fn rfc3339(unix: i64) -> String {
    let t = chrono::DateTime::from_timestamp(unix, 0).unwrap_or_default().naive_utc();
    use chrono::{Datelike, Timelike};
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// `migration.EventsToJSON` (`json.Marshal` of maps: sorted keys, HTML escapes).
pub fn events_to_json(events: &[Event]) -> String {
    use go_string as s;
    let items: Vec<String> = events
        .iter()
        .map(|e| {
            let mut m = format!("{{\"description\":{}", s(&e.description));
            if let Some(end) = e.end.filter(|t| *t != ZERO_UNIX) {
                m.push_str(&format!(",\"end\":{}", s(&rfc3339(end))));
            }
            m.push_str(&format!(
                ",\"isAllDay\":{},\"location\":{},\"recurrenceRule\":{}",
                e.all_day,
                s(&e.location),
                s(&e.rrule)
            ));
            if let Some(start) = e.start.filter(|t| *t != ZERO_UNIX) {
                m.push_str(&format!(",\"start\":{}", s(&rfc3339(start))));
            }
            let status = go_lower(trim_space(&e.status));
            if matches!(
                status.as_str(),
                "confirmed" | "tentative" | "cancelled" | "needs-action" | "in-progress" | "completed"
            ) {
                m.push_str(&format!(",\"status\":{}", s(&status)));
            }
            m.push_str(&format!(
                ",\"timeZone\":{},\"title\":{},\"uid\":{}}}",
                s(&e.timezone),
                s(&e.title),
                s(&e.uid)
            ));
            m
        })
        .collect();
    format!("[{}]", items.join(","))
}

// Go's parseDateTimeIn for RECURRENCE-ID and EXDATE. Kept out of the feed JSON.
fn recurrence_dates(line: &str) -> Vec<i64> {
    let Some((name,value))=line.split_once(':') else {return vec![]};
    if name.to_ascii_uppercase().starts_with("RECURRENCE-ID") && value.contains(',') {return vec![];}
    let (mut form,mut timezone)=(None,None);
    for parameter in name.split(';').skip(1) {
        if let Some((key,value))=parameter.split_once('=') {
            let value=value.trim();
            let value=if value.len()>=2 && value.starts_with('"') && value.ends_with('"') {&value[1..value.len()-1]} else {value};
            if form.is_none() && key.trim().eq_ignore_ascii_case("VALUE") {form=Some(value);}
            if timezone.is_none() && key.trim().eq_ignore_ascii_case("TZID") {timezone=Some(value);}
        }
    }
    let date_only=form.is_some_and(|value|value.eq_ignore_ascii_case("DATE"));
    let zone=load_location(timezone.unwrap_or(""));
    value.split(',').filter_map(|value| {
        let value=strip_fraction(value.trim());
        if date_only {parse_date(&value).map(|t|zone.to_utc(t))}
        else if value.ends_with('Z') {layout_z(&value)}
        else {layout_offset(&value).or_else(||parse_in(&value,&zone))}
    }).collect()
}

fn go_string(value: &str) -> String {
 serde_json::to_string(value).expect("string JSON").replace('<',"\\u003c").replace('>',"\\u003e").replace('&',"\\u0026").replace('\u{2028}',"\\u2028").replace('\u{2029}',"\\u2029")
}
/// Frozen Go ParseITIP: duplicate METHOD rejects; the first VEVENT is used.
pub fn parse_itip(data: &str) -> Result<(String, Event), &'static str> {
 let (mut method,mut seen,mut inside,mut lines)=(String::new(),false,false,Vec::new());
 for line in unfold(data) {let line=trim_space(&line);
  if go_upper(line).starts_with("METHOD:") {
   if seen {return Err("duplicate METHOD")} seen=true;
   method=go_upper(line.strip_prefix("METHOD:").unwrap_or(line));
   if !matches!(method.as_str(),"REQUEST"|"REPLY"|"CANCEL"|"COUNTER") {return Err("unsupported METHOD")}
   continue;
  }
  if line=="BEGIN:VEVENT" {inside=true;lines.push(line.to_owned());continue}
  if line=="END:VEVENT" {lines.push(line.to_owned());inside=false;continue}
  if inside {lines.push(line.to_owned())}
 }
 if method.is_empty()||lines.is_empty(){return Err("missing METHOD or VEVENT")}
 Ok((method,parse_component(&lines.join("\n"))?))
}
