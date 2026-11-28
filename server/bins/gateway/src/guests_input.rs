//! Go encoding/json field folding, presence and duplicate/null semantics.
use serde::de::{MapAccess, Visitor};
use serde_json::{json, Value};
#[derive(Default)]
pub struct Profile {
    host: i64,
    name: String,
    booleans: [Option<bool>; 7],
    days: Option<Box<serde_json::value::RawValue>>,
    apps: Option<Box<serde_json::value::RawValue>>,
}
const BOOLS: [&str; 7] = [
    "canPost",
    "historyFromJoin",
    "allowDownload",
    "allowMeetCreate",
    "allowMeetHost",
    "canInitiateDm",
    "allowNativeShell",
];
impl Profile {
    pub fn payload(self) -> Result<String, &'static str> {
        if self.host <= 0 {
            return Err("invalid hostDomainId");
        }
        if self.booleans.iter().any(Option::is_none) {
            return Err("all guest profile boolean fields are required");
        }
        let days = self.days.ok_or("defaultExpiryDays is required")?;
        let days = if days.get() == "null" {
            Value::Null
        } else {
            json!(serde_json::from_str::<i64>(days.get())
                .map_err(|_| "defaultExpiryDays must be an integer or null")?)
        };
        let apps = self.apps.ok_or("apps is required")?;
        let apps = serde_json::from_str::<Vec<Option<String>>>(apps.get())
            .map_err(|_| "apps must be an array")?
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect::<Vec<_>>();
        let mut body =
            json!({"hostDomainId":self.host,"name":self.name,"defaultExpiryDays":days,"apps":apps});
        for (key, value) in BOOLS.iter().zip(self.booleans) {
            body[*key] = json!(value.expect("checked"));
        }
        Ok(body.to_string())
    }
}
impl<'de> serde::Deserialize<'de> for Profile {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Profile;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest profile object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Profile, E> {
                Ok(Profile::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Profile, M::Error> {
                let mut body = Profile::default();
                while let Some(key) = map.next_key::<String>()? {
                    let folded = fold(&key);
                    if let Some(index) = BOOLS.iter().position(|s| s.to_ascii_lowercase() == folded)
                    {
                        body.booleans[index] = map.next_value()?;
                    } else {
                        match folded.as_str() {
                            "hostdomainid" => {
                                if let Some(value) = map.next_value::<Option<i64>>()? {
                                    body.host = value;
                                }
                            }
                            "name" => {
                                if let Some(value) = map.next_value::<Option<String>>()? {
                                    body.name = value;
                                }
                            }
                            "defaultexpirydays" => body.days = Some(map.next_value()?),
                            "apps" => body.apps = Some(map.next_value()?),
                            _ => return Err(serde::de::Error::custom("unknown field")),
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
pub fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ſ' => 's',
            'K' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}
pub async fn read<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<crate::Body>,
    cap: usize,
) -> Result<T, ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > cap.saturating_sub(bytes.len()) {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    serde_json::from_slice(&go_json_bytes(&bytes)).map_err(|_| ())
}

#[derive(Default)]
pub struct Expires {
    pub value: Option<String>,
    pub zero: bool,
}
impl<'de> serde::Deserialize<'de> for Expires {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Expires;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest expiry object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Expires, E> {
                Ok(Expires::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Expires, M::Error> {
                let mut body = Expires::default();
                while let Some(key) = map.next_key::<String>()? {
                    if fold(&key) != "expiresat" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        body.value = Some(
                            timestamp(&value)
                                .map_err(|_| serde::de::Error::custom("invalid time"))?,
                        );
                        let t = parse_time(&value)
                            .map_err(|_| serde::de::Error::custom("invalid time"))?;
                        body.zero =
                            t.timestamp() == -62135596800 && t.timestamp_subsec_nanos() == 0;
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
/// pgx encodes timestamptz in whole microseconds, rather than PostgreSQL's
/// rounding of a nine-digit timestamp string. Keep that wire boundary exact.
pub fn timestamp(value: &str) -> Result<String, ()> {
    use chrono::Datelike;
    let t = parse_time(value)?;
    let t = chrono::DateTime::from_timestamp_micros(t.timestamp_micros()).ok_or(())?;
    if t.year() <= 0 {
        return Ok(format!(
            "{:04}-{} BC",
            1 - t.year(),
            t.format("%m-%dT%H:%M:%S%.6f+00")
        ));
    }
    if t.year() > 9999 {
        return Ok(format!(
            "{}-{}",
            t.year(),
            t.format("%m-%dT%H:%M:%S%.6f+00")
        ));
    }
    Ok(t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

#[derive(Default)]
pub struct Assignment {
    value: Option<Box<serde_json::value::RawValue>>,
}
impl Assignment {
    pub fn target(self) -> Result<Option<i64>, &'static str> {
        let value = self.value.ok_or("profileId is required")?;
        if value.get() == "null" {
            return Ok(None);
        }
        serde_json::from_str::<i64>(value.get())
            .ok()
            .filter(|n| *n > 0)
            .map(Some)
            .ok_or("invalid profileId")
    }
}
impl<'de> serde::Deserialize<'de> for Assignment {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Assignment;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest profile assignment")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Assignment, E> {
                Ok(Assignment::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Assignment, M::Error> {
                let mut body = Assignment::default();
                while let Some(key) = map.next_key::<String>()? {
                    if fold(&key) != "profileid" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    body.value = Some(map.next_value()?);
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

#[derive(Default)]
pub struct Sponsor {
    pub user: i64,
}
impl<'de> serde::Deserialize<'de> for Sponsor {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Sponsor;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest sponsor object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Sponsor, E> {
                Ok(Sponsor::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Sponsor, M::Error> {
                let mut body = Sponsor::default();
                while let Some(key) = map.next_key::<String>()? {
                    if fold(&key) != "sponsoruserid" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    if let Some(value) = map.next_value::<Option<i64>>()? {
                        body.user = value;
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

#[derive(Default)]
pub struct Domain {
    pub value: String,
}
impl<'de> serde::Deserialize<'de> for Domain {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Domain;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest domain object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Domain, E> {
                Ok(Domain::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Domain, M::Error> {
                let mut body = Domain::default();
                while let Some(key) = map.next_key::<String>()? {
                    if fold(&key) != "domain" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        body.value = value;
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
pub fn lower(value: &str) -> String {
    value
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}
pub fn domain(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("domain must not be empty");
    }
    if value.len() > 253 {
        return Err("domain exceeds 253 characters");
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("domain contains control character");
    }
    if !value.contains('.') {
        return Err("domain must contain at least one dot");
    }
    for label in value.split('.') {
        if label.is_empty() {
            return Err("domain label must not be empty");
        }
        if label.len() > 63 {
            return Err("domain label exceeds 63 characters");
        }
        if label.starts_with('-') {
            return Err("domain label starts with hyphen");
        }
        if label.ends_with('-') {
            return Err("domain label ends with hyphen");
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err("domain label contains invalid character");
        }
    }
    Ok(())
}
#[derive(Default)]
pub struct Revoke {
    pub value: String,
}
impl<'de> serde::Deserialize<'de> for Revoke {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Revoke;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest invite revoke object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Revoke, E> {
                Ok(Revoke::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Revoke, M::Error> {
                let mut body = Revoke::default();
                while let Some(key) = map.next_key::<String>()? {
                    if fold(&key) != "expectedinviteid" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        body.value = value;
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
#[derive(Default)]
pub struct Submission {
    pub email: String,
    pub message: Option<String>,
}
impl<'de> serde::Deserialize<'de> for Submission {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Submission;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest invite submission")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Submission, E> {
                Ok(Submission::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Submission, M::Error> {
                let mut body = Submission::default();
                while let Some(key) = map.next_key::<String>()? {
                    match fold(&key).as_str() {
                        "invitedemail" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.email = v
                            }
                        }
                        "message" => body.message = map.next_value()?,
                        _ => return Err(serde::de::Error::custom("unknown field")),
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
/// Identity's ASCII-only address fold precedes structural validation.
pub fn email(raw: &str) -> Result<String, &'static str> {
    let folded = raw.trim().to_ascii_lowercase();
    let value = mailparse::addrparse(&folded)
        .ok()
        .and_then(|xs| {
            if xs.len() == 1 {
                match &xs[0] {
                    mailparse::MailAddr::Single(a) => Some(a.addr.clone()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .unwrap_or(folded);
    if value.is_empty() {
        return Err("email must not be empty");
    }
    if value.len() > 254 {
        return Err("email exceeds 254 characters");
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("email contains control character");
    }
    let Some((local, host)) = value
        .rsplit_once('@')
        .filter(|(l, h)| !l.is_empty() && !h.is_empty())
    else {
        return Err("invalid email format");
    };
    if local.contains("..") {
        return Err("local-part contains consecutive dots");
    }
    if local.starts_with('.') {
        return Err("local-part starts with a dot");
    }
    if local.ends_with('.') {
        return Err("local-part ends with a dot");
    }
    if !local.is_ascii() {
        return Err("non-ASCII local-part requires SMTPUTF8");
    }
    if host.starts_with('[') && host.ends_with(']') {
        return Err("IP domain literals are not supported");
    }
    if !host.contains('.') {
        return Err("domain must contain at least one dot");
    }
    if host.contains('_') {
        return Err("domain contains underscore");
    }
    if value.chars().any(char::is_whitespace) && !local.starts_with('"') {
        return Err("invalid email format");
    }
    if mailparse::addrparse(&value).is_err() {
        return Err("invalid email format");
    }
    Ok(value)
}
#[derive(Default)]
pub struct Invite {
    pub email: String,
    pub name: String,
    pub expires: Option<String>,
    pub profile: Option<i64>,
}
impl<'de> serde::Deserialize<'de> for Invite {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Invite;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest invitation")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Invite, E> {
                Ok(Invite::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Invite, M::Error> {
                let mut body = Invite::default();
                while let Some(key) = map.next_key::<String>()? {
                    match fold(&key).as_str() {
                        "email" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.email = v
                            }
                        }
                        "displayname" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.name = v
                            }
                        }
                        "profileid" => body.profile = map.next_value()?,
                        "expiresat" => {
                            body.expires = map
                                .next_value::<Option<String>>()?
                                .map(|v| timestamp(&v))
                                .transpose()
                                .map_err(|_| serde::de::Error::custom("invalid time"))?
                        }
                        _ => return Err(serde::de::Error::custom("unknown field")),
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// encoding/json replaces each malformed UTF-8 byte and unpaired UTF-16 escape.
/// Syntax errors still reach the strict JSON decoder unchanged.
pub(crate) fn go_utf8(mut input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    loop {
        match std::str::from_utf8(input) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let at = e.valid_up_to();
                out.push_str(std::str::from_utf8(&input[..at]).expect("validated prefix"));
                out.push('\u{fffd}');
                input = &input[at + 1..];
            }
        }
    }
}
pub(crate) fn go_json_bytes(input: &[u8]) -> Vec<u8> {
    let text = go_utf8(input);
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let (mut i, mut quoted) = (0, false);
    fn escape(bytes: &[u8], at: usize) -> Option<u16> {
        if bytes.get(at..at + 2)? != b"\\u" {
            return None;
        }
        u16::from_str_radix(std::str::from_utf8(bytes.get(at + 2..at + 6)?).ok()?, 16).ok()
    }
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            quoted = !quoted;
            out.push(b);
            i += 1;
            continue;
        }
        if quoted && b == b'\\' {
            if let Some(code) = escape(bytes, i) {
                if (0xd800..=0xdbff).contains(&code) {
                    if escape(bytes, i + 6).is_some_and(|n| (0xdc00..=0xdfff).contains(&n)) {
                        out.extend_from_slice(&bytes[i..i + 12]);
                        i += 12;
                        continue;
                    } else {
                        out.extend_from_slice(b"\\ufffd");
                        i += 6;
                        continue;
                    }
                } else if (0xdc00..=0xdfff).contains(&code) {
                    out.extend_from_slice(b"\\ufffd");
                    i += 6;
                    continue;
                }
            }
            out.push(b);
            i += 1;
            if let Some(b) = bytes.get(i) {
                out.push(*b);
                i += 1;
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

#[derive(Default)]
pub struct Reinvite {
    pub value: Option<String>,
}
impl<'de> serde::Deserialize<'de> for Reinvite {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Reinvite;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("guest recovery expiry")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Reinvite, E> {
                Ok(Reinvite::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Reinvite, M::Error> {
                let mut body = Reinvite::default();
                while let Some(key) = map.next_key::<String>()? {
                    if fold(&key) != "expiresat" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    body.value = map
                        .next_value::<Option<String>>()?
                        .map(|v| timestamp(&v))
                        .transpose()
                        .map_err(|_| serde::de::Error::custom("invalid time"))?;
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// Go 1.26's parseStrictRFC3339 deliberately retains its legacy Parse fallback
/// (time/format_rfc3339.go, issue 54580): one-digit hours, comma fractions and
/// zone 24/60 are accepted. Leap seconds and lowercase Z are rejected.
pub(crate) fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>, ()> {
    if value.len() < 19
        || value.as_bytes().get(10) != Some(&b'T')
        || !value.as_bytes()[..4].iter().all(u8::is_ascii_digit)
    {
        return Err(());
    }
    let mut normalized = value.to_owned();
    if normalized.as_bytes()[11].is_ascii_digit() && normalized.as_bytes().get(12) == Some(&b':') {
        normalized.insert(11, '0');
    }
    if normalized.len() < 20
        || !normalized.as_bytes()[17..19].iter().all(u8::is_ascii_digit)
        || normalized[17..19].parse::<u8>().map_err(|_| ())? > 59
    {
        return Err(());
    }
    if normalized.as_bytes()[19] == b',' {
        normalized.replace_range(19..20, ".");
    }
    if normalized.as_bytes()[19] == b'.' {
        let mut end = 20;
        while normalized
            .as_bytes()
            .get(end)
            .is_some_and(u8::is_ascii_digit)
        {
            end += 1;
        }
        if end == 20 {
            return Err(());
        }
        if end > 29 {
            normalized.replace_range(29..end, "");
        }
    }
    let (text, offset) = if let Some(text) = normalized.strip_suffix('Z') {
        (text, 0)
    } else {
        let at = normalized
            .rfind(|c| c == '+' || c == '-')
            .filter(|at| *at > 10)
            .ok_or(())?;
        let zone = &normalized[at..];
        let b = zone.as_bytes();
        if b.len() != 6 || b[3] != b':' || !b[1..3].iter().chain(&b[4..6]).all(u8::is_ascii_digit) {
            return Err(());
        }
        let hour = zone[1..3].parse::<i64>().map_err(|_| ())?;
        let minute = zone[4..6].parse::<i64>().map_err(|_| ())?;
        if hour > 24 || minute > 60 {
            return Err(());
        }
        (
            &normalized[..at],
            (hour * 3600 + minute * 60) * if b[0] == b'+' { 1 } else { -1 },
        )
    };
    let time = chrono::DateTime::parse_from_rfc3339(&format!("{text}Z"))
        .map_err(|_| ())?
        .with_timezone(&chrono::Utc);
    time.checked_sub_signed(chrono::Duration::seconds(offset))
        .ok_or(())
}
