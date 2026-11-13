//! Go `json.NewDecoder(r.Body).Decode(&struct)` semantics for the F01 admin
//! bodies: first value only, case-folded keys, null keeps zero values.
use serde::de::{MapAccess, Visitor};
use std::fmt;

pub use crate::guests_input::fold;

/// First JSON value of the body; trailing bytes are never examined, as Go's.
pub async fn first<T: serde::de::DeserializeOwned>(
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
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}

macro_rules! body {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        pub struct $name { $(pub $field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<$name, E> {
                        Ok($name::default())
                    }
                    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<$name, M::Error> {
                        let mut body = $name::default();
                        while let Some(key) = map.next_key::<String>()? {
                            match fold(&key).as_str() {
                                $($key => {
                                    if let Some(value) = map.next_value::<Option<$ty>>()? {
                                        body.$field = value;
                                    }
                                })+
                                _ => {
                                    let _: serde::de::IgnoredAny = map.next_value()?;
                                }
                            }
                        }
                        Ok(body)
                    }
                }
                decoder.deserialize_any(Fields)
            }
        }
    };
}
body!(Alias {
    email: String = "email"
});
body!(Quota {
    quota_bytes: Option<i64> = "quotabytes",
    sending_quota_day: Option<i64> = "sendingquotaday"
});
body!(UserCreate {
    email: String = "email",
    display_name: String = "displayname",
    password: String = "password",
    is_local_admin: bool = "islocaladmin"
});
body!(UserUpdate {
    display_name: Option<String> = "displayname",
    enabled: Option<bool> = "enabled",
    is_local_admin: Option<bool> = "islocaladmin"
});
body!(PasswordReset {
    password: String = "password",
    must_change: Option<bool> = "mustchange"
});
body!(Entitlement {
    enabled: bool = "enabled"
});

/// `strconv.Atoi`/`ParseInt` with the error ignored: syntax errors give 0 and
/// range errors saturate.
pub fn atoi(text: &str) -> i64 {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    match digits.parse::<i64>() {
        Ok(n) if negative => -n,
        Ok(n) => n,
        Err(_) if negative => i64::MIN,
        Err(_) => i64::MAX,
    }
}

/// Go `r.URL.Query().Get(name)`: pairs with `;` or bad escapes are dropped.
pub fn query(uri: &hyper::Uri, name: &str) -> Option<String> {
    fn decode(value: &str) -> Option<String> {
        let input = value.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < input.len() {
            match input[index] {
                b'+' => out.push(b' '),
                b'%' => {
                    let a = (*input.get(index + 1)? as char).to_digit(16)?;
                    let b = (*input.get(index + 2)? as char).to_digit(16)?;
                    out.push((a * 16 + b) as u8);
                    index += 2;
                }
                b => out.push(b),
            }
            index += 1;
        }
        Some(crate::guests_input::go_utf8(&out))
    }
    for pair in uri.query()?.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (decode(key), decode(value)) else {
            continue;
        };
        if key == name {
            return Some(value);
        }
    }
    None
}

/// Go's `identity.ValidateAndCanonicalizeEmail`: structural validation, then the
/// RFC 2142 reserved local-part gate (a quoted local part is judged unquoted).
pub fn address(raw: &str) -> Result<String, &'static str> {
    let value = crate::guests_input::email(raw)?;
    let local = value.rsplit_once('@').map_or("", |(local, _)| local);
    let bare = local
        .strip_prefix('"')
        .and_then(|l| l.strip_suffix('"'))
        .unwrap_or(local);
    if [
        "postmaster",
        "abuse",
        "webmaster",
        "hostmaster",
        "mailer-daemon",
        "nobody",
    ]
    .contains(&bare)
    {
        return Err("email local-part is reserved (RFC 2142)");
    }
    Ok(value)
}

body!(RoleCreate {
    name: String = "name",
    description: String = "description",
    permissions: Vec<Option<String>> = "permissions",
    domain_scope: Option<i64> = "domainscope"
});
body!(RoleUpdate {
    name: Option<String> = "name",
    description: Option<String> = "description",
    permissions: Vec<Option<String>> = "permissions",
    domain_scope: Option<i64> = "domainscope",
    sod_class: Option<String> = "sodclass"
});
body!(RoleAssign {
    user_id: i64 = "userid",
    domain_override: Option<i64> = "domainoverride",
    expires_at: Option<String> = "expiresat",
    scope_type: Option<String> = "scopetype",
    scope_id: Option<i64> = "scopeid",
    eligible: Option<bool> = "eligible"
});
body!(RoleBulk {
    user_ids: Vec<Option<i64>> = "userids",
    expires_at: Option<String> = "expiresat",
    scope_type: Option<String> = "scopetype",
    scope_id: Option<i64> = "scopeid",
    eligible: Option<bool> = "eligible"
});

/// A `[]string` element: JSON `null` decodes to the zero value.
pub fn strings(items: Vec<Option<String>>) -> Vec<String> {
    items.into_iter().map(Option::unwrap_or_default).collect()
}

/// Go's `time.Parse(time.RFC3339, raw)`: the instant, or `None` when Go refuses.
pub fn rfc3339(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDate, TimeZone};
    let b = raw.as_bytes();
    let digits = |from: usize, len: usize| -> Option<i64> {
        let part = b.get(from..from + len)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0i64, |n, d| n * 10 + i64::from(d - b'0')))
    };
    let delimiters = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if b.len() < 20 || delimiters.iter().any(|(i, c)| b[*i] != *c) {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0u32;
    if matches!(b[at], b'.' | b',') {
        let start = at + 1;
        let mut end = start;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end == start {
            return None;
        }
        for (i, d) in b[start..end].iter().take(9).enumerate() {
            nanos += u32::from(d - b'0') * 10u32.pow(8 - i as u32);
        }
        at = end;
    }
    let offset = if b.get(at) == Some(&b'Z') && at + 1 == b.len() {
        0
    } else if b.len() == at + 6 && matches!(b[at], b'+' | b'-') && b[at + 3] == b':' {
        let (hh, mm) = (digits(at + 1, 2)?, digits(at + 4, 2)?);
        if hh > 24 || mm > 59 {
            return None;
        }
        let seconds = hh * 3600 + mm * 60;
        if b[at] == b'-' {
            -seconds
        } else {
            seconds
        }
    } else {
        return None;
    };
    let naive = NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32)?.and_hms_nano_opt(
        hour as u32,
        minute as u32,
        second as u32,
        nanos,
    )?;
    let local = chrono::Utc.from_utc_datetime(&naive);
    Some(local - chrono::Duration::seconds(offset))
}

/// A UTC instant as Postgres `timestamptz` text, truncated to microseconds as pgx does.
pub fn timestamptz(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S%.6f+00").to_string()
}

#[cfg(test)]
mod tests {
    use super::{rfc3339, timestamptz};

    fn utc(raw: &str) -> Option<String> {
        rfc3339(raw).map(timestamptz)
    }

    #[test]
    fn rfc3339_matches_go_time_parse() {
        assert_eq!(
            utc("2031-01-01T00:00:00+02:00").as_deref(),
            Some("2030-12-31 22:00:00.000000+00")
        );
        assert_eq!(
            utc("2031-02-28T10:20:30.123456789Z").as_deref(),
            Some("2031-02-28 10:20:30.123456+00")
        );
        assert!(utc("2031-02-29T00:00:00Z").is_none(), "no leap day");
        assert!(utc("2028-02-29T00:00:00Z").is_some());
        assert!(utc("2031-01-01T24:00:00Z").is_none());
        assert!(utc("2031-01-01T00:00:60Z").is_none());
        assert!(utc("2031-01-01t00:00:00Z").is_none());
        assert!(utc("2031-01-01T00:00:00z").is_none());
        assert!(utc("2031-01-01T00:00:00").is_none(), "zone required");
        assert!(utc("2031-01-01T00:00:00.Z").is_none());
        assert!(utc("tomorrow").is_none());
    }
}
