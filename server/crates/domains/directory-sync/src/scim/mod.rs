//! SCIM 2.0 provisioning (F02, #375): pure wire codecs, row decoders, filter/PATCH
//! engines, and payload builders. Database execution of the cataloged `crate::sql::SCIM_*`
//! contracts runs on `WorkerPool` in `bins/gateway/src/scim.rs`.
#![allow(clippy::result_unit_err)]
pub mod filter;
pub mod patch;
mod status;
pub mod wire;

use setjoin_pg::{Row, StatementFailure};
pub use status::reducer_status;
use wire::{Email, Enterprise, Group, Member, Meta, Name, Phone, User};

fn failure(message: &str) -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: message.into(),
    }
}

/// The source binding a verified token carries.
#[derive(Clone, Copy, Debug)]
pub struct Fence {
    pub source_id: i64,
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub id: i64,
    pub deletion_policy: String,
    pub fence: Fence,
}

pub fn candidate(row: &Row) -> Result<(Token, String), StatementFailure> {
    let bad = |_| failure("scim token row");
    Ok((
        Token {
            id: row.try_get(0).map_err(bad)?,
            deletion_policy: row.try_get(3).map_err(bad)?,
            fence: Fence {
                source_id: row.try_get(5).map_err(bad)?,
                generation: row.try_get(6).map_err(bad)?,
            },
        },
        row.try_get(2).map_err(bad)?,
    ))
}

// ---- users ------------------------------------------------------------------------

pub struct UserRow {
    pub id: i64,
    pub external_id: Option<String>,
    pub user_name: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub job_title: Option<String>,
    pub phone: Option<String>,
    pub enabled: Option<bool>,
    pub created: String,
    pub updated: String,
    pub updated_nano: String,
    pub updated_micros: i64,
}

pub fn user_row(row: &Row) -> Option<UserRow> {
    Some(UserRow {
        id: row.try_get(0).ok()?,
        external_id: row.try_get(1).ok()?,
        user_name: row.try_get(2).ok()?,
        email: row.try_get(3).ok()?,
        display_name: row.try_get(4).ok()?,
        first_name: row.try_get(5).ok()?,
        last_name: row.try_get(6).ok()?,
        job_title: row.try_get(7).ok()?,
        phone: row.try_get(8).ok()?,
        enabled: row.try_get(9).ok()?,
        created: row.try_get(10).ok()?,
        updated: row.try_get(11).ok()?,
        updated_nano: row.try_get(12).ok()?,
        updated_micros: row.try_get(13).ok()?,
    })
}

/// Go `userRowToResource`.
pub fn user_resource(row: &UserRow) -> User {
    resource_from(
        row.id,
        row.external_id.as_deref(),
        row.user_name.as_deref(),
        row.email.as_deref(),
        row.display_name.as_deref(),
        row.first_name.as_deref(),
        row.last_name.as_deref(),
        row.job_title.as_deref(),
        row.phone.as_deref(),
        row.enabled,
        &row.created,
        &row.updated,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn resource_from(
    id: i64,
    external_id: Option<&str>,
    user_name: Option<&str>,
    email: Option<&str>,
    display_name: Option<&str>,
    first: Option<&str>,
    last: Option<&str>,
    title: Option<&str>,
    phone: Option<&str>,
    enabled: Option<bool>,
    created: &str,
    updated: &str,
) -> User {
    let mut user = User {
        id: id.to_string(),
        meta: Some(Meta {
            resource_type: "User".into(),
            created: created.into(),
            last_modified: updated.into(),
            location: format!("/scim/v2/Users/{id}"),
        }),
        ..Default::default()
    };
    user.external_id = external_id.unwrap_or_default().into();
    user.user_name = user_name.unwrap_or_default().into();
    user.display_name = display_name.unwrap_or_default().into();
    if let Some(email) = email {
        user.emails = vec![Email {
            value: email.into(),
            kind: "work".into(),
            primary: Some(true),
            ..Default::default()
        }];
    }
    if first.is_some() || last.is_some() {
        let mut name = Name {
            given: first.unwrap_or_default().into(),
            family: last.unwrap_or_default().into(),
            ..Default::default()
        };
        if let (Some(f), Some(l)) = (first, last) {
            name.formatted = format!("{f} {l}");
        }
        user.name = Some(name);
    }
    user.title = title.unwrap_or_default().into();
    if let Some(phone) = phone {
        user.phones = vec![Phone {
            value: phone.into(),
            kind: "work".into(),
        }];
    }
    user.active = enabled;
    user
}

pub fn decode_patch_row(row: &Row, user: i64, now: &str) -> Option<(User, String)> {
    let external: String = row.try_get(0).ok()?;
    let text = |i| row.try_get::<_, Option<String>>(i).ok();
    let (username, email, display) = (text(1)?, text(2)?, text(3)?);
    let (first, last, title, phone, department) =
        (text(4)?, text(5)?, text(6)?, text(7)?, text(8)?);
    let enabled: Option<bool> = row.try_get(9).ok()?;
    let mut resource = resource_from(
        user,
        Some(&external),
        username.as_deref(),
        email.as_deref(),
        display.as_deref(),
        first.as_deref(),
        last.as_deref(),
        title.as_deref(),
        phone.as_deref(),
        enabled,
        now,
        now,
    );
    if let Some(department) = department {
        resource.enterprise = Some(Enterprise {
            department,
            manager: None,
        });
    }
    Some((resource, external))
}

pub enum Page {
    Filter(filter::Node, i64, i64),
    Sync(String, i64),
    All(i64, i64),
}

pub enum ListError {
    Http(patch::HttpError),
    /// Go's `500 Query failed`.
    Query,
}

pub struct Listed {
    pub rows: Vec<UserRow>,
    pub total: i64,
}

/// Resolved static-SQL parameters for a SCIM `filter` query.
pub struct FilterParams {
    pub attribute: String,
    pub operator: String,
    pub value: String,
}

/// Validate a parsed SCIM filter node and compute static-SQL bind arguments
/// for `sql::SCIM_USERS_FILTER_COUNT` / `sql::SCIM_USERS_FILTER_LIST`.
pub fn resolve_filter(node: &filter::Node) -> Result<FilterParams, ListError> {
    let (_, kind) = filter::column(&node.attribute).ok_or_else(|| {
        ListError::Http(patch::http(
            400,
            "Unsupported filter attribute",
            "invalidFilter",
        ))
    })?;
    let value = match node.operator.as_str() {
        "eq" => node.value.clone(),
        "co" | "sw" if kind != filter::Kind::Text => return Err(ListError::Query),
        "co" => format!("%{}%", node.value),
        "sw" => format!("{}%", node.value),
        "pr" => String::new(),
        _ => String::new(),
    };
    Ok(FilterParams {
        attribute: node.attribute.clone(),
        operator: node.operator.clone(),
        value,
    })
}

/// Go `time.Parse(time.RFC3339Nano, text)`, normalized for PostgreSQL with the
/// fraction cut to microseconds (pgx's encoding).
fn rfc3339nano(text: &str) -> Result<String, ()> {
    let b = text.as_bytes();
    let digits = |s: usize, n: usize| -> Result<u32, ()> {
        let part = b.get(s..s + n).ok_or(())?;
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(());
        }
        Ok(part.iter().fold(0, |a, d| a * 10 + u32::from(d - b'0')))
    };
    let year = digits(0, 4)?;
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') || b.get(10) != Some(&b'T') {
        return Err(());
    }
    let (month, day) = (digits(5, 2)?, digits(8, 2)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + u32::from(leap),
        _ => return Err(()),
    };
    if day < 1 || day > days {
        return Err(());
    }
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(());
    }
    let mut at = 19;
    let mut fraction = String::new();
    if matches!(b.get(at), Some(b'.' | b',')) && b.get(at + 1).is_some_and(u8::is_ascii_digit) {
        at += 1;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            fraction.push(b[at] as char);
            at += 1;
        }
        fraction.truncate(6);
    }
    let zone = match &text[at..] {
        "Z" => "Z".to_owned(),
        z if z.len() == 6 && matches!(z.as_bytes()[0], b'+' | b'-') && z.as_bytes()[3] == b':' => {
            let (zh, zm) = (
                z[1..3].parse::<u32>().map_err(|_| ())?,
                z[4..6].parse::<u32>().map_err(|_| ())?,
            );
            if zh > 24 || zm > 59 || !z[1..3].bytes().all(|d| d.is_ascii_digit()) {
                return Err(());
            }
            z.to_owned()
        }
        _ => return Err(()),
    };
    let fraction = if fraction.is_empty() {
        String::new()
    } else {
        format!(".{fraction}")
    };
    Ok(format!("{}{fraction}{zone}", &text[..19]))
}

pub fn sync_token(source: i64, updated: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(
        format!(
            "{{\"sourceId\":{},\"updatedAt\":{}}}",
            wire::quote(&source.to_string()),
            wire::quote(updated)
        )
        .as_bytes(),
    )
}

pub fn decode_sync_token(token: &str, source: i64) -> Result<String, ()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let data = URL_SAFE_NO_PAD.decode(token).map_err(|_| ())?;
    let value: serde_json::Value = serde_json::from_slice(&data).map_err(|_| ())?;
    let mut source_id = String::new();
    let mut updated = String::new();
    if let Some(map) = value.as_object() {
        for (k, v) in map {
            let target = match k.to_ascii_lowercase().as_str() {
                "sourceid" => &mut source_id,
                "updatedat" => &mut updated,
                _ => continue,
            };
            match v {
                serde_json::Value::Null => {}
                serde_json::Value::String(s) => *target = s.clone(),
                _ => return Err(()),
            }
        }
    } else if !value.is_null() {
        return Err(());
    }
    if source_id != source.to_string() {
        return Err(());
    }
    rfc3339nano(&updated)
}

// ---- user writes ------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
pub struct UserFields {
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub primary_email: String,
    pub phone: String,
    pub department: String,
    pub manager_ext_id: String,
    pub active: bool,
}

/// Go `extractUserFields`.
pub fn extract_user_fields(req: &User) -> UserFields {
    let mut display = req.display_name.clone();
    if display.is_empty() {
        if let Some(name) = &req.name {
            display = name.formatted.clone();
        }
    }
    if display.is_empty() {
        display = req.user_name.clone();
    }
    let (first, last) = req
        .name
        .as_ref()
        .map(|n| (n.given.clone(), n.family.clone()))
        .unwrap_or_default();
    let mut email = req
        .emails
        .first()
        .map(|e| e.value.clone())
        .unwrap_or_default();
    if email.is_empty() {
        email = req.user_name.clone();
    }
    UserFields {
        display_name: display,
        first_name: first,
        last_name: last,
        primary_email: email,
        phone: req
            .phones
            .first()
            .map(|p| p.value.clone())
            .unwrap_or_default(),
        department: req
            .enterprise
            .as_ref()
            .map(|e| e.department.clone())
            .unwrap_or_default(),
        manager_ext_id: req
            .enterprise
            .as_ref()
            .and_then(|e| e.manager.clone())
            .unwrap_or_default(),
        active: req.active.unwrap_or(true),
    }
}

pub enum ApplyError {
    Http(patch::HttpError),
    /// Go's classified reducer status (500 for anything unrecognized).
    Status(u16),
}

/// Build JSON payload for `identity_source_scim_apply`.
pub fn build_apply_user_payload(
    fence: Fence,
    external_id: &str,
    fields: &UserFields,
    title: &str,
    expected: i64,
    touched: Option<&patch::Touched>,
) -> Result<String, ApplyError> {
    use serde_json::{json, Map, Value};
    if fence.source_id <= 0 || fence.generation <= 0 {
        return Err(ApplyError::Status(500));
    }
    if external_id.is_empty() {
        return Err(ApplyError::Http(patch::http(
            400,
            "externalId is required as the immutable SCIM subject",
            "invalidValue",
        )));
    }
    let payload: Value = match touched {
        None => json!({
            "operation": if fields.active { "upsert" } else { "disable" },
            "email": fields.primary_email, "displayName": fields.display_name,
            "firstName": fields.first_name, "lastName": fields.last_name,
            "jobTitle": title, "phone": fields.phone, "department": fields.department,
            "enabled": fields.active, "managerSubject": fields.manager_ext_id,
            "expectedUserId": expected, "replaceAll": true,
        }),
        Some(touched) => {
            let mut map = Map::new();
            map.insert("operation".into(), json!("upsert"));
            map.insert("expectedUserId".into(), json!(expected));
            map.insert("replaceAll".into(), json!(false));
            let has = |k: &str| touched.contains(k);
            if has("displayName") {
                map.insert("displayName".into(), json!(fields.display_name));
            }
            if has("givenName") {
                map.insert("firstName".into(), json!(fields.first_name));
            }
            if has("familyName") {
                map.insert("lastName".into(), json!(fields.last_name));
            }
            if has("title") {
                map.insert("jobTitle".into(), json!(title));
            }
            if has("emails") {
                map.insert("email".into(), json!(fields.primary_email));
            }
            if has("phoneNumbers") {
                map.insert("phone".into(), json!(fields.phone));
            }
            if has("department") {
                map.insert("department".into(), json!(fields.department));
            }
            if has("active") {
                map.insert("enabled".into(), json!(fields.active));
                if !fields.active {
                    map.insert("operation".into(), json!("disable"));
                }
            }
            Value::Object(map)
        }
    };
    Ok(payload.to_string())
}

/// Decode the JSON response from `identity_source_scim_apply`.
pub fn parse_apply_user_result(raw: &str) -> Result<i64, ApplyError> {
    use serde_json::Value;
    let result: Value = serde_json::from_str(raw).map_err(|_| ApplyError::Status(500))?;
    let text = |k: &str| result.get(k).and_then(Value::as_str).unwrap_or("");
    if text("state") != "applied" || text("userId").is_empty() {
        return Err(ApplyError::Status(500));
    }
    go_parse_int(text("userId")).ok_or(ApplyError::Status(500))
}

/// `strconv.ParseInt(s, 10, 64)`: optional sign, digits, in range.
pub fn go_parse_int(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>()
        .ok()
        .or_else(|| text.strip_prefix('+')?.parse().ok())
}

/// `strconv.Atoi` on a 64-bit platform.
pub fn atoi(text: &str) -> Option<i64> {
    go_parse_int(text)
}

// ---- groups -----------------------------------------------------------------------

pub struct GroupRow {
    pub id: i64,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub created: String,
}

pub fn group_row(row: &Row) -> Option<GroupRow> {
    Some(GroupRow {
        id: row.try_get(0).ok()?,
        external_id: row.try_get(1).ok()?,
        display_name: row.try_get(2).ok()?,
        created: row.try_get(3).ok()?,
    })
}

pub fn group_member_row(row: &Row) -> Option<Member> {
    let id: i64 = row.try_get(2).ok()?;
    Some(Member {
        value: row.try_get(0).ok()?,
        display: row.try_get(1).ok()?,
        reference: format!("/scim/v2/Users/{id}"),
        kind: "User".into(),
    })
}

pub fn group_resource(row: &GroupRow, id_text: &str, members: Vec<Member>) -> Group {
    Group {
        id: id_text.into(),
        external_id: row.external_id.clone().unwrap_or_default(),
        display_name: row.display_name.clone().unwrap_or_default(),
        members,
        meta: Some(Meta {
            resource_type: "Group".into(),
            created: row.created.clone(),
            last_modified: String::new(),
            location: format!("/scim/v2/Groups/{id_text}"),
        }),
    }
}

pub enum GroupFailure {
    Http(patch::HttpError),
    Status(u16),
}

// ---- welcome email ----------------------------------------------------------------

/// Go `resolveWelcomeTemplate(cfg, "")`: disabled or no usable locale sends nothing.
pub fn welcome_template(config: &serde_json::Value) -> Option<(String, String, String)> {
    let map = config.as_object()?;
    let field = |m: &serde_json::Map<String, serde_json::Value>, name: &str| {
        m.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    if field(map, "enabled")?.as_bool() != Some(true) {
        return None;
    }
    let default_locale = field(map, "default_locale")
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let locales = field(map, "locales")?;
    let locales = locales.as_object()?;
    for locale in [default_locale.as_str(), "en"] {
        if locale.is_empty() {
            continue;
        }
        if let Some(entry) = locales.get(locale).and_then(|v| v.as_object()) {
            let text = |name| {
                field(entry, name)
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            };
            let subject = text("subject");
            if !subject.is_empty() {
                return Some((subject, text("body_text"), text("body_html")));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339nano_follows_go_parse() {
        assert_eq!(
            rfc3339nano("2026-10-01T12:00:00Z").unwrap(),
            "2026-10-01T12:00:00Z"
        );
        assert_eq!(
            rfc3339nano("2026-10-01T12:00:00.1234567891+02:00").unwrap(),
            "2026-10-01T12:00:00.123456+02:00"
        );
        for bad in [
            "2026-10-01 12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2026-10-01T24:00:00Z",
            "2026-10-01T12:00:00",
            "2026-10-01T12:00:60Z",
            "",
        ] {
            assert!(rfc3339nano(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sync_tokens_round_trip_and_bind_the_source() {
        let token = sync_token(7, "2026-10-01T12:00:00.5Z");
        assert_eq!(
            decode_sync_token(&token, 7).unwrap(),
            "2026-10-01T12:00:00.5Z"
        );
        assert!(decode_sync_token(&token, 8).is_err());
        assert!(decode_sync_token("%%", 7).is_err());
    }

    #[test]
    fn go_integers() {
        assert_eq!(go_parse_int("+7"), Some(7));
        assert_eq!(go_parse_int("-7"), Some(-7));
        assert_eq!(go_parse_int("007"), Some(7));
        assert_eq!(go_parse_int("7a"), None);
        assert_eq!(go_parse_int(""), None);
        assert_eq!(go_parse_int("9223372036854775808"), None);
    }

    #[test]
    fn filters_follow_go_operators_and_allowlist() {
        let node = filter::parse("userName eq \"a b\"").unwrap();
        assert_eq!(
            (node.attribute.as_str(), node.value.as_str()),
            ("userName", "a b")
        );
        assert!(filter::parse("userName").is_err());
        assert!(filter::parse("userName gt x").is_err());
        assert!(filter::parse("userName eq \"\"").is_err());
        assert!(resolve_filter(&filter::parse("password_hash pr").unwrap()).is_err());
        assert!(matches!(
            resolve_filter(&filter::parse("active co t").unwrap()),
            Err(ListError::Query)
        ));
    }
}
