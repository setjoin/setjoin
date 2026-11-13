//! SCIM 2.0 provisioning (F02, #375): bearer-token authentication, user and
//! group resources, filter/pagination and the PATCH engine. Authority is the
//! verified token's source and generation only (R1-R4): every statement carries
//! them from the token row, never from the request. Writes call the existing
//! source-fenced reducers; nothing here reimplements their logic.
pub mod filter;
pub mod patch;
mod status;
pub mod wire;

use setjoin_pg::{Param, ScopedExecutor, StatementFailure, Type};
pub use status::reducer_status;
use wire::{Email, Enterprise, Group, Member, Meta, Name, Phone, User};

const SECONDS: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'";

fn failure(message: &str) -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: message.into(),
    }
}
fn nano(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'")
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

fn candidate(row: &setjoin_pg::Row) -> Result<(Token, String), StatementFailure> {
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
const TOKEN_COLUMNS: &str = "token_id, name, token_hash, deletion_policy, attribute_mapping::text, source_id, source_generation";

/// Indexed single-candidate lookup by the lowercase hex SHA-256 of the token.
pub async fn token_by_hash(
    exec: &ScopedExecutor,
    lookup_hash: &str,
) -> Result<Option<(Token, String)>, StatementFailure> {
    let rows = exec
        .read(
            &format!("SELECT {TOKEN_COLUMNS} FROM scim_token_lookup($1)"),
            &[(&lookup_hash, Type::TEXT)],
        )
        .await?;
    rows.first().map(candidate).transpose()
}
/// Legacy (pre-V238, no lookup hash) tokens; rows that fail to scan are skipped.
pub async fn legacy_tokens(
    exec: &ScopedExecutor,
) -> Result<Vec<(Token, String)>, StatementFailure> {
    let rows = exec
        .read(
            &format!("SELECT {TOKEN_COLUMNS} FROM scim_list_active_tokens()"),
            &[],
        )
        .await?;
    Ok(rows.iter().filter_map(|r| candidate(r).ok()).collect())
}
pub async fn record_usage(exec: &ScopedExecutor, token: i64) {
    let _ = exec
        .read(
            "SELECT scim_record_token_usage($1)",
            &[(&token, Type::INT8)],
        )
        .await;
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

fn user_columns() -> String {
    format!(
        "u.id, l.external_subject, u.username, u.email, u.display_name, u.first_name, u.last_name, \
         u.job_title, u.phone, u.enabled, to_char(u.created_at AT TIME ZONE 'UTC',{SECONDS}), \
         to_char(u.updated_at AT TIME ZONE 'UTC',{SECONDS}), {}, \
         (extract(epoch FROM u.updated_at) * 1000000)::bigint",
        nano("u.updated_at")
    )
}
const LINKED: &str = "FROM user_identity_links l JOIN users u ON u.id=l.user_id";

fn user_row(row: &setjoin_pg::Row) -> Option<UserRow> {
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
fn decode_sync_token(token: &str, source: i64) -> Result<String, ()> {
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

pub async fn list_users(
    worker: &ScopedExecutor,
    source: i64,
    page: Page,
) -> Result<Listed, ListError> {
    let columns = user_columns();
    let base = "l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id)";
    let query = |e: StatementFailure| {
        let _ = e;
        ListError::Query
    };
    match page {
        Page::Filter(node, start, count) => {
            let (clause, value) = match filter::to_sql(&node) {
                Err(()) => {
                    return Err(ListError::Http(patch::http(
                        400,
                        "Unsupported filter attribute",
                        "invalidFilter",
                    )))
                }
                Ok(filter::Where::Rejected) => return Err(ListError::Query),
                Ok(filter::Where::Clause(sql, value)) => (sql, value),
            };
            let source_arg = if value.is_some() { 2 } else { 1 };
            let mut params: Vec<Param<'_>> = vec![];
            if let Some(v) = &value {
                params.push((v, Type::TEXT));
            }
            params.push((&source, Type::INT8));
            let total = worker
                .read(
                    &format!("SELECT COUNT(*) {LINKED} WHERE l.source_id=${source_arg} AND {base} AND {clause}"),
                    &params,
                )
                .await
                .map_err(query)?;
            let total: i64 = total
                .first()
                .ok_or(ListError::Query)?
                .try_get(0)
                .map_err(|_| ListError::Query)?;
            let offset = start - 1;
            params.push((&count, Type::INT8));
            params.push((&offset, Type::INT8));
            let rows = worker
                .read_iterated(
                    &format!(
                        "SELECT {columns} {LINKED} WHERE l.source_id=${source_arg} AND {base} AND {clause} \
                         ORDER BY u.id LIMIT ${} OFFSET ${}",
                        source_arg + 1,
                        source_arg + 2
                    ),
                    &params,
                )
                .await
                .map_err(query)?;
            Ok(Listed {
                rows: rows.iter().filter_map(user_row).collect(),
                total,
            })
        }
        Page::Sync(token, count) => {
            let cursor = decode_sync_token(&token, source).map_err(|_| ListError::Query)?;
            let rows = worker
                .read_iterated(
                    &format!(
                        "SELECT {columns} {LINKED} WHERE l.source_id=$1 AND {base} \
                         AND u.updated_at > $2::text::timestamptz ORDER BY u.updated_at LIMIT $3"
                    ),
                    &[
                        (&source, Type::INT8),
                        (&cursor, Type::TEXT),
                        (&count, Type::INT8),
                    ],
                )
                .await
                .map_err(query)?;
            Ok(Listed {
                rows: rows.iter().filter_map(user_row).collect(),
                total: 0,
            })
        }
        Page::All(start, count) => {
            let total = worker
                .read(
                    &format!("SELECT COUNT(*) {LINKED} WHERE l.source_id=$1 AND {base}"),
                    &[(&source, Type::INT8)],
                )
                .await
                .map_err(query)?;
            let total: i64 = total
                .first()
                .ok_or(ListError::Query)?
                .try_get(0)
                .map_err(|_| ListError::Query)?;
            let offset = start - 1;
            let rows = worker
                .read_iterated(
                    &format!(
                        "SELECT {columns} {LINKED} WHERE l.source_id=$1 AND {base} \
                         ORDER BY u.id LIMIT $2 OFFSET $3"
                    ),
                    &[
                        (&source, Type::INT8),
                        (&count, Type::INT8),
                        (&offset, Type::INT8),
                    ],
                )
                .await
                .map_err(query)?;
            Ok(Listed {
                rows: rows.iter().filter_map(user_row).collect(),
                total,
            })
        }
    }
}

/// One linked user, or `None` (Go answers 404 for every error here).
pub async fn get_user(worker: &ScopedExecutor, source: i64, id: i64) -> Option<UserRow> {
    let columns = user_columns();
    let rows = worker
        .read(
            &format!(
                "SELECT {columns} {LINKED} WHERE l.source_id=$1 AND u.id=$2 \
                 AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id)"
            ),
            &[(&source, Type::INT8), (&id, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first().and_then(user_row)
}

/// Subject of a linked user, for PUT.
pub async fn source_subject(worker: &ScopedExecutor, source: i64, user: i64) -> Option<String> {
    let rows = worker
        .read(
            "SELECT l.external_subject FROM user_identity_links l WHERE l.source_id = $1 AND l.user_id = $2 \
             AND l.state = 'active' AND 'provision' = ANY(l.purposes)",
            &[(&source, Type::INT8), (&user, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first()?.try_get(0).ok()
}

/// The current resource for PATCH and DELETE (department path included).
pub async fn user_for_patch(
    worker: &ScopedExecutor,
    source: i64,
    user: i64,
    now: &str,
) -> Option<(User, String)> {
    let rows = worker
        .read(
            "SELECT l.external_subject,u.username,u.email,u.display_name,u.first_name,u.last_name,\
             u.job_title,u.phone,d.path,u.enabled FROM user_identity_links l JOIN users u ON u.id=l.user_id \
             LEFT JOIN departments d ON d.id=u.department_id WHERE l.source_id=$1 AND u.id=$2 \
             AND l.state='active' AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id)",
            &[(&source, Type::INT8), (&user, Type::INT8)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
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

/// `identity_source_scim_apply` as `applySourceUser` (`touched == None`) or
/// `applySourceUserPatch`. `request` is a fresh random UUID.
#[allow(clippy::too_many_arguments)]
pub async fn apply_user(
    worker: &ScopedExecutor,
    fence: Fence,
    request: &str,
    external_id: &str,
    fields: &UserFields,
    title: &str,
    expected: i64,
    touched: Option<&patch::Touched>,
) -> Result<i64, ApplyError> {
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
    let payload = payload.to_string();
    let rows = worker
        .read(
            "SELECT identity_source_scim_apply($1,$2,$3::text::uuid,$4,$5::text::jsonb)::text",
            &[
                (&fence.source_id, Type::INT8),
                (&fence.generation, Type::INT8),
                (&request, Type::TEXT),
                (&external_id, Type::TEXT),
                (&payload, Type::TEXT),
            ],
        )
        .await
        .map_err(|e| ApplyError::Status(reducer_status(&e)))?;
    let raw: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or(ApplyError::Status(500))?;
    let result: Value = serde_json::from_str(&raw).map_err(|_| ApplyError::Status(500))?;
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

pub async fn group_total(exec: &ScopedExecutor, source: i64) -> Result<i64, StatementFailure> {
    let rows = exec
        .read(
            "SELECT COUNT(*) FROM distribution_groups WHERE scim_source_id=$1",
            &[(&source, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| failure("count"))
}
pub async fn list_groups(
    exec: &ScopedExecutor,
    source: i64,
    start: i64,
    count: i64,
) -> Result<Vec<GroupRow>, StatementFailure> {
    let offset = start - 1;
    let rows = exec
        .read_iterated(
            &format!(
                "SELECT dg.id, dg.scim_external_id, mb.display_name, to_char(dg.created_at AT TIME ZONE 'UTC',{SECONDS}) \
                 FROM distribution_groups dg JOIN mailboxes mb ON mb.id = dg.mailbox_id \
                 WHERE dg.scim_source_id=$1 ORDER BY dg.id LIMIT $2 OFFSET $3"
            ),
            &[(&source, Type::INT8), (&count, Type::INT8), (&offset, Type::INT8)],
        )
        .await?;
    Ok(rows.iter().filter_map(group_row).collect())
}
fn group_row(row: &setjoin_pg::Row) -> Option<GroupRow> {
    Some(GroupRow {
        id: row.try_get(0).ok()?,
        external_id: row.try_get(1).ok()?,
        display_name: row.try_get(2).ok()?,
        created: row.try_get(3).ok()?,
    })
}
pub async fn get_group(
    exec: &ScopedExecutor,
    source: i64,
    id: i64,
) -> Result<Option<GroupRow>, StatementFailure> {
    let rows = exec
        .read(
            &format!(
                "SELECT dg.id, dg.scim_external_id, mb.display_name, to_char(dg.created_at AT TIME ZONE 'UTC',{SECONDS}) \
                 FROM distribution_groups dg JOIN mailboxes mb ON mb.id = dg.mailbox_id \
                 WHERE dg.id=$1 AND dg.scim_source_id=$2"
            ),
            &[(&id, Type::INT8), (&source, Type::INT8)],
        )
        .await?;
    Ok(rows.first().and_then(group_row))
}
/// A failed member query yields no members, as Go's.
pub async fn group_members(worker: &ScopedExecutor, source: i64, group: i64) -> Vec<Member> {
    let Ok(rows) = worker
        .read_iterated(
            "SELECT l.external_subject, COALESCE(u.display_name, ''), u.id FROM distribution_group_members dgm \
             JOIN mailboxes mb ON mb.id = dgm.mailbox_id JOIN users u ON u.id = mb.user_id \
             JOIN user_identity_links l ON l.user_id=u.id JOIN distribution_groups dg ON dg.id=dgm.group_id \
             WHERE dgm.group_id=$1 AND dg.scim_source_id=$2 AND l.source_id=$2 AND l.state='active' \
             AND 'provision'=ANY(l.purposes) AND NOT is_guest_account(u.id) ORDER BY u.display_name",
            &[(&group, Type::INT8), (&source, Type::INT8)],
        )
        .await
    else {
        return vec![];
    };
    rows.iter()
        .filter_map(|r| {
            let id: i64 = r.try_get(2).ok()?;
            Some(Member {
                value: r.try_get(0).ok()?,
                display: r.try_get(1).ok()?,
                reference: format!("/scim/v2/Users/{id}"),
                kind: "User".into(),
            })
        })
        .collect()
}

/// Group id of an extID, scoped to the source (PATCH pre-check; error = 404 there).
pub async fn group_external_id(exec: &ScopedExecutor, source: i64, id: i64) -> Option<String> {
    let rows = exec
        .read(
            "SELECT COALESCE(scim_external_id, '') FROM distribution_groups WHERE id=$1 AND scim_source_id=$2",
            &[(&id, Type::INT8), (&source, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first()?.try_get(0).ok()
}

/// `scim_upsert_group` then `scim_apply_group_members(.., TRUE)` in Go's one
/// transaction: a single statement, so both commit or neither does.
pub async fn create_group(
    exec: &ScopedExecutor,
    fence: Fence,
    external_id: &str,
    display_name: &str,
    members: &[String],
) -> Result<i64, u16> {
    let members = members.to_vec();
    let rows = exec
        .read(
            "SELECT g.id FROM (SELECT scim_upsert_group($1,$2,$3,$4) AS id) g, \
             LATERAL (SELECT scim_apply_group_members($1,$2,$3,$5,TRUE) AS applied OFFSET 0) m",
            &[
                (&fence.source_id, Type::INT8),
                (&fence.generation, Type::INT8),
                (&external_id, Type::TEXT),
                (&display_name, Type::TEXT),
                (&members, Type::TEXT_ARRAY),
            ],
        )
        .await
        .map_err(|e| reducer_status(&e))?;
    rows.first().and_then(|r| r.try_get(0).ok()).ok_or(500)
}

pub enum GroupFailure {
    Http(patch::HttpError),
    Status(u16),
}

pub async fn run_group_step(
    exec: &ScopedExecutor,
    fence: Fence,
    group: i64,
    external_id: &str,
    step: patch::GroupStep,
) -> Result<(), GroupFailure> {
    use patch::GroupStep::*;
    let status = |e: StatementFailure| GroupFailure::Status(reducer_status(&e));
    match step {
        Rename(name) => {
            let rows = exec
                .read(
                    "SELECT scim_upsert_group($1,$2,$3,$4)",
                    &[
                        (&fence.source_id, Type::INT8),
                        (&fence.generation, Type::INT8),
                        (&external_id, Type::TEXT),
                        (&name, Type::TEXT),
                    ],
                )
                .await
                .map_err(status)?;
            let updated: i64 = rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or(GroupFailure::Status(500))?;
            if updated != group {
                return Err(GroupFailure::Http(patch::http(
                    404,
                    "Group is not managed by this SCIM source",
                    "noTarget",
                )));
            }
            Ok(())
        }
        Replace(ids) => apply_members(exec, fence, external_id, &ids, true)
            .await
            .map_err(GroupFailure::Status),
        Add(ids) => apply_members(exec, fence, external_id, &ids, false)
            .await
            .map_err(GroupFailure::Status),
        Remove(ids) => {
            exec.read(
                "SELECT scim_remove_group_members($1,$2,$3,$4)",
                &[
                    (&fence.source_id, Type::INT8),
                    (&fence.generation, Type::INT8),
                    (&external_id, Type::TEXT),
                    (&ids, Type::TEXT_ARRAY),
                ],
            )
            .await
            .map_err(status)?;
            Ok(())
        }
    }
}
pub async fn apply_members(
    exec: &ScopedExecutor,
    fence: Fence,
    external_id: &str,
    ids: &[String],
    replace: bool,
) -> Result<(), u16> {
    let ids = ids.to_vec();
    exec.read(
        "SELECT scim_apply_group_members($1,$2,$3,$4,$5)",
        &[
            (&fence.source_id, Type::INT8),
            (&fence.generation, Type::INT8),
            (&external_id, Type::TEXT),
            (&ids, Type::TEXT_ARRAY),
            (&replace, Type::BOOL),
        ],
    )
    .await
    .map(|_| ())
    .map_err(|e| reducer_status(&e))
}

pub async fn delete_group(exec: &ScopedExecutor, fence: Fence, group: i64) -> Result<bool, u16> {
    let rows = exec
        .read(
            "SELECT scim_delete_group($1,$2,$3)",
            &[
                (&fence.source_id, Type::INT8),
                (&fence.generation, Type::INT8),
                (&group, Type::INT8),
            ],
        )
        .await
        .map_err(|e| reducer_status(&e))?;
    rows.first().and_then(|r| r.try_get(0).ok()).ok_or(500)
}

// ---- welcome email ----------------------------------------------------------------

/// Go `notify.SendWelcomeEmail(ctx, workerPool, id, "", logger)`: idempotent,
/// best effort, never fails the request. Delivery is the `deliver` reducer.
pub async fn send_welcome(worker: &ScopedExecutor, user: i64) {
    let sentinel = format!("system:welcome:{user}");
    let Ok(rows) = worker
        .read(
            "SELECT EXISTS (SELECT 1 FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
             WHERE mb.user_id = $1 AND m.raw_ref = $2)",
            &[(&user, Type::INT8), (&sentinel, Type::TEXT)],
        )
        .await
    else {
        return;
    };
    if rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()) != Some(false) {
        return;
    }
    let Ok(rows) = worker
        .read("SELECT get_system_config('welcome_email')::text", &[])
        .await
    else {
        return;
    };
    let Some(Some(raw)) = rows
        .first()
        .map(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
    else {
        return;
    };
    let Ok(config) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let Some(template) = welcome_template(&config) else {
        return;
    };
    // identity.ResolvePrimaryMailbox, then the recipient's personalization fields.
    let Ok(rows) = worker
        .read(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[(&user, Type::INT8)],
        )
        .await
    else {
        return;
    };
    let Some(mailbox) = rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()) else {
        return;
    };
    let Ok(rows) = worker
        .read(
            "SELECT u.display_name, u.username, COALESCE(mb.email, u.email) FROM mailboxes mb \
             JOIN users u ON u.id = mb.user_id WHERE mb.id = $1",
            &[(&mailbox, Type::INT8)],
        )
        .await
    else {
        return;
    };
    let Some(row) = rows.first() else { return };
    let (Ok(mut display), Ok(username), Ok(email)) = (
        row.try_get::<_, String>(0),
        row.try_get::<_, String>(1),
        row.try_get::<_, String>(2),
    ) else {
        return;
    };
    let (local, domain) = match email.rfind('@') {
        Some(at) => (&email[..at], &email[at + 1..]),
        None => ("", email.as_str()),
    };
    if display.is_empty() {
        display = if local.is_empty() {
            email.clone()
        } else {
            local.to_owned()
        };
    }
    let values = [
        ("DisplayName", display),
        ("Email", email.clone()),
        ("Username", username),
        ("OrgName", domain.to_owned()),
        ("WebmailURL", format!("https://{domain}")),
    ];
    let substitute = |text: &str| {
        let mut out = text.to_owned();
        for (key, value) in &values {
            out = out.replace(&format!("{{{{{key}}}}}"), value);
        }
        out
    };
    let (subject, body_text, body_html) = (
        substitute(&template.0),
        substitute(&template.1),
        substitute(&template.2),
    );
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let message_id = format!("welcome-{user}-{nanos}@setjoin");
    let from = format!("noreply@{domain}");
    let to = format!(
        "[{{\"email\":{},\"name\":\"\"}}]",
        serde_json::to_string(&email).unwrap_or_default()
    );
    let size = (body_text.len() + body_html.len()) as i64;
    let _ = worker
        .read(
            "SELECT deliver($1,$2,$3,$4,$5,$6::text::jsonb,$7::text::jsonb,$8::text::jsonb,$9,$10,$11,$12,$13,$14,FALSE,now(),$15,$16,$17,0.0::real,$18::text::jsonb)",
            &[
                (&sentinel, Type::TEXT),
                (&message_id, Type::TEXT),
                (&from, Type::TEXT),
                (&"SetJoin Team", Type::TEXT),
                (&email, Type::TEXT),
                (&to, Type::TEXT),
                (&"[]", Type::TEXT),
                (&"[]", Type::TEXT),
                (&subject, Type::TEXT),
                (&"", Type::TEXT),
                (&"", Type::TEXT),
                (&body_text, Type::TEXT),
                (&body_html, Type::TEXT),
                (&size, Type::INT8),
                (&"none", Type::TEXT),
                (&"none", Type::TEXT),
                (&"none", Type::TEXT),
                (&"{}", Type::TEXT),
            ],
        )
        .await;
}

/// Go `resolveWelcomeTemplate(cfg, "")`: disabled or no usable locale sends nothing.
fn welcome_template(config: &serde_json::Value) -> Option<(String, String, String)> {
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
        assert!(filter::to_sql(&filter::parse("password_hash pr").unwrap()).is_err());
        assert!(matches!(
            filter::to_sql(&filter::parse("active co t").unwrap()),
            Ok(filter::Where::Rejected)
        ));
    }
}
