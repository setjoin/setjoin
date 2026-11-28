//! Admin identity (F01) slice `idv2-sources`, write half: strict request bodies and the
//! receipted reducer calls behind the source lifecycle, job cancel and conflict
//! decision routes. Every statement takes the actor from the verified context (`$2`),
//! never from the request, and runs on the worker credential as Go's `workerPool` does.
use super::{deadline, envelope, invalid, sql, FAMILY};
use serde_json::value::RawValue;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};
use std::collections::BTreeMap;

/// Go's `identityBodyMaxBytes`.
pub const BODY_MAX: usize = 64 << 10;

/// Why a body was refused before any statement ran.
pub enum BodyError {
    /// `*http.MaxBytesError`: 413.
    TooLarge,
    /// Any other decode failure: the route's 400 detail.
    Invalid,
}

/// Go's `decodeIdentityJSON` (strict) for an object-shaped request: the first JSON value
/// is a struct whose members are all among `names` (matched case-insensitively), then
/// EOF. `null` decodes to the zero struct. Returns the raw member values by field name,
/// the last duplicate winning.
pub fn strict_object(
    body: &[u8],
    names: &[&'static str],
) -> Result<BTreeMap<&'static str, Box<RawValue>>, BodyError> {
    let text = single_value(body)?;
    if text.trim() == "null" {
        return Ok(BTreeMap::new());
    }
    fields(text, names)
}

/// Go's `Decode(&v)` then `Decode(&struct{})` is EOF: the body is exactly one JSON value
/// within the 64 KiB cap; returns that value's text.
pub fn single_value(body: &[u8]) -> Result<&str, BodyError> {
    let limited = &body[..body.len().min(BODY_MAX + 1)];
    let mut stream = serde_json::Deserializer::from_slice(limited).into_iter::<&RawValue>();
    let first = match stream.next() {
        Some(Ok(raw)) => raw,
        Some(Err(e)) if e.is_eof() && body.len() > BODY_MAX => return Err(BodyError::TooLarge),
        _ => return Err(BodyError::Invalid),
    };
    if body.len() > BODY_MAX && stream.byte_offset() > BODY_MAX {
        return Err(BodyError::TooLarge);
    }
    // The second Decode must report EOF; any other outcome (a value, bad syntax, or a
    // read past the cap) is the route's 400.
    if stream.next().is_some() {
        return Err(BodyError::Invalid);
    }
    if body.len() > BODY_MAX {
        return Err(BodyError::Invalid);
    }
    Ok(first.get())
}

/// A struct's members (names matched case-insensitively, unknown ones refused).
fn fields(
    text: &str,
    names: &[&'static str],
) -> Result<BTreeMap<&'static str, Box<RawValue>>, BodyError> {
    let members = members(text).ok_or(BodyError::Invalid)?;
    let mut out = BTreeMap::new();
    for (key, value) in members {
        let wanted = names
            .iter()
            .find(|n| **n == key)
            .or_else(|| names.iter().find(|n| super::fold(n) == super::fold(&key)));
        let Some(name) = wanted else {
            return Err(BodyError::Invalid);
        };
        out.insert(*name, value);
    }
    Ok(out)
}

/// The members of a JSON object in document order (duplicates kept, so the last wins when
/// folded into a map); `None` when the text is not an object.
pub fn members(text: &str) -> Option<Vec<(String, Box<RawValue>)>> {
    struct Pairs(Vec<(String, Box<RawValue>)>);
    impl<'de> serde::Deserialize<'de> for Pairs {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Pairs;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Pairs, A::Error> {
                    let mut out = Vec::new();
                    while let Some(entry) = map.next_entry::<String, Box<RawValue>>()? {
                        out.push(entry);
                    }
                    Ok(Pairs(out))
                }
            }
            d.deserialize_map(V)
        }
    }
    serde_json::from_str::<Pairs>(text).ok().map(|p| p.0)
}

/// A string member: absent or `null` is the zero value, any other type is a decode error.
pub fn text(
    members: &BTreeMap<&'static str, Box<RawValue>>,
    name: &str,
) -> Result<String, BodyError> {
    match members.get(name) {
        None => Ok(String::new()),
        Some(raw) => match serde_json::from_str::<Option<String>>(raw.get()) {
            Ok(value) => Ok(value.unwrap_or_default()),
            Err(_) => Err(BodyError::Invalid),
        },
    }
}

/// Go's `validIdentityReason`.
pub fn valid_reason(reason: &str) -> bool {
    reason.len() <= 1024
        && !reason.trim().is_empty()
        && reason.chars().all(|c| c >= '\u{20}' && c != '\u{7f}')
}

/// Go's `RequireReason(identity.write)`: whether `identity` is a reason-required area.
pub async fn reason_required(factory: &TxFactory, admin: &AdminPermissionProof) -> bool {
    let area = "identity";
    factory
        .run_admin_read_contract(admin, &sql::REASON_REQUIRED_AREA, &[&area])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let perm = "identity.write";
    let env = envelope(user.user(), user.generation(), operation, ip);
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MISSING_REASON_AUDIT,
            &[&actor, &ip, &perm],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "reason_missing",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .map(|_| ())
                    .ok_or_else(invalid)
            },
        )
        .await;
}

pub(crate) fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// The reducer's jsonb text of a committed call (`None` is SQL NULL).
fn body_of(rows: &[setjoin_pg::Row], index: usize) -> Result<Option<String>, StatementFailure> {
    let row = rows.first().ok_or_else(invalid)?;
    row.try_get::<_, Option<String>>(index)
        .map_err(|_| invalid())
}

/// `POST .../sources/{sourceKey}/{pause,resume,retire,activate}`: Go's one reducer call.
#[allow(clippy::too_many_arguments)]
pub async fn lifecycle(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    key: &str,
    action: &str,
    expected: i64,
    idempotency: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{key}:{action}:{expected}:{idempotency}:{reason}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::IDV2_SOURCE_LIFECYCLE,
            &[&actor, &key, &action, &expected, &idempotency, &reason],
            Some(command("identity_source_lifecycle")),
            |rows| body_of(&rows, 0),
        )
        .await
}

/// What one atomic permission-check-then-mutate statement decided.
pub struct Verdict {
    pub status: u16,
    pub body: Option<String>,
}

/// Decode a `(status, body)` row from `job_cancel`, `conflict_decide`, or a transition op.
pub fn parse_verdict(rows: &[setjoin_pg::Row]) -> Result<Verdict, StatementFailure> {
    let row = rows.first().ok_or_else(invalid)?;
    let status: i32 = row.try_get(0).map_err(|_| invalid())?;
    Ok(Verdict {
        status: status as u16,
        body: row.try_get::<_, Option<String>>(1).map_err(|_| invalid())?,
    })
}

/// `POST .../jobs/{id}/cancel`.
pub async fn job_cancel(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    job: &str,
    held: &[String],
    operation: [u8; 16],
) -> CommandOutcome<Verdict, StatementFailure> {
    let actor = user.user().get();
    let held_vec = held.to_vec();
    let env = envelope(user.user(), user.generation(), operation, job);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::IDV2_JOB_CANCEL,
            &[&actor, &job, &held_vec],
            Some(command("identity_job_cancel")),
            |rows| parse_verdict(&rows),
        )
        .await
}

/// The refusal a conflict decision statement can answer without running the reducer.
pub struct DecideInput<'a> {
    pub conflict: &'a str,
    pub generation: i64,
    pub decision: &'a str,
    pub person: Option<i64>,
    pub reason: &'a str,
    pub idempotency: &'a str,
    /// `""` when the caller passes `requireUnscopedIdentityAdmin`, else Go's 403 detail.
    pub unscoped_refusal: &'a str,
}

/// One `groupMapping` after Go's decode.
pub struct GroupMapping {
    pub group: String,
    pub distribution: Option<i64>,
    pub role: Option<String>,
    pub department: Option<i64>,
}

/// `json.NewDecoder(body).Decode(&[]groupMapping)`: the first value only (trailing bytes
/// are never read); any type error is Go's "invalid JSON". `null` is an empty list.
pub fn decode_group_mappings(body: &[u8]) -> Option<Vec<GroupMapping>> {
    use serde_json::Value;
    let first = serde_json::Deserializer::from_slice(body)
        .into_iter::<&RawValue>()
        .next();
    let Some(Ok(raw)) = first else {
        return None;
    };
    let items = match serde_json::from_str::<Value>(raw.get()).ok()? {
        Value::Null => return Some(Vec::new()),
        Value::Array(items) => items,
        _ => return None,
    };
    let text = |v: Option<&Value>| match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(()),
    };
    let number = |v: Option<&Value>| match v {
        None | Some(Value::Null) => Ok(None),
        Some(n @ Value::Number(_)) if n.is_i64() => Ok(n.as_i64()),
        Some(_) => Err(()),
    };
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        let object = match item {
            Value::Null => {
                out.push(GroupMapping {
                    group: String::new(),
                    distribution: None,
                    role: None,
                    department: None,
                });
                continue;
            }
            Value::Object(object) => object,
            _ => return None,
        };
        let member = |name: &str| {
            object.get(name).or_else(|| {
                object
                    .iter()
                    .find(|(k, _)| super::fold(k) == name)
                    .map(|(_, v)| v)
            })
        };
        out.push(GroupMapping {
            group: text(member("idp_group")).ok()?.unwrap_or_default(),
            distribution: number(member("distribution_group_id")).ok()?,
            role: text(member("admin_role")).ok()?,
            department: number(member("department_id")).ok()?,
        });
    }
    Some(out)
}

/// `identity.ValidateSSOGroupMappings`: Go's 400 text for a bad entry.
pub fn validate_group_mappings(list: &[GroupMapping]) -> Result<(), String> {
    if list.len() > 100 {
        return Err(format!(
            "SSO group mapping has {} entries; maximum is 100",
            list.len()
        ));
    }
    for (i, m) in list.iter().enumerate() {
        if m.group.trim().is_empty() {
            return Err(format!(
                "SSO group mapping entry {i} has an empty IdP group"
            ));
        }
        if m.group.len() > 1024 {
            return Err(format!("SSO group mapping entry {i} exceeds 1024 bytes"));
        }
        if m.group.chars().any(|c| c.is_control()) {
            return Err(format!(
                "SSO group mapping entry {i} contains a control character"
            ));
        }
    }
    Ok(())
}

/// `json.Marshal([]groupMapping)`.
pub fn render_group_mappings(list: &[GroupMapping]) -> String {
    let items: Vec<String> = list
        .iter()
        .map(|m| {
            let mut text = format!("{{\"idp_group\":{}", super::s(&m.group));
            if let Some(n) = m.distribution {
                text.push_str(&format!(",\"distribution_group_id\":{n}"));
            }
            if let Some(role) = &m.role {
                text.push_str(&format!(",\"admin_role\":{}", super::s(role)));
            }
            if let Some(n) = m.department {
                text.push_str(&format!(",\"department_id\":{n}"));
            }
            text.push('}');
            text
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// What `rust_admin_group_mappings_put` decided.
pub struct MappingVerdict {
    pub status: u16,
    pub detail: String,
}

/// Decode the reducer verdict returned by `sql::IDV2_GROUP_MAPPINGS_PUT`.
pub fn parse_mapping_verdict(rows: &[setjoin_pg::Row]) -> Result<MappingVerdict, StatementFailure> {
    let text: String = rows
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    Ok(MappingVerdict {
        status: v["status"].as_u64().ok_or_else(invalid)? as u16,
        detail: v["detail"].as_str().unwrap_or_default().to_owned(),
    })
}
