//! Admin identity (F01) slice `idv2-sources`, write half: strict request bodies and the
//! receipted reducer calls behind the source lifecycle, job cancel and conflict
//! decision routes. Every statement takes the actor from the verified context (`$2`),
//! never from the request, and runs on the worker credential as Go's `workerPool` does.
use super::{deadline, envelope, invalid, scope};
use serde_json::value::RawValue;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};
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
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT 'identity'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) {
    let auth = scope(actor);
    let _ = setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "reason_missing",
        },
        &envelope(&auth, operation, ip),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($4::text,'')::inet,'identity.write','core') \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&ip, Type::TEXT)],
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
        family: "F01",
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
    worker: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    action: &str,
    expected: i64,
    idempotency: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_source_lifecycle"),
        &envelope(&auth, operation, &format!("{key}:{action}:{expected}:{idempotency}:{reason}")),
        &auth,
        deadline(),
        "SELECT identity_source_lifecycle($2,$4,$5,$6,$7::text::uuid,$8)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&key, Type::TEXT),
            (&action, Type::TEXT),
            (&expected, Type::INT8),
            (&idempotency, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        |rows| body_of(rows, 0),
    )
    .await
}

/// What one atomic permission-check-then-mutate statement decided.
pub struct Verdict {
    pub status: u16,
    pub body: Option<String>,
}

pub(crate) fn verdict(rows: &[setjoin_pg::Row]) -> Result<Verdict, StatementFailure> {
    let row = rows.first().ok_or_else(invalid)?;
    let status: i32 = row.try_get(0).map_err(|_| invalid())?;
    Ok(Verdict {
        status: status as u16,
        body: row.try_get::<_, Option<String>>(1).map_err(|_| invalid())?,
    })
}

/// `POST .../jobs/{id}/cancel`: Go reads the job to re-check the kind's permission, then
/// cancels; here both run in one statement so the owner check and the mutation share a
/// snapshot. `held` lists the job kinds the caller's live global permissions allow.
pub async fn job_cancel(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    job: &str,
    held: &[String],
    operation: [u8; 16],
) -> CommandOutcome<Verdict, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_job_cancel"),
        &envelope(&auth, operation, job),
        &auth,
        deadline(),
        "SELECT q.s, CASE WHEN q.s = 202 THEN identity_job_cancel($2,$4::text::uuid)::text END \
         FROM (SELECT CASE WHEN j.r IS NULL THEN 404 WHEN NOT (j.r->>'kind' = ANY($5::text[])) THEN 403 ELSE 202 END AS s \
               FROM (SELECT identity_job_read($2,$4::text::uuid) AS r) j \
               WHERE $1::bigint > 0 AND $3::text <> '') q",
        &[(&job, Type::TEXT), (&held, Type::TEXT_ARRAY)],
        verdict,
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

/// `POST .../conflicts/{id}/decision`: Go's candidate lookup, scope check and
/// `identity_match_decide` as one statement (status 404/403 before the reducer, 200 after).
pub async fn conflict_decide(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    input: &DecideInput<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Verdict, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_match_decide"),
        &envelope(
            &auth,
            operation,
            &format!("{}:{}:{}:{:?}:{}", input.conflict, input.generation, input.decision, input.person, input.idempotency),
        ),
        &auth,
        deadline(),
        "SELECT q.s, CASE WHEN q.s = 200 THEN identity_match_decide($2,$4::text::uuid,$5,$6,$7,$8,$9::text::uuid)::text \
                          WHEN q.s = 403 THEN $10::text END \
         FROM (SELECT CASE WHEN c.id IS NULL THEN 404 \
                           WHEN c.candidate_user_id IS NULL AND $10::text <> '' THEN 403 \
                           WHEN c.candidate_user_id IS NOT NULL AND NOT identity_admin_scope_allows($2,c.candidate_user_id,'identity.write') THEN 404 \
                           ELSE 200 END AS s \
               FROM (SELECT 1) one LEFT JOIN identity_match_candidates c ON c.id = $4::text::uuid \
               WHERE $1::bigint > 0 AND $3::text <> '') q",
        &[
            (&input.conflict, Type::TEXT),
            (&input.generation, Type::INT8),
            (&input.decision, Type::TEXT),
            (&input.person, Type::INT8),
            (&input.reason, Type::TEXT),
            (&input.idempotency, Type::TEXT),
            (&input.unscoped_refusal, Type::TEXT),
        ],
        verdict,
    )
    .await
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

/// `PUT /admin/identity/group-mappings/{type}/{id}` on the request pool, as Go's `h.pool`.
pub async fn group_mappings_put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    provider_type: &str,
    provider_id: &str,
    mappings: &str,
    permissions: &[String],
    operation: [u8; 16],
) -> CommandOutcome<MappingVerdict, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("identity_group_mappings_put"),
        &envelope(&auth, operation, &format!("{provider_type}:{provider_id}:{mappings}")),
        &auth,
        deadline(),
        "SELECT rust_admin_group_mappings_put($2,$4,$5,$6,$7::text[])::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&provider_type, Type::TEXT),
            (&provider_id, Type::TEXT),
            (&mappings, Type::TEXT),
            (&permissions, Type::TEXT_ARRAY),
        ],
        |rows| {
            let text: String = rows.first().ok_or_else(invalid)?.try_get(0).map_err(|_| invalid())?;
            let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
            Ok(MappingVerdict {
                status: v["status"].as_u64().ok_or_else(invalid)? as u16,
                detail: v["detail"].as_str().unwrap_or_default().to_owned(),
            })
        },
    )
    .await
}
