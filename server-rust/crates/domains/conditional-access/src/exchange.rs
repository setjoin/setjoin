//! Conditional access (F03) slice `remaining`: policy export and diff. Both are reads that
//! repeat Go's queries and render Go's structs field for field.
use super::policies::compact;
use super::{done, invalid, s};
use serde_json::Value;
use setjoin_pg::{ScopedExecutor, StatementFailure};
use std::collections::BTreeMap;

fn bad<E>(_: E) -> StatementFailure {
    invalid()
}

/// `json.Unmarshal(text, &[]string)` with Go's error-ignoring caller: an array gives its
/// strings (a non-string element is the empty string), anything else leaves the nil slice.
fn string_slice(text: &str) -> Option<Vec<String>> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => Some(
            items
                .into_iter()
                .map(|v| match v {
                    Value::String(text) => text,
                    _ => String::new(),
                })
                .collect(),
        ),
        _ => None,
    }
}

/// `json.Unmarshal(text, &[][]string)` likewise: an element that is not an array of strings is
/// a nil (`null`) inner slice.
fn nested_slice(text: &str) -> Option<Vec<Option<Vec<String>>>> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => Some(
            items
                .into_iter()
                .map(|v| match v {
                    Value::Array(inner) => Some(
                        inner
                            .into_iter()
                            .map(|v| match v {
                                Value::String(text) => text,
                                _ => String::new(),
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

fn strings(list: &Option<Vec<String>>) -> String {
    match list {
        None => "null".into(),
        Some(items) => format!(
            "[{}]",
            items.iter().map(|i| s(i)).collect::<Vec<_>>().join(",")
        ),
    }
}

/// `GET .../export`: `{schemaVersion, generatedBy, policies, named_locations, auth_strengths}`
/// of the live rows.
pub async fn export(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT name, description, priority, scope_type, scope_target, conditions::text, actions::text \
             FROM conditional_access_policies WHERE deleted_at IS NULL ORDER BY priority ASC",
            &[],
        )
        .await?;
    let mut policies = Vec::new();
    for r in &rows {
        let mut item = format!("{{\"name\":{}", s(&r.try_get::<_, String>(0).map_err(bad)?));
        let description: String = r.try_get(1).map_err(bad)?;
        if !description.is_empty() {
            item.push_str(&format!(",\"description\":{}", s(&description)));
        }
        item.push_str(&format!(
            ",\"priority\":{}",
            r.try_get::<_, i32>(2).map_err(bad)?
        ));
        for (index, key) in [(3usize, "scope_type"), (4, "scope_target")] {
            let text: String = r.try_get(index).map_err(bad)?;
            if !text.is_empty() {
                item.push_str(&format!(",\"{key}\":{}", s(&text)));
            }
        }
        for (index, key) in [(5usize, "conditions"), (6, "actions")] {
            if let Some(text) = r.try_get::<_, Option<String>>(index).map_err(bad)? {
                item.push_str(&format!(",\"{key}\":{}", compact(&text)));
            }
        }
        item.push('}');
        policies.push(item);
    }
    let rows = exec
        .read(
            "SELECT id, name, ip_ranges::text, countries::text, is_trusted FROM named_locations WHERE deleted_at IS NULL",
            &[],
        )
        .await?;
    let mut locations = Vec::new();
    for r in &rows {
        locations.push(format!(
            "{{\"id\":{},\"name\":{},\"cidrs\":{},\"countries\":{},\"trusted\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            strings(&string_slice(&r.try_get::<_, String>(2).map_err(bad)?)),
            strings(&string_slice(&r.try_get::<_, String>(3).map_err(bad)?)),
            r.try_get::<_, bool>(4).map_err(bad)?
        ));
    }
    let rows = exec
        .read(
            "SELECT id, slug, name, builtin, requirement::text, min_acr FROM auth_strengths",
            &[],
        )
        .await?;
    let mut strengths = Vec::new();
    for r in &rows {
        let combinations = match nested_slice(&r.try_get::<_, String>(4).map_err(bad)?) {
            None => "null".to_string(),
            Some(list) => format!(
                "[{}]",
                list.iter()
                    .map(strings)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        strengths.push(format!(
            "{{\"id\":{},\"slug\":{},\"name\":{},\"builtin\":{},\"combinations\":{},\"min_acr\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            r.try_get::<_, bool>(3).map_err(bad)?,
            combinations,
            s(&r.try_get::<_, String>(5).map_err(bad)?),
        ));
    }
    Ok(done(format!(
        "{{\"schemaVersion\":1,\"generatedBy\":\"setjoin\",\"policies\":[{}],\"named_locations\":[{}],\"auth_strengths\":[{}]}}",
        policies.join(","),
        locations.join(","),
        strengths.join(",")
    )))
}

/// One policy of a document handed to diff: the raw `conditions`/`actions` texts when present.
pub struct DocPolicy {
    pub name: String,
    pub conditions: Option<String>,
    pub actions: Option<String>,
}

/// `POST .../diff`: `{added, changed, removed}` of names against the live rows; the
/// fingerprint is the compacted conditions plus actions, so key order still counts. Go ranges a
/// map for `removed` (random order); this answers in name order.
pub async fn diff(
    exec: &ScopedExecutor,
    policies: &[DocPolicy],
) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT name, conditions::text, actions::text FROM conditional_access_policies WHERE deleted_at IS NULL",
            &[],
        )
        .await?;
    let fingerprint = |conditions: Option<&str>, actions: Option<&str>| {
        compact(conditions.unwrap_or("{}")) + &compact(actions.unwrap_or("{}"))
    };
    let mut live: BTreeMap<String, String> = BTreeMap::new();
    for r in &rows {
        live.insert(
            r.try_get::<_, String>(0).map_err(bad)?,
            fingerprint(
                r.try_get::<_, Option<String>>(1).map_err(bad)?.as_deref(),
                r.try_get::<_, Option<String>>(2).map_err(bad)?.as_deref(),
            ),
        );
    }
    let name = |n: &str| format!("{{\"name\":{}}}", s(n));
    let (mut added, mut changed) = (Vec::new(), Vec::new());
    let mut in_doc = std::collections::BTreeSet::new();
    for p in policies {
        in_doc.insert(p.name.clone());
        match live.get(&p.name) {
            None => added.push(name(&p.name)),
            Some(existing) => {
                if fingerprint(p.conditions.as_deref(), p.actions.as_deref()) != *existing {
                    changed.push(name(&p.name));
                }
            }
        }
    }
    let removed: Vec<String> = live
        .keys()
        .filter(|n| !in_doc.contains(*n))
        .map(|n| name(n))
        .collect();
    Ok(done(format!(
        "{{\"added\":[{}],\"changed\":[{}],\"removed\":[{}]}}",
        added.join(","),
        changed.join(","),
        removed.join(",")
    )))
}
