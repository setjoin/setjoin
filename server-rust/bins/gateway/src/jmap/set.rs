//! General `Email/set` served by Rust (#315, #356): Go's `emailSet`, one phase.
//!
//! [`classify_call`] accepts `Email/set` with Go struct arguments
//! (`accountId`, `ifInState`, `create`, `update`, `destroy`, ASCII case-folded,
//! extra keys ignored) for a single active phase:
//! - `update`: `{}` (`SetPhase::Update("{}")`) or a map of numeric positive ids
//!   to patch objects without `snoozeUntil` (non-canonical numeric keys allowed;
//!   `destroy: []` or `null` alongside `update` is allowed).
//! - `destroy`: non-empty array of strings of any length (no 256 cap).
//!
//! `create` (non-null), `snoozeUntil`, mixed `update` + non-empty `destroy`,
//! and zero-phase (`{accountId}`) return `None` and defer to Wave 2 / Go via
//! preflight.
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{go_string_array_field, go_string_field, struct_arguments};
use super::get::parse_id;
use super::reply::marshal_sorted;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// `{"<id>": <patch>, ...}` with keys sorted, as Go re-marshals it.
    Update(String),
    Destroy {
        ids: Vec<i64>,
        bad: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetArgs {
    Valid {
        raw_account_id: String,
        phase: Phase,
    },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRequest {
    pub client_id: String,
    pub args: SetArgs,
}

pub fn classify_call(raw_args: &str, client_id: &str) -> Option<SetRequest> {
    let fields = struct_arguments(
        raw_args,
        &["accountId", "ifInState", "create", "update", "destroy"],
    )?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(detail) => {
                return Some(SetRequest {
                    client_id: client_id.to_owned(),
                    args: SetArgs::Invalid(detail),
                })
            }
        },
    };
    let destroy = match fields.get("destroy") {
        None => None,
        Some(raw) => match go_string_array_field(raw.get()) {
            Ok(None) => None,
            Ok(Some(items)) if items.is_empty() => None,
            Ok(Some(items)) => {
                let (mut ids, mut bad) = (Vec::new(), Vec::new());
                for item in items {
                    match parse_id(&item) {
                        Some(id) => ids.push(id),
                        None => bad.push(item),
                    }
                }
                Some((ids, bad))
            }
            Err(detail) => {
                return Some(SetRequest {
                    client_id: client_id.to_owned(),
                    args: SetArgs::Invalid(detail),
                })
            }
        },
    };
    if fields
        .get("create")
        .is_some_and(|raw| raw.get().trim() != "null")
    {
        return None;
    }
    let update = match fields.get("update") {
        None => None,
        Some(raw) if raw.get().trim() == "null" => None,
        Some(raw) => {
            let Value::Object(map) = serde_json::from_str::<Value>(raw.get()).ok()? else {
                return None;
            };
            if map.is_empty() {
                Some("{}".to_owned())
            } else {
                for (id, patch) in &map {
                    parse_id(id)?;
                    if !patch.as_object()?.keys().all(|k| k != "snoozeUntil") {
                        return None;
                    }
                }
                let patches: BTreeMap<String, Box<RawValue>> =
                    serde_json::from_str(raw.get()).ok()?;
                Some(marshal_sorted(&patches)?)
            }
        }
    };
    let phase = match (update, destroy) {
        (Some(patches), None) => Phase::Update(patches),
        (None, Some((ids, bad))) => Phase::Destroy { ids, bad },
        _ => return None,
    };
    Some(SetRequest {
        client_id: client_id.to_owned(),
        args: SetArgs::Valid {
            raw_account_id,
            phase,
        },
    })
}

/// Go's `mergeSetResults` for one phase: the object re-marshalled with sorted
/// keys. `None` when `raw` is not a JSON object.
pub fn merged(raw: &str) -> Option<String> {
    let object: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw).ok()?;
    marshal_sorted(&object)
}

/// Go's `addSetErrors(result, "notDestroyed", bad)` on the merged result.
pub fn add_not_destroyed(merged_result: &str, bad: &[String]) -> Option<String> {
    if bad.is_empty() {
        return Some(merged_result.to_owned());
    }
    let mut object: BTreeMap<String, Box<RawValue>> = serde_json::from_str(merged_result).ok()?;
    let mut bucket: BTreeMap<String, Box<RawValue>> = match object.get("notDestroyed") {
        Some(existing) => serde_json::from_str(existing.get()).unwrap_or_default(),
        None => BTreeMap::new(),
    };
    for id in bad {
        bucket.insert(
            id.clone(),
            RawValue::from_string(r#"{"type":"notFound"}"#.to_owned()).ok()?,
        );
    }
    object.insert(
        "notDestroyed".into(),
        RawValue::from_string(marshal_sorted(&bucket)?).ok()?,
    );
    marshal_sorted(&object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widened_set_handles_empty_update_empty_destroy_if_in_state_and_over_256() {
        let r = classify_call(
            r#"{"ACCOUNTID":"0012","ifInState":"1","create":null,"update":{"+20":{"keywords":{"$seen":true}},"003":{"mailboxIds":{"9":true}}},"destroy":[],"extra":1}"#,
            "c1",
        )
        .unwrap();
        assert_eq!(
            r.args,
            SetArgs::Valid {
                raw_account_id: "0012".into(),
                phase: Phase::Update(
                    r#"{"+20":{"keywords":{"$seen":true}},"003":{"mailboxIds":{"9":true}}}"#.into()
                ),
            }
        );

        let r = classify_call(r#"{"accountId":"12","update":{},"destroy":[]}"#, "c1").unwrap();
        assert_eq!(
            r.args,
            SetArgs::Valid {
                raw_account_id: "12".into(),
                phase: Phase::Update("{}".into()),
            }
        );

        let many = (1..=300)
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        let r = classify_call(&format!(r#"{{"accountId":"12","destroy":[{many}]}}"#), "c1").unwrap();
        assert!(matches!(
            r.args,
            SetArgs::Valid {
                phase: Phase::Destroy { ref ids, .. },
                ..
            } if ids.len() == 300
        ));
    }

    #[test]
    fn deferred_shapes_return_none() {
        for args in [
            r#"{"accountId":"12","create":{"a":{}}}"#,
            r#"{"accountId":"12","create":{}}"#,
            r#"{"accountId":"12","update":{"1":{"snoozeUntil":null}}}"#,
            r#"{"accountId":"12","update":{"1":{}},"destroy":["2"]}"#,
            r#"{"accountId":"12","update":{"x":{}}}"#,
            r#"{"accountId":"12","update":{"1":5}}"#,
            r#"{"accountId":"12"}"#,
            r#"{"accountId":"12","destroy":[]}"#,
        ] {
            assert_eq!(classify_call(args, "c1"), None, "{args}");
        }
    }

    #[test]
    fn go_merges_and_folds_bad_ids() {
        let raw = r#"{"newState": "2", "updated": [], "oldState": "1", "accountId": "12", "destroyed": [5], "notDestroyed": {"7": {"type": "notFound"}}}"#;
        let m = merged(raw).unwrap();
        assert_eq!(
            m,
            r#"{"accountId":"12","destroyed":[5],"newState":"2","notDestroyed":{"7":{"type":"notFound"}},"oldState":"1","updated":[]}"#
        );
        assert_eq!(
            add_not_destroyed(&m, &["a>".into(), "7".into()]).unwrap(),
            r#"{"accountId":"12","destroyed":[5],"newState":"2","notDestroyed":{"7":{"type":"notFound"},"a\u003e":{"type":"notFound"}},"oldState":"1","updated":[]}"#
        );
    }
}
