//! General `Email/set` served by Rust (#315): Go's `emailSet`, one phase.
//!
//! [`classify`] recognises one `Email/set` call with `accountId` and exactly
//! one non-empty phase: `update` (an object of canonical message ids to patch
//! objects, none naming `snoozeUntil`) or `destroy` (an array of at most 256
//! strings); `create` must be absent or null. Anything else (create, snooze
//! patches, several phases, `ifInState`, other keys) is `None` and the whole
//! request goes to Go untouched: those need Go's attachment-blob gate, the
//! per-message snooze calls or a multi-reducer batch.
//!
//! The answer is Go's: the reducer's JSONB re-marshalled as a map
//! ([`super::reply::marshal_sorted`]), and for `destroy` the malformed ids
//! folded into `notDestroyed` as `{"type":"notFound"}` (`addSetErrors`).
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{canonical_id, single_call};
use super::get::parse_id;
use super::reply::marshal_sorted;

pub const MAX_DESTROY: usize = 256;

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
pub struct SetRequest {
    pub account_id: i64,
    pub client_id: String,
    pub phase: Phase,
}

pub fn classify(body: &[u8]) -> Option<SetRequest> {
    let call = single_call(body, "Email/set")?;
    let raw: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&call.raw_args).ok()?;
    if raw
        .keys()
        .any(|k| !["accountId", "create", "update", "destroy"].contains(&k.as_str()))
    {
        return None;
    }
    let account_id = canonical_id(call.args.get("accountId")?.as_str()?)?;
    if !matches!(call.args.get("create"), None | Some(Value::Null)) {
        return None;
    }
    let update = match call.args.get("update") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) if !map.is_empty() => Some(map),
        Some(_) => return None,
    };
    let destroy = match call.args.get("destroy") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_DESTROY => Some(items),
        Some(_) => return None,
    };
    let phase = match (update, destroy) {
        (Some(update), None) => {
            for (id, patch) in update {
                canonical_id(id)?;
                if !patch.as_object()?.keys().all(|k| k != "snoozeUntil") {
                    return None;
                }
            }
            let patches: BTreeMap<String, Box<RawValue>> =
                serde_json::from_str(raw.get("update")?.get()).ok()?;
            Phase::Update(marshal_sorted(&patches)?)
        }
        (None, Some(items)) => {
            let (mut ids, mut bad) = (Vec::new(), Vec::new());
            for item in items {
                let item = item.as_str()?;
                match parse_id(item) {
                    Some(id) => ids.push(id),
                    None => bad.push(item.to_owned()),
                }
            }
            Phase::Destroy { ids, bad }
        }
        _ => return None,
    };
    Some(SetRequest {
        account_id,
        client_id: call.client_id,
        phase,
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

    fn parse(args: &str) -> Option<SetRequest> {
        classify(
            format!(
                r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{args},"c1"]]}}"#
            )
            .as_bytes(),
        )
    }

    #[test]
    fn update_patches_are_sorted_and_compact() {
        let r = parse(r#"{"accountId":"12","create":null,"update":{"20":{"keywords":{"$seen":true}},"3":{"mailboxIds":{"9":true}}},"destroy":null}"#)
            .unwrap();
        assert_eq!(
            r.phase,
            Phase::Update(
                r#"{"20":{"keywords":{"$seen":true}},"3":{"mailboxIds":{"9":true}}}"#.into()
            )
        );
    }

    #[test]
    fn destroy_splits_malformed_ids() {
        let r = parse(r#"{"accountId":"12","destroy":["5","x","+6"]}"#).unwrap();
        assert_eq!(
            r.phase,
            Phase::Destroy {
                ids: vec![5, 6],
                bad: vec!["x".into()]
            }
        );
    }

    #[test]
    fn anything_else_goes_to_go() {
        for args in [
            r#"{"accountId":"12","create":{"a":{}}}"#,
            r#"{"accountId":"12","update":{"1":{"snoozeUntil":null}}}"#,
            r#"{"accountId":"12","update":{"1":{}},"destroy":["2"]}"#,
            r#"{"accountId":"12","update":{"x":{}}}"#,
            r#"{"accountId":"12","update":{}}"#,
            r#"{"accountId":"12","destroy":[]}"#,
            r#"{"accountId":"12","update":{"1":5}}"#,
            r#"{"accountId":"12","ifInState":"1","destroy":["2"]}"#,
            r#"{"accountId":"12"}"#,
        ] {
            assert_eq!(parse(args), None, "{args}");
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
