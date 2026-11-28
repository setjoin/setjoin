//! General `Email/set` served by Rust (#315, #356 Wave 2a): Go's `emailSet`.
//!
//! [`classify_call`] accepts `Email/set` with Go struct arguments
//! (`accountId`, `ifInState`, `create`, `update`, `destroy`, ASCII case-folded,
//! extra keys ignored) for any combination of phases:
//! - `create`: JSON object (non-objects skipped like Go `jsonIsObject`);
//!   attachments undergo an R1-scoped `owned_blob_set` ownership gate before
//!   the main transaction.
//! - `update`: JSON object partitioned into `snoozeUntil` (non-null string
//!   parsing as RFC3339Nano, run per-message via `message_snooze`) and ordinary
//!   patches (run via `jmap_email_set_update` when non-empty).
//! - `destroy`: non-empty string array of any length (`[]` / `null` / absent
//!   skips `jmap_email_set_destroy`; non-empty arrays pass valid `i64`s to the
//!   reducer and fold malformed IDs into `notDestroyed`).
//! - zero-phase (`{accountId}` / `update: {}` / `destroy: []`): still writes
//!   one `email_set` audit row carrying `details.operation` inside `run_locked_tx`.
use std::collections::{BTreeMap, HashSet};

use serde_json::value::RawValue;
use serde_json::Value;
use setjoin_pg::ScopedExecutor;

use super::envelope::{go_string_array_field, go_string_field, struct_arguments};
use super::get::parse_id;
use super::reply::marshal_sorted;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetArgs {
    Valid {
        raw_account_id: String,
        /// Present when `create` is a JSON object (including `{}`).
        create: Option<String>,
        /// Present when ordinary `update` has >= 1 entry (sorted JSON object).
        ordinary_update: Option<String>,
        /// `(message_id_str, snooze_until_rfc3339)` pairs for `message_snooze`.
        snooze_updates: Vec<(String, String)>,
        /// Present when raw `destroy` array is non-empty (`(valid_ids, bad_ids)`).
        destroy: Option<(Vec<i64>, Vec<String>)>,
    },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRequest {
    pub client_id: String,
    pub args: SetArgs,
}

pub(super) struct GatedCreate {
    pub filtered_json: String,
    pub denied: BTreeMap<String, String>,
}

fn json_is_object(raw: &str) -> bool {
    raw.trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
}

/// Mirror Go's `parseSnoozeUntil` (`mail.go:53-65`): returns `Some(rfc3339)`
/// only when `snoozeUntil` (case-folded) is a non-null string parsing as
/// `time.RFC3339Nano`.
fn parse_snooze_until(patch_raw: &str) -> Option<String> {
    let Value::Object(map) = serde_json::from_str::<Value>(patch_raw).ok()? else {
        return None;
    };
    let mut found: Option<&Value> = None;
    for (k, v) in &map {
        if crate::guests_input::fold(k) == "snoozeuntil" {
            found = Some(v);
        }
    }
    let Value::String(s) = found? else {
        return None;
    };
    if s.len() < 20 || s.as_bytes().get(10) != Some(&b'T') || s.ends_with('z') {
        return None;
    }
    use chrono::Timelike;
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    if dt.nanosecond() >= 1_000_000_000 {
        return None;
    }
    Some(s.clone())
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
    let create = match fields.get("create") {
        None => None,
        Some(raw) if raw.get().trim() == "null" || !json_is_object(raw.get()) => None,
        Some(raw) => Some(raw.get().to_owned()),
    };
    let mut snooze_updates = Vec::new();
    let ordinary_update = match fields.get("update") {
        None => None,
        Some(raw) if raw.get().trim() == "null" || !json_is_object(raw.get()) => None,
        Some(raw) => {
            let map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw.get()).ok()?;
            let mut ordinary: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
            for (id, patch) in map {
                if let Some(until) = parse_snooze_until(patch.get()) {
                    snooze_updates.push((id, until));
                } else {
                    ordinary.insert(id, patch);
                }
            }
            if ordinary.is_empty() {
                None
            } else {
                Some(marshal_sorted(&ordinary)?)
            }
        }
    };
    Some(SetRequest {
        client_id: client_id.to_owned(),
        args: SetArgs::Valid {
            raw_account_id,
            create,
            ordinary_update,
            snooze_updates,
            destroy,
        },
    })
}

/// Extract non-empty `attachments[].blobId` strings from a creation entry,
/// mirroring Go's `attachmentRefs` decode. Returns `None` when malformed so the
/// creation stays in `filtered` for the reducer's own `notCreated` error.
fn extract_creation_blob_ids(raw: &str) -> Option<Vec<String>> {
    let val: Value = serde_json::from_str(raw).ok()?;
    let obj = match val {
        Value::Null => return Some(Vec::new()),
        Value::Object(obj) => obj,
        _ => return None,
    };
    let items = match obj.get("attachments") {
        None | Some(Value::Null) => return Some(Vec::new()),
        Some(Value::Array(items)) => items,
        _ => return None,
    };
    let mut out = Vec::new();
    for item in items {
        let item_obj = match item {
            Value::Null => continue,
            Value::Object(obj) => obj,
            _ => return None,
        };
        match item_obj.get("blobId") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => {
                if !s.is_empty() {
                    out.push(s.clone());
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Screen every creation's `attachments[].blobId` via `owned_blob_set` on the
/// BYPASSRLS worker pool before `run_locked_tx`. Fails closed on missing worker
/// or DB error when any attachment blob is referenced.
pub(super) async fn gate_attachment_blob_ownership(
    worker: Option<&ScopedExecutor>,
    actor: i64,
    raw_create: &str,
) -> Result<GatedCreate, ()> {
    let creates: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(raw_create).map_err(|_| ())?;
    let mut per_creation: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique: Vec<String> = Vec::new();
    for (id, raw) in &creates {
        let Some(ids) = extract_creation_blob_ids(raw.get()) else {
            // Fail closed: unverifiable attachment references must deny creation.
            per_creation.insert(id.clone(), None);
            continue;
        };
        for blob_id in &ids {
            if seen.insert(blob_id.clone()) {
                unique.push(blob_id.clone());
            }
        }
        per_creation.insert(id.clone(), Some(ids));
    }
    let has_unverifiable = per_creation.values().any(Option::is_none);
    if unique.is_empty() && !has_unverifiable {
        return Ok(GatedCreate {
            filtered_json: marshal_sorted(&creates).ok_or(())?,
            denied: BTreeMap::new(),
        });
    }
    let owned: HashSet<String> = if unique.is_empty() {
        HashSet::new()
    } else {
        let worker = worker.ok_or(())?;
        let rows = super::worker_read_contract(
            worker,
            &setjoin_jmap::sql::EMAIL_SET_OWNED_BLOBS,
            &[&unique, &actor],
        )
        .await
        .map_err(|_| ())?;
        setjoin_jmap::email_set::decode_owned_blob_set(&rows)
            .into_iter()
            .collect()
    };
    let mut filtered: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
    let mut denied: BTreeMap<String, String> = BTreeMap::new();
    for (id, raw) in creates {
        let blocked = match per_creation.get(&id) {
            Some(Some(ids)) => ids.iter().any(|blob_id| !owned.contains(blob_id)),
            _ => true,
        };
        if blocked {
            denied.insert(
                id,
                r#"{"description":"attachment blob is not owned by the authenticated account","type":"forbidden"}"#
                    .to_owned(),
            );
        } else {
            filtered.insert(id, raw);
        }
    }
    Ok(GatedCreate {
        filtered_json: marshal_sorted(&filtered).ok_or(())?,
        denied,
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
    merge_error_map(
        &mut object,
        "notDestroyed",
        bad.iter().map(|id| (id.as_str(), r#"{"type":"notFound"}"#)),
    )?;
    marshal_sorted(&object)
}

fn merge_error_map<'a>(
    object: &mut BTreeMap<String, Box<RawValue>>,
    key: &str,
    entries: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<()> {
    let mut bucket: BTreeMap<String, Box<RawValue>> = match object.get(key) {
        Some(existing) => serde_json::from_str(existing.get()).unwrap_or_default(),
        None => BTreeMap::new(),
    };
    let mut any = false;
    for (id, err_json) in entries {
        any = true;
        bucket.insert(
            id.to_owned(),
            RawValue::from_string(err_json.to_owned()).ok()?,
        );
    }
    if any {
        object.insert(
            key.into(),
            RawValue::from_string(marshal_sorted(&bucket)?).ok()?,
        );
    }
    Some(())
}

/// Merge reducer phase results, attachment ownership `notCreated` errors,
/// malformed `notDestroyed` IDs, and snooze results with Q1 `updated` shape:
/// - Pure ordinary OR ordinary + all-failed snoozes: `"updated": [<i64>, ...]`
/// - Pure snooze with >= 1 success: `"updated": {"<id>": null}`
/// - Mixed ordinary + >= 1 successful snooze: converts ordinary array IDs into
///   `"<id>": null` alongside successful snoozes in `"updated": { ... }`.
pub(super) fn merge_response(
    parts: &[String],
    denied_created: &BTreeMap<String, String>,
    bad_destroy: &[String],
    had_ordinary_update: bool,
    snooze_updated: &[String],
    snooze_not_updated: &[(String, String)],
) -> Option<String> {
    let mut root: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
    for part in parts {
        if let Ok(obj) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(part) {
            root.extend(obj);
        }
    }
    if !denied_created.is_empty() {
        merge_error_map(
            &mut root,
            "notCreated",
            denied_created.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        )?;
    }
    if !bad_destroy.is_empty() {
        merge_error_map(
            &mut root,
            "notDestroyed",
            bad_destroy
                .iter()
                .map(|id| (id.as_str(), r#"{"type":"notFound"}"#)),
        )?;
    }
    if !snooze_updated.is_empty() {
        let mut updated_map: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        if had_ordinary_update {
            if let Some(existing) = root.get("updated") {
                if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(existing.get()) {
                    for item in items {
                        let key = match item {
                            Value::Number(n) => n.to_string(),
                            Value::String(s) => s,
                            _ => continue,
                        };
                        updated_map.insert(key, RawValue::from_string("null".to_owned()).ok()?);
                    }
                }
            }
        }
        for id in snooze_updated {
            updated_map.insert(id.clone(), RawValue::from_string("null".to_owned()).ok()?);
        }
        root.insert(
            "updated".into(),
            RawValue::from_string(marshal_sorted(&updated_map)?).ok()?,
        );
    }
    if !snooze_not_updated.is_empty() {
        merge_error_map(
            &mut root,
            "notUpdated",
            snooze_not_updated
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )?;
    }
    marshal_sorted(&root)
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
                create: None,
                ordinary_update: Some(
                    r#"{"+20":{"keywords":{"$seen":true}},"003":{"mailboxIds":{"9":true}}}"#.into()
                ),
                snooze_updates: Vec::new(),
                destroy: None,
            }
        );

        let r = classify_call(r#"{"accountId":"12","update":{},"destroy":[]}"#, "c1").unwrap();
        assert_eq!(
            r.args,
            SetArgs::Valid {
                raw_account_id: "12".into(),
                create: None,
                ordinary_update: None,
                snooze_updates: Vec::new(),
                destroy: None,
            }
        );

        let many = (1..=300)
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        let r =
            classify_call(&format!(r#"{{"accountId":"12","destroy":[{many}]}}"#), "c1").unwrap();
        assert!(matches!(
            r.args,
            SetArgs::Valid {
                destroy: Some((ref ids, _)),
                ..
            } if ids.len() == 300
        ));
    }

    #[test]
    fn wave2a_claims_create_snooze_mixed_and_zero_phase() {
        let r = classify_call(
            r#"{"accountId":"12","create":{"a":{}},"update":{"1":{"snoozeUntil":"2026-12-01T08:00:00.000Z"},"2":{"snoozeUntil":null},"3":{"keywords":{"$seen":true}}},"destroy":["4","bad"]}"#,
            "c1",
        )
        .unwrap();
        assert_eq!(
            r.args,
            SetArgs::Valid {
                raw_account_id: "12".into(),
                create: Some(r#"{"a":{}}"#.into()),
                ordinary_update: Some(
                    r#"{"2":{"snoozeUntil":null},"3":{"keywords":{"$seen":true}}}"#.into()
                ),
                snooze_updates: vec![("1".into(), "2026-12-01T08:00:00.000Z".into())],
                destroy: Some((vec![4], vec!["bad".into()])),
            }
        );

        let zero = classify_call(r#"{"accountId":"12"}"#, "c1").unwrap();
        assert_eq!(
            zero.args,
            SetArgs::Valid {
                raw_account_id: "12".into(),
                create: None,
                ordinary_update: None,
                snooze_updates: Vec::new(),
                destroy: None,
            }
        );

        // Non-object create/update are skipped just like Go jsonIsObject.
        let non_obj =
            classify_call(r#"{"accountId":"12","create":[1],"update":123}"#, "c1").unwrap();
        assert_eq!(
            non_obj.args,
            SetArgs::Valid {
                raw_account_id: "12".into(),
                create: None,
                ordinary_update: None,
                snooze_updates: Vec::new(),
                destroy: None,
            }
        );
    }

    #[test]
    fn q1_updated_shape_matrix() {
        let ord =
            r#"{"accountId":"12","newState":"2","notUpdated":{},"oldState":"1","updated":[10]}"#
                .to_owned();
        // 1. Pure ordinary -> array
        assert_eq!(
            merge_response(&[ord.clone()], &BTreeMap::new(), &[], true, &[], &[]).unwrap(),
            r#"{"accountId":"12","newState":"2","notUpdated":{},"oldState":"1","updated":[10]}"#
        );
        // 2. Ordinary + all-failed snooze -> array kept
        assert_eq!(
            merge_response(
                &[ord.clone()],
                &BTreeMap::new(),
                &[],
                true,
                &[],
                &[(
                    "bad".into(),
                    r#"{"description":"invalid message id","type":"invalidArguments"}"#.into()
                )],
            )
            .unwrap(),
            r#"{"accountId":"12","newState":"2","notUpdated":{"bad":{"description":"invalid message id","type":"invalidArguments"}},"oldState":"1","updated":[10]}"#
        );
        // 3. Pure snooze -> object map
        assert_eq!(
            merge_response(&[], &BTreeMap::new(), &[], false, &["5".into()], &[]).unwrap(),
            r#"{"updated":{"5":null}}"#
        );
        // 4. Mixed ordinary + >=1 successful snooze -> object map preserving both
        assert_eq!(
            merge_response(&[ord], &BTreeMap::new(), &[], true, &["5".into()], &[]).unwrap(),
            r#"{"accountId":"12","newState":"2","notUpdated":{},"oldState":"1","updated":{"10":null,"5":null}}"#
        );
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
