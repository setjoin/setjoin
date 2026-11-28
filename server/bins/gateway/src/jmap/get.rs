//! `Email/get` served by Rust (#315, #356): Go's `emailGet`.
//!
//! [`classify_call`] accepts `Email/get` with Go struct arguments (`accountId`,
//! `ids`, `properties`, case-folded ASCII keys, extra keys ignored): `ids` may
//! be absent, `null`, `[]`, or any length (`> 256` returns `requestTooLarge`
//! natively after `resolve_account`). Invalid field types return
//! `invalidArguments`.
//!
//! Go splits `ids` with `parseIDList`: a string is an id when it is a base-10
//! int64 greater than zero (an explicit `+` is accepted, leading zeros too);
//! every other string can never exist and is appended to the reducer's
//! `notFound` by `addNotFound`, which re-marshals the whole result as a map
//! (keys sorted) when there is at least one such string.
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{go_string_array_field, go_string_field, struct_arguments};

pub const MAX_IDS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetArgs {
    Valid {
        raw_account_id: String,
        /// Go's `parseIDList` valid ids; empty when `ids` was absent/`null`/`[]`
        /// or all-malformed.
        ids: Vec<i64>,
        /// Malformed ids, in request order.
        bad: Vec<String>,
        properties: Option<Vec<String>>,
        too_many: bool,
    },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetRequest {
    pub client_id: String,
    pub args: GetArgs,
}

pub fn classify_call(raw_args: &str, client_id: &str) -> Option<GetRequest> {
    let fields = struct_arguments(raw_args, &["accountId", "ids", "properties"])?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(detail) => {
                return Some(GetRequest {
                    client_id: client_id.to_owned(),
                    args: GetArgs::Invalid(detail),
                })
            }
        },
    };
    let raw_ids = match fields.get("ids") {
        None => Vec::new(),
        Some(raw) => match go_string_array_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(detail) => {
                return Some(GetRequest {
                    client_id: client_id.to_owned(),
                    args: GetArgs::Invalid(detail),
                })
            }
        },
    };
    let properties = match fields.get("properties") {
        None => None,
        Some(raw) => match go_string_array_field(raw.get()) {
            Ok(opt) => opt,
            Err(detail) => {
                return Some(GetRequest {
                    client_id: client_id.to_owned(),
                    args: GetArgs::Invalid(detail),
                })
            }
        },
    };
    let too_many = raw_ids.len() > MAX_IDS;
    let (mut ids, mut bad) = (Vec::new(), Vec::new());
    if !too_many {
        for id in raw_ids {
            match parse_id(&id) {
                Some(v) => ids.push(v),
                None => bad.push(id),
            }
        }
    }
    Some(GetRequest {
        client_id: client_id.to_owned(),
        args: GetArgs::Valid {
            raw_account_id,
            ids,
            bad,
            properties,
            too_many,
        },
    })
}

/// Go's `parseID`: `strconv.ParseInt(id, 10, 64)` and `v > 0`.
pub fn parse_id(id: &str) -> Option<i64> {
    id.parse::<i64>().ok().filter(|v| *v > 0)
}

/// Go's `addNotFound`: unchanged when `bad` is empty; otherwise the result
/// object re-marshalled with sorted keys, raw values compacted, and `bad`
/// appended to `notFound`. `None` when `raw` is not a JSON object (Go returns
/// the input unchanged then; the caller forwards).
pub fn add_not_found(raw: &str, bad: &[String]) -> Option<String> {
    if bad.is_empty() {
        return Some(raw.to_owned());
    }
    let mut object: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw).ok()?;
    let mut found: Vec<Value> = match object.get("notFound") {
        Some(existing) => serde_json::from_str(existing.get()).unwrap_or_default(),
        None => Vec::new(),
    };
    found.extend(bad.iter().cloned().map(Value::String));
    object.insert(
        "notFound".into(),
        RawValue::from_string(serde_json::to_string(&found).ok()?).ok()?,
    );
    super::reply::marshal_sorted(&object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widened_get_handles_empty_null_extra_and_over_256() {
        let r = classify_call(
            r#"{"ACCOUNTID":"0012","ids":["5","+6","x","0","-3"],"properties":["subject"],"extra":1}"#,
            "c1",
        )
        .unwrap();
        assert_eq!(
            r.args,
            GetArgs::Valid {
                raw_account_id: "0012".into(),
                ids: vec![5, 6],
                bad: vec!["x".into(), "0".into(), "-3".into()],
                properties: Some(vec!["subject".to_owned()]),
                too_many: false,
            }
        );

        for args in [
            r#"{"accountId":"12"}"#,
            r#"{"accountId":"12","ids":[]}"#,
            r#"{"accountId":"12","ids":null}"#,
        ] {
            let r = classify_call(args, "c1").unwrap();
            assert_eq!(
                r.args,
                GetArgs::Valid {
                    raw_account_id: "12".into(),
                    ids: vec![],
                    bad: vec![],
                    properties: None,
                    too_many: false,
                },
                "{args}"
            );
        }

        let many = (0..257)
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        let r = classify_call(&format!(r#"{{"accountId":"12","ids":[{many}]}}"#), "c1").unwrap();
        assert!(matches!(r.args, GetArgs::Valid { too_many: true, .. }));

        for bad_args in [
            r#"{"accountId":"12","ids":[1]}"#,
            r#"{"accountId":"12","ids":["1"],"properties":"subject"}"#,
            r#"{"accountId":"12","ids":["1"],"properties":[1]}"#,
            r#"{"accountId":12,"ids":["1"]}"#,
        ] {
            let r = classify_call(bad_args, "c1").unwrap();
            assert!(matches!(r.args, GetArgs::Invalid(_)), "{bad_args}");
        }
    }

    #[test]
    fn not_found_is_re_marshalled_like_go() {
        let raw = r#"{"list": [], "state": "3", "notFound": null, "accountId": "12"}"#;
        assert_eq!(add_not_found(raw, &[]).as_deref(), Some(raw));
        assert_eq!(
            add_not_found(raw, &["a<b".to_owned()]).as_deref(),
            Some(r#"{"accountId":"12","list":[],"notFound":["a\u003cb"],"state":"3"}"#)
        );
        let raw = r#"{"list": [], "state": "3", "notFound": ["9"], "accountId": "12"}"#;
        assert_eq!(
            add_not_found(raw, &["x".to_owned()]).as_deref(),
            Some(r#"{"accountId":"12","list":[],"notFound":["9","x"],"state":"3"}"#)
        );
    }
}
