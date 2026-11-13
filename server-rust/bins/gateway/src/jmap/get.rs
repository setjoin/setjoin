//! `Email/get` served by Rust (#315): Go's `emailGet`.
//!
//! [`classify`] recognises one `Email/get` call whose arguments are `accountId`
//! (a canonical id string), a non-empty array of at most 256 strings `ids`, and
//! an optional `properties` (null or an array of strings). Any other shape
//! (other keys, non-string ids, no ids, over 256 ids, several calls, result
//! references) is `None` and the whole request goes to Go untouched.
//!
//! Go splits `ids` with `parseIDList`: a string is an id when it is a base-10
//! int64 greater than zero (an explicit `+` is accepted, leading zeros too);
//! every other string can never exist and is appended to the reducer's
//! `notFound` by `addNotFound`, which re-marshals the whole result as a map
//! (keys sorted) when there is at least one such string.
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{canonical_id, exact_keys, single_call};

pub const MAX_IDS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetRequest {
    pub account_id: i64,
    pub client_id: String,
    /// Go's `parseIDList` valid ids; `None` is Go's nil slice (NULL = all),
    /// which the classifier never produces for a request it claims, except
    /// that an all-malformed list is an empty non-nil slice.
    pub ids: Vec<i64>,
    /// Malformed ids, in request order.
    pub bad: Vec<String>,
    pub properties: Option<Vec<String>>,
}

pub fn classify(body: &[u8]) -> Option<GetRequest> {
    let call = single_call(body, "Email/get")?;
    let args = exact_keys(&call.args, &["accountId", "ids"], &["properties"])?;
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
    let raw_ids = args.get("ids")?.as_array()?;
    if raw_ids.is_empty() || raw_ids.len() > MAX_IDS {
        return None;
    }
    let (mut ids, mut bad) = (Vec::new(), Vec::new());
    for id in raw_ids {
        let id = id.as_str()?;
        match parse_id(id) {
            Some(v) => ids.push(v),
            None => bad.push(id.to_owned()),
        }
    }
    let properties = match args.get("properties") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|p| p.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?,
        ),
        Some(_) => return None,
    };
    Some(GetRequest {
        account_id,
        client_id: call.client_id,
        ids,
        bad,
        properties,
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

    fn call(args: &str) -> String {
        format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/get",{args},"c1"]]}}"#
        )
    }

    #[test]
    fn the_webmail_shape_is_claimed_and_ids_are_split() {
        let r = classify(
            call(r#"{"accountId":"12","ids":["5","+6","x","0","-3"],"properties":["subject"]}"#)
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(r.ids, vec![5, 6]);
        assert_eq!(r.bad, vec!["x", "0", "-3"]);
        assert_eq!(r.properties, Some(vec!["subject".to_owned()]));
    }

    #[test]
    fn anything_else_goes_to_go() {
        for args in [
            r#"{"accountId":"12"}"#,
            r#"{"accountId":"12","ids":[]}"#,
            r#"{"accountId":"12","ids":null}"#,
            r#"{"accountId":"12","ids":[1]}"#,
            r#"{"accountId":"12","ids":["1"],"properties":"subject"}"#,
            r#"{"accountId":"12","ids":["1"],"properties":[1]}"#,
            r#"{"accountId":"12","ids":["1"],"extra":1}"#,
            r#"{"accountId":12,"ids":["1"]}"#,
        ] {
            assert_eq!(classify(call(args).as_bytes()), None, "{args}");
        }
        let many = (0..257)
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            classify(call(&format!(r#"{{"accountId":"12","ids":[{many}]}}"#)).as_bytes()),
            None
        );
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
