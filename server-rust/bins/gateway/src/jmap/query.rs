//! General `Email/query` served by Rust (#315): Go's `emailQuery`.
//!
//! [`classify`] recognises one `Email/query` call whose arguments are
//! `accountId` (a canonical id string) and optionally `filter`, `sort`
//! (any JSON, passed to the reducer exactly as written, `null` included),
//! `position` (an integer in `i32`) and `limit` (an integer). The reducer
//! `jmap_email_query` owns every filter and sort. `limit` is clamped as Go
//! clamps it (`<= 0` or `> 256` is 50). Other keys, non-integer numbers,
//! several calls and result references are `None`: the request goes to Go.
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{canonical_id, single_call};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRequest {
    pub account_id: i64,
    pub client_id: String,
    /// Go's `RawMessage`: `None` when the key is absent.
    pub filter: Option<String>,
    pub sort: Option<String>,
    pub position: i32,
    pub limit: i32,
}

pub fn classify(body: &[u8]) -> Option<QueryRequest> {
    let call = single_call(body, "Email/query")?;
    let raw: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&call.raw_args).ok()?;
    if raw
        .keys()
        .any(|k| !["accountId", "filter", "sort", "position", "limit"].contains(&k.as_str()))
    {
        return None;
    }
    let account_id = canonical_id(call.args.get("accountId")?.as_str()?)?;
    let integer = |name: &str| -> Option<Option<i64>> {
        match call.args.get(name) {
            None => Some(None),
            Some(Value::Number(n)) => n.as_i64().map(Some),
            Some(_) => None,
        }
    };
    let position = match integer("position")? {
        None => 0,
        Some(n) => i32::try_from(n).ok()?,
    };
    let limit = match integer("limit")? {
        Some(n) if (1..=256).contains(&n) => n as i32,
        _ => 50,
    };
    Some(QueryRequest {
        account_id,
        client_id: call.client_id,
        filter: raw.get("filter").map(|v| v.get().to_owned()),
        sort: raw.get("sort").map(|v| v.get().to_owned()),
        position,
        limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &str) -> Option<QueryRequest> {
        classify(
            format!(
                r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{args},"c1"]]}}"#
            )
            .as_bytes(),
        )
    }

    #[test]
    fn filter_and_sort_pass_through_as_written() {
        let r = parse(r#"{"accountId":"12","filter":{"text":"a  b","minSize":12345678901234567890},"sort":null,"position":3,"limit":0}"#)
            .unwrap();
        assert_eq!(
            r.filter.as_deref(),
            Some(r#"{"text":"a  b","minSize":12345678901234567890}"#)
        );
        assert_eq!(r.sort.as_deref(), Some("null"));
        assert_eq!((r.position, r.limit), (3, 50));
        let r = parse(r#"{"accountId":"12"}"#).unwrap();
        assert_eq!((r.filter, r.sort, r.position, r.limit), (None, None, 0, 50));
    }

    #[test]
    fn anything_else_goes_to_go() {
        for args in [
            r#"{"accountId":"12","anchor":"1"}"#,
            r#"{"accountId":"12","limit":1.5}"#,
            r#"{"accountId":"12","limit":"5"}"#,
            r#"{"accountId":"12","position":2147483648}"#,
            r#"{"accountId":12}"#,
            r#"{"filter":{}}"#,
        ] {
            assert_eq!(parse(args), None, "{args}");
        }
    }
}
