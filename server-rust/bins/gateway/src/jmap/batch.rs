//! `Email/recover`, `Email/purge`, `Email/deletedQuery` and `Email/bundles`
//! served by Rust (#315): Go's `emailBatchOp`, `emailDeletedQuery` and
//! `emailBundles`.
//!
//! [`classify_batch`]: `accountId` and 1..=256 string `ids`; malformed ids
//! (not base-10 int64 > 0) go to `notRecovered`/`notPurged` as
//! `{"type":"notFound"}` like Go's `addSetErrors`, which re-marshals the result
//! with sorted keys only when there is at least one; otherwise the reducer's
//! JSONB is compacted as it came. [`classify_paged`]: `accountId` and optional
//! integer `limit`/`position` (position in `i32`); the limit is clamped as Go
//! clamps it (`<= 0` or above the cap is 50; cap 256 deleted query, 200
//! bundles). `Email/bundles` answers `{"accountId","bundles","position"}` as Go
//! marshals that map (the request's `accountId` string echoed back).
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{canonical_id, exact_keys, single_call};
use super::get::parse_id;
use super::reply::{go_compact, marshal_sorted};
use setjoin_jmap::{BatchOp, Paged};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRequest {
    pub account_id: i64,
    pub client_id: String,
    pub op: BatchOp,
    pub ids: Vec<i64>,
    pub bad: Vec<String>,
}

pub fn classify_batch(body: &[u8]) -> Option<BatchRequest> {
    let (op, method) = if let Some(call) = single_call(body, "Email/recover") {
        (BatchOp::Recover, call)
    } else {
        (BatchOp::Purge, single_call(body, "Email/purge")?)
    };
    let args = exact_keys(&method.args, &["accountId", "ids"], &[])?;
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
    let items = args.get("ids")?.as_array()?;
    if items.is_empty() || items.len() > 256 {
        return None;
    }
    let (mut ids, mut bad) = (Vec::new(), Vec::new());
    for item in items {
        let item = item.as_str()?;
        match parse_id(item) {
            Some(id) => ids.push(id),
            None => bad.push(item.to_owned()),
        }
    }
    Some(BatchRequest {
        account_id,
        client_id: method.client_id,
        op,
        ids,
        bad,
    })
}

impl BatchRequest {
    pub fn method(&self) -> &'static str {
        match self.op {
            BatchOp::Recover => "Email/recover",
            BatchOp::Purge => "Email/purge",
        }
    }

    /// Go's answer body for the reducer's `raw` result.
    pub fn result(&self, raw: &str) -> Option<String> {
        if self.bad.is_empty() {
            return Some(raw.to_owned());
        }
        let bucket_name = match self.op {
            BatchOp::Recover => "notRecovered",
            BatchOp::Purge => "notPurged",
        };
        let mut object: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw).ok()?;
        let mut bucket: BTreeMap<String, Box<RawValue>> = match object.get(bucket_name) {
            Some(existing) => serde_json::from_str(existing.get()).unwrap_or_default(),
            None => BTreeMap::new(),
        };
        for id in &self.bad {
            bucket.insert(
                id.clone(),
                RawValue::from_string(r#"{"type":"notFound"}"#.to_owned()).ok()?,
            );
        }
        object.insert(
            bucket_name.into(),
            RawValue::from_string(marshal_sorted(&bucket)?).ok()?,
        );
        marshal_sorted(&object)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagedRequest {
    pub account_id: i64,
    pub client_id: String,
    pub which: Paged,
    pub limit: i32,
    pub position: i32,
}

pub fn classify_paged(body: &[u8]) -> Option<PagedRequest> {
    let (which, call, cap) = if let Some(call) = single_call(body, "Email/deletedQuery") {
        (Paged::DeletedQuery, call, 256)
    } else if let Some(call) = single_call(body, "Email/bundles") {
        (Paged::Bundles, call, 200)
    } else {
        (Paged::Nudges, single_call(body, "Email/nudges")?, 200)
    };
    let args = exact_keys(&call.args, &["accountId"], &["limit", "position"])?;
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
    let integer = |name: &str| -> Option<Option<i64>> {
        match args.get(name) {
            None => Some(None),
            Some(Value::Number(n)) => n.as_i64().map(Some),
            Some(_) => None,
        }
    };
    let limit = match integer("limit")? {
        Some(n) if (1..=cap).contains(&n) => n as i32,
        _ => 50,
    };
    let position = match integer("position")? {
        None => 0,
        Some(n) => i32::try_from(n).ok()?,
    };
    Some(PagedRequest {
        account_id,
        client_id: call.client_id,
        which,
        limit,
        position,
    })
}

impl PagedRequest {
    pub fn method(&self) -> &'static str {
        match self.which {
            Paged::DeletedQuery => "Email/deletedQuery",
            Paged::Bundles => "Email/bundles",
            Paged::Nudges => "Email/nudges",
        }
    }

    /// Go's answer body for the reducer's `raw` result. `Email/bundles` wraps
    /// it in the sorted map Go marshals.
    pub fn result(&self, raw: &str) -> Option<String> {
        match self.which {
            Paged::DeletedQuery => Some(raw.to_owned()),
            Paged::Bundles => Some(format!(
                r#"{{"accountId":"{}","bundles":{},"position":{}}}"#,
                self.account_id,
                go_compact(raw)?,
                self.position
            )),
            Paged::Nudges => Some(format!(
                r#"{{"accountId":"{}","nudges":{},"position":{}}}"#,
                self.account_id,
                go_compact(raw)?,
                self.position
            )),
        }
    }

    /// Go's answer with `feature.stale_nudges` OFF (position is 0 whatever was asked).
    pub fn nudges_off(&self) -> String {
        format!(
            r#"{{"accountId":"{}","nudges":[],"position":0}}"#,
            self.account_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(method: &str, args: &str) -> Vec<u8> {
        format!(
            r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["{method}",{args},"c1"]]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn batch_splits_ids_and_folds_malformed_ones_as_go_does() {
        let r = classify_batch(&call(
            "Email/purge",
            r#"{"accountId":"12","ids":["5","x"]}"#,
        ))
        .unwrap();
        assert_eq!(
            (r.op, r.ids.clone(), r.bad.clone()),
            (BatchOp::Purge, vec![5], vec!["x".to_owned()])
        );
        let raw = r#"{"purged": ["5"], "newState": "2", "notPurged": {}, "accountId": "12"}"#;
        assert_eq!(
            r.result(raw).unwrap(),
            r#"{"accountId":"12","newState":"2","notPurged":{"x":{"type":"notFound"}},"purged":["5"]}"#
        );
        let clean =
            classify_batch(&call("Email/recover", r#"{"accountId":"12","ids":["5"]}"#)).unwrap();
        assert_eq!(clean.result(raw).unwrap(), raw);
        assert_eq!(
            classify_batch(&call("Email/recover", r#"{"accountId":"12","ids":[]}"#)),
            None
        );
    }

    #[test]
    fn paged_limits_follow_go() {
        let r = classify_paged(&call(
            "Email/bundles",
            r#"{"accountId":"12","limit":201,"position":3}"#,
        ))
        .unwrap();
        assert_eq!((r.limit, r.position), (50, 3));
        let r = classify_paged(&call(
            "Email/deletedQuery",
            r#"{"accountId":"12","limit":201}"#,
        ))
        .unwrap();
        assert_eq!(r.limit, 201);
        assert_eq!(
            classify_paged(&call(
                "Email/deletedQuery",
                r#"{"accountId":"12","limit":1.5}"#
            )),
            None
        );
        assert_eq!(
            classify_paged(&call("Email/bundles", r#"{"accountId":"12","x":1}"#)),
            None
        );
    }

    #[test]
    fn receipt_claims_any_object_call_only() {
        assert!(classify_receipt(&call("Email/recoveryReceipt", r#"{"accountId":"1","ids":[]}"#)).is_some());
        assert!(classify_receipt(&call("Email/recoveryReceipt", r#"[1]"#)).is_none());
    }

    #[test]
    fn bundles_wrap_the_reducer_array_like_go() {
        let r =
            classify_paged(&call("Email/bundles", r#"{"accountId":"12","position":4}"#)).unwrap();
        assert_eq!(
            r.result(r#"[{"count": 2}]"#).unwrap(),
            r#"{"accountId":"12","bundles":[{"count":2}],"position":4}"#
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DismissRequest {
    pub account_id: i64,
    pub client_id: String,
    pub thread_id: String,
}

/// `Email/nudgeDismiss`: `accountId` and a string `threadId`.
pub fn classify_dismiss(body: &[u8]) -> Option<DismissRequest> {
    let call = single_call(body, "Email/nudgeDismiss")?;
    let args = exact_keys(&call.args, &["accountId", "threadId"], &[])?;
    Some(DismissRequest {
        account_id: canonical_id(args.get("accountId")?.as_str()?)?,
        client_id: call.client_id,
        thread_id: args.get("threadId")?.as_str()?.to_owned(),
    })
}

impl DismissRequest {
    /// Go's answer with the toggle OFF.
    pub fn off(&self) -> String {
        format!(r#"{{"accountId":"{}","dismissed":[]}}"#, self.account_id)
    }

    /// Go's `{"accountId","dismissed":raw}` map with the toggle ON.
    pub fn result(&self, raw: &str) -> Option<String> {
        Some(format!(
            r#"{{"accountId":"{}","dismissed":{}}}"#,
            self.account_id,
            go_compact(raw)?
        ))
    }
}

/// `Email/recoveryReceipt` with `feature.client_recovery_receipts` OFF: Go checks the
/// toggle before it reads the arguments or the account, so any object-argument call
/// gets the same `forbidden` answer. (ON needs the signing key and raw-MIME fetch:
/// Go's until the continuity ticket moves them.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRequest {
    pub client_id: String,
}

pub const RECEIPTS_FLAG: &str = "feature.client_recovery_receipts";

pub fn classify_receipt(body: &[u8]) -> Option<ReceiptRequest> {
    let call = single_call(body, "Email/recoveryReceipt")?;
    call.args.is_object().then_some(ReceiptRequest { client_id: call.client_id })
}
