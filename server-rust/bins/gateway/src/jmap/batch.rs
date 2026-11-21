//! `Email/recover`, `Email/purge`, `Email/deletedQuery`, `Email/bundles`,
//! `Email/nudges`, `Email/nudgeDismiss` and `Email/recoveryReceipt`
//! served by Rust (#315, #356).
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::envelope::{go_i64_field, go_string_field, single_call, struct_arguments};
use super::get::parse_id;
use super::reply::{go_compact, marshal_sorted};
use crate::problem::go_string;
use setjoin_jmap::{BatchOp, Paged};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchArgs {
    Valid {
        ids: Vec<i64>,
        bad: Vec<String>,
    },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRequest {
    pub raw_account_id: String,
    pub client_id: String,
    pub op: BatchOp,
    pub args: BatchArgs,
}

pub fn classify_batch(body: &[u8]) -> Option<BatchRequest> {
    if let Some(call) = single_call(body, "Email/recover") {
        let raw = serde_json::to_string(&call.args).ok()?;
        classify_batch_call("Email/recover", &raw, &call.client_id)
    } else {
        let call = single_call(body, "Email/purge")?;
        let raw = serde_json::to_string(&call.args).ok()?;
        classify_batch_call("Email/purge", &raw, &call.client_id)
    }
}

pub fn classify_batch_call(method: &str, raw_args: &str, client_id: &str) -> Option<BatchRequest> {
    let op = match method {
        "Email/recover" => BatchOp::Recover,
        "Email/purge" => BatchOp::Purge,
        _ => return None,
    };
    let fields = struct_arguments(raw_args, &["accountId", "ids"])?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(msg) => {
                return Some(BatchRequest {
                    raw_account_id: String::new(),
                    client_id: client_id.to_owned(),
                    op,
                    args: BatchArgs::Invalid(msg),
                });
            }
        },
    };
    let raw_ids = match fields.get("ids") {
        None => return None,
        Some(raw) => match super::envelope::go_string_array_field(raw.get()) {
            Ok(Some(items)) if !items.is_empty() => items,
            Ok(_) => return None,
            Err(msg) => {
                return Some(BatchRequest {
                    raw_account_id,
                    client_id: client_id.to_owned(),
                    op,
                    args: BatchArgs::Invalid(msg),
                });
            }
        },
    };
    let (mut ids, mut bad) = (Vec::new(), Vec::new());
    for item in raw_ids {
        match parse_id(&item) {
            Some(id) => ids.push(id),
            None => bad.push(item),
        }
    }
    Some(BatchRequest {
        raw_account_id,
        client_id: client_id.to_owned(),
        op,
        args: BatchArgs::Valid { ids, bad },
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
    pub fn result(&self, raw: &str, bad: &[String]) -> Option<String> {
        if bad.is_empty() {
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
        for id in bad {
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
pub enum PagedArgs {
    Valid { limit: i32, position: i32 },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagedRequest {
    pub raw_account_id: String,
    pub client_id: String,
    pub which: Paged,
    pub args: PagedArgs,
}

pub fn classify_paged(body: &[u8]) -> Option<PagedRequest> {
    for method in ["Email/deletedQuery", "Email/bundles", "Email/nudges"] {
        if let Some(call) = single_call(body, method) {
            let raw = serde_json::to_string(&call.args).ok()?;
            return classify_paged_call(method, &raw, &call.client_id);
        }
    }
    None
}

pub fn classify_paged_call(method: &str, raw_args: &str, client_id: &str) -> Option<PagedRequest> {
    let (which, cap) = match method {
        "Email/deletedQuery" => (Paged::DeletedQuery, 256),
        "Email/bundles" => (Paged::Bundles, 200),
        "Email/nudges" => (Paged::Nudges, 200),
        _ => return None,
    };
    let fields = struct_arguments(raw_args, &["accountId", "limit", "position"])?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(msg) => {
                return Some(PagedRequest {
                    raw_account_id: String::new(),
                    client_id: client_id.to_owned(),
                    which,
                    args: PagedArgs::Invalid(msg),
                });
            }
        },
    };
    let limit = match fields.get("limit") {
        None => 50,
        Some(raw) => match go_i64_field(raw.get()) {
            Ok(Some(n)) if (1..=cap).contains(&n) => n as i32,
            Ok(_) => 50,
            Err(msg) => {
                return Some(PagedRequest {
                    raw_account_id,
                    client_id: client_id.to_owned(),
                    which,
                    args: PagedArgs::Invalid(msg),
                });
            }
        },
    };
    let position = match fields.get("position") {
        None => 0,
        Some(raw) => match go_i64_field(raw.get()) {
            Ok(None) => 0,
            Ok(Some(n)) => i32::try_from(n).ok()?,
            Err(msg) => {
                return Some(PagedRequest {
                    raw_account_id,
                    client_id: client_id.to_owned(),
                    which,
                    args: PagedArgs::Invalid(msg),
                });
            }
        },
    };
    Some(PagedRequest {
        raw_account_id,
        client_id: client_id.to_owned(),
        which,
        args: PagedArgs::Valid { limit, position },
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

    /// Go's answer body for the reducer's `raw` result. `Email/bundles` and
    /// `Email/nudges` wrap it in the sorted map Go marshals.
    pub fn result(&self, raw: &str, position: i32) -> Option<String> {
        let acct = go_string(&self.raw_account_id);
        match self.which {
            Paged::DeletedQuery => Some(raw.to_owned()),
            Paged::Bundles => Some(format!(
                r#"{{"accountId":{acct},"bundles":{},"position":{position}}}"#,
                go_compact(raw)?,
            )),
            Paged::Nudges => Some(format!(
                r#"{{"accountId":{acct},"nudges":{},"position":{position}}}"#,
                go_compact(raw)?,
            )),
        }
    }

    /// Go's answer with `feature.stale_nudges` OFF (position is 0 whatever was asked).
    pub fn nudges_off(&self) -> String {
        format!(
            r#"{{"accountId":{},"nudges":[],"position":0}}"#,
            go_string(&self.raw_account_id)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DismissArgs {
    Valid { thread_id: String },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DismissRequest {
    pub raw_account_id: String,
    pub client_id: String,
    pub args: DismissArgs,
}

/// `Email/nudgeDismiss`: `accountId` and `threadId`.
pub fn classify_dismiss(body: &[u8]) -> Option<DismissRequest> {
    let call = single_call(body, "Email/nudgeDismiss")?;
    let raw = serde_json::to_string(&call.args).ok()?;
    classify_dismiss_call("Email/nudgeDismiss", &raw, &call.client_id)
}

pub fn classify_dismiss_call(
    method: &str,
    raw_args: &str,
    client_id: &str,
) -> Option<DismissRequest> {
    if method != "Email/nudgeDismiss" {
        return None;
    }
    let fields = struct_arguments(raw_args, &["accountId", "threadId"])?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(msg) => {
                return Some(DismissRequest {
                    raw_account_id: String::new(),
                    client_id: client_id.to_owned(),
                    args: DismissArgs::Invalid(msg),
                });
            }
        },
    };
    let thread_id = match fields.get("threadId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(msg) => {
                return Some(DismissRequest {
                    raw_account_id,
                    client_id: client_id.to_owned(),
                    args: DismissArgs::Invalid(msg),
                });
            }
        },
    };
    Some(DismissRequest {
        raw_account_id,
        client_id: client_id.to_owned(),
        args: DismissArgs::Valid { thread_id },
    })
}

impl DismissRequest {
    /// Go's answer with the toggle OFF.
    pub fn off(&self) -> String {
        format!(
            r#"{{"accountId":{},"dismissed":[]}}"#,
            go_string(&self.raw_account_id)
        )
    }

    /// Go's `{"accountId","dismissed":raw}` map with the toggle ON.
    pub fn result(&self, raw: &str) -> Option<String> {
        Some(format!(
            r#"{{"accountId":{},"dismissed":{}}}"#,
            go_string(&self.raw_account_id),
            go_compact(raw)?
        ))
    }
}

/// `Email/recoveryReceipt`: checks `feature.client_recovery_receipts` and
/// continuity signer readiness before decoding arguments so disabled receipts
/// still match Go's `forbidden` response regardless of arguments/account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRequest {
    pub raw_args: String,
    pub client_id: String,
}

pub const RECEIPTS_FLAG: &str = "feature.client_recovery_receipts";

pub fn classify_receipt(body: &[u8]) -> Option<ReceiptRequest> {
    let call = single_call(body, "Email/recoveryReceipt")?;
    let raw = serde_json::to_string(&call.args).ok()?;
    classify_receipt_call("Email/recoveryReceipt", &raw, &call.client_id)
}

pub fn classify_receipt_call(
    method: &str,
    raw_args: &str,
    client_id: &str,
) -> Option<ReceiptRequest> {
    if method != "Email/recoveryReceipt" {
        return None;
    }
    let val: Value = serde_json::from_str(raw_args).ok()?;
    (val.is_object() || val.is_null()).then(|| ReceiptRequest {
        raw_args: raw_args.to_owned(),
        client_id: client_id.to_owned(),
    })
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
        let BatchArgs::Valid { ids, bad } = &r.args else {
            panic!("expected valid");
        };
        assert_eq!(
            (r.op, ids.clone(), bad.clone()),
            (BatchOp::Purge, vec![5], vec!["x".to_owned()])
        );
        let raw = r#"{"purged": ["5"], "newState": "2", "notPurged": {}, "accountId": "12"}"#;
        assert_eq!(
            r.result(raw, bad).unwrap(),
            r#"{"accountId":"12","newState":"2","notPurged":{"x":{"type":"notFound"}},"purged":["5"]}"#
        );
        let clean =
            classify_batch(&call("Email/recover", r#"{"accountId":"12","ids":["5"]}"#)).unwrap();
        assert_eq!(clean.result(raw, &[]).unwrap(), raw);
        assert_eq!(
            classify_batch(&call("Email/recover", r#"{"accountId":"12","ids":[]}"#)),
            None
        );
        // Over 256 ids is handled in Wave 1.
        let many = (1..=300)
            .map(|n| format!(r#""{n}""#))
            .collect::<Vec<_>>()
            .join(",");
        let big = classify_batch_call(
            "Email/purge",
            &format!(r#"{{"accountId":"12","ids":[{many}]}}"#),
            "c1",
        )
        .unwrap();
        let BatchArgs::Valid { ids, .. } = big.args else {
            panic!("expected valid");
        };
        assert_eq!(ids.len(), 300);
    }

    #[test]
    fn paged_limits_and_extra_fields_follow_go() {
        let r = classify_paged(&call(
            "Email/bundles",
            r#"{"accountId":"0012","limit":201,"position":3,"extra":1}"#,
        ))
        .unwrap();
        assert_eq!(r.raw_account_id, "0012");
        assert_eq!(
            r.args,
            PagedArgs::Valid {
                limit: 50,
                position: 3
            }
        );
        let r = classify_paged(&call(
            "Email/deletedQuery",
            r#"{"accountId":"12","limit":201}"#,
        ))
        .unwrap();
        assert_eq!(
            r.args,
            PagedArgs::Valid {
                limit: 201,
                position: 0
            }
        );
        let bad = classify_paged(&call(
            "Email/deletedQuery",
            r#"{"accountId":"12","limit":1.5}"#,
        ))
        .unwrap();
        assert!(matches!(bad.args, PagedArgs::Invalid(_)));
    }

    #[test]
    fn receipt_claims_any_object_call_only() {
        assert!(classify_receipt(&call(
            "Email/recoveryReceipt",
            r#"{"accountId":"1","ids":[]}"#
        ))
        .is_some());
        assert!(classify_receipt(&call("Email/recoveryReceipt", r#"[1]"#)).is_none());
    }

    #[test]
    fn bundles_wrap_the_reducer_array_like_go() {
        let r = classify_paged(&call(
            "Email/bundles",
            r#"{"accountId":"0012","position":4}"#,
        ))
        .unwrap();
        let PagedArgs::Valid { position, .. } = r.args else {
            panic!("expected valid");
        };
        assert_eq!(
            r.result(r#"[{"count": 2}]"#, position).unwrap(),
            r#"{"accountId":"0012","bundles":[{"count":2}],"position":4}"#
        );
    }
}
