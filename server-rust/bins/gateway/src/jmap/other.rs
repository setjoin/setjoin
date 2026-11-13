//! Mailbox method translation (#316). Account IDs are comparisons; only the
//! verified mailbox reaches the domain adapter.
use super::envelope::{canonical_id, single_call};
use serde_json::{Map, Value};
use setjoin_jmap::mailbox::Read;

pub struct OtherRequest {
    pub account_id: i64,
    pub client_id: String,
    pub method: &'static str,
    pub read: Read,
    pub bad: Vec<String>,
    pub too_many: bool,
}

pub fn classify(body: &[u8]) -> Option<OtherRequest> {
    for method in [
        "Mailbox/get",
        "Mailbox/query",
        "Mailbox/changes",
        "Mailbox/queryChanges",
        "Thread/get",
        "Thread/changes",
        "SearchSnippet/get",
    ] {
        if let Some(call) = single_call(body, method) {
            let fields = super::envelope::struct_arguments(
                &call.raw_args,
                &[
                    "accountId",
                    "ids",
                    "properties",
                    "filter",
                    "sort",
                    "position",
                    "limit",
                    "sinceState",
                    "maxChanges",
                    "sinceQueryState",
                    "emailIds",
                ],
            )?;
            let value: Value = serde_json::from_str(&serde_json::to_string(&fields).ok()?).ok()?;
            let args = value.as_object()?;
            let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
            let (mut bad, mut too_many) = (Vec::new(), false);
            let read = match method {
                "Thread/get" => Read::ThreadGet(strings(args.get("ids"))?),
                "Thread/changes" => Read::ThreadChanges(string(args, "sinceState")?),
                "SearchSnippet/get" => {
                    let ids = strings(args.get("emailIds"))?
                        .filter(|v| !v.is_empty())
                        .map(|items| {
                            items
                                .into_iter()
                                .filter_map(|id| match super::get::parse_id(&id) {
                                    Some(id) => Some(id),
                                    None => {
                                        bad.push(id);
                                        None
                                    }
                                })
                                .collect()
                        });
                    Read::SearchSnippet {
                        filter: raw_json(fields.get("filter")),
                        ids,
                    }
                }
                "Mailbox/get" => {
                    let raw_ids = strings(args.get("ids"))?;
                    too_many = raw_ids.as_ref().is_some_and(|ids| ids.len() > 256);
                    let ids = raw_ids.filter(|ids| !ids.is_empty()).map(|raw| {
                        raw.into_iter()
                            .filter_map(|id| match super::get::parse_id(&id) {
                                Some(id) => Some(id),
                                None => {
                                    bad.push(id);
                                    None
                                }
                            })
                            .collect()
                    });
                    Read::Get {
                        ids,
                        properties: strings(args.get("properties"))?,
                    }
                }
                "Mailbox/query" => Read::Query {
                    filter: raw_json(fields.get("filter")),
                    sort: raw_json(fields.get("sort")),
                    position: integer(args, "position")?,
                    limit: match integer(args, "limit")? {
                        n if n <= 0 => None,
                        n => Some(n),
                    },
                },
                "Mailbox/changes" => {
                    integer(args, "maxChanges")?;
                    Read::Changes(string(args, "sinceState")?)
                }
                "Mailbox/queryChanges" => {
                    let since = string(args, "sinceQueryState")?;
                    Read::QueryChanges {
                        filter: raw_json(fields.get("filter")),
                        sort: raw_json(fields.get("sort")),
                        since: if since.is_empty() { "0".into() } else { since },
                    }
                }
                _ => unreachable!(),
            };
            return Some(OtherRequest {
                account_id,
                client_id: call.client_id,
                method,
                read,
                bad,
                too_many,
            });
        }
    }
    None
}
fn raw_json(value: Option<&Box<serde_json::value::RawValue>>) -> Option<String> {
    value
        .filter(|v| v.get().trim() != "null")
        .map(|v| v.get().to_owned())
}
fn integer(args: &Map<String, Value>, key: &str) -> Option<i32> {
    match args.get(key) {
        None | Some(Value::Null) => Some(0),
        Some(v) => i32::try_from(v.as_i64()?).ok(),
    }
}
fn string(args: &Map<String, Value>, key: &str) -> Option<String> {
    match args.get(key) {
        None | Some(Value::Null) => Some(String::new()),
        Some(v) => v.as_str().map(str::to_owned),
    }
}
fn strings(value: Option<&Value>) -> Option<Option<Vec<String>>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .map(Some),
        _ => None,
    }
}
