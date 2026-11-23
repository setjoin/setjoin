//! Mailbox, Thread, and SearchSnippet translation (#316, #356). Account IDs
//! are resolved against the caller or an explicit delegate grant before
//! reaching the domain adapter.
use super::envelope::{
    go_i64_field, go_string_array_field, go_string_field, single_call, struct_arguments,
};
use serde_json::value::RawValue;
use setjoin_jmap::mailbox::Read;

pub enum OtherArgs {
    Valid {
        read: Read,
        bad: Vec<String>,
        too_many: bool,
    },
    Invalid(String),
}

pub struct OtherRequest {
    pub raw_account_id: String,
    pub client_id: String,
    pub method: &'static str,
    pub args: OtherArgs,
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
            return classify_call(method, &call.raw_args, &call.client_id);
        }
    }
    None
}

pub fn classify_call(method: &str, raw_args: &str, client_id: &str) -> Option<OtherRequest> {
    let method: &'static str = match method {
        "Mailbox/get" => "Mailbox/get",
        "Mailbox/query" => "Mailbox/query",
        "Mailbox/changes" => "Mailbox/changes",
        "Mailbox/queryChanges" => "Mailbox/queryChanges",
        "Thread/get" => "Thread/get",
        "Thread/changes" => "Thread/changes",
        "SearchSnippet/get" => "SearchSnippet/get",
        _ => return None,
    };
    let fields = struct_arguments(
        raw_args,
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
    let invalid = |raw_account_id: String, msg: String| {
        Some(OtherRequest {
            raw_account_id,
            client_id: client_id.to_owned(),
            method,
            args: OtherArgs::Invalid(msg),
        })
    };
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(msg) => return invalid(String::new(), msg),
        },
    };
    let get_string = |key: &str| -> Result<String, String> {
        match fields.get(key) {
            None => Ok(String::new()),
            Some(raw) => Ok(go_string_field(raw.get())?.unwrap_or_default()),
        }
    };
    let get_strings = |key: &str| -> Result<Option<Vec<String>>, String> {
        match fields.get(key) {
            None => Ok(None),
            Some(raw) => go_string_array_field(raw.get()),
        }
    };
    let get_i64 = |key: &str| -> Result<i64, String> {
        match fields.get(key) {
            None => Ok(0),
            Some(raw) => Ok(go_i64_field(raw.get())?.unwrap_or(0)),
        }
    };

    let (mut bad, mut too_many) = (Vec::new(), false);
    let read = match method {
        "Thread/get" => match get_strings("ids") {
            Ok(ids) => Read::ThreadGet(ids),
            Err(msg) => return invalid(raw_account_id, msg),
        },
        "Thread/changes" => {
            if let Err(msg) = get_i64("maxChanges") {
                return invalid(raw_account_id, msg);
            }
            match get_string("sinceState") {
                Ok(since) => Read::ThreadChanges(since),
                Err(msg) => return invalid(raw_account_id, msg),
            }
        }
        "SearchSnippet/get" => {
            let raw_ids = match get_strings("emailIds") {
                Ok(ids) => ids,
                Err(msg) => return invalid(raw_account_id, msg),
            };
            let ids = raw_ids.filter(|v| !v.is_empty()).map(|items| {
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
            let raw_ids = match get_strings("ids") {
                Ok(ids) => ids,
                Err(msg) => return invalid(raw_account_id, msg),
            };
            let properties = match get_strings("properties") {
                Ok(props) => props,
                Err(msg) => return invalid(raw_account_id, msg),
            };
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
            Read::Get { ids, properties }
        }
        "Mailbox/query" => {
            let position = match get_i64("position") {
                Ok(n) => i32::try_from(n).ok()?,
                Err(msg) => return invalid(raw_account_id, msg),
            };
            let limit = match get_i64("limit") {
                Ok(n) if n <= 0 => None,
                Ok(n) => Some(i32::try_from(n).unwrap_or(i32::MAX)),
                Err(msg) => return invalid(raw_account_id, msg),
            };
            Read::Query {
                filter: raw_json(fields.get("filter")),
                sort: raw_json(fields.get("sort")),
                position,
                limit,
            }
        }
        "Mailbox/changes" => {
            if let Err(msg) = get_i64("maxChanges") {
                return invalid(raw_account_id, msg);
            }
            match get_string("sinceState") {
                Ok(since) => Read::Changes(since),
                Err(msg) => return invalid(raw_account_id, msg),
            }
        }
        "Mailbox/queryChanges" => match get_string("sinceQueryState") {
            Ok(since) => Read::QueryChanges {
                filter: raw_json(fields.get("filter")),
                sort: raw_json(fields.get("sort")),
                since: if since.is_empty() { "0".into() } else { since },
            },
            Err(msg) => return invalid(raw_account_id, msg),
        },
        _ => unreachable!(),
    };
    Some(OtherRequest {
        raw_account_id,
        client_id: client_id.to_owned(),
        method,
        args: OtherArgs::Valid {
            read,
            bad,
            too_many,
        },
    })
}

fn raw_json(value: Option<&Box<RawValue>>) -> Option<String> {
    value
        .filter(|v| v.get().trim() != "null")
        .map(|v| v.get().to_owned())
}
