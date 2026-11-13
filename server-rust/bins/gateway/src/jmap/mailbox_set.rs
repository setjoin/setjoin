//! Go's SetRequest / dispatchSet input contract, including ignored ifInState.
use super::envelope::{canonical_id, single_call_with_capability};
use serde_json::Value;
pub struct Request {
    pub method: &'static str,
    pub account_id: i64,
    pub client_id: String,
    pub create: Option<String>,
    pub update: Option<String>,
    pub destroy: Option<Vec<i64>>,
    pub bad: Vec<String>,
}
pub fn classify(body: &[u8]) -> Option<Request> {
    classify_method(body, "Mailbox/set", "urn:ietf:params:jmap:mail")
}
pub fn classify_identity(body: &[u8]) -> Option<Request> {
    classify_method(body, "Identity/set", "urn:ietf:params:jmap:submission")
}
fn classify_method(body: &[u8], method: &'static str, capability: &str) -> Option<Request> {
    let call = single_call_with_capability(body, method, capability)?;
    let fields = super::envelope::struct_arguments(
        &call.raw_args,
        &["accountId", "ifInState", "create", "update", "destroy"],
    )?;
    let value: Value = serde_json::from_str(&serde_json::to_string(&fields).ok()?).ok()?;
    let args = value.as_object()?;
    if args
        .get("ifInState")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return None;
    }
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
    let object = |key| {
        fields
            .get(key)
            .filter(|v| v.get().trim_start().starts_with('{'))
            .map(|v| v.get().to_owned())
    };
    let mut bad = Vec::new();
    let destroy = match args.get("destroy") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) if items.is_empty() => None,
        Some(Value::Array(items)) => {
            let mut ids = Vec::new();
            for id in items {
                let id = if id.is_null() { "" } else { id.as_str()? };
                match super::get::parse_id(id) {
                    Some(id) => ids.push(id),
                    None => bad.push(id.to_owned()),
                }
            }
            Some(ids)
        }
        _ => return None,
    };
    Some(Request {
        method,
        account_id,
        client_id: call.client_id,
        create: object("create"),
        update: object("update"),
        destroy,
        bad,
    })
}
