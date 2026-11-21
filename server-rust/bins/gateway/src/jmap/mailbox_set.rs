//! Go's SetRequest / dispatchSet input contract, including ignored ifInState.
use super::envelope::{
    go_string_array_field, go_string_field, single_call_with_capability, struct_arguments,
};

pub enum MailboxSetArgs {
    Valid {
        create: Option<String>,
        update: Option<String>,
        destroy: Option<Vec<i64>>,
        bad: Vec<String>,
    },
    Invalid(String),
}

pub struct Request {
    pub method: &'static str,
    pub raw_account_id: String,
    pub client_id: String,
    pub args: MailboxSetArgs,
}

pub fn classify(body: &[u8]) -> Option<Request> {
    let call = single_call_with_capability(body, "Mailbox/set", "urn:ietf:params:jmap:mail")?;
    classify_call("Mailbox/set", &call.raw_args, &call.client_id)
}

pub fn classify_identity(body: &[u8]) -> Option<Request> {
    let call =
        single_call_with_capability(body, "Identity/set", "urn:ietf:params:jmap:submission")?;
    classify_call("Identity/set", &call.raw_args, &call.client_id)
}

pub fn classify_call(method: &str, raw_args: &str, client_id: &str) -> Option<Request> {
    let method: &'static str = match method {
        "Mailbox/set" => "Mailbox/set",
        "Identity/set" => "Identity/set",
        _ => return None,
    };
    let fields = struct_arguments(
        raw_args,
        &["accountId", "ifInState", "create", "update", "destroy"],
    )?;
    let invalid = |raw_account_id: String, msg: String| {
        Some(Request {
            method,
            raw_account_id,
            client_id: client_id.to_owned(),
            args: MailboxSetArgs::Invalid(msg),
        })
    };
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(msg) => return invalid(String::new(), msg),
        },
    };
    if let Some(raw) = fields.get("ifInState") {
        if let Err(msg) = go_string_field(raw.get()) {
            return invalid(raw_account_id, msg);
        }
    }
    let object_field = |key: &str| -> Result<Option<String>, String> {
        let Some(raw) = fields.get(key) else {
            return Ok(None);
        };
        let trimmed = raw.get().trim();
        if trimmed == "null" {
            return Ok(None);
        }
        if trimmed.starts_with('{') {
            return Ok(Some(raw.get().to_owned()));
        }
        Err(format!("invalid {key} argument"))
    };
    let create = match object_field("create") {
        Ok(v) => v,
        Err(msg) => return invalid(raw_account_id, msg),
    };
    let update = match object_field("update") {
        Ok(v) => v,
        Err(msg) => return invalid(raw_account_id, msg),
    };
    let mut bad = Vec::new();
    let destroy = match fields.get("destroy") {
        None => None,
        Some(raw) => match go_string_array_field(raw.get()) {
            Ok(None) => None,
            Ok(Some(items)) if items.is_empty() => None,
            Ok(Some(items)) => {
                let mut ids = Vec::new();
                for id in items {
                    match super::get::parse_id(&id) {
                        Some(id) => ids.push(id),
                        None => bad.push(id),
                    }
                }
                Some(ids)
            }
            Err(msg) => return invalid(raw_account_id, msg),
        },
    };
    Some(Request {
        method,
        raw_account_id,
        client_id: client_id.to_owned(),
        args: MailboxSetArgs::Valid {
            create,
            update,
            destroy,
            bad,
        },
    })
}
