use super::{envelope, reply};
use serde_json::{json, Value};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};

pub struct Request {
    pub method: &'static str,
    pub since: String,
}

pub fn classify_call(method: &str, raw_args: &str, _client_id: &str) -> Option<Request> {
    let method: &'static str = match method {
        "Identity/get" => "Identity/get",
        "Identity/changes" => "Identity/changes",
        _ => return None,
    };
    let val: Value = serde_json::from_str(raw_args).ok()?;
    if !val.is_object() && !val.is_null() {
        return None;
    }
    // Go `identityChanges` ignores json.Unmarshal errors, defaulting non-string
    // `sinceState` to "" and ignoring invalid `accountId`/`maxChanges`.
    let since = if method == "Identity/changes" && !val.is_null() {
        let args = envelope::struct_arguments(raw_args, &["accountId", "sinceState"])?;
        args.get("sinceState")
            .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Some(Request { method, since })
}

pub async fn response_call(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    r: &Request,
) -> (&'static str, String) {
    let since = r.since.as_str();
    let state = setjoin_jmap::identity::state(exec, auth).await;
    let value = if r.method == "Identity/changes" {
        let Some(state) = state else {
            return (
                "error",
                reply::jmap_error_json("serverFail", 500, "user not found"),
            );
        };
        let changed = !since.is_empty() && since != state;
        let updated = if changed {
            vec![format!("i{}", auth.actor().get())]
        } else {
            vec![]
        };
        json!({"created":[],"destroyed":[],"hasMoreChanges":false,"newState":state,"oldState":since,"updated":updated})
    } else {
        let primary = setjoin_jmap::identity::primary(exec, auth).await;
        let mut p = json!({"id":format!("i{}",auth.actor().get()),"name":primary.name,"email":primary.email,"isDefault":true,"mayDelete":false});
        for (name, value) in [
            ("givenName", primary.given),
            ("familyName", primary.family),
            (
                "avatar",
                primary.avatar.map(|s| {
                    if s.is_empty() {
                        s
                    } else {
                        format!("/blobs/{s}")
                    }
                }),
            ),
        ] {
            if let Some(value) = value.filter(|s| !s.is_empty()) {
                p[name] = json!(value);
            }
        }
        let mut list = vec![p];
        for (prefix, entries, delete) in [
            ("a", setjoin_jmap::identity::aliases(exec, auth).await, true),
            (
                "d",
                setjoin_jmap::identity::delegated(worker, auth).await,
                false,
            ),
        ] {
            for a in entries {
                let mut row = json!({"id":format!("{prefix}{}",a.id),"name":a.name,"email":a.email,"isDefault":false,"mayDelete":delete});
                for (name, value) in [("signature", a.signature), ("replyTo", a.reply)] {
                    if let Some(value) = value.filter(|s| !s.is_empty()) {
                        row[name] = json!(value);
                    }
                }
                list.push(row);
            }
        }
        json!({"list":list,"state":state.unwrap_or_else(||"unavailable".into())})
    };
    (r.method, value.to_string())
}
