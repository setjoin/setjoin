use super::{
    envelope::{self, SingleCall},
    reply,
};
use serde_json::json;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
pub struct Request {
    pub method: &'static str,
    pub call: SingleCall,
    pub since: String,
}
pub fn classify(body: &[u8]) -> Option<Request> {
    for method in ["Identity/get", "Identity/changes"] {
        if let Some(call) =
            envelope::single_call_with_capability(body, method, "urn:ietf:params:jmap:submission")
        {
            if !call.args.is_object() && !call.args.is_null() {
                return None;
            }
            let since = if method == "Identity/changes" && !call.args.is_null() {
                let args =
                    envelope::struct_arguments(&call.raw_args, &["accountId", "sinceState"])?;
                args.get("sinceState")
                    .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            return Some(Request {
                method,
                call,
                since,
            });
        }
    }
    None
}
pub async fn response(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    session: &str,
    r: &Request,
) -> Option<String> {
    let state = setjoin_jmap::identity::state(exec, auth).await;
    let value = if r.method == "Identity/changes" {
        let Some(state) = state else {
            return Some(reply::method_error(
                session,
                "serverFail",
                500,
                "user not found",
                &r.call.client_id,
            ));
        };
        let changed = !r.since.is_empty() && r.since != state;
        let updated = if changed {
            vec![format!("i{}", auth.actor().get())]
        } else {
            vec![]
        };
        json!({"created":[],"destroyed":[],"hasMoreChanges":false,"newState":state,"oldState":r.since,"updated":updated})
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
    reply::method_response(session, r.method, &value.to_string(), &r.call.client_id)
}
