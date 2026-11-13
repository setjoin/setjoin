//! Recognises the one JMAP request shape the mark-read route may serve.
//!
//! The reducer contract (`jmap_email_set_update`) is the oracle: a patch it
//! would treat as exactly `SetMessageSeen` is `{"keywords": {"$seen": b}}`
//! with a JSON boolean or an empty string (which Go's reducer rejects per
//! item). Everything else — other keywords, `keywords/$seen`
//! path patches (which the reducer ignores), snooze, mailboxIds, several
//! updates, create/destroy, result references, extra or differently-cased
//! keys, non-canonical ids — is `None`. JMAP1's general Email/set adapter
//! gets the next chance to serve it; only unclaimed shapes forward whole.

use super::envelope::{canonical_id, exact_keys, single_call};

/// A `POST /jmap` body that is exactly one `$seen` update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenRequest {
    /// The request's `accountId`. Request-owned: only ever compared with the
    /// verified caller's primary mailbox, never used as the scope (R2).
    pub account_id: i64,
    pub message_id: i64,
    pub seen: SeenValue,
    /// The method call id, echoed back in the response.
    pub client_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeenValue {
    Flag(bool),
    EmptyString,
}

/// `Some` only when `body` is fully expressible as `SetMessageSeen`.
pub fn classify(body: &[u8]) -> Option<SeenRequest> {
    let call = single_call(body, "Email/set")?;
    let args = exact_keys(&call.args, &["accountId", "update"], &["create", "destroy"])?;
    for optional in ["create", "destroy"] {
        if args.get(optional).is_some_and(|v| !v.is_null()) {
            return None;
        }
    }
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
    let update = args.get("update")?.as_object()?;
    if update.len() != 1 {
        return None;
    }
    let (id, patch) = update.iter().next()?;
    let message_id = canonical_id(id)?;
    let patch = exact_keys(patch, &["keywords"], &[])?;
    let keywords = exact_keys(patch.get("keywords")?, &["$seen"], &[])?;
    let seen = match keywords.get("$seen")? {
        serde_json::Value::Bool(value) => SeenValue::Flag(*value),
        serde_json::Value::String(value) if value.is_empty() => SeenValue::EmptyString,
        _ => return None,
    };

    Some(SeenRequest {
        account_id,
        message_id,
        seen,
        client_id: call.client_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEBMAIL: &str = r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","create":null,"update":{"345":{"keywords":{"$seen":true}}},"destroy":null},"0"]]}"#;

    fn with_patch(patch: &str) -> String {
        format!(
            r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{{"accountId":"12","update":{{"345":{patch}}}}},"0"]]}}"#
        )
    }

    #[test]
    fn webmail_mark_read_is_a_seen_request() {
        assert_eq!(
            classify(WEBMAIL.as_bytes()),
            Some(SeenRequest {
                account_id: 12,
                message_id: 345,
                seen: SeenValue::Flag(true),
                client_id: "0".into()
            })
        );
        let unread = with_patch(r#"{"keywords":{"$seen":false}}"#);
        assert_eq!(
            classify(unread.as_bytes()).map(|r| r.seen),
            Some(SeenValue::Flag(false))
        );
    }

    #[test]
    fn any_other_patch_is_not_a_seen_request() {
        for patch in [
            r#"{"keywords":{"$seen":true,"$flagged":true}}"#,
            r#"{"keywords":{"$seen":"true"}}"#,
            r#"{"keywords":{"$seen":1}}"#,
            r#"{"keywords":{"$seen":null}}"#,
            r#"{"keywords":{}}"#,
            r#"{"keywords/$seen":true}"#,
            r#"{"keywords":{"$seen":true},"mailboxIds":{"1":true}}"#,
            r#"{"keywords":{"$seen":true},"snoozeUntil":null}"#,
            r#"{"Keywords":{"$seen":true}}"#,
        ] {
            assert_eq!(classify(with_patch(patch).as_bytes()), None, "{patch}");
        }
    }

    #[test]
    fn any_other_request_shape_is_not_a_seen_request() {
        let cases = [
            // two updates
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}},"2":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // two method calls
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}}}},"0"],["Email/get",{"accountId":"12"},"1"]]}"#,
            // create alongside
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","create":{},"update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // destroy alongside
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","destroy":["9"],"update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // result reference
            r##"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","#update":{},"update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"##,
            // ifInState (Go ignores it; Rust does not guess)
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","ifInState":"3","update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // missing mail capability
            r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Email/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // createdIds in the request
            r#"{"using":["urn:ietf:params:jmap:mail"],"createdIds":{},"methodCalls":[["Email/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // non-canonical ids
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"012","update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","update":{"+1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":12,"update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // another method
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}}}},"0"]]}"#,
            // client id needing escaping, wrong arity
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}}}},"<a>"]]}"#,
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","update":{"1":{"keywords":{"$seen":true}}}}]]}"#,
            // trailing data, not JSON
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[]} x"#,
            "not json",
        ];
        for body in cases {
            assert_eq!(classify(body.as_bytes()), None, "{body}");
        }
    }
}
