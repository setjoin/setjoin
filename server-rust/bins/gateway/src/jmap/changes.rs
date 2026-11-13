//! `Email/changes` served by Rust (#315): Go's `emailChanges`.
//!
//! [`classify`] recognises one `Email/changes` call whose arguments are
//! `accountId` (a canonical id string), an optional string `sinceState` and an
//! optional integer `maxChanges` in `0..=i32::MAX`. Anything else (other keys,
//! a non-string state, negative or huge caps, several calls, result
//! references) is `None` and the whole request goes to Go untouched.
//!
//! The answer is Go's bytes: the reducer's JSONB compacted as
//! `json.RawMessage` ([`super::reply::go_compact`]) inside the standard
//! response envelope, or Go's method-level error object. Order of checks, as
//! in Go's `emailChanges`: account (`parseAccountID`), then the client state
//! (`sinceStateError`), then the reducer.
use serde_json::Value;

use super::envelope::{canonical_id, exact_keys, single_call};

/// A `POST /jmap` body that is exactly one `Email/changes` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangesRequest {
    /// Request-owned: compared with the verified caller's primary mailbox,
    /// never used as the scope (R2).
    pub account_id: i64,
    pub client_id: String,
    /// Go's `sinceState`; absent is `""`.
    pub since_state: String,
    /// Go's `nullIfZero(maxChanges)`.
    pub max_changes: Option<i32>,
}

pub fn classify(body: &[u8]) -> Option<ChangesRequest> {
    let call = single_call(body, "Email/changes")?;
    let args = exact_keys(&call.args, &["accountId"], &["sinceState", "maxChanges"])?;
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;
    let since_state = match args.get("sinceState") {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return None,
    };
    let max_changes = match args.get("maxChanges") {
        None => None,
        Some(v) => match i32::try_from(v.as_i64()?).ok().filter(|n| *n >= 0)? {
            0 => None,
            n => Some(n),
        },
    };
    Some(ChangesRequest {
        account_id,
        client_id: call.client_id,
        since_state,
        max_changes,
    })
}

/// Go's `decodeStateToken`: base-10 int64, not negative.
pub fn since_state_is_well_formed(s: &str) -> bool {
    s.parse::<i64>().is_ok_and(|v| v >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(args: &str) -> String {
        format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/changes",{args},"c1"]]}}"#
        )
    }

    fn parse(args: &str) -> Option<ChangesRequest> {
        classify(call(args).as_bytes())
    }

    #[test]
    fn the_webmail_shape_is_claimed() {
        assert_eq!(
            parse(r#"{"accountId":"12","sinceState":"41","maxChanges":50}"#),
            Some(ChangesRequest {
                account_id: 12,
                client_id: "c1".into(),
                since_state: "41".into(),
                max_changes: Some(50),
            })
        );
    }

    #[test]
    fn omitted_and_zero_arguments_take_gos_defaults() {
        let r = parse(r#"{"accountId":"12"}"#).unwrap();
        assert_eq!((r.since_state.as_str(), r.max_changes), ("", None));
        assert_eq!(
            parse(r#"{"accountId":"12","sinceState":"0","maxChanges":0}"#)
                .unwrap()
                .max_changes,
            None
        );
    }

    #[test]
    fn anything_else_goes_to_go() {
        for args in [
            r#"{"accountId":"12","sinceState":41}"#,
            r#"{"accountId":"12","sinceState":null}"#,
            r#"{"accountId":"12","sinceState":"1","maxChanges":-1}"#,
            r#"{"accountId":"12","sinceState":"1","maxChanges":2147483648}"#,
            r#"{"accountId":"12","sinceState":"1","maxChanges":1.5}"#,
            r#"{"accountId":"12","sinceState":"1","maxChanges":null}"#,
            r#"{"accountId":"12","sinceState":"1","extra":true}"#,
            r#"{"accountId":"012","sinceState":"1"}"#,
            r#"{"accountId":12,"sinceState":"1"}"#,
            r#"{"sinceState":"1"}"#,
        ] {
            assert_eq!(parse(args), None, "{args}");
        }
        let two = r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/changes",{"accountId":"1"},"a"],["Email/changes",{"accountId":"1"},"b"]]}"#;
        assert_eq!(classify(two.as_bytes()), None);
    }

    #[test]
    fn state_tokens_follow_go_parse_int() {
        for ok in ["0", "7", "+5", "-0", "0007", "9223372036854775807"] {
            assert!(since_state_is_well_formed(ok), "{ok}");
        }
        for bad in [
            "",
            "abc",
            "-1",
            "1.5",
            "9223372036854775808",
            " 1",
            "1_0",
            "unavailable",
        ] {
            assert!(!since_state_is_well_formed(bad), "{bad}");
        }
    }
}
