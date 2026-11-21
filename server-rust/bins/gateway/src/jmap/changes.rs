//! `Email/changes` served by Rust (#315, #356): Go's `emailChanges`.
//!
//! [`classify_call`] accepts `Email/changes` with Go struct arguments
//! (`accountId`, `sinceState`, `maxChanges`, case-folded ASCII keys, extra keys
//! ignored). `sinceState: null`/absent defaults to `""` (native
//! `cannotCalculateChanges`); `maxChanges: null`/`<= 0` (within `i32`) maps to
//! `None`. Out-of-range `i32` `maxChanges` defers; non-integer/non-string
//! field types return `invalidArguments`.

use super::envelope::{go_i64_field, go_string_field, struct_arguments};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangesArgs {
    Valid {
        raw_account_id: String,
        /// Go's `sinceState`; absent/`null` is `""`.
        since_state: String,
        /// Go's `nullIfZero(maxChanges)`.
        max_changes: Option<i32>,
    },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangesRequest {
    pub client_id: String,
    pub args: ChangesArgs,
}

pub fn classify_call(raw_args: &str, client_id: &str) -> Option<ChangesRequest> {
    let fields = struct_arguments(raw_args, &["accountId", "sinceState", "maxChanges"])?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(detail) => {
                return Some(ChangesRequest {
                    client_id: client_id.to_owned(),
                    args: ChangesArgs::Invalid(detail),
                })
            }
        },
    };
    let since_state = match fields.get("sinceState") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(detail) => {
                return Some(ChangesRequest {
                    client_id: client_id.to_owned(),
                    args: ChangesArgs::Invalid(detail),
                })
            }
        },
    };
    let max_changes = match fields.get("maxChanges") {
        None => None,
        Some(raw) => match go_i64_field(raw.get()) {
            Ok(None) => None,
            Ok(Some(n)) => {
                let n = i32::try_from(n).ok()?;
                (n > 0).then_some(n)
            }
            Err(detail) => {
                return Some(ChangesRequest {
                    client_id: client_id.to_owned(),
                    args: ChangesArgs::Invalid(detail),
                })
            }
        },
    };
    Some(ChangesRequest {
        client_id: client_id.to_owned(),
        args: ChangesArgs::Valid {
            raw_account_id,
            since_state,
            max_changes,
        },
    })
}

/// Go's `decodeStateToken`: base-10 int64, not negative.
pub fn since_state_is_well_formed(s: &str) -> bool {
    s.parse::<i64>().is_ok_and(|v| v >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widened_changes_accepts_nulls_extra_and_negative_i32() {
        assert_eq!(
            classify_call(
                r#"{"ACCOUNTID":"0012","sinceState":null,"maxChanges":null,"extra":true}"#,
                "c1",
            )
            .unwrap()
            .args,
            ChangesArgs::Valid {
                raw_account_id: "0012".into(),
                since_state: String::new(),
                max_changes: None,
            }
        );
        assert_eq!(
            classify_call(r#"{"accountId":"12","sinceState":"1","maxChanges":-1}"#, "c1")
                .unwrap()
                .args,
            ChangesArgs::Valid {
                raw_account_id: "12".into(),
                since_state: "1".into(),
                max_changes: None,
            }
        );
        assert_eq!(
            classify_call(
                r#"{"accountId":"12","sinceState":"1","maxChanges":2147483648}"#,
                "c1"
            ),
            None
        );
        for bad in [
            r#"{"accountId":"12","sinceState":41}"#,
            r#"{"accountId":"12","sinceState":"1","maxChanges":1.5}"#,
            r#"{"accountId":12,"sinceState":"1"}"#,
        ] {
            let r = classify_call(bad, "c1").unwrap();
            assert!(matches!(r.args, ChangesArgs::Invalid(_)), "{bad}");
        }
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
