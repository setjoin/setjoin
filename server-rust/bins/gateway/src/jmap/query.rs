//! General `Email/query` served by Rust (#315, #356): Go's `emailQuery`.
//!
//! [`classify_call`] accepts `Email/query` with Go struct arguments
//! (`accountId`, `filter`, `sort`, `position`, `limit`, ASCII case-folded,
//! ignoring `calculateTotal`, `collapseThreads`, `anchor`, extra keys).
//! `null` `position`/`limit` map to `0` (`limit` clamped to `50` outside
//! `1..=256`); non-integer types return `invalidArguments`.

use super::envelope::{go_i64_field, go_string_field, struct_arguments};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryArgs {
    Valid {
        raw_account_id: String,
        /// Go's `RawMessage`: `None` when the key is absent.
        filter: Option<String>,
        sort: Option<String>,
        /// `Err(())` when an `i64` overflows `i32` (PostgreSQL `22003` -> `serverFail`).
        position: Result<i32, ()>,
        limit: i32,
    },
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRequest {
    pub client_id: String,
    pub args: QueryArgs,
}

pub fn classify_call(raw_args: &str, client_id: &str) -> Option<QueryRequest> {
    let fields = struct_arguments(
        raw_args,
        &["accountId", "filter", "sort", "position", "limit"],
    )?;
    let raw_account_id = match fields.get("accountId") {
        None => String::new(),
        Some(raw) => match go_string_field(raw.get()) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(detail) => {
                return Some(QueryRequest {
                    client_id: client_id.to_owned(),
                    args: QueryArgs::Invalid(detail),
                })
            }
        },
    };
    let position = match fields.get("position") {
        None => Ok(0),
        Some(raw) => match go_i64_field(raw.get()) {
            Ok(None) => Ok(0),
            Ok(Some(n)) => i32::try_from(n).map_err(|_| ()),
            Err(detail) => {
                return Some(QueryRequest {
                    client_id: client_id.to_owned(),
                    args: QueryArgs::Invalid(detail),
                })
            }
        },
    };
    let limit = match fields.get("limit") {
        None => 50,
        Some(raw) => match go_i64_field(raw.get()) {
            Ok(Some(n)) if (1..=256).contains(&n) => n as i32,
            Ok(_) => 50,
            Err(detail) => {
                return Some(QueryRequest {
                    client_id: client_id.to_owned(),
                    args: QueryArgs::Invalid(detail),
                })
            }
        },
    };
    Some(QueryRequest {
        client_id: client_id.to_owned(),
        args: QueryArgs::Valid {
            raw_account_id,
            filter: fields.get("filter").map(|v| v.get().to_owned()),
            sort: fields.get("sort").map(|v| v.get().to_owned()),
            position,
            limit,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_and_sort_pass_through_and_extra_keys_ignored() {
        let r = classify_call(
            r#"{"ACCOUNTID":"0012","filter":{"text":"a  b","minSize":12345678901234567890},"sort":null,"position":null,"limit":null,"calculateTotal":true,"collapseThreads":true,"anchor":"1"}"#,
            "c1",
        )
        .unwrap();
        assert_eq!(
            r.args,
            QueryArgs::Valid {
                raw_account_id: "0012".into(),
                filter: Some(r#"{"text":"a  b","minSize":12345678901234567890}"#.into()),
                sort: Some("null".into()),
                position: Ok(0),
                limit: 50,
            }
        );

        let r = classify_call(r#"{"accountId":"12","position":2147483648}"#, "c1").unwrap();
        assert!(matches!(
            r.args,
            QueryArgs::Valid {
                position: Err(()),
                ..
            }
        ));

        for bad in [
            r#"{"accountId":"12","limit":1.5}"#,
            r#"{"accountId":"12","limit":"5"}"#,
            r#"{"accountId":12}"#,
        ] {
            let r = classify_call(bad, "c1").unwrap();
            assert!(matches!(r.args, QueryArgs::Invalid(_)), "{bad}");
        }
    }
}
