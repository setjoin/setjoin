//! The webmail inbox list (`Email/query`) served by Rust (#216).
//!
//! [`classify`] recognises the one request shape the route may serve: a
//! single `Email/query` whose arguments are `accountId`, `filter` =
//! `{"inMailbox": "<tag>"}` plus optional `focus` (`"focused"`/`"other"`) and
//! `hasKeyword` (`"$seen"`/`"$unseen"`), optional `sort` (absent, `[]`, or
//! one `receivedAt` comparator with an optional boolean `isAscending`),
//! optional integer `position` (0..=i32::MAX) and optional integer `limit`.
//! That is what `inboxStore.loadEmails` sends for the Inbox (and any other
//! tag view) with no search. Everything else — other filters or sort
//! properties, `anchor`, `calculateTotal`, `collapseThreads`, extra or
//! differently-cased keys, nulls, non-canonical ids, several calls, result
//! references — is `None`. JMAP1's general Email/query adapter gets the
//! next chance to serve it; only unclaimed shapes forward whole.
//!
//! `limit` is clamped as Go's `emailQuery` clamps it (`<= 0` or `> 256` →
//! 50); `position` is echoed as requested, past `total` included.
//!
//! [`body`] writes Go's bytes for the answer: Go returns the reducer's JSONB
//! as a `json.RawMessage`, which `json.Encoder` compacts, so the keys keep
//! PostgreSQL's JSONB order (shorter keys first, then bytewise): `ids`,
//! `state`, `total`, `position`, `accountId`, `canCalculateChanges`.
//! `ids` are strings (`id::TEXT`); `total`/`position` numbers.
//!
//! This adapter serves only `Email/query`. The separate JMAP1 Email/get
//! adapter includes its audit write; encrypted mail still requires Go's
//! S/MIME decrypt-on-read helper (#328).
use serde_json::Value;
use setjoin_jmap::{EmailListPage, EmailListQuery, Focus};

use super::envelope::{canonical_id, exact_keys, single_call};

/// A `POST /jmap` body the list route can answer completely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListRequest {
    /// Request-owned: only compared with the verified caller's primary
    /// mailbox, never used as the scope (R2).
    pub account_id: i64,
    pub client_id: String,
    pub query: EmailListQuery,
}

/// Go's `emailQuery` default and cap.
const DEFAULT_LIMIT: i32 = 50;
const MAX_LIMIT: i64 = 256;

pub fn classify(body: &[u8]) -> Option<ListRequest> {
    let call = single_call(body, "Email/query")?;
    let client_id = call.client_id.as_str();
    let args = exact_keys(
        &call.args,
        &["accountId", "filter"],
        &["sort", "position", "limit"],
    )?;
    let account_id = canonical_id(args.get("accountId")?.as_str()?)?;

    let filter = exact_keys(
        args.get("filter")?,
        &["inMailbox"],
        &["focus", "hasKeyword"],
    )?;
    let tag = canonical_id(filter.get("inMailbox")?.as_str()?)?;
    let focus = match filter.get("focus").map(Value::as_str) {
        None => None,
        Some(Some("focused")) => Some(Focus::Focused),
        Some(Some("other")) => Some(Focus::Other),
        Some(_) => return None,
    };
    let seen = match filter.get("hasKeyword").map(Value::as_str) {
        None => None,
        Some(Some("$seen")) => Some(true),
        Some(Some("$unseen")) => Some(false),
        Some(_) => return None,
    };

    let ascending = match args.get("sort") {
        None => false,
        Some(sort) => match sort.as_array()?.as_slice() {
            [] => false,
            [comparator] => {
                let c = exact_keys(comparator, &["property"], &["isAscending"])?;
                if c.get("property")?.as_str()? != "receivedAt" {
                    return None;
                }
                // The reducer's COALESCE(isAscending, true).
                match c.get("isAscending") {
                    None => true,
                    Some(v) => v.as_bool()?,
                }
            }
            _ => return None,
        },
    };

    let position = match args.get("position") {
        None => 0,
        Some(v) => i32::try_from(v.as_i64()?).ok().filter(|p| *p >= 0)?,
    };
    let limit = match args.get("limit") {
        None => DEFAULT_LIMIT,
        Some(v) => match v.as_i64()? {
            n if n <= 0 || n > MAX_LIMIT => DEFAULT_LIMIT,
            n => n as i32,
        },
    };

    Some(ListRequest {
        account_id,
        client_id: client_id.to_owned(),
        query: EmailListQuery {
            tag,
            focus,
            seen,
            ascending,
            position,
            limit,
        },
    })
}

/// Go's response body for a served list request.
pub fn body(
    session_state: &str,
    mailbox: i64,
    position: i32,
    client_id: &str,
    page: &EmailListPage,
) -> String {
    let ids: Vec<String> = page.ids.iter().map(|id| format!("\"{id}\"")).collect();
    format!(
        r#"{{"sessionState":"{session_state}","methodResponses":[["Email/query",{{"ids":[{}],"state":"{}","total":{},"position":{position},"accountId":"{mailbox}","canCalculateChanges":false}},"{client_id}"]]}}"#,
        ids.join(","),
        page.email_state,
        page.total,
    ) + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `emailQuery(filter, sort, 50, position)` sends for the Inbox.
    const WEBMAIL: &str = r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"12","filter":{"inMailbox":"77","focus":"focused"},"sort":[{"property":"receivedAt","isAscending":false}],"limit":50,"position":100},"0"]]}"#;

    fn with_args(args: &str) -> String {
        format!(
            r#"{{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{args},"c1"]]}}"#
        )
    }

    fn query(args: &str) -> Option<EmailListQuery> {
        classify(with_args(args).as_bytes()).map(|r| r.query)
    }

    #[test]
    fn webmail_inbox_page_is_a_list_request() {
        assert_eq!(
            classify(WEBMAIL.as_bytes()),
            Some(ListRequest {
                account_id: 12,
                client_id: "0".into(),
                query: EmailListQuery {
                    tag: 77,
                    focus: Some(Focus::Focused),
                    seen: None,
                    ascending: false,
                    position: 100,
                    limit: 50,
                },
            })
        );
    }

    #[test]
    fn optional_arguments_take_go_and_reducer_defaults() {
        let q = query(r#"{"accountId":"12","filter":{"inMailbox":"77"}}"#).unwrap();
        assert_eq!(
            (q.focus, q.seen, q.ascending, q.position, q.limit),
            (None, None, false, 0, 50)
        );
        // Empty sort = the reducer's default order; a comparator without
        // isAscending is ascending (COALESCE(..., true)).
        assert!(
            !query(r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":[]}"#)
                .unwrap()
                .ascending
        );
        assert!(query(r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":[{"property":"receivedAt"}]}"#).unwrap().ascending);
        let other = query(r#"{"accountId":"12","filter":{"inMailbox":"77","focus":"other","hasKeyword":"$unseen"}}"#).unwrap();
        assert_eq!((other.focus, other.seen), (Some(Focus::Other), Some(false)));
        assert_eq!(
            query(r#"{"accountId":"12","filter":{"inMailbox":"77","hasKeyword":"$seen"}}"#)
                .unwrap()
                .seen,
            Some(true)
        );
    }

    #[test]
    fn limit_is_clamped_like_go() {
        let limit = |n: &str| {
            query(&format!(
                r#"{{"accountId":"12","filter":{{"inMailbox":"7"}},"limit":{n}}}"#
            ))
            .map(|q| q.limit)
        };
        assert_eq!(limit("1"), Some(1));
        assert_eq!(limit("256"), Some(256));
        assert_eq!(limit("257"), Some(50));
        assert_eq!(limit("0"), Some(50));
        assert_eq!(limit("-3"), Some(50));
        // Not an integer Go's json.Unmarshal would accept into int: Go's.
        assert_eq!(limit("1.5"), None);
        assert_eq!(limit("1e2"), None);
        assert_eq!(limit("\"10\""), None);
        assert_eq!(limit("null"), None);
    }

    #[test]
    fn position_must_be_a_non_negative_int4() {
        let pos = |n: &str| {
            query(&format!(
                r#"{{"accountId":"12","filter":{{"inMailbox":"7"}},"position":{n}}}"#
            ))
            .map(|q| q.position)
        };
        assert_eq!(pos("0"), Some(0));
        assert_eq!(pos("2147483647"), Some(i32::MAX));
        assert_eq!(pos("2147483648"), None);
        assert_eq!(pos("-1"), None);
        assert_eq!(pos("null"), None);
    }

    #[test]
    fn any_other_query_shape_goes_to_go() {
        for args in [
            r#"{"accountId":"12","filter":{"inMailbox":"77","text":"x"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77","from":"a@b"}}"#,
            r#"{"accountId":"12","filter":{"inArchive":true}}"#,
            r#"{"accountId":"12","filter":{}}"#,
            r#"{"accountId":"12","filter":null}"#,
            r#"{"accountId":"12"}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"__no_match__"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":77}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"077"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77","focus":"Other"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77","focus":null}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77","hasKeyword":"$flagged"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77","hasKeyword":"$SEEN"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":[{"property":"subject","isAscending":true}]}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":[{"property":"receivedAt","isAscending":"true"}]}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":[{"property":"receivedAt","collation":"x"}]}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":[{"property":"receivedAt"},{"property":"size"}]}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"sort":{"property":"receivedAt"}}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"anchor":"5"}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"calculateTotal":true}"#,
            r#"{"accountId":"12","filter":{"inMailbox":"77"},"collapseThreads":true}"#,
            r#"{"accountId":"12","Filter":{"inMailbox":"77"}}"#,
            r##"{"accountId":"12","#filter":{},"filter":{"inMailbox":"77"}}"##,
            r#"{"accountId":"012","filter":{"inMailbox":"77"}}"#,
            r#"{"accountId":12,"filter":{"inMailbox":"77"}}"#,
        ] {
            assert_eq!(query(args), None, "{args}");
        }
        for body in [
            // two calls (Email/query + Email/get back-reference)
            r##"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"12","filter":{"inMailbox":"7"}},"0"],["Email/get",{"accountId":"12","#ids":{"resultOf":"0","name":"Email/query","path":"/ids"}},"1"]]}"##,
            r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Email/query",{"accountId":"12","filter":{"inMailbox":"7"}},"0"]]}"#,
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"12","filter":{"inMailbox":"7"}},"<x>"]]}"#,
            r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/get",{"accountId":"12","ids":["7"]},"0"]]}"#,
            r#"{"using":["urn:ietf:params:jmap:mail"],"createdIds":{},"methodCalls":[["Email/query",{"accountId":"12","filter":{"inMailbox":"7"}},"0"]]}"#,
        ] {
            assert_eq!(classify(body.as_bytes()), None, "{body}");
        }
    }

    #[test]
    fn mark_read_and_list_never_both_claim_a_body() {
        use crate::jmap::seen;
        assert!(seen::classify(WEBMAIL.as_bytes()).is_none());
        let seen = r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"12","update":{"345":{"keywords":{"$seen":true}}}},"0"]]}"#;
        assert!(classify(seen.as_bytes()).is_none());
    }

    /// Review item 6: expected bytes are REAL Go output from mailserverd's
    /// `emailQuery` on the real stack (rp07 review-fix kit `capture.sh`,
    /// account 1, Inbox tag 1, Trash tag 4), committed under `tests/golden/`;
    /// the inputs are the values that capture answered with.
    #[test]
    fn bodies_equal_captured_go_output() {
        const S: &str = "71-0-0-69-0-0-0-1793295569";
        let first = EmailListPage {
            email_state: 71,
            total: 69,
            ids: (11..=60).collect(),
        };
        assert_eq!(
            body(S, 1, 0, "0", &first),
            include_str!("../../tests/golden/go-list-1.json")
        );
        let past_end = EmailListPage {
            email_state: 71,
            total: 69,
            ids: vec![],
        };
        assert_eq!(
            body(S, 1, 500, "0", &past_end),
            include_str!("../../tests/golden/go-list-3.json")
        );
        let empty_tag = EmailListPage {
            email_state: 71,
            total: 0,
            ids: vec![],
        };
        assert_eq!(
            body(S, 1, 0, "0", &empty_tag),
            include_str!("../../tests/golden/go-list-5.json")
        );
    }
}
