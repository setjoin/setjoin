//! The current list authority: `jmap_email_query`, called the way Go's
//! `emailQuery` calls it (`CallScoped`: one transaction, the scope GUC, then
//! `SELECT jmap_email_query($1, $2, $3, $4, $5)` with the request's raw
//! `filter`/`sort` JSON and the clamped `position`/`limit` as integers).
use tokio_postgres::types::Type;
use tokio_postgres::Client;

use crate::email_list::{ListEmails, ListQuery, Page};
use crate::harness::BoxError;

/// Besides the page, every call pins the reducer facts Go's answer is built
/// from: exactly the keys `accountId`, `canCalculateChanges` (false), `ids`,
/// `position` (the requested one), `state`, `total`, with `accountId` the
/// mailbox. A change there fails the case.
pub struct ReducerList;

/// The `filter` and `sort` JSON the webmail sends for `q`.
pub fn request_json(q: &ListQuery) -> (String, String) {
    let mut filter = format!(r#"{{"inMailbox":"{}""#, q.tag);
    if let Some(focus) = q.focus {
        filter += &format!(r#","focus":"{focus}""#);
    }
    match q.seen {
        Some(true) => filter += r#","hasKeyword":"$seen""#,
        Some(false) => filter += r#","hasKeyword":"$unseen""#,
        None => {}
    }
    filter += "}";
    let sort = format!(
        r#"[{{"property":"receivedAt","isAscending":{}}}]"#,
        q.ascending
    );
    (filter, sort)
}

impl ListEmails for ReducerList {
    fn name(&self) -> &'static str {
        "reducer jmap_email_query"
    }

    async fn list(
        &self,
        client: &mut Client,
        mailbox: i64,
        q: ListQuery,
    ) -> Result<Page, BoxError> {
        let (filter, sort) = request_json(&q);
        let tx = client.transaction().await?;
        tx.query_typed(
            "SELECT set_config('app.current_mailbox_id', $1, true)",
            &[(&mailbox.to_string(), Type::TEXT)],
        )
        .await?;
        let row = tx
            .query_typed(
                "SELECT (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(r) k), \
                        r->>'accountId', r->'canCalculateChanges' = 'false'::jsonb, \
                        (r->>'position')::int8, (r->>'state')::int8, (r->>'total')::int8, \
                        ARRAY(SELECT x::int8 FROM jsonb_array_elements_text(r->'ids') x) \
                   FROM (SELECT jmap_email_query($1, $2::jsonb, $3::jsonb, $4, $5) AS r) q",
                &[
                    (&mailbox, Type::INT8),
                    (&filter, Type::TEXT),
                    (&sort, Type::TEXT),
                    (&q.position, Type::INT4),
                    (&q.limit, Type::INT4),
                ],
            )
            .await?
            .remove(0);
        tx.commit().await?;
        let keys: Vec<String> = row.get(0);
        let pins = [
            (
                keys == [
                    "accountId",
                    "canCalculateChanges",
                    "ids",
                    "position",
                    "state",
                    "total",
                ],
                "key set",
            ),
            (row.get::<_, String>(1) == mailbox.to_string(), "accountId"),
            (row.get::<_, bool>(2), "canCalculateChanges false"),
            (
                row.get::<_, i64>(3) == i64::from(q.position),
                "position echoed",
            ),
        ];
        for (ok, what) in pins {
            if !ok {
                return Err(format!("reducer contract changed: {what} (keys {keys:?})").into());
            }
        }
        Ok(Page {
            state: row.get(4),
            total: row.get(5),
            ids: row.get(6),
        })
    }
}
