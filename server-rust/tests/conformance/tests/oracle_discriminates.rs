//! Negative self-test: deliberately wrong implementations must fail the
//! mark-read and email-list oracles, so a green oracle run means something.
use setjoin_conformance::email_list::{self, ListEmails, ListQuery, Page};
use setjoin_conformance::harness::{BoxError, Db};
use setjoin_conformance::mark_read::{self, SeenOutcome, SetSeen};
use setjoin_conformance::reducer::ReducerPath;
use setjoin_conformance::reducer_list::ReducerList;
use setjoin_contracts::command::SetMessageSeen;
use tokio_postgres::types::Type;
use tokio_postgres::Client;

/// Claims success, writes nothing.
struct NoWrite;
impl SetSeen for NoWrite {
    fn name(&self) -> &'static str {
        "no-write"
    }
    async fn set_seen(&self, _: &mut Client, _: SetMessageSeen) -> Result<SeenOutcome, BoxError> {
        Ok(SeenOutcome::Updated)
    }
}

/// The reducer, then a second (unjournaled) state bump and push.
struct DoubleBump;
impl SetSeen for DoubleBump {
    fn name(&self) -> &'static str {
        "double-bump"
    }
    async fn set_seen(&self, c: &mut Client, cmd: SetMessageSeen) -> Result<SeenOutcome, BoxError> {
        let out = ReducerPath.set_seen(c, cmd).await?;
        let mb = cmd.mailbox.get();
        c.query_typed(
            "SELECT app_notify('tag:' || $1, json_build_object('event','state_change','tag_id',NULL,'state',bump_email_state($1))::text)",
            &[(&mb, Type::INT8)],
        )
        .await?;
        Ok(out)
    }
}

/// Updates the message by id alone, ignoring which mailbox asked (an R3
/// break). It writes on the owner connection: under `setjoin_app`, FORCE RLS
/// would already hide the foreign row, and this impl must really misbehave.
struct IgnoresOwnership<'a>(&'a Db);
impl SetSeen for IgnoresOwnership<'_> {
    fn name(&self) -> &'static str {
        "ignores-ownership"
    }
    async fn set_seen(&self, _: &mut Client, cmd: SetMessageSeen) -> Result<SeenOutcome, BoxError> {
        let owner = self.0.connect().await?;
        let id = cmd.message.get();
        owner
            .query_typed(
                "UPDATE messages SET is_read = $2 WHERE id = $1",
                &[(&id, Type::INT8), (&cmd.seen, Type::BOOL)],
            )
            .await?;
        Ok(SeenOutcome::NotFound)
    }
}

macro_rules! must_fail {
    ($name:ident: |$db:ident| $imp:expr => $($case:ident),+) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let Some($db) = Db::for_case(stringify!($name)) else { return };
            let imp = $imp;
            $(
                assert!(
                    mark_read::$case(&$db, &imp).await.is_err(),
                    "{} passed {} — the oracle does not discriminate",
                    imp.name(),
                    stringify!($case)
                );
            )+
        }
    };
}

must_fail!(no_write_fails_the_oracle: |db| NoWrite =>
    read_sets_is_read,
    read_adjusts_unread_on_every_tag,
    read_bumps_email_state_once,
    read_writes_one_journal_row,
    read_pushes_once,
    unread_restores_unread_on_every_tag);

must_fail!(double_bump_fails_the_oracle: |db| DoubleBump =>
    read_bumps_email_state_once,
    read_pushes_once);

must_fail!(ignoring_ownership_fails_the_oracle: |db| IgnoresOwnership(&db) =>
    foreign_mailbox_message_refused_without_effect);

// ── email-list oracle (#216) ──

/// Lists every message carrying the tag by tag alone, on the owner
/// connection: no mailbox predicate (an R1 break), no deleted/snooze rules.
struct ByTagOnly<'a>(&'a Db);
impl ListEmails for ByTagOnly<'_> {
    fn name(&self) -> &'static str {
        "by-tag-only"
    }
    async fn list(&self, _: &mut Client, mailbox: i64, q: ListQuery) -> Result<Page, BoxError> {
        let owner = self.0.connect().await?;
        let row = owner
            .query_typed(
                "SELECT (SELECT jmap_email_state::int8 FROM mailboxes WHERE id = $1), \
                        (SELECT count(*) FROM message_tags WHERE tag_id = $2)::int8, \
                        ARRAY(SELECT mt.message_id FROM message_tags mt JOIN messages m ON m.id = mt.message_id \
                               WHERE mt.tag_id = $2 \
                               ORDER BY m.pinned_at IS NOT NULL DESC, m.received_at DESC \
                               LIMIT $4 OFFSET $3)",
                &[
                    (&mailbox, Type::INT8),
                    (&q.tag, Type::INT8),
                    (&i64::from(q.position), Type::INT8),
                    (&i64::from(q.limit), Type::INT8),
                ],
            )
            .await?
            .remove(0);
        Ok(Page {
            state: row.get(0),
            total: row.get(1),
            ids: row.get(2),
        })
    }
}

/// The reducer's page, then marks the listed messages read (a hidden
/// mark-read during listing).
struct MarksListedRead;
impl ListEmails for MarksListedRead {
    fn name(&self) -> &'static str {
        "marks-listed-read"
    }
    async fn list(&self, c: &mut Client, mailbox: i64, q: ListQuery) -> Result<Page, BoxError> {
        let page = ReducerList.list(c, mailbox, q).await?;
        let tx = c.transaction().await?;
        tx.query_typed(
            "SELECT set_config('app.current_mailbox_id', $1, true)",
            &[(&mailbox.to_string(), Type::TEXT)],
        )
        .await?;
        tx.query_typed(
            "SELECT jmap_email_set_update($1, jsonb_object_agg(id::text, '{\"keywords\":{\"$seen\":true}}'::jsonb)) \
               FROM unnest($2::int8[]) id HAVING count(*) > 0",
            &[(&mailbox, Type::INT8), (&page.ids, Type::INT8_ARRAY)],
        )
        .await?;
        tx.commit().await?;
        Ok(page)
    }
}

macro_rules! list_must_fail {
    ($name:ident: |$db:ident| $imp:expr => $($case:ident),+) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let Some($db) = Db::for_case(stringify!($name)) else { return };
            let imp = $imp;
            $(
                assert!(
                    email_list::$case(&$db, &imp).await.is_err(),
                    "{} passed {} — the oracle does not discriminate",
                    imp.name(),
                    stringify!($case)
                );
            )+
        }
    };
}

list_must_fail!(by_tag_only_fails_the_list_oracle: |db| ByTagOnly(&db) =>
    first_page_is_newest_first_with_pinned_on_top,
    stale_position_past_total_is_an_empty_page,
    foreign_tag_lists_nothing);

list_must_fail!(hidden_mark_read_fails_the_list_oracle: |db| MarksListedRead =>
    listing_has_no_side_effects);

/// The pre-#223 order: pinned, then `received_at` with no `id` tiebreak, so
/// messages sharing a `received_at` page in whatever order the plan yields.
struct NoTiebreak<'a>(&'a Db);
impl ListEmails for NoTiebreak<'_> {
    fn name(&self) -> &'static str {
        "no-tiebreak"
    }
    async fn list(&self, _: &mut Client, mailbox: i64, q: ListQuery) -> Result<Page, BoxError> {
        let owner = self.0.connect().await?;
        let dir = if q.ascending { "ASC" } else { "DESC" };
        let filter = "m.mailbox_id = $1 AND NOT m.is_deleted \
             AND EXISTS (SELECT 1 FROM message_tags mt WHERE mt.message_id = m.id \
                          AND mt.received_at = m.received_at AND mt.tag_id = $2) \
             AND NOT EXISTS (SELECT 1 FROM message_tags ms JOIN tags ts ON ts.id = ms.tag_id \
                              WHERE ms.message_id = m.id AND ms.received_at = m.received_at \
                                AND ts.exclusive_group = 'snooze')";
        let sql = format!(
            "SELECT (SELECT jmap_email_state::int8 FROM mailboxes WHERE id = $1), \
                    (SELECT count(*) FROM messages m WHERE {filter})::int8, \
                    ARRAY(SELECT m.id FROM messages m WHERE {filter} \
                           ORDER BY m.pinned_at IS NOT NULL DESC, m.received_at {dir} \
                           LIMIT $4 OFFSET $3)"
        );
        let row = owner
            .query_typed(
                &sql,
                &[
                    (&mailbox, Type::INT8),
                    (&q.tag, Type::INT8),
                    (&i64::from(q.position), Type::INT8),
                    (&i64::from(q.limit), Type::INT8),
                ],
            )
            .await?
            .remove(0);
        Ok(Page {
            state: row.get(0),
            total: row.get(1),
            ids: row.get(2),
        })
    }
}

list_must_fail!(no_tiebreak_fails_the_list_oracle: |db| NoTiebreak(&db) =>
    equal_received_at_pages_in_id_order);
