//! The email-list oracle (#216) against the Rust read
//! (`setjoin_jmap::query_email_list`): the same `email_list` cases the reducer
//! runs, unchanged. The read owns its `READ ONLY` scoped transaction through
//! `setjoin-pg` on its own pool (`setjoin_app` from `DB_APP_DSN` when set, as
//! the reducer path runs), so the oracle's `Client` resolves only the
//! session's actor.
use setjoin_conformance::email_list::{self, ListEmails, ListQuery, Page};
use setjoin_conformance::harness::{BoxError, Db};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_jmap::{query_email_list, EmailListQuery, Focus};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
use tokio_postgres::types::Type;
use tokio_postgres::Client;

pub struct RustRead {
    exec: ScopedExecutor,
}

impl RustRead {
    pub fn new(db: &Db) -> Self {
        let dsn = db.app.as_deref().unwrap_or(&db.dsn);
        Self {
            exec: ScopedExecutor::from_dsn(dsn, 2).expect("read pool"),
        }
    }
}

impl ListEmails for RustRead {
    fn name(&self) -> &'static str {
        "rust setjoin-jmap query_email_list"
    }

    async fn list(
        &self,
        client: &mut Client,
        mailbox: i64,
        q: ListQuery,
    ) -> Result<Page, BoxError> {
        // Plays the authentication boundary: the session's actor is the
        // mailbox's bound user.
        let user: i64 = client
            .query_typed(
                "SELECT user_id FROM mailboxes WHERE id = $1",
                &[(&mailbox, Type::INT8)],
            )
            .await?[0]
            .get(0);
        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(user).map_err(|_| "actor id")?,
            MailboxId::new(mailbox).map_err(|_| "mailbox id")?,
            Generation(1),
        );
        let query = EmailListQuery {
            tag: q.tag,
            focus: match q.focus {
                None => None,
                Some("focused") => Some(Focus::Focused),
                Some("other") => Some(Focus::Other),
                Some(other) => return Err(format!("unknown focus {other}").into()),
            },
            seen: q.seen,
            ascending: q.ascending,
            position: q.position,
            limit: q.limit,
        };
        let page = query_email_list(&self.exec, &auth, &query)
            .await
            .map_err(|e| format!("{e:?}"))?;
        Ok(Page {
            state: page.email_state,
            total: page.total,
            ids: page.ids,
        })
    }
}

macro_rules! oracle_cases {
    ($($case:ident),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "current_thread")]
            async fn $case() {
                let Some(db) = Db::for_case(stringify!($case)) else { return };
                let imp = RustRead::new(&db);
                if let Err(e) = email_list::$case(&db, &imp).await {
                    panic!("{}: {e:?}", stringify!($case));
                }
            }
        )+

        #[test]
        fn every_oracle_case_runs() {
            assert_eq!(&[$(stringify!($case)),+][..], email_list::CASES);
        }
    };
}

oracle_cases!(
    first_page_is_newest_first_with_pinned_on_top,
    pages_continue_without_gaps_or_repeats,
    last_partial_page_and_page_at_total,
    stale_position_past_total_is_an_empty_page,
    empty_tag_is_an_empty_page,
    oldest_first_keeps_pinned_on_top,
    unread_and_read_filters,
    focused_and_other_split,
    snoozed_hidden_from_location_but_listed_under_snooze,
    label_lists_its_own_messages,
    foreign_tag_lists_nothing,
    listing_has_no_side_effects,
    equal_received_at_pages_in_id_order,
);
