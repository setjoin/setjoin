//! Email-list parity oracle (#216). The contract is today's
//! `jmap_email_query` (mailserver/sql/reducers/jmap_email.sql) for the
//! request the webmail inbox sends: `inMailbox` plus optional `focus` and
//! `hasKeyword` `$seen`/`$unseen`, sorted by `receivedAt`, paged by
//! `position`/`limit`. Every case takes an implementation of [`ListEmails`],
//! so the reducer and the Rust read run the same cases unchanged.
//!
//! Expected pages are fixture literals ([`ListFixture`]): message ids in the
//! order the fixture's `received_at`/`pinned_at` values define, never read
//! back from the implementation under test. Every case removes its
//! fixtures, pass or fail.
use std::fmt::Debug;
use std::future::Future;

use tokio_postgres::types::Type;
use tokio_postgres::Client;

use crate::fixture::{self, Account, Snapshot};
use crate::harness::{BoxError, Db, Listener};

/// One page request, in the webmail's terms (already clamped as Go's
/// handler clamps `limit`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListQuery {
    /// `inMailbox`
    pub tag: i64,
    /// `focus`: `"focused"` or `"other"`.
    pub focus: Option<&'static str>,
    /// `hasKeyword`: `Some(true)` = `$seen`, `Some(false)` = `$unseen`.
    pub seen: Option<bool>,
    pub ascending: bool,
    pub position: i32,
    pub limit: i32,
}

impl ListQuery {
    pub fn tag(tag: i64) -> Self {
        Self {
            tag,
            focus: None,
            seen: None,
            ascending: false,
            position: 0,
            limit: 50,
        }
    }
    pub fn page(self, position: i32, limit: i32) -> Self {
        Self {
            position,
            limit,
            ..self
        }
    }
}

/// The data an `Email/query` answer carries beyond its constant fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub state: i64,
    pub total: i64,
    pub ids: Vec<i64>,
}

/// An implementation of the list read. It owns its own transaction on
/// `client` (a connection from the `DB_DSN` pool) or its own pool.
pub trait ListEmails {
    fn name(&self) -> &'static str;
    fn list(
        &self,
        client: &mut Client,
        mailbox: i64,
        query: ListQuery,
    ) -> impl Future<Output = Result<Page, BoxError>>;
}

pub const CASES: &[&str] = &[
    "first_page_is_newest_first_with_pinned_on_top",
    "pages_continue_without_gaps_or_repeats",
    "last_partial_page_and_page_at_total",
    "stale_position_past_total_is_an_empty_page",
    "empty_tag_is_an_empty_page",
    "oldest_first_keeps_pinned_on_top",
    "unread_and_read_filters",
    "focused_and_other_split",
    "snoozed_hidden_from_location_but_listed_under_snooze",
    "label_lists_its_own_messages",
    "foreign_tag_lists_nothing",
    "listing_has_no_side_effects",
    "equal_received_at_pages_in_id_order",
];

fn expect_eq<T: PartialEq + Debug>(
    imp: &impl ListEmails,
    what: &str,
    actual: T,
    expected: T,
) -> Result<(), BoxError> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{}: {what}: expected {expected:?}, got {actual:?}",
            imp.name()
        )
        .into())
    }
}

/// One mailbox with a known listing. Inbox, newest first:
/// `pinned` (oldest, but pinned; unread), `i1` (unread), `i2` (read),
/// `i3` (unread, tagged Other), `i4` (read), `i5` (unread). Not listed in
/// Inbox: `snoozed` (Inbox + Snoozed), `deleted` (is_deleted). `labelled`
/// carries only the user label.
pub struct ListFixture {
    pub account: Account,
    pub snoozed_tag: i64,
    pub trash: i64,
    pub pinned: i64,
    pub i1: i64,
    pub i2: i64,
    pub i3: i64,
    pub i4: i64,
    pub i5: i64,
    pub snoozed: i64,
    pub deleted: i64,
    pub labelled: i64,
}

async fn tag_id(c: &Client, mailbox: i64, name: &str) -> Result<i64, BoxError> {
    Ok(c.query_typed(
        "SELECT id FROM tags WHERE mailbox_id = $1 AND name = $2",
        &[(&mailbox, Type::INT8), (&name, Type::TEXT)],
    )
    .await?[0]
        .get(0))
}

impl ListFixture {
    async fn build(c: &Client, label: &str) -> Result<ListFixture, BoxError> {
        let a = fixture::account(c, label).await?;
        // The account's two default messages are dropped: this fixture
        // defines the whole listing.
        c.query_typed(
            "DELETE FROM messages WHERE mailbox_id = $1",
            &[(&a.mailbox, Type::INT8)],
        )
        .await?;
        let snoozed_tag = tag_id(c, a.mailbox, "Snoozed").await?;
        let other = tag_id(c, a.mailbox, "Other").await?;
        let trash = tag_id(c, a.mailbox, "Trash").await?;
        let inbox = a.inbox;
        let i1 = message_at(c, &a, &[inbox], 1, false).await?;
        let i2 = message_at(c, &a, &[inbox], 2, true).await?;
        let i3 = message_at(c, &a, &[inbox, other], 3, false).await?;
        let i4 = message_at(c, &a, &[inbox], 4, true).await?;
        let i5 = message_at(c, &a, &[inbox], 5, false).await?;
        let snoozed = message_at(c, &a, &[inbox, snoozed_tag], 6, false).await?;
        let deleted = message_at(c, &a, &[inbox], 7, false).await?;
        let pinned = message_at(c, &a, &[inbox], 8, false).await?;
        let labelled = message_at(c, &a, &[a.label], 9, false).await?;
        c.query_typed(
            "UPDATE messages SET is_deleted = TRUE WHERE id = $1",
            &[(&deleted, Type::INT8)],
        )
        .await?;
        c.query_typed(
            "UPDATE messages SET pinned_at = now() WHERE id = $1",
            &[(&pinned, Type::INT8)],
        )
        .await?;
        Ok(ListFixture {
            account: a,
            snoozed_tag,
            trash,
            pinned,
            i1,
            i2,
            i3,
            i4,
            i5,
            snoozed,
            deleted,
            labelled,
        })
    }

    pub fn inbox(&self) -> ListQuery {
        ListQuery::tag(self.account.inbox)
    }
}

/// Insert a message with an explicit `received_at` (`minutes_ago` whole
/// minutes before now), so the listing order is fixed by the fixture.
async fn message_at(
    c: &Client,
    a: &Account,
    tags: &[i64],
    minutes_ago: i32,
    is_read: bool,
) -> Result<i64, BoxError> {
    let id: i64 = c
        .query_typed(
            "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, \
             thread_id, raw_ref, received_at, is_read) \
             SELECT $1, $2, '<' || u || '@oracle.test>', 'oracle', 'oracle@example.test', 10, \
                    'thr-' || u, 'raw-' || u, date_trunc('minute', now()) - make_interval(mins => $3), $4 \
             FROM (SELECT gen_random_uuid()::text AS u) g \
             RETURNING id",
            &[
                (&a.mailbox, Type::INT8),
                (&a.inbox, Type::INT8),
                (&minutes_ago, Type::INT4),
                (&is_read, Type::BOOL),
            ],
        )
        .await?[0]
        .get(0);
    for (i, tag) in tags.iter().enumerate() {
        let primary = i == 0;
        c.query_typed(
            "INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) \
             SELECT id, received_at, $2, 'system', $3 FROM messages WHERE id = $1",
            &[(&id, Type::INT8), (tag, Type::INT8), (&primary, Type::BOOL)],
        )
        .await?;
    }
    Ok(id)
}

struct Session<'a> {
    db: &'a Db,
    c: Client,
    cmd: Client,
    accounts: Vec<Account>,
}

impl<'a> Session<'a> {
    async fn open(db: &'a Db) -> Result<Session<'a>, BoxError> {
        Ok(Session {
            db,
            c: db.connect().await?,
            cmd: db.connect_command().await?,
            accounts: Vec::new(),
        })
    }

    async fn fixture(&mut self, label: &str) -> Result<ListFixture, BoxError> {
        let f = ListFixture::build(&self.c, label).await;
        if let Ok(f) = &f {
            self.accounts.push(f.account.clone());
        }
        f
    }

    async fn snapshot(&self, a: &Account) -> Result<Snapshot, BoxError> {
        fixture::snapshot(&self.c, a.mailbox).await
    }

    async fn listen(&self, a: &Account) -> Result<Listener, BoxError> {
        let mut l = self.db.listen(&format!("tag:{}", a.mailbox)).await?;
        l.drain(&self.c).await?;
        Ok(l)
    }

    /// Lists `q` in `caller`'s mailbox and checks the page against
    /// `expected_ids`/`expected_total`, with the state the fixture holds.
    async fn expect_page(
        &mut self,
        imp: &impl ListEmails,
        caller: &Account,
        q: ListQuery,
        expected_ids: &[i64],
        expected_total: i64,
    ) -> Result<(), BoxError> {
        let state = self.snapshot(caller).await?.email_state;
        let page = imp.list(&mut self.cmd, caller.mailbox, q).await?;
        expect_eq(
            imp,
            &format!("page for {q:?}"),
            page,
            Page {
                state,
                total: expected_total,
                ids: expected_ids.to_vec(),
            },
        )
    }

    async fn close(self, result: Result<(), BoxError>) -> Result<(), BoxError> {
        let mut cleanup = Ok(());
        for a in &self.accounts {
            if let Err(e) = fixture::remove(&self.c, a).await {
                cleanup = Err(format!(
                    "fixture cleanup failed for mailbox {}: {e:?}",
                    a.mailbox
                ));
            }
        }
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) => Err(e),
            (Ok(()), Err(c)) => Err(c.into()),
            (Err(e), Err(c)) => Err(format!("{e}; {c}").into()),
        }
    }
}

macro_rules! case {
    ($(#[$doc:meta])* $name:ident($s:ident, $f:ident, $imp:ident) $body:block) => {
        $(#[$doc])*
        pub async fn $name(db: &Db, $imp: &impl ListEmails) -> Result<(), BoxError> {
            let mut $s = Session::open(db).await?;
            let result: Result<(), BoxError> = async {
                let $f = $s.fixture(stringify!($name)).await?;
                $body
            }
            .await;
            $s.close(result).await
        }
    };
}

case! {
    /// Default webmail page: pinned first, then newest first; deleted and
    /// snoozed messages are not listed.
    first_page_is_newest_first_with_pinned_on_top(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, f.inbox(), &[f.pinned, f.i1, f.i2, f.i3, f.i4, f.i5], 6).await
    }
}

case! {
    /// Consecutive pages of two cover the listing exactly once.
    pages_continue_without_gaps_or_repeats(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, f.inbox().page(0, 2), &[f.pinned, f.i1], 6).await?;
        s.expect_page(imp, a, f.inbox().page(2, 2), &[f.i2, f.i3], 6).await?;
        s.expect_page(imp, a, f.inbox().page(4, 2), &[f.i4, f.i5], 6).await
    }
}

case! {
    /// Boundary: a page straddling the end is partial; a page starting at
    /// `total` is empty with the same `total`.
    last_partial_page_and_page_at_total(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, f.inbox().page(5, 2), &[f.i5], 6).await?;
        s.expect_page(imp, a, f.inbox().page(6, 2), &[], 6).await
    }
}

case! {
    /// A cursor left over from a longer listing (messages since deleted) is an
    /// empty page with the current `total` and `state`, not an error.
    stale_position_past_total_is_an_empty_page(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, f.inbox().page(4, 2), &[f.i4, f.i5], 6).await?;
        s.c.query_typed(
            "UPDATE messages SET is_deleted = TRUE WHERE id = ANY($1)",
            &[(&vec![f.i4, f.i5], Type::INT8_ARRAY)],
        )
        .await?;
        s.expect_page(imp, a, f.inbox().page(4, 2), &[], 4).await?;
        s.expect_page(imp, a, f.inbox().page(1000, 50), &[], 4).await
    }
}

case! {
    /// A tag with no messages: empty page, `total` 0.
    empty_tag_is_an_empty_page(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, ListQuery::tag(f.trash), &[], 0).await
    }
}

case! {
    /// `isAscending: true`: pinned still first, then oldest first.
    oldest_first_keeps_pinned_on_top(s, f, imp) {
        let a = &f.account;
        let q = ListQuery { ascending: true, ..f.inbox() };
        s.expect_page(imp, a, q, &[f.pinned, f.i5, f.i4, f.i3, f.i2, f.i1], 6).await
    }
}

case! {
    /// Unread flags as a filter: `$unseen` lists the unread, `$seen` the read.
    unread_and_read_filters(s, f, imp) {
        let a = &f.account;
        let unread = ListQuery { seen: Some(false), ..f.inbox() };
        s.expect_page(imp, a, unread, &[f.pinned, f.i1, f.i3, f.i5], 4).await?;
        let read = ListQuery { seen: Some(true), ..f.inbox() };
        s.expect_page(imp, a, read, &[f.i2, f.i4], 2).await?;
        // A read elsewhere moves the message between the two listings.
        s.c.query_typed(
            "UPDATE messages SET is_read = TRUE WHERE id = $1",
            &[(&f.i1, Type::INT8)],
        )
        .await?;
        s.expect_page(imp, a, unread, &[f.pinned, f.i3, f.i5], 3).await?;
        s.expect_page(imp, a, read, &[f.i1, f.i2, f.i4], 3).await
    }
}

case! {
    /// `focus`: `focused` hides the Other pile, `other` lists only it.
    focused_and_other_split(s, f, imp) {
        let a = &f.account;
        let focused = ListQuery { focus: Some("focused"), ..f.inbox() };
        s.expect_page(imp, a, focused, &[f.pinned, f.i1, f.i2, f.i4, f.i5], 5).await?;
        let other = ListQuery { focus: Some("other"), ..f.inbox() };
        s.expect_page(imp, a, other, &[f.i3], 1).await
    }
}

case! {
    /// A snoozed message keeps its Inbox tag but is listed only under Snoozed.
    snoozed_hidden_from_location_but_listed_under_snooze(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, ListQuery::tag(f.snoozed_tag), &[f.snoozed], 1).await
    }
}

case! {
    /// A user label (no exclusive group) lists its own messages.
    label_lists_its_own_messages(s, f, imp) {
        let a = &f.account;
        s.expect_page(imp, a, ListQuery::tag(a.label), &[f.labelled], 1).await
    }
}

case! {
    /// Negative: another mailbox's tag id lists nothing in the caller's
    /// mailbox, and the owner still sees its own messages.
    foreign_tag_lists_nothing(s, f, imp) {
        let other = s.fixture("foreign_tag_owner").await?;
        s.expect_page(imp, &f.account, other.inbox(), &[], 0).await?;
        s.expect_page(imp, &f.account, ListQuery::tag(other.snoozed_tag), &[], 0).await?;
        s.expect_page(imp, &other.account, other.inbox().page(0, 1), &[other.pinned], 6).await
    }
}

case! {
    /// Listing marks nothing read, bumps no state, journals nothing, pushes
    /// nothing.
    listing_has_no_side_effects(s, f, imp) {
        let a = &f.account;
        let before = s.snapshot(a).await?;
        let mut l = s.listen(a).await?;
        for q in [f.inbox(), ListQuery { seen: Some(false), ..f.inbox() }, f.inbox().page(6, 2)] {
            imp.list(&mut s.cmd, a.mailbox, q).await?;
        }
        expect_eq(imp, "mailbox after listing", s.snapshot(a).await?, before)?;
        expect_eq(imp, "pushes", l.drain(&s.c).await?, Vec::<String>::new())
    }
}

/// Adds `n` Inbox messages that share one `received_at` (older than every
/// [`ListFixture`] message), returned in id order. Every other one is then
/// rewritten so heap order is not id order.
async fn tie_block(c: &Client, a: &Account, n: usize) -> Result<Vec<i64>, BoxError> {
    let mut ids = Vec::with_capacity(n);
    for _ in 0..n {
        ids.push(message_at(c, a, &[a.inbox], 20, false).await?);
    }
    let moved: Vec<i64> = ids.iter().copied().step_by(2).collect();
    c.query_typed(
        "UPDATE messages SET subject = 'oracle moved' WHERE id = ANY($1)",
        &[(&moved, Type::INT8_ARRAY)],
    )
    .await?;
    ids.sort_unstable();
    Ok(ids)
}

case! {
    /// #223: messages sharing a `received_at` are ordered by `id`, in the
    /// sort's direction, so pages of 7 (not dividing the tie block) cover
    /// the listing exactly once, newest first and oldest first.
    equal_received_at_pages_in_id_order(s, f, imp) {
        let a = &f.account;
        let ties = tie_block(&s.c, a, 30).await?;
        let mut newest: Vec<i64> = vec![f.pinned, f.i1, f.i2, f.i3, f.i4, f.i5];
        newest.extend(ties.iter().rev());
        let mut oldest: Vec<i64> = vec![f.pinned];
        oldest.extend(ties.iter());
        oldest.extend([f.i5, f.i4, f.i3, f.i2, f.i1]);
        let total = newest.len() as i64;
        for (ascending, expected) in [(false, &newest), (true, &oldest)] {
            let q = ListQuery { ascending, ..f.inbox() };
            s.expect_page(imp, a, q.page(0, 256), expected, total).await?;
            for (i, chunk) in expected.chunks(7).enumerate() {
                s.expect_page(imp, a, q.page((i * 7) as i32, 7), chunk, total).await?;
            }
        }
        Ok(())
    }
}
