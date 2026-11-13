//! Mark-read parity oracle (#212). The contract is today's `$seen` behaviour
//! of `jmap_email_set_update` (mailserver/sql/reducers/jmap_email.sql). Every
//! case takes an implementation of [`SetSeen`], so the Rust command (#214) runs
//! these same cases unchanged.
//!
//! Expected values are fixture literals (see [`fixture::account`]): Inbox
//! starts with 2 unread, the label with 1; one command is one state bump. They
//! are never read back from the implementation under test. A case returns
//! `Err` on the first divergence, so a wrong implementation is observable
//! (see `tests/oracle_discriminates.rs`). Every case removes its fixtures,
//! pass or fail.
use std::fmt::Debug;
use std::future::Future;

use setjoin_contracts::command::SetMessageSeen;
use setjoin_contracts::ids::{MailboxId, MessageId};
use tokio_postgres::Client;

use crate::fixture::{self, Account, JournalRow, Snapshot};
use crate::harness::{BoxError, Db, Listener};

/// What a set-seen command reports for its one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeenOutcome {
    /// The message belongs to the mailbox and the command committed.
    Updated,
    /// No such message in the caller's mailbox.
    NotFound,
}

/// An implementation of set-message-seen. It owns its own transaction on
/// `client` (a connection from the `DB_DSN` pool).
pub trait SetSeen {
    fn name(&self) -> &'static str;
    fn set_seen(
        &self,
        client: &mut Client,
        cmd: SetMessageSeen,
    ) -> impl Future<Output = Result<SeenOutcome, BoxError>>;
}

/// The cases, by name; `tests/` files run each one per implementation.
pub const CASES: &[&str] = &[
    "read_sets_is_read",
    "read_adjusts_unread_on_every_tag",
    "read_bumps_email_state_once",
    "read_writes_one_journal_row",
    "read_pushes_once",
    "unread_restores_unread_on_every_tag",
    "repeat_read_changes_no_data",
    "repeat_read_emits_no_state_change",
    "foreign_mailbox_message_refused_without_effect",
];

fn expect_eq<T: PartialEq + Debug>(
    imp: &impl SetSeen,
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

/// The push payload `app_notify` carries for an email state change
/// (`json_build_object('event','state_change','tag_id',NULL,'state',n)::TEXT`).
fn state_push(state: i64) -> String {
    format!(r#"{{"event" : "state_change", "tag_id" : null, "state" : {state}}}"#)
}

const NO_PUSH: Vec<String> = Vec::new();

/// One case's connections and the fixtures it must remove. `c` (owner) sets
/// up and observes; `cmd` runs the implementation under test.
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

    /// A fresh account, checked against the fixture literals before any command.
    async fn account(&mut self, label: &str) -> Result<(Account, Snapshot), BoxError> {
        let a = fixture::account(&self.c, label).await?;
        self.accounts.push(a.clone());
        let s = self.snapshot(&a).await?;
        let pre = |ok: bool, what: &str| -> Result<(), BoxError> {
            if ok {
                Ok(())
            } else {
                Err(format!("fixture precondition failed: {what}").into())
            }
        };
        pre(!s.is_read[&a.two_labels], "two_labels unread")?;
        pre(!s.is_read[&a.inbox_only], "inbox_only unread")?;
        pre(s.unread(a.inbox) == 2, "Inbox unread = 2")?;
        pre(s.unread(a.label) == 1, "label unread = 1")?;
        Ok((a, s))
    }

    async fn snapshot(&self, a: &Account) -> Result<Snapshot, BoxError> {
        fixture::snapshot(&self.c, a.mailbox).await
    }

    /// LISTEN on the account's push channel, with anything already queued drained.
    async fn listen(&self, a: &Account) -> Result<Listener, BoxError> {
        let mut l = self.db.listen(&format!("tag:{}", a.mailbox)).await?;
        l.drain(&self.c).await?;
        Ok(l)
    }

    async fn pushes(&self, l: &mut Listener) -> Result<Vec<String>, BoxError> {
        l.drain(&self.c).await
    }

    /// Run one set-seen as `caller` on `message`, expecting `outcome`.
    async fn set_seen(
        &mut self,
        imp: &impl SetSeen,
        caller: &Account,
        message: i64,
        seen: bool,
        outcome: SeenOutcome,
    ) -> Result<(), BoxError> {
        let cmd = SetMessageSeen {
            mailbox: MailboxId::new(caller.mailbox).expect("fixture mailbox id"),
            message: MessageId::new(message).expect("fixture message id"),
            seen,
        };
        let out = imp.set_seen(&mut self.cmd, cmd).await?;
        expect_eq(imp, "outcome", out, outcome)
    }

    /// Remove every fixture, then report the case result (a cleanup failure is
    /// reported too, never swallowed).
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
    ($(#[$doc:meta])* $name:ident($s:ident, $imp:ident) $body:block) => {
        $(#[$doc])*
        pub async fn $name(db: &Db, $imp: &impl SetSeen) -> Result<(), BoxError> {
            let mut $s = Session::open(db).await?;
            let result: Result<(), BoxError> = async { $body }.await;
            $s.close(result).await
        }
    };
}

case! {
    /// Marking an unread message read sets `is_read` on it and on nothing else.
    read_sets_is_read(s, imp) {
        let (a, _) = s.account("oracle-isread").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let after = s.snapshot(&a).await?;
        expect_eq(imp, "target is_read", after.is_read[&a.two_labels], true)?;
        expect_eq(imp, "sibling is_read", after.is_read[&a.inbox_only], false)
    }
}

case! {
    /// Every tag on the message loses one unread and gets one `jmap_state`
    /// bump; the mailbox's other tags do not change.
    read_adjusts_unread_on_every_tag(s, imp) {
        let (a, before) = s.account("oracle-unread").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let after = s.snapshot(&a).await?;
        expect_eq(imp, "Inbox unread", after.unread(a.inbox), 1)?;
        expect_eq(imp, "label unread", after.unread(a.label), 0)?;
        let inbox_delta = after.tag_state(a.inbox) - before.tag_state(a.inbox);
        expect_eq(imp, "Inbox jmap_state delta", inbox_delta, 1)?;
        let label_delta = after.tag_state(a.label) - before.tag_state(a.label);
        expect_eq(imp, "label jmap_state delta", label_delta, 1)?;
        for (tag, counters) in &before.tags {
            if *tag != a.inbox && *tag != a.label {
                expect_eq(imp, &format!("other tag {tag}"), after.tags.get(tag), Some(counters))?;
            }
        }
        Ok(())
    }
}

case! {
    /// One command, one `jmap_email_state` bump.
    read_bumps_email_state_once(s, imp) {
        let (a, before) = s.account("oracle-state").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let after = s.snapshot(&a).await?;
        expect_eq(imp, "email_state delta", after.email_state - before.email_state, 1)
    }
}

case! {
    /// Exactly one journal row: the message, `updated`, at the new state.
    read_writes_one_journal_row(s, imp) {
        let (a, before) = s.account("oracle-journal").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let after = s.snapshot(&a).await?;
        let added: Vec<JournalRow> = after
            .journal
            .iter()
            .filter(|r| !before.journal.contains(r))
            .cloned()
            .collect();
        let expected = vec![JournalRow {
            datatype: "email".into(),
            state_seq: before.email_state + 1,
            entity_id: a.two_labels,
            op: "updated".into(),
        }];
        expect_eq(imp, "new journal rows", added, expected)?;
        expect_eq(imp, "journal size", after.journal.len(), before.journal.len() + 1)
    }
}

case! {
    /// Exactly one push on the mailbox channel, carrying the new state.
    read_pushes_once(s, imp) {
        let (a, before) = s.account("oracle-push").await?;
        let mut l = s.listen(&a).await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let pushes = s.pushes(&mut l).await?;
        expect_eq(imp, "pushes", pushes, vec![state_push(before.email_state + 1)])
    }
}

case! {
    /// Marking a read message unread puts one unread back on every tag, with
    /// the same one bump, one journal row and one push.
    unread_restores_unread_on_every_tag(s, imp) {
        let (a, _) = s.account("oracle-markunread").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let mid = s.snapshot(&a).await?;
        let mut l = s.listen(&a).await?;
        s.set_seen(imp, &a, a.two_labels, false, SeenOutcome::Updated).await?;
        let after = s.snapshot(&a).await?;
        expect_eq(imp, "target is_read", after.is_read[&a.two_labels], false)?;
        expect_eq(imp, "Inbox unread", after.unread(a.inbox), 2)?;
        expect_eq(imp, "label unread", after.unread(a.label), 1)?;
        expect_eq(imp, "email_state delta", after.email_state - mid.email_state, 1)?;
        expect_eq(imp, "journal rows added", after.journal.len() - mid.journal.len(), 1)?;
        let pushes = s.pushes(&mut l).await?;
        expect_eq(imp, "pushes", pushes, vec![state_push(mid.email_state + 1)])
    }
}

case! {
    /// Repeating a read on an already-read message changes no message or tag
    /// data.
    repeat_read_changes_no_data(s, imp) {
        let (a, _) = s.account("oracle-repeat-data").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let first = s.snapshot(&a).await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let second = s.snapshot(&a).await?;
        expect_eq(imp, "is_read", &second.is_read, &first.is_read)?;
        expect_eq(imp, "tag counters and jmap_state", &second.tags, &first.tags)
    }
}

case! {
    /// Repeating a read on an already-read message emits no state change: no
    /// `jmap_email_state` bump, no journal row, no push (ticket #212:
    /// "repeating the same read changes nothing").
    repeat_read_emits_no_state_change(s, imp) {
        let (a, _) = s.account("oracle-repeat-state").await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let first = s.snapshot(&a).await?;
        let mut l = s.listen(&a).await?;
        s.set_seen(imp, &a, a.two_labels, true, SeenOutcome::Updated).await?;
        let second = s.snapshot(&a).await?;
        let pushes = s.pushes(&mut l).await?;
        expect_eq(imp, "email_state", second.email_state, first.email_state)?;
        expect_eq(imp, "journal", &second.journal, &first.journal)?;
        expect_eq(imp, "pushes", pushes, NO_PUSH)
    }
}

case! {
    /// A message id from another mailbox is refused as not found, and neither
    /// mailbox changes or receives a push.
    foreign_mailbox_message_refused_without_effect(s, imp) {
        let (caller, caller_before) = s.account("oracle-caller").await?;
        let (owner, owner_before) = s.account("oracle-owner").await?;
        let mut caller_l = s.listen(&caller).await?;
        let mut owner_l = s.listen(&owner).await?;
        s.set_seen(imp, &caller, owner.two_labels, true, SeenOutcome::NotFound).await?;
        expect_eq(imp, "caller mailbox", s.snapshot(&caller).await?, caller_before)?;
        expect_eq(imp, "owner mailbox", s.snapshot(&owner).await?, owner_before)?;
        expect_eq(imp, "caller pushes", s.pushes(&mut caller_l).await?, NO_PUSH)?;
        expect_eq(imp, "owner pushes", s.pushes(&mut owner_l).await?, NO_PUSH)
    }
}
