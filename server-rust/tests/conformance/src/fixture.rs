//! Committed fixtures for the mark-read oracle, plus a read-only snapshot of
//! everything mark-read may touch.
//!
//! Commands must really commit (NOTIFY is delivered only on commit), so the
//! fixtures are committed rows. Each account lives in its own throwaway domain
//! and [`remove`] deletes everything it created, so a run leaves no residue in
//! the shared test database that later DB-backed suites rely on. User ids and
//! mailbox ids are forced to diverge (ADR-003), so a stray
//! `user_id = mailbox_id` predicate cannot pass by accident.
use std::collections::BTreeMap;

use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::Client;

use crate::harness::BoxError;

/// One mailbox: Inbox (system location tag) plus one user label.
///
/// `two_labels` (unread) is tagged Inbox (primary) and the label; `inbox_only`
/// (unread) is tagged Inbox only. So before any command the fixture holds
/// Inbox unread = 2 and label unread = 1.
#[derive(Clone, Debug)]
pub struct Account {
    pub domain: i64,
    pub user: i64,
    pub mailbox: i64,
    pub inbox: i64,
    pub label: i64,
    pub two_labels: i64,
    pub inbox_only: i64,
}

fn one_i64(rows: &[tokio_postgres::Row]) -> i64 {
    rows[0].get(0)
}

pub async fn account(c: &Client, label: &str) -> Result<Account, BoxError> {
    let unique: String = c
        .query_typed("SELECT replace(gen_random_uuid()::text, '-', '')", &[])
        .await?[0]
        .get(0);
    let domain_name = format!("oracle-{unique}.test");
    let email = format!("{label}@{domain_name}");
    let domain = one_i64(
        &c.query_typed(
            "INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id",
            &[(&domain_name, Type::TEXT)],
        )
        .await?,
    );
    let user = one_i64(
        &c.query_typed(
            "INSERT INTO users (username, domain_id, email, display_name, password_hash) \
             VALUES ($1, $2, $1, $3, 'x') RETURNING id",
            &[
                (&email, Type::TEXT),
                (&domain, Type::INT8),
                (&label, Type::TEXT),
            ],
        )
        .await?,
    );
    let mut mailbox_id = one_i64(
        &c.query_typed("SELECT nextval('mailboxes_id_seq')", &[])
            .await?,
    );
    if mailbox_id == user {
        mailbox_id = one_i64(
            &c.query_typed("SELECT nextval('mailboxes_id_seq')", &[])
                .await?,
        );
    }
    // The insert fires the system-tag and folder triggers (Inbox, Sent, ...).
    let mailbox = one_i64(
        &c.query_typed(
            "INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) \
             VALUES ($1, $2, $3, $4, $5, 'personal', TRUE) RETURNING id",
            &[
                (&mailbox_id, Type::INT8),
                (&user, Type::INT8),
                (&domain, Type::INT8),
                (&email, Type::TEXT),
                (&label, Type::TEXT),
            ],
        )
        .await?,
    );
    let inbox = one_i64(
        &c.query_typed(
            "SELECT id FROM tags WHERE mailbox_id = $1 AND name = 'Inbox'",
            &[(&mailbox, Type::INT8)],
        )
        .await?,
    );
    let label_tag = one_i64(
        &c.query_typed(
            "INSERT INTO tags (mailbox_id, name, tag_type) VALUES ($1, 'Oracle Label', 'user') RETURNING id",
            &[(&mailbox, Type::INT8)],
        )
        .await?,
    );
    let two_labels = message(c, mailbox, inbox, &[inbox, label_tag], false).await?;
    let inbox_only = message(c, mailbox, inbox, &[inbox], false).await?;
    Ok(Account {
        domain,
        user,
        mailbox,
        inbox,
        label: label_tag,
        two_labels,
        inbox_only,
    })
}

/// Remove only this fixture, releasing partition locks before identity cascades.
/// Keep mailbox/user deletion atomic for the deferred primary-mailbox invariant.
/// Append-only audit cleanup uses the owner credential with triggers suspended
/// only for that exact statement. Separate protocol calls are essential: a
/// DELETE followed by BEGIN in one simple-query message shares that transaction.
pub async fn remove(c: &Client, a: &Account) -> Result<(), BoxError> {
    let (mb, user, domain) = (a.mailbox, a.user, a.domain);
    c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM mailbox_audit_log WHERE mailbox_id={mb}; COMMIT;"
    ))
    .await?;
    c.query_typed(
        "DELETE FROM messages WHERE mailbox_id=$1",
        &[(&mb, Type::INT8)],
    )
    .await?;
    // The welcome mail's trace row: left in the default partition it blocks creating the
    // month's partition for every later suite (the health check then reports a warning).
    c.batch_execute(&format!(
        "DELETE FROM message_trace WHERE details->>'mailbox_id'='{mb}'"
    ))
    .await?;
    c.batch_execute(&format!(
        "BEGIN; DELETE FROM mailboxes WHERE id={mb}; \
         DELETE FROM users WHERE id={user}; DELETE FROM domains WHERE id={domain}; COMMIT;"
    ))
    .await?;
    Ok(())
}

/// Insert a message tagged with `tags` (the first is primary). Tag counters are
/// maintained by `trg_message_tags_counters`.
pub async fn message(
    c: &Client,
    mailbox: i64,
    folder: i64,
    tags: &[i64],
    is_read: bool,
) -> Result<i64, BoxError> {
    let id = one_i64(
        &c.query_typed(
            "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, \
             thread_id, raw_ref, received_at, is_read) \
             SELECT $1, $2, '<' || u || '@oracle.test>', 'oracle', 'oracle@example.test', 10, \
                    'thr-' || u, 'raw-' || u, now(), $3 \
             FROM (SELECT gen_random_uuid()::text AS u) g \
             RETURNING id",
            &[(&mailbox, Type::INT8), (&folder, Type::INT8), (&is_read, Type::BOOL)],
        )
        .await?,
    );
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

/// A journal row as written by `append_change`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct JournalRow {
    pub datatype: String,
    pub state_seq: i64,
    pub entity_id: i64,
    pub op: String,
}

/// Everything mark-read may change in one mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// message id → is_read
    pub is_read: BTreeMap<i64, bool>,
    /// tag id → (unread_count, jmap_state), every tag in the mailbox
    pub tags: BTreeMap<i64, (i32, i64)>,
    pub email_state: i64,
    pub journal: Vec<JournalRow>,
}

impl Snapshot {
    pub fn unread(&self, tag: i64) -> i32 {
        self.tags[&tag].0
    }
    pub fn tag_state(&self, tag: i64) -> i64 {
        self.tags[&tag].1
    }
}

pub async fn snapshot(c: &Client, mailbox: i64) -> Result<Snapshot, BoxError> {
    let p = [(&mailbox as &(dyn ToSql + Sync), Type::INT8)];
    let is_read = c
        .query_typed("SELECT id, is_read FROM messages WHERE mailbox_id = $1", &p)
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let tags = c
        .query_typed(
            "SELECT id, unread_count, jmap_state FROM tags WHERE mailbox_id = $1",
            &p,
        )
        .await?
        .iter()
        .map(|r| (r.get(0), (r.get(1), r.get(2))))
        .collect();
    let email_state = one_i64(
        &c.query_typed("SELECT jmap_email_state FROM mailboxes WHERE id = $1", &p)
            .await?,
    );
    let journal = c
        .query_typed(
            "SELECT datatype, state_seq, entity_id, op FROM jmap_changes_journal \
             WHERE mailbox_id = $1 ORDER BY datatype, state_seq, entity_id",
            &p,
        )
        .await?
        .iter()
        .map(|r| JournalRow {
            datatype: r.get(0),
            state_seq: r.get(1),
            entity_id: r.get(2),
            op: r.get(3),
        })
        .collect();
    Ok(Snapshot {
        is_read,
        tags,
        email_state,
        journal,
    })
}
