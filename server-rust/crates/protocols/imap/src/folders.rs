//! LIST, STATUS, CREATE, DELETE, RENAME, CLOSE and EXPUNGE (#345): a port of
//! frozen Go's handlers of the same names, wire quirks included (DOX.md).
use crate::{
    messages::operation_id,
    session::{split_args, Session},
};
use setjoin_contracts::{command::CommandEnvelope, ids::Digest};
use setjoin_pg::{CommandOutcome, ScopedTx, StatementFailure, Type};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Bound for the one CLOSE/EXPUNGE transaction (Go bounds it only by the pool).
const PURGE_DEADLINE: Duration = Duration::from_secs(30);

/// `strings.EqualFold` (simple folding, approximated by lowercase equality).
pub(crate) fn equal_fold(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

fn is_system_name(lower: &str) -> bool {
    matches!(lower, "inbox" | "sent" | "drafts" | "trash" | "spam")
}

fn special_use(name: &str) -> &'static str {
    match name.to_lowercase().as_str() {
        "inbox" => " \\Inbox",
        "sent" => " \\Sent",
        "drafts" => " \\Drafts",
        "trash" => " \\Trash",
        "spam" | "junk" => " \\Junk",
        _ => "",
    }
}

impl Session {
    /// `identity.ResolvePrimaryMailbox` on the request pool (0 = none or error).
    async fn primary_mailbox(&self) -> Option<i64> {
        let rows = self
            .server
            .db
            .read(
                "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
                &[(&self.user_id, Type::INT8)],
            )
            .await
            .ok()?;
        rows.first()?.try_get::<_, i64>(0).ok()
    }

    pub(crate) async fn list(&mut self, tag: &str) {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return;
        }
        // The settings read ignores its error and a missing row leaves Go's
        // zero values (so no row means "show everything", not "subscribed only").
        let (mut expose_all, mut sub_only, mut exposed, mut separator) =
            (false, false, Vec::<i64>::new(), String::new());
        if let Ok(rows) = self
            .server
            .db
            .read(
                "SELECT COALESCE(expose_all, FALSE), COALESCE(show_subscribed_only, TRUE), \
                 COALESCE(exposed_tag_ids, '{}'), COALESCE(folder_separator, '/') \
                 FROM user_imap_settings WHERE user_id = $1",
                &[(&self.user_id, Type::INT8)],
            )
            .await
        {
            if let Some(row) = rows.first() {
                expose_all = row.try_get(0).unwrap_or(false);
                sub_only = row.try_get(1).unwrap_or(false);
                exposed = row.try_get(2).unwrap_or_default();
                separator = row.try_get(3).unwrap_or_default();
            }
        }
        if separator.is_empty() {
            separator = "/".into();
        }
        let Ok(rows) = self
            .server
            .db
            .read(
                "SELECT t.id, COALESCE(t.imap_name, t.name), t.parent_id, \
                 COALESCE((SELECT COUNT(*) FROM tags child WHERE child.parent_id = t.id \
                           AND child.imap_expose = TRUE), 0)::bigint, t.tag_type \
                 FROM tags t JOIN mailboxes m ON m.id = t.mailbox_id \
                 WHERE m.user_id = $1 AND t.imap_expose = TRUE \
                 ORDER BY t.sort_order, t.name",
                &[(&self.user_id, Type::INT8)],
            )
            .await
        else {
            self.reply(tag, "NO Server error");
            return;
        };
        let mut paths: HashMap<i64, String> = HashMap::new();
        for row in &rows {
            let id: i64 = row.get(0);
            let name: String = row.get(1);
            // pgx cannot scan a NULL parent_id into int64: the scan fails at that
            // column (id and name are already set, the later columns stay zero),
            // Go ignores the error, handles this one row, and the failed scan
            // has closed the rows, so the command ends with `NO Server error`.
            let parent: Option<i64> = row.get(2);
            let scan_failed = parent.is_none();
            let (children, tag_type): (i64, String) = if scan_failed {
                (0, String::new())
            } else {
                (row.get(3), row.get(4))
            };
            let visible = !(sub_only && !expose_all) || exposed.contains(&id);
            if visible {
                let parent = parent.unwrap_or(0);
                let path = if parent == 0 {
                    name.clone()
                } else if let Some(prefix) = paths.get(&parent) {
                    format!("{prefix}{separator}{name}")
                } else {
                    name.clone()
                };
                paths.insert(id, path.clone());
                let mut flags = String::from(if children > 0 {
                    "\\HasChildren"
                } else {
                    "\\HasNoChildren"
                });
                if tag_type == "system" {
                    flags.push_str(special_use(&name));
                }
                // Go sends this through reply(line, ""): trailing space.
                self.out.extend_from_slice(
                    format!("* LIST ({flags}) \"{separator}\" \"{path}\" \r\n").as_bytes(),
                );
            }
            if scan_failed {
                self.reply(tag, "NO Server error");
                return;
            }
        }
        self.reply(tag, "OK LIST completed");
    }

    pub(crate) async fn status(&mut self, tag: &str, args: &str) {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return;
        }
        let first = args.split(' ').next().unwrap_or("");
        let folder = crate::session::canonical_mailbox(first.trim_matches('"'));
        let rows = self
            .server
            .db
            .read(
                "SELECT COALESCE(t.total_count, 0)::bigint, COALESCE(t.unread_count, 0)::bigint, \
                 COALESCE(t.imap_uid_validity, 0)::bigint, COALESCE(t.imap_uid_next, 1)::bigint \
                 FROM tags t JOIN mailboxes m ON m.id = t.mailbox_id \
                 WHERE m.user_id = $1 AND (t.name = $2 OR t.imap_name = $2) \
                   AND t.imap_expose = TRUE LIMIT 1",
                &[(&self.user_id, Type::INT8), (&folder, Type::TEXT)],
            )
            .await;
        let Some(row) = rows.ok().and_then(|r| r.into_iter().next()) else {
            self.reply(tag, "NO No such mailbox");
            return;
        };
        let (total, unread, mut validity, mut next): (i64, i64, i64, i64) =
            (row.get(0), row.get(1), row.get(2), row.get(3));
        if validity == 0 {
            validity = 1;
        }
        if next < 1 {
            next = 1;
        }
        self.out.extend_from_slice(
            format!(
                "* STATUS \"{folder}\" (MESSAGES {total} UNSEEN {unread} UIDVALIDITY {validity} UIDNEXT {next}) \r\n"
            )
            .as_bytes(),
        );
        self.reply(tag, "OK STATUS completed");
    }

    pub(crate) async fn create(&mut self, tag: &str, args: &str) {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return;
        }
        let name = crate::session::canonical_mailbox(args.trim_matches('"'));
        if name.is_empty() {
            self.reply(tag, "BAD Missing mailbox name");
            return;
        }
        // Go refuses these five and nothing else (Junk and Starred pass).
        if is_system_name(&name.to_lowercase()) {
            self.reply(tag, "NO Cannot create system mailbox");
            return;
        }
        let Some(mailbox) = self.primary_mailbox().await else {
            self.reply(tag, "NO Cannot find mailbox");
            return;
        };
        let created = self
            .server
            .db
            .protocol_statement(
                "INSERT INTO tags (mailbox_id, name, tag_type, sort_order, imap_expose) \
                 VALUES ($1, $2, 'user', 999, TRUE) ON CONFLICT (mailbox_id, name) DO NOTHING",
                &[(&mailbox, Type::INT8), (&name, Type::TEXT)],
            )
            .await;
        if created.is_err() {
            self.reply(tag, "NO CREATE failed");
            return;
        }
        self.reply(tag, "OK CREATE completed");
    }

    pub(crate) async fn delete(&mut self, tag: &str, args: &str) {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return;
        }
        let name = crate::session::canonical_mailbox(args.trim_matches('"'));
        if name.is_empty() {
            self.reply(tag, "BAD Missing mailbox name");
            return;
        }
        let Some(mailbox) = self.primary_mailbox().await.filter(|m| *m != 0) else {
            self.reply(tag, "NO Cannot find mailbox");
            return;
        };
        let kind = self
            .server
            .db
            .read(
                "SELECT tag_type FROM tags WHERE mailbox_id = $1 AND name = $2",
                &[(&mailbox, Type::INT8), (&name, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()));
        let Some(kind) = kind else {
            self.reply(tag, "NO No such mailbox");
            return;
        };
        if kind == "system" {
            self.reply(tag, "NO Cannot delete system mailbox");
            return;
        }
        let deleted = self
            .server
            .db
            .protocol_statement(
                "DELETE FROM tags WHERE mailbox_id = $1 AND name = $2 AND tag_type = 'user'",
                &[(&mailbox, Type::INT8), (&name, Type::TEXT)],
            )
            .await;
        if deleted.is_err() {
            self.reply(tag, "NO DELETE failed");
            return;
        }
        if equal_fold(&name, &self.selected) {
            self.reply("*", "OK [CLOSED] Previous mailbox closed");
            self.selected.clear();
            self.mailbox_id = 0;
        }
        self.reply(tag, "OK DELETE completed");
    }

    pub(crate) async fn rename(&mut self, tag: &str, args: &str) {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return;
        }
        let parts = split_args(args);
        if parts.len() < 2 {
            self.reply(tag, "BAD Missing arguments");
            return;
        }
        let old = parts[0].trim_matches('"').to_string();
        let new = parts[1].trim_matches('"').to_string();
        if old.is_empty() || new.is_empty() {
            self.reply(tag, "BAD Invalid mailbox names");
            return;
        }
        if is_system_name(&old.to_lowercase()) {
            self.reply(tag, "NO Cannot rename system mailbox");
            return;
        }
        let Some(mailbox) = self.primary_mailbox().await.filter(|m| *m != 0) else {
            self.reply(tag, "NO Cannot find mailbox");
            return;
        };
        let renamed = self
            .server
            .db
            .protocol_statement(
                "UPDATE tags SET name = $1 WHERE mailbox_id = $2 AND name = $3 AND tag_type = 'user'",
                &[
                    (&new, Type::TEXT),
                    (&mailbox, Type::INT8),
                    (&old, Type::TEXT),
                ],
            )
            .await;
        if renamed.is_err() {
            self.reply(tag, "NO RENAME failed");
            return;
        }
        if equal_fold(&old, &self.selected) {
            self.selected = new;
        }
        self.reply(tag, "OK RENAME completed");
    }

    /// One scoped transaction that purges the selected folder's `\Deleted`
    /// messages through the reducer (`jmap_email_purge`, no notify: the STORE
    /// already pushed `destroyed`). `announce` collects each expunged sequence
    /// number the way Go streams them before the purge statement runs.
    async fn purge_deleted(&mut self, all_rows: bool, announce: &mut Vec<i64>) -> bool {
        let Some(auth) = self.mailbox_auth() else {
            return false;
        };
        let envelope = CommandEnvelope {
            operation: operation_id(self.user_id),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(b"imap-purge-deleted").into()),
            command: (),
        };
        let (tag_id, mailbox, uid) = (self.tag_id, self.mailbox_id, self.uid_column());
        let outcome = self
            .server
            .db
            .run(
                &envelope,
                &auth,
                Instant::now() + PURGE_DEADLINE,
                async |tx: &mut ScopedTx| -> Result<(), StatementFailure> {
                    let order = if all_rows {
                        format!("ORDER BY {uid}")
                    } else {
                        String::new()
                    };
                    let filter = if all_rows { "" } else { " AND m.is_deleted = TRUE" };
                    let rows = tx
                        .query(
                            &format!(
                                "SELECT m.id, m.is_deleted FROM messages m \
                                 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
                                 WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE{filter} {order}"
                            ),
                            &[(&tag_id, Type::INT8), (&mailbox, Type::INT8)],
                        )
                        .await?;
                    let mut ids = Vec::<i64>::new();
                    let (mut current, mut gone) = (0i64, 0i64);
                    for row in &rows {
                        let (Ok(id), Ok(deleted)) =
                            (row.try_get::<_, i64>(0), row.try_get::<_, bool>(1))
                        else {
                            continue;
                        };
                        current += 1;
                        if deleted {
                            announce.push((current - gone).max(1));
                            ids.push(id);
                            gone += 1;
                        }
                    }
                    if !ids.is_empty() {
                        tx.execute(
                            "SELECT jmap_email_purge($1, $2::bigint[], FALSE)",
                            &[(&mailbox, Type::INT8), (&ids, Type::INT8_ARRAY)],
                        )
                        .await?;
                    }
                    Ok(())
                },
            )
            .await;
        matches!(outcome, CommandOutcome::Committed(()))
    }

    pub(crate) async fn expunge(&mut self, tag: &str) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        if self.read_only {
            self.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only");
            return;
        }
        let mut announced = Vec::new();
        let ok = self.purge_deleted(true, &mut announced).await;
        for seq in announced {
            self.out
                .extend_from_slice(format!("* {seq} EXPUNGE\r\n").as_bytes());
        }
        if !ok {
            self.reply(tag, "NO Server error");
            return;
        }
        self.reply(tag, "OK EXPUNGE completed");
        self.audit("imap_expunge").await;
    }

    /// CLOSE always succeeds at the protocol level, even on a read-only
    /// selection (Go does not check it) and whatever the purge did; it writes no
    /// audit row.
    pub(crate) async fn close(&mut self, tag: &str) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        let _ = self.purge_deleted(false, &mut Vec::new()).await;
        self.reply("*", "OK [CLOSED] Previous mailbox closed");
        self.selected.clear();
        self.mailbox_id = 0;
        self.reply(tag, "OK CLOSE completed");
    }
}
