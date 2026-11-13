//! APPEND and IDLE (#345): a port of frozen Go's `handleAppend` and the simple
//! idle loop. See DOX.md for the mirrored quirks and the one IDLE gap.
use crate::{
    conn::LineError,
    messages::operation_id,
    session::{canonical_mailbox, Session},
};
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, ScopedTx, StatementFailure, Type};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};

const APPEND_DEADLINE: Duration = Duration::from_secs(60);
const MAX_LITERAL: i64 = 50_000_000;

enum Abort {
    OverQuota,
    Failed,
}

impl From<StatementFailure> for Abort {
    fn from(_: StatementFailure) -> Self {
        Abort::Failed
    }
}

/// `strconv.Atoi` (base 10): optional sign, digits only, no spaces, no overflow.
fn go_atoi(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

struct Dest {
    tag_id: i64,
    mailbox: i64,
    name: String,
    validity: i64,
    membership: bool,
}

const DEST_COLUMNS: &str = "t.id, t.mailbox_id, t.name, t.imap_uid_validity, \
     COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.imap_membership_uid'),FALSE) \
     AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE)";

fn dest_row(row: &setjoin_pg::Row) -> Option<Dest> {
    Some(Dest {
        tag_id: row.try_get(0).ok()?,
        mailbox: row.try_get(1).ok()?,
        name: row.try_get(2).ok()?,
        validity: row.try_get(3).ok()?,
        membership: row.try_get(4).ok()?,
    })
}

impl Session {
    async fn append_destination(&self, name: &str) -> Option<Dest> {
        let first = self
            .server
            .db
            .read(
                &format!(
                    "SELECT {DEST_COLUMNS} FROM tags t \
                     WHERE t.mailbox_id = $1 AND (t.name = $2 OR t.imap_name = $2)"
                ),
                &[(&self.mailbox_id, Type::INT8), (&name, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(dest_row));
        if first.is_some() {
            return first;
        }
        // An APPEND issued before SELECT bound a mailbox resolves by the user.
        self.server
            .db
            .read(
                &format!(
                    "SELECT {DEST_COLUMNS} FROM tags t JOIN mailboxes mb ON mb.id = t.mailbox_id \
                     WHERE mb.user_id = $1 AND (t.name = $2 OR t.imap_name = $2) \
                     ORDER BY mb.is_primary DESC LIMIT 1"
                ),
                &[(&self.user_id, Type::INT8), (&name, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(dest_row))
    }

    /// Returns false when the connection must end: Go panics on two malformed
    /// argument shapes and its recover closes the socket without a reply.
    pub(crate) async fn append(&mut self, tag: &str, args: &str) -> bool {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return true;
        }
        if self.read_only {
            self.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only");
            return true;
        }
        if !args.ends_with('}') {
            self.reply(tag, "BAD Expected literal size");
            return true;
        }
        let brace = args.rfind('{');
        let size_text = match brace {
            Some(i) => &args[i + 1..args.len() - 1],
            None => &args[..args.len() - 1],
        };
        let size = match go_atoi(size_text) {
            Some(n) if n > 0 && n <= MAX_LITERAL => n,
            _ => {
                self.reply(tag, "BAD Invalid literal size");
                return true;
            }
        };
        // `args[:braceIdx]` with braceIdx == -1 panics in Go.
        let Some(brace) = brace else {
            return false;
        };
        let prefix = args[..brace].trim();
        let Some(mailbox_name) = prefix.split_whitespace().next() else {
            self.reply(tag, "BAD mailbox required");
            return true;
        };
        let mailbox_name = canonical_mailbox(mailbox_name.trim_matches('"'));

        self.out.extend_from_slice(b"+ Ready for literal data\r\n");
        if !self.flush().await {
            return false;
        }
        let literal = tokio::time::timeout(
            crate::conn::READ_TIMEOUT,
            self.conn.read_exact(size as usize),
        )
        .await;
        let Ok(Ok(literal)) = literal else {
            self.reply(tag, "NO Failed to read message data");
            return true;
        };
        // The line ending after the literal; its errors are ignored.
        let _ = tokio::time::timeout(crate::conn::READ_TIMEOUT, self.conn.read_line()).await;

        let (mut seen, mut flagged, mut answered, mut draft) = (false, false, false, false);
        if let (Some(open), Some(close)) = (prefix.find('('), prefix.find(')')) {
            // Go slices prefix[open+1:close]; ")" before "(" panics.
            if open + 1 > close {
                return false;
            }
            for flag in prefix[open + 1..close].split_whitespace() {
                match flag.to_uppercase().as_str() {
                    "\\SEEN" => seen = true,
                    "\\FLAGGED" => flagged = true,
                    "\\ANSWERED" => answered = true,
                    "\\DRAFT" => draft = true,
                    _ => {}
                }
            }
        }
        let Some(dest) = self.append_destination(&mailbox_name).await else {
            self.reply(tag, "NO No such mailbox");
            return true;
        };
        let body = String::from_utf8(literal).ok();
        let uid = self
            .append_in_tx(&dest, size, [seen, flagged, answered, draft], args, body)
            .await;
        match uid {
            Ok(uid) => {
                // Go sends this through reply(line, ""): trailing space.
                self.out.extend_from_slice(b"* 0 EXISTS \r\n");
                self.reply(
                    tag,
                    &format!("OK [APPENDUID {} {uid}] APPEND completed", dest.validity),
                );
            }
            Err(Abort::OverQuota) => self.reply(tag, "NO [OVERQUOTA] APPEND exceeds mailbox quota"),
            Err(Abort::Failed) => self.reply(tag, "NO APPEND failed"),
        }
        true
    }

    async fn append_in_tx(
        &self,
        dest: &Dest,
        size: i64,
        flags: [bool; 4],
        args: &str,
        body: Option<String>,
    ) -> Result<i64, Abort> {
        let (Ok(actor), Ok(mailbox)) = (ActorId::new(self.user_id), MailboxId::new(dest.mailbox))
        else {
            return Err(Abort::Failed);
        };
        let auth = MailboxAuthContext::from_authenticated_session(actor, mailbox, Generation(1));
        let envelope = CommandEnvelope {
            operation: operation_id(self.user_id),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(args.as_bytes()).into()),
            command: (),
        };
        let outcome = self
            .server
            .db
            .run(
                &envelope,
                &auth,
                Instant::now() + APPEND_DEADLINE,
                async |tx: &mut ScopedTx| -> Result<i64, Abort> {
                    // Quota first: the check locks the mailbox row.
                    let within = tx
                        .query(
                            "SELECT check_quota($1, $2)",
                            &[(&dest.mailbox, Type::INT8), (&size, Type::INT8)],
                        )
                        .await?;
                    match within.first().and_then(|r| r.try_get::<_, Option<bool>>(0).ok()) {
                        Some(Some(true)) => {}
                        Some(Some(false)) => return Err(Abort::OverQuota),
                        _ => return Err(Abort::Failed),
                    }
                    let next: i64 = tx
                        .query(
                            "SELECT next_imap_uid_for_tag($1)",
                            &[(&dest.tag_id, Type::INT8)],
                        )
                        .await?
                        .first()
                        .and_then(|r| r.try_get::<_, Option<i64>>(0).ok().flatten())
                        .ok_or(Abort::Failed)?;
                    let body = body.as_deref().ok_or(Abort::Failed)?;
                    let message_id = format!("<append-{next}@setjoin.local>");
                    let thread = format!("append-{next}");
                    let inserted = tx
                        .query(
                            "INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, \
                             from_addr, to_addrs, thread_id, raw_ref, \
                             is_read, is_flagged, is_answered, is_draft, body_text, size_bytes, received_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, $7, $8, $9, $10, $11, $12, $13, $14, NOW()) \
                             RETURNING id, received_at::text",
                            &[
                                (&dest.mailbox, Type::INT8),
                                (&dest.tag_id, Type::INT8),
                                (&next, Type::INT8),
                                (&message_id, Type::TEXT),
                                (&"(appended)", Type::TEXT),
                                (&"", Type::TEXT),
                                (&thread, Type::TEXT),
                                (&thread, Type::TEXT),
                                (&flags[0], Type::BOOL),
                                (&flags[1], Type::BOOL),
                                (&flags[2], Type::BOOL),
                                (&flags[3], Type::BOOL),
                                (&body, Type::TEXT),
                                (&size, Type::INT8),
                            ],
                        )
                        .await?;
                    let row = inserted.first().ok_or(Abort::Failed)?;
                    let (msg_id, recv): (i64, String) =
                        (row.try_get(0).map_err(|_| Abort::Failed)?, row.try_get(1).map_err(|_| Abort::Failed)?);
                    tx.execute(
                        "SELECT tag_message($1, $2::text::timestamptz, $3, $4, 'imap', TRUE)",
                        &[
                            (&msg_id, Type::INT8),
                            (&recv, Type::TEXT),
                            (&dest.name, Type::TEXT),
                            (&dest.mailbox, Type::INT8),
                        ],
                    )
                    .await?;
                    let uid = if dest.membership {
                        tx.query(
                            "SELECT imap_uid FROM message_tags \
                             WHERE message_id = $1 AND received_at = $2::text::timestamptz AND tag_id = $3",
                            &[
                                (&msg_id, Type::INT8),
                                (&recv, Type::TEXT),
                                (&dest.tag_id, Type::INT8),
                            ],
                        )
                        .await?
                        .first()
                        .and_then(|r| r.try_get::<_, Option<i64>>(0).ok().flatten())
                        .ok_or(Abort::Failed)?
                    } else {
                        next
                    };
                    tx.execute(
                        "UPDATE mailboxes SET used_bytes = used_bytes + $1 WHERE id = $2",
                        &[(&size, Type::INT8), (&dest.mailbox, Type::INT8)],
                    )
                    .await?;
                    tx.execute(
                        "SELECT notify_state_change($1, $2, $3, 'created')",
                        &[
                            (&dest.mailbox, Type::INT8),
                            (&dest.tag_id, Type::INT8),
                            (&msg_id, Type::INT8),
                        ],
                    )
                    .await?;
                    Ok(uid)
                },
            )
            .await;
        match outcome {
            CommandOutcome::Committed(uid) => Ok(uid),
            CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(Abort::OverQuota)) => {
                Err(Abort::OverQuota)
            }
            _ => Err(Abort::Failed),
        }
    }

    /// IDLE (`idleSimple`): the continuation carries the tag, then lines are read
    /// with no deadline until a trimmed `DONE`. A read error just leaves IDLE and
    /// the command loop meets the same error. Returns false when the session ends.
    pub(crate) async fn idle(&mut self, tag: &str) -> bool {
        if !self.authed {
            self.reply(tag, "NO [AUTHENTICATIONREQUIRED] Authenticate before IDLE");
            return true;
        }
        self.reply(tag, "+ idling");
        if !self.flush().await {
            return false;
        }
        let mut closed = self.close_rx.clone();
        loop {
            let line = tokio::select! {
                _ = async { let _ = closed.wait_for(|v| *v).await; } => return false,
                line = self.conn.read_line() => line,
            };
            match line {
                Ok(line) => {
                    if String::from_utf8_lossy(&line).trim() == "DONE" {
                        self.reply(tag, "OK IDLE completed");
                        return true;
                    }
                }
                // Owner-approved security fix 2026-11-05 (#449): a client that disconnects during
                // IDLE ends the session and frees its connection slots (frozen Go swallowed the
                // error in a 100 ms loop and leaked the slot).
                Err(LineError::Closed) if setjoin_contracts::mutants::on("imap-idle-spins-on-close") => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(LineError::TooLong | LineError::Closed) => return true,
            }
        }
    }
}
