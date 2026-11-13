//! COPY, MOVE and `UID COPY|MOVE` (#345): a port of frozen Go's `handleCopy` and
//! `handleMove`: one scoped transaction per command, an aligned input relation
//! of (message id, received_at) and set-based statements around the reducers.
use crate::{
    messages::{operation_id, parse_seq_set, resolve_seq_set, Msg},
    session::{canonical_mailbox, split_args, Session},
};
use setjoin_contracts::{command::CommandEnvelope, ids::Digest};
use setjoin_pg::{CommandOutcome, ScopedTx, StatementFailure, Type};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const TRANSFER_DEADLINE: Duration = Duration::from_secs(30);

enum Abort {
    Failed,
}

impl From<StatementFailure> for Abort {
    fn from(_: StatementFailure) -> Self {
        Abort::Failed
    }
}

#[derive(Default)]
struct Moved {
    validity: i64,
    sources: Vec<i64>,
    destinations: Vec<i64>,
    count: usize,
}

/// `copyConflictOrErr`: 23505 on the `message_tags` primary key is the duplicate
/// signal; the allocator ledger's key (also 23505) is a plain failure.
fn is_membership_conflict(f: &StatementFailure) -> bool {
    f.sqlstate.as_deref() == Some("23505")
        && f.message
            .split("constraint \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .is_some_and(|name| name.contains("message_tags"))
}

fn uid_set(uids: &[i64]) -> String {
    uids.iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

struct Input {
    ids: Vec<i64>,
    recvs: Vec<String>,
    sources: Vec<i64>,
}

/// `destinationUIDs`: legacy mode keeps the source UID; membership mode pairs
/// each input ordinal with the inserted membership's UID or fails the command.
fn destination_uids(
    input: &Input,
    membership: bool,
    inserted: &HashMap<(i64, String), i64>,
) -> Result<Vec<i64>, Abort> {
    if !membership {
        return Ok(input.sources.clone());
    }
    input
        .ids
        .iter()
        .zip(&input.recvs)
        .map(|(id, recv)| {
            inserted
                .get(&(*id, recv.clone()))
                .copied()
                .ok_or(Abort::Failed)
        })
        .collect()
}

async fn memberships(
    tx: &mut ScopedTx,
    sql: &str,
    params: &[setjoin_pg::Param<'_>],
) -> Result<HashMap<(i64, String), i64>, StatementFailure> {
    let rows = tx.query(sql, params).await?;
    let mut out = HashMap::with_capacity(rows.len());
    for row in &rows {
        // pgx scans into plain int64: a NULL UID fails the command.
        let uid = row
            .try_get::<_, Option<i64>>(2)
            .ok()
            .flatten()
            .ok_or_else(|| crate::messages::failure("row scan failed"))?;
        out.insert((row.get::<_, i64>(0), row.get::<_, String>(1)), uid);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn transfer_in_tx(
    tx: &mut ScopedTx,
    mov: bool,
    tag_id: i64,
    mailbox: i64,
    uid_column: &str,
    membership: bool,
    ranges: &[crate::messages::Range],
    is_uid: bool,
    target: &str,
) -> Result<Moved, Abort> {
    let mut moved = Moved::default();
    let dest = tx
        .query(
            "SELECT id, exclusive_group, imap_uid_validity FROM tags \
             WHERE mailbox_id = $1 AND (name = $2 OR imap_name = $2)",
            &[(&mailbox, Type::INT8), (&target, Type::TEXT)],
        )
        .await?;
    // An unknown target resolves nothing: the command completes with zero moved.
    let Some(dest) = dest.first() else {
        return Ok(moved);
    };
    let (dest_id, group, validity): (i64, Option<String>, i64) =
        (dest.get(0), dest.get(1), dest.get(2));
    moved.validity = validity;

    let rows = tx
        .query(
            &format!(
                "SELECT m.id, {uid_column}, m.received_at::text FROM messages m \
                 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
                 WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE AND NOT m.is_deleted \
                 ORDER BY {uid_column}"
            ),
            &[(&tag_id, Type::INT8), (&mailbox, Type::INT8)],
        )
        .await?;
    let mut all = Vec::with_capacity(rows.len());
    let mut recvs = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        // Any row pgx cannot scan (NULL UID) fails and rolls back the command.
        let uid = row
            .try_get::<_, Option<i64>>(1)
            .ok()
            .flatten()
            .ok_or(Abort::Failed)?;
        all.push(Msg {
            id: row.get(0),
            uid,
            seq: i as i64 + 1,
            ..Msg::default()
        });
        recvs.push(row.get::<_, String>(2));
    }
    let targets = resolve_seq_set(ranges, &all, is_uid);
    if targets.is_empty() {
        return Ok(moved);
    }
    let input = Input {
        ids: targets.iter().map(|m| m.id).collect(),
        recvs: targets
            .iter()
            .map(|m| recvs[m.seq as usize - 1].clone())
            .collect(),
        sources: targets.iter().map(|m| m.uid).collect(),
    };
    moved.sources = input.sources.clone();

    if mov {
        tx.execute(
            "DELETE FROM message_tags mt \
             USING messages m, \
                   unnest($1::bigint[], $2::text[]::timestamptz[]) WITH ORDINALITY AS u(mid, rat, ord) \
             WHERE mt.message_id = m.id AND mt.received_at = m.received_at \
               AND m.mailbox_id = $3 AND mt.tag_id = $4 AND mt.is_primary = TRUE \
               AND mt.message_id = u.mid AND mt.received_at = u.rat",
            &[
                (&input.ids, Type::INT8_ARRAY),
                (&input.recvs, Type::TEXT_ARRAY),
                (&mailbox, Type::INT8),
                (&tag_id, Type::INT8),
            ],
        )
        .await?;
        if group.as_deref() == Some("location") {
            let inserted = memberships(
                tx,
                "SELECT out_message_id, out_received_at::text, out_imap_uid \
                 FROM imap_batch_move_location($1::bigint[], $2::text[]::timestamptz[], $3, $4, 'imap')",
                &[
                    (&input.ids, Type::INT8_ARRAY),
                    (&input.recvs, Type::TEXT_ARRAY),
                    (&target, Type::TEXT),
                    (&mailbox, Type::INT8),
                ],
            )
            .await?;
            moved.destinations = destination_uids(&input, membership, &inserted)?;
            moved.count = input.ids.len();
            return Ok(moved);
        }
    }
    let inserted = memberships(
        tx,
        "WITH input AS (\
           SELECT u.mid, u.rat, u.ord \
             FROM unnest($1::bigint[], $2::text[]::timestamptz[]) WITH ORDINALITY AS u(mid, rat, ord)\
         ), inserted AS (\
           INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) \
           SELECT i.mid, i.rat, $3, 'imap', TRUE \
             FROM input i JOIN messages m ON m.id = i.mid AND m.received_at = i.rat \
            WHERE m.mailbox_id = $4 \
            ORDER BY i.ord \
           RETURNING message_id, received_at, imap_uid\
         ) \
         SELECT ins.message_id, ins.received_at::text, ins.imap_uid \
           FROM inserted ins JOIN input i ON i.mid = ins.message_id AND i.rat = ins.received_at \
          ORDER BY i.ord",
        &[
            (&input.ids, Type::INT8_ARRAY),
            (&input.recvs, Type::TEXT_ARRAY),
            (&dest_id, Type::INT8),
            (&mailbox, Type::INT8),
        ],
    )
    .await?;
    moved.destinations = destination_uids(&input, membership, &inserted)?;
    // The raw tag insert bypassed the state bump: one precise 'updated' delta per
    // message in source order (COPY also bumps the destination tag's state).
    let tag_arg: Option<i64> = if mov { None } else { Some(dest_id) };
    for id in &input.ids {
        tx.execute(
            "SELECT notify_state_change($1, $2, $3, 'updated')",
            &[
                (&mailbox, Type::INT8),
                (&tag_arg, Type::INT8),
                (id, Type::INT8),
            ],
        )
        .await?;
    }
    moved.count = input.ids.len();
    Ok(moved)
}

impl Session {
    /// COPY and MOVE share Go's argument handling; `mov` selects MOVE.
    pub(crate) async fn transfer(&mut self, tag: &str, args: &str, is_uid: bool, mov: bool) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        if self.read_only {
            self.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only");
            return;
        }
        let parts = split_args(args);
        if parts.len() < 2 {
            self.reply(tag, "BAD Missing arguments");
            return;
        }
        let target = canonical_mailbox(parts[1..].join(" ").trim_matches('"'));
        let ranges = parse_seq_set(parts[0]);
        if ranges.is_empty() {
            self.reply(tag, "BAD Invalid sequence number");
            return;
        }
        let verb = if mov { "MOVE" } else { "COPY" };
        let Some(auth) = self.mailbox_auth() else {
            self.reply(tag, &format!("NO {verb} failed"));
            return;
        };
        let envelope = CommandEnvelope {
            operation: operation_id(self.user_id),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(args.as_bytes()).into()),
            command: (),
        };
        let (tag_id, mailbox, uid_column, membership) = (
            self.tag_id,
            self.mailbox_id,
            self.uid_column(),
            self.use_membership_uid,
        );
        let outcome = self
            .server
            .db
            .run(
                &envelope,
                &auth,
                Instant::now() + TRANSFER_DEADLINE,
                async |tx: &mut ScopedTx| {
                    transfer_in_tx(
                        tx, mov, tag_id, mailbox, uid_column, membership, &ranges, is_uid, &target,
                    )
                    .await
                },
            )
            .await;
        let moved = match outcome {
            CommandOutcome::Committed(moved) => moved,
            // A failed statement decides the rollback reason, so the duplicate
            // membership (COPY's insert only) arrives as the statement failure.
            CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(failure))
                if !mov && is_membership_conflict(&failure) =>
            {
                self.reply(
                    tag,
                    "NO [CANNOT] Destination already contains one or more messages",
                );
                return;
            }
            _ => {
                self.reply(tag, &format!("NO {verb} failed"));
                return;
            }
        };
        if moved.count > 0 {
            // Go sends this through reply(line, ""): trailing space.
            self.out.extend_from_slice(
                format!(
                    "* OK [COPYUID {} {} {}] {verb} completed \r\n",
                    moved.validity,
                    uid_set(&moved.sources),
                    uid_set(&moved.destinations)
                )
                .as_bytes(),
            );
        }
        self.reply(tag, &format!("OK {verb} completed"));
        self.audit(if mov { "imap_move" } else { "imap_copy" })
            .await;
    }
}
