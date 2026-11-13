//! FETCH, SEARCH, STORE and UID (#344): a port of frozen Go's `handleFetch`,
//! `handleSearch`, `handleStore` and `handleUID` over the selected tag. The wire
//! contract is Go's bytes, quirks included (see DOX.md "Mirrored Go quirks").
use crate::session::{split_args, Session};
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Param, ScopedTx, StatementFailure, Type};
use sha2::{Digest as _, Sha256};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime},
};

/// Bound for the one STORE transaction (Go bounds it only by the pool).
const STORE_DEADLINE: Duration = Duration::from_secs(30);
const STAR: i64 = -1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Range {
    pub(crate) lo: i64,
    pub(crate) hi: i64,
}

/// `parseSeqSet`: commas, ranges and `*`; invalid tokens are dropped; anything
/// from the first `(` is ignored.
pub(crate) fn parse_seq_set(seq: &str) -> Vec<Range> {
    let seq = match seq.find('(') {
        Some(i) => seq[..i].trim(),
        None => seq,
    };
    let atom = |s: &str| -> Option<i64> {
        let s = s.trim();
        if s == "*" {
            return Some(STAR);
        }
        match s.parse::<i64>() {
            Ok(n) if n >= 1 => Some(n),
            _ => None,
        }
    };
    let mut out = Vec::new();
    for part in seq.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once(':') {
            None => {
                if let Some(n) = atom(part) {
                    out.push(Range { lo: n, hi: n });
                }
            }
            Some((lo, hi)) => {
                if let (Some(lo), Some(hi)) = (atom(lo), atom(hi)) {
                    out.push(Range { lo, hi });
                }
            }
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Msg {
    pub(crate) id: i64,
    pub(crate) uid: i64,
    pub(crate) seq: i64,
    pub(crate) read: bool,
    pub(crate) flagged: bool,
    pub(crate) answered: bool,
    pub(crate) draft: bool,
    pub(crate) deleted: bool,
}

/// `resolveSeqSet`: `msgs` ascend by UID and carry their 1-based position.
pub(crate) fn resolve_seq_set(ranges: &[Range], msgs: &[Msg], is_uid: bool) -> Vec<Msg> {
    let Some(last) = msgs.last() else {
        return Vec::new();
    };
    let star = if is_uid { last.uid } else { msgs.len() as i64 };
    let resolve = |v: i64| if v == STAR { star } else { v };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in msgs {
        let key = if is_uid { m.uid } else { m.seq };
        for r in ranges {
            let (mut lo, mut hi) = (resolve(r.lo), resolve(r.hi));
            if lo > hi {
                std::mem::swap(&mut lo, &mut hi);
            }
            if key >= lo && key <= hi {
                if seen.insert(m.id) {
                    out.push(m.clone());
                }
                break;
            }
        }
    }
    out
}

#[derive(Default)]
struct Delta {
    add: bool,
    remove: bool,
    replace: bool,
    seen: bool,
    flagged: bool,
    answered: bool,
    draft: bool,
    deleted: bool,
}

/// `parseStoreFlags`: returns the delta and whether `.SILENT` was given.
fn parse_store_flags(op: &str, flags: &str) -> (Delta, bool) {
    let op = op.to_uppercase();
    let silent = op.ends_with(".SILENT");
    let op = op.strip_suffix(".SILENT").unwrap_or(&op);
    let mut d = Delta::default();
    match op {
        "+FLAGS" => d.add = true,
        "-FLAGS" => d.remove = true,
        "FLAGS" => d.replace = true,
        _ => {}
    }
    for f in flags
        .trim_matches(|c| c == '(' || c == ')')
        .split_whitespace()
    {
        match f.to_uppercase().as_str() {
            "\\SEEN" => d.seen = true,
            "\\FLAGGED" => d.flagged = true,
            "\\ANSWERED" => d.answered = true,
            "\\DRAFT" => d.draft = true,
            "\\DELETED" => d.deleted = true,
            _ => {}
        }
    }
    (d, silent)
}

fn apply_delta(m: &Msg, d: &Delta) -> Msg {
    let set = |cur: bool, mentioned: bool| {
        if d.replace {
            mentioned
        } else if d.add {
            mentioned || cur
        } else if d.remove {
            !mentioned && cur
        } else {
            cur
        }
    };
    Msg {
        read: set(m.read, d.seen),
        flagged: set(m.flagged, d.flagged),
        answered: set(m.answered, d.answered),
        draft: set(m.draft, d.draft),
        deleted: set(m.deleted, d.deleted),
        ..m.clone()
    }
}

fn flag_names(m: &Msg) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (on, name) in [
        (m.read, "\\Seen"),
        (m.flagged, "\\Flagged"),
        (m.answered, "\\Answered"),
        (m.draft, "\\Draft"),
        (m.deleted, "\\Deleted"),
    ] {
        if on {
            out.push(name);
        }
    }
    out
}

/// `quoteIMAP`: empty is NIL; otherwise a quoted string with `\` and `"` escaped.
fn quote(s: &str) -> String {
    if s.is_empty() {
        return "NIL".into();
    }
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn split_address(addr: &str) -> (&str, &str) {
    match addr.rfind('@') {
        Some(i) => (&addr[..i], &addr[i + 1..]),
        None => (addr, ""),
    }
}

/// `parseAddrTuple`.
fn address_tuple(addr: &str) -> String {
    if addr.is_empty() {
        return "NIL".into();
    }
    let (local, host) = split_address(addr);
    format!("((NIL NIL {} {}))", quote(local), quote(host))
}

/// `formatAddrTuples`.
fn address_tuples(addrs: &[String]) -> String {
    if addrs.is_empty() {
        return "NIL".into();
    }
    let parts: Vec<String> = addrs
        .iter()
        .map(|a| {
            let (local, host) = split_address(a);
            format!("(NIL NIL {} {})", quote(local), quote(host))
        })
        .collect();
    format!("({})", parts.join(" "))
}

/// A jsonb address array scanned into Go's `[]string`: SQL/JSON null is empty,
/// a JSON null element is "", any other non-string element fails the scan.
fn decode_addresses(text: &str) -> Option<Vec<String>> {
    let list: Option<Vec<Option<String>>> = serde_json::from_str(text).ok()?;
    Some(
        list.unwrap_or_default()
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect(),
    )
}

/// Go's `%q` (strconv.Quote) for the ESEARCH tag.
fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if c == ' ' || !(c.is_control() || c.is_whitespace() || is_format(c)) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// The common Unicode format (Cf) and private-use characters Go does not print.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x180e | 0x200b..=0x200f
        | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff | 0xfff9..=0xfffb
        | 0xe000..=0xf8ff | 0xf0000..=0x10ffff)
}

/// `buildSearchClause`: placeholders start at `$first`; every value is TEXT.
fn build_search_clause(args: &str, first: usize) -> (String, Vec<String>) {
    if args.is_empty() {
        return (String::new(), Vec::new());
    }
    let keys = split_args(args);
    let (mut clauses, mut params): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut n = first;
    let trim = |s: &str| s.trim_matches('"').to_string();
    let mut i = 0;
    while i < keys.len() {
        match keys[i].to_uppercase().as_str() {
            "SEEN" => clauses.push("m.is_read = TRUE".into()),
            "UNSEEN" | "NEW" => clauses.push("m.is_read = FALSE".into()),
            "DELETED" => clauses.push("m.is_deleted = TRUE".into()),
            "UNDELETED" => clauses.push("m.is_deleted = FALSE".into()),
            "ANSWERED" => clauses.push("m.is_answered = TRUE".into()),
            "UNANSWERED" => clauses.push("m.is_answered = FALSE".into()),
            "FLAGGED" => clauses.push("m.is_flagged = TRUE".into()),
            "UNFLAGGED" => clauses.push("m.is_flagged = FALSE".into()),
            "DRAFT" => clauses.push("m.is_draft = TRUE".into()),
            "UNDRAFT" => clauses.push("m.is_draft = FALSE".into()),
            "RECENT" => clauses.push("FALSE".into()),
            key @ ("FROM" | "SUBJECT" | "TEXT" | "BODY") if i + 1 < keys.len() => {
                clauses.push(match key {
                    "FROM" => format!("m.from_addr ILIKE ${n}"),
                    "SUBJECT" => format!("m.subject ILIKE ${n}"),
                    _ => format!("(m.subject ILIKE ${n} OR m.body_text ILIKE ${n})"),
                });
                params.push(format!("%{}%", trim(keys[i + 1])));
                n += 1;
                i += 1;
            }
            "HEADER" if i + 2 < keys.len() => {
                let field = keys[i + 1].trim_matches('"').to_uppercase();
                if field == "MESSAGE-ID" {
                    clauses.push(format!("m.message_id = ${n}"));
                    params.push(trim(keys[i + 2]));
                    n += 1;
                } else {
                    // An unsupported header cannot safely mean ALL.
                    clauses.push("FALSE".into());
                }
                i += 2;
            }
            "KEYWORD" if i + 1 < keys.len() => {
                clauses.push(format!(
                    "EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id \
                     WHERE mt.message_id = m.id AND t.name = ${n})"
                ));
                params.push(keys[i + 1].to_string());
                n += 1;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    if clauses.is_empty() {
        return (String::new(), Vec::new());
    }
    (format!(" AND {}", clauses.join(" AND ")), params)
}

pub(crate) fn failure(message: &str) -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        message: message.into(),
        hint: None,
    }
}

/// Operation IDs only need to be unique per attempt and non-zero.
pub(crate) fn operation_id(user: i64) -> OperationId {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hash = Sha256::new();
    hash.update(nanos.to_be_bytes());
    hash.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hash.update(user.to_be_bytes());
    hash.update(std::process::id().to_be_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    OperationId(id)
}

impl Session {
    pub(crate) fn selected_mailbox(&self) -> bool {
        self.authed && !self.selected.is_empty()
    }

    pub(crate) fn mailbox_auth(&self) -> Option<MailboxAuthContext> {
        Some(MailboxAuthContext::from_authenticated_session(
            ActorId::new(self.user_id).ok()?,
            MailboxId::new(self.mailbox_id).ok()?,
            Generation(1),
        ))
    }

    pub(crate) fn uid_column(&self) -> &'static str {
        if self.use_membership_uid {
            "mt.imap_uid"
        } else {
            "m.imap_uid"
        }
    }

    /// `auditLog`: after the reply, best effort, only with a resolved mailbox.
    pub(crate) async fn audit(&self, action: &str) {
        if self.mailbox_id > 0 {
            let _ = self
                .server
                .db
                .record_mailbox_audit(self.mailbox_id, self.user_id, action)
                .await;
        }
    }

    pub(crate) async fn uid_command(&mut self, tag: &str, args: &str) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        let parts: Vec<&str> = args.split_whitespace().collect();
        if parts.len() < 2 {
            self.reply(tag, "BAD Missing arguments");
            return;
        }
        let rest = parts[1..].join(" ");
        match parts[0].to_uppercase().as_str() {
            "FETCH" => self.fetch(tag, &rest, true).await,
            "SEARCH" => self.search(tag, true, &rest).await,
            "STORE" => self.store(tag, true, &rest).await,
            "COPY" => self.transfer(tag, &rest, true, false).await,
            "MOVE" => self.transfer(tag, &rest, true, true).await,
            _ => self.reply(tag, "BAD Unknown UID command"),
        }
    }

    pub(crate) async fn fetch(&mut self, tag: &str, args: &str, is_uid: bool) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        let Some(first) = args.split_whitespace().next() else {
            self.reply(tag, "BAD Missing arguments");
            return;
        };
        let ranges = parse_seq_set(first);
        if ranges.is_empty() {
            self.reply(tag, "BAD Invalid sequence number");
            return;
        }
        let Some(rows) = self.read_fetch_rows().await else {
            self.reply(tag, "NO Server error");
            return;
        };
        let all: Vec<Msg> = rows.iter().map(|r| r.msg.clone()).collect();
        for target in resolve_seq_set(&ranges, &all, is_uid) {
            let Some(row) = rows.iter().find(|r| r.msg.id == target.id) else {
                continue;
            };
            let from = address_tuple(&row.from);
            let to = match address_tuples(&row.to) {
                t if t == "NIL" => "((NIL NIL \"\" \"\"))".to_string(),
                t => t,
            };
            let date = if row.date.is_empty() {
                "NIL".to_string()
            } else {
                quote(&row.date)
            };
            // Go sends this through reply(line, ""): a trailing space before CRLF.
            let line = format!(
                "* {} FETCH (UID {} FLAGS ({}) RFC822.SIZE {} ENVELOPE ({} {} {} {} {} {} {} NIL NIL NIL)) \r\n",
                target.seq,
                target.uid,
                flag_names(&target).join(" "),
                row.size,
                date,
                quote(&row.subject),
                from,
                from,
                from,
                to,
                address_tuples(&row.cc),
            );
            self.out.extend_from_slice(line.as_bytes());
        }
        self.reply(tag, "OK FETCH completed");
        self.audit("imap_fetch").await;
    }

    async fn read_fetch_rows(&self) -> Option<Vec<FetchRow>> {
        let auth = self.mailbox_auth()?;
        let uid = self.uid_column();
        // The received date is rendered in UTC: Go formats pgx's local-zone time
        // and the production gateway runs in UTC.
        let sql = format!(
            "SELECT m.id, {uid}, m.subject, m.from_addr, m.to_addrs::text, m.cc_addrs::text, \
                    m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted, \
                    m.size_bytes, \
                    to_char(m.received_at AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS') || ' +0000' \
             FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
             ORDER BY {uid}"
        );
        let rows = self
            .server
            .db
            .read_scoped(
                &auth,
                &sql,
                &[(&self.tag_id, Type::INT8), (&self.mailbox_id, Type::INT8)],
            )
            .await
            .ok()?;
        let mut out = Vec::with_capacity(rows.len());
        for (i, row) in rows.iter().enumerate() {
            // pgx fails the whole command on a row it cannot scan (NULL subject
            // or UID, a non-string address element).
            out.push(FetchRow {
                msg: Msg {
                    id: row.try_get(0).ok()?,
                    uid: row.try_get::<_, Option<i64>>(1).ok()??,
                    seq: i as i64 + 1,
                    read: row.try_get(6).ok()?,
                    flagged: row.try_get(7).ok()?,
                    answered: row.try_get(8).ok()?,
                    draft: row.try_get(9).ok()?,
                    deleted: row.try_get(10).ok()?,
                },
                subject: row.try_get::<_, Option<String>>(2).ok()??,
                from: row.try_get(3).ok()?,
                to: decode_addresses(&row.try_get::<_, String>(4).ok()?)?,
                cc: decode_addresses(&row.try_get::<_, String>(5).ok()?)?,
                size: row.try_get(11).ok()?,
                date: row.try_get(12).ok()?,
            });
        }
        Some(out)
    }

    pub(crate) async fn search(&mut self, tag: &str, is_uid: bool, args: &str) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        let Some(uids) = self.read_search_uids(args).await else {
            self.reply(tag, "NO Server error");
            return;
        };
        let nums: Vec<String> = uids
            .iter()
            .enumerate()
            .map(|(i, uid)| {
                if is_uid {
                    uid.to_string()
                } else {
                    (i + 1).to_string()
                }
            })
            .collect();
        let mut response = format!("ESEARCH (TAG {})", go_quote(tag));
        if is_uid {
            response.push_str(" UID");
        }
        if !nums.is_empty() {
            response.push_str(" ALL ");
            response.push_str(&nums.join(","));
        }
        self.reply("*", &response);
        self.reply(tag, "OK SEARCH completed");
    }

    async fn read_search_uids(&self, args: &str) -> Option<Vec<i64>> {
        let auth = self.mailbox_auth()?;
        let uid = self.uid_column();
        let (clause, values) = build_search_clause(args, 3);
        let sql = format!(
            "SELECT {uid} FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
               AND NOT m.is_deleted{clause} ORDER BY {uid}"
        );
        let mut params: Vec<Param<'_>> =
            vec![(&self.tag_id, Type::INT8), (&self.mailbox_id, Type::INT8)];
        for value in &values {
            params.push((value, Type::TEXT));
        }
        let rows = self
            .server
            .db
            .read_scoped(&auth, &sql, &params)
            .await
            .ok()?;
        let mut uids = Vec::with_capacity(rows.len());
        for row in &rows {
            uids.push(row.try_get::<_, Option<i64>>(0).ok()??);
        }
        Some(uids)
    }

    pub(crate) async fn store(&mut self, tag: &str, is_uid: bool, args: &str) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        if self.read_only {
            self.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only");
            return;
        }
        let parts: Vec<&str> = args.split_whitespace().collect();
        if parts.len() < 3 {
            self.reply(tag, "BAD Missing arguments");
            return;
        }
        let ranges = parse_seq_set(parts[0]);
        if ranges.is_empty() {
            self.reply(tag, "BAD Invalid sequence number");
            return;
        }
        let (delta, silent) = parse_store_flags(parts[1], &parts[2..].join(" "));
        let Some(auth) = self.mailbox_auth() else {
            self.reply(tag, "NO Store failed");
            return;
        };
        let envelope = CommandEnvelope {
            operation: operation_id(self.user_id),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(args.as_bytes()).into()),
            command: (),
        };
        let (tag_id, mailbox, uid_column) = (self.tag_id, self.mailbox_id, self.uid_column());
        let outcome = self
            .server
            .db
            .run(
                &envelope,
                &auth,
                Instant::now() + STORE_DEADLINE,
                async |tx: &mut ScopedTx| {
                    store_in_tx(tx, tag_id, mailbox, uid_column, &ranges, &delta, is_uid).await
                },
            )
            .await;
        let CommandOutcome::Committed(post) = outcome else {
            self.reply(tag, "NO Store failed");
            return;
        };
        if !silent {
            for m in &post {
                let line = format!(
                    "* {} FETCH (UID {} FLAGS ({}))\r\n",
                    m.seq,
                    m.uid,
                    flag_names(m).join(" ")
                );
                self.out.extend_from_slice(line.as_bytes());
            }
        }
        self.reply(tag, "OK STORE completed");
        self.audit("imap_store").await;
    }
}

struct FetchRow {
    msg: Msg,
    subject: String,
    from: String,
    to: Vec<String>,
    cc: Vec<String>,
    size: i64,
    date: String,
}

/// One scoped transaction: ordered view, keyword patch via the reducer, then
/// the `\Deleted` writes with their state pushes (Go's `handleStore` body).
async fn store_in_tx(
    tx: &mut ScopedTx,
    tag_id: i64,
    mailbox: i64,
    uid_column: &str,
    ranges: &[Range],
    delta: &Delta,
    is_uid: bool,
) -> Result<Vec<Msg>, StatementFailure> {
    let sql = format!(
        "SELECT m.id, {uid_column}, m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted \
         FROM messages m \
         JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
         WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
         ORDER BY {uid_column}"
    );
    let rows = tx
        .query(&sql, &[(&tag_id, Type::INT8), (&mailbox, Type::INT8)])
        .await?;
    let mut msgs = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        // A NULL UID cannot be scanned by pgx and fails the whole command.
        let scan = || -> Option<Msg> {
            Some(Msg {
                id: row.try_get(0).ok()?,
                uid: row.try_get::<_, Option<i64>>(1).ok()??,
                seq: i as i64 + 1,
                read: row.try_get(2).ok()?,
                flagged: row.try_get(3).ok()?,
                answered: row.try_get(4).ok()?,
                draft: row.try_get(5).ok()?,
                deleted: row.try_get(6).ok()?,
            })
        };
        msgs.push(scan().ok_or_else(|| failure("row scan failed"))?);
    }
    let targets = resolve_seq_set(ranges, &msgs, is_uid);
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut patch = serde_json::Map::new();
    let (mut delete_ids, mut restore_ids) = (Vec::<i64>::new(), Vec::<i64>::new());
    let mut post = Vec::with_capacity(targets.len());
    for m in &targets {
        let np = apply_delta(m, delta);
        let mut kw = serde_json::Map::new();
        for (key, current, next) in [
            ("$seen", m.read, np.read),
            ("$flagged", m.flagged, np.flagged),
            ("$answered", m.answered, np.answered),
            ("$draft", m.draft, np.draft),
        ] {
            if delta.replace || current != next {
                kw.insert(key.into(), next.into());
            }
        }
        if !kw.is_empty() {
            patch.insert(m.id.to_string(), serde_json::json!({ "keywords": kw }));
        }
        if np.deleted != m.deleted {
            if np.deleted {
                &mut delete_ids
            } else {
                &mut restore_ids
            }
            .push(m.id);
        }
        post.push(np);
    }
    if !patch.is_empty() {
        let patch = serde_json::Value::Object(patch).to_string();
        tx.execute(
            "SELECT jmap_email_set_update($1, $2::jsonb)",
            &[(&mailbox, Type::INT8), (&patch, Type::TEXT)],
        )
        .await?;
    }
    // \Deleted is the expunge mark (messages.is_deleted); the reducer's keyword
    // path does not own it. Ownership is re-asserted in the same WHERE (R3).
    for (ids, value, operation) in [
        (&delete_ids, true, "destroyed"),
        (&restore_ids, false, "created"),
    ] {
        if ids.is_empty() {
            continue;
        }
        tx.execute(
            "UPDATE messages SET is_deleted = $3 WHERE id = ANY($1) AND mailbox_id = $2",
            &[
                (ids, Type::INT8_ARRAY),
                (&mailbox, Type::INT8),
                (&value, Type::BOOL),
            ],
        )
        .await?;
        for id in ids {
            tx.execute(
                "SELECT notify_state_change($1, NULL::BIGINT, $2, $3)",
                &[
                    (&mailbox, Type::INT8),
                    (id, Type::INT8),
                    (&operation, Type::TEXT),
                ],
            )
            .await?;
        }
    }
    Ok(post)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(lo: i64, hi: i64) -> Range {
        Range { lo, hi }
    }

    #[test]
    fn seq_set_matches_go_parse_seq_set() {
        assert_eq!(
            parse_seq_set("1,3:5,*"),
            vec![r(1, 1), r(3, 5), r(STAR, STAR)]
        );
        assert_eq!(parse_seq_set("3(FLAGS)"), vec![r(3, 3)]);
        assert_eq!(parse_seq_set(" 2 : 4 "), vec![r(2, 4)]);
        for bad in ["", "abc", "0", "-1", "1:abc", "1:*:3", "1:", ":2"] {
            assert!(parse_seq_set(bad).is_empty(), "{bad}");
        }
        assert_eq!(parse_seq_set("+2"), vec![r(2, 2)]);
    }

    fn msgs(uids: &[i64]) -> Vec<Msg> {
        uids.iter()
            .enumerate()
            .map(|(i, &uid)| Msg {
                id: uid * 10,
                uid,
                seq: i as i64 + 1,
                ..Msg::default()
            })
            .collect()
    }

    fn ids(found: Vec<Msg>) -> Vec<i64> {
        found.into_iter().map(|m| m.id).collect()
    }

    #[test]
    fn resolve_honours_uid_vs_sequence_stars_and_reversal() {
        let m = msgs(&[10, 20, 30, 40]);
        assert_eq!(
            ids(resolve_seq_set(&parse_seq_set("2:3"), &m, false)),
            [200, 300]
        );
        assert_eq!(ids(resolve_seq_set(&parse_seq_set("*"), &m, false)), [400]);
        assert_eq!(
            ids(resolve_seq_set(&parse_seq_set("3:2"), &m, false)),
            [200, 300]
        );
        assert!(resolve_seq_set(&parse_seq_set("2"), &m, true).is_empty());
        assert_eq!(
            ids(resolve_seq_set(&parse_seq_set("15:25"), &m, true)),
            [200]
        );
        assert_eq!(
            ids(resolve_seq_set(&parse_seq_set("1:3,2:4"), &m, false)),
            [100, 200, 300, 400]
        );
        assert!(resolve_seq_set(&parse_seq_set("1:*"), &[], false).is_empty());
    }

    #[test]
    fn replace_clears_unmentioned_flags_and_relative_ops_touch_only_mentioned() {
        let m = Msg {
            read: true,
            flagged: true,
            ..Msg::default()
        };
        let (d, silent) = parse_store_flags("flags.silent", "(\\Answered)");
        assert!(silent && d.replace);
        let n = apply_delta(&m, &d);
        assert!(!n.read && !n.flagged && n.answered);
        let (d, _) = parse_store_flags("-FLAGS", "(\\Seen)");
        let n = apply_delta(&m, &d);
        assert!(!n.read && n.flagged);
        let (d, _) = parse_store_flags("BOGUS", "(\\Seen)");
        assert!(apply_delta(&m, &d).read);
    }

    #[test]
    fn go_percent_q_escapes_like_strconv_quote() {
        assert_eq!(go_quote("a1"), "\"a1\"");
        assert_eq!(go_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(go_quote("t\u{1}\u{7f}"), "\"t\\x01\\x7f\"");
        assert_eq!(go_quote("\u{e9}\u{200b}"), "\"\u{e9}\\u200b\"");
    }

    #[test]
    fn search_clause_numbers_placeholders_and_ignores_unknown_keys() {
        let (sql, params) = build_search_clause("UNSEEN FROM \"bob\" HEADER x y SINCE", 3);
        assert_eq!(
            sql,
            " AND m.is_read = FALSE AND m.from_addr ILIKE $3 AND FALSE"
        );
        assert_eq!(params, ["%bob%"]);
        assert_eq!(build_search_clause("", 3), (String::new(), vec![]));
        assert_eq!(build_search_clause("SINCE x", 3).0, "");
        let (sql, params) = build_search_clause("TEXT a KEYWORD k HEADER message-id <m>", 3);
        assert!(sql.contains("ILIKE $3 OR m.body_text ILIKE $3"));
        assert!(sql.contains("t.name = $4") && sql.contains("m.message_id = $5"));
        assert_eq!(params, ["%a%", "k", "<m>"]);
    }

    #[test]
    fn envelope_addresses_follow_go() {
        assert_eq!(address_tuple(""), "NIL");
        assert_eq!(address_tuple("nohost"), "((NIL NIL \"nohost\" NIL))");
        assert_eq!(address_tuple("a@b@c"), "((NIL NIL \"a@b\" \"c\"))");
        assert_eq!(address_tuples(&[]), "NIL");
        assert_eq!(
            decode_addresses("[\"a@x\",null]"),
            Some(vec!["a@x".into(), String::new()])
        );
        assert_eq!(decode_addresses("[1]"), None);
        assert_eq!(decode_addresses("null"), Some(vec![]));
    }
}
