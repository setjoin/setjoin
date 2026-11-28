//! FETCH, SEARCH, STORE and UID (#344): a port of frozen Go's `handleFetch`,
//! `handleSearch`, `handleStore` and `handleUID` over the selected tag. The wire
//! contract is Go's bytes, quirks included (see DOX.md "Mirrored Go quirks").
use crate::session::{query_vanished_uids_in_tx, split_args, Session};
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{CommandOutcome, MailboxTx, Param, ReadOnly, ReadWrite, StatementFailure, Type};
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
    pub(crate) modseq: i64,
}

pub(crate) fn uid_in_ranges(uid: i64, ranges: &[Range], star: i64) -> bool {
    let resolve = |v: i64| if v == STAR { star.max(uid) } else { v };
    for r in ranges {
        let (mut lo, mut hi) = (resolve(r.lo), resolve(r.hi));
        if lo > hi {
            std::mem::swap(&mut lo, &mut hi);
        }
        if uid >= lo && uid <= hi {
            return true;
        }
    }
    false
}

/// Format a sorted slice of positive sequence numbers or UIDs into compact RFC 3501/7162
/// sequence-set notation (e.g. `[1, 2, 3, 7, 9, 10]` -> `"1:3,7,9:10"`).
pub(crate) fn format_uid_set(uids: &[i64]) -> String {
    if uids.is_empty() {
        return String::new();
    }
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];
    for &u in &sorted[1..] {
        if u == prev + 1 {
            prev = u;
        } else {
            if start == prev {
                parts.push(start.to_string());
            } else {
                parts.push(format!("{start}:{prev}"));
            }
            start = u;
            prev = u;
        }
    }
    if start == prev {
        parts.push(start.to_string());
    } else {
        parts.push(format!("{start}:{prev}"));
    }
    parts.join(",")
}

/// Strict sequence-set parser forbidding `*` and rejecting any malformed token
/// (RFC 7162 §3.2.5.2 `known-uids` / `seq-match-data`).
pub(crate) fn parse_uid_set_strict_no_star(seq: &str) -> Option<Vec<Range>> {
    let seq = seq.trim();
    if seq.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for part in seq.split(',') {
        let part = part.trim();
        if part.is_empty() || part.contains('*') {
            return None;
        }
        match part.split_once(':') {
            None => {
                let n = part.parse::<i64>().ok()?;
                if n < 1 {
                    return None;
                }
                out.push(Range { lo: n, hi: n });
            }
            Some((lo_s, hi_s)) => {
                if hi_s.contains(':') {
                    return None;
                }
                let lo = lo_s.trim().parse::<i64>().ok()?;
                let hi = hi_s.trim().parse::<i64>().ok()?;
                if lo < 1 || hi < 1 {
                    return None;
                }
                out.push(Range { lo, hi });
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// RFC 7162 §3.2.5.2 strict ascending sequence/UID set parser (no `*`):
/// every item must be `<n>` or `<lo>:<hi>` with strictly ASCII-digit `u32`
/// values `1 <= lo <= hi`, items must be strictly ascending (`lo > prev_hi`),
/// and returns `(ranges, exact_cardinality)`.
pub(crate) fn parse_strict_ascending_set_no_star(s: &str) -> Option<(Vec<Range>, u64)> {
    let parse_nz_u32 = |tok: &str| -> Option<i64> {
        if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n = tok.parse::<u32>().ok()?;
        (n >= 1).then_some(i64::from(n))
    };
    let s = s.trim();
    if s.is_empty() || s.contains('*') {
        return None;
    }
    let mut out = Vec::new();
    let mut prev_hi: i64 = 0;
    let mut total: u64 = 0;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (lo, hi) = match part.split_once(':') {
            None => {
                let n = parse_nz_u32(part)?;
                (n, n)
            }
            Some((lo_s, hi_s)) => {
                if hi_s.contains(':') {
                    return None;
                }
                let lo = parse_nz_u32(lo_s.trim())?;
                let hi = parse_nz_u32(hi_s.trim())?;
                (lo, hi)
            }
        };
        if lo < 1 || hi < lo || lo <= prev_hi {
            return None;
        }
        let span = u64::try_from(hi.checked_sub(lo)?).ok()?.checked_add(1)?;
        total = total.checked_add(span)?;
        prev_hi = hi;
        out.push(Range { lo, hi });
    }
    (!out.is_empty()).then_some((out, total))
}

/// RFC 7162 §3.2.5.2 `seq-match-data` lower-UID bounding: walks `(seq, uid)`
/// pairs in lockstep from `seq_ranges` and `uid_ranges` (which must be strictly
/// ascending and equal-cardinality) while `seq <= rows.len()` and
/// `rows[seq - 1].msg.uid == uid`. Returns the highest aligned UID (or `0` if
/// the first pair already mismatched); vanished UIDs `<= aligned_floor` are
/// guaranteed already absent from the client's view and may be skipped.
pub(crate) fn compute_qresync_aligned_uid_floor(
    seq_ranges: &[Range],
    uid_ranges: &[Range],
    rows: &[FetchRow],
) -> i64 {
    let mut si = 0usize;
    let mut ui = 0usize;
    let mut s_off: i64 = 0;
    let mut u_off: i64 = 0;
    let mut aligned_floor: i64 = 0;
    let row_count = rows.len() as i64;
    while si < seq_ranges.len() && ui < uid_ranges.len() {
        let seq = seq_ranges[si].lo.saturating_add(s_off);
        let uid = uid_ranges[ui].lo.saturating_add(u_off);
        if seq < 1 || seq > row_count {
            break;
        }
        if rows[(seq - 1) as usize].msg.uid != uid {
            break;
        }
        aligned_floor = uid;
        if seq >= seq_ranges[si].hi {
            si += 1;
            s_off = 0;
        } else {
            s_off += 1;
        }
        if uid >= uid_ranges[ui].hi {
            ui += 1;
            u_off = 0;
        } else {
            u_off += 1;
        }
    }
    aligned_floor
}

/// Format sorted, disjoint closed UID intervals `(lo, hi)` into RFC 3501/7162
/// sequence-set notation (e.g. `[(1, 3), (7, 7), (9, 10)]` -> `"1:3,7,9:10"`).
pub(crate) fn format_uid_ranges(ranges: &[(i64, i64)]) -> String {
    ranges
        .iter()
        .filter(|&&(lo, hi)| lo > 0 && hi >= lo)
        .map(|&(lo, hi)| {
            if lo == hi {
                lo.to_string()
            } else {
                format!("{lo}:{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Exact O(R + M) range subtraction `known \ live_uids` returning sorted, merged
/// closed intervals — handles arbitrarily large UID spans with zero expansion cap.
pub(crate) fn subtract_live_from_ranges(
    known: &[Range],
    rows: &[FetchRow],
    star_uid: i64,
) -> Vec<(i64, i64)> {
    let mut intervals: Vec<(i64, i64)> = known
        .iter()
        .filter_map(|r| {
            let mut lo = if r.lo == STAR { star_uid } else { r.lo };
            let mut hi = if r.hi == STAR { star_uid } else { r.hi };
            if lo <= 0 || hi <= 0 {
                return None;
            }
            if lo > hi {
                std::mem::swap(&mut lo, &mut hi);
            }
            Some((lo, hi))
        })
        .collect();
    if intervals.is_empty() {
        return Vec::new();
    }
    intervals.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::with_capacity(intervals.len());
    for (lo, hi) in intervals {
        if let Some(last) = merged.last_mut() {
            if lo <= last.1.saturating_add(1) {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        merged.push((lo, hi));
    }
    let mut live: Vec<i64> = rows.iter().map(|r| r.msg.uid).filter(|&u| u > 0).collect();
    live.sort_unstable();
    live.dedup();

    let mut out = Vec::new();
    let mut li = 0usize;
    for (lo, hi) in merged {
        while li < live.len() && live[li] < lo {
            li += 1;
        }
        let mut cur = lo;
        while li < live.len() && live[li] <= hi {
            let u = live[li];
            if u > cur {
                out.push((cur, u - 1));
            }
            cur = u.saturating_add(1);
            li += 1;
        }
        if cur <= hi {
            out.push((cur, hi));
        }
    }
    out
}

pub(crate) fn flag_names_joined(m: &Msg) -> String {
    flag_names(m).join(" ")
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
            "MODSEQ" if i + 1 < keys.len() => {
                // RFC 7162 §3.1.5: MODSEQ [<entry-name> <entry-type-req>] <mod-sequence-valzer>
                if let Ok(val) = keys[i + 1].parse::<i64>() {
                    if val >= 0 {
                        clauses.push(format!("COALESCE(m.imap_modseq, 1) >= ${n}::bigint"));
                        params.push(val.to_string());
                        n += 1;
                    }
                    i += 1;
                } else if i + 3 < keys.len() {
                    if let Ok(val) = keys[i + 3].parse::<i64>() {
                        if val >= 0 {
                            clauses.push(format!("COALESCE(m.imap_modseq, 1) >= ${n}::bigint"));
                            params.push(val.to_string());
                            n += 1;
                        }
                    }
                    i += 3;
                }
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

    pub(crate) fn uid_column(&self) -> &'static str {
        if self.use_membership_uid {
            "mt.imap_uid"
        } else {
            "m.imap_uid"
        }
    }

    /// `auditLog`: after the reply, best effort, only with a resolved mailbox.
    pub(crate) async fn audit(&self, action: &str) {
        if self.mailbox_id <= 0 {
            return;
        }
        let (Some(tx_factory), Some(mutate_cap)) = (self.tx_factory(), self.mutate_cap()) else {
            return;
        };
        let mailbox = mutate_cap.mailbox().get();
        let actor = mutate_cap.actor().get();
        let message: Option<i64> = None;
        let envelope = self.mailbox_envelope(&mutate_cap, action.as_bytes());
        let _ = tx_factory
            .run_mailbox_write_pipelined(
                &mutate_cap,
                &envelope,
                Instant::now() + Duration::from_secs(5),
                "INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id) \
                 VALUES ($1, $2, $3, $4)",
                &[
                    (&mailbox, Type::INT8),
                    (&actor, Type::INT8),
                    (&action, Type::TEXT),
                    (&message, Type::INT8),
                ],
                None,
                |_| Ok(()),
            )
            .await;
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
        let req = match parse_fetch_args(args, is_uid) {
            Ok(req) => req,
            Err(msg) => {
                self.reply(tag, msg);
                return;
            }
        };
        if req.vanished && !self.qresync_enabled {
            self.reply(tag, "BAD VANISHED requires ENABLE QRESYNC");
            return;
        }
        let ranges = parse_seq_set(&req.seq_set);
        if ranges.is_empty() {
            self.reply(tag, "BAD Invalid sequence number");
            return;
        }
        if req.wants_modseq || req.changed_since.is_some() {
            self.activate_condstore().await;
        }
        let (rows, vanished_str) = if let (true, Some(since)) = (req.vanished, req.changed_since) {
            let (Some(tx_factory), Some(read_cap)) = (self.tx_factory(), self.read_cap()) else {
                self.reply(tag, "NO Server error");
                return;
            };
            let (tag_id, mailbox_id, uid_col, membership) = (
                self.tag_id,
                read_cap.mailbox().get(),
                self.uid_column(),
                self.use_membership_uid,
            );
            let Ok(mut tx) = tx_factory.begin_mailbox_read_repeatable(&read_cap).await else {
                self.reply(tag, "NO Server error");
                return;
            };
            let snap: Result<(Vec<FetchRow>, String), StatementFailure> = async {
                let rows = read_fetch_rows_in_tx(&mut tx, tag_id, mailbox_id, uid_col).await?;
                let uid_bounds = tx
                    .query(
                        "SELECT COALESCE(t.imap_uid_next, 1)::bigint, \
                         GREATEST( \
                           COALESCE((SELECT MAX(t2.imap_uid_next) FROM tags t2 WHERE t2.mailbox_id = t.mailbox_id), 1) - 1, \
                           COALESCE((SELECT MAX(m2.imap_uid) FROM messages m2 WHERE m2.mailbox_id = t.mailbox_id), 0), \
                           COALESCE((SELECT MAX(j.imap_uid) FROM jmap_changes_journal j WHERE j.mailbox_id = t.mailbox_id AND j.datatype = 'email'), 0) \
                         )::bigint \
                         FROM tags t WHERE t.id = $1 AND t.mailbox_id = $2",
                        &[(&tag_id, Type::INT8), (&mailbox_id, Type::INT8)],
                    )
                    .await?;
                let next_uid = uid_bounds
                    .first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .unwrap_or(1)
                    .max(1);
                let mailbox_max_uid = uid_bounds
                    .first()
                    .and_then(|r| r.try_get::<_, i64>(1).ok())
                    .unwrap_or(0)
                    .max(0);
                let max_active_uid = rows.iter().map(|r| r.msg.uid).max().unwrap_or(0);
                let legacy_bound = if membership { 0 } else { mailbox_max_uid };
                let star_uid = max_active_uid
                    .max(next_uid.saturating_sub(1))
                    .max(legacy_bound);
                let (vanished, resync_required) = query_vanished_uids_in_tx(
                    &mut tx,
                    mailbox_id,
                    tag_id,
                    since,
                    membership,
                    Some(&ranges),
                    star_uid,
                )
                .await?;
                let formatted = if resync_required {
                    format_uid_ranges(&subtract_live_from_ranges(&ranges, &rows, star_uid))
                } else {
                    format_uid_set(&vanished)
                };
                Ok((rows, formatted))
            }
            .await;
            let _ = tx.finish().await;
            let Ok((rows, formatted)) = snap else {
                self.reply(tag, "NO Server error");
                return;
            };
            (rows, (!formatted.is_empty()).then_some(formatted))
        } else {
            let Some(rows) = self.read_fetch_rows().await else {
                self.reply(tag, "NO Server error");
                return;
            };
            (rows, None)
        };
        if let Some(formatted) = vanished_str {
            self.reply("*", &format!("VANISHED (EARLIER) {formatted}"));
        }
        let all: Vec<Msg> = rows.iter().map(|r| r.msg.clone()).collect();
        let include_modseq =
            req.wants_modseq || req.changed_since.is_some() || self.condstore_enabled;
        for target in resolve_seq_set(&ranges, &all, is_uid) {
            if let Some(since) = req.changed_since {
                if target.modseq <= since {
                    continue;
                }
            }
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
            let line = if include_modseq {
                format!(
                    "* {} FETCH (UID {} FLAGS ({}) MODSEQ ({}) RFC822.SIZE {} ENVELOPE ({} {} {} {} {} {} {} NIL NIL NIL)) \r\n",
                    target.seq,
                    target.uid,
                    flag_names(&target).join(" "),
                    target.modseq,
                    row.size,
                    date,
                    quote(&row.subject),
                    from,
                    from,
                    from,
                    to,
                    address_tuples(&row.cc),
                )
            } else {
                format!(
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
                )
            };
            self.out.extend_from_slice(line.as_bytes());
            if include_modseq {
                self.selected_highest_modseq = Some(
                    self.selected_highest_modseq
                        .map_or(target.modseq, |seen| seen.max(target.modseq)),
                );
            }
        }
        self.reply(tag, "OK FETCH completed");
        self.audit("imap_fetch").await;
    }

    pub(crate) async fn read_fetch_rows(&self) -> Option<Vec<FetchRow>> {
        let tx_factory = self.tx_factory()?;
        let read_cap = self.read_cap()?;
        let mailbox = read_cap.mailbox().get();
        // The received date is rendered in UTC: Go formats pgx's local-zone time
        // and the production gateway runs in UTC.
        let sql = if self.use_membership_uid {
            "SELECT m.id, mt.imap_uid, m.subject, m.from_addr, m.to_addrs::text, m.cc_addrs::text, \
                    m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted, \
                    m.size_bytes, \
                    to_char(m.received_at AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS') || ' +0000', \
                    COALESCE(m.imap_modseq, 1)::bigint \
             FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
             ORDER BY mt.imap_uid"
        } else {
            "SELECT m.id, m.imap_uid, m.subject, m.from_addr, m.to_addrs::text, m.cc_addrs::text, \
                    m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted, \
                    m.size_bytes, \
                    to_char(m.received_at AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS') || ' +0000', \
                    COALESCE(m.imap_modseq, 1)::bigint \
             FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
             ORDER BY m.imap_uid"
        };
        let rows = tx_factory
            .run_mailbox_read_pipelined(
                &read_cap,
                sql,
                &[(&self.tag_id, Type::INT8), (&mailbox, Type::INT8)],
            )
            .await
            .ok()?;
        decode_fetch_rows(&rows)
    }

    pub(crate) async fn search(&mut self, tag: &str, is_uid: bool, args: &str) {
        if !self.selected_mailbox() {
            self.reply(tag, "NO No mailbox selected");
            return;
        }
        let has_modseq_criterion = split_args(args)
            .iter()
            .any(|k| k.eq_ignore_ascii_case("MODSEQ"));
        if has_modseq_criterion {
            self.activate_condstore().await;
        }
        let Some((uids, max_modseq)) = self.read_search_uids(args).await else {
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
            if has_modseq_criterion {
                if let Some(m) = max_modseq {
                    response.push_str(&format!(" MODSEQ {m}"));
                }
            }
        }
        self.reply("*", &response);
        self.reply(tag, "OK SEARCH completed");
    }

    async fn read_search_uids(&self, args: &str) -> Option<(Vec<i64>, Option<i64>)> {
        let tx_factory = self.tx_factory()?;
        let read_cap = self.read_cap()?;
        let mailbox = read_cap.mailbox().get();
        let uid = self.uid_column();
        let (clause, values) = build_search_clause(args, 3);
        let sql = format!(
            "SELECT {uid}, COALESCE(m.imap_modseq, 1)::bigint FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
               AND NOT m.is_deleted{clause} ORDER BY {uid}"
        );
        let mut params: Vec<Param<'_>> = vec![(&self.tag_id, Type::INT8), (&mailbox, Type::INT8)];
        for value in &values {
            params.push((value, Type::TEXT));
        }
        let mut tx = tx_factory.begin_mailbox_read(&read_cap).await.ok()?;
        let rows = tx.query(&sql, &params).await.ok()?;
        tx.finish().await.ok()?;
        let mut uids = Vec::with_capacity(rows.len());
        let mut max_modseq: Option<i64> = None;
        for row in &rows {
            uids.push(row.try_get::<_, Option<i64>>(0).ok()??);
            let ms = row.try_get::<_, i64>(1).unwrap_or(1).max(1);
            max_modseq = Some(max_modseq.map_or(ms, |cur| cur.max(ms)));
        }
        Some((uids, max_modseq))
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
        let req = match parse_store_args(args) {
            Ok(req) => req,
            Err(msg) => {
                self.reply(tag, msg);
                return;
            }
        };
        let ranges = parse_seq_set(&req.seq_set);
        if ranges.is_empty() {
            self.reply(tag, "BAD Invalid sequence number");
            return;
        }
        let (delta, silent) = parse_store_flags(&req.op, &req.flags);
        if req.unchanged_since.is_some() {
            self.activate_condstore().await;
        }
        let (Some(tx_factory), Some(mutate_cap)) = (self.tx_factory(), self.mutate_cap()) else {
            self.reply(tag, "NO Store failed");
            return;
        };
        let envelope = self.mailbox_envelope(&mutate_cap, args.as_bytes());
        let (tag_id, mailbox, uid_column) =
            (self.tag_id, mutate_cap.mailbox().get(), self.uid_column());
        let unchanged_since = req.unchanged_since;
        let outcome = tx_factory
            .run_mailbox_write(
                &mutate_cap,
                &envelope,
                Instant::now() + STORE_DEADLINE,
                async |tx: &mut MailboxTx<ReadWrite>| {
                    store_in_tx(
                        tx,
                        tag_id,
                        mailbox,
                        uid_column,
                        &ranges,
                        &delta,
                        is_uid,
                        unchanged_since,
                    )
                    .await
                },
            )
            .await;
        let CommandOutcome::Committed(result) = outcome else {
            self.reply(tag, "NO Store failed");
            return;
        };
        if result.after_modseq > 0
            && self
                .selected_highest_modseq
                .is_some_and(|seen| result.before_modseq <= seen)
        {
            self.selected_highest_modseq = Some(result.after_modseq);
        }
        let include_modseq = req.unchanged_since.is_some() || self.condstore_enabled;
        if !silent {
            for m in &result.updated {
                let line = if include_modseq {
                    format!(
                        "* {} FETCH (UID {} FLAGS ({}) MODSEQ ({}))\r\n",
                        m.seq,
                        m.uid,
                        flag_names(m).join(" "),
                        m.modseq
                    )
                } else {
                    format!(
                        "* {} FETCH (UID {} FLAGS ({}))\r\n",
                        m.seq,
                        m.uid,
                        flag_names(m).join(" ")
                    )
                };
                self.out.extend_from_slice(line.as_bytes());
            }
        } else if req.unchanged_since.is_some() {
            // RFC 7162 §3.1.3: STORE (UNCHANGEDSINCE n) ... .SILENT MUST still
            // return untagged FETCH with MODSEQ for every modified message.
            for m in &result.updated {
                let line = format!(
                    "* {} FETCH (UID {} MODSEQ ({}))\r\n",
                    m.seq, m.uid, m.modseq
                );
                self.out.extend_from_slice(line.as_bytes());
            }
        }
        if !result.modified.is_empty() {
            self.reply(
                tag,
                &format!(
                    "OK [MODIFIED {}] Conditional STORE failed",
                    format_uid_set(&result.modified)
                ),
            );
        } else {
            self.reply(tag, "OK STORE completed");
        }
        self.audit("imap_store").await;
    }
}

pub(crate) fn decode_fetch_rows(rows: &[setjoin_pg::Row]) -> Option<Vec<FetchRow>> {
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
                modseq: row.try_get::<_, i64>(13).unwrap_or(1).max(1),
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

pub(crate) async fn read_fetch_rows_in_tx(
    tx: &mut MailboxTx<ReadOnly>,
    tag_id: i64,
    mailbox_id: i64,
    uid_col: &str,
) -> Result<Vec<FetchRow>, StatementFailure> {
    let sql = format!(
        "SELECT m.id, {uid_col}, m.subject, m.from_addr, m.to_addrs::text, m.cc_addrs::text, \
                m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted, \
                m.size_bytes, \
                to_char(m.received_at AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS') || ' +0000', \
                COALESCE(m.imap_modseq, 1)::bigint \
         FROM messages m \
         JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
         WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE \
         ORDER BY {uid_col}"
    );
    let rows = tx
        .query(&sql, &[(&tag_id, Type::INT8), (&mailbox_id, Type::INT8)])
        .await?;
    decode_fetch_rows(&rows).ok_or_else(|| failure("fetch row scan failed"))
}

pub(crate) struct FetchRow {
    pub(crate) msg: Msg,
    subject: String,
    from: String,
    to: Vec<String>,
    cc: Vec<String>,
    size: i64,
    date: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FetchRequest {
    seq_set: String,
    wants_modseq: bool,
    changed_since: Option<i64>,
    vanished: bool,
}

fn parse_fetch_args(args: &str, is_uid: bool) -> Result<FetchRequest, &'static str> {
    let Some(first) = args.split_whitespace().next() else {
        return Err("BAD Missing arguments");
    };
    let rest = args.get(first.len()..).unwrap_or("").trim();
    // Look for a trailing parenthesized FETCH modifier list containing CHANGEDSINCE
    // and/or VANISHED in any order (RFC 7162 §3.1.4 & §3.2.6).
    let mut items_part = rest;
    let mut changed_since: Option<i64> = None;
    let mut vanished = false;
    if let Some(open) = rest.rfind('(') {
        if rest.ends_with(')') && open < rest.len() - 1 {
            let candidate = rest[open + 1..rest.len() - 1].trim();
            let mods: Vec<&str> = candidate.split_whitespace().collect();
            let is_mod_list = mods.first().is_some_and(|tok| {
                tok.eq_ignore_ascii_case("CHANGEDSINCE") || tok.eq_ignore_ascii_case("VANISHED")
            });
            if is_mod_list {
                let mut idx = 0usize;
                while idx < mods.len() {
                    if mods[idx].eq_ignore_ascii_case("CHANGEDSINCE") {
                        if changed_since.is_some() {
                            return Err("BAD Duplicate CHANGEDSINCE modifier");
                        }
                        let Some(raw_val) = mods.get(idx + 1) else {
                            return Err("BAD Invalid CHANGEDSINCE modifier");
                        };
                        let Ok(val) = raw_val.parse::<i64>() else {
                            return Err("BAD Invalid CHANGEDSINCE modifier");
                        };
                        // RFC 7162 §3.1.4: mod-sequence-value MUST be >= 1.
                        if val < 1 {
                            return Err("BAD Invalid CHANGEDSINCE modifier");
                        }
                        changed_since = Some(val);
                        idx += 2;
                    } else if mods[idx].eq_ignore_ascii_case("VANISHED") {
                        if vanished {
                            return Err("BAD Duplicate VANISHED modifier");
                        }
                        vanished = true;
                        idx += 1;
                    } else {
                        return Err("BAD Invalid FETCH modifier");
                    }
                }
                if vanished && changed_since.is_none() {
                    return Err("BAD VANISHED requires CHANGEDSINCE");
                }
                if vanished && !is_uid {
                    return Err("BAD VANISHED requires UID FETCH");
                }
                items_part = rest[..open].trim();
                if items_part.is_empty() {
                    return Err("BAD Missing FETCH items");
                }
            }
        }
    }
    let wants_modseq = items_part
        .split(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
        .any(|tok| tok.eq_ignore_ascii_case("MODSEQ"));
    Ok(FetchRequest {
        seq_set: first.to_string(),
        wants_modseq,
        changed_since,
        vanished,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoreRequest {
    seq_set: String,
    unchanged_since: Option<i64>,
    op: String,
    flags: String,
}

fn parse_store_args(args: &str) -> Result<StoreRequest, &'static str> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("BAD Missing arguments");
    }
    let seq_set = parts[0].to_string();
    let mut idx = 1usize;
    let mut unchanged_since = None;
    if parts[idx].starts_with('(') {
        let mut combined = String::new();
        let mut closed = false;
        while idx < parts.len() {
            if !combined.is_empty() {
                combined.push(' ');
            }
            combined.push_str(parts[idx]);
            let ends = parts[idx].ends_with(')');
            idx += 1;
            if ends {
                closed = true;
                break;
            }
        }
        if !closed {
            return Err("BAD Invalid STORE modifier");
        }
        let inner = combined.trim_matches(|c| c == '(' || c == ')').trim();
        let mod_parts: Vec<&str> = inner.split_whitespace().collect();
        if mod_parts.len() == 2 && mod_parts[0].eq_ignore_ascii_case("UNCHANGEDSINCE") {
            let Ok(val) = mod_parts[1].parse::<i64>() else {
                return Err("BAD Invalid UNCHANGEDSINCE modifier");
            };
            if val < 0 {
                return Err("BAD Invalid UNCHANGEDSINCE modifier");
            }
            unchanged_since = Some(val);
        } else {
            return Err("BAD Invalid STORE modifier");
        }
    }
    if parts.len() < idx + 2 {
        return Err("BAD Missing arguments");
    }
    Ok(StoreRequest {
        seq_set,
        unchanged_since,
        op: parts[idx].to_string(),
        flags: parts[idx + 1..].join(" "),
    })
}

struct StoreOutcome {
    updated: Vec<Msg>,
    modified: Vec<i64>,
    before_modseq: i64,
    after_modseq: i64,
}

/// One scoped transaction: ordered view, optional RFC 7162 UNCHANGEDSINCE guard,
/// keyword patch via the reducer, then the `\Deleted` writes with their state
/// pushes (Go's `handleStore` body + CONDSTORE single-currency MODSEQ).
#[allow(clippy::too_many_arguments)]
async fn store_in_tx(
    tx: &mut MailboxTx<ReadWrite>,
    tag_id: i64,
    mailbox: i64,
    uid_column: &str,
    ranges: &[Range],
    delta: &Delta,
    is_uid: bool,
    unchanged_since: Option<i64>,
) -> Result<StoreOutcome, StatementFailure> {
    // Canonical #481 lock order: lock mailboxes BEFORE locking messages so
    // concurrent JMAP/IMAP writes serialize cleanly with zero deadlock inversion.
    let mb_rows = tx
        .query(
            "SELECT (COALESCE(jmap_email_state, 0) + 1)::bigint FROM mailboxes WHERE id = $1 FOR UPDATE",
            &[(&mailbox, Type::INT8)],
        )
        .await?;
    let before_modseq = mb_rows
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .unwrap_or(1)
        .max(1);
    let sql = format!(
        "SELECT m.id, {uid_column}, m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted, \
                COALESCE(m.imap_modseq, 1)::bigint \
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
                modseq: row.try_get::<_, i64>(7).unwrap_or(1).max(1),
            })
        };
        msgs.push(scan().ok_or_else(|| failure("row scan failed"))?);
    }
    let targets = resolve_seq_set(ranges, &msgs, is_uid);
    if targets.is_empty() {
        return Ok(StoreOutcome {
            updated: Vec::new(),
            modified: Vec::new(),
            before_modseq,
            after_modseq: before_modseq,
        });
    }
    // Lock target message rows in ascending id order BEFORE evaluating
    // UNCHANGEDSINCE and mutating, eliminating any check-then-write race.
    let target_ids: Vec<i64> = targets.iter().map(|m| m.id).collect();
    let locked_rows = tx
        .query(
            "SELECT id, is_read, is_flagged, is_answered, is_draft, is_deleted, \
                    COALESCE(imap_modseq, 1)::bigint \
               FROM messages \
              WHERE id = ANY($1) AND mailbox_id = $2 \
              ORDER BY id \
              FOR UPDATE",
            &[(&target_ids, Type::INT8_ARRAY), (&mailbox, Type::INT8)],
        )
        .await?;
    let mut locked_by_id = std::collections::HashMap::with_capacity(locked_rows.len());
    for row in &locked_rows {
        let scan_locked = || -> Option<(i64, bool, bool, bool, bool, bool, i64)> {
            Some((
                row.try_get(0).ok()?,
                row.try_get(1).ok()?,
                row.try_get(2).ok()?,
                row.try_get(3).ok()?,
                row.try_get(4).ok()?,
                row.try_get(5).ok()?,
                row.try_get::<_, i64>(6).ok()?.max(1),
            ))
        };
        if let Some((id, read, flagged, answered, draft, deleted, modseq)) = scan_locked() {
            locked_by_id.insert(id, (read, flagged, answered, draft, deleted, modseq));
        }
    }
    let mut eligible = Vec::with_capacity(targets.len());
    let mut modified = Vec::new();
    for mut m in targets {
        let Some(&(read, flagged, answered, draft, deleted, modseq)) = locked_by_id.get(&m.id)
        else {
            continue;
        };
        m.read = read;
        m.flagged = flagged;
        m.answered = answered;
        m.draft = draft;
        m.deleted = deleted;
        m.modseq = modseq;
        if let Some(limit) = unchanged_since {
            if m.modseq > limit {
                modified.push(if is_uid { m.uid } else { m.seq });
                continue;
            }
        }
        eligible.push(m);
    }
    if eligible.is_empty() {
        return Ok(StoreOutcome {
            updated: Vec::new(),
            modified,
            before_modseq,
            after_modseq: before_modseq,
        });
    }
    let mut patch = serde_json::Map::new();
    let (mut delete_ids, mut restore_ids) = (Vec::<i64>::new(), Vec::<i64>::new());
    let mut post = Vec::with_capacity(eligible.len());
    for m in &eligible {
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
    if !delete_ids.is_empty() || !restore_ids.is_empty() {
        tx.execute(
            "SELECT 1 FROM mailboxes WHERE id = $1 FOR KEY SHARE",
            &[(&mailbox, Type::INT8)],
        )
        .await?;
    }
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
    if !post.is_empty() {
        let ids: Vec<i64> = post.iter().map(|m| m.id).collect();
        let modseq_rows = tx
            .query(
                "SELECT id, COALESCE(imap_modseq, 1)::bigint FROM messages \
                 WHERE id = ANY($1) AND mailbox_id = $2",
                &[(&ids, Type::INT8_ARRAY), (&mailbox, Type::INT8)],
            )
            .await?;
        let mut by_id = std::collections::HashMap::with_capacity(modseq_rows.len());
        for row in &modseq_rows {
            if let (Ok(id), Ok(ms)) = (row.try_get::<_, i64>(0), row.try_get::<_, i64>(1)) {
                by_id.insert(id, ms.max(1));
            }
        }
        for m in &mut post {
            if let Some(&ms) = by_id.get(&m.id) {
                m.modseq = ms;
            }
        }
    }
    let after_rows = tx
        .query(
            "SELECT (COALESCE(jmap_email_state, 0) + 1)::bigint FROM mailboxes WHERE id = $1",
            &[(&mailbox, Type::INT8)],
        )
        .await?;
    let after_modseq = after_rows
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .unwrap_or(before_modseq)
        .max(1);
    Ok(StoreOutcome {
        updated: post,
        modified,
        before_modseq,
        after_modseq,
    })
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

    #[test]
    fn rfc7162_parsers_handle_modseq_changedsince_unchangedsince_and_uid_sets() {
        assert_eq!(format_uid_set(&[]), "");
        assert_eq!(format_uid_set(&[5, 1, 2, 3, 5, 9, 10]), "1:3,5,9:10");

        let f = parse_fetch_args("1:* (FLAGS MODSEQ) (CHANGEDSINCE 7 VANISHED)", true).unwrap();
        assert_eq!(f.seq_set, "1:*");
        assert!(f.wants_modseq);
        assert_eq!(f.changed_since, Some(7));
        assert!(f.vanished);
        let f_rev = parse_fetch_args("1:* (FLAGS MODSEQ) (VANISHED CHANGEDSINCE 7)", true).unwrap();
        assert_eq!(f_rev, f);
        assert!(parse_fetch_args("1:* (FLAGS) (CHANGEDSINCE 7 VANISHED)", false).is_err());
        assert!(parse_fetch_args("1:* (FLAGS) (VANISHED)", true).is_err());
        assert!(parse_fetch_args("1:* (FLAGS) (CHANGEDSINCE 0)", true).is_err());
        assert!(parse_fetch_args("1:* (FLAGS) (CHANGEDSINCE -1)", true).is_err());

        // Exact interval subtraction handles huge ranges without truncation.
        let live_rows = vec![
            FetchRow {
                msg: Msg {
                    uid: 10,
                    ..Msg::default()
                },
                subject: String::new(),
                from: String::new(),
                to: Vec::new(),
                cc: Vec::new(),
                size: 0,
                date: String::new(),
            },
            FetchRow {
                msg: Msg {
                    uid: 50_000,
                    ..Msg::default()
                },
                subject: String::new(),
                from: String::new(),
                to: Vec::new(),
                cc: Vec::new(),
                size: 0,
                date: String::new(),
            },
        ];
        assert_eq!(
            format_uid_ranges(&subtract_live_from_ranges(
                &[r(1, 100_000)],
                &live_rows,
                100_000
            )),
            "1:9,11:49999,50001:100000"
        );

        let s = parse_store_args("1:3 (UNCHANGEDSINCE 9) +FLAGS (\\Seen)").unwrap();
        assert_eq!(s.seq_set, "1:3");
        assert_eq!(s.unchanged_since, Some(9));
        assert_eq!(s.op, "+FLAGS");
        assert_eq!(s.flags, "(\\Seen)");
        assert!(parse_store_args("1 (UNCHANGEDSINCE nope) +FLAGS (\\Seen)").is_err());

        let (sql, params) = build_search_clause("MODSEQ 12", 3);
        assert_eq!(sql, " AND COALESCE(m.imap_modseq, 1) >= $3::bigint");
        assert_eq!(params, ["12"]);
        let (sql, params) = build_search_clause("MODSEQ \"/flags/\\seen\" all 15", 3);
        assert_eq!(sql, " AND COALESCE(m.imap_modseq, 1) >= $3::bigint");
        assert_eq!(params, ["15"]);

        // RFC 7162 §3.2.5.2 strict ascending seq-match-data & lower-UID bounding
        assert_eq!(
            parse_strict_ascending_set_no_star("1:3,5,8:9"),
            Some((vec![r(1, 3), r(5, 5), r(8, 9)], 6))
        );
        for bad in [
            "",
            "1:*",
            "3:1",
            "2,1",
            "1:3,3:5",
            "0",
            "1,1",
            "+1",
            "-1",
            "1:+2",
            "4294967296",
        ] {
            assert!(
                parse_strict_ascending_set_no_star(bad).is_none(),
                "must reject {bad:?}"
            );
        }
        let aligned_rows: Vec<FetchRow> = [10, 20, 40]
            .iter()
            .enumerate()
            .map(|(i, &uid)| FetchRow {
                msg: Msg {
                    id: uid,
                    uid,
                    seq: i as i64 + 1,
                    ..Msg::default()
                },
                subject: String::new(),
                from: String::new(),
                to: Vec::new(),
                cc: Vec::new(),
                size: 0,
                date: String::new(),
            })
            .collect();
        assert_eq!(
            compute_qresync_aligned_uid_floor(
                &[r(1, 3)],
                &[r(10, 10), r(20, 20), r(30, 30)],
                &aligned_rows,
            ),
            20
        );
        assert_eq!(
            compute_qresync_aligned_uid_floor(&[r(1, 2)], &[r(5, 5), r(10, 10)], &aligned_rows,),
            0
        );
    }
}
