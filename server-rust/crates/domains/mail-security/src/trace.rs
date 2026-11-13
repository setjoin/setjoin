//! Slice `trace` (#327): Go's `admin.TraceHandler` (`List`, `Export`, `Timeline`) and
//! `user.TraceHandler` (`GET /messages/{emailId}/trace`), with the shared
//! `internal/delivery` read contract.
//!
//! `message_trace` and `outbound_queue` carry no tenant column: the admin routes sit behind
//! the console gate the adapter checks (`requireMailPerm` for list and timeline,
//! `requireMailExport` for the CSV) and read globally. `delivery_attempts`, `messages` and
//! `message_tags` are forced-RLS tables that Go reads on the worker pool; the user route
//! filters them by the verified user (`mb.user_id`) and the resolved mailbox in the same
//! WHERE. Everything here is a read, so there is no reducer.
use super::{done, invalid, nano, s};
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
use std::collections::HashMap;

/// `httputil.ParseLimitOffset(r, 50, 200)`.
pub fn page(limit: &str, offset: &str) -> (i64, i64) {
    let limit = match atoi(limit) {
        Some(n) if (1..=200).contains(&n) => n,
        _ => 50,
    };
    let offset = atoi(offset).unwrap_or(0).clamp(0, 1_000_000);
    (limit, offset)
}

/// `strconv.Atoi`: `None` on any syntax or range error.
fn atoi(text: &str) -> Option<i64> {
    let digits = text
        .strip_prefix('-')
        .or_else(|| text.strip_prefix('+'))
        .unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.strip_prefix('+').unwrap_or(text).parse().ok()
}

/// Go's `time.Parse(time.RFC3339, text)`: the instant as a PostgreSQL timestamptz literal
/// (fraction cut to microseconds as pgx encodes), `None` when Go would refuse it.
pub fn go_rfc3339(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<u32> {
        let part = text.get(from..from + len)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + u32::from(leap),
        _ => return None,
    };
    if day < 1 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut at = 19;
    let mut fraction = String::new();
    if matches!(b[at], b'.' | b',') && b.get(at + 1).is_some_and(u8::is_ascii_digit) {
        at += 1;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            fraction.push(b[at] as char);
            at += 1;
        }
        fraction.truncate(6);
    }
    let zone = text.get(at..)?;
    let valid = zone == "Z"
        || (zone.len() == 6
            && matches!(zone.as_bytes()[0], b'+' | b'-')
            && zone.as_bytes()[3] == b':'
            && zone[1..3].bytes().all(|c| c.is_ascii_digit())
            && zone[4..6].bytes().all(|c| c.is_ascii_digit())
            && zone[1..3].parse::<u32>().ok()? <= 23
            && zone[4..6].parse::<u32>().ok()? <= 59);
    if !valid {
        return None;
    }
    let fraction = if fraction.is_empty() {
        String::new()
    } else {
        format!(".{fraction}")
    };
    Some(format!("{}{fraction}{zone}", &text[..19]))
}

/// The seven query-string filters shared by list and export (decoded text).
#[derive(Default)]
pub struct Filters {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub event: String,
    pub status: String,
    pub date_from: String,
    pub date_to: String,
}

/// Go's dynamic WHERE, in Go's order: every value rides a bind parameter.
fn where_clause(f: &Filters) -> (String, Vec<String>) {
    let mut clause = "WHERE 1=1".to_owned();
    let mut args: Vec<String> = vec![];
    let mut add = |sql: &str, value: String| {
        args.push(value);
        clause += &format!(
            " AND {sql}",
            sql = sql.replace("$N", &format!("${}", args.len()))
        );
    };
    if !f.from.is_empty() {
        add("from_addr ILIKE $N", format!("%{}%", f.from));
    }
    if !f.to.is_empty() {
        add("rcpt_addr ILIKE $N", format!("%{}%", f.to));
    }
    if !f.event.is_empty() {
        add("event = $N", f.event.clone());
    }
    if !f.status.is_empty() {
        add("details->>'status' = $N", f.status.clone());
    }
    if !f.subject.is_empty() {
        add("details->>'subject' ILIKE $N", format!("%{}%", f.subject));
    }
    if let Some(t) = (!f.date_from.is_empty())
        .then(|| go_rfc3339(&f.date_from))
        .flatten()
    {
        add("occurred_at >= $N::text::timestamptz", t);
    }
    if let Some(t) = (!f.date_to.is_empty())
        .then(|| go_rfc3339(&f.date_to))
        .flatten()
    {
        add("occurred_at <= $N::text::timestamptz", t);
    }
    (clause, args)
}

/// `json.RawMessage` as `json.Marshal` writes it: whitespace outside strings removed.
fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !matches!(c, ' ' | '\t' | '\n' | '\r') {
            out.push(c);
        }
    }
    out
}

fn text_args(args: &[String]) -> Vec<setjoin_pg::Param<'_>> {
    args.iter().map(|a| (a as _, Type::TEXT)).collect()
}

/// `GET /admin/trace`: `{records, total, limit, offset}`; any query error is Go's 500.
pub async fn admin_list(
    worker: &ScopedExecutor,
    filters: &Filters,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let (clause, args) = where_clause(filters);
    let total = worker
        .read(
            &format!("SELECT COUNT(*) FROM message_trace {clause}"),
            &text_args(&args),
        )
        .await?
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)?;
    let n = args.len();
    let mut params = text_args(&args);
    params.push((&limit, Type::INT8));
    params.push((&offset, Type::INT8));
    let rows = worker
        .read_iterated(
            &format!(
                "SELECT id, message_id, event, from_addr, rcpt_addr, remote_host, details::text, {} \
                 FROM message_trace {clause} ORDER BY occurred_at DESC LIMIT ${} OFFSET ${}",
                nano("occurred_at"),
                n + 1,
                n + 2
            ),
            &params,
        )
        .await?;
    let mut records = vec![];
    for row in &rows {
        // Go skips a row whose Scan fails; every column here is scannable.
        let Ok(id) = row.try_get::<_, i64>(0) else {
            continue;
        };
        let (Ok(message), Ok(event), Ok(from), Ok(rcpt), Ok(host), Ok(details), Ok(at)) = (
            row.try_get::<_, String>(1),
            row.try_get::<_, String>(2),
            row.try_get::<_, String>(3),
            row.try_get::<_, String>(4),
            row.try_get::<_, Option<String>>(5),
            row.try_get::<_, Option<String>>(6),
            row.try_get::<_, String>(7),
        ) else {
            continue;
        };
        let mut record = format!(
            "{{\"id\":{id},\"messageId\":{},\"event\":{},\"fromAddr\":{},\"rcptAddr\":{}",
            s(&message),
            s(&event),
            s(&from),
            s(&rcpt)
        );
        if let Some(host) = host {
            record += &format!(",\"remoteHost\":{}", s(&host));
        }
        if let Some(details) = details.filter(|d| !d.is_empty()) {
            record += &format!(",\"details\":{}", compact(&details));
        }
        record += &format!(",\"occurredAt\":{}}}", s(&at));
        records.push(record);
    }
    Ok(done(format!(
        "{{\"records\":[{}],\"total\":{total},\"limit\":{limit},\"offset\":{offset}}}",
        records.join(",")
    )))
}

/// `GET /admin/trace/export`: Go's CSV (header row written as is, data cells
/// formula-neutralised), capped at 10 000 rows.
pub async fn admin_export(
    worker: &ScopedExecutor,
    filters: &Filters,
) -> Result<String, StatementFailure> {
    let (clause, args) = where_clause(filters);
    let rows = worker
        .read_iterated(
            &format!(
                "SELECT message_id, event, from_addr, rcpt_addr, remote_host, details::text, \
                 to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
                 FROM message_trace {clause} ORDER BY occurred_at DESC LIMIT 10000"
            ),
            &text_args(&args),
        )
        .await;
    let rows = match rows {
        Ok(rows) => rows,
        // pgx prepares the statement before binding: a data exception (invalid UTF-8 or NUL in a
        // filter) surfaces on the iteration Go never checks, so the download is header only.
        Err(e) if e.sqlstate.as_deref().is_some_and(|c| c.starts_with("22")) => vec![],
        Err(e) => return Err(e),
    };
    Ok(export_csv(&rows))
}

/// The header-only download Go sends when the query fails during iteration.
pub fn export_empty() -> String {
    export_csv(&[])
}

fn export_csv(rows: &[setjoin_pg::Row]) -> String {
    let header: Vec<String> = [
        "message_id",
        "event",
        "from_addr",
        "rcpt_addr",
        "remote_host",
        "details",
        "occurred_at",
    ]
    .iter()
    .map(|h| (*h).to_owned())
    .collect();
    let mut out = setjoin_contracts::csv::record(&header);
    for row in rows {
        let (Ok(message), Ok(event), Ok(from), Ok(rcpt), Ok(host), Ok(details), Ok(at)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, String>(2),
            row.try_get::<_, String>(3),
            row.try_get::<_, Option<String>>(4),
            row.try_get::<_, Option<String>>(5),
            row.try_get::<_, String>(6),
        ) else {
            continue;
        };
        let cells: Vec<String> = [
            message,
            event,
            from,
            rcpt,
            host.unwrap_or_default(),
            details.unwrap_or_default(),
            at,
        ]
        .iter()
        .map(|c| setjoin_contracts::csv::escape_formula(c))
        .collect();
        out += &setjoin_contracts::csv::record(&cells);
    }
    out
}

// ---- internal/delivery ----

struct Latest {
    mx_host: Option<String>,
    code: Option<i32>,
    text: Option<String>,
    at: Option<String>,
    outcome: String,
}
struct Attempt {
    n: i32,
    at: Option<String>,
    mx_host: Option<String>,
    code: Option<i32>,
    text: Option<String>,
    outcome: String,
    tls: bool,
}
struct Recipient {
    email: String,
    status: &'static str,
    mx_host: Option<String>,
    delivered_at: Option<String>,
    next_attempt_at: Option<String>,
    code: Option<i32>,
    text: Option<String>,
    attempts: Vec<Attempt>,
}

fn opt_str(v: &Option<String>) -> String {
    v.as_ref().map_or("null".to_owned(), |t| s(t))
}
fn opt_num(v: Option<i32>) -> String {
    v.map_or("null".to_owned(), |n| n.to_string())
}

/// `delivery.MapRecipientStatus`.
fn recipient_status(outcome: &str) -> &'static str {
    match outcome {
        "accepted" => "delivered",
        "rejected" => "bounced",
        "deferred" | "error" => "deferred",
        _ => "queued",
    }
}
/// `delivery.MapOverallStatus`.
fn overall_status(queue: &str) -> String {
    match queue {
        "pending" => "queued".to_owned(),
        other => other.to_owned(),
    }
}
fn is_terminal(overall: &str) -> bool {
    overall == "delivered" || overall == "bounced"
}
fn rank(status: &str) -> u8 {
    match status {
        "bounced" => 0,
        "deferred" => 1,
        "sending" => 2,
        "queued" => 3,
        "delivered" => 4,
        _ => 5,
    }
}
fn attempt_json(a: &Attempt) -> String {
    format!(
        "{{\"n\":{},\"at\":{},\"mxHost\":{},\"smtpCode\":{},\"smtpText\":{},\"outcome\":{},\"tls\":{}}}",
        a.n,
        opt_str(&a.at),
        opt_str(&a.mx_host),
        opt_num(a.code),
        opt_str(&a.text),
        s(&a.outcome),
        a.tls
    )
}
fn recipient_json(r: &Recipient) -> String {
    format!(
        "{{\"email\":{},\"status\":{},\"mxHost\":{},\"deliveredAt\":{},\"nextAttemptAt\":{},\"lastSmtpCode\":{},\"lastSmtpText\":{},\"attempts\":[{}]}}",
        s(&r.email),
        s(r.status),
        opt_str(&r.mx_host),
        opt_str(&r.delivered_at),
        opt_str(&r.next_attempt_at),
        opt_num(r.code),
        opt_str(&r.text),
        r.attempts.iter().map(attempt_json).collect::<Vec<_>>().join(",")
    )
}

/// The binding DISTINCT-ON read contract: one current row per recipient. `mailbox` is
/// `Some` for the user path (ownership in the WHERE) and `None` for the admin path (the
/// RBAC-gated cross-mailbox read). A failure degrades to what was read, as Go's Warn does.
async fn read_latest(
    worker: &ScopedExecutor,
    pk: i64,
    mailbox: Option<i64>,
) -> HashMap<String, Latest> {
    let mut out = HashMap::new();
    let scope = if mailbox.is_some() {
        " AND mailbox_id = $2"
    } else {
        ""
    };
    let sql = format!(
        "SELECT DISTINCT ON (recipient_email) recipient_email, mx_host, smtp_code, smtp_text, {}, outcome \
         FROM delivery_attempts WHERE message_pk = $1{scope} ORDER BY recipient_email, attempt_number DESC",
        nano("attempted_at")
    );
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![(&pk, Type::INT8)];
    if let Some(m) = mailbox.as_ref() {
        params.push((m, Type::INT8));
    }
    let Ok(rows) = worker.read(&sql, &params).await else {
        return out;
    };
    for row in &rows {
        let (Ok(email), Ok(mx_host), Ok(code), Ok(text), Ok(at), Ok(outcome)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, Option<String>>(1),
            row.try_get::<_, Option<i32>>(2),
            row.try_get::<_, Option<String>>(3),
            row.try_get::<_, Option<String>>(4),
            row.try_get::<_, String>(5),
        ) else {
            return out;
        };
        out.insert(
            email,
            Latest {
                mx_host,
                code,
                text,
                at,
                outcome,
            },
        );
    }
    out
}
async fn read_history(
    worker: &ScopedExecutor,
    pk: i64,
    mailbox: Option<i64>,
) -> HashMap<String, Vec<Attempt>> {
    let mut out: HashMap<String, Vec<Attempt>> = HashMap::new();
    let scope = if mailbox.is_some() {
        " AND mailbox_id = $2"
    } else {
        ""
    };
    let sql = format!(
        "SELECT recipient_email, attempt_number, {}, mx_host, smtp_code, smtp_text, outcome, tls \
         FROM delivery_attempts WHERE message_pk = $1{scope} ORDER BY recipient_email, attempt_number ASC",
        nano("attempted_at")
    );
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![(&pk, Type::INT8)];
    if let Some(m) = mailbox.as_ref() {
        params.push((m, Type::INT8));
    }
    let Ok(rows) = worker.read(&sql, &params).await else {
        return out;
    };
    for row in &rows {
        let (Ok(email), Ok(n), Ok(at), Ok(mx_host), Ok(code), Ok(text), Ok(outcome), Ok(tls)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, i32>(1),
            row.try_get::<_, Option<String>>(2),
            row.try_get::<_, Option<String>>(3),
            row.try_get::<_, Option<i32>>(4),
            row.try_get::<_, Option<String>>(5),
            row.try_get::<_, String>(6),
            row.try_get::<_, bool>(7),
        ) else {
            return out;
        };
        out.entry(email).or_default().push(Attempt {
            n,
            at,
            mx_host,
            code,
            text,
            outcome,
            tls,
        });
    }
    out
}

// ---- GET /admin/trace/{messageId} ----

/// The ordered delivery timeline of one message. Any read error before the recipients is
/// Go's 500; the per-recipient reads degrade.
pub async fn timeline(
    worker: &ScopedExecutor,
    message_id: &str,
) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            &format!(
                "SELECT event, rcpt_addr, from_addr, remote_host, details::text, {} \
                 FROM message_trace WHERE message_id = $1 ORDER BY occurred_at ASC",
                nano("occurred_at")
            ),
            &[(&message_id, Type::TEXT)],
        )
        .await?;
    let mut events = vec![];
    for row in &rows {
        let (Ok(event), Ok(rcpt), Ok(from), Ok(host), Ok(details), Ok(at)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, Option<String>>(1),
            row.try_get::<_, Option<String>>(2),
            row.try_get::<_, Option<String>>(3),
            row.try_get::<_, Option<String>>(4),
            row.try_get::<_, String>(5),
        ) else {
            continue;
        };
        events.push(format!(
            "{{\"event\":{},\"rcptAddr\":{},\"fromAddr\":{},\"remoteHost\":{},\"details\":{},\"occurredAt\":{}}}",
            s(&event),
            opt_str(&rcpt),
            opt_str(&from),
            opt_str(&host),
            details
                .filter(|d| !d.is_empty())
                .map_or("null".to_owned(), |d| compact(&d)),
            s(&at)
        ));
    }
    let queue = worker
        .read(
            &format!(
                "SELECT status, attempt_count, {}, last_error, rcpt_addrs, {}, message_pk \
                 FROM outbound_queue WHERE message_id = $1 ORDER BY queued_at DESC LIMIT 1",
                nano("next_attempt_at"),
                nano("queued_at")
            ),
            &[(&message_id, Type::TEXT)],
        )
        .await?;
    let mut out = format!(
        "{{\"messageId\":{},\"events\":[{}],",
        s(message_id),
        events.join(",")
    );
    let Some(row) = queue.first() else {
        out += "\"queue\":null,\"multiRecipient\":false}";
        return Ok(done(out));
    };
    let bad = |_| invalid();
    let status: String = row.try_get(0).map_err(bad)?;
    let attempts: i32 = row.try_get(1).map_err(bad)?;
    let next: Option<String> = row.try_get(2).map_err(bad)?;
    let last: Option<String> = row.try_get(3).map_err(bad)?;
    let rcpts: Vec<String> = row.try_get(4).map_err(bad)?;
    let queued: String = row.try_get(5).map_err(bad)?;
    let pk: Option<i64> = row.try_get(6).map_err(bad)?;
    out += &format!(
        "\"queue\":{{\"status\":{},\"attemptCount\":{attempts},\"nextAttemptAt\":{},\"lastError\":{},\"rcptAddrs\":[{}],\"queuedAt\":{}}},\"multiRecipient\":{}",
        s(&status),
        opt_str(&next),
        opt_str(&last),
        rcpts.iter().map(|r| s(r)).collect::<Vec<_>>().join(","),
        s(&queued),
        rcpts.len() > 1
    );
    if let Some(pk) = pk {
        let overall = overall_status(&status);
        let latest = read_latest(worker, pk, None).await;
        let history = read_history(worker, pk, None).await;
        let (recipients, expired) = if latest.is_empty() && is_terminal(&overall) {
            (vec![], true)
        } else {
            let mut list = recipients(&rcpts, latest, history, None, None);
            sort_problems_first(&mut list);
            (list, false)
        };
        // `recipients` is omitempty: an empty list is not written at all.
        if !recipients.is_empty() {
            out += &format!(
                ",\"recipients\":[{}]",
                recipients
                    .iter()
                    .map(recipient_json)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        if !overall.is_empty() {
            out += &format!(",\"overallStatus\":{}", s(&overall));
        }
        if expired {
            out += ",\"detailExpired\":true";
        }
    }
    out += "}";
    Ok(done(out))
}

fn sort_problems_first(list: &mut [Recipient]) {
    list.sort_by(|a, b| {
        rank(a.status)
            .cmp(&rank(b.status))
            .then_with(|| a.email.cmp(&b.email))
    });
}

/// The recipient set overlaid with each recipient's latest attempt. `delivered` and `next`
/// are the user path's queue values (`None` on the admin path).
fn recipients(
    emails: &[String],
    mut latest: HashMap<String, Latest>,
    mut history: HashMap<String, Vec<Attempt>>,
    delivered: Option<&String>,
    next: Option<&String>,
) -> Vec<Recipient> {
    emails
        .iter()
        .map(|email| {
            let attempts = history.remove(email).unwrap_or_default();
            let mut r = Recipient {
                email: email.clone(),
                status: "queued",
                mx_host: None,
                delivered_at: None,
                next_attempt_at: None,
                code: None,
                text: None,
                attempts,
            };
            if let Some(l) = latest.remove(email) {
                r.status = recipient_status(&l.outcome);
                r.mx_host = l.mx_host;
                r.code = l.code;
                r.text = l.text;
                if r.status == "delivered" {
                    r.delivered_at = delivered.cloned().or(l.at);
                }
                if r.status == "deferred" {
                    r.next_attempt_at = next.cloned();
                }
            }
            r
        })
        .collect()
}

// ---- GET /messages/{emailId}/trace ----

/// `user.OwnedMessage`.
pub struct Owned {
    pub raw_ref: String,
    pub mailbox_id: i64,
    pub pk: i64,
    received_at: std::time::SystemTime,
    pub subject: String,
}

/// `ResolveOwnedMessage`: the message only when it sits in one of the user's mailboxes
/// (R1); `Ok(None)` is Go's IDOR-safe 404.
pub async fn owned(
    worker: &ScopedExecutor,
    email_id: i64,
    user: i64,
) -> Result<Option<Owned>, StatementFailure> {
    let rows = worker
        .read(
            "SELECT m.raw_ref, m.mailbox_id, m.id, m.received_at, COALESCE(m.subject, 'message') \
             FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
             WHERE m.id = $1 AND mb.user_id = $2",
            &[(&email_id, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let bad = |_| invalid();
    Ok(Some(Owned {
        raw_ref: row.try_get(0).map_err(bad)?,
        mailbox_id: row.try_get(1).map_err(bad)?,
        pk: row.try_get(2).map_err(bad)?,
        received_at: row.try_get(3).map_err(bad)?,
        subject: row.try_get(4).map_err(bad)?,
    }))
}

/// `isSentMessage`: any error reads as inbound.
pub async fn is_sent(worker: &ScopedExecutor, om: &Owned) -> bool {
    let at = om.received_at;
    let Ok(rows) = worker
        .read(
            "SELECT EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id \
             WHERE mt.message_id = $1 AND mt.received_at = $2 AND t.mailbox_id = $3 \
             AND t.name = 'Sent' AND t.tag_type = 'system' AND t.exclusive_group = 'location')",
            &[
                (&om.pk, Type::INT8),
                (&at, Type::TIMESTAMPTZ),
                (&om.mailbox_id, Type::INT8),
            ],
        )
        .await
    else {
        return false;
    };
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .unwrap_or(false)
}

/// `user.sanitizeFilename`: every rune outside `[A-Za-z0-9._-]` becomes `_`, 100 bytes max.
fn sanitize_filename(subject: &str) -> String {
    let mut out: String = subject
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    out.truncate(100);
    if out.is_empty() {
        out = "message".to_owned();
    }
    out
}

/// The loopback JMAP download URL both the inbound fetch and the outbound `raw` link use.
pub fn download_url(base: &str, om: &Owned) -> String {
    format!(
        "{base}/{}/{}/{}.eml",
        om.mailbox_id,
        om.raw_ref,
        sanitize_filename(&om.subject)
    )
}

/// `writeOutbound`: the per-recipient delivery view of a Sent message.
pub async fn outbound(worker: &ScopedExecutor, om: &Owned, base: &str) -> String {
    // readOutboundQueue
    let queue = worker
        .read(
            &format!(
                "SELECT status, {}, {}, rcpt_addrs FROM outbound_queue \
                 WHERE message_pk = $1 AND mailbox_id = $2 ORDER BY queued_at DESC LIMIT 1",
                nano("next_attempt_at"),
                nano("delivered_at")
            ),
            &[(&om.pk, Type::INT8), (&om.mailbox_id, Type::INT8)],
        )
        .await
        .ok()
        .and_then(|rows| {
            let row = rows.first()?;
            Some((
                row.try_get::<_, String>(0).ok()?,
                row.try_get::<_, Option<String>>(1).ok()?,
                row.try_get::<_, Option<String>>(2).ok()?,
                row.try_get::<_, Vec<String>>(3).ok()?,
            ))
        });
    let found = queue.is_some();
    let (mut overall, next, delivered, rcpts) = match queue {
        Some((status, next, delivered, rcpts)) => (overall_status(&status), next, delivered, rcpts),
        None => (String::new(), None, None, vec![]),
    };
    let latest = read_latest(worker, om.pk, Some(om.mailbox_id)).await;
    let history = read_history(worker, om.pk, Some(om.mailbox_id)).await;
    let list = if found && latest.is_empty() && is_terminal(&overall) {
        vec![]
    } else {
        let emails: Vec<String> = if found {
            rcpts
        } else {
            // Undo-send: the set is whoever has an attempt (map order does not matter, the
            // list is sorted below).
            latest.keys().cloned().collect()
        };
        let mut list = recipients(&emails, latest, history, delivered.as_ref(), next.as_ref());
        sort_problems_first(&mut list);
        list
    };
    if overall.is_empty() {
        overall = derive_overall(&list).to_owned();
    }
    done(format!(
        "{{\"direction\":\"outbound\",\"auth\":{{}},\"raw\":{{\"url\":{},\"sizeBytes\":0}},\"overallStatus\":{},\"recipients\":[{}]}}",
        s(&download_url(base, om)),
        s(&overall),
        list.iter().map(recipient_json).collect::<Vec<_>>().join(",")
    ))
}

/// `deriveOverallStatus`, worst first.
fn derive_overall(list: &[Recipient]) -> &'static str {
    let any = |status: &str| list.iter().any(|r| r.status == status);
    if any("bounced") {
        "bounced"
    } else if any("deferred") {
        "deferred"
    } else if any("sending") {
        "sending"
    } else if any("queued") {
        "queued"
    } else if any("delivered") {
        "delivered"
    } else {
        "queued"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_follows_parse_limit_offset() {
        assert_eq!(page("", ""), (50, 0));
        assert_eq!(page("200", "7"), (200, 7));
        assert_eq!(page("201", "-3"), (50, 0));
        assert_eq!(page("+5", "9999999"), (5, 1_000_000));
        assert_eq!(page("0x10", "1e3"), (50, 0));
    }

    #[test]
    fn go_rfc3339_follows_time_parse() {
        assert_eq!(
            go_rfc3339("2026-10-01T10:00:00Z").as_deref(),
            Some("2026-10-01T10:00:00Z")
        );
        assert_eq!(
            go_rfc3339("2026-10-01T10:00:00.123456789+02:00").as_deref(),
            Some("2026-10-01T10:00:00.123456+02:00")
        );
        assert_eq!(go_rfc3339("2026-02-30T10:00:00Z"), None);
        assert_eq!(go_rfc3339("2026-10-01 10:00:00Z"), None);
        assert_eq!(go_rfc3339("2026-10-01T10:00:60Z"), None);
        assert_eq!(go_rfc3339("2026-10-01T10:00:00"), None);
        assert_eq!(go_rfc3339("2026-10-01T10:00:00+24:00"), None);
    }

    #[test]
    fn filename_follows_sanitize() {
        assert_eq!(sanitize_filename("Re: h\u{e9}llo/../x"), "Re__h_llo_.._x");
        assert_eq!(sanitize_filename(""), "message");
        assert_eq!(sanitize_filename(&"a".repeat(150)).len(), 100);
    }

    #[test]
    fn compact_keeps_strings() {
        assert_eq!(
            compact("{\"a\": \"x, y\", \"b\": [1, 2]}"),
            "{\"a\":\"x, y\",\"b\":[1,2]}"
        );
    }
}
