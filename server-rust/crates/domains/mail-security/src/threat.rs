//! Slice `threat` (#326): Go's `admin.ThreatHandler.View` (four read-only threat views, JSON
//! or CSV) and `admin.IPRulesHandler` (list, create, delete of admin-managed IP rules).
//!
//! Every route sits behind a console gate the adapter checks first: `requireLogsPerm`
//! (`audit.read`, organization-wide only) for the reads and `requireSecurityWrite` for the two
//! writes. All of these tables are global (no tenant column): the actor id comes from the
//! verified token and is the only identity written (`created_by`, the audit actor). A rule
//! create or delete is a receipted reducer so the row and Go's best-effort audit row commit
//! together.
use super::{command, deadline, done, envelope, invalid, nano, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};

/// Go's `admin.ConsoleScopes[ConsoleLogs]` (`requireLogsPerm`); organization-wide only.
pub const LOGS: [&str; 1] = ["audit.read"];

pub const DEFAULT_LIMIT: i64 = 100;
pub const MAX_LIMIT: i64 = 500;
/// `httputil.NewInternalProblem` detail.
pub const INTERNAL_DETAIL: &str = "An unexpected error occurred. Please try again.";

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

/// `limit` (default 100, clamped to 500) and `offset` (default 0) of both handlers.
pub fn page(limit: &str, offset: &str) -> (i64, i64) {
    let limit = match atoi(limit) {
        Some(n) if n > 0 => n.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    };
    let offset = match atoi(offset) {
        Some(n) if n >= 0 => n,
        _ => 0,
    };
    (limit, offset)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Attempts,
    Lockouts,
    FeedBlocks,
    RateCounters,
}
impl View {
    /// Go's `viewRegistry` key lookup.
    pub fn named(name: &str) -> Option<View> {
        Some(match name {
            "attempts" => View::Attempts,
            "lockouts" => View::Lockouts,
            "feed-blocks" => View::FeedBlocks,
            "rate-counters" => View::RateCounters,
            _ => return None,
        })
    }
    fn table(self) -> &'static str {
        match self {
            View::Attempts => "auth_attempts",
            View::Lockouts => "auth_lockouts",
            View::FeedBlocks => "threat_feed_blocks",
            View::RateCounters => "rate_limit_counters",
        }
    }
    fn sort_columns(self) -> &'static [&'static str] {
        match self {
            View::Attempts => &["occurred_at", "source_ip", "outcome"],
            View::Lockouts => &["locked_until", "failed_count", "updated_at"],
            View::FeedBlocks => &["added_at", "source"],
            View::RateCounters => &["count", "window_start", "blocked_until"],
        }
    }
    fn default_order(self) -> &'static str {
        match self {
            View::Attempts => "occurred_at DESC",
            View::Lockouts => "locked_until DESC",
            View::FeedBlocks => "added_at DESC",
            View::RateCounters => "count DESC",
        }
    }
    pub fn csv_headers(self) -> &'static [&'static str] {
        match self {
            View::Attempts => &[
                "source_ip",
                "target_username",
                "protocol",
                "outcome",
                "failure_reason",
                "geo_country",
                "occurred_at",
            ],
            View::Lockouts => &[
                "lockout_key",
                "failed_count",
                "locked_until",
                "escalation_level",
                "updated_at",
            ],
            View::FeedBlocks => &["cidr", "source", "added_at"],
            View::RateCounters => &["key", "count", "window_start", "blocked_until"],
        }
    }
}

/// `strings.EqualFold` against an ASCII name: simple Unicode folding maps U+017F to `s` and
/// U+212A to `k`.
fn fold_eq(text: &str, ascii: &str) -> bool {
    let fold = |c: char| match c {
        '\u{17f}' => 's',
        '\u{212a}' => 'k',
        c => c.to_lowercase().next().unwrap_or(c),
    };
    let mut have = text.chars().map(fold);
    let mut want = ascii.chars().map(fold);
    loop {
        match (have.next(), want.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// The allow-listed column the request names, if any (`resolveOrder` / `resolveAccessorSort`).
fn sort_column(view: View, sort: &str) -> Option<&'static str> {
    view.sort_columns()
        .iter()
        .copied()
        .find(|allowed| fold_eq(sort, allowed))
}

pub struct Query<'a> {
    pub limit: i64,
    pub offset: i64,
    pub since: &'a str,
    pub q: &'a str,
    pub sort: &'a str,
    pub dir: &'a str,
}

/// One rendered row: its JSON object and its CSV cells (Go's `fmt.Sprint` of each value).
pub struct Item {
    pub json: String,
    pub cells: Vec<String>,
}

/// `fmt.Sprint(time.Time)` for a UTC process: `2006-01-02 15:04:05.999999999 +0000 UTC`.
fn gotime(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || ' +0000 UTC'"
    )
}

fn text(row: &Row, i: usize) -> Result<String, StatementFailure> {
    row.try_get::<_, String>(i).map_err(|_| invalid())
}
fn stamp(row: &Row, i: usize) -> Result<(String, String), StatementFailure> {
    Ok((text(row, i)?, text(row, i + 1)?))
}
/// A nullable timestamp: JSON `null` / CSV `<nil>` (Go's `fmt.Sprint(nil)`).
fn maybe_stamp(row: &Row, i: usize) -> Result<(String, String), StatementFailure> {
    let json = row.try_get::<_, Option<String>>(i).map_err(|_| invalid())?;
    let cell = row
        .try_get::<_, Option<String>>(i + 1)
        .map_err(|_| invalid())?;
    Ok((
        json.map_or("null".to_owned(), |t| s(&t)),
        cell.unwrap_or_else(|| "<nil>".to_owned()),
    ))
}

fn attempt(row: &Row) -> Result<Item, StatementFailure> {
    let (ip, user, protocol, outcome, reason, geo) = (
        text(row, 0)?,
        text(row, 1)?,
        text(row, 2)?,
        text(row, 3)?,
        text(row, 4)?,
        text(row, 5)?,
    );
    let (at, at_cell) = stamp(row, 6)?;
    Ok(Item {
        json: format!(
            "{{\"failureReason\":{},\"geoCountry\":{},\"occurredAt\":{},\"outcome\":{},\"protocol\":{},\"sourceIp\":{},\"targetUsername\":{}}}",
            s(&reason), s(&geo), s(&at), s(&outcome), s(&protocol), s(&ip), s(&user)
        ),
        cells: vec![ip, user, protocol, outcome, reason, geo, at_cell],
    })
}
fn lockout(row: &Row) -> Result<Item, StatementFailure> {
    let key = text(row, 0)?;
    let failed = row.try_get::<_, i32>(1).map_err(|_| invalid())?;
    let (until, until_cell) = stamp(row, 2)?;
    let level = row.try_get::<_, i32>(4).map_err(|_| invalid())?;
    let (updated, updated_cell) = stamp(row, 5)?;
    Ok(Item {
        json: format!(
            "{{\"escalationLevel\":{level},\"failedCount\":{failed},\"lockedUntil\":{},\"lockoutKey\":{},\"updatedAt\":{}}}",
            s(&until), s(&key), s(&updated)
        ),
        cells: vec![key, failed.to_string(), until_cell, level.to_string(), updated_cell],
    })
}
fn feed_block(row: &Row) -> Result<Item, StatementFailure> {
    let (cidr, source) = (text(row, 0)?, text(row, 1)?);
    let (added, added_cell) = stamp(row, 2)?;
    Ok(Item {
        json: format!(
            "{{\"addedAt\":{},\"cidr\":{},\"source\":{}}}",
            s(&added),
            s(&cidr),
            s(&source)
        ),
        cells: vec![cidr, source, added_cell],
    })
}
fn rate_counter(row: &Row) -> Result<Item, StatementFailure> {
    let key = text(row, 0)?;
    let count = row.try_get::<_, i32>(1).map_err(|_| invalid())?;
    let (window, window_cell) = stamp(row, 2)?;
    let (blocked, blocked_cell) = maybe_stamp(row, 4)?;
    Ok(Item {
        json: format!(
            "{{\"blockedUntil\":{blocked},\"count\":{count},\"key\":{},\"windowStart\":{}}}",
            s(&key),
            s(&window)
        ),
        cells: vec![key, count.to_string(), window_cell, blocked_cell],
    })
}

/// The view's page and its total. `exec` is the request credential (the three table views);
/// `worker` is the BYPASSRLS credential the lockouts accessor needs. Any failure is Go's 500.
pub async fn rows(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    view: View,
    query: &Query<'_>,
) -> Result<(Vec<Item>, i64), StatementFailure> {
    if view == View::Lockouts {
        return lockouts(worker, query).await;
    }
    // Filters in Go's order; every value rides a bind parameter.
    let mut clauses: Vec<String> = vec![];
    let mut args: Vec<&str> = vec![];
    if view == View::Attempts && !query.since.is_empty() {
        args.push(query.since);
        clauses.push(format!(
            "occurred_at >= now() - ${}::text::interval",
            args.len()
        ));
    }
    if !query.q.is_empty() {
        args.push(query.q);
        let n = args.len();
        clauses.push(match view {
            View::Attempts => format!(
                "(target_username ILIKE '%' || ${n}::text || '%' OR source_ip::text ILIKE '%' || ${n}::text || '%')"
            ),
            View::FeedBlocks => format!(
                "(cidr::text ILIKE '%' || ${n}::text || '%' OR source ILIKE '%' || ${n}::text || '%')"
            ),
            _ => format!("key ILIKE '%' || ${n}::text || '%'"),
        });
    }
    let where_clause = if clauses.is_empty() {
        "WHERE 1=1".to_owned()
    } else {
        format!("WHERE 1=1 AND {}", clauses.join(" AND "))
    };
    let table = view.table();
    let text_args: Vec<setjoin_pg::Param<'_>> = args.iter().map(|a| (a as _, Type::TEXT)).collect();
    let total = exec
        .read(
            &format!("SELECT COUNT(*) FROM {table} {where_clause}"),
            &text_args,
        )
        .await?
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)?;
    let order = match sort_column(view, query.sort) {
        None => view.default_order().to_owned(),
        Some(column) => format!(
            "{column} {}",
            if fold_eq(query.dir, "DESC") {
                "DESC"
            } else {
                "ASC"
            }
        ),
    };
    let select = match view {
        View::Attempts => format!(
            "host(source_ip::inet), target_username, protocol, outcome, COALESCE(failure_reason,''), COALESCE(geo_country,''), {}, {}",
            nano("occurred_at"),
            gotime("occurred_at")
        ),
        View::FeedBlocks => format!(
            "cidr::text AS cidr, source, {}, {}",
            nano("added_at"),
            gotime("added_at")
        ),
        _ => format!(
            "key, count, {}, {}, {}, {}",
            nano("window_start"),
            gotime("window_start"),
            nano("blocked_until"),
            gotime("blocked_until")
        ),
    };
    let (n, m) = (args.len() + 1, args.len() + 2);
    let mut params = text_args;
    params.push((&query.limit, Type::INT8));
    params.push((&query.offset, Type::INT8));
    let rows = exec
        .read(
            &format!(
                "SELECT {select} FROM {table} {where_clause} ORDER BY {order} LIMIT ${n} OFFSET ${m}"
            ),
            &params,
        )
        .await?;
    let build = match view {
        View::Attempts => attempt,
        View::FeedBlocks => feed_block,
        _ => rate_counter,
    };
    // A row Go cannot scan is skipped; every column here scans.
    Ok((rows.iter().filter_map(|r| build(r).ok()).collect(), total))
}

/// The lockouts view reads only through the worker-owned `lockout_count` / `lockout_list`
/// accessors (`auth_lockouts` is deny-all FORCE RLS).
async fn lockouts(
    worker: &ScopedExecutor,
    query: &Query<'_>,
) -> Result<(Vec<Item>, i64), StatementFailure> {
    let total = worker
        .read("SELECT lockout_count($1::text)", &[(&query.q, Type::TEXT)])
        .await?
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)?;
    let (column, dir) = match sort_column(View::Lockouts, query.sort) {
        None => ("", ""),
        Some(column) => (
            column,
            if fold_eq(query.dir, "desc") {
                "desc"
            } else {
                "asc"
            },
        ),
    };
    // Go binds the page bounds as int4 parameters: pgx refuses an out-of-range value.
    let limit = i32::try_from(query.limit).map_err(|_| invalid())?;
    let offset = i32::try_from(query.offset).map_err(|_| invalid())?;
    let rows = worker
        .read(
            &format!(
                "SELECT lockout_key, failed_count, {}, {}, escalation_level, {}, {} FROM lockout_list($1::text, $2::int, $3::int, $4::text, $5::text)",
                nano("locked_until"),
                gotime("locked_until"),
                nano("updated_at"),
                gotime("updated_at")
            ),
            &[
                (&query.q, Type::TEXT),
                (&limit, Type::INT4),
                (&offset, Type::INT4),
                (&column, Type::TEXT),
                (&dir, Type::TEXT),
            ],
        )
        .await?;
    Ok((rows.iter().filter_map(|r| lockout(r).ok()).collect(), total))
}

/// `{rows, total, limit, offset}` as `map[string]any` renders it (sorted keys).
pub fn view_json(items: &[Item], total: i64, limit: i64, offset: i64) -> String {
    done(format!(
        "{{\"limit\":{limit},\"offset\":{offset},\"rows\":[{}],\"total\":{total}}}",
        items
            .iter()
            .map(|i| i.json.as_str())
            .collect::<Vec<_>>()
            .join(",")
    ))
}

/// The CSV document of `viewCSV`: header row, then every cell formula-neutralised.
pub fn view_csv(view: View, items: &[Item]) -> String {
    let headers: Vec<String> = view.csv_headers().iter().map(|h| (*h).to_owned()).collect();
    let mut out = setjoin_contracts::csv::record(&headers);
    for item in items {
        let cells: Vec<String> = item
            .cells
            .iter()
            .map(|c| setjoin_contracts::csv::escape_formula(c))
            .collect();
        out += &setjoin_contracts::csv::record(&cells);
    }
    out
}

/// Go's 404 detail for an unregistered view.
pub fn unknown_view_detail(name: &str) -> String {
    format!(
        "Unknown threat view: {name}. Valid views: attempts, lockouts, feed-blocks, rate-counters."
    )
}

// ---- IP rules ----

/// `GET /admin/threat/ip-rules`: `{rows, total, limit, offset}`; any failure is Go's 500.
pub async fn ip_rules_list(
    exec: &ScopedExecutor,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let total = exec
        .read("SELECT COUNT(*) FROM ip_rules", &[])
        .await?
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)?;
    let iso = |column: &str| {
        format!("to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    };
    let rows = exec
        .read(
            &format!(
                "SELECT id, cidr::text, action, description, {}, {}, created_by FROM ip_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                iso("expires_at"),
                iso("created_at")
            ),
            &[(&limit, Type::INT8), (&offset, Type::INT8)],
        )
        .await?;
    let mut items = vec![];
    for r in &rows {
        let bad = |_| invalid();
        let expires: Option<String> = r.try_get(4).map_err(bad)?;
        let by: Option<i64> = r.try_get(6).map_err(bad)?;
        items.push(format!(
            "{{\"id\":{},\"cidr\":{},\"action\":{},\"description\":{},\"expiresAt\":{},\"createdAt\":{},\"createdBy\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&text(r, 1)?),
            s(&text(r, 2)?),
            s(&text(r, 3)?),
            expires.map_or("null".to_owned(), |e| s(&e)),
            s(&text(r, 5)?),
            by.map_or("null".to_owned(), |b| b.to_string()),
        ));
    }
    Ok(done(format!(
        "{{\"limit\":{limit},\"offset\":{offset},\"rows\":[{}],\"total\":{total}}}",
        items.join(",")
    )))
}

/// `POST /admin/threat/ip-rules`: the row and Go's `ip_rule_create` audit row in one
/// transaction. `created_by` is the verified actor. A rolled-back outcome is Go's 500.
#[allow(clippy::too_many_arguments)]
pub async fn ip_rule_create(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    cidr: &str,
    action: &str,
    description: &str,
    expires: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let digest = format!(
        "threat.ip_rule.create:{}:{}:{}:{}",
        s(cidr),
        s(action),
        s(description),
        expires.map_or("null".to_owned(), s)
    );
    let expires = expires.map(str::to_owned);
    setjoin_pg::run_receipted_command(
        worker,
        command("threat.ip_rule.create"),
        &envelope(&auth, operation, &digest),
        &auth,
        deadline(),
        "SELECT rust_mailsec_ip_rule_create($2,$4,$5,$6,$7,$8) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[
            (&cidr, Type::TEXT),
            (&action, Type::TEXT),
            (&description, Type::TEXT),
            (&expires, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        super::first_i64,
    )
    .await
}

/// `DELETE /admin/threat/ip-rules/{id}`: `Committed(false)` is Go's 404.
pub async fn ip_rule_delete(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("threat.ip_rule.delete"),
        &envelope(&auth, operation, &format!("threat.ip_rule.delete:{id}")),
        &auth,
        deadline(),
        "SELECT rust_mailsec_ip_rule_delete($2,$4,$5) WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, bool>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}

/// `{"id":N}` of the create answer.
pub fn created_body(id: i64) -> String {
    done(format!("{{\"id\":{id}}}"))
}

// ---- net/netip.ParsePrefix, with Go's exact error text ----

fn quote(text: &str) -> String {
    setjoin_contracts::go_quote::quote(text.as_bytes())
}

fn addr_error(input: &str, msg: &str, at: Option<&str>) -> String {
    match at.filter(|a| !a.is_empty()) {
        Some(at) => format!("ParseAddr({}): {msg} (at {})", quote(input), quote(at)),
        None => format!("ParseAddr({}): {msg}", quote(input)),
    }
}

/// `parseIPv4Fields(in, off, end)`.
fn ipv4_fields(input: &str, off: usize, end: usize) -> Result<(), String> {
    let field = &input[off..end];
    let b = field.as_bytes();
    let (mut value, mut pos, mut digits) = (0u32, 0usize, 0usize);
    for i in 0..b.len() {
        match b[i] {
            b'0'..=b'9' => {
                if digits == 1 && value == 0 {
                    return Err(addr_error(
                        input,
                        "IPv4 field has octet with leading zero",
                        None,
                    ));
                }
                value = value * 10 + u32::from(b[i] - b'0');
                digits += 1;
                if value > 255 {
                    return Err(addr_error(input, "IPv4 field has value >255", None));
                }
            }
            b'.' => {
                if i == 0 || i == b.len() - 1 || b[i - 1] == b'.' {
                    return Err(addr_error(
                        input,
                        "IPv4 field must have at least one digit",
                        Some(&field[i..]),
                    ));
                }
                if pos == 3 {
                    return Err(addr_error(input, "IPv4 address too long", None));
                }
                pos += 1;
                value = 0;
                digits = 0;
            }
            _ => return Err(addr_error(input, "unexpected character", Some(&field[i..]))),
        }
    }
    if pos < 3 {
        return Err(addr_error(input, "IPv4 address too short", None));
    }
    Ok(())
}

/// `parseIPv6`; `Ok(true)` when the address carries a zone.
fn ipv6(input: &str) -> Result<bool, String> {
    let mut rest = input;
    let mut zone = "";
    if let Some(i) = rest.find('%') {
        zone = &rest[i + 1..];
        rest = &rest[..i];
        if zone.is_empty() {
            return Err(addr_error(input, "zone must be a non-empty string", None));
        }
    }
    let mut ellipsis: i64 = -1;
    if rest.starts_with("::") {
        ellipsis = 0;
        rest = &rest[2..];
        if rest.is_empty() {
            return Ok(!zone.is_empty());
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let b = rest.as_bytes();
        let (mut off, mut acc) = (0usize, 0u32);
        while off < b.len() {
            let digit = match b[off] {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'f' => c - b'a' + 10,
                c @ b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            acc = (acc << 4) + u32::from(digit);
            if off > 3 {
                return Err(addr_error(
                    input,
                    "each group must have 4 or less digits",
                    Some(rest),
                ));
            }
            if acc > 0xffff {
                return Err(addr_error(input, "IPv6 field has value >=2^16", Some(rest)));
            }
            off += 1;
        }
        if off == 0 {
            return Err(addr_error(
                input,
                "each colon-separated field must have at least one digit",
                Some(rest),
            ));
        }
        if off < b.len() && b[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return Err(addr_error(
                    input,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    Some(rest),
                ));
            }
            if i + 4 > 16 {
                return Err(addr_error(
                    input,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    Some(rest),
                ));
            }
            let mut end = input.len();
            if !zone.is_empty() {
                end -= zone.len() + 1;
            }
            ipv4_fields(input, end - rest.len(), end)?;
            rest = "";
            i += 4;
            break;
        }
        i += 2;
        rest = &rest[off..];
        if rest.is_empty() {
            break;
        }
        if !rest.starts_with(':') {
            return Err(addr_error(
                input,
                "unexpected character, want colon",
                Some(rest),
            ));
        } else if rest.len() == 1 {
            return Err(addr_error(
                input,
                "colon must be followed by more characters",
                Some(rest),
            ));
        }
        rest = &rest[1..];
        if rest.starts_with(':') {
            if ellipsis >= 0 {
                return Err(addr_error(input, "multiple :: in address", Some(rest)));
            }
            ellipsis = i as i64;
            rest = &rest[1..];
            if rest.is_empty() {
                break;
            }
        }
    }
    if !rest.is_empty() {
        return Err(addr_error(
            input,
            "trailing garbage after address",
            Some(rest),
        ));
    }
    if i < 16 {
        if ellipsis < 0 {
            return Err(addr_error(input, "address string too short", None));
        }
    } else if ellipsis >= 0 {
        return Err(addr_error(
            input,
            "the :: must expand to at least one field of zeros",
            None,
        ));
    }
    Ok(!zone.is_empty())
}

/// `netip.ParseAddr`: `(is_ipv6, has_zone)`.
fn parse_addr(input: &str) -> Result<(bool, bool), String> {
    for c in input.bytes() {
        match c {
            b'.' => return ipv4_fields(input, 0, input.len()).map(|()| (false, false)),
            b':' => return ipv6(input).map(|zone| (true, zone)),
            b'%' => return Err(addr_error(input, "missing IPv6 address", None)),
            _ => {}
        }
    }
    Err(addr_error(input, "unable to parse IP", None))
}

/// `netip.ParsePrefix`: `Err` carries Go's error text.
pub fn parse_prefix(input: &str) -> Result<(), String> {
    let wrap = |msg: &str| format!("netip.ParsePrefix({}): {msg}", quote(input));
    let Some(slash) = input.rfind('/') else {
        return Err(wrap("no '/'"));
    };
    let (v6, zone) = parse_addr(&input[..slash]).map_err(|e| wrap(&e))?;
    if v6 && zone {
        return Err(wrap("IPv6 zones cannot be present in a prefix"));
    }
    let bits_text = &input[slash + 1..];
    let bad_bits = || wrap(&format!("bad bits after slash: {}", quote(bits_text)));
    if bits_text.len() > 1 && !matches!(bits_text.as_bytes()[0], b'1'..=b'9') {
        return Err(bad_bits());
    }
    let Some(bits) = atoi(bits_text).filter(|_| bits_text.bytes().all(|b| b.is_ascii_digit()))
    else {
        return Err(bad_bits());
    };
    if bits < 0 || bits > if v6 { 128 } else { 32 } {
        return Err(wrap("prefix length out of range"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_errors_match_frozen_go() {
        let table: Vec<(String, Option<String>)> =
            serde_json::from_str(include_str!("../tests/netip_prefix.json")).expect("fixture");
        assert!(table.len() > 100);
        for (input, expected) in table {
            assert_eq!(parse_prefix(&input).err(), expected, "input {input:?}");
        }
    }

    #[test]
    fn page_follows_go() {
        assert_eq!(page("", ""), (100, 0));
        assert_eq!(page("9999", "-3"), (500, 0));
        assert_eq!(page("+7", "5"), (7, 5));
        assert_eq!(page("99999999999999999999", "x"), (100, 0));
        assert_eq!(page("0", "99999999999999999999"), (100, 0));
    }

    #[test]
    fn sort_columns_fold_like_go() {
        assert_eq!(sort_column(View::Attempts, "OUTCOME"), Some("outcome"));
        assert_eq!(
            sort_column(View::Attempts, "\u{17f}ource_ip"),
            Some("source_ip")
        );
        assert_eq!(sort_column(View::Attempts, "id"), None);
    }
}
