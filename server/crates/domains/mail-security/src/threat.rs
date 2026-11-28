//! Slice `threat` (#326): Go's `admin.ThreatHandler.View` (four read-only threat views, JSON
//! or CSV) and `admin.IPRulesHandler` (list, create, delete of admin-managed IP rules).
//!
//! Every route sits behind a console gate the adapter checks first: `requireLogsPerm`
//! (`audit.read`, organization-wide only) for the reads and `requireSecurityWrite` for the two
//! writes. Table views and IP rule reads run via `AdminReadTx`; IP rule creates and deletes
//! run via `AdminWriteTx` (`ReducerWritesCoreAudit`). The `lockouts` view uses the worker-only
//! `lockout_count` / `lockout_list` accessors (`WorkerBypass`) via the gateway composition root.
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, Row, StatementFailure};

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
    fn sort_columns(self) -> &'static [&'static str] {
        match self {
            View::Attempts => &["occurred_at", "source_ip", "outcome"],
            View::Lockouts => &["locked_until", "failed_count", "updated_at"],
            View::FeedBlocks => &["added_at", "source"],
            View::RateCounters => &["count", "window_start", "blocked_until"],
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

/// Resolved `(column, dir)` arguments for `lockout_list`.
pub fn lockout_sort(query: &Query<'_>) -> (&'static str, &'static str) {
    match sort_column(View::Lockouts, query.sort) {
        None => ("", ""),
        Some(column) => (
            column,
            if fold_eq(query.dir, "desc") {
                "desc"
            } else {
                "asc"
            },
        ),
    }
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

/// Format a row returned by `sql::THREAT_LOCKOUT_LIST`.
pub fn lockout_item(row: &Row) -> Result<Item, StatementFailure> {
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
        cells: vec![
            key,
            failed.to_string(),
            until_cell,
            level.to_string(),
            updated_cell,
        ],
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

/// The view's page and its total for the three `AdminRead` table views (`Attempts`,
/// `FeedBlocks`, `RateCounters`). `View::Lockouts` uses `sql::THREAT_LOCKOUT_*` (`WorkerBypass`).
pub async fn rows(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    view: View,
    query: &Query<'_>,
) -> Result<(Vec<Item>, i64), StatementFailure> {
    let desc = fold_eq(query.dir, "DESC");
    let col = sort_column(view, query.sort);
    match view {
        View::Attempts => {
            let total = factory
                .run_admin_read_contract(
                    admin,
                    &sql::THREAT_ATTEMPTS_COUNT,
                    &[&query.since, &query.q],
                )
                .await?
                .first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .ok_or_else(invalid)?;
            let contract = match (col, desc) {
                (None, _) | (Some("occurred_at"), true) => &sql::THREAT_ATTEMPTS_OCCURRED_AT_DESC,
                (Some("occurred_at"), false) => &sql::THREAT_ATTEMPTS_OCCURRED_AT_ASC,
                (Some("source_ip"), true) => &sql::THREAT_ATTEMPTS_SOURCE_IP_DESC,
                (Some("source_ip"), false) => &sql::THREAT_ATTEMPTS_SOURCE_IP_ASC,
                (Some("outcome"), true) => &sql::THREAT_ATTEMPTS_OUTCOME_DESC,
                (Some("outcome"), false) => &sql::THREAT_ATTEMPTS_OUTCOME_ASC,
                _ => &sql::THREAT_ATTEMPTS_OCCURRED_AT_DESC,
            };
            let rows = factory
                .run_admin_read_contract(
                    admin,
                    contract,
                    &[&query.since, &query.q, &query.limit, &query.offset],
                )
                .await?;
            Ok((rows.iter().filter_map(|r| attempt(r).ok()).collect(), total))
        }
        View::FeedBlocks => {
            let total = factory
                .run_admin_read_contract(admin, &sql::THREAT_FEED_BLOCKS_COUNT, &[&query.q])
                .await?
                .first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .ok_or_else(invalid)?;
            let contract = match (col, desc) {
                (None, _) | (Some("added_at"), true) => &sql::THREAT_FEED_BLOCKS_ADDED_AT_DESC,
                (Some("added_at"), false) => &sql::THREAT_FEED_BLOCKS_ADDED_AT_ASC,
                (Some("source"), true) => &sql::THREAT_FEED_BLOCKS_SOURCE_DESC,
                (Some("source"), false) => &sql::THREAT_FEED_BLOCKS_SOURCE_ASC,
                _ => &sql::THREAT_FEED_BLOCKS_ADDED_AT_DESC,
            };
            let rows = factory
                .run_admin_read_contract(admin, contract, &[&query.q, &query.limit, &query.offset])
                .await?;
            Ok((
                rows.iter().filter_map(|r| feed_block(r).ok()).collect(),
                total,
            ))
        }
        View::RateCounters => {
            let total = factory
                .run_admin_read_contract(admin, &sql::THREAT_RATE_COUNTERS_COUNT, &[&query.q])
                .await?
                .first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .ok_or_else(invalid)?;
            let contract = match (col, desc) {
                (None, _) | (Some("count"), true) => &sql::THREAT_RATE_COUNTERS_COUNT_DESC,
                (Some("count"), false) => &sql::THREAT_RATE_COUNTERS_COUNT_ASC,
                (Some("window_start"), true) => &sql::THREAT_RATE_COUNTERS_WINDOW_START_DESC,
                (Some("window_start"), false) => &sql::THREAT_RATE_COUNTERS_WINDOW_START_ASC,
                (Some("blocked_until"), true) => &sql::THREAT_RATE_COUNTERS_BLOCKED_UNTIL_DESC,
                (Some("blocked_until"), false) => &sql::THREAT_RATE_COUNTERS_BLOCKED_UNTIL_ASC,
                _ => &sql::THREAT_RATE_COUNTERS_COUNT_DESC,
            };
            let rows = factory
                .run_admin_read_contract(admin, contract, &[&query.q, &query.limit, &query.offset])
                .await?;
            Ok((
                rows.iter().filter_map(|r| rate_counter(r).ok()).collect(),
                total,
            ))
        }
        View::Lockouts => Err(invalid()),
    }
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let total = factory
        .run_admin_read_contract(admin, &sql::THREAT_IP_RULES_COUNT, &[])
        .await?
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)?;
    let rows = factory
        .run_admin_read_contract(admin, &sql::THREAT_IP_RULES_LIST, &[&limit, &offset])
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    cidr: &str,
    action: &str,
    description: &str,
    expires: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let digest = format!(
        "threat.ip_rule.create:{}:{}:{}:{}",
        s(cidr),
        s(action),
        s(description),
        expires.map_or("null".to_owned(), s)
    );
    let expires = expires.map(str::to_owned);
    let env = envelope(admin.actor(), admin.generation(), operation, &digest);
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::THREAT_IP_RULE_CREATE,
            &[&cidr, &action, &description, &expires, &ip],
            Some(command("threat.ip_rule.create")),
            |rows, _| super::first_i64(&rows),
        )
        .await
}

/// `DELETE /admin/threat/ip-rules/{id}`: `Committed(false)` is Go's 404.
pub async fn ip_rule_delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("threat.ip_rule.delete:{id}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::THREAT_IP_RULE_DELETE,
            &[&id, &ip],
            Some(command("threat.ip_rule.delete")),
            |rows, _| {
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
