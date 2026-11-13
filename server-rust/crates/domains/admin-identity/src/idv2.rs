//! Admin identity (F01) slice `idv2-sources`: the identity v2 list and detail reads
//! (sources, people, conflicts, events). Go serves these on its worker pool with
//! `identity_*` reducers and plain `SELECT`s; every statement here is a read, so the
//! reads run on the executor the caller passes (the worker credential in production).
//!
//! Wire shapes follow `encoding/json` over `map[string]any`: keys sorted, compact,
//! HTML-escaped, `time.Time` as RFC 3339 with trimmed fractions, `json.RawMessage`
//! compacted. List cursors are Go's opaque base64url JSON, bound to the actor, the
//! domain scope and the filters, and expire after 15 minutes.
use super::{invalid, nano, s};
use base64::Engine as _;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
use sha2::{Digest as _, Sha256};

pub const LIST_DEFAULT: usize = 100;
pub const LIST_MAX: usize = 500;
const FILTER_MAX: usize = 256;
const CURSOR_MAX: usize = 4096;
const CURSOR_TTL: i64 = 15 * 60;

/// What a list resource accepts (`identityListSpec`).
pub struct Spec {
    pub resource: &'static str,
    pub default_sort: &'static str,
    /// Filters beyond `filter` and `source`: only `state`, with its enum.
    pub state: Option<&'static [&'static str]>,
    /// Byte bound of the `state` filter (`filterBounds["state"]`).
    pub state_max: usize,
}
pub const SOURCES: Spec = Spec {
    resource: "sources",
    default_sort: "sourceKey",
    state: Some(&["draft", "validated", "active", "paused", "error", "retired"]),
    state_max: 16,
};
pub const PEOPLE: Spec = Spec {
    resource: "people",
    default_sort: "userId",
    state: Some(&["enabled", "disabled"]),
    state_max: 16,
};
pub const CONFLICTS: Spec = Spec {
    resource: "conflicts",
    default_sort: "-createdAt",
    state: Some(&["pending", "deferred"]),
    state_max: 16,
};
pub const EVENTS: Spec = Spec {
    resource: "events",
    default_sort: "-occurredAt",
    state: None,
    state_max: 16,
};
pub const TRANSITIONS: Spec = Spec {
    resource: "transitions",
    default_sort: "-createdAt",
    state: Some(&[
        "draft",
        "previewed",
        "awaiting_approval",
        "authorized",
        "executing",
        "authority_committed",
        "effects_pending",
        "completed",
        "failed_precommit",
        "failed_recoverable",
        "rollback_previewed",
        "rolling_back",
        "rolled_back",
        "cancelled",
        "expired",
    ]),
    state_max: 32,
};

/// Go's `identityListCursor`; absent fields keep their zero value.
#[derive(Default, Clone)]
pub struct Cursor {
    pub version: i64,
    pub resource: String,
    pub binding: String,
    pub expires: i64,
    pub text: String,
    pub number: i64,
    pub time: String,
    pub id: String,
}

pub struct Opts {
    pub limit: usize,
    pub filter: String,
    pub source: String,
    pub state: String,
    pub binding: String,
    pub cursor: Cursor,
    pub had_cursor: bool,
}

/// A refusal rendered as Go's bare problem (`WriteProblemStatus`).
pub struct Refusal {
    pub status: u16,
    pub detail: String,
    /// A known reducer refusal (`reducererr.WriteClassified`): code and remediation.
    pub reducer: Option<(String, String)>,
}
fn refuse(status: u16, detail: &str) -> Refusal {
    Refusal {
        status,
        detail: detail.to_owned(),
        reducer: None,
    }
}

/// One query pair as Go's `url.Values` holds it. Go keeps raw bytes; names and
/// values are read here lossily, which no accepted name, enum, key, number or
/// base64 cursor can equal, and `raw_len`/`invalid` keep what the lossy text loses.
struct Pair {
    name: String,
    value: String,
    /// Byte length of the unescaped value (Go's `len`).
    raw_len: usize,
    /// The value is not UTF-8.
    invalid: bool,
}

/// Go's `url.Values` for a raw query: pairs with a `;` or a bad escape are dropped,
/// `+` is a space.
fn query_pairs(raw: &str) -> Vec<Pair> {
    let mut out = Vec::new();
    for part in raw.split('&') {
        if part.is_empty() || part.contains(';') {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let (Some(key), Some(value)) = (unescape(key), unescape(value)) else {
            continue;
        };
        out.push(Pair {
            name: String::from_utf8_lossy(&key).into_owned(),
            raw_len: value.len(),
            invalid: std::str::from_utf8(&value).is_err(),
            value: String::from_utf8_lossy(&value).into_owned(),
        });
    }
    out
}
/// `url.Values.Get` for every name: the first value (non-UTF-8 values read lossily).
pub fn query_first(raw: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for pair in query_pairs(raw) {
        out.entry(pair.name).or_insert(pair.value);
    }
    out
}
fn unescape(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Go's `validIdentitySourceKey`.
pub fn valid_source_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 64 {
        return false;
    }
    for (index, c) in key.chars().enumerate() {
        if index == 0 && !c.is_ascii_alphanumeric() {
            return false;
        }
        if !c.is_ascii_alphanumeric() && !matches!(c, ':' | '-' | '_' | '.') {
            return false;
        }
    }
    true
}

/// `parseIdentityListOptions`. A non-UTF-8 value is read as Go reads it: only `filter`
/// can carry one past the checks, and the database then refuses it.
pub fn parse_list(
    raw_query: &str,
    spec: &Spec,
    actor: i64,
    domain_scope: i64,
    now: i64,
) -> Result<Opts, Refusal> {
    let pairs = query_pairs(raw_query);
    let mut allowed = vec!["cursor", "limit", "sort", "filter", "source"];
    if spec.state.is_some() {
        allowed.push("state");
    }
    // A name given twice, or one that is not accepted, is refused.
    for (index, Pair { name, .. }) in pairs.iter().enumerate() {
        if !allowed.contains(&name.as_str()) || pairs[..index].iter().any(|p| &p.name == name) {
            return Err(refuse(
                400,
                "unsupported or repeated identity list query parameter",
            ));
        }
    }
    let pair = |name: &str| pairs.iter().find(|p| p.name == name);
    let get = |name: &str| pair(name).map(|p| p.value.clone()).unwrap_or_default();
    let raw_len = |name: &str| pair(name).map_or(0, |p| p.raw_len);
    let (mut filter, source, state, sort) =
        (get("filter"), get("source"), get("state"), get("sort"));
    let filter_invalid = pair("filter").is_some_and(|p| p.invalid);
    let sort = if sort.is_empty() {
        spec.default_sort.to_owned()
    } else {
        sort
    };
    if sort != spec.default_sort {
        return Err(refuse(400, "unsupported identity list sort"));
    }
    let mut limit = LIST_DEFAULT;
    let raw_limit = get("limit");
    if !raw_limit.is_empty() {
        match raw_limit.parse::<i64>() {
            Ok(n) if (1..=LIST_MAX as i64).contains(&n) => limit = n as usize,
            _ => return Err(refuse(400, "identity list limit must be between 1 and 500")),
        }
    }
    let mut bounds = vec![("filter", FILTER_MAX, &filter), ("source", 64, &source)];
    if spec.state.is_some() {
        bounds.push(("state", spec.state_max, &state));
    }
    for (name, max, value) in bounds {
        if raw_len(name) > max {
            return Err(Refusal {
                status: 400,
                detail: format!("identity list {name} exceeds {max} bytes"),
                reducer: None,
            });
        }
        if name == "state" && !value.is_empty() {
            if let Some(allowed) = spec.state {
                if !allowed.contains(&value.as_str()) {
                    return Err(refuse(400, "unsupported identity list state"));
                }
            }
        }
    }
    if !source.is_empty() && !valid_source_key(&source) {
        return Err(refuse(400, "invalid identity source filter"));
    }
    // Go sends a non-UTF-8 filter to PostgreSQL, which refuses the parameter (the
    // handler's "query failed" answer). A NUL never reaches the server either, so it
    // stands for those bytes and fails the same way in the list query.
    if filter_invalid {
        filter = "\u{0}".to_owned();
    }
    let material = format!(
        "v1\n{}\n{actor}\n{domain_scope}\n{sort}\n{filter}\n{source}\n{state}",
        spec.resource
    );
    let binding = hex(&Sha256::digest(material.as_bytes()));
    let mut opts = Opts {
        limit,
        filter,
        source,
        state,
        binding,
        cursor: Cursor::default(),
        had_cursor: false,
    };
    let raw_cursor = get("cursor");
    if raw_cursor.is_empty() {
        return Ok(opts);
    }
    opts.had_cursor = true;
    let bad_cursor = || refuse(400, "invalid identity list cursor");
    if raw_len("cursor") > CURSOR_MAX {
        return Err(bad_cursor());
    }
    // Go's base64 decoder skips CR and LF and ignores non-zero trailing bits.
    let stripped: String = raw_cursor
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .collect();
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    let decoded = engine.decode(stripped).map_err(|_| bad_cursor())?;
    let mut stream = serde_json::Deserializer::from_slice(&decoded).into_iter::<CursorWire>();
    let Some(Ok(CursorWire(cursor))) = stream.next() else {
        return Err(bad_cursor());
    };
    // Anything after the first value, other than whitespace, is refused.
    if decoded[stream.byte_offset()..]
        .iter()
        .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err(bad_cursor());
    }
    if cursor.version != 1 || cursor.resource != spec.resource || cursor.binding != opts.binding {
        return Err(refuse(
            400,
            "identity list cursor does not match the requested filters",
        ));
    }
    if cursor.expires <= now {
        return Err(refuse(410, "identity list cursor has expired"));
    }
    opts.cursor = cursor;
    Ok(opts)
}

/// Go's `json.Decoder` with `DisallowUnknownFields` over `identityListCursor`:
/// case-folded names, `null` keeps the zero value, wrong types fail.
struct CursorWire(Cursor);
impl<'de> serde::Deserialize<'de> for CursorWire {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = CursorWire;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a cursor object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<CursorWire, E> {
                Ok(CursorWire(Cursor::default()))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<CursorWire, M::Error> {
                let mut c = Cursor::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::fold(&key).as_str() {
                        "v" => {
                            if let Some(x) = map.next_value::<Option<i64>>()? {
                                c.version = x;
                            }
                        }
                        "resource" => {
                            if let Some(x) = map.next_value::<Option<String>>()? {
                                c.resource = x;
                            }
                        }
                        "binding" => {
                            if let Some(x) = map.next_value::<Option<String>>()? {
                                c.binding = x;
                            }
                        }
                        "expires" => {
                            if let Some(x) = map.next_value::<Option<i64>>()? {
                                c.expires = x;
                            }
                        }
                        "text" => {
                            if let Some(x) = map.next_value::<Option<String>>()? {
                                c.text = x;
                            }
                        }
                        "number" => {
                            if let Some(x) = map.next_value::<Option<i64>>()? {
                                c.number = x;
                            }
                        }
                        "time" => {
                            if let Some(x) = map.next_value::<Option<String>>()? {
                                c.time = x;
                            }
                        }
                        "id" => {
                            if let Some(x) = map.next_value::<Option<String>>()? {
                                c.id = x;
                            }
                        }
                        _ => return Err(serde::de::Error::custom("unknown field")),
                    }
                }
                Ok(CursorWire(c))
            }
        }
        decoder.deserialize_any(Fields)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `encodeIdentityListCursor`: the struct's field order, zero fields omitted.
pub fn encode_cursor(resource: &str, binding: &str, now: i64, c: &Cursor) -> String {
    let mut text = format!(
        "{{\"v\":1,\"resource\":{},\"binding\":{},\"expires\":{}",
        s(resource),
        s(binding),
        now + CURSOR_TTL
    );
    if !c.text.is_empty() {
        text.push_str(&format!(",\"text\":{}", s(&c.text)));
    }
    if c.number != 0 {
        text.push_str(&format!(",\"number\":{}", c.number));
    }
    if !c.time.is_empty() {
        text.push_str(&format!(",\"time\":{}", s(&c.time)));
    }
    if !c.id.is_empty() {
        text.push_str(&format!(",\"id\":{}", s(&c.id)));
    }
    text.push('}');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::go_escape(&text))
}

/// `json.Compact` with HTML escaping, for a `json.RawMessage` inside a map.
pub fn compact(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in raw.chars() {
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

fn text_or_null(value: Option<String>) -> String {
    value.map(|v| s(&v)).unwrap_or_else(|| "null".into())
}

/// Go's `time.Parse(time.RFC3339Nano, text)` for a cursor time; the canonical
/// form (UTC, microseconds) is returned, `None` when Go would refuse it.
pub fn parse_rfc3339(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<i64> {
        let part = text.get(from..from + len)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + i64::from(leap),
        _ => return None,
    };
    if day < 1 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut at = 19;
    let mut fraction = String::new();
    if b[at] == b'.' {
        let start = at + 1;
        let mut end = start;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end == start || end - start > 9 {
            return None;
        }
        fraction = text[start..end].to_owned();
        at = end;
    }
    let zone = text.get(at..)?;
    let valid_zone = zone == "Z"
        || (zone.len() == 6
            && matches!(zone.as_bytes()[0], b'+' | b'-')
            && zone.as_bytes()[3] == b':'
            && zone[1..3].bytes().all(|c| c.is_ascii_digit())
            && zone[4..6].bytes().all(|c| c.is_ascii_digit())
            && zone[1..3].parse::<i64>().ok()? <= 23
            && zone[4..6].parse::<i64>().ok()? <= 59);
    if !valid_zone {
        return None;
    }
    // pgx sends microseconds: keep six fractional digits.
    fraction.truncate(6);
    let fraction = if fraction.is_empty() {
        String::new()
    } else {
        format!(".{fraction}")
    };
    Some(format!("{}T{}{fraction}{zone}", &text[..10], &text[11..19]))
}

/// Go's `uuid.Parse`: 36 hyphenated, 32 hex, braced or `urn:uuid:` forms.
pub fn parse_uuid(text: &str) -> Option<String> {
    let inner = match text.len() {
        36 => text,
        38 if text.starts_with('{') && text.ends_with('}') => &text[1..37],
        45 if text.get(..9)?.eq_ignore_ascii_case("urn:uuid:") => &text[9..],
        32 => {
            return text.bytes().all(|c| c.is_ascii_hexdigit()).then(|| {
                format!(
                    "{}-{}-{}-{}-{}",
                    &text[0..8],
                    &text[8..12],
                    &text[12..16],
                    &text[16..20],
                    &text[20..32]
                )
            });
        }
        _ => return None,
    };
    let b = inner.as_bytes();
    let dashes = [8usize, 13, 18, 23];
    let ok = b.iter().enumerate().all(|(i, c)| {
        if dashes.contains(&i) {
            *c == b'-'
        } else {
            c.is_ascii_hexdigit()
        }
    });
    ok.then(|| inner.to_ascii_lowercase())
}

/// One page of a list: the encoded body and nothing else (the adapter adds the
/// ETag). `Err` carries Go's bare problem.
pub type Page = Result<String, Refusal>;

fn failed(detail: &str) -> Refusal {
    refuse(500, detail)
}

fn page(items: Vec<String>, more: Option<String>) -> String {
    match more {
        Some(cursor) => format!(
            "{{\"items\":[{}],\"nextCursor\":{}}}",
            items.join(","),
            s(&cursor)
        ),
        None => format!("{{\"items\":[{}]}}", items.join(",")),
    }
}

/// `GET /admin/identity/v2/sources`.
pub async fn sources(
    exec: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    opts: &Opts,
    now: i64,
) -> Page {
    if opts.had_cursor && opts.cursor.text.is_empty() {
        return Err(refuse(400, "invalid identity list cursor"));
    }
    let sql = format!(
        "SELECT source_key,display_name,kind,state,generation,mapping_version,capabilities::text,{},{},last_error_code,\
         committed_cursor IS NOT NULL,\
         (SELECT count(*) FROM identity_source_inbox i WHERE i.source_id=s.id AND i.state IN ('pending','quarantined')) \
         FROM identity_sources s \
         WHERE ($2::bigint = 0 OR EXISTS (SELECT 1 FROM user_identity_links scoped_link WHERE scoped_link.source_id=s.id AND admin_can_reach($1,scoped_link.user_id))) \
         AND ($3::text = '' OR s.source_key ILIKE '%' || $3 || '%' OR s.display_name ILIKE '%' || $3 || '%') \
         AND ($4::text = '' OR s.source_key=$4) \
         AND ($5::text = '' OR s.state=$5) \
         AND ($6::text = '' OR s.source_key>$6) \
         ORDER BY s.source_key LIMIT $7",
        nano("last_success_at"),
        nano("last_failure_at")
    );
    let limit = opts.limit as i64 + 1;
    let rows = exec
        .read(
            &sql,
            &[
                (&actor, Type::INT8),
                (&domain_scope, Type::INT8),
                (&opts.filter, Type::TEXT),
                (&opts.source, Type::TEXT),
                (&opts.state, Type::TEXT),
                (&opts.cursor.text, Type::TEXT),
                (&limit, Type::INT8),
            ],
        )
        .await
        .map_err(|_| failed("identity source query failed"))?;
    let mut items = Vec::new();
    let mut keys = Vec::new();
    for row in &rows {
        let decode = || -> Result<(String, String), StatementFailure> {
            let key = row.try_get::<_, String>(0).map_err(|_| invalid())?;
            let item = format!(
                "{{\"attentionCount\":{},\"capabilities\":{},\"displayName\":{},\"generation\":\"{}\",\"hasCursor\":{},\"kind\":{},\"lastErrorCode\":{},\"lastFailureAt\":{},\"lastSuccessAt\":{},\"mappingVersion\":\"{}\",\"sourceKey\":{},\"state\":{}}}",
                row.try_get::<_, i64>(11).map_err(|_| invalid())?,
                compact(&row.try_get::<_, String>(6).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
                row.try_get::<_, i64>(4).map_err(|_| invalid())?,
                row.try_get::<_, bool>(10).map_err(|_| invalid())?,
                s(&row.try_get::<_, String>(2).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(9).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(8).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(7).map_err(|_| invalid())?),
                row.try_get::<_, i64>(5).map_err(|_| invalid())?,
                s(&key),
                s(&row.try_get::<_, String>(3).map_err(|_| invalid())?),
            );
            Ok((key, item))
        };
        let (key, item) = decode().map_err(|_| failed("identity source decode failed"))?;
        keys.push(key);
        items.push(item);
    }
    let more = (items.len() > opts.limit).then(|| {
        items.truncate(opts.limit);
        let cursor = Cursor {
            text: keys[opts.limit - 1].clone(),
            ..Cursor::default()
        };
        encode_cursor("sources", &opts.binding, now, &cursor)
    });
    Ok(page(items, more))
}

/// `GET /admin/identity/v2/people`.
pub async fn people(exec: &ScopedExecutor, actor: i64, opts: &Opts, now: i64) -> Page {
    if opts.had_cursor && opts.cursor.number <= 0 {
        return Err(refuse(400, "invalid identity list cursor"));
    }
    let sql = "SELECT u.id,u.email,u.display_name,u.enabled,a.authority_kind,s.source_key,\
         (count(l.id) FILTER (WHERE l.state='active')::integer)::bigint,\
         (count(l.id) FILTER (WHERE l.state='detached')::integer)::bigint \
         FROM users u \
         JOIN user_lifecycle_authorities a ON a.user_id=u.id \
         LEFT JOIN user_identity_links al ON al.id=a.link_id \
         LEFT JOIN identity_sources s ON s.id=al.source_id \
         LEFT JOIN user_identity_links l ON l.user_id=u.id \
         WHERE NOT is_guest_account(u.id) AND admin_can_reach($1,u.id) \
         AND ($2::text = '' OR u.email ILIKE '%' || $2 || '%' OR COALESCE(u.display_name,'') ILIKE '%' || $2 || '%') \
         AND ($3::text = '' OR s.source_key=$3) \
         AND ($4::text = '' OR ($4='enabled' AND u.enabled) OR ($4='disabled' AND NOT u.enabled)) \
         AND ($5::bigint = 0 OR u.id>$5) \
         GROUP BY u.id,u.email,u.display_name,u.enabled,a.authority_kind,s.source_key \
         ORDER BY u.id LIMIT $6";
    let limit = opts.limit as i64 + 1;
    let rows = exec
        .read(
            sql,
            &[
                (&actor, Type::INT8),
                (&opts.filter, Type::TEXT),
                (&opts.source, Type::TEXT),
                (&opts.state, Type::TEXT),
                (&opts.cursor.number, Type::INT8),
                (&limit, Type::INT8),
            ],
        )
        .await
        .map_err(|_| failed("identity people query failed"))?;
    let mut items = Vec::new();
    let mut ids = Vec::new();
    for row in &rows {
        let decode = || -> Result<(i64, String), StatementFailure> {
            let id = row.try_get::<_, i64>(0).map_err(|_| invalid())?;
            let item = format!(
                "{{\"activeLinks\":{},\"detachedLinks\":{},\"displayName\":{},\"email\":{},\"enabled\":{},\"lifecycleAuthority\":{},\"sourceKey\":{},\"userId\":\"{id}\"}}",
                row.try_get::<_, i64>(6).map_err(|_| invalid())?,
                row.try_get::<_, i64>(7).map_err(|_| invalid())?,
                text_or_null(row.try_get::<_, Option<String>>(2).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
                row.try_get::<_, bool>(3).map_err(|_| invalid())?,
                s(&row.try_get::<_, String>(4).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(5).map_err(|_| invalid())?),
            );
            Ok((id, item))
        };
        let (id, item) = decode().map_err(|_| failed("identity people decode failed"))?;
        ids.push(id);
        items.push(item);
    }
    let more = (items.len() > opts.limit).then(|| {
        items.truncate(opts.limit);
        let cursor = Cursor {
            number: ids[opts.limit - 1],
            ..Cursor::default()
        };
        encode_cursor("people", &opts.binding, now, &cursor)
    });
    Ok(page(items, more))
}

/// `GET /admin/identity/v2/conflicts`.
pub async fn conflicts(
    exec: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    opts: &Opts,
    now: i64,
) -> Page {
    let (mut cursor_time, mut cursor_id): (Option<String>, Option<String>) = (None, None);
    if !opts.cursor.time.is_empty() || !opts.cursor.id.is_empty() {
        let (Some(time), Some(id)) = (
            parse_rfc3339(&opts.cursor.time),
            parse_uuid(&opts.cursor.id),
        ) else {
            return Err(refuse(400, "invalid identity list cursor"));
        };
        cursor_time = Some(time);
        cursor_id = Some(id);
    }
    let sql = format!(
        "SELECT c.id::text,s.source_key,c.evidence_class,c.status,c.generation,{},{},c.redacted_explanation,{} \
         FROM identity_match_candidates c JOIN identity_sources s ON s.id=c.source_id \
         WHERE c.status IN ('pending','deferred') \
         AND (($2::bigint = 0 AND c.candidate_user_id IS NULL) OR (c.candidate_user_id IS NOT NULL AND admin_can_reach($1,c.candidate_user_id))) \
         AND ($3::text = '' OR c.redacted_explanation ILIKE '%' || $3 || '%' OR c.evidence_class ILIKE '%' || $3 || '%') \
         AND ($4::text = '' OR s.source_key=$4) \
         AND ($5::text = '' OR c.status=$5) \
         AND ($6::text IS NULL OR (c.created_at,c.id)<($6::text::timestamptz,$7::text::uuid)) \
         ORDER BY c.created_at DESC,c.id DESC LIMIT $8",
        nano("c.created_at"),
        nano("c.expires_at"),
        "to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
    );
    let limit = opts.limit as i64 + 1;
    let rows = exec
        .read(
            &sql,
            &[
                (&actor, Type::INT8),
                (&domain_scope, Type::INT8),
                (&opts.filter, Type::TEXT),
                (&opts.source, Type::TEXT),
                (&opts.state, Type::TEXT),
                (&cursor_time, Type::TEXT),
                (&cursor_id, Type::TEXT),
                (&limit, Type::INT8),
            ],
        )
        .await
        .map_err(|_| failed("identity conflict query failed"))?;
    let mut items = Vec::new();
    let mut last: Vec<(String, String)> = Vec::new();
    for row in &rows {
        let decode = || -> Result<(String, String, String), StatementFailure> {
            let id = row.try_get::<_, String>(0).map_err(|_| invalid())?;
            let created = row.try_get::<_, String>(5).map_err(|_| invalid())?;
            let item = format!(
                "{{\"createdAt\":{},\"evidenceClass\":{},\"expiresAt\":{},\"explanation\":{},\"generation\":\"{}\",\"id\":{},\"sourceKey\":{},\"state\":{}}}",
                s(&created),
                s(&row.try_get::<_, String>(2).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(6).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(7).map_err(|_| invalid())?),
                row.try_get::<_, i64>(4).map_err(|_| invalid())?,
                s(&id),
                s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(3).map_err(|_| invalid())?),
            );
            // The cursor time is Go's `UTC().Format(RFC3339Nano)`: trimmed fraction.
            Ok((
                id,
                item,
                row.try_get::<_, String>(8).map_err(|_| invalid())?,
            ))
        };
        let (id, item, precise) =
            decode().map_err(|_| failed("identity conflict decode failed"))?;
        last.push((id, trim_fraction(&precise)));
        items.push(item);
    }
    let more = (items.len() > opts.limit).then(|| {
        items.truncate(opts.limit);
        let (id, time) = last[opts.limit - 1].clone();
        let cursor = Cursor {
            time,
            id,
            ..Cursor::default()
        };
        encode_cursor("conflicts", &opts.binding, now, &cursor)
    });
    Ok(page(items, more))
}

/// `2026-01-01T00:00:00.120000Z` as Go's RFC3339Nano prints it.
fn trim_fraction(text: &str) -> String {
    let Some(body) = text.strip_suffix('Z') else {
        return text.to_owned();
    };
    match body.split_once('.') {
        Some((head, fraction)) => {
            let fraction = fraction.trim_end_matches('0');
            if fraction.is_empty() {
                format!("{head}Z")
            } else {
                format!("{head}.{fraction}Z")
            }
        }
        None => text.to_owned(),
    }
}

/// `GET /admin/identity/v2/events`.
pub async fn events(
    exec: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    opts: &Opts,
    now: i64,
) -> Page {
    let (mut cursor_time, mut cursor_id): (Option<String>, i64) = (None, 0);
    if !opts.cursor.time.is_empty() || opts.cursor.number != 0 {
        let Some(time) = parse_rfc3339(&opts.cursor.time) else {
            return Err(refuse(400, "invalid identity list cursor"));
        };
        if opts.cursor.number <= 0 {
            return Err(refuse(400, "invalid identity list cursor"));
        }
        cursor_time = Some(time);
        cursor_id = opts.cursor.number;
    }
    let sql = format!(
        "SELECT e.id::text,{},e.user_id::text,s.source_key,e.link_id::text,e.transition_id::text,e.action,e.reason,\
         e.correlation_id::text,e.metadata::text,to_char(e.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM identity_link_events e LEFT JOIN identity_sources s ON s.id=e.source_id \
         WHERE (($2::bigint = 0 AND e.user_id IS NULL) OR (e.user_id IS NOT NULL AND admin_can_reach($1,e.user_id))) \
         AND ($3::text = '' OR e.action ILIKE '%' || $3 || '%' OR COALESCE(s.source_key,'') ILIKE '%' || $3 || '%') \
         AND ($4::text = '' OR s.source_key=$4) \
         AND ($5::text IS NULL OR (e.occurred_at,e.id)<($5::text::timestamptz,$6::bigint)) \
         ORDER BY e.occurred_at DESC,e.id DESC LIMIT $7",
        nano("e.occurred_at")
    );
    let limit = opts.limit as i64 + 1;
    let rows = exec
        .read(
            &sql,
            &[
                (&actor, Type::INT8),
                (&domain_scope, Type::INT8),
                (&opts.filter, Type::TEXT),
                (&opts.source, Type::TEXT),
                (&cursor_time, Type::TEXT),
                (&cursor_id, Type::INT8),
                (&limit, Type::INT8),
            ],
        )
        .await
        .map_err(|_| failed("identity event query failed"))?;
    let mut items = Vec::new();
    let mut last: Vec<(i64, String)> = Vec::new();
    for row in &rows {
        let decode = || -> Result<(i64, String, String), StatementFailure> {
            let id = row.try_get::<_, String>(0).map_err(|_| invalid())?;
            let number = id.parse::<i64>().map_err(|_| invalid())?;
            let item = format!(
                "{{\"action\":{},\"correlationId\":{},\"id\":{},\"linkId\":{},\"metadata\":{},\"occurredAt\":{},\"reason\":{},\"sourceKey\":{},\"transitionId\":{},\"userId\":{}}}",
                s(&row.try_get::<_, String>(6).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(8).map_err(|_| invalid())?),
                s(&id),
                text_or_null(row.try_get::<_, Option<String>>(4).map_err(|_| invalid())?),
                compact(&row.try_get::<_, String>(9).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(7).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(3).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(5).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(2).map_err(|_| invalid())?),
            );
            Ok((
                number,
                item,
                row.try_get::<_, String>(10).map_err(|_| invalid())?,
            ))
        };
        let (number, item, precise) =
            decode().map_err(|_| failed("identity event decode failed"))?;
        last.push((number, trim_fraction(&precise)));
        items.push(item);
    }
    let more = (items.len() > opts.limit).then(|| {
        items.truncate(opts.limit);
        let (number, time) = last[opts.limit - 1].clone();
        let cursor = Cursor {
            time,
            number,
            ..Cursor::default()
        };
        encode_cursor("events", &opts.binding, now, &cursor)
    });
    Ok(page(items, more))
}

/// `GET /admin/identity/v2/transitions`.
pub async fn transitions(exec: &ScopedExecutor, actor: i64, opts: &Opts, now: i64) -> Page {
    let (mut cursor_time, mut cursor_id): (Option<String>, Option<String>) = (None, None);
    if !opts.cursor.time.is_empty() || !opts.cursor.id.is_empty() {
        let (Some(time), Some(id)) = (
            parse_rfc3339(&opts.cursor.time),
            parse_uuid(&opts.cursor.id),
        ) else {
            return Err(refuse(400, "invalid identity list cursor"));
        };
        cursor_time = Some(time);
        cursor_id = Some(id);
    }
    let sql = format!(
        "SELECT t.id::text,t.user_id::text,t.kind,t.state,s.source_key,t.protected,t.reason,t.failure_code,{},{},\
         (count(e.effect_kind) FILTER (WHERE e.state<>'completed')::integer)::bigint,\
         to_char(t.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM identity_transitions t \
         JOIN identity_sources s ON s.id=t.source_id \
         LEFT JOIN identity_transition_effects e ON e.transition_id=t.id \
         WHERE admin_can_reach($1,t.user_id) \
         AND ($2::text = '' OR t.kind ILIKE '%' || $2 || '%' OR t.state ILIKE '%' || $2 || '%' OR s.source_key ILIKE '%' || $2 || '%') \
         AND ($3::text = '' OR s.source_key=$3) \
         AND ($4::text = '' OR t.state=$4) \
         AND ($5::text IS NULL OR (t.created_at,t.id)<($5::text::timestamptz,$6::text::uuid)) \
         GROUP BY t.id,s.source_key \
         ORDER BY t.created_at DESC,t.id DESC LIMIT $7",
        nano("t.created_at"),
        nano("t.updated_at"),
    );
    let limit = opts.limit as i64 + 1;
    let rows = exec
        .read(
            &sql,
            &[
                (&actor, Type::INT8),
                (&opts.filter, Type::TEXT),
                (&opts.source, Type::TEXT),
                (&opts.state, Type::TEXT),
                (&cursor_time, Type::TEXT),
                (&cursor_id, Type::TEXT),
                (&limit, Type::INT8),
            ],
        )
        .await
        .map_err(|_| failed("identity transition query failed"))?;
    let mut items = Vec::new();
    let mut last: Vec<(String, String)> = Vec::new();
    for row in &rows {
        let decode = || -> Result<(String, String, String), StatementFailure> {
            let id = row.try_get::<_, String>(0).map_err(|_| invalid())?;
            let item = format!(
                "{{\"createdAt\":{},\"failureCode\":{},\"id\":{},\"kind\":{},\"pendingEffects\":{},\"protected\":{},\"reason\":{},\"sourceKey\":{},\"state\":{},\"updatedAt\":{},\"userId\":{}}}",
                s(&row.try_get::<_, String>(8).map_err(|_| invalid())?),
                text_or_null(row.try_get::<_, Option<String>>(7).map_err(|_| invalid())?),
                s(&id),
                s(&row.try_get::<_, String>(2).map_err(|_| invalid())?),
                row.try_get::<_, i64>(10).map_err(|_| invalid())?,
                row.try_get::<_, bool>(5).map_err(|_| invalid())?,
                s(&row.try_get::<_, String>(6).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(4).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(3).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(9).map_err(|_| invalid())?),
                s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
            );
            Ok((
                id,
                item,
                row.try_get::<_, String>(11).map_err(|_| invalid())?,
            ))
        };
        let (id, item, precise) =
            decode().map_err(|_| failed("identity transition decode failed"))?;
        last.push((id, trim_fraction(&precise)));
        items.push(item);
    }
    let more = (items.len() > opts.limit).then(|| {
        items.truncate(opts.limit);
        let (id, time) = last[opts.limit - 1].clone();
        let cursor = Cursor {
            time,
            id,
            ..Cursor::default()
        };
        encode_cursor("transitions", &opts.binding, now, &cursor)
    });
    Ok(page(items, more))
}

/// `GET /admin/identity/v2/people/{id}`: `identity_person_read`'s JSON verbatim;
/// `None` is Go's 404 (NULL result).
pub async fn person(exec: &ScopedExecutor, actor: i64, id: i64) -> Result<Option<String>, Refusal> {
    let rows = exec
        .read(
            "SELECT identity_person_read($1,$2)::text",
            &[(&actor, Type::INT8), (&id, Type::INT8)],
        )
        .await
        .map_err(|_| failed("identity person read failed"))?;
    let row = rows
        .first()
        .ok_or_else(|| failed("identity person read failed"))?;
    row.try_get::<_, Option<String>>(0)
        .map_err(|_| failed("identity person read failed"))
}

/// `GET /admin/identity/v2/conflicts/{id}`: redacted evidence and decision history,
/// the jsonb text verbatim; `None` is Go's 404 (no row, or the candidate's user is
/// outside the caller's reach).
pub async fn conflict(
    exec: &ScopedExecutor,
    actor: i64,
    id: &str,
) -> Result<Option<String>, Refusal> {
    const SQL: &str = r#"SELECT jsonb_build_object( 'id', c.id, 'source', jsonb_build_object( 'sourceKey', s.source_key, 'displayName', s.display_name, 'kind', s.kind, 'state', s.state, 'generation', s.generation::text ), 'subjectFingerprint', substr(encode(digest(c.external_subject,'sha256'),'hex'),1,16), 'evidenceClass', c.evidence_class, 'evidenceDigest', encode(c.evidence_digest,'hex'), 'explanation', c.redacted_explanation, 'state', c.status, 'generation', c.generation::text, 'createdAt', c.created_at, 'expiresAt', c.expires_at, 'decidedAt', c.decided_at, 'candidatePerson', CASE WHEN u.id IS NULL THEN NULL ELSE jsonb_build_object( 'userId', u.id::text, 'email', u.email, 'displayName', u.display_name, 'enabled', u.enabled, 'protected', protection.is_protected ) END, 'allowedDecisions', CASE WHEN c.status NOT IN ('pending','deferred') OR c.expires_at<=statement_timestamp() OR c.generation<>s.generation THEN '[]'::jsonb WHEN c.candidate_user_id IS NULL AND s.state='active' AND source_payload.available THEN '["create","reject","defer"]'::jsonb WHEN c.candidate_user_id IS NULL OR c.evidence_class='soft' OR protection.is_protected OR s.state<>'active' THEN '["reject","defer"]'::jsonb ELSE '["link","reject","defer"]'::jsonb END, 'decisionHistory', COALESCE(( SELECT jsonb_agg(history.row ORDER BY history.occurred_at DESC) FROM ( SELECT d.occurred_at, jsonb_build_object( 'id', d.id::text, 'decision', d.decision, 'reason', d.reason, 'personId', CASE WHEN d.person_id IS NULL THEN NULL ELSE d.person_id::text END, 'linkId', CASE WHEN d.link_id IS NULL THEN NULL ELSE d.link_id::text END, 'decidedBy', d.decided_by::text, 'occurredAt', d.occurred_at ) AS row FROM identity_match_decisions d WHERE d.candidate_id=c.id ORDER BY d.occurred_at DESC,d.id DESC LIMIT 50 ) history ),'[]'::jsonb) )::text FROM identity_match_candidates c JOIN identity_sources s ON s.id=c.source_id LEFT JOIN users u ON u.id=c.candidate_user_id LEFT JOIN LATERAL ( SELECT u.id IS NOT NULL AND ( EXISTS ( SELECT 1 FROM admin_role_assignments ara JOIN admin_role_groups arg ON arg.id=ara.role_group_id WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>statement_timestamp()) AND admin_assignment_active( ara.eligible,ara.activated_until ) AND EXISTS ( SELECT 1 FROM admin_permissions ap WHERE ap.permission_key=ANY(arg.permissions) AND ap.is_sensitive ) ) OR EXISTS ( SELECT 1 FROM system_config cfg, LATERAL jsonb_array_elements_text(cfg.value) x(raw) WHERE cfg.key='ca_break_glass_user_ids' AND x.raw::bigint=u.id ) ) AS is_protected ) protection ON true LEFT JOIN LATERAL ( SELECT false AS available ) source_payload ON true WHERE c.id=$2::text::uuid AND identity_admin_scope_allows( $1,c.candidate_user_id,'users.read' )"#;
    let rows = exec
        .read(SQL, &[(&actor, Type::INT8), (&id, Type::TEXT)])
        .await
        .map_err(|_| failed("identity conflict read failed"))?;
    match rows.first() {
        None => Ok(None),
        Some(row) => row
            .try_get::<_, String>(0)
            .map(Some)
            .map_err(|_| failed("identity conflict read failed")),
    }
}
