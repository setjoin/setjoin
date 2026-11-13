//! User mail settings and profile (F19): `/settings/*` and `/user/*` routes. Foundation
//! dependencies only (`authz`, `contracts`, `db`, `pg`) and no other family crate. See
//! DOX.md for the four-slice map and per-slice contracts.
//!
//! The actor comes from the sealed auth context; path ids, query strings and bodies name
//! targets but never grant authority, and the verified user sits in the same WHERE as every
//! write. Responses render in `encoding/json` field order (structs) or sorted key order
//! (maps), HTML-escaped, with the trailing newline of Go's `Encoder`.
#![forbid(unsafe_code)]
pub mod prefs;
pub mod profile;
pub mod security;
pub mod settings;
pub mod sync;
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{MailboxAuthContext, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F19";

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid user settings result".into(),
    }
}
pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}
pub(crate) fn envelope(
    auth: &MailboxAuthContext,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}
pub(crate) fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// encoding/json HTML escaping of an already rendered document.
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
/// A JSON string as `encoding/json` writes it (HTML-escaped).
pub fn s(text: &str) -> String {
    go_escape(&serde_json::to_string(text).expect("string"))
}
/// Go's `Encoder` output: the document plus its trailing newline.
pub fn done(text: String) -> String {
    text + "\n"
}
/// RFC 3339 with Go's trimmed fractional seconds (`time.Time` JSON), UTC.
pub(crate) fn nano(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
    )
}
pub(crate) fn first_i64(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}

/// `strconv.FormatFloat(f, 'f', -1, 64)` inside 1e-6..1e21, `'e'` outside, as
/// `encoding/json` writes a `float64`.
pub fn go_f64(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let abs = f.abs();
    if !(1e-6..1e21).contains(&abs) {
        let text = format!("{f:e}");
        let (mantissa, exponent) = text.split_once('e').expect("exponent");
        let exponent: i32 = exponent.parse().expect("exponent");
        return if exponent < 0 {
            format!("{mantissa}e-{}", -exponent)
        } else {
            format!("{mantissa}e+{exponent:02}")
        };
    }
    format!("{f}")
}

/// `json.Marshal` of a decoded `interface{}` tree: sorted object keys, every number a
/// `float64`, HTML-escaped strings, no whitespace.
pub fn go_marshal(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => go_f64(n.as_f64().unwrap_or(0.0)),
        Value::String(text) => s(text),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(go_marshal).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|k| format!("{}:{}", s(k), go_marshal(&map[*k])))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}
