//! #377: JMAP Reminder/{get,dismiss,snooze} and Continuity/{get,present}
//! recorded Go-parity oracle, mutants and WebSocket / readiness tests.
#[allow(dead_code, unused_imports)]
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_family_oracle;

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Duration, SecondsFormat, Utc};
use http_body_util::BodyExt;
use hyper::Request;
use jmap_family_oracle::{run, Case, Mutation, CONTINUITY_KEY_ID, CONTINUITY_SEED};
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use setjoin_conformance::harness::{BoxError, Db};
use setjoin_gateway::jmap::{JmapCommands, JmapRoute, JmapServices};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use tokio::net::TcpListener;

const MAIL_CAPS: &str = r#"["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"]"#;

const REMINDER_EFFECTS: &[(&str, &str)] = &[
    (
        "own",
        "SELECT coalesce(jmap_reminder_state,0)::text || '|' || coalesce((SELECT string_agg(id::text || ':' || coalesce(dismissed_at::text,'null') || ':' || coalesce(snoozed_until::text,'null'), ',' ORDER BY id) FROM reminders WHERE mailbox_id = {a.mailbox}), '') FROM mailboxes WHERE id = {a.mailbox}",
    ),
    (
        "foreign",
        "SELECT coalesce(jmap_reminder_state,0)::text || '|' || coalesce((SELECT string_agg(id::text || ':' || coalesce(dismissed_at::text,'null') || ':' || coalesce(snoozed_until::text,'null'), ',' ORDER BY id) FROM reminders WHERE mailbox_id = {f.mailbox}), '') FROM mailboxes WHERE id = {f.mailbox}",
    ),
];

const CONTINUITY_EFFECTS: &[(&str, &str)] = &[
    (
        "control",
        "SELECT (continuity_last_wall_clock IS NOT NULL)::text || '|' || coalesce(continuity_last_boot_epoch::text,'null') FROM upgrade_control_state WHERE singleton",
    ),
    (
        "witnesses",
        "SELECT coalesce(string_agg(mailbox_id::text || ':' || timeline_generation::text || ':' || state_watermark::text || ':' || signal_class, ',' ORDER BY id), '') FROM continuity_client_witnesses WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
];

const RECEIPTS_ON: &[(&str, bool)] = &[("feature.client_recovery_receipts", true)];
const RECEIPTS_OFF: &[(&str, bool)] = &[("feature.client_recovery_receipts", false)];

const CONTINUITY_SETUP_OWN: &[&str] = &[
    r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{a.mailbox}"},"g1"]]}"#,
];
const CONTINUITY_SETUP_DELEGATE: &[&str] = &[
    r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{f.mailbox}"},"g1"]]}"#,
];

const SEED_OWN_AND_FOREIGN_REMINDER: &[&str] = &[
    "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body) VALUES ({a.mailbox}, 'flag', 101, '2026-01-01T00:00:00Z'::timestamptz, '2026-01-01T00:00:00Z'::timestamptz, 'Own reminder', 'Body') RETURNING id",
    "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body) VALUES ({f.mailbox}, 'flag', 102, '2026-01-01T00:00:00Z'::timestamptz, '2026-01-01T00:00:00Z'::timestamptz, 'Foreign reminder', 'Foreign body') RETURNING id",
];

const SEED_OWN_REMINDER: &[&str] = &[
    "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body) VALUES ({a.mailbox}, 'flag', 101, '2026-01-01T00:00:00Z'::timestamptz, '2026-01-01T00:00:00Z'::timestamptz, 'Own reminder', 'Body') RETURNING id",
];

const SEED_TWO_OWN_REMINDERS: &[&str] = &[
    "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body) VALUES ({a.mailbox}, 'flag', 101, '2026-01-01T00:00:00Z'::timestamptz, '2026-01-01T00:00:00Z'::timestamptz, 'First reminder', 'Body 1') RETURNING id",
    "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body) VALUES ({a.mailbox}, 'task', 102, '2026-01-01T00:01:00Z'::timestamptz, '2026-01-01T00:01:00Z'::timestamptz, 'Second reminder', 'Body 2') RETURNING id",
];

const SEED_FOREIGN_REMINDER: &[&str] = &[
    "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body) VALUES ({f.mailbox}, 'flag', 102, '2026-01-01T00:00:00Z'::timestamptz, '2026-01-01T00:00:00Z'::timestamptz, 'Foreign reminder', 'Foreign body') RETURNING id",
];

const SEED_DELEGATE_FULL: &[&str] = &[
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
];

const SEED_DELEGATE_READ: &[&str] = &[
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES ({f.mailbox}, {a.user}, 'read', {f.user})",
];

const SEED_DELEGATE_CALENDAR: &[&str] = &[
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES ({f.mailbox}, {a.user}, 'manage_calendar', {f.user})",
];

const REVOKE_DELEGATE: &[&str] =
    &["DELETE FROM mailbox_delegates WHERE mailbox_id = {f.mailbox} AND user_id = {a.user}"];

const SUSPEND_FOREIGN: &[&str] = &[
    "UPDATE mailboxes SET enabled = false WHERE id = {f.mailbox}",
    "UPDATE mailbox_lifecycle SET access_state = 'suspended', generation = generation + 1, updated_at = statement_timestamp() WHERE mailbox_id = {f.mailbox} AND binding_state IN ('bound','shared')",
];

fn extract_prior_token(prior: &[String]) -> Result<String, BoxError> {
    let doc: Value = serde_json::from_str(prior.first().ok_or("missing setup response")?)?;
    Ok(doc
        .pointer("/methodResponses/0/1/token")
        .and_then(Value::as_str)
        .ok_or("missing continuity token in setup response")?
        .to_owned())
}

fn resign_token_with(
    prior: &[String],
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Result<String, BoxError> {
    let token = extract_prior_token(prior)?;
    let (payload_b64, _) = token.split_once('.').ok_or("malformed setup token")?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)?;
    let mut claims: serde_json::Map<String, Value> = serde_json::from_slice(&payload_bytes)?;
    mutate(&mut claims);
    let encoded_payload = serde_json::to_vec(&Value::Object(claims))?;
    let key =
        Ed25519KeyPair::from_seed_unchecked(&CONTINUITY_SEED).map_err(|_| "continuity seed key")?;
    let sig = key.sign(&encoded_payload);
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&encoded_payload),
        URL_SAFE_NO_PAD.encode(sig.as_ref())
    ))
}

fn vars_bad_signature(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let token = extract_prior_token(prior)?;
    let (payload, sig) = token.split_once('.').ok_or("malformed setup token")?;
    let mut bytes = sig.as_bytes().to_vec();
    let last = bytes.last_mut().ok_or("empty signature")?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = format!("{payload}.{}", String::from_utf8(bytes)?);
    Ok(vec![("token".to_owned(), tampered)])
}

fn vars_expired_token(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let expired = resign_token_with(prior, |claims| {
        let old = (Utc::now() - Duration::days(200)).to_rfc3339_opts(SecondsFormat::Secs, true);
        claims.insert("issuedAt".to_owned(), json!(old));
    })?;
    Ok(vec![("token".to_owned(), expired)])
}

fn vars_unknown_key_token(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let unknown = resign_token_with(prior, |claims| {
        claims.insert("keyId".to_owned(), json!("unknown-continuity-key"));
    })?;
    Ok(vec![("token".to_owned(), unknown)])
}

fn vars_newer_timeline_token(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let newer = resign_token_with(prior, |claims| {
        claims.insert("stateWatermark".to_owned(), json!("999999"));
    })?;
    Ok(vec![("token".to_owned(), newer)])
}

const REMINDER_GET_SUCCESS: Case = Case {
    seed: SEED_OWN_AND_FOREIGN_REMINDER,
    absent: &["{seed.1}", "Foreign reminder"],
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-get-success",
        "success",
        "Reminder/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/get",{"accountId":"{a.mailbox}","limit":50},"c1"]]}"#,
    )
};

const REMINDER_GET_NO_TENANT_MUTANT: Case = Case {
    absent: &[],
    ..REMINDER_GET_SUCCESS
};

const REMINDER_GET_CROSS_TENANT: Case = Case {
    seed: SEED_FOREIGN_REMINDER,
    absent: &["{seed.0}", "Foreign reminder"],
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-get-cross-tenant",
        "cross-tenant",
        "Reminder/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const REMINDER_GET_INVALID: Case = Case {
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-get-invalid-input",
        "invalid-input",
        "Reminder/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/get",{"accountId":"{a.mailbox}","limit":"bad"},"c1"]]}"#,
    )
};

const REMINDER_GET_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE_FULL,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-get-delegate-personal",
        "delegate-personal",
        "Reminder/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_SUCCESS: Case = Case {
    mutator: true,
    seed: SEED_OWN_REMINDER,
    effects: REMINDER_EFFECTS,
    notify: &["tag:{a.mailbox}"],
    ..Case::new(
        "reminder",
        "reminder-dismiss-success",
        "success",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{a.mailbox}","reminderId":"{seed.0}"},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_ALL: Case = Case {
    mutator: true,
    seed: SEED_TWO_OWN_REMINDERS,
    effects: REMINDER_EFFECTS,
    notify: &["tag:{a.mailbox}"],
    ..Case::new(
        "reminder",
        "reminder-dismiss-all",
        "success",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{a.mailbox}","all":true},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: SEED_OWN_REMINDER,
    effects: REMINDER_EFFECTS,
    notify: &["tag:{a.mailbox}"],
    ..Case::new(
        "reminder",
        "reminder-dismiss-repeat",
        "repeat",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{a.mailbox}","reminderId":"{seed.0}"},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: SEED_FOREIGN_REMINDER,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-dismiss-cross-tenant",
        "cross-tenant",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{f.mailbox}","reminderId":"{seed.0}"},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_FOREIGN: Case = Case {
    mutator: true,
    seed: SEED_FOREIGN_REMINDER,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-dismiss-foreign-object",
        "foreign-object",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{a.mailbox}","reminderId":"{seed.0}"},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_INVALID: Case = Case {
    mutator: true,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-dismiss-invalid-input",
        "invalid-input",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{a.mailbox}","reminderId":"bad"},"c1"]]}"#,
    )
};

const REMINDER_DISMISS_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: SEED_DELEGATE_FULL,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-dismiss-delegate-personal",
        "delegate-personal",
        "Reminder/dismiss",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/dismiss",{"accountId":"{f.mailbox}","all":true},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_SUCCESS: Case = Case {
    mutator: true,
    seed: SEED_OWN_REMINDER,
    effects: REMINDER_EFFECTS,
    notify: &["tag:{a.mailbox}"],
    ..Case::new(
        "reminder",
        "reminder-snooze-success",
        "success",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{a.mailbox}","reminderId":"{seed.0}","until":"2099-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: SEED_OWN_REMINDER,
    effects: REMINDER_EFFECTS,
    notify: &["tag:{a.mailbox}"],
    ..Case::new(
        "reminder",
        "reminder-snooze-repeat",
        "repeat",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{a.mailbox}","reminderId":"{seed.0}","until":"2099-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: SEED_FOREIGN_REMINDER,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-snooze-cross-tenant",
        "cross-tenant",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{f.mailbox}","reminderId":"{seed.0}","until":"2099-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_FOREIGN: Case = Case {
    mutator: true,
    seed: SEED_FOREIGN_REMINDER,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-snooze-foreign-object",
        "foreign-object",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{a.mailbox}","reminderId":"{seed.0}","until":"2099-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_INVALID: Case = Case {
    mutator: true,
    seed: SEED_OWN_REMINDER,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-snooze-invalid-input",
        "invalid-input",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{a.mailbox}","reminderId":"{seed.0}","until":"2000-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_INVALID_ID: Case = Case {
    mutator: true,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-snooze-invalid-id",
        "invalid-input",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{a.mailbox}","reminderId":"bad","until":"2099-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const REMINDER_SNOOZE_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: SEED_DELEGATE_FULL,
    effects: REMINDER_EFFECTS,
    ..Case::new(
        "reminder",
        "reminder-snooze-delegate-personal",
        "delegate-personal",
        "Reminder/snooze",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:reminders"],"methodCalls":[["Reminder/snooze",{"accountId":"{f.mailbox}","reminderId":"1","until":"2099-01-01T00:00:00Z"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_SUCCESS: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-success",
        "success",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: RECEIPTS_ON,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-repeat",
        "repeat",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-cross-tenant",
        "cross-tenant",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_INVALID: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-invalid-input",
        "invalid-input",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":7},"c1"]]}"#,
    )
};

const CONTINUITY_GET_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_READ,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-delegate-allowed",
        "delegate-allowed",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_CALENDAR,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-delegate-insufficient",
        "delegate-insufficient",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_READ,
    between: REVOKE_DELEGATE,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-delegate-revoked",
        "delegate-revoked",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_SUSPENDED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_READ,
    between: SUSPEND_FOREIGN,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-suspended",
        "suspended",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_GET_DISABLED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_OFF,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-get-disabled",
        "disabled",
        "Continuity/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/get",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_SUCCESS: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    setup: CONTINUITY_SETUP_OWN,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-success",
        "success",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"{resp.0:/methodResponses/0/1/token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: RECEIPTS_ON,
    setup: CONTINUITY_SETUP_OWN,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-repeat",
        "repeat",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"{resp.0:/methodResponses/0/1/token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_NEWER_TIMELINE: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    setup: CONTINUITY_SETUP_OWN,
    vars: vars_newer_timeline_token,
    effects: CONTINUITY_EFFECTS,
    notify: &["continuity_signal_changed"],
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-newer-timeline",
        "success",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"{var.token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-cross-tenant",
        "cross-tenant",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{f.mailbox}","token":"x"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_INVALID: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-invalid-input",
        "invalid-input",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":""},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_INVALID_SIGNATURE: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    setup: CONTINUITY_SETUP_OWN,
    vars: vars_bad_signature,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-invalid-signature",
        "invalid-input",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"{var.token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_EXPIRED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    setup: CONTINUITY_SETUP_OWN,
    vars: vars_expired_token,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-expired",
        "invalid-input",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"{var.token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_UNKNOWN_KEY: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    setup: CONTINUITY_SETUP_OWN,
    vars: vars_unknown_key_token,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-unknown-key",
        "invalid-input",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"{var.token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_READ,
    setup: CONTINUITY_SETUP_DELEGATE,
    effects: CONTINUITY_EFFECTS,
    scrub: &[("/methodResponses/0/1/token", "token")],
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-delegate-allowed",
        "delegate-allowed",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{f.mailbox}","token":"{resp.0:/methodResponses/0/1/token}"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_CALENDAR,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-delegate-insufficient",
        "delegate-insufficient",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{f.mailbox}","token":"x"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_READ,
    between: REVOKE_DELEGATE,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-delegate-revoked",
        "delegate-revoked",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{f.mailbox}","token":"x"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_SUSPENDED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_ON,
    seed: SEED_DELEGATE_READ,
    between: SUSPEND_FOREIGN,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-suspended",
        "suspended",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{f.mailbox}","token":"x"},"c1"]]}"#,
    )
};

const CONTINUITY_PRESENT_DISABLED: Case = Case {
    mutator: true,
    toggles: RECEIPTS_OFF,
    effects: CONTINUITY_EFFECTS,
    restore_continuity: true,
    ..Case::new(
        "continuity",
        "continuity-present-disabled",
        "disabled",
        "Continuity/present",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Continuity/present",{"accountId":"{a.mailbox}","token":"x"},"c1"]]}"#,
    )
};

macro_rules! oracle_case {
    ($name:ident, $case:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            run(&$case, Mutation::None).await
        }
    };
}

macro_rules! status_mutant {
    ($name:ident, $case:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(_) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            let diff = run(&$case, Mutation::Status)
                .await
                .expect_err("changed status must fail")
                .to_string();
            assert!(diff.contains("/response/status"), "{diff}");
            println!(
                "MUTANT-REJECTED: POST /jmap {} :: changed-status",
                $case.method
            );
            Ok(())
        }
    };
}

oracle_case!(reminder_get_success, REMINDER_GET_SUCCESS);
oracle_case!(reminder_get_cross_tenant, REMINDER_GET_CROSS_TENANT);
oracle_case!(reminder_get_invalid_input, REMINDER_GET_INVALID);
oracle_case!(
    reminder_get_delegate_personal,
    REMINDER_GET_DELEGATE_PERSONAL
);

oracle_case!(reminder_dismiss_success, REMINDER_DISMISS_SUCCESS);
oracle_case!(reminder_dismiss_all, REMINDER_DISMISS_ALL);
oracle_case!(reminder_dismiss_repeat, REMINDER_DISMISS_REPEAT);
oracle_case!(reminder_dismiss_cross_tenant, REMINDER_DISMISS_CROSS_TENANT);
oracle_case!(reminder_dismiss_foreign_object, REMINDER_DISMISS_FOREIGN);
oracle_case!(reminder_dismiss_invalid_input, REMINDER_DISMISS_INVALID);
oracle_case!(
    reminder_dismiss_delegate_personal,
    REMINDER_DISMISS_DELEGATE_PERSONAL
);

oracle_case!(reminder_snooze_success, REMINDER_SNOOZE_SUCCESS);
oracle_case!(reminder_snooze_repeat, REMINDER_SNOOZE_REPEAT);
oracle_case!(reminder_snooze_cross_tenant, REMINDER_SNOOZE_CROSS_TENANT);
oracle_case!(reminder_snooze_foreign_object, REMINDER_SNOOZE_FOREIGN);
oracle_case!(reminder_snooze_invalid_input, REMINDER_SNOOZE_INVALID);
oracle_case!(reminder_snooze_invalid_id, REMINDER_SNOOZE_INVALID_ID);
oracle_case!(
    reminder_snooze_delegate_personal,
    REMINDER_SNOOZE_DELEGATE_PERSONAL
);

oracle_case!(continuity_get_success, CONTINUITY_GET_SUCCESS);
oracle_case!(continuity_get_repeat, CONTINUITY_GET_REPEAT);
oracle_case!(continuity_get_cross_tenant, CONTINUITY_GET_CROSS_TENANT);
oracle_case!(continuity_get_invalid_input, CONTINUITY_GET_INVALID);
oracle_case!(
    continuity_get_delegate_allowed,
    CONTINUITY_GET_DELEGATE_ALLOWED
);
oracle_case!(
    continuity_get_delegate_insufficient,
    CONTINUITY_GET_DELEGATE_INSUFFICIENT
);
oracle_case!(
    continuity_get_delegate_revoked,
    CONTINUITY_GET_DELEGATE_REVOKED
);
oracle_case!(continuity_get_suspended, CONTINUITY_GET_SUSPENDED);
oracle_case!(continuity_get_disabled, CONTINUITY_GET_DISABLED);

oracle_case!(continuity_present_success, CONTINUITY_PRESENT_SUCCESS);
oracle_case!(continuity_present_repeat, CONTINUITY_PRESENT_REPEAT);
oracle_case!(
    continuity_present_newer_timeline,
    CONTINUITY_PRESENT_NEWER_TIMELINE
);
oracle_case!(
    continuity_present_cross_tenant,
    CONTINUITY_PRESENT_CROSS_TENANT
);
oracle_case!(continuity_present_invalid_input, CONTINUITY_PRESENT_INVALID);
oracle_case!(
    continuity_present_invalid_signature,
    CONTINUITY_PRESENT_INVALID_SIGNATURE
);
oracle_case!(continuity_present_expired, CONTINUITY_PRESENT_EXPIRED);
oracle_case!(
    continuity_present_unknown_key,
    CONTINUITY_PRESENT_UNKNOWN_KEY
);
oracle_case!(
    continuity_present_delegate_allowed,
    CONTINUITY_PRESENT_DELEGATE_ALLOWED
);
oracle_case!(
    continuity_present_delegate_insufficient,
    CONTINUITY_PRESENT_DELEGATE_INSUFFICIENT
);
oracle_case!(
    continuity_present_delegate_revoked,
    CONTINUITY_PRESENT_DELEGATE_REVOKED
);
oracle_case!(continuity_present_suspended, CONTINUITY_PRESENT_SUSPENDED);
oracle_case!(continuity_present_disabled, CONTINUITY_PRESENT_DISABLED);

status_mutant!(mutant_reminder_get_status, REMINDER_GET_SUCCESS);
status_mutant!(mutant_reminder_dismiss_status, REMINDER_DISMISS_SUCCESS);
status_mutant!(mutant_reminder_snooze_status, REMINDER_SNOOZE_SUCCESS);
status_mutant!(mutant_continuity_get_status, CONTINUITY_GET_SUCCESS);
status_mutant!(mutant_continuity_present_status, CONTINUITY_PRESENT_SUCCESS);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutant_reminder_get_no_tenant_filter() -> Result<(), BoxError> {
    run(
        &REMINDER_GET_NO_TENANT_MUTANT,
        Mutation::NoTenantFilter {
            function: "reminders_get(bigint,integer)",
            from: "r.mailbox_id = p_mailbox_id",
        },
    )
    .await
}

/// Offline readiness test (no database required): Continuity/* stays with Go
/// when the continuity signing key is absent (`Reminder/*` readiness without
/// a signer is verified in `family::mod::tests::reminder_and_continuity_classification_and_readiness`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continuity_without_signer_forwards_to_go() {
    let exec = common::patient_exec("host=127.0.0.1 port=1 user=x dbname=x", 1).expect("lazy");
    let services = JmapServices::new(exec.clone(), "mail.test".into(), 52428800);
    assert!(services.continuity_signer.is_none());
    let commands = Arc::new(JmapCommands {
        services: Some(Arc::new(services)),
        worker: None,
        exec,
        keys: common::recovery_keys(),
        issuer: "mailserver".into(),
        denylist: None,
    });
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("").expect("proxies"),
            upstream_header_timeout: std::time::Duration::from_secs(5),
            edge_limit: None,
        },
        RouteTable::proxy_all().with(JmapRoute(commands)),
    )
    .expect("gateway");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(gateway.serve(listener));

    for method in ["Continuity/get", "Continuity/present"] {
        let body = json!({
            "using": serde_json::from_str::<Value>(MAIL_CAPS).unwrap(),
            "methodCalls": [[method, {"accountId": "1", "token": "x"}, "c1"]],
        })
        .to_string();
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .expect("handshake");
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("POST")
            .uri("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", "application/json")
            .body(common::full(body))
            .expect("request");
        let resp = sender.send_request(req).await.expect("response");
        // With Go upstream unset, a Go forward answers 502 Bad Gateway.
        assert_eq!(resp.status().as_u16(), 502, "{method} should defer to Go");
        conn_task.abort();
    }

    // Confirm metrics recorded the two Continuity/* forwards.
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .expect("handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri("/_gateway/metrics")
        .header("host", "mail.test")
        .body(common::full(String::new()))
        .expect("metrics");
    let resp = sender.send_request(req).await.expect("metrics resp");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let metrics = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(
        metrics.contains("setjoin_gateway_proxied_to_go_total 2"),
        "{metrics}"
    );
    conn_task.abort();
    server.abort();
}
