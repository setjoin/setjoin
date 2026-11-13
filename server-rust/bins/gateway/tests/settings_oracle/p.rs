//! Slice `profile` (#309): `POST /user/profile` (display name) and `GET /user/quota` (the
//! actor's own mailbox storage totals). Both routes are gated by `requireAuth` only.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{Value, json};
use setjoin_conformance::fixture::Account;

/// `(method, inventory pattern)` for an action.
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "profile-update" => ("POST", "/user/profile"),
        "quota-get" => ("GET", "/user/quota"),
        _ => panic!("unknown profile action {action}"),
    }
}

/// The status Go answers; `None` leaves the recorded status unchecked.
pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        (
            "profile-update",
            "bad-json" | "array-body" | "wrong-type" | "scalar-body" | "empty-body" | "null-body"
            | "empty" | "blank" | "nbsp" | "null-name" | "too-long",
        ) => Some(400),
        ("profile-update", "nul") | ("quota-get", "overflow") => Some(500),
        _ => Some(200),
    }
}

const EXTRA_KEYS: [&str; 2] = ["x0", "x1"];

/// `(used, quota, enabled)` of the actor's extra mailboxes for a label.
fn extras(label: &str) -> Vec<(i64, i64, bool)> {
    match label {
        "overflow" => vec![(0, i64::MAX, true), (0, i64::MAX, true)],
        "single" => vec![],
        "zero" => vec![(0, 0, true)],
        _ => vec![(2500, 20_000, true), (40, 60, false)],
    }
}

/// Sets the storage figures. Frozen Go's start-up reconciles `used_bytes` from the stored
/// messages, so this runs again once the Go process is up (and before the first snapshot).
pub async fn reapply(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
    seed: &Seed,
) -> Result<(), BoxError> {
    if action != "quota-get" {
        return Ok(());
    }
    let set = "UPDATE mailboxes SET used_bytes=$2, quota_bytes=$3, enabled=$4 WHERE id=$1";
    owner
        .execute(set, &[&a.mailbox, &1000_i64, &5000_i64, &true])
        .await?;
    owner
        .execute(set, &[&b.mailbox, &777_777_i64, &888_888_i64, &true])
        .await?;
    for (n, (used, quota, enabled)) in extras(label).into_iter().enumerate() {
        owner
            .execute(set, &[&seed.vars[EXTRA_KEYS[n]], &used, &quota, &enabled])
            .await?;
    }
    if let Some(id) = seed.vars.get("foreign_extra") {
        owner
            .execute(set, &[id, &123_456_i64, &654_321_i64, &true])
            .await?;
    }
    Ok(())
}

const STAMP: &str = "2026-10-01T10:00:00Z";

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    // Fixed, readable timestamps: a changed row shows up as `<timestamp>`.
    for (user, name) in [(a.user, "Actor Original"), (b.user, "Other Original")] {
        owner
            .execute(
                "UPDATE users SET display_name=$2, updated_at=$3::text::timestamptz WHERE id=$1",
                &[&user, &name, &STAMP],
            )
            .await?;
    }
    let mut undo = vec![];
    let mut mailboxes = vec![];
    let mut vars = std::collections::BTreeMap::new();
    if action == "quota-get" {
        vars.insert("quota", 1);
        // Extra mailboxes of the actor: disabled and non-primary ones are summed too.
        for (n, _) in extras(label).iter().enumerate() {
            let email = format!("profile-extra-{}-{n}@profile-quota.test", a.user);
            let id: i64 = owner
                .query_one(
                    "INSERT INTO mailboxes(user_id,domain_id,email,display_name) VALUES($1,$2,$3,'Extra') RETURNING id",
                    &[&a.user, &a.domain, &email],
                )
                .await?
                .get(0);
            vars.insert(EXTRA_KEYS[n], id);
            mailboxes.push(id);
        }
        if !mailboxes.is_empty() {
            undo.push(format!(
                "DELETE FROM mailboxes WHERE id IN ({})",
                mailboxes
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if label == "foreign" {
            // A second mailbox of the other tenant: still not the actor's.
            let email = format!("profile-extra-{}-x@profile-quota.test", b.user);
            let id: i64 = owner
                .query_one(
                    "INSERT INTO mailboxes(user_id,domain_id,email,display_name) VALUES($1,$2,$3,'Extra') RETURNING id",
                    &[&b.user, &b.domain, &email],
                )
                .await?
                .get(0);
            vars.insert("foreign_extra", id);
            undo.push(format!("DELETE FROM mailboxes WHERE id={id}"));
        }
    }
    vars.insert("actor", a.user);
    vars.insert("other", b.user);
    Ok(Seed {
        names: vec![],
        vars,
        extra_users: vec![],
        undo,
        text_masks: vec![],
    })
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let other = seed.vars.get("other").copied().unwrap_or(0);
    let query = if label == "ignored-query" {
        "?display_name=Query%20Name&x=%zz"
    } else {
        ""
    };
    let body = if action == "quota-get" {
        String::new()
    } else {
        match label {
            "bad-json" => "{".to_owned(),
            "array-body" => r#"["Name"]"#.to_owned(),
            "scalar-body" => r#""Name""#.to_owned(),
            "empty-body" => String::new(),
            "null-body" => "null".to_owned(),
            "wrong-type" => r#"{"display_name":5}"#.to_owned(),
            "null-name" => r#"{"display_name":null}"#.to_owned(),
            "empty" => r#"{"display_name":""}"#.to_owned(),
            "blank" => r#"{"display_name":" \t\n "}"#.to_owned(),
            "nbsp" => "{\"display_name\":\"\\u00a0\\u2003\\u3000\"}".to_owned(),
            "unicode-space" => "{\"display_name\":\"\\u0085\\u2028\\u2029\\u200b\"}".to_owned(),
            "padded" => "{\"display_name\":\"  \\u00a0Padded Name\\u2003 \"}".to_owned(),
            "too-long" => format!("{{\"display_name\":\"{}\"}}", "x".repeat(256)),
            "at-limit" => format!("{{\"display_name\":\"{}\"}}", "é".repeat(255)),
            "limit-padded" => format!("{{\"display_name\":\"  {}  \"}}", "x".repeat(255)),
            "html" => r#"{"display_name":"<b>Tom & \"Jerry\"</b> \u2028 é"}"#.to_owned(),
            "fold" => r#"{"DISPLAY_NAME":"Folded Name"}"#.to_owned(),
            "unknown-field" => {
                format!(r#"{{"display_name":"Known","email":"x@y.test","id":{other},"user_id":{other}}}"#)
            }
            "foreign" => format!(
                r#"{{"display_name":"Hijack Attempt","user_id":{other},"id":{other},"email":"other@x.test"}}"#
            ),
            "duplicate" => r#"{"display_name":"First","display_name":"Second"}"#.to_owned(),
            "trailing" => r#"{"display_name":"Trailing"} trailing junk"#.to_owned(),
            "two-values" => r#"{"display_name":"One"}{"display_name":"Two"}"#.to_owned(),
            "nul" => "{\"display_name\":\"a\\u0000b\"}".to_owned(),
            "emoji" => "{\"display_name\":\"\\ud83d\\ude00 Smile \\ud800\"}".to_owned(),
            _ => r#"{"display_name":"New Display Name"}"#.to_owned(),
        }
    };
    Req {
        path: pattern.to_owned(),
        query: query.into(),
        recorded_body: body.replace(&format!(":{other}"), ":\"<other>\""),
        body,
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    let mut users = vec![];
    let mut mailboxes = vec![];
    for (account, who) in [(a, "actor"), (b, "other")] {
        let rows = super::rows(
            owner,
            &format!(
                "SELECT jsonb_build_object('display_name',display_name,'updated_at',updated_at)::text FROM users WHERE id={}",
                account.user
            ),
        )
        .await?;
        users.push(json!({"who":who,"rows":rows}));
        let rows = super::rows(
            owner,
            &format!(
                "SELECT jsonb_build_object('used',used_bytes,'quota',quota_bytes,'enabled',enabled)::text FROM mailboxes WHERE user_id={} ORDER BY used_bytes, quota_bytes, id",
                account.user
            ),
        )
        .await?;
        mailboxes.push(json!({"who":who,"rows":rows}));
    }
    let mut out = json!({"users":users});
    if seed.vars.contains_key("quota") {
        out["mailboxes"] = json!(mailboxes);
    }
    Ok(out)
}
