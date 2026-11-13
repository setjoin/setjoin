//! Slice `settings-c` (#308): sessions (list, revoke one, revoke all), devices, login history,
//! "this wasn't me" account securing and the security score. Every case presents a token whose
//! `jti` is `CURRENT_JTI`, so a seeded web session with that id is the `current` one.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{Value, json};
use setjoin_conformance::fixture::Account;

pub const CURRENT_JTI: &str = "settings3-current";

/// `(method, inventory pattern)` for an action.
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "sessions-list" => ("GET", "/user/sessions"),
        "session-revoke" => ("DELETE", "/user/sessions/{id}"),
        "sessions-revoke-all" => ("POST", "/user/sessions/revoke-all"),
        "devices-list" => ("GET", "/user/devices"),
        "login-history" => ("GET", "/user/login-history"),
        "secure-account" => ("POST", "/user/sign-ins/secure-account"),
        "security-score" => ("GET", "/user/security-score"),
        _ => panic!("unknown settings-c action {action}"),
    }
}

/// The status Go answers; `None` leaves the recorded status unchecked.
pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        (
            "session-revoke",
            "foreign" | "foreign-token" | "unknown" | "revoke-all-word" | "repeat",
        ) => Some(404),
        _ => Some(200),
    }
}

/// A second revoke-all needs a token the first one's `all` watermark (`not_before >= iat`)
/// does not revoke, so that case issues its token from the future.
pub fn token(action: &str, label: &str, user: i64) -> String {
    let mut claims = json!({"jti": CURRENT_JTI});
    if (action, label) == ("sessions-revoke-all", "repeat") {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        claims["iat"] = json!(now + 300);
    }
    crate::common::recovery_token_with(user, claims)
}

const F1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const F2: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2";
const F3: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3";
const F4: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4";
const DEV1: &str = "11111111-1111-4111-8111-111111111111";
const DEV3: &str = "33333333-3333-4333-8333-333333333333";

async fn token_row(
    owner: &tokio_postgres::Client,
    user: i64,
    label: &str,
    kind: &str,
    client: Option<&str>,
    family: Option<&str>,
    rotated: bool,
    state: &str,
    last_used: Option<&str>,
    protocol: Option<&str>,
    issued: &str,
) -> Result<i64, BoxError> {
    // `state`: live | revoked | expired
    let (revoked, expires) = match state {
        "revoked" => ("now() - interval '1 hour'", "now() + interval '1 day'"),
        "expired" => ("NULL", "now() - interval '1 hour'"),
        _ => ("NULL", "now() + interval '1 day'"),
    };
    let sql = format!(
        "INSERT INTO oauth_tokens(user_id,client_id,token_hash,token_type,issued_at,expires_at,revoked_at,previous_token_hash,last_used_at,last_used_protocol,family_id) \
         VALUES($1,$2,convert_to($3,'UTF8'),$4,$5::text::timestamptz,{expires},{revoked},CASE WHEN $6 THEN convert_to('prev-'||$3,'UTF8') END,$7::text::timestamptz,$8,$9::text::uuid) RETURNING id"
    );
    let hash = format!("settings3-{user}-{label}");
    Ok(owner
        .query_one(
            &sql,
            &[
                &user, &client, &hash, &kind, &issued, &rotated, &last_used, &protocol, &family,
            ],
        )
        .await?
        .get(0))
}

async fn web(
    owner: &tokio_postgres::Client,
    user: i64,
    id: &str,
    expiry: &str,
    seen: &str,
    ip: Option<&str>,
    agent: Option<&str>,
    method: Option<&str>,
) -> Result<(), BoxError> {
    owner
        .execute(
            &format!("INSERT INTO sessions(id,user_id,token_hash,expires_at,last_seen_at,ip,user_agent,auth_method) VALUES($1,$2,convert_to($1,'UTF8'),now() + interval '{expiry}',$3::text::timestamptz,$4::text::inet,$5,$6)"),
            &[&id, &user, &seen, &ip, &agent, &method],
        )
        .await?;
    Ok(())
}

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    let mut text_masks = vec![];
    let foreign = label == "foreign";
    let mut undo = vec![format!(
        "DELETE FROM sessions WHERE user_id IN ({0},{1}); DELETE FROM login_events WHERE user_id IN ({0},{1}); DELETE FROM device_registry WHERE user_id IN ({0},{1}); DELETE FROM devices WHERE user_id IN ({0},{1}); DELETE FROM oauth_tokens WHERE user_id IN ({0},{1}); DELETE FROM session_revocations WHERE user_id IN ({0},{1})",
        a.user, b.user
    )];
    let sessionish = matches!(
        action,
        "sessions-list" | "session-revoke" | "sessions-revoke-all" | "secure-account"
    );
    if sessionish {
        // The other tenant's sessions and tokens: never visible to or touched by the actor.
        web(
            owner,
            b.user,
            "settings3-other-web",
            "1 day",
            "2026-10-01T10:00:06Z",
            Some("198.51.100.9"),
            Some("OtherBrowser"),
            Some("password"),
        )
        .await?;
        let o1 = token_row(
            owner,
            b.user,
            "o1",
            "refresh",
            Some("other-app"),
            Some(F3),
            false,
            "live",
            Some("2026-10-01T10:00:07Z"),
            Some("imap"),
            "2026-10-01T10:00:00Z",
        )
        .await?;
        vars.insert("o1", o1);
        names.push(("id", o1, "<other-token>".into()));
        text_masks.push((
            format!("\"id\":\"{o1}\""),
            "\"id\":\"<other-token>\"".into(),
        ));
        if !foreign {
            web(
                owner,
                a.user,
                CURRENT_JTI,
                "1 day",
                "2026-10-01T10:00:05Z",
                Some("203.0.113.5"),
                Some("Firefox <b>"),
                Some("password"),
            )
            .await?;
            web(
                owner,
                a.user,
                "settings3-web2",
                "1 day",
                "2026-10-01T10:00:03Z",
                None,
                None,
                Some("webauthn"),
            )
            .await?;
            web(
                owner,
                a.user,
                "settings3-expired",
                "-1 hour",
                "2026-10-01T10:00:09Z",
                Some("203.0.113.6"),
                Some("Old"),
                Some("totp"),
            )
            .await?;
            let rows: [(
                &str,
                &str,
                Option<&str>,
                Option<&str>,
                bool,
                &str,
                Option<&str>,
                Option<&str>,
                &str,
            ); 9] = [
                (
                    "ta",
                    "refresh",
                    Some("mobile"),
                    Some(F1),
                    false,
                    "live",
                    Some("2026-10-01T10:00:04Z"),
                    Some("imap"),
                    "2026-10-01T10:00:00Z",
                ),
                (
                    "ta2",
                    "refresh",
                    Some("mobile"),
                    Some(F1),
                    true,
                    "live",
                    Some("2026-10-01T10:00:08Z"),
                    Some("imap"),
                    "2026-10-01T10:00:00Z",
                ),
                (
                    "tb",
                    "xoauth2",
                    None,
                    None,
                    false,
                    "live",
                    None,
                    None,
                    "2026-10-01T10:00:01Z",
                ),
                (
                    "tc",
                    "app_password",
                    Some("Thunderbird"),
                    Some(F2),
                    false,
                    "live",
                    Some("2026-10-01T10:00:02Z"),
                    Some("smtp"),
                    "2026-10-01T10:00:00Z",
                ),
                (
                    "td",
                    "access",
                    Some("web"),
                    Some(F4),
                    false,
                    "live",
                    Some("2026-10-01T10:00:10Z"),
                    None,
                    "2026-10-01T10:00:00Z",
                ),
                (
                    "te",
                    "refresh",
                    Some("old-app"),
                    Some(F4),
                    false,
                    "revoked",
                    Some("2026-10-01T10:00:11Z"),
                    None,
                    "2026-10-01T10:00:00Z",
                ),
                (
                    "tf",
                    "refresh",
                    Some("lapsed"),
                    None,
                    false,
                    "expired",
                    Some("2026-10-01T10:00:12Z"),
                    None,
                    "2026-10-01T10:00:00Z",
                ),
                (
                    "tg",
                    "authorization_code",
                    Some("code"),
                    None,
                    false,
                    "live",
                    None,
                    None,
                    "2026-10-01T10:00:13Z",
                ),
                (
                    "th",
                    "refresh",
                    None,
                    None,
                    false,
                    "live",
                    None,
                    None,
                    "2026-10-01T10:00:00.5Z",
                ),
            ];
            for (key, kind, client, family, rotated, state, used, protocol, issued) in rows {
                let id = token_row(
                    owner, a.user, key, kind, client, family, rotated, state, used, protocol,
                    issued,
                )
                .await?;
                vars.insert(key_static(key), id);
                names.push(("id", id, format!("<{key}>")));
                text_masks.push((format!("\"id\":\"{id}\""), format!("\"id\":\"<{key}>\"")));
            }
        }
    }
    if matches!(action, "devices-list" | "security-score") {
        let registry = "INSERT INTO device_registry(user_id,device_hash,user_agent,first_seen,last_seen,trust_tier,device_fingerprint) VALUES($1,$2,$3,$4::text::timestamptz,$5::text::timestamptz,$6,$7::text::uuid)";
        let none: Option<&str> = None;
        let count = match (action, label) {
            ("devices-list", "foreign") => 0,
            ("security-score", "baseline") => 6,
            ("security-score", "five") => 5,
            ("security-score", "foreign") => 0,
            ("security-score", _) => 2,
            _ => 3,
        };
        if action == "devices-list" {
            if !foreign {
                owner
                    .execute(
                        registry,
                        &[
                            &a.user,
                            &"hash-aaa",
                            &Some("Mail/1.0"),
                            &"2026-10-01T10:00:01Z",
                            &"2026-10-01T10:00:09.123456Z",
                            &"known",
                            &Some(DEV1),
                        ],
                    )
                    .await?;
                owner
                    .execute(
                        registry,
                        &[
                            &a.user,
                            &"hash-bbb",
                            &Some(""),
                            &"2026-10-01T10:00:02Z",
                            &"2026-10-01T10:00:08Z",
                            &"risky",
                            &none,
                        ],
                    )
                    .await?;
                owner
                    .execute(
                        registry,
                        &[
                            &a.user,
                            &"hash-ccc",
                            &Some("Agent/2 <x>"),
                            &"2026-10-01T10:00:03.5Z",
                            &"2026-10-01T10:00:07Z",
                            &"managed",
                            &Some(DEV3),
                        ],
                    )
                    .await?;
                owner.execute("INSERT INTO devices(user_id,device_name,platform,fingerprint) VALUES($1,'Pixel & co','android',$2)", &[&a.user, &DEV1]).await?;
                owner.execute("INSERT INTO devices(user_id,device_name,platform,fingerprint) VALUES($1,NULL,'ios',$2)", &[&a.user, &DEV3]).await?;
            }
            owner
                .execute(
                    registry,
                    &[
                        &b.user,
                        &"hash-other",
                        &Some("OtherAgent"),
                        &"2026-10-01T10:00:04Z",
                        &"2026-10-01T10:00:10Z",
                        &"known",
                        &Some(DEV1),
                    ],
                )
                .await?;
            owner.execute("INSERT INTO devices(user_id,device_name,platform,fingerprint) VALUES($1,'Other phone','android',$2)", &[&b.user, &DEV1]).await?;
        } else {
            for n in 0..count {
                owner
                    .execute(
                        registry,
                        &[
                            &a.user,
                            &format!("hash-{n}"),
                            &none,
                            &"2026-10-01T10:00:01Z",
                            &"2026-10-01T10:00:02Z",
                            &"unknown",
                            &none,
                        ],
                    )
                    .await?;
            }
            for n in 0..8 {
                owner
                    .execute(
                        registry,
                        &[
                            &b.user,
                            &format!("other-{n}"),
                            &none,
                            &"2026-10-01T10:00:01Z",
                            &"2026-10-01T10:00:02Z",
                            &"unknown",
                            &none,
                        ],
                    )
                    .await?;
            }
        }
    }
    if matches!(action, "login-history" | "security-score") {
        let event = "INSERT INTO login_events(user_id,success,occurred_at,source_ip,location,device_name,platform,client,protocol,auth_method,fail_reason,session_id) VALUES($1,$2,now() - $3::text::interval,$4::text::inet,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id";
        let insert = |user: i64,
                      ok: bool,
                      ago: &'static str,
                      ip: Option<&'static str>,
                      loc: Option<&'static str>,
                      dev: Option<&'static str>,
                      client: Option<&'static str>,
                      method: Option<&'static str>,
                      reason: Option<&'static str>,
                      session: Option<&'static str>| {
            async move {
                let row = owner
                    .query_one(
                        event,
                        &[
                            &user,
                            &ok,
                            &ago,
                            &ip,
                            &loc,
                            &dev,
                            &Some("linux"),
                            &client,
                            &client.map(|_| "http"),
                            &method,
                            &reason,
                            &session,
                        ],
                    )
                    .await?;
                Ok::<i64, BoxError>(row.get(0))
            }
        };
        if action == "login-history" {
            if !foreign && label != "empty" {
                let e1 = insert(
                    a.user,
                    true,
                    "5 minutes",
                    Some("203.0.113.7"),
                    Some("Berlin, DE"),
                    Some("Pixel"),
                    Some("web"),
                    Some("password"),
                    None,
                    Some(CURRENT_JTI),
                )
                .await?;
                let e2 = insert(
                    a.user,
                    false,
                    "10 minutes",
                    Some("203.0.113.8"),
                    Some("Paris"),
                    Some("Laptop"),
                    Some("imap"),
                    Some("password"),
                    Some("bad <password>"),
                    Some("someone-else"),
                )
                .await?;
                let e3 = insert(
                    a.user,
                    true,
                    "15 minutes",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
                let e4 = insert(
                    a.user,
                    false,
                    "20 minutes",
                    Some("2001:db8::7"),
                    Some("Paris"),
                    None,
                    Some("smtp"),
                    Some("app_password"),
                    None,
                    None,
                )
                .await?;
                let e5 = insert(
                    a.user,
                    false,
                    "25 minutes",
                    Some("203.0.113.8"),
                    Some("Oslo"),
                    Some("Laptop"),
                    Some("web"),
                    Some("totp"),
                    Some("expired code"),
                    None,
                )
                .await?;
                let e6 = insert(
                    a.user,
                    true,
                    "30 minutes",
                    Some("203.0.113.9"),
                    Some("Berlin, DE"),
                    Some("Pixel"),
                    Some("web"),
                    Some("webauthn"),
                    None,
                    None,
                )
                .await?;
                for (n, id) in [e1, e2, e3, e4, e5, e6].into_iter().enumerate() {
                    names.push(("id", id, format!("<event-{}>", n + 1)));
                }
            }
            insert(
                b.user,
                false,
                "7 minutes",
                Some("198.51.100.1"),
                Some("Madrid"),
                None,
                Some("web"),
                Some("password"),
                Some("other failure"),
                None,
            )
            .await?;
            insert(
                b.user,
                true,
                "8 minutes",
                Some("198.51.100.2"),
                Some("Rome"),
                None,
                Some("web"),
                Some("password"),
                None,
                Some(CURRENT_JTI),
            )
            .await?;
        } else {
            let fails = match label {
                "baseline" => 2,
                "success" => 1,
                _ => 0,
            };
            for n in 0..fails {
                insert(
                    a.user,
                    false,
                    if n == 0 { "1 hour" } else { "2 hours" },
                    Some("203.0.113.8"),
                    Some("Paris"),
                    None,
                    Some("web"),
                    Some("password"),
                    Some("bad"),
                    None,
                )
                .await?;
            }
            for _ in 0..4 {
                insert(
                    b.user,
                    false,
                    "3 hours",
                    Some("198.51.100.1"),
                    Some("Madrid"),
                    None,
                    Some("web"),
                    Some("password"),
                    Some("bad"),
                    None,
                )
                .await?;
            }
        }
    }
    if action == "security-score" {
        let codes = |has: bool| -> Option<Vec<String>> {
            has.then(|| vec!["c1".into(), "c2".into(), "c3".into()])
        };
        let (totp, backup): (bool, Option<Vec<String>>) = match label {
            "success" | "perfect" => (true, codes(true)),
            "empty-codes" => (true, Some(vec![])),
            "totp-only" => (true, None),
            "codes-only" => (false, codes(true)),
            _ => (false, None),
        };
        owner
            .execute(
                "UPDATE users SET totp_enabled=$2, totp_backup_codes_enc=$3 WHERE id=$1",
                &[&a.user, &totp, &backup],
            )
            .await?;
        owner
            .execute(
                "UPDATE users SET totp_enabled=TRUE, totp_backup_codes_enc=$2 WHERE id=$1",
                &[&b.user, &codes(true)],
            )
            .await?;
    }
    vars.insert("actor", a.user);
    vars.insert("other", b.user);
    Ok(Seed {
        names,
        vars,
        extra_users: vec![],
        undo: std::mem::take(&mut undo),
        text_masks,
    })
}

fn key_static(key: &str) -> &'static str {
    match key {
        "ta" => "ta",
        "ta2" => "ta2",
        "tb" => "tb",
        "tc" => "tc",
        "td" => "td",
        "te" => "te",
        "tf" => "tf",
        "tg" => "tg",
        _ => "th",
    }
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let mut path = pattern.to_owned();
    let mut query = String::new();
    let mut body = String::new();
    if action == "session-revoke" {
        let id = match label {
            "success" | "repeat" => "settings3-web2".to_owned(),
            "current" => CURRENT_JTI.to_owned(),
            "oauth-family" => var("ta").to_string(),
            "rotated-child" => var("ta2").to_string(),
            "oauth-legacy" => var("tb").to_string(),
            "app-password" => var("tc").to_string(),
            "revoked-token" => var("te").to_string(),
            "expired-token" => var("tf").to_string(),
            "foreign" => "settings3-other-web".to_owned(),
            "foreign-token" => var("o1").to_string(),
            "revoke-all-word" => "revoke-all".to_owned(),
            "encoded" => "settings3%2Dweb2".to_owned(),
            _ => "no-such-session".to_owned(),
        };
        path = format!("/user/sessions/{id}");
    }
    match (action, label) {
        (_, "ignored-query") => query = "?limit=-1&x=%zz&outcome=failed".into(),
        ("login-history", "outcome-success") => query = "?outcome=success".into(),
        ("login-history", "outcome-failed") => query = "?outcome=failed".into(),
        ("login-history", "outcome-other") => query = "?outcome=bogus".into(),
        ("login-history", "limit") => query = "?limit=2".into(),
        ("login-history", "offset") => query = "?limit=2&offset=2".into(),
        ("login-history", "offset-past-end") => query = "?offset=50".into(),
        ("login-history", "bad-limit") => query = "?limit=abc".into(),
        ("login-history", "big-limit") => query = "?limit=500".into(),
        ("login-history", "zero-limit") => query = "?limit=0".into(),
        ("login-history", "negative-offset") => query = "?limit=3&offset=-5".into(),
        ("login-history", "plus-limit") => query = "?limit=%2B3".into(),
        ("login-history", "range-limit") => query = "?limit=99999999999999999999".into(),
        ("login-history", "range-offset") => query = "?limit=2&offset=99999999999999999999".into(),
        ("login-history", "encoded-outcome") => query = "?outcome=succ%65ss".into(),
        (_, "bad-body") => body = "{not json".into(),
        _ => {}
    }
    Req {
        path,
        query,
        recorded_body: body.clone(),
        body,
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    let who = |column: &str| {
        format!(
            "CASE {column} WHEN {} THEN 'actor' WHEN {} THEN 'other' ELSE {column}::text END",
            a.user, b.user
        )
    };
    let label_of = seed
        .names
        .iter()
        .filter(|n| n.0 == "id")
        .map(|(_, id, label)| format!("WHEN {id} THEN '{label}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let label_of = if label_of.is_empty() {
        "id::text".to_owned()
    } else {
        format!("CASE id {label_of} ELSE id::text END")
    };
    let sessions = super::rows(owner, &format!("SELECT jsonb_build_object('who',{},'id',id)::text FROM sessions WHERE user_id IN ({},{}) ORDER BY user_id=0, id", who("user_id"), a.user, b.user)).await?;
    let tokens = super::rows(owner, &format!("SELECT jsonb_build_object('who',{},'token',{label_of},'revoked',revoked_at IS NOT NULL,'revoked_by',CASE WHEN revoked_by IS NULL THEN NULL ELSE {} END)::text FROM oauth_tokens WHERE user_id IN ({},{}) ORDER BY user_id=0, {label_of}", who("user_id"), who("revoked_by"), a.user, b.user)).await?;
    let revocations = super::rows(owner, &format!("SELECT jsonb_build_object('who',{},'scope',scope,'jti',jti,'family',family_id,'reason',reason,'created_by',{},'live',expires_at > now())::text FROM session_revocations WHERE user_id IN ({},{}) ORDER BY user_id=0, scope, jti, family_id", who("user_id"), who("created_by"), a.user, b.user)).await?;
    let users = super::rows(owner, &format!("SELECT jsonb_build_object('who',{},'must_change_password',must_change_password)::text FROM users WHERE id IN ({},{}) ORDER BY id=0, id", who("id"), a.user, b.user)).await?;
    Ok(json!({"sessions":sessions,"oauth_tokens":tokens,"revocations":revocations,"users":users}))
}
