//! Slice `dlp` (#325): DLP patterns, anti-phishing configuration and the link-protect audit
//! list. `dlp_policies`, the `antiphish%` configuration rows and `link_protect_audit` are
//! global, so a case moves every row it did not seed aside (triggers off) and `teardown`
//! removes its own rows and puts the others back.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "patterns-get" => ("GET", "/admin/dlp/patterns"),
        "patterns-put" => ("PUT", "/admin/dlp/patterns"),
        "anti-get" => ("GET", "/admin/anti-phish"),
        "anti-put" => ("PUT", "/admin/anti-phish"),
        "audit" => ("GET", "/admin/link-protect/audit"),
        _ => panic!("unknown dlp action {action}"),
    }
}

/// The permission that satisfies an action's gate.
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "patterns-put" => vec!["mail.security"],
        "anti-put" => vec!["security.write"],
        "audit" => vec!["audit.read"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        (_, "denied") => Some(403),
        ("audit", "scoped") | ("patterns-put", "scoped") => Some(403),
        ("audit", "bad-since") => Some(400),
        ("patterns-put", "violation-blocks") => Some(500),
        ("patterns-put", "invalid-json" | "wrong-type" | "bad-field" | "bad-id" | "empty-body") => {
            Some(400)
        }
        ("anti-put", "invalid-json" | "wrong-type" | "empty-body" | "bad-list") => Some(400),
        ("patterns-put", _) => Some(200),
        ("anti-put", _) => Some(204),
        _ => Some(200),
    }
}

const TABLES: [(&str, &str); 3] = [
    ("dlp_policies", "TRUE"),
    ("system_config", "key LIKE 'antiphish%'"),
    ("link_protect_audit", "TRUE"),
];

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    // Move every foreign row aside so reads show exactly this case's rows.
    let mut stash = vec![];
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica;")
        .await?;
    for (table, filter) in TABLES {
        for row in owner
            .query(
                &format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {filter}"),
                &[],
            )
            .await?
        {
            stash.push(format!("{table}|{}", row.get::<_, String>(0)));
        }
        if table == "dlp_policies" {
            owner.batch_execute("DELETE FROM dlp_violations").await?;
        }
        owner
            .batch_execute(&format!("DELETE FROM {table} WHERE {filter}"))
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    match action {
        "patterns-get" | "patterns-put" if label != "empty" => {
            // (name, regex, action, enabled, domain, is_pattern, priority)
            let rows: [(&str, &str, &str, bool, Option<i64>, bool, i32); 8] = [
                (
                    "p2 <card> & co",
                    "\\b\\d{16}\\b",
                    "quarantine",
                    true,
                    None,
                    true,
                    1,
                ),
                (
                    "p1 ssn",
                    "\\b\\d{3}-\\d{2}-\\d{4}\\b",
                    "block",
                    true,
                    None,
                    true,
                    0,
                ),
                ("p4 low", "secret", "warn", false, None, true, 3),
                (
                    "p3 mail",
                    "[a-z]+@[a-z]+",
                    "notify_admin",
                    true,
                    None,
                    true,
                    2,
                ),
                ("a-own", "alpha", "block", true, Some(a.domain), true, 4),
                (
                    "b-own",
                    "bravo",
                    "quarantine",
                    true,
                    Some(b.domain),
                    true,
                    5,
                ),
                ("policy-not-pattern", "x", "block", true, None, false, 6),
                ("p5 same-priority", "tie", "block", true, None, true, 1),
            ];
            for (i, (name, regex, act, enabled, domain, pattern, priority)) in
                rows.iter().enumerate()
            {
                let id: i64 = owner
                    .query_one(
                        "INSERT INTO dlp_policies (name,regex_patterns,action,enabled,domain_id,is_pattern,priority,applies_to_all) \
                         VALUES ($1,ARRAY[$2],$3,$4,$5,$6,$7,true) RETURNING id",
                        &[name, regex, act, enabled, domain, pattern, priority],
                    )
                    .await?
                    .get(0);
                vars.insert(["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"][i], id);
                names.push(("id", id, format!("<d{i}>")));
            }
            if label == "violation-blocks" {
                owner
                    .execute(
                        "INSERT INTO dlp_violations (policy_id,mailbox_id,violation_type,action_taken) VALUES ($1,$2,'regex','blocked')",
                        &[&vars["d0"], &a.mailbox],
                    )
                    .await?;
            }
        }
        "anti-get" if label != "defaults" => {
            let rows: &[(&str, &str)] = match label {
                "mixed" => &[
                    ("antiphish_display_name", "\"true\""),
                    ("antiphish_lookalike", "\"True\""),
                    ("antiphish_contact_graph", "1"),
                    ("antiphish_strict_mode", "true"),
                    ("antiphish_exclusion_domains", "null"),
                    ("antiphish_exclusion_users", "{\"a\":1}"),
                ],
                "bad-list" => &[
                    ("antiphish_display_name", "false"),
                    ("antiphish_exclusion_domains", "[1,2]"),
                    ("antiphish_exclusion_users", "[\"u@x.test\",null,\"<b>\"]"),
                ],
                "string-lists" => &[
                    ("antiphish_exclusion_domains", "\"[\\\"x.test\\\"]\""),
                    ("antiphish_exclusion_users", "\"\""),
                ],
                _ => &[
                    ("antiphish_display_name", "false"),
                    ("antiphish_lookalike", "false"),
                    ("antiphish_contact_graph", "true"),
                    ("antiphish_strict_mode", "true"),
                    ("antiphish_exclusion_domains", "[\"a.test\",\"b & c.test\"]"),
                    ("antiphish_exclusion_users", "[\"ceo@a.test\"]"),
                ],
            };
            for (k, v) in rows {
                owner
                    .execute(
                        "INSERT INTO system_config (key,value) VALUES ($1,$2::text::jsonb)",
                        &[k, v],
                    )
                    .await?;
            }
        }
        "anti-put" if label == "overwrite" || label == "repeat" => {
            for (k, v) in [
                ("antiphish_display_name", "false"),
                ("antiphish_exclusion_users", "[\"old@x.test\"]"),
            ] {
                owner
                    .execute("INSERT INTO system_config (key,value,description) VALUES ($1,$2::text::jsonb,'seeded')", &[&k, &v])
                    .await?;
            }
        }
        "audit" if label != "empty" => {
            // (hash, verdict, scanner, message, mailbox, ip, created)
            let mut rows: Vec<(String, &str, &str, Option<i64>, i64, Option<&str>, &str)> = vec![
                (
                    "hash-a".into(),
                    "safe",
                    "spamhaus",
                    Some(11),
                    a.mailbox,
                    Some("10.0.0.1"),
                    "2026-10-05T10:00:00Z",
                ),
                (
                    "hash-b".into(),
                    "malicious",
                    "safebrowsing",
                    Some(12),
                    b.mailbox,
                    Some("10.0.0.2"),
                    "2026-10-04T10:00:00Z",
                ),
                (
                    "hash-a".into(),
                    "unknown",
                    "pipeline",
                    Some(13),
                    a.mailbox,
                    Some("::1"),
                    "2026-10-03T10:00:00.123456Z",
                ),
                (
                    "hash-c".into(),
                    "safe",
                    "spamhaus",
                    Some(14),
                    a.mailbox,
                    Some(""),
                    "2026-10-02T10:00:00Z",
                ),
                (
                    "hash-d".into(),
                    "safe",
                    "spamhaus",
                    Some(15),
                    a.mailbox,
                    Some("10.0.0.5"),
                    "2026-10-01T10:00:00Z",
                ),
            ];
            if label == "null-message" {
                rows[1].3 = None;
            }
            if label == "null-ip" {
                rows[2].5 = None;
            }
            for (i, (hash, verdict, scanner, message, mailbox, ip, at)) in rows.iter().enumerate() {
                let id: i64 = owner
                    .query_one(
                        "INSERT INTO link_protect_audit (url_hash,verdict,scanner,message_id,mailbox_id,client_ip,created_at) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7::text::timestamptz) RETURNING id",
                        &[hash, verdict, scanner, message, mailbox, ip, at],
                    )
                    .await?
                    .get(0);
                vars.insert(["l0", "l1", "l2", "l3", "l4"][i], id);
                names.push(("id", id, format!("<l{i}>")));
            }
        }
        _ => {}
    }
    for (account, who) in [(a, "actor"), (b, "other")] {
        names.push(("mailbox_id", account.mailbox, format!("<mailbox-{who}>")));
    }
    Ok(Seed { stash, names, vars })
}

/// Removes this case's rows, then restores the rows moved aside.
pub async fn teardown(owner: &tokio_postgres::Client, seed: &Seed) -> Result<(), BoxError> {
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica;")
        .await?;
    owner.batch_execute("DELETE FROM dlp_violations").await?;
    for (table, filter) in TABLES {
        owner
            .batch_execute(&format!("DELETE FROM {table} WHERE {filter}"))
            .await?;
    }
    for row in &seed.stash {
        let (table, json) = row.split_once('|').ok_or("stash row")?;
        owner
            .execute(
                &format!("INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1::text::jsonb)"),
                &[&json],
            )
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    Ok(())
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let _ = seed;
    let body = match (action, label) {
        ("patterns-put", "empty-body") | ("anti-put", "empty-body") => String::new(),
        ("patterns-put", "invalid-json") | ("anti-put", "invalid-json") => "{".into(),
        ("patterns-put", "wrong-type") => "{\"name\":\"x\"}".into(),
        ("patterns-put", "bad-field") => "[{\"name\":5}]".into(),
        ("patterns-put", "bad-id") => "[{\"id\":\"x\",\"name\":\"n\"}]".into(),
        ("patterns-put", "empty-array") => "[]".into(),
        ("patterns-put", "null") => "null".into(),
        ("patterns-put", "null-element") => "[null,{\"name\":\"after\"}]".into(),
        ("patterns-put", "folded-keys") => "[{\"ID\":7,\"NAME\":\"Up\",\"Regex\":\"r\",\"SEVERITY\":\"high\",\"Enabled\":true,\"extra\":[1]}]".into(),
        ("patterns-put", "severities") => "[{\"name\":\"c\",\"regex\":\"1\",\"severity\":\"critical\",\"enabled\":true},{\"name\":\"h\",\"regex\":\"2\",\"severity\":\"high\",\"enabled\":true},{\"name\":\"m\",\"regex\":\"3\",\"severity\":\"medium\",\"enabled\":false},{\"name\":\"l\",\"regex\":\"4\",\"severity\":\"low\"},{\"name\":\"u\",\"regex\":\"5\",\"severity\":\"bogus\",\"enabled\":null},{\"name\":\"e\",\"regex\":\"\",\"severity\":\"\"}]".into(),
        ("patterns-put", "escapes") => "[{\"name\":\"<b>&\\u2028 'q'\",\"regex\":\"[<>&]\\\\d\",\"severity\":\"high\",\"enabled\":true}]".into(),
        ("patterns-put", "trailing") => "[{\"name\":\"t\",\"regex\":\"r\",\"severity\":\"low\",\"enabled\":true}] garbage".into(),
        ("patterns-put", _) => "[{\"id\":99,\"name\":\"ssn\",\"regex\":\"\\\\d{3}\",\"severity\":\"critical\",\"enabled\":true},{\"name\":\"card\",\"regex\":\"\\\\d{16}\",\"severity\":\"high\",\"enabled\":false}]".into(),
        ("anti-put", "defaults-body") => "{}".into(),
        ("anti-put", "null-lists") => "{\"display_name_enabled\":true,\"exclusion_domains\":null,\"exclusion_users\":null}".into(),
        ("anti-put", "empty-lists") => "{\"exclusion_domains\":[],\"exclusion_users\":[]}".into(),
        ("anti-put", "folded-keys") => "{\"Display_Name_Enabled\":true,\"LOOKALIKE_ENABLED\":true,\"Strict_Mode\":true,\"Exclusion_Domains\":[\"<x>&.test\"],\"unknown\":1}".into(),
        ("anti-put", "wrong-type") => "{\"strict_mode\":\"yes\"}".into(),
        ("anti-put", "bad-list") => "{\"exclusion_domains\":[1]}".into(),
        ("anti-put", "null-bool") => "{\"display_name_enabled\":null,\"strict_mode\":true}".into(),
        ("anti-put", "trailing") => "{\"strict_mode\":true} garbage".into(),
        ("anti-put", _) => "{\"display_name_enabled\":true,\"lookalike_enabled\":false,\"contact_graph_enabled\":true,\"strict_mode\":true,\"exclusion_domains\":[\"a.test\",\"b.test\"],\"exclusion_users\":[\"ceo@a.test\"]}".into(),
        _ => String::new(),
    };
    let query = match (action, label) {
        ("audit", "since") => "?since=2026-10-03T00:00:00Z",
        ("audit", "since-offset") => "?since=2026-10-03T12:00:00%2B02:00",
        ("audit", "since-fraction") => "?since=2026-10-03T10:00:00.5Z",
        ("audit", "zero-since") => "?since=0001-01-01T00:00:00Z",
        ("audit", "bad-since") => "?since=yesterday",
        ("audit", "url-hash") => "?url_hash=hash-a",
        ("audit", "url-hash-since") => "?url_hash=hash-a&since=2026-10-04T00:00:00Z",
        ("audit", "limit") => "?limit=2",
        ("audit", "bad-limit") => "?limit=abc",
        ("audit", "zero-limit") => "?limit=0",
        ("audit", "negative-limit") => "?limit=-3",
        ("audit", "big-limit") => "?limit=101",
        ("audit", "max-limit") => "?limit=100",
        ("audit", "no-match") => "?url_hash=nothing",
        (_, "ignored-query") => "?x=%zz&limit=1",
        _ => "",
    };
    Req {
        path: pattern.to_string(),
        query: query.to_string(),
        recorded_query: String::new(),
        body: body.clone(),
        recorded_body: body,
        headers: vec![],
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    _a: &Account,
    _b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let policies = super::rows(
        owner,
        "SELECT (to_jsonb(p) - 'id' - 'created_at' - 'updated_at' - 'domain_id')::text || '' FROM dlp_policies p ORDER BY priority, name, id",
    )
    .await?;
    let config = super::rows(
        owner,
        "SELECT jsonb_build_object('key',key,'value',value,'description',description,'encrypted',encrypted)::text FROM system_config WHERE key LIKE 'antiphish%' ORDER BY key",
    )
    .await?;
    let violations: i64 = owner
        .query_one("SELECT count(*) FROM dlp_violations", &[])
        .await?
        .get(0);
    let audit: i64 = owner
        .query_one("SELECT count(*) FROM link_protect_audit", &[])
        .await?
        .get(0);
    Ok(json!({"policies":policies,"config":config,"violations":violations,"audit_rows":audit}))
}
