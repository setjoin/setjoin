//! Slice `threat` (#326): the four threat views and the IP-rule list, create and delete.
//!
//! The threat tables (`auth_attempts`, `auth_lockouts`, `threat_feed_blocks`,
//! `rate_limit_counters`, `ip_rules`) are global, so a case stashes every row, seeds its own and
//! `teardown` removes whatever is left and puts the stash back. `auth_attempts` rows are relative
//! to the run time (a partition for their month is created on demand); the other tables hold
//! fixed 2026-10-0x times. A `view` label is `<view>-<variant>`.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

const TABLES: [&str; 5] = [
    "auth_attempts",
    "auth_lockouts",
    "threat_feed_blocks",
    "rate_limit_counters",
    "ip_rules",
];
const VIEWS: [&str; 4] = ["attempts", "lockouts", "feed-blocks", "rate-counters"];

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "view" => ("GET", "/admin/threat/{view}"),
        "ip-list" => ("GET", "/admin/threat/ip-rules"),
        "ip-create" => ("POST", "/admin/threat/ip-rules"),
        "ip-delete" => ("DELETE", "/admin/threat/ip-rules/{id}"),
        _ => panic!("unknown threat action {action}"),
    }
}

/// The permission that satisfies an action's gate (`requireLogsPerm` / `requireSecurityWrite`).
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "ip-create" | "ip-delete" => vec!["security.write"],
        _ => vec!["audit.read"],
    }
}

fn split(label: &str) -> (&str, &str) {
    for view in VIEWS {
        if let Some(rest) = label.strip_prefix(view).and_then(|r| r.strip_prefix('-')) {
            return (view, rest);
        }
    }
    ("", label)
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    let (_, variant) = split(label);
    match (action, variant) {
        (_, "denied") => Some(403),
        // A domain-scoped principal is refused the org-wide-only audit surface.
        ("view" | "ip-list", "scoped") => Some(403),
        ("view", "unknown" | "unknown-escaped") => Some(404),
        ("view", "bad-since" | "bad-utf8" | "huge-offset") => Some(500),
        ("view", _) | ("ip-list", _) => Some(200),
        ("ip-create", l) if l.starts_with("success") || l == "repeat" || l == "scoped" => {
            Some(201)
        }
        ("ip-create", "bad-expires" | "empty-expires") => Some(500),
        ("ip-create", _) => Some(400),
        ("ip-delete", "missing" | "empty" | "repeat") => Some(404),
        ("ip-delete", "bad-id" | "zero-id" | "negative-id" | "huge-id") => Some(400),
        ("ip-delete", _) => Some(204),
        _ => None,
    }
}

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut stash = vec![];
    for table in TABLES {
        for row in owner
            .query(&format!("SELECT to_jsonb(t)::text FROM {table} t"), &[])
            .await?
        {
            stash.push(format!("{table}\t{}", row.get::<_, String>(0)));
        }
    }
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; {} COMMIT;",
            TABLES
                .iter()
                .map(|t| format!("DELETE FROM {t};"))
                .collect::<String>()
        ))
        .await?;
    // `auth_attempts` has no default partition: make sure the months the seed spans exist.
    owner
        .batch_execute(
            "DO $$ DECLARE d date; BEGIN \
             FOREACH d IN ARRAY ARRAY[date_trunc('month', now() - interval '13 days')::date, date_trunc('month', now())::date] LOOP \
              IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'auth_attempts_' || to_char(d, 'YYYY_MM')) THEN \
               EXECUTE format('CREATE TABLE %I PARTITION OF auth_attempts FOR VALUES FROM (%L) TO (%L)', 'auth_attempts_' || to_char(d, 'YYYY_MM'), d, (d + interval '1 month')::date); \
              END IF; \
             END LOOP; END $$;",
        )
        .await?;
    // Rule ids are masked wherever `/{id}` appears in a path; keep them well clear of the small
    // numbers a CIDR prefix length or an octet could spell.
    owner
        .execute("SELECT setval('ip_rules_id_seq', $1)", &[&(2_000_000 + a.user * 10)])
        .await?;
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    let (_, variant) = split(label);
    if variant != "empty" {
        // Distinct outcomes, addresses and counts keep every sort deterministic.
        let attempts: [(&str, &str, &str, &str, Option<&str>, Option<&str>, &str); 6] = [
            ("203.0.113.7", "alice@x.test", "imap", "failure", Some("bad password"), Some("US"), "now() - interval '12 days' - interval '1 second'"),
            ("203.0.113.8", "bob@x.test", "smtp", "success", None, None, "now() - interval '12 days' - interval '2 seconds'"),
            ("2001:db8::1", "carol<&>@x.test", "http", "lockout", Some("too many <tries>"), Some("DE"), "now() - interval '12 days' - interval '3 seconds'"),
            ("198.51.100.9", "=cmd|' /C calc'!A0", "http", "threat_blocked", Some("=formula"), Some("CN"), "now() - interval '12 days' - interval '4 seconds'"),
            ("192.0.2.44", "\u{e9}milie@x.test", "http", "rate_limited", Some(""), Some("FR"), "now() - interval '2 hours'"),
            ("192.0.2.45", "dave@x.test", "pop3", "geo_blocked", Some("blocked, \"quoted\""), Some("RU"), "now() - interval '10 days'"),
        ];
        for (ip, user, protocol, outcome, reason, geo, at) in attempts {
            owner
                .execute(
                    &format!("INSERT INTO auth_attempts (source_ip,target_username,protocol,outcome,failure_reason,geo_country,occurred_at) VALUES ($1::text::inet,$2,$3,$4,$5,$6,{at})"),
                    &[&ip, &user, &protocol, &outcome, &reason, &geo],
                )
                .await?;
        }
        let lockouts: [(&str, i32, &str, i32, &str); 5] = [
            ("ip:203.0.113.7", 5, "2026-10-05T10:00:00Z", 2, "2026-10-01T10:00:05Z"),
            ("user:alice@x.test", 3, "2026-10-04T10:00:00Z", 1, "2026-10-01T10:00:04Z"),
            ("user:=SUM(A1)", 8, "2026-10-06T10:00:00.25Z", 3, "2026-10-01T10:00:03.5Z"),
            ("ip:2001:db8::7", 1, "2026-10-03T10:00:00Z", 0, "2026-10-01T10:00:02Z"),
            ("user:bob<&>", 2, "2026-10-02T10:00:00Z", 0, "2026-10-01T10:00:01Z"),
        ];
        for (key, failed, until, level, updated) in lockouts {
            owner
                .execute(
                    "INSERT INTO auth_lockouts (lockout_key,failed_count,locked_until,escalation_level,updated_at) VALUES ($1,$2,$3::text::timestamptz,$4,$5::text::timestamptz)",
                    &[&key, &failed, &until, &level, &updated],
                )
                .await?;
        }
        let feeds: [(&str, &str, &str); 4] = [
            ("192.0.2.0/24", "spamhaus-drop", "2026-10-01T10:00:04Z"),
            ("198.51.100.0/24", "dshield", "2026-10-01T10:00:03Z"),
            ("203.0.113.0/25", "=feed(evil)", "2026-10-01T10:00:02.125Z"),
            ("2001:db8:1::/48", "tor \u{fc}nicode", "2026-10-01T10:00:01Z"),
        ];
        for (cidr, source, added) in feeds {
            owner
                .execute(
                    "INSERT INTO threat_feed_blocks (cidr,source,added_at) VALUES ($1::text::inet,$2,$3::text::timestamptz)",
                    &[&cidr, &source, &added],
                )
                .await?;
        }
        let rates: [(&str, i32, &str, Option<&str>); 5] = [
            ("ip:203.0.113.7", 40, "2026-10-01T10:00:05Z", Some("2026-10-01T10:05:05Z")),
            ("login:alice", 5, "2026-10-01T10:00:04Z", None),
            ("api:key-1", 120, "2026-10-01T10:00:03.5Z", Some("2026-10-01T11:00:03Z")),
            ("ip:198.51.100.9", 7, "2026-10-01T10:00:02Z", Some("2026-10-01T10:30:02Z")),
            ("@weird,key", 1, "2026-10-01T10:00:01Z", Some("2026-10-01T10:10:01Z")),
        ];
        for (key, count, start, blocked) in rates {
            owner
                .execute(
                    "INSERT INTO rate_limit_counters (key,count,window_start,blocked_until) VALUES ($1,$2,$3::text::timestamptz,$4::text::timestamptz)",
                    &[&key, &count, &start, &blocked],
                )
                .await?;
        }
        let rules: [(&str, &str, &str, Option<&str>, &str, Option<i64>); 4] = [
            ("10.0.0.0/8", "block", "internal <net> & co", None, "2026-10-01T10:00:04Z", Some(a.user)),
            ("198.51.100.0/24", "allow", "partner", Some("2026-12-31T00:00:00Z"), "2026-10-01T10:00:03Z", Some(b.user)),
            ("2001:db8::/32", "block", "v6 range", None, "2026-10-01T10:00:02Z", None),
            ("203.0.113.9/32", "block", "\u{e9} unicode", Some("2026-10-02T00:00:00Z"), "2026-10-01T10:00:01Z", Some(a.user)),
        ];
        for (n, (cidr, act, description, expires, created, by)) in rules.into_iter().enumerate() {
            let id: i64 = owner
                .query_one(
                    "INSERT INTO ip_rules (cidr,action,description,expires_at,created_at,created_by) VALUES ($1::text::inet,$2,$3,$4::text::timestamptz,$5::text::timestamptz,$6) RETURNING id",
                    &[&cidr, &act, &description, &expires, &created, &by],
                )
                .await?
                .get(0);
            let key: &'static str = ["r1", "r2", "r3", "r4"][n];
            vars.insert(key, id);
            names.push(("id", id, format!("<{key}>")));
            names.push(("target_id", id, format!("<{key}>")));
        }
    }
    // The ids a create will take (the sequence is not shared with anything else in the case).
    let next: i64 = owner
        .query_one("SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END FROM ip_rules_id_seq", &[])
        .await?
        .get(0);
    for (n, label) in ["<new>", "<new2>"].into_iter().enumerate() {
        names.push(("id", next + n as i64, label.into()));
        names.push(("target_id", next + n as i64, label.into()));
    }
    for (account, who) in [(a, "actor"), (b, "other")] {
        names.push(("createdBy", account.user, format!("<{who}>")));
        names.push(("created_by", account.user, format!("<{who}>")));
    }
    let _ = action;
    Ok(Seed { stash, names, vars })
}

/// Removes whatever the case left in the threat tables and restores the stash.
pub async fn teardown(owner: &tokio_postgres::Client, seed: &Seed) -> Result<(), BoxError> {
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; {} COMMIT;",
            TABLES
                .iter()
                .map(|t| format!("DELETE FROM {t};"))
                .collect::<String>()
        ))
        .await?;
    for entry in &seed.stash {
        let (table, row) = entry.split_once('\t').ok_or("stash entry")?;
        owner
            .batch_execute("BEGIN; SET LOCAL session_replication_role=replica;")
            .await?;
        owner
            .execute(
                &format!("INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1::text::jsonb)"),
                &[&row],
            )
            .await?;
        owner.batch_execute("COMMIT;").await?;
    }
    Ok(())
}

/// The query of a `view` case, per view where the column names differ.
fn view_query(view: &str, variant: &str) -> String {
    let sort = |attempts: &str, lockouts: &str, feed: &str, rate: &str| {
        match view {
            "attempts" => attempts,
            "lockouts" => lockouts,
            "feed-blocks" => feed,
            _ => rate,
        }
        .to_owned()
    };
    match variant {
        "limit" => "?limit=2".into(),
        "offset" => "?limit=2&offset=2".into(),
        "big-limit" => "?limit=9999".into(),
        "bad-limit" => "?limit=abc&offset=zz".into(),
        "zero-limit" => "?limit=0".into(),
        "negative-offset" => "?offset=-5".into(),
        "huge-offset" => "?offset=3000000000".into(),
        "sort" => sort(
            "?sort=source_ip&dir=asc",
            "?sort=failed_count&dir=asc",
            "?sort=source",
            "?sort=window_start&dir=asc",
        ),
        "sort-desc" => sort(
            "?sort=OUTCOME&dir=desc",
            "?sort=updated_at&dir=DESC",
            "?sort=source&dir=desc",
            "?sort=blocked_until&dir=desc",
        ),
        "sort-bad" => "?sort=id&dir=desc".into(),
        "sort-injection" => "?sort=occurred_at%3B+DROP+TABLE+auth_attempts&dir=asc".into(),
        "query" => sort("?q=alice", "?q=alice", "?q=drop", "?q=ip:203"),
        "query-address" => "?q=203.0.113".into(),
        "query-wildcard" => "?q=%25".into(),
        "query-none" => "?q=zzz-no-match".into(),
        "since" => "?since=24h".into(),
        "since-days" => "?since=7+days".into(),
        "since-wide" => "?since=30+days".into(),
        "since-ignored" => "?since=bogus".into(),
        "bad-since" => "?since=bogus".into(),
        "bad-utf8" => "?q=%ff".into(),
        "csv" => "?format=csv".into(),
        "csv-limit" => "?format=csv&limit=2&offset=1".into(),
        "csv-sorted" => "?format=csv&q=a".into(),
        "csv-upper" => "?format=CSV".into(),
        "ignored-query" => "?x=%zz&format=json&unknown=1".into(),
        _ => String::new(),
    }
}

fn create_body(variant: &str) -> String {
    let rule = |cidr: &str, action: &str, description: &str| {
        json!({"cidr": cidr, "action": action, "description": description}).to_string()
    };
    match variant {
        "success-expires" => json!({"cidr":"192.0.2.0/24","action":"block","description":"scanner","expiresAt":"2027-01-01T00:00:00Z"}).to_string(),
        "success-null-expires" => r#"{"cidr":"2001:db8:ffff::/48","action":"allow","description":"v6 <ok> & fine","expiresAt":null}"#.into(),
        "success-nonmasked" => rule("198.51.100.77/24", "block", "host bits set"),
        "success-extra-fields" => r#"{"cidr":"192.0.2.0/25","action":"block","description":"extra","createdBy":999999,"id":5,"unknown":[1]}"#.into(),
        "success-case-keys" => r#"{"CIDR":"192.0.2.128/25","Action":"allow","DESCRIPTION":"folded","ExpiresAt":"2027-02-03T04:05:06+02:00"}"#.into(),
        "success-trailing" => r#"{"cidr":"192.0.2.0/26","action":"block","description":"trailing"} trailing text"#.into(),
        "success-v4mapped" => rule("::ffff:192.0.2.1/128", "block", "mapped"),
        "invalid-json" => "{".into(),
        "empty-body" => String::new(),
        "array-body" => "[]".into(),
        "null-body" => "null".into(),
        "wrong-type" => r#"{"cidr":5,"action":"block","description":"x"}"#.into(),
        "wrong-type-expires" => r#"{"cidr":"192.0.2.0/24","action":"block","description":"x","expiresAt":5}"#.into(),
        "bad-cidr-nomask" => rule("192.0.2.1", "block", "x"),
        "bad-cidr-text" => rule("not-an-ip/8", "block", "x"),
        "bad-cidr-octet" => rule("256.0.0.1/8", "block", "x"),
        "bad-cidr-bits" => rule("10.0.0.0/33", "block", "x"),
        "bad-cidr-bits-text" => rule("10.0.0.0/x", "block", "x"),
        "bad-cidr-bits-zero-pad" => rule("10.0.0.0/08", "block", "x"),
        "bad-cidr-zone" => rule("fe80::1%eth0/64", "block", "x"),
        "bad-cidr-short" => rule("10.0/8", "block", "x"),
        "bad-cidr-leading-zero" => rule("010.0.0.0/8", "block", "x"),
        "bad-cidr-unicode" => rule("10.0.0.\u{e9}/8", "block", "x"),
        "bad-cidr-control" => rule("10.0.0.0\u{1}/8", "block", "x"),
        "bad-cidr-v6" => rule("1::2::3/64", "block", "x"),
        "bad-cidr-v6-bits" => rule("::1/129", "block", "x"),
        "bad-cidr-embedded" => rule("::1.2.3/96", "block", "x"),
        "bad-cidr-empty" => rule("", "block", "x"),
        "bad-action" => rule("192.0.2.0/24", "permit", "x"),
        "bad-action-case" => rule("192.0.2.0/24", "Block", "x"),
        "bad-action-quote" => rule("192.0.2.0/24", "a\"b<c>", "x"),
        "no-description" => rule("192.0.2.0/24", "block", ""),
        "bad-expires" => json!({"cidr":"192.0.2.0/24","action":"block","description":"x","expiresAt":"not a time"}).to_string(),
        "empty-expires" => json!({"cidr":"192.0.2.0/24","action":"block","description":"x","expiresAt":""}).to_string(),
        _ => rule("192.0.2.0/24", "block", "scanner <bad> & co"),
    }
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let (view, variant) = split(label);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let mut req = Req {
        path: pattern.to_owned(),
        query: String::new(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        headers: vec![],
    };
    match action {
        "view" => {
            req.path = match label {
                "unknown" => "/admin/threat/bogus".to_owned(),
                "unknown-escaped" => "/admin/threat/%3Cb%3E%26x".to_owned(),
                // The persona cases (`denied`, `scoped`) read the attempts view.
                _ if view.is_empty() => "/admin/threat/attempts".to_owned(),
                _ => format!("/admin/threat/{view}"),
            };
            req.query = view_query(view, variant);
        }
        "ip-list" => {
            req.query = match variant {
                "limit" => "?limit=2".into(),
                "offset" => "?limit=2&offset=1".into(),
                "big-limit" => "?limit=9999".into(),
                "bad-limit" => "?limit=abc&offset=zz".into(),
                "zero-limit" => "?limit=0".into(),
                "negative-offset" => "?offset=-5".into(),
                "ignored-query" => "?x=%zz&sort=id".into(),
                _ => String::new(),
            };
        }
        "ip-create" => {
            req.body = create_body(variant);
            req.recorded_body = req.body.clone();
        }
        "ip-delete" => {
            let id = match variant {
                "bad-id" => "abc".to_owned(),
                "zero-id" => "0".to_owned(),
                "negative-id" => "-4".to_owned(),
                "huge-id" => "99999999999999999999".to_owned(),
                "missing" | "empty" => "999999999".to_owned(),
                "plus-id" => format!("%2B{}", var("r2")),
                "success-v6" => var("r3").to_string(),
                _ => var("r1").to_string(),
            };
            req.path = pattern.replace("{id}", &id);
        }
        _ => panic!("unknown threat action {action}"),
    }
    req
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    _a: &Account,
    _b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let text: String = owner
        .query_one(
            "SELECT jsonb_build_object('ip_rules',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM ip_rules r),\
             'attempts',(SELECT count(*) FROM auth_attempts),'lockouts',(SELECT count(*) FROM auth_lockouts),\
             'feed_blocks',(SELECT count(*) FROM threat_feed_blocks))::text",
            &[],
        )
        .await?
        .get(0);
    Ok(serde_json::from_str(&text)?)
}

/// The shared masks, then this slice's: the scoped admin's domain id inside the audited denial
/// text, and the day stamp of a CSV download's file name.
pub fn mask_text(text: &str, scoped_domain: &str) -> String {
    let mut out = text.replace(&format!("domain={scoped_domain})"), "domain=<other-domain>)");
    // A rule id the shared masks cannot see: percent-encoded `+id` in a path, and the id in
    // Go's 404 text.
    for (head, tail, label) in [("%2B", "", "<id>"), ("ip_rule ", " not found", "<id>")] {
        let mut rest = out.as_str();
        let mut done = String::new();
        while let Some(at) = rest.find(head) {
            let digits = rest[at + head.len()..].bytes().take_while(u8::is_ascii_digit).count();
            let end = at + head.len() + digits;
            if digits > 0 && rest[end..].starts_with(tail) {
                done.push_str(&rest[..at + head.len()]);
                done.push_str(label);
            } else {
                done.push_str(&rest[..end]);
            }
            rest = &rest[end..];
        }
        done.push_str(rest);
        out = done;
    }
    for key in ["threat-attempts-", "threat-lockouts-", "threat-feed-blocks-", "threat-rate-counters-"] {
        while let Some(at) = out.find(key).filter(|at| {
            let digits = &out[at + key.len()..];
            digits.len() >= 12 && digits.as_bytes()[..8].iter().all(u8::is_ascii_digit) && digits[8..].starts_with(".csv")
        }) {
            let start = at + key.len();
            out.replace_range(start..start + 8, "<date>");
        }
    }
    out
}
