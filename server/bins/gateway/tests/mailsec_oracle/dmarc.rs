//! Slice `dmarc` (#324): the DMARC live, failures and trend reads and the auth log.
//!
//! `dmarc_reports` and `auth_event_log` are global tables, so a case moves every row it
//! did not seed aside (triggers off) and `teardown` removes its own rows and puts the
//! others back. Dates are relative to the run day: `mask_days` renders them `<today-N>`.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "live" => ("GET", "/admin/dmarc/live"),
        "failures" => ("GET", "/admin/dmarc/failures"),
        "trend" => ("GET", "/admin/dmarc/trend"),
        "auth-log" => ("GET", "/admin/auth-log"),
        _ => panic!("unknown dmarc action {action}"),
    }
}

/// The permission that satisfies an action's gate (`requireMailPerm` / `requireLogsPerm`).
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "auth-log" => vec!["audit.read"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        (_, "denied") => Some(403),
        // A domain-scoped principal is refused the org-wide-only audit surface.
        ("auth-log", "scoped") => Some(403),
        _ => Some(200),
    }
}

const DAY: &str = "date_trunc('day', now() AT TIME ZONE 'UTC')";

/// `(domain key, begin offset (SQL), end offset (SQL), none, pass, fail, temperror, permerror)`.
/// Rows whose end is today's midnight are the ones the live view counts.
struct Report {
    domain: &'static str,
    begin: &'static str,
    end: &'static str,
    counts: [i32; 5],
}

const REPORTS: [Report; 7] = [
    Report {
        domain: "a",
        begin: "- interval '1 day'",
        end: "",
        counts: [1, 5, 2, 3, 1],
    },
    Report {
        domain: "a",
        begin: "- interval '23 hours'",
        end: "",
        counts: [0, 1, 1, 0, 0],
    },
    Report {
        domain: "a",
        begin: "- interval '3 days'",
        end: "- interval '2 days'",
        counts: [2, 4, 0, 0, 0],
    },
    Report {
        domain: "a",
        begin: "- interval '40 days'",
        end: "- interval '39 days'",
        counts: [9, 9, 9, 9, 9],
    },
    Report {
        domain: "b",
        begin: "- interval '1 day'",
        end: "",
        counts: [0, 7, 9, 0, 0],
    },
    Report {
        domain: "b",
        begin: "- interval '2 days'",
        end: "- interval '1 day'",
        counts: [3, 3, 3, 0, 0],
    },
    Report {
        domain: "orphan.dmarc-oracle.test",
        begin: "- interval '1 day'",
        end: "",
        counts: [0, 2, 0, 0, 0],
    },
];

struct Event {
    key: &'static str,
    user: Option<bool>,
    email: Option<&'static str>,
    event: &'static str,
    provider: &'static str,
    ip: Option<&'static str>,
    age: &'static str,
}

const EVENTS: [Event; 6] = [
    Event {
        key: "e1",
        user: Some(true),
        email: Some("owner@auth-oracle.test"),
        event: "login",
        provider: "bcrypt",
        ip: Some("10.0.0.1"),
        age: "1 hour",
    },
    Event {
        key: "e2",
        user: None,
        email: Some("ghost@auth-oracle.test"),
        event: "login_failed",
        provider: "ldap",
        ip: Some("2001:db8::1"),
        age: "2 hours",
    },
    Event {
        key: "e3",
        user: Some(true),
        email: None,
        event: "login",
        provider: "webauthn",
        ip: Some("10.0.0.3"),
        age: "3 hours",
    },
    Event {
        key: "e4",
        user: Some(false),
        email: Some("Mixed@Case-Oracle.test"),
        event: "login",
        provider: "basic",
        ip: None,
        age: "4 hours",
    },
    Event {
        key: "e5",
        user: Some(true),
        email: Some("owner@auth-oracle.test"),
        event: "login_failed",
        provider: "bcrypt",
        ip: Some("10.0.0.5"),
        age: "3 days",
    },
    Event {
        key: "e6",
        user: None,
        email: Some("kerb@auth-oracle.test"),
        event: "login",
        provider: "kerberos",
        ip: Some("192.0.2.77"),
        age: "30 minutes",
    },
];

/// `(sender, spf, dkim, dmarc, age, belongs to actor)`.
const MESSAGES: [(&str, Option<&str>, Option<&str>, &str, &str, bool); 7] = [
    (
        "f1@dmarc-oracle.test",
        Some("pass"),
        Some("fail"),
        "fail",
        "10 minutes",
        true,
    ),
    (
        "f2@dmarc-oracle.test",
        None,
        None,
        "fail",
        "20 minutes",
        true,
    ),
    (
        "f3@dmarc-oracle.test",
        Some("softfail"),
        Some("none"),
        "fail",
        "5 hours",
        true,
    ),
    (
        "ok@dmarc-oracle.test",
        Some("pass"),
        Some("pass"),
        "pass",
        "15 minutes",
        true,
    ),
    (
        "old@dmarc-oracle.test",
        Some("fail"),
        Some("fail"),
        "fail",
        "30 hours",
        true,
    ),
    (
        "g1@dmarc-oracle.test",
        Some("fail"),
        Some("pass"),
        "fail",
        "25 minutes",
        false,
    ),
    (
        "g2@dmarc-oracle.test",
        Some("pass"),
        None,
        "fail",
        "2 hours",
        false,
    ),
];

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut stash = vec![];
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    if action != "auth-log" {
        // The reads observe the global auth log's row count (recorded as 0); rows other suites
        // left behind are moved aside like the `auth-log` case does, and restored by `teardown`.
        for row in owner
            .query("SELECT 'a:' || to_jsonb(e)::text FROM auth_event_log e", &[])
            .await?
        {
            stash.push(row.get::<_, String>(0));
        }
        owner
            .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM auth_event_log; COMMIT;")
            .await?;
    }
    for account in [a, b] {
        let who = if account.user == a.user {
            "actor"
        } else {
            "other"
        };
        names.push(("userId", account.user, format!("<{who}>")));
    }
    let empty = label == "empty";
    let domain_of = |id: i64| async move {
        owner
            .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
            .await
            .map(|r| r.get::<_, String>(0))
    };
    match action {
        "live" | "trend" => {
            // The fixture's domain names are random, and the live view sorts by name: give both
            // account domains fixed names so the per-domain order is stable across runs.
            for (account, name) in [(a, "a.dmarc5-oracle.test"), (b, "b.dmarc5-oracle.test")] {
                owner
                    .execute(
                        "UPDATE domains SET name=$2 WHERE id=$1",
                        &[&account.domain, &name],
                    )
                    .await?;
            }
            for row in owner
                .query("SELECT 'd:' || to_jsonb(r)::text FROM dmarc_reports r", &[])
                .await?
            {
                stash.push(row.get::<_, String>(0));
            }
            owner
                .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM dmarc_reports; COMMIT;")
                .await?;
            if !empty {
                for r in &REPORTS {
                    let domain: String = match r.domain {
                        "a" => domain_of(a.domain).await?,
                        "b" => domain_of(b.domain).await?,
                        other => other.to_owned(),
                    };
                    let end = if r.end.is_empty() {
                        DAY.to_owned()
                    } else {
                        format!("{DAY} {}", r.end)
                    };
                    let sql = format!(
                        "INSERT INTO dmarc_reports (domain, report_uri, begin_time, end_time, total_count, count_none, count_pass, count_fail, count_temperror, count_permperror, policy_domain, policy_pct) \
                         VALUES ($1,'mailto:rua@dmarc-oracle.test',{DAY} {},{end},$2,$3,$4,$5,$6,$7,$1,100)",
                        r.begin
                    );
                    let c = r.counts;
                    owner
                        .execute(
                            &sql,
                            &[
                                &domain,
                                &c.iter().sum::<i32>(),
                                &c[0],
                                &c[1],
                                &c[2],
                                &c[3],
                                &c[4],
                            ],
                        )
                        .await?;
                }
            }
        }
        "failures" => {
            if !empty {
                for (n, (from, spf, dkim, dmarc, age, mine)) in MESSAGES.iter().enumerate() {
                    let account = if *mine { a } else { b };
                    let key = format!("dmarc5-{n}-{}", account.user);
                    let id: i64 = owner
                        .query_one(
                            &format!("INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, thread_id, raw_ref, received_at, is_read, spf_result, dkim_result, dmarc_result) \
                             VALUES ($1,$2,'<'||$3::text||'@oracle.test>','dmarc oracle',$4,10,'thr-'||$3::text,'raw-'||$3::text,now() - interval '{age}',false,$5,$6,$7) RETURNING id"),
                            &[&account.mailbox, &account.inbox, &key, from, spf, dkim, dmarc],
                        )
                        .await?
                        .get(0);
                    owner
                        .execute(
                            "INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) SELECT id, received_at, $2, 'system', true FROM messages WHERE id=$1",
                            &[&id, &account.inbox],
                        )
                        .await?;
                    vars.insert(
                        Box::leak(format!("m{n}").into_boxed_str()) as &'static str,
                        id,
                    );
                }
            }
        }
        "auth-log" => {
            for row in owner
                .query(
                    "SELECT 'a:' || to_jsonb(e)::text FROM auth_event_log e",
                    &[],
                )
                .await?
            {
                stash.push(row.get::<_, String>(0));
            }
            owner
                .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM auth_event_log; COMMIT;")
                .await?;
            if !empty {
                for e in &EVENTS {
                    let user = e.user.map(|mine| if mine { a.user } else { b.user });
                    let id: i64 = owner
                        .query_one(
                            &format!("INSERT INTO auth_event_log (user_id, event, provider, email, ip_address, occurred_at) \
                             VALUES ($1,$2,$3,$4,$5::text::inet,now() - interval '{}') RETURNING id", e.age),
                            &[&user, &e.event, &e.provider, &e.email, &e.ip],
                        )
                        .await?
                        .get(0);
                    vars.insert(e.key, id);
                    names.push(("id", id, format!("<{}>", e.key)));
                }
            }
        }
        _ => panic!("unknown dmarc action {action}"),
    }
    Ok(Seed { stash, names, vars })
}

/// Removes this case's rows, then restores the rows moved aside.
pub async fn teardown(
    owner: &tokio_postgres::Client,
    action: &str,
    seed: &Seed,
) -> Result<(), BoxError> {
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica;")
        .await?;
    match action {
        "live" | "trend" => {
            owner
                .batch_execute(
                    "DELETE FROM dmarc_reports WHERE report_uri='mailto:rua@dmarc-oracle.test'",
                )
                .await?;
        }
        "auth-log" => {
            let ids: Vec<i64> = seed.vars.values().copied().collect();
            owner
                .execute("DELETE FROM auth_event_log WHERE id = ANY($1)", &[&ids])
                .await?;
        }
        _ => {}
    }
    for row in &seed.stash {
        let (table, json) = row.split_at(2);
        let sql = if table == "d:" {
            "INSERT INTO dmarc_reports SELECT * FROM jsonb_populate_record(NULL::dmarc_reports, $1::text::jsonb)"
        } else {
            "INSERT INTO auth_event_log SELECT * FROM jsonb_populate_record(NULL::auth_event_log, $1::text::jsonb)"
        };
        owner.execute(sql, &[&json]).await?;
    }
    owner.batch_execute("COMMIT;").await?;
    Ok(())
}

pub fn request(action: &str, label: &str, _seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let query = match (action, label) {
        ("failures", "limit") => "?limit=1",
        ("failures", "bad-limit") => "?limit=abc",
        ("failures", "big-limit") => "?limit=201",
        ("failures", "zero-limit") => "?limit=0",
        ("failures", "negative-limit") => "?limit=-3",
        ("auth-log", "provider") => "?provider=bcrypt",
        ("auth-log", "event") => "?event=login_failed",
        ("auth-log", "provider-all") => "?provider=all&event=all",
        ("auth-log", "since") => "?since=2%20hours",
        ("auth-log", "bad-since") => "?since=soon",
        ("auth-log", "email") => "?email=CASE-ORACLE",
        ("auth-log", "email-like") => "?email=%25",
        ("auth-log", "limit") => "?limit=2",
        ("auth-log", "zero-limit") => "?limit=0",
        ("auth-log", "bad-limit") => "?limit=abc",
        ("auth-log", "negative-limit") => "?limit=-1",
        ("auth-log", "combined") => {
            "?provider=bcrypt&event=login&since=1%20day&email=owner&limit=5"
        }
        ("auth-log", "no-match") => "?provider=jwt",
        (_, "ignored-query") => "?x=1&limit=%zz",
        _ => "",
    };
    Req {
        path: pattern.to_string(),
        query: query.to_string(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        headers: vec![],
    }
}

/// Reads change nothing: the snapshot is the row counts of the tables a case reads.
pub async fn snapshot(
    owner: &tokio_postgres::Client,
    _a: &Account,
    _b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let row = owner
        .query_one(
            "SELECT (SELECT count(*) FROM dmarc_reports)::bigint, (SELECT count(*) FROM auth_event_log)::bigint, \
             (SELECT count(*) FROM messages WHERE dmarc_result='fail')::bigint",
            &[],
        )
        .await?;
    Ok(
        json!({"dmarc_reports":row.get::<_,i64>(0),"auth_event_log":row.get::<_,i64>(1),"failed_messages":row.get::<_,i64>(2)}),
    )
}

/// The shared masks, then this slice's: the scoped admin's domain id inside the audited denial
/// text and quoted run-relative dates (`"2026-11-02"` becomes `"<today-N>"`).
pub fn mask_text(
    text: &str,
    scoped: &(String, &str),
    days: &[String],
    shared: impl Fn(&str) -> String,
) -> String {
    let mut out = shared(text).replace(scoped.0.as_str(), scoped.1);
    for (n, day) in days.iter().enumerate() {
        out = out.replace(&format!("\"{day}\""), &format!("\"<today-{n}>\""));
    }
    out
}
