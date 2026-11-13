//! Slice `spam` (#322): the ML spam dashboard and model switches, the per-user sender
//! lists, trusted senders, external-sender warning, the sender-control center and the user
//! report. User routes need only a verified token; the three admin switches reach a target
//! user through `admin_can_reach`, so their cross-tenant cases scope the admin to the
//! other tenant's domain.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

const ONE: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const TWO: &str = "aaaaaaaa-0000-4000-8000-000000000002";
const THREE: &str = "aaaaaaaa-0000-4000-8000-000000000003";
const SENT: &str = "2026-10-01T10:00:00Z";
const FLAG: &str = "feature.sender_control_center";

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "dashboard" => ("GET", "/admin/spam"),
        "reset" => ("DELETE", "/admin/spam/models/{userId}"),
        "disable" => ("POST", "/admin/spam/models/{userId}/disable"),
        "enable" => ("POST", "/admin/spam/models/{userId}/enable"),
        "senders-get" => ("GET", "/settings/senders"),
        "senders-put" => ("PUT", "/settings/senders"),
        "never-block" => ("POST", "/settings/senders/never-block"),
        "control-get" => ("GET", "/settings/sender-control"),
        "control-action" => ("POST", "/settings/sender-control/actions"),
        "trusted-list" => ("GET", "/settings/trusted-senders"),
        "trusted-add" => ("POST", "/settings/trusted-senders"),
        "trusted-remove" => ("DELETE", "/settings/trusted-senders/{sender}"),
        "external-get" => ("GET", "/settings/external-sender"),
        "external-put" => ("PUT", "/settings/external-sender"),
        "report" => ("POST", "/report"),
        _ => panic!("unknown spam action {action}"),
    }
}

pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "reset" | "disable" | "enable" => vec!["security.write"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    if label == "denied" {
        return Some(403);
    }
    let write = |ok: u16| ok;
    Some(match (action, label) {
        ("reset" | "disable" | "enable", "bad-id" | "zero-id" | "negative-id") => 400,
        // user_spam_model.user_id references users: a missing user fails the insert.
        ("disable", "missing") => 500,
        ("reset" | "disable" | "enable", "unreachable") => 403,
        ("reset" | "disable" | "enable", _) => 200,
        ("dashboard", _) => 200,
        ("senders-put", "invalid-json") => 400,
        ("senders-put", "duplicate") => 500,
        ("senders-put", "flag-on-missing-headers") => 428,
        ("senders-put", "flag-on-stale") => 409,
        ("senders-put", "flag-on-invalid" | "flag-on-overlap") => 400,
        ("never-block", "flag-on") => 409,
        ("never-block", "empty-sender" | "invalid-json") => 400,
        ("control-get", "bad-mailbox" | "bad-message" | "bad-time" | "missing-params") => 400,
        ("control-get", "foreign" | "missing-message") => 404,
        ("control-action", "flag-off") => 404,
        ("control-action", "foreign") => 404,
        ("control-action", "stale" | "conflict" | "undo-stale") => 409,
        ("control-action", "bad-action" | "undo-no-target") => 400,
        (
            "control-action",
            "bad-json"
            | "unknown-field"
            | "trailing"
            | "bad-target"
            | "bad-operation"
            | "bad-target-operation",
        ) => 400,
        ("control-action", "missing-if-match") => 428,
        ("trusted-add" | "trusted-remove", "invalid" | "empty-sender" | "invalid-json") => 400,
        ("trusted-remove", _) => 204,
        ("external-put", "missing" | "null" | "wrong-type" | "invalid-json") => 400,
        ("report", "flag-on") => 409,
        ("report", "bad-type" | "empty-id" | "bad-id" | "invalid-json") => 400,
        ("report", "foreign" | "missing") => 404,
        ("report", _) => 201,
        _ => write(200),
    })
}

fn flag_on(action: &str, label: &str) -> bool {
    label.starts_with("flag-on") || (action == "control-action" && label != "flag-off")
}

async fn message_at(
    owner: &tokio_postgres::Client,
    account: &Account,
    key: &str,
    from: &str,
) -> Result<i64, BoxError> {
    let id: i64 = owner
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, thread_id, raw_ref, received_at, is_read) \
             VALUES ($1,$2,'<'||$3::text||'@oracle.test>','spam oracle',$4,10,'thr-'||$3::text,'raw-'||$3::text,$5::text::timestamptz,false) RETURNING id",
            &[&account.mailbox, &account.inbox, &key, &from, &SENT],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) SELECT id, received_at, $2, 'system', true FROM messages WHERE id=$1",
            &[&id, &account.inbox],
        )
        .await?;
    Ok(id)
}

fn is_model(action: &str) -> bool {
    matches!(action, "dashboard" | "reset" | "disable" | "enable")
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
    let mut stash = vec![];
    for (account, who) in [(a, "actor"), (b, "other")] {
        names.push(("mailboxId", account.mailbox, format!("<mailbox-{who}>")));
        names.push(("mailbox_id", account.mailbox, format!("<mailbox-{who}>")));
        names.push(("mailbox", account.mailbox, format!("<mailbox-{who}>")));
    }
    names.push(("target_id", a.user, "<actor>".into()));
    names.push(("target_id", b.user, "<other>".into()));
    for (account, who) in [(a, "actor"), (b, "other")] {
        let other: Option<i64> = owner
            .query_opt(
                "SELECT id FROM tags WHERE mailbox_id=$1 AND name='Other'",
                &[&account.mailbox],
            )
            .await?
            .map(|r| r.get(0));
        if let Some(tag) = other {
            names.push(("tag_id", tag, format!("<tag-other-{who}>")));
        }
    }
    names.push(("id", a.user, "<actor>".into()));
    names.push(("id", b.user, "<other>".into()));
    names.push(("user_id", 999_999_999, "<missing>".into()));
    // The feature flag: record its state and force the case's.
    let original: bool = owner
        .query_one(
            "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
            &[&FLAG],
        )
        .await?
        .get(0);
    vars.insert("flag_original", original as i64);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[&FLAG, &flag_on(action, label)],
        )
        .await?;
    if is_model(action) {
        // The model table is global: move every foreign row aside.
        stash = owner
            .query("SELECT to_jsonb(m)::text FROM user_spam_model m", &[])
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect();
        owner.execute("DELETE FROM user_spam_model", &[]).await?;
        let none = matches!(label, "empty" | "norow" | "fresh" | "missing");
        if !none {
            let bytes = vec![7u8; 3000];
            let disabled_a = action == "enable";
            owner
                .execute(
                    "INSERT INTO user_spam_model (user_id, model_bytes, trained_at, sample_count, disabled, fp_count, fn_count, classified_count) \
                     VALUES ($1,$2,now(),120,$3,3,2,40)",
                    &[&a.user, &bytes, &disabled_a],
                )
                .await?;
            owner
                .execute(
                    "INSERT INTO user_spam_model (user_id, model_bytes, trained_at, sample_count, disabled, fp_count, fn_count, classified_count) \
                     VALUES ($1,$2,now() - interval '20 days',60,true,1,1,7)",
                    &[&b.user, &vec![9u8; 100]],
                )
                .await?;
        }
        return Ok(Seed { stash, names, vars });
    }
    // The user-facing routes: a message per tenant and the sender data.
    let ma = message_at(owner, a, "spam-a", "bulk@ext.test").await?;
    let mb = message_at(owner, b, "spam-b", "other@ext.test").await?;
    vars.insert("ma", ma);
    vars.insert("mb", mb);
    names.push(("messageId", ma, "<msg-actor>".into()));
    names.push(("message_id", ma, "<msg-actor>".into()));
    names.push(("target_id", ma, "<msg-actor>".into()));
    names.push(("target_id", mb, "<msg-other>".into()));
    names.push(("messageId", mb, "<msg-other>".into()));
    names.push(("message_id", mb, "<msg-other>".into()));
    let lists: &[(&str, &str, &str)] = &[
        ("a", "x@ok.test", "safe"),
        ("a", "y@ok.test", "safe"),
        ("a", "bad@bad.test", "blocked"),
        ("b", "b-only@ok.test", "safe"),
        ("b", "b-bad@bad.test", "blocked"),
    ];
    let populate = matches!(
        action,
        "senders-get" | "senders-put" | "never-block" | "control-get" | "control-action"
    ) && !matches!(label, "empty" | "flag-on-empty" | "foreign-empty");
    if populate {
        for (who, sender, kind) in lists {
            let user = if *who == "a" { a.user } else { b.user };
            if label == "foreign" && action == "senders-get" && *who == "a" {
                continue;
            }
            owner
                .execute(
                    "INSERT INTO user_sender_list (user_id, sender, list_type) VALUES ($1,$2,$3)",
                    &[&user, sender, kind],
                )
                .await?;
        }
    }
    if action == "control-get" && label == "with-state" {
        owner
            .execute("INSERT INTO user_sender_list (user_id, sender, list_type) VALUES ($1,'bulk@ext.test','safe')", &[&a.user])
            .await?;
        owner
            .execute(
                "INSERT INTO vip_senders (user_id, sender_email) VALUES ($1,'bulk@ext.test')",
                &[&a.user],
            )
            .await?;
        owner
            .execute("INSERT INTO focus_sender_overrides (user_id, sender, focused) VALUES ($1,'bulk@ext.test',true)", &[&a.user])
            .await?;
    }
    if matches!(action, "trusted-list" | "trusted-add" | "trusted-remove") {
        let rows: &[(&str, &str, &str)] = &[
            ("a", "first@ok.test", "2026-10-01T10:00:01Z"),
            ("a", "second@ok.test", "2026-10-01T10:00:02Z"),
            ("b", "b-trusted@ok.test", "2026-10-01T10:00:03Z"),
        ];
        for (who, sender, at) in rows {
            if label == "empty" || (label == "foreign" && *who == "a") {
                continue;
            }
            let user = if *who == "a" { a.user } else { b.user };
            owner
                .execute(
                    "INSERT INTO user_image_allow (user_id, sender, created_at) VALUES ($1,$2,$3::text::timestamptz)",
                    &[&user, sender, at],
                )
                .await?;
        }
    }
    if action == "external-get" {
        match label {
            "domain" => {
                owner
                    .execute(
                        "INSERT INTO external_sender_config (domain_id, enabled, warn_text, warn_color) VALUES ($1,false,'Careful <ext> & co','#102030')",
                        &[&a.domain],
                    )
                    .await?;
            }
            "domain-null-text" => {
                owner
                    .execute(
                        "INSERT INTO external_sender_config (domain_id, enabled, warn_text, warn_color) VALUES ($1,true,NULL,'#a0b0c0')",
                        &[&a.domain],
                    )
                    .await?;
            }
            "foreign" => {
                owner
                    .execute(
                        "UPDATE users SET external_sender_warning=false WHERE id=$1",
                        &[&b.user],
                    )
                    .await?;
                owner
                    .execute(
                        "INSERT INTO external_sender_config (domain_id, enabled, warn_text, warn_color) VALUES ($1,false,'other tenant','#000000')",
                        &[&b.domain],
                    )
                    .await?;
            }
            "disabled" => {
                owner
                    .execute(
                        "UPDATE users SET external_sender_warning=false WHERE id=$1",
                        &[&a.user],
                    )
                    .await?;
                let original: Option<String> = owner
                    .query_opt(
                        "SELECT value::text FROM system_config WHERE key='external_sender.enabled'",
                        &[],
                    )
                    .await?
                    .map(|r| r.get(0));
                stash.push(original.unwrap_or_default());
                owner
                    .execute("UPDATE system_config SET value='false'::jsonb WHERE key='external_sender.enabled'", &[])
                    .await?;
            }
            _ => {}
        }
    }
    if action == "control-action" {
        let prior = |op: &'static str, act: &'static str, generation: i64| (op, act, generation);
        let seeded = match label {
            "undo" => Some(prior(ONE, "safe", 1)),
            "undo-stale" => Some(prior(ONE, "safe", 1)),
            "conflict" => Some(prior(TWO, "safe", 1)),
            _ => None,
        };
        if let Some((op, act, generation)) = seeded {
            let digest = "0".repeat(64);
            owner
                .execute(
                    "SELECT sender_control_action($1,$2,$3,$4::text::timestamptz,$5::text::uuid,$6,$7,$8,NULL)",
                    &[&a.user, &a.mailbox, &ma, &SENT, &op, &act, &generation, &digest],
                )
                .await?;
            if label == "undo-stale" {
                // A later change moves the generation on, so the undo target is stale.
                owner
                    .execute(
                        "UPDATE sender_control_state SET generation=generation+1 WHERE user_id=$1",
                        &[&a.user],
                    )
                    .await?;
            }
        }
    }
    Ok(Seed { stash, names, vars })
}

/// Restores the flag, the global tables a case touched and removes its operation rows.
pub async fn teardown(
    owner: &tokio_postgres::Client,
    action: &str,
    label: &str,
    seed: &Seed,
) -> Result<(), BoxError> {
    let original = seed.vars.get("flag_original").copied().unwrap_or(0) != 0;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[&FLAG, &original],
        )
        .await?;
    if is_model(action) {
        owner.execute("DELETE FROM user_spam_model", &[]).await?;
        for row in &seed.stash {
            owner
                .execute(
                    "INSERT INTO user_spam_model SELECT * FROM jsonb_populate_record(NULL::user_spam_model, $1::text::jsonb)",
                    &[row],
                )
                .await?;
        }
    }
    if action == "external-get" && label == "disabled" {
        if let Some(value) = seed.stash.first() {
            owner
                .execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='external_sender.enabled'", &[value])
                .await?;
        }
    }
    owner
        .execute(
            "DELETE FROM sender_control_operations WHERE operation_id = ANY($1::uuid[])",
            &[&vec![ONE.to_string(), TWO.to_string(), THREE.to_string()]],
        )
        .await
        .ok();
    Ok(())
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let id = |who: &str| {
        seed.names
            .iter()
            .find(|n| n.0 == "id" && n.2 == who)
            .map(|n| n.1)
            .unwrap_or(0)
    };
    let mailbox = |who: &str| {
        seed.names
            .iter()
            .find(|n| n.0 == "mailboxId" && n.2 == format!("<mailbox-{who}>"))
            .map(|n| n.1)
            .unwrap_or(0)
    };
    let mut req = Req {
        path: pattern.to_owned(),
        query: String::new(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        headers: vec![],
    };
    match action {
        "dashboard" => {
            if label == "ignored-query" {
                req.query = "?limit=-1&x=%zz".into();
            }
        }
        "reset" | "disable" | "enable" => {
            let target = match label {
                "bad-id" => "abc".to_string(),
                "zero-id" => "0".to_string(),
                "negative-id" => "-5".to_string(),
                "missing" => "999999999".to_string(),
                "scoped" => id("<other>").to_string(),
                _ => id("<actor>").to_string(),
            };
            req.path = pattern.replace("{userId}", &target);
        }
        "senders-put" => {
            let flag = label.starts_with("flag-on");
            req.body = match label {
                "success" => {
                    r#"{"safe":["A@Ok.test","new@ok.test"],"blocked":["bad@bad.test"]}"#.into()
                }
                "empty-lists" => r#"{"safe":[],"blocked":[]}"#.into(),
                "null-lists" => "{}".into(),
                "repeat" => r#"{"safe":["r@ok.test"],"blocked":[]}"#.into(),
                "duplicate" => r#"{"safe":["d@ok.test","d@ok.test"],"blocked":[]}"#.into(),
                "invalid-json" => "{bad".into(),
                "null-element" => r#"{"safe":[null,"n@ok.test"],"blocked":[]}"#.into(),
                "mixed-case-keys" => r#"{"SAFE":["c@ok.test"],"Blocked":["d@bad.test"]}"#.into(),
                "foreign" => r#"{"safe":["f@ok.test"],"blocked":[]}"#.into(),
                "flag-on-success" | "flag-on-repeat" | "flag-on-missing-headers" => {
                    format!(
                        r#"{{"safe":["Z@Ok.test","w@ok.test"],"blocked":["q@bad.test"],"expectedGeneration":"1","operationId":"{ONE}"}}"#
                    )
                }
                "flag-on-nil-lists" => {
                    format!(r#"{{"expectedGeneration":"1","operationId":"{ONE}"}}"#)
                }
                "flag-on-stale" => format!(
                    r#"{{"safe":["s@ok.test"],"blocked":[],"expectedGeneration":"7","operationId":"{ONE}"}}"#
                ),
                "flag-on-invalid" => format!(
                    r#"{{"safe":[""],"blocked":[],"expectedGeneration":"1","operationId":"{ONE}"}}"#
                ),
                "flag-on-overlap" => format!(
                    r#"{{"safe":["o@ok.test"],"blocked":["o@ok.test"],"expectedGeneration":"1","operationId":"{ONE}"}}"#
                ),
                _ => r#"{"safe":["m@ok.test"],"blocked":[]}"#.into(),
            };
            if flag && label != "flag-on-missing-headers" {
                let generation = if label == "flag-on-stale" { "7" } else { "1" };
                req.headers = vec![
                    ("idempotency-key".into(), ONE.into()),
                    ("if-match".into(), format!("\"{generation}\"")),
                ];
            }
        }
        "never-block" => {
            req.body = match label {
                "absent" => r#"{"sender":"new@ok.test"}"#.into(),
                "already-safe" => r#"{"sender":"x@ok.test"}"#.into(),
                "empty-sender" => r#"{"sender":""}"#.into(),
                "invalid-json" => "[".into(),
                _ => r#"{"sender":"bad@bad.test"}"#.into(),
            };
        }
        "control-get" => {
            let (mb, msg) = match label {
                "foreign" => (mailbox("other"), var("mb")),
                "missing-message" => (mailbox("actor"), 999_999_999),
                _ => (mailbox("actor"), var("ma")),
            };
            let (query, recorded) = match label {
                "bad-mailbox" => (
                    format!("?mailboxId=0&messageId={}&receivedAt={SENT}", var("ma")),
                    "?mailboxId=0&messageId=<msg-actor>&receivedAt=2026-10-01T10:00:00Z".to_string(),
                ),
                "bad-message" => (
                    format!("?mailboxId={}&messageId=abc&receivedAt={SENT}", mailbox("actor")),
                    "?mailboxId=<mailbox-actor>&messageId=abc&receivedAt=2026-10-01T10:00:00Z".to_string(),
                ),
                "bad-time" => (
                    format!("?mailboxId={}&messageId={}&receivedAt=yesterday", mailbox("actor"), var("ma")),
                    "?mailboxId=<mailbox-actor>&messageId=<msg-actor>&receivedAt=yesterday".to_string(),
                ),
                "missing-params" => (String::new(), String::new()),
                "foreign" => (
                    format!("?mailboxId={mb}&messageId={msg}&receivedAt={SENT}"),
                    "?mailboxId=<mailbox-other>&messageId=<msg-other>&receivedAt=2026-10-01T10:00:00Z".to_string(),
                ),
                "missing-message" => (
                    format!("?mailboxId={mb}&messageId={msg}&receivedAt={SENT}"),
                    "?mailboxId=<mailbox-actor>&messageId=999999999&receivedAt=2026-10-01T10:00:00Z".to_string(),
                ),
                _ => (
                    format!("?mailboxId={mb}&messageId={msg}&receivedAt={SENT}"),
                    "?mailboxId=<mailbox-actor>&messageId=<msg-actor>&receivedAt=2026-10-01T10:00:00Z".to_string(),
                ),
            };
            req.query = query;
            req.recorded_query = recorded;
        }
        "control-action" => {
            let actor_mailbox = mailbox("actor");
            let (mb, msg, mb_text, msg_text) = if label == "foreign" {
                (
                    mailbox("other"),
                    var("mb"),
                    "<mailbox-other>",
                    "<msg-other>",
                )
            } else {
                (actor_mailbox, var("ma"), "<mailbox-actor>", "<msg-actor>")
            };
            let action_name = match label {
                "always-focus" => "always_focus",
                "never-focus" => "never_focus",
                "vip" => "vip",
                "not-vip" => "not_vip",
                "block" | "conflict" => "block",
                "never-block" => "never_block",
                "report-spam" => "report_spam",
                "report-phishing" => "report_phishing",
                "undo" | "undo-stale" | "undo-no-target" => "undo",
                "bad-action" => "explode",
                _ => "safe",
            };
            let generation = match label {
                "stale" => "9",
                "undo" => "2",
                "undo-stale" => "2",
                _ => "1",
            };
            let operation = match label {
                "undo" | "undo-stale" => TWO,
                "conflict" => TWO,
                _ => ONE,
            };
            let target = if matches!(label, "undo" | "undo-stale") {
                format!(r#","targetOperationId":"{ONE}""#)
            } else if label == "bad-target-operation" {
                r#","targetOperationId":"not-a-uuid""#.to_owned()
            } else {
                String::new()
            };
            let (mailbox_field, mailbox_recorded) = if label == "bad-target" {
                ("0".to_owned(), "0".to_owned())
            } else {
                (mb.to_string(), mb_text.to_owned())
            };
            let build = |m: &str, g: &str| {
                format!(
                    r#"{{"mailboxId":"{m}","messageId":"{g}","receivedAt":"{SENT}","operationId":"{operation}","action":"{action_name}","expectedGeneration":"{generation}"{target}}}"#
                )
            };
            req.body = build(&mailbox_field, &msg.to_string());
            req.recorded_body = build(&mailbox_recorded, msg_text);
            match label {
                "bad-json" => {
                    req.body = "{nope".into();
                    req.recorded_body = req.body.clone();
                }
                "unknown-field" => {
                    req.body = req.body.replacen('{', r#"{"extra":1,"#, 1);
                    req.recorded_body = req.recorded_body.replacen('{', r#"{"extra":1,"#, 1);
                }
                "trailing" => {
                    req.body.push_str(" {}");
                    req.recorded_body.push_str(" {}");
                }
                _ => {}
            }
            let operation_header = if label == "bad-operation" {
                THREE
            } else {
                operation
            };
            req.headers = vec![("idempotency-key".into(), operation_header.into())];
            if label != "missing-if-match" {
                req.headers
                    .push(("if-match".into(), format!("\"{generation}\"")));
            }
            if label == "undo-no-target" {
                // no targetOperationId: the reducer refuses
            }
        }
        "trusted-add" => {
            req.body = match label {
                "normalized" => r#"{"sender":"  New@Ok.test "}"#.into(),
                "duplicate" => r#"{"sender":"first@ok.test"}"#.into(),
                "invalid" => r#"{"sender":"not-an-email"}"#.into(),
                "empty-sender" => r#"{"sender":""}"#.into(),
                "invalid-json" => "nope".into(),
                "unicode" => r#"{"sender":"Üser@Ok.test"}"#.into(),
                "display-name" => r#"{"sender":"Bob <Bob@Ok.test>"}"#.into(),
                _ => r#"{"sender":"added@ok.test"}"#.into(),
            };
        }
        "trusted-remove" => {
            let sender = match label {
                "missing" => "nobody@ok.test",
                "invalid" => "bad",
                "uppercase" => "FIRST@OK.TEST",
                "foreign" => "b-trusted@ok.test",
                "encoded" => "first%40ok.test",
                _ => "first@ok.test",
            };
            req.path = pattern.replace("{sender}", sender);
        }
        "external-put" => {
            req.body = match label {
                "enable" => r#"{"enabled":true}"#.into(),
                "missing" => "{}".into(),
                "null" => r#"{"enabled":null}"#.into(),
                "wrong-type" => r#"{"enabled":"yes"}"#.into(),
                "invalid-json" => "{".into(),
                _ => r#"{"enabled":false}"#.into(),
            };
        }
        "report" => {
            let ma = var("ma").to_string();
            let mb = var("mb").to_string();
            let (body, recorded) = match label {
                "phishing" => (
                    format!(r#"{{"emailId":"{ma}","type":"phishing"}}"#),
                    r#"{"emailId":"<msg-actor>","type":"phishing"}"#.to_owned(),
                ),
                "concern" => (
                    format!(r#"{{"emailId":"{ma}","type":"concern"}}"#),
                    r#"{"emailId":"<msg-actor>","type":"concern"}"#.to_owned(),
                ),
                "with-note" => (
                    format!(r#"{{"emailId":"{ma}","type":"spam","note":"looks <bad> & odd"}}"#),
                    r#"{"emailId":"<msg-actor>","type":"spam","note":"looks <bad> & odd"}"#
                        .to_owned(),
                ),
                "foreign" => (
                    format!(r#"{{"emailId":"{mb}","type":"spam"}}"#),
                    r#"{"emailId":"<msg-other>","type":"spam"}"#.to_owned(),
                ),
                "missing" => (
                    r#"{"emailId":"999999999","type":"spam"}"#.to_owned(),
                    r#"{"emailId":"999999999","type":"spam"}"#.to_owned(),
                ),
                "bad-type" => (
                    format!(r#"{{"emailId":"{ma}","type":"junk"}}"#),
                    r#"{"emailId":"<msg-actor>","type":"junk"}"#.to_owned(),
                ),
                "empty-id" => (
                    r#"{"type":"spam"}"#.to_owned(),
                    r#"{"type":"spam"}"#.to_owned(),
                ),
                "bad-id" => (
                    r#"{"emailId":"abc","type":"spam"}"#.to_owned(),
                    r#"{"emailId":"abc","type":"spam"}"#.to_owned(),
                ),
                "invalid-json" => ("[".to_owned(), "[".to_owned()),
                _ => (
                    format!(r#"{{"emailId":"{ma}","type":"spam"}}"#),
                    r#"{"emailId":"<msg-actor>","type":"spam"}"#.to_owned(),
                ),
            };
            req.body = body;
            req.recorded_body = recorded;
        }
        _ => {}
    }
    if label == "ignored-query" && req.query.is_empty() {
        req.query = "?x=1&limit=-1&y=%zz".into();
    }
    if req.recorded_body.is_empty() {
        req.recorded_body = req.body.clone();
    }
    req
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    let users = [a.user, b.user, 999_999_999];
    let rows = |sql: String| async move { super::rows(owner, &sql).await };
    let models = rows(
        "SELECT jsonb_build_object('user_id',user_id,'samples',sample_count,'disabled',disabled,'fp',fp_count,'fn',fn_count,'classified',classified_count,'bytes',octet_length(model_bytes))::text FROM user_spam_model ORDER BY user_id".into(),
    )
    .await?;
    let senders = rows(format!(
        "SELECT jsonb_build_object('user_id',user_id,'sender',sender,'list',list_type)::text FROM user_sender_list WHERE user_id IN ({}, {}) ORDER BY user_id, list_type, sender",
        users[0], users[1]
    ))
    .await?;
    let trusted = rows(format!(
        "SELECT jsonb_build_object('user_id',user_id,'sender',sender,'created_at',created_at)::text FROM user_image_allow WHERE user_id IN ({}, {}) ORDER BY user_id, sender",
        users[0], users[1]
    ))
    .await?;
    let external = rows(format!(
        "SELECT jsonb_build_object('user_id',id,'warning',external_sender_warning)::text FROM users WHERE id IN ({}, {}) ORDER BY id",
        users[0], users[1]
    ))
    .await?;
    let state = rows(format!(
        "SELECT jsonb_build_object('user_id',user_id,'generation',generation)::text FROM sender_control_state WHERE user_id IN ({}, {}) ORDER BY user_id",
        users[0], users[1]
    ))
    .await?;
    let list_ops = rows(format!(
        "SELECT jsonb_build_object('operation_id',operation_id,'user_id',user_id,'generation',generation,'request_digest',request_digest,'result',result)::text FROM sender_list_operations WHERE user_id IN ({}, {}) ORDER BY operation_id",
        users[0], users[1]
    ))
    .await?;
    // The control digest covers run-specific ids, so it is compared against an independent
    // computation of Go's json.Marshal bytes instead of stored.
    let ma = seed.vars.get("ma").copied().unwrap_or(0);
    let control_ops = rows(format!(
        "SELECT jsonb_build_object('operation_id',operation_id,'user_id',user_id,'generation',generation,'sender',sender_address,'action',action,\
         'digest_ok',(request_digest = encode(sha256(convert_to('{{\"MailboxID\":\"'||{mailbox}||'\",\"MessageID\":\"'||{ma}||'\",\"ReceivedAt\":\"{SENT}\",\"OperationID\":\"'||operation_id||'\",\"Action\":\"'||action||'\",\"ExpectedGeneration\":\"'||generation||'\",\"TargetOperationID\":\"'||COALESCE(target_operation_id::text,'')||'\"}}','UTF8')),'hex')) OR request_digest=repeat('0',64),\
         'target',target_operation_id,'before',before_state,'result',result)::text FROM sender_control_operations WHERE user_id IN ({}, {}) ORDER BY operation_id",
        users[0], users[1], mailbox = a.mailbox
    ))
    .await?;
    let outbox = rows(format!(
        "SELECT jsonb_build_object('operation_id',operation_id,'user_id',user_id,'message_id',message_id,'kind',feedback_kind,'state',state)::text FROM sender_feedback_outbox WHERE user_id IN ({}, {}) ORDER BY operation_id",
        users[0], users[1]
    ))
    .await?;
    let personal = rows(format!(
        "SELECT jsonb_build_object('user_id',user_id,'kind','focus','sender',sender,'focused',focused)::text FROM focus_sender_overrides WHERE user_id IN ({0}, {1}) \
         UNION ALL SELECT jsonb_build_object('user_id',user_id,'kind','vip','sender',sender_email)::text FROM vip_senders WHERE user_id IN ({0}, {1}) ORDER BY 1",
        users[0], users[1]
    ))
    .await?;
    let tags = rows(format!(
        "SELECT jsonb_build_object('message_id',mt.message_id,'tag',t.name)::text FROM message_tags mt JOIN tags t ON t.id=mt.tag_id WHERE mt.message_id IN ({}, {}) ORDER BY mt.message_id, t.name",
        seed.vars.get("ma").copied().unwrap_or(0),
        seed.vars.get("mb").copied().unwrap_or(0)
    ))
    .await?;
    Ok(json!({
        "models": models, "senders": senders, "trusted": trusted, "external": external,
        "state": state, "list_operations": list_ops, "control_operations": control_ops,
        "outbox": outbox, "personal": personal, "tags": tags,
    }))
}
