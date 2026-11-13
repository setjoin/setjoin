//! Slice `quarantine` (#320): user self-service and admin quarantine actions.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::{self, Account};

/// `(method, inventory pattern)` for an action.
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "user-list" => ("GET", "/quarantine"),
        "user-count" => ("GET", "/quarantine/count"),
        "user-release" => ("POST", "/quarantine/{id}/release"),
        "user-reject" => ("POST", "/quarantine/{id}/reject"),
        "admin-list" => ("GET", "/admin/quarantine"),
        "admin-stats" => ("GET", "/admin/quarantine/stats"),
        "admin-preview" => ("GET", "/admin/quarantine/{id}/preview"),
        "admin-release" => ("POST", "/admin/quarantine/{id}/release"),
        "admin-reject" => ("POST", "/admin/quarantine/{id}/reject"),
        _ => panic!("unknown quarantine action {action}"),
    }
}

/// The permissions that satisfy an action's gate.
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "admin-preview" => vec!["mail.export"],
        "admin-release" | "admin-reject" => vec!["security.write"],
        _ => vec!["mail.security"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    let user = action.starts_with("user-");
    match (action, label) {
        (_, "denied") => Some(403),
        (_, "bad-id") => Some(400),
        ("user-release", "repeat") => Some(403),
        ("admin-release", "repeat") => Some(404),
        ("user-release" | "user-reject", "foreign" | "already" | "missing") => Some(403),
        ("admin-release" | "admin-reject" | "admin-preview", "already" | "missing") => Some(404),
        _ if user || action.starts_with("admin-") => Some(200),
        _ => None,
    }
}

struct Spec {
    key: &'static str,
    mine: bool,
    reason: &'static str,
    kind: &'static str,
    virus: Option<&'static str>,
    subject: &'static str,
    from: &'static str,
    html: Option<&'static str>,
    at: &'static str,
    state: &'static str,
}

const SPECS: [Spec; 5] = [
    Spec {
        key: "qa1",
        mine: true,
        reason: "r-a1 Eicar & <found>",
        kind: "virus",
        virus: Some("Eicar-Test"),
        subject: "Invoice <b>1</b> & more",
        from: "evil@bad.test",
        html: Some("<p onclick=\"x()\">hi & bye \u{2028}</p>"),
        at: "2026-10-01T10:00:04Z",
        state: "active",
    },
    Spec {
        key: "qa2",
        mine: true,
        reason: "r-a2",
        kind: "dlp",
        virus: None,
        subject: "Quarterly numbers",
        from: "cfo@corp.test",
        html: None,
        at: "2026-10-01T10:00:03Z",
        state: "active",
    },
    Spec {
        key: "qa3",
        mine: true,
        reason: "r-a3",
        kind: "admin",
        virus: None,
        subject: "Released one",
        from: "friend@ok.test",
        html: Some("<i>ok</i>"),
        at: "2026-10-01T10:00:02Z",
        state: "released",
    },
    Spec {
        key: "qa4",
        mine: true,
        reason: "r-a4",
        kind: "sandbox",
        virus: None,
        subject: "Rejected one",
        from: "spam@bad.test",
        html: Some("<b>no</b>"),
        at: "2026-10-01T10:00:01Z",
        state: "rejected",
    },
    Spec {
        key: "qb1",
        mine: false,
        reason: "r-b1",
        kind: "virus",
        virus: Some("Other-Virus"),
        subject: "Other tenant",
        from: "x@other.test",
        html: Some("<p>b</p>"),
        at: "2026-10-01T10:00:00Z",
        state: "active",
    },
];

async fn quarantine_one(
    owner: &tokio_postgres::Client,
    account: &Account,
    spec: &Spec,
    user: i64,
) -> Result<(i64, i64), BoxError> {
    let message = fixture::message(
        owner,
        account.mailbox,
        account.inbox,
        &[account.inbox],
        false,
    )
    .await?;
    owner
        .execute(
            "UPDATE messages SET subject=$2, from_addr=$3, body_html=$4 WHERE id=$1",
            &[&message, &spec.subject, &spec.from, &spec.html],
        )
        .await?;
    owner
        .execute(
            "SELECT quarantine_message($1,$2,$3,$4,$5,FALSE)",
            &[
                &message,
                &account.mailbox,
                &spec.reason,
                &spec.kind,
                &spec.virus,
            ],
        )
        .await?;
    let id: i64 = owner
        .query_one(
            "SELECT id FROM quarantined_messages WHERE message_id=$1",
            &[&message],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE quarantined_messages SET quarantined_at=$2::text::timestamptz WHERE id=$1",
            &[&id, &spec.at],
        )
        .await?;
    match spec.state {
        "released" => {
            owner.execute("UPDATE quarantined_messages SET released_at='2026-10-02T00:00:00Z', released_by=$2 WHERE id=$1", &[&id, &user]).await?;
        }
        "rejected" => {
            owner.execute("UPDATE quarantined_messages SET rejected_at='2026-10-03T00:00:00Z', rejected_by=$2 WHERE id=$1", &[&id, &user]).await?;
        }
        _ => {}
    }
    Ok((message, id))
}

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    _action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    for spec in &SPECS {
        // The `foreign` label gives the actor no quarantine rows at all.
        if spec.mine && label == "foreign" {
            continue;
        }
        let (account, user) = if spec.mine { (a, a.user) } else { (b, b.user) };
        let (message, id) = quarantine_one(owner, account, spec, user).await?;
        vars.insert(spec.key, id);
        names.push(("id", id, format!("<{}>", spec.key)));
        names.push(("qm_id", id, format!("<{}>", spec.key)));
        names.push(("messageId", message, format!("<msg-{}>", spec.key)));
        names.push(("message_id", message, format!("<msg-{}>", spec.key)));
    }
    for (account, who) in [(a, "actor"), (b, "other")] {
        names.push(("mailboxId", account.mailbox, format!("<mailbox-{who}>")));
        names.push(("mailbox_id", account.mailbox, format!("<mailbox-{who}>")));
        let quarantined: Option<i64> = owner
            .query_opt(
                "SELECT id FROM tags WHERE mailbox_id=$1 AND name='Quarantined'",
                &[&account.mailbox],
            )
            .await?
            .map(|r| r.get(0));
        if let Some(tag) = quarantined {
            names.push(("tag_id", tag, format!("<tag-quarantined-{who}>")));
        }
        names.push(("tag_id", account.inbox, format!("<tag-inbox-{who}>")));
    }
    for key in ["releasedBy", "released_by", "rejectedBy", "rejected_by"] {
        names.push((key, a.user, "<actor>".into()));
        names.push((key, b.user, "<other>".into()));
    }
    Ok(Seed {
        stash: vec![],
        names,
        vars,
    })
}

pub async fn plant_foreign(
    owner: &tokio_postgres::Client,
    b: &Account,
    seed: &Seed,
) -> Result<(), BoxError> {
    let _ = seed;
    let spec = Spec {
        key: "qb2",
        mine: false,
        reason: "r-b2 planted",
        kind: "dlp",
        virus: None,
        subject: "Planted",
        from: "p@other.test",
        html: None,
        at: "2026-10-01T10:00:05Z",
        state: "active",
    };
    quarantine_one(owner, b, &spec, b.user).await?;
    Ok(())
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let id = match label {
        "bad-id" => "abc".to_string(),
        "missing" => "999999999".to_string(),
        "foreign" => var("qb1").to_string(),
        "already" if action.ends_with("release") || action == "admin-reject" => {
            var("qa3").to_string()
        }
        "already" => var("qa3").to_string(),
        "rejected-again" => var("qa4").to_string(),
        "no-html" => var("qa2").to_string(),
        "second" => var("qa2").to_string(),
        _ => var("qa1").to_string(),
    };
    let query = match (action, label) {
        ("user-list", "limit") => "?limit=1",
        ("user-list", "offset") => "?limit=1&offset=1",
        ("user-list", "clamp") => "?limit=100&offset=0",
        ("user-list", "bad-limit") => "?limit=abc&offset=zz",
        ("user-list", "negative-offset") => "?offset=-1",
        ("user-list", "zero-limit") => "?limit=0",
        ("admin-list", "active") => "?status=active",
        ("admin-list", "released") => "?status=released",
        ("admin-list", "rejected") => "?status=rejected",
        ("admin-list", "all") => "?status=all",
        ("admin-list", "unknown-status") => "?status=bogus",
        ("admin-list", "q-subject") => "?q=invoice",
        ("admin-list", "q-from") => "?q=CORP.test",
        ("admin-list", "q-wild") => "?q=%25",
        ("admin-list", "limit") => "?limit=1",
        ("admin-list", "offset") => "?limit=1&offset=1",
        ("admin-list", "bad-limit") => "?limit=abc&offset=zz",
        ("admin-list", "negative-offset") => "?offset=-5",
        ("admin-list", "big-limit") => "?limit=1000",
        (_, "ignored-query") => "?limit=-1&x=%zz",
        _ => "",
    };
    Req {
        path: pattern.replace("{id}", &id),
        query: query.to_string(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        headers: vec![],
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    let mut quarantine = vec![];
    for (key, id) in &seed.vars {
        let row = owner
            .query_opt(
                "SELECT jsonb_build_object('seed',$2::text,'qm_id',q.id,'message_id',q.message_id,'mailbox_id',q.mailbox_id,'released_at',q.released_at,'released_by',q.released_by,'rejected_at',q.rejected_at,'rejected_by',q.rejected_by,\
                 'message_exists',m.id IS NOT NULL,'is_deleted',m.is_deleted,\
                 'tags',(SELECT COALESCE(jsonb_agg(t.name ORDER BY t.name),'[]'::jsonb) FROM message_tags mt JOIN tags t ON t.id=mt.tag_id WHERE mt.message_id=q.message_id))::text \
                 FROM quarantined_messages q LEFT JOIN messages m ON m.id=q.message_id WHERE q.id=$1",
                &[id, &key.to_string()],
            )
            .await?;
        quarantine.push(match row {
            Some(r) => serde_json::from_str(&r.get::<_, String>(0))?,
            None => json!({"seed":key,"row":"gone"}),
        });
    }
    let mut mailboxes = vec![];
    for (account, who) in [(a, "actor"), (b, "other")] {
        let tags = super::rows(owner, &format!("SELECT jsonb_build_object('name',name,'total',total_count,'unread',unread_count,'state',jmap_state)::text FROM tags WHERE mailbox_id={} AND (total_count>0 OR name IN ('Inbox','Quarantined')) ORDER BY name", account.mailbox)).await?;
        let state = super::rows(owner, &format!("SELECT jsonb_build_object('email_state',jmap_email_state,'tag_state',jmap_tag_state)::text FROM mailboxes WHERE id={}", account.mailbox)).await?;
        let journal = super::rows(owner, &format!("SELECT jsonb_build_object('datatype',datatype,'op',op,'n',count(*))::text FROM jmap_changes_journal WHERE mailbox_id={} GROUP BY datatype,op ORDER BY datatype,op", account.mailbox)).await?;
        mailboxes.push(json!({"who":who,"tags":tags,"state":state,"journal":journal}));
    }
    Ok(json!({"quarantine":quarantine,"mailboxes":mailboxes}))
}
