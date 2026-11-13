//! Slice `settings-a` (#306): the eleven `/settings/*` routes.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

/// `(method, inventory pattern)` for an action.
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "imap-get" => ("GET", "/settings/imap"),
        "imap-put" => ("PUT", "/settings/imap"),
        "view-get" => ("GET", "/settings/view"),
        "view-put" => ("PUT", "/settings/view"),
        "undo-get" => ("GET", "/settings/undo-send"),
        "undo-put" => ("PUT", "/settings/undo-send"),
        "newsletter-get" => ("GET", "/settings/newsletter-bundles"),
        "newsletter-put" => ("PUT", "/settings/newsletter-bundles"),
        "signature-list" => ("GET", "/settings/signatures-list"),
        "signature-put" => ("PUT", "/settings/signatures"),
        "signature-delete" => ("DELETE", "/settings/signatures/{id}"),
        _ => panic!("unknown settings-a action {action}"),
    }
}

/// The status Go answers; `None` leaves the recorded status unchecked.
pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        (_, "bad-json" | "array-body" | "wrong-type" | "bad-window" | "bad-window-value") => {
            Some(400)
        }
        ("undo-put", "string" | "float") => Some(400),
        ("imap-put", "partial" | "null-tags") => Some(500),
        (
            "signature-put",
            "bool-default" | "no-alias" | "null-body" | "long-alias" | "long-html" | "long-text"
            | "bad-default-for" | "limit" | "too-big",
        ) => Some(400),
        ("signature-delete", "bad-id") => Some(400),
        ("signature-delete", "foreign" | "missing") => Some(404),
        ("signature-delete", "repeat") => Some(404),
        (_, _) if action.ends_with("-get") || action == "signature-list" => Some(200),
        ("signature-delete", _) => Some(204),
        _ => Some(200),
    }
}

const ACTOR_PREFS: &str = r#"{"defaultView":"list","offlineWindow":"90d","smartMute":true,"extra":{"n":[1,2.5,100],"s":"a<b"},"undoSendDelay":12,"bundleNewsletters":false,"newsletterOptouts":["list-a.test","list-b.test"]}"#;
const OTHER_PREFS: &str = r#"{"defaultView":"other","undoSendDelay":20,"bundleNewsletters":true,"newsletterOptouts":["other.test"]}"#;

/// The actor's `users.view_prefs` text for a label (`None` is SQL NULL).
fn actor_prefs(action: &str, label: &str) -> Option<&'static str> {
    match (action, label) {
        (_, "foreign" | "null-prefs") => None,
        (_, "array") => Some("[1,2]"),
        (_, "jsonnull") => Some("null"),
        ("view-get", "partial") => Some(r#"{"readingPane":"left"}"#),
        ("view-get", "numbers") => Some(
            r#"{"undoSendDelay":7.0,"big":1e300,"huge":12345678901234567890,"small":1e-7,"mid":0.000001,"neg":-0.0,"exp":1.5e21}"#,
        ),
        ("view-get", "html") => Some(r#"{"defaultView":"<b>&</b>  é"}"#),
        ("undo-get", "float") => Some(r#"{"undoSendDelay":7.9}"#),
        ("undo-get", "negative") => Some(r#"{"undoSendDelay":-3}"#),
        ("undo-get", "string") => Some(r#"{"undoSendDelay":"x"}"#),
        ("undo-get", "huge") => Some(r#"{"undoSendDelay":1e30}"#),
        ("newsletter-get", "bad-types") => {
            Some(r#"{"bundleNewsletters":"x","newsletterOptouts":[1,"a"]}"#)
        }
        ("newsletter-get", "null-items") => {
            Some(r#"{"bundleNewsletters":true,"newsletterOptouts":["a",null,"<b>"]}"#)
        }
        ("newsletter-get", "null-list") => Some(r#"{"newsletterOptouts":null}"#),
        _ => Some(ACTOR_PREFS),
    }
}

struct Sig {
    key: &'static str,
    mine: bool,
    alias: &'static str,
    html: &'static str,
    text: &'static str,
    default: bool,
    role: &'static str,
    at: &'static str,
}
const SIGS: [Sig; 5] = [
    Sig {
        key: "s1",
        mine: true,
        alias: "work@sig.test",
        html: "<p>Work & co \u{2028}</p>",
        text: "Work <co>",
        default: true,
        role: "new",
        at: "2026-10-01T10:00:01Z",
    },
    Sig {
        key: "s2",
        mine: true,
        alias: "home@sig.test",
        html: "<i>Home</i>",
        text: "Home",
        default: false,
        role: "reply",
        at: "2026-10-01T10:00:02Z",
    },
    Sig {
        key: "s3",
        mine: true,
        alias: "Zed@sig.test",
        html: "",
        text: "",
        default: false,
        role: "none",
        at: "2026-10-01T10:00:03Z",
    },
    Sig {
        key: "o1",
        mine: false,
        alias: "work@sig.test",
        html: "<p>Other work</p>",
        text: "Other",
        default: true,
        role: "both",
        at: "2026-10-01T10:00:04Z",
    },
    Sig {
        key: "o2",
        mine: false,
        alias: "side@sig.test",
        html: "<p>Side</p>",
        text: "Side",
        default: false,
        role: "none",
        at: "2026-10-01T10:00:05Z",
    },
];

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    // users.view_prefs
    for (user, text) in [
        (a.user, actor_prefs(action, label)),
        (b.user, Some(OTHER_PREFS)),
    ] {
        owner
            .execute(
                "UPDATE users SET view_prefs = $2::text::jsonb WHERE id = $1",
                &[&user, &text],
            )
            .await?;
    }
    // user_imap_settings: the actor has none for `foreign` and `new-row`.
    if !matches!(label, "foreign" | "new-row") {
        owner
            .execute(
                "INSERT INTO user_imap_settings(user_id,expose_all,show_subscribed_only,exposed_tag_ids,folder_separator,imap_enabled) VALUES($1,TRUE,FALSE,$2,'.',TRUE)",
                &[&a.user, &vec![101_i64, 102]],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO user_imap_settings(user_id,expose_all,show_subscribed_only,exposed_tag_ids,folder_separator,imap_enabled) VALUES($1,FALSE,TRUE,$2,'/',FALSE)",
            &[&b.user, &vec![103_i64]],
        )
        .await?;
    // user_signatures: none for the actor on `foreign`.
    for sig in &SIGS {
        if sig.mine && label == "foreign" {
            continue;
        }
        let user = if sig.mine { a.user } else { b.user };
        let id: i64 = owner
            .query_one(
                "INSERT INTO user_signatures(user_id,alias_email,signature_html,signature_text,is_default,default_for,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7::text::timestamptz,$7::text::timestamptz) RETURNING id",
                &[&user, &sig.alias, &sig.html, &sig.text, &sig.default, &sig.role, &sig.at],
            )
            .await?
            .get(0);
        vars.insert(sig.key, id);
        names.push(("id", id, format!("<{}>", sig.key)));
    }
    // 98 fillers on top of the actor's three (and the other's two stay apart): 101 rows
    // would exceed the cap, so `limit` seeds 100 for the actor in total.
    if matches!(label, "limit" | "limit-update") {
        owner
            .execute(
                "INSERT INTO user_signatures(user_id,alias_email,created_at,updated_at) SELECT $1,'fill-'||g||'@sig.test','2026-10-01T09:00:00Z','2026-10-01T09:00:00Z' FROM generate_series(1,97) g",
                &[&a.user],
            )
            .await?;
    }
    Ok(Seed {
        names,
        vars,
        extra_users: vec![],
        undo: vec![],
        text_masks: vec![],
    })
}

pub async fn plant_foreign(
    owner: &tokio_postgres::Client,
    b: &Account,
    _seed: &Seed,
) -> Result<(), BoxError> {
    // A foreign row an unfiltered query would surface.
    owner
        .execute(
            "INSERT INTO user_signatures(user_id,alias_email,signature_html,signature_text,created_at,updated_at) VALUES($1,'planted@sig.test','<p>planted</p>','planted','2026-10-01T10:00:06Z','2026-10-01T10:00:06Z')",
            &[&b.user],
        )
        .await?;
    Ok(())
}

fn long(n: usize) -> String {
    "x".repeat(n)
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let query = if label == "ignored-query" {
        "?limit=-1&x=%zz"
    } else {
        ""
    };
    let imap = |expose: &str, tags: &str, sep: &str| {
        format!(
            r#"{{"exposeAll":{expose},"showSubscribedOnly":true,"exposedTagIds":{tags},"folderSeparator":{sep}}}"#
        )
    };
    let sig = |alias: &str, html: &str, default: &str, role: &str| {
        format!(
            r#"{{"alias_email":{},"signature_html":{},"signature_text":"txt","is_default":{},"default_for":{}}}"#,
            json!(alias),
            json!(html),
            json!(default),
            json!(role)
        )
    };
    let mut path = pattern.to_owned();
    let mut recorded = None;
    let body = match (action, label) {
        ("imap-put", "bad-json") | ("view-put", "bad-json") | ("undo-put", "bad-json") | ("newsletter-put", "bad-json") | ("signature-put", "bad-json") => "{".to_owned(),
        ("imap-put", "partial") => r#"{"exposeAll":true}"#.to_owned(),
        ("imap-put", "wrong-type") => imap("\"yes\"", "[1]", "\"/\""),
        ("imap-put", "null-tags") => imap("true", "null", "\"/\""),
        ("imap-put", "empty-tags") => imap("false", "[]", "\".\""),
        ("imap-put", "fold") => r#"{"EXPOSEALL":true,"ShowSubscribedOnly":false,"EXPOSEDTAGIDS":[7,null,9],"FolderSeparator":"é<&>"}"#.to_owned(),
        ("imap-put", _) => imap("false", "[1,2,3]", "\".\""),
        ("view-put", "array-body") => "[1]".to_owned(),
        ("view-put", "null-body") => "null".to_owned(),
        ("view-put", "bad-window") => r#"{"offlineWindow":5}"#.to_owned(),
        ("view-put", "bad-window-value") => r#"{"offlineWindow":"2d"}"#.to_owned(),
        ("view-put", "empty") => "{}".to_owned(),
        ("view-put", "trailing") => r#"{"readingPane":"left"} trailing junk"#.to_owned(),
        ("view-put", "numbers") => r#"{"a":1e2,"b":1.50,"c":12345678901234567890,"d":1e-7,"e":-0.0,"f":1e300,"g":0.1,"h":[1,2.0,{"i":3e0}]}"#.to_owned(),
        ("view-put", "html") => r#"{"offlineWindow":"all","defaultView":"<b>&</b>  é","dup":1,"dup":2,"\ud800":"lone \udc00 x"}"#.to_owned(),
        ("view-put", _) => r#"{"defaultView":"compact","offlineWindow":"7d","nested":{"k":[1,2.50,"<x>"]},"n":1e2,"keep":null}"#.to_owned(),
        ("undo-put", "string") => r#"{"undoSendDelay":"9"}"#.to_owned(),
        ("undo-put", "float") => r#"{"undoSendDelay":7.5}"#.to_owned(),
        ("undo-put", "low") => r#"{"undoSendDelay":1}"#.to_owned(),
        ("undo-put", "high") => r#"{"undoSendDelay":100}"#.to_owned(),
        ("undo-put", "missing") => "{}".to_owned(),
        ("undo-put", "null-body") => "null".to_owned(),
        ("undo-put", "fold") => r#"{"UNDOSENDDELAY":17}"#.to_owned(),
        ("undo-put", _) => r#"{"undoSendDelay":12}"#.to_owned(),
        ("newsletter-put", "wrong-type") => r#"{"bundleNewsletters":"x"}"#.to_owned(),
        ("newsletter-put", "bundle-only") => r#"{"bundleNewsletters":false}"#.to_owned(),
        ("newsletter-put", "lists-only") => r#"{"optedOutLists":["z.test"]}"#.to_owned(),
        ("newsletter-put", "empty-lists") => r#"{"optedOutLists":[]}"#.to_owned(),
        ("newsletter-put", "null-lists") => r#"{"bundleNewsletters":true,"optedOutLists":null}"#.to_owned(),
        ("newsletter-put", "nothing") => "{}".to_owned(),
        ("newsletter-put", "html") => r#"{"optedOutLists":["<a>&"," ",null]}"#.to_owned(),
        ("newsletter-put", _) => r#"{"bundleNewsletters":false,"optedOutLists":["a.test","b.test"]}"#.to_owned(),
        ("signature-put", "bool-default") => r#"{"alias_email":"a@sig.test","is_default":true}"#.to_owned(),
        ("signature-put", "no-alias") => r#"{"signature_text":"x"}"#.to_owned(),
        ("signature-put", "null-body") => "null".to_owned(),
        ("signature-put", "long-alias") => sig(&format!("{}@sig.test", long(312)), "", "false", "none"),
        ("signature-put", "long-html") => {
            let body = sig("big@sig.test", &long(64 * 1024 + 1), "false", "none");
            recorded = Some(format!("<signature_html of {} bytes>", 64 * 1024 + 1));
            body
        }
        ("signature-put", "long-text") => {
            let body = format!(r#"{{"alias_email":"big@sig.test","signature_text":"{}"}}"#, long(8 * 1024 + 1));
            recorded = Some("<signature_text of 8193 bytes>".into());
            body
        }
        ("signature-put", "too-big") => {
            let body = format!(r#"{{"alias_email":"big@sig.test","signature_text":"{}"}}"#, long(129 * 1024));
            recorded = Some("<body of 132119 bytes>".into());
            body
        }
        ("signature-put", "bad-default-for") => sig("a@sig.test", "", "false", "sometimes"),
        ("signature-put", "update") => sig("home@sig.test", "<b>updated</b>", "true", "none"),
        ("signature-put", "role-flip") => sig("Zed@sig.test", "<b>z</b>", "false", "new"),
        ("signature-put", "default-both") => sig("work@sig.test", "<b>w</b>", "true", "both"),
        ("signature-put", "foreign") => sig("work@sig.test", "<b>mine</b>", "true", "new"),
        ("signature-put", "limit") => sig("over@sig.test", "", "false", "none"),
        ("signature-put", "limit-update") => sig("work@sig.test", "<b>at cap</b>", "false", "reply"),
        ("signature-put", "empty-role") => r#"{"alias_email":"plain@sig.test","signature_html":"<p>p</p>"}"#.to_owned(),
        ("signature-put", _) => sig("new@sig.test", "<p>New & <b>bold</b></p>", "true", "new"),
        _ => String::new(),
    };
    if action == "signature-delete" {
        let id = match label {
            "bad-id" => "abc".to_owned(),
            "missing" => "999999999".to_owned(),
            "foreign" => var("o1").to_string(),
            "repeat" | "second" => var("s2").to_string(),
            "plus" => format!("+{}", var("s3")),
            _ => var("s1").to_string(),
        };
        path = path.replace("{id}", &id);
    }
    let _: Option<Value> = None;
    Req {
        path,
        query: query.into(),
        recorded_body: recorded.unwrap_or_else(|| body.clone()),
        body,
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let mut imap = vec![];
    let mut prefs = vec![];
    let mut signatures = vec![];
    for (account, who) in [(a, "actor"), (b, "other")] {
        let row = super::rows(
            owner,
            &format!(
                "SELECT to_jsonb(s)::text FROM user_imap_settings s WHERE user_id={}",
                account.user
            ),
        )
        .await?;
        imap.push(json!({"who":who,"row":row.first()}));
        let p = super::rows(
            owner,
            &format!(
                "SELECT COALESCE(view_prefs,'\"<sql-null>\"'::jsonb)::text FROM users WHERE id={}",
                account.user
            ),
        )
        .await?;
        prefs.push(json!({"who":who,"view_prefs":p.first()}));
        let rows = super::rows(owner, &format!("SELECT jsonb_build_object('alias',alias_email,'html',signature_html,'text',signature_text,'is_default',is_default,'default_for',default_for,'created_at',created_at,'updated_at',updated_at)::text FROM user_signatures WHERE user_id={} AND alias_email NOT LIKE 'fill-%' ORDER BY alias_email, id", account.user)).await?;
        let filler: i64 = owner.query_one("SELECT count(*) FROM user_signatures WHERE user_id=$1 AND alias_email LIKE 'fill-%'", &[&account.user]).await?.get(0);
        signatures.push(json!({"who":who,"rows":rows,"fillers":filler}));
    }
    Ok(json!({"imap":imap,"prefs":prefs,"signatures":signatures}))
}
