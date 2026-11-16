//! F08 slice `terms-remaining` (#303) oracle: a table-driven runner over the shared
//! Platform harness. Each case names one request, its persona, its seed rows and the
//! table whose rows are the observed effect. Record mode runs frozen Go behind the front
//! door; replay serves the same request from Rust with no Go upstream.
#![allow(dead_code)]
use super::{masked, pin_load_values, record, SERIAL};
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    platform_terms::PlatformTermsRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Probe {
    inner: PlatformTermsRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

/// One request and what it must observe.
pub struct Case {
    pub method: &'static str,
    pub pattern: &'static str,
    /// Values for `{id}` style placeholders, in order.
    pub fill: Vec<String>,
    pub query: String,
    pub perm: &'static str,
    pub body: String,
    pub headers: Vec<(&'static str, String)>,
    /// SQL executed (as the owner) before the request, after Go has started.
    pub seed: Vec<String>,
    /// SQL executed afterwards on every path.
    pub cleanup: Vec<String>,
    /// SQL returning one `jsonb::text` row per observed effect row.
    pub effects: &'static str,
    pub table: &'static str,
    pub channels: Vec<&'static str>,
    pub status: u16,
    /// `(from, to)` text substitutions applied to the response body before comparing.
    pub replace: Vec<(String, String)>,
    /// `(from, to)` substitutions applied to the whole observation (request, response, effects)
    /// to map ids seeded above the lane's sequence offsets back to the recorded literals.
    pub unshift: Vec<(String, String)>,
}

pub fn group(action: &str) -> &'static str {
    match action {
        a if a.starts_with("domains-") => "domains",
        a if a.starts_with("alerts-") => "alerts",
        a if a.starts_with("apps-") => "apps",
        a if a.starts_with("branding-") => "branding",
        a if a.starts_with("dns-") => "dns",
        a if a.starts_with("federation-") => "federation",
        a if a.starts_with("monitor-") || a.starts_with("reports-") => "monitor",
        a if a.starts_with("setup-") => "setup",
        _ => "terms",
    }
}

/// The run's own rows, for the `{a_user}` style placeholders a table may use.
pub struct Ids {
    pub a_user: i64,
    pub b_user: i64,
    pub a_domain: i64,
    pub b_domain: i64,
    pub a_mailbox: i64,
    pub b_mailbox: i64,
    pub a_msg1: i64,
    pub a_msg2: i64,
}
impl Ids {
    pub fn subst(&self, text: &str) -> String {
        text.replace("{a_user}", &self.a_user.to_string())
            .replace("{b_user}", &self.b_user.to_string())
            .replace("{a_domain}", &self.a_domain.to_string())
            .replace("{b_domain}", &self.b_domain.to_string())
            .replace("{a_mailbox}", &self.a_mailbox.to_string())
            .replace("{b_mailbox}", &self.b_mailbox.to_string())
            .replace("{a_msg1}", &self.a_msg1.to_string())
            .replace("{a_msg2}", &self.a_msg2.to_string())
    }
}

/// Replace `"key":<n>` numbers that are this run's generated ids by a stable name.
fn mask_ids(text: &str, keys: &[&str], ids: &[(i64, &str)]) -> String {
    let mut out = text.to_owned();
    for key in keys {
        for (n, name) in ids {
            let from = format!("\"{key}\":{n}");
            let mut at = 0;
            while let Some(i) = out[at..].find(&from) {
                let end = at + i + from.len();
                if out.as_bytes().get(end).is_some_and(|b| b.is_ascii_digit()) {
                    at = end;
                    continue;
                }
                let to = format!("\"{key}\":\"{name}\"");
                out.replace_range(at + i..end, &to);
                at += i + to.len();
            }
        }
    }
    out
}

/// Dates of the monitor seeds (hours ago) and the process task count, both run-specific.
fn mask_run(text: &str, dates: &[(String, String)]) -> String {
    let mut out = text.to_owned();
    for (date, token) in dates {
        out = out.replace(
            &format!("\"date\":\"{date}\""),
            &format!("\"date\":\"{token}\""),
        );
    }
    // The MTA-STS policy id is the generation time.
    let marker = "v=STSv1; id=";
    let mut at = 0;
    while let Some(i) = out[at..].find(marker) {
        let start = at + i + marker.len();
        let len = out[start..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        out.replace_range(start..start + len, "<stamp>");
        at = start + 7;
    }
    for key in ["goroutines", "lastAckAgeSeconds"] {
        let marker = format!("\"{key}\":");
        let mut at = 0;
        while let Some(i) = out[at..].find(&marker) {
            let start = at + i + marker.len();
            let len = out[start..]
                .bytes()
                .take_while(|b| b.is_ascii_digit())
                .count();
            out.replace_range(start..start + len, "\"<n>\"");
            at = start + 5;
        }
    }
    out
}

/// Run-time timestamps in a rendered body (`2026-10-0x` seeds stay).
fn mask_stamps(text: &str, keys: &[&str]) -> String {
    let mut out = text.to_owned();
    for key in keys {
        for marker in [format!("\"{key}\":\""), format!("\"{key}\": \"")] {
            let mut at = 0;
            while let Some(i) = out[at..].find(&marker) {
                let start = at + i + marker.len();
                let Some(len) = out[start..].find('"') else {
                    break;
                };
                if !out[start..].starts_with("2026-10-0") {
                    out.replace_range(start..start + len, "<timestamp>");
                    at = start + "<timestamp>".len();
                } else {
                    at = start + len;
                }
            }
        }
    }
    out
}

const EFFECTS: &str = "SELECT j FROM (SELECT 1 k, id, to_jsonb(t)::text j FROM terms_of_use t UNION ALL SELECT 2, tou_id, to_jsonb(a)::text FROM terms_of_use_acceptance a) x ORDER BY k, id";
const FIRST: i64 = 9101;
/// Fixed ids keep goldens stable; the next generated id is pinned too.
const NEXT_ID: &str = "SELECT setval(pg_get_serial_sequence('terms_of_use','id'), 9200, false)";
const DOC: &str = "INSERT INTO terms_of_use(id,name,version,body_md,lang,require_scroll,enabled,created_at) OVERRIDING SYSTEM VALUE VALUES ";

fn docs(rows: &[(&str, i32, &str, &str)]) -> String {
    let values = rows
        .iter()
        .enumerate()
        .map(|(i, (name, version, body, lang))| {
            format!(
                "({},'{name}',{version},'{body}','{lang}',true,true,'2026-10-01 10:00:00+00')",
                FIRST + i as i64
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{DOC}{values}")
}

fn specs(action: &str, label: &str, user: i64) -> Option<Case> {
    let base = |method, pattern, perm, status| Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: vec![],
        seed: vec![NEXT_ID.into()],
        cleanup: vec!["DELETE FROM terms_of_use WHERE id>=9000".into()],
        effects: EFFECTS,
        table: "terms_of_use",
        channels: vec![],
        status,
        replace: vec![],
        unshift: vec![],
    };
    let mut c = match action {
        "terms-list" => base("GET", "/admin/terms-of-use", "access.policy_read", 200),
        "terms-create" => base("POST", "/admin/terms-of-use", "access.policy_write", 201),
        "terms-update" => base(
            "PUT",
            "/admin/terms-of-use/{id}",
            "access.policy_write",
            204,
        ),
        "terms-delete" => base(
            "DELETE",
            "/admin/terms-of-use/{id}",
            "access.policy_write",
            204,
        ),
        _ => return None,
    };
    let three = docs(&[
        ("zeta", 1, "z body", "en"),
        ("Alpha", 2, "a body", "fr"),
        ("beta", 1, "b body", "en"),
    ]);
    match action {
        "terms-list" => {
            if label != "empty" {
                c.seed.push(three.clone());
            }
            match label {
                "limit-two" => c.query = "?limit=2".into(),
                "limit-big" => c.query = "?limit=99999".into(),
                "limit-bad" => c.query = "?limit=abc".into(),
                "limit-zero" => c.query = "?limit=0".into(),
                "limit-negative" => c.query = "?limit=-3".into(),
                "limit-one" => c.query = "?limit=1".into(),
                "limit-padded" => c.query = "?limit=%2B2".into(),
                "ignored-query" => c.query = "?q=%00&x=%zz&offset=5".into(),
                "escaping" => c.seed.push(format!(
                    "{DOC}({},'a<b>&c',1,'<script>&amp; \u{2028} é \u{1F600}','en',false,false,'2026-10-02 10:00:00+00')",
                    FIRST + 10
                )),
                _ => {}
            }
        }
        "terms-create" => {
            let ok = r#"{"name":"Acceptable use","version":3,"body_md":"Rules","lang":"fr","require_scroll":true,"enabled":true}"#;
            c.body = ok.into();
            match label {
                "repeat" => {}
                "default-lang" => c.body = r#"{"name":"Acceptable use","version":1,"body_md":"x"}"#.into(),
                "flags-off" => c.body = r#"{"name":"n","version":1,"body_md":"x","require_scroll":false,"enabled":false}"#.into(),
                "bad-json" => c.body = "{\"name\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "string-body" => c.body = "\"x\"".into(),
                "missing-name" => c.body = r#"{"version":1,"body_md":"x"}"#.into(),
                "missing-body" => c.body = r#"{"name":"n","version":1}"#.into(),
                "empty-name" => c.body = r#"{"name":"","version":1,"body_md":"x"}"#.into(),
                "version-zero" => c.body = r#"{"name":"n","version":0,"body_md":"x"}"#.into(),
                "version-missing" => c.body = r#"{"name":"n","body_md":"x"}"#.into(),
                "version-negative" => c.body = r#"{"name":"n","version":-1,"body_md":"x"}"#.into(),
                "version-float" => c.body = r#"{"name":"n","version":1.5,"body_md":"x"}"#.into(),
                "version-whole-float" => c.body = r#"{"name":"n","version":1.0,"body_md":"x"}"#.into(),
                "version-exponent" => c.body = r#"{"name":"n","version":1e2,"body_md":"x"}"#.into(),
                "version-string" => c.body = r#"{"name":"n","version":"1","body_md":"x"}"#.into(),
                "version-null" => c.body = r#"{"name":"n","version":null,"body_md":"x"}"#.into(),
                "version-overflow" => c.body = r#"{"name":"n","version":3000000000,"body_md":"x"}"#.into(),
                "version-max-int" => c.body = r#"{"name":"n","version":2147483647,"body_md":"x"}"#.into(),
                "version-huge" => c.body = r#"{"name":"n","version":99999999999999999999,"body_md":"x"}"#.into(),
                "unknown-key" => c.body = r#"{"name":"n","version":1,"body_md":"x","extra":{"a":[1,2]}}"#.into(),
                "folded" => c.body = r#"{"NAME":"n","Version":2,"BODY_MD":"x","Lang":"de","REQUIRE_SCROLL":true,"Enabled":true}"#.into(),
                "duplicate-key" => c.body = r#"{"name":"first","name":"second","version":1,"body_md":"x"}"#.into(),
                "null-field-keeps" => c.body = r#"{"name":"n","name":null,"version":1,"body_md":"x","lang":null}"#.into(),
                "flag-string" => c.body = r#"{"name":"n","version":1,"body_md":"x","enabled":"yes"}"#.into(),
                "name-number" => c.body = r#"{"name":5,"version":1,"body_md":"x"}"#.into(),
                "nul-name" => c.body = r#"{"name":"a\u0000b","version":1,"body_md":"x"}"#.into(),
                "escaped" => c.body = r#"{"name":"a<b>&c","version":1,"body_md":"  😀 é"}"#.into(),
                "bad-utf8" => c.body = "{\"name\":\"a\u{FFFD}b\",\"version\":1,\"body_md\":\"x\"}".into(),
                "trailing-data" => c.body = format!("{ok} {{\"x\":1}}"),
                "trailing-junk" => c.body = format!("{ok} garbage"),
                "duplicate" => {
                    c.seed.push(docs(&[("Acceptable use", 3, "old", "fr")]));
                }
                "same-name-other-lang" => {
                    c.seed.push(docs(&[("Acceptable use", 3, "old", "en")]));
                }
                "oversize" => {
                    c.body = format!("{{\"name\":\"n\",\"version\":1,\"body_md\":\"{}\"}}", "a".repeat((1 << 20) + 16));
                    c.status = 400;
                }
                "denied" | "scoped" | "success" => {}
                _ => return None,
            }
            if label == "denied" {
                c.status = 403;
            }
            if label != "success"
                && !matches!(
                    label,
                    "denied"
                        | "scoped"
                        | "repeat"
                        | "default-lang"
                        | "flags-off"
                        | "version-max-int"
                        | "unknown-key"
                        | "folded"
                        | "duplicate-key"
                        | "null-field-keeps"
                        | "escaped"
                        | "trailing-data"
                        | "trailing-junk"
                        | "same-name-other-lang"
                        | "bad-utf8"
                )
            {
                c.status = 0;
            }
        }
        "terms-update" | "terms-delete" => {
            let target = (FIRST + 1).to_string();
            c.fill = vec![target.clone()];
            c.seed.push(three.clone());
            // A cascading acceptance row for the document that is deleted or edited.
            c.seed.push(format!(
                "INSERT INTO terms_of_use_acceptance(user_id,tou_id,version,accepted_at,source_ip) VALUES ({user},{target},2,'2026-10-01 11:00:00+00','10.0.0.1')"
            ));
            let ok = r#"{"name":"Renamed","version":5,"body_md":"new body","lang":"de","require_scroll":false,"enabled":false}"#;
            if action == "terms-update" {
                c.body = ok.into();
            }
            match label {
                "success" | "denied" | "scoped" | "repeat" => {}
                "missing" => c.fill = vec!["999999".into()],
                "zero-id" => c.fill = vec!["0".into()],
                "negative-id" => c.fill = vec!["-5".into()],
                "plus-id" => c.fill = vec![format!("%2B{target}")],
                "padded-id" => c.fill = vec![format!("0{target}")],
                "bad-id" => c.fill = vec!["abc".into()],
                "float-id" => c.fill = vec!["1.5".into()],
                "huge-id" => c.fill = vec!["99999999999999999999".into()],
                "bad-id-bad-json" if action == "terms-update" => {
                    c.fill = vec!["abc".into()];
                    c.body = "{".into();
                }
                "missing-bad-body" if action == "terms-update" => {
                    c.fill = vec!["999999".into()];
                    c.body = r#"{"name":"n"}"#.into();
                }
                "missing-version-overflow" if action == "terms-update" => {
                    c.fill = vec!["999999".into()];
                    c.body = r#"{"name":"n","version":3000000000,"body_md":"x"}"#.into();
                }
                "bad-json" if action == "terms-update" => c.body = "{\"name\":".into(),
                "null-body" if action == "terms-update" => c.body = "null".into(),
                "array-body" if action == "terms-update" => c.body = "[1]".into(),
                "empty-body" if action == "terms-update" => c.body = String::new(),
                "missing-body" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":1}"#.into()
                }
                "version-zero" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":0,"body_md":"x"}"#.into()
                }
                "version-float" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":2.5,"body_md":"x"}"#.into()
                }
                "version-overflow" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":3000000000,"body_md":"x"}"#.into()
                }
                "default-lang" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":1,"body_md":"x"}"#.into()
                }
                "folded" if action == "terms-update" => {
                    c.body = r#"{"NAME":"n","VERSION":4,"Body_Md":"x","LANG":"it"}"#.into()
                }
                "unknown-key" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":1,"body_md":"x","zzz":null}"#.into()
                }
                "null-field-keeps" if action == "terms-update" => {
                    c.body = r#"{"name":"n","version":1,"body_md":"x","lang":null,"enabled":null}"#
                        .into()
                }
                "duplicate" if action == "terms-update" => {
                    // Rename onto another document's (name, version, lang).
                    c.body = r#"{"name":"zeta","version":1,"body_md":"x","lang":"en"}"#.into();
                }
                "same-values" if action == "terms-update" => {
                    c.body = r#"{"name":"Alpha","version":2,"body_md":"a body","lang":"fr","require_scroll":true,"enabled":true}"#.into();
                }
                "others-untouched" => {}
                _ => return None,
            }
            if label == "denied" {
                c.status = 403;
            } else if matches!(
                label,
                "missing"
                    | "zero-id"
                    | "negative-id"
                    | "huge-id"
                    | "bad-id"
                    | "float-id"
                    | "padded-id"
                    | "plus-id"
                    | "missing-bad-body"
                    | "missing-version-overflow"
                    | "bad-id-bad-json"
                    | "repeat"
            ) || (action == "terms-update"
                && !matches!(
                    label,
                    "success"
                        | "scoped"
                        | "default-lang"
                        | "folded"
                        | "unknown-key"
                        | "null-field-keeps"
                        | "same-values"
                        | "others-untouched"
                ))
            {
                c.status = 0;
            }
        }
        _ => {}
    }
    if label == "denied" {
        c.status = 403;
    }
    if label == "repeat" {
        c.status = 0;
    }
    if label == "ignored-query" && action != "terms-list" {
        c.query = "?limit=-1&q=%00&x=%zz".into();
    }
    Some(c)
}

/// An admin token (the governed grants are the only authority).
fn token(user: i64) -> String {
    super::admin_token(user)
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("plat5-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "plat5-admin").await?;
    let b = fixture::account(&owner, "plat5-other").await?;
    if label.starts_with("self-domain") {
        std::env::set_var("FEDERATION_LOCAL_DOMAIN", "self.test");
    }
    let zone = if group(action) == "dns" {
        let zone = super::dns::Zone::start()
            .await
            .map_err(|e| format!("fake DNS needs 127.0.0.77:53 (run as root): {e}"))?;
        let resolv = std::env::temp_dir().join("setjoin-plat5-resolv.conf");
        std::fs::write(
            &resolv,
            "nameserver 127.0.0.77\noptions timeout:2 attempts:1\n",
        )?;
        std::env::set_var("GOFREE_ORACLE_RESOLV_CONF", &resolv);
        Some(zone)
    } else {
        None
    };
    let mut dates = vec![];
    for hours in super::monitor::OFFSETS {
        let text: String = owner
            .query_one("SELECT to_char((now() - make_interval(hours => $1::int)) AT TIME ZONE 'UTC','YYYY-MM-DD')", &[&(hours as i32)])
            .await?
            .get(0);
        dates.push((text, format!("<date-{hours}h>")));
    }
    let ids = Ids {
        a_user: a.user,
        b_user: b.user,
        a_domain: a.domain,
        b_domain: b.domain,
        a_mailbox: a.mailbox,
        b_mailbox: b.mailbox,
        a_msg1: a.two_labels,
        a_msg2: a.inbox_only,
    };
    let case = match group(action) {
        "domains" => super::domains::specs(action, label),
        "alerts" => super::alerts::specs(action, label),
        "apps" => super::apps::specs(action, label),
        "branding" => super::branding::specs(action, label),
        "dns" => super::dns::specs(action, label),
        "federation" => super::federation::specs(action, label),
        "monitor" => super::monitor::specs(action, label),
        "setup" => super::setup::specs(action, label),
        _ => specs(action, label, a.user),
    }
    .ok_or(());
    let Ok(case) = case else {
        // An unknown case still created its fixtures: do not leak them.
        for account in [&a, &b] {
            common::remove_blob_account(&owner, account).await?;
        }
        return Err("unknown platform action".into());
    };
    let case = Case {
        fill: case.fill.iter().map(|v| ids.subst(v)).collect(),
        query: ids.subst(&case.query),
        body: ids.subst(&case.body),
        seed: case.seed.iter().map(|v| ids.subst(v)).collect(),
        cleanup: case.cleanup.iter().map(|v| ids.subst(v)).collect(),
        ..case
    };
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let domain_names = [
        (domain_of(a.domain).await?, "host-a.test"),
        (domain_of(b.domain).await?, "host-b.test"),
    ];
    let id_names = [(a.domain, "<domain-a>"), (b.domain, "<domain-b>")];
    let mailbox_names = [(a.mailbox, "<mailbox-a>"), (b.mailbox, "<mailbox-b>")];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        for (n, name) in &id_names {
            out = out.replace(&format!("domain={n}"), &format!("domain={name}"));
        }
        out = mask_ids(&out, &["id", "domain_id", "host_domain_id"], &id_names);
        mask_ids(
            &out,
            &["catch_all_mailbox_id", "catchAllMailboxId", "mailbox_id"],
            &mailbox_names,
        )
    };
    let sent_body = case.body.clone();
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "scoped" => (vec![case.perm], Some(b.domain)),
        "scoped-own" => (vec![case.perm], Some(a.domain)),
        "scoped-other" => (vec![case.perm], Some(b.domain)),
        _ => (vec![case.perm], None),
    };
    let role = format!("plat5-role-{}", a.user);
    owner
        .execute(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)",
            &[&role, &permissions, &scope],
        )
        .await?;
    owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&a.user, &role]).await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F08'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let users: Vec<(i64, &str)> = vec![(a.user, "<admin>"), (b.user, "<other>")];
    let result = async {
        let uploads: Arc<std::sync::Mutex<Vec<Value>>> = Arc::new(std::sync::Mutex::new(vec![]));
        let seen = uploads.clone();
        let s3 = common::fake_upstream(move |request| {
            let seen = seen.clone();
            async move {
                use http_body_util::BodyExt;
                let (parts, body) = request.into_parts();
                let raw = body.collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                if parts.method == hyper::Method::PUT {
                    seen.lock().expect("uploads").push(super::branding::upload(&parts, &raw));
                }
                // minio asks for the bucket region before a PUT.
                if parts.method == hyper::Method::GET && parts.uri.query().is_some_and(|q| q.contains("location")) {
                    return Response::new(common::full("<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"));
                }
                let mut response = Response::new(common::full(""));
                response.headers_mut().insert("etag", "\"d41d8cd98f00b204e9800998ecf8427e\"".parse().expect("etag"));
                response
            }
        })
        .await;
        let go = if label.starts_with("self-domain") {
            common::go_oracle::start_named_with_federation_domain(&db, s3, "gofree-plat5-http", "self.test").await?
        } else {
            common::go_oracle::start_named(&db, s3, None, "gofree-plat5-http").await?
        };
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: PlatformTermsRoute::new(exec, Arc::new(common::recovery_keys()), "mailserver".into())
                .with_store(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"), "mailblobs", "test-access", "test-secret")?))
                .with_resolver(setjoin_platform::dns::Resolver::Server(super::dns::ADDRESS.parse().expect("address")))
                .with_worker(ScopedExecutor::from_dsn_with(&db.dsn, 4, setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient }).map_err(|e| e.0)?),
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F08" && r["slice"] == "terms-remaining" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        // A rate-limit replay needs the front door's route budgets (Go's defaults); recording
        // leaves every budget to Go.
        let edge_limit = (!recording && burst(action, label).is_some()).then(|| {
            setjoin_gateway::jmap::limit::EdgeLimit::new(
                setjoin_gateway::jmap::limit::Limiter::new(100_000, 60),
                Arc::new(|| -> BoxFuture<bool> { Box::pin(async { true }) }),
            )
        });
        let table = RouteTable::proxy_all().with(adapter);
        let table = if !recording && native_mux(action) {
            table.with_catchall(setjoin_gateway::catchall::CatchallRoute::new())
        } else {
            table
        };
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit,
            },
            table,
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        for statement in &case.seed {
            owner.batch_execute(statement).await?;
        }
        let mut concrete = case.pattern.to_owned();
        let mut verbatim = false;
        for value in &case.fill {
            if let Some(raw) = value.strip_prefix('!') {
                // A verbatim request path (escaped or unclean spellings).
                concrete = raw.to_owned();
                verbatim = true;
            } else if let (Some(open), Some(close)) = (concrete.find('{'), concrete.find('}')) {
                // The first remaining `{placeholder}` of the route pattern takes the value.
                concrete.replace_range(open..=close, value);
            } else if concrete.ends_with('/') {
                // A subtree registration (`/auth/admin/`) takes the rest of the path.
                concrete.push_str(value);
            }
        }
        let external = external_path(&concrete, label, verbatim);
        let effects = async |c: &tokio_postgres::Client| -> Result<Value, BoxError> {
            Ok(json!(super::rows(c, case.effects).await?))
        };
        if label == "repeat" {
            let uri = format!("{external}{}", case.query);
            let first = common::send(address, request(&case, &uri, a.user, sent_body.clone())?).await;
            let first_status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && case.status != 0 && first_status != case.status {
                return Err(format!("initial {action}: {first_status} {data:?}").into());
            }
        }
        let before = effects(&owner).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut listeners = vec![];
        for channel in &case.channels {
            listeners.push((*channel, db.listen(channel).await?));
        }
        let uri = format!("{external}{}", case.query);
        let build = || request(&case, &uri, a.user, sent_body.clone());
        if let Some(spend) = burst(action, label) {
            whole_window(if group(action) == "setup" { 60 } else { 900 }).await?;
            for _ in 0..spend {
                let spent = common::send(address, build()?).await;
                let spent_status = spent.status().as_u16();
                let _ = common::body_bytes(spent).await;
                if spent_status == 429 {
                    return Err(format!("{action}/{label}: budget spent before the burst ended").into());
                }
            }
        }
        let response = common::send(address, build()?).await;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = effects(&owner).await?;
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) {
                return Err("invalid audit id".into());
            }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                    row[key] = json!("<checksum>");
                }
            }
            *row = masked(row.clone(), &users, &names)?;
        }
        let mut notify = vec![];
        for (channel, listener) in &mut listeners {
            for event in listener.drain(&owner).await? {
                let payload = serde_json::from_str::<Value>(&event).unwrap_or(json!(event));
                notify.push(json!({"channel":channel,"payload":masked(payload, &users, &names)?}));
            }
        }
        if recording && case.status != 0 && status != case.status {
            return Err(format!("Go {action}/{label}: expected {}, got {status}: {raw}", case.status).into());
        }
        let mut text = names(&raw);
        for (from, to) in &case.replace {
            text = text.replace(from.as_str(), to);
        }
        text = super::mask_uuids(&mask_run(&mask_stamps(&pin_load_values(&text), &["createdAt", "updatedAt", "lastChecked"]), &dates));
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        // A HEAD answer has no body: its Content-Length is the one Go advertised, so keep it.
        if case.method != "HEAD" {
            if let Some(length) = headers.get_mut("content-length") {
                *length = json!([text.len().to_string()]);
            }
        }
        let (before, after) = (masked(before, &users, &names)?, masked(after, &users, &names)?);
        let effects = json!([{"table":case.table,"before":before,"after":after}]);
        let mut req = json!({"method":case.method,"path":case.pattern,"external_path":external.clone()});
        if !case.body.is_empty() {
            req["body"] = json!(names(&case.body));
        }
        if !case.query.is_empty() {
            req["query"] = json!(case.query);
        }
        let mut observation = json!({"request":req,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        // The goldens name the actor's own domain by the id it had on the recording database
        // (101); a seasoned clone creates it at a different id, so the path maps back.
        let unshift = case.unshift.clone();
        let mut unshift_domain: Option<(String, String)> = None;
        if case.pattern.starts_with("/admin/domains/") && ids.a_domain != 101 {
            // Boundary-aware: the id must end at `/`, `"`, `?`, `\\` (escaped quote) or the end.
            unshift_domain = Some((format!("/domains/{}", ids.a_domain), "/domains/101".to_owned()));
        }
        if !unshift.is_empty() || unshift_domain.is_some() {
            let mut whole = observation.to_string();
            for (from, to) in &unshift {
                whole = whole.replace(from.as_str(), to);
            }
            if let Some((from, to)) = &unshift_domain {
                whole = replace_bounded(&whole, from, to);
            }
            observation = serde_json::from_str(&whole)?;
            let length = observation["response"]["body"].as_str().map(|b| b.len().to_string());
            if let (Some(length), Some(slot)) = (length, observation["response"]["headers"].get_mut("content-length")) {
                *slot = json!([length]);
            }
        }
        if group(action) == "branding" {
            observation["s3"] = json!(uploads.lock().expect("uploads").clone());
        }
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            let mut zero = vec!["setjoin_gateway_proxied_to_go_by_family_total{family=\"F08\"} 0"];
            if native_mux(action) {
                // Nothing on these root-pinned surfaces may reach Go, in any family.
                zero.push("setjoin_gateway_proxied_to_go_total 0");
            }
            for line in zero {
                if !metrics.lines().any(|l| l == line) {
                    return Err(format!("replay forwarded to Go ({line}): {metrics}").into());
                }
            }
        }
        server.abort();
        let stem = if action.starts_with(group(action)) { format!("{action}-{label}") } else { format!("{}-{action}-{label}", group(action)) };
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/platform/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = format!("{} {}", case.method, case.pattern);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let mut expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            if let Some(body) = expected["observation"]["response"]["body"].as_str() {
                expected["observation"]["response"]["body"] = json!(mask_stamps(&pin_load_values(body), &["createdAt", "updatedAt", "lastChecked"]));
            }
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                eprintln!("FAULT-OBSERVED {fault}: {status}");
                compared.err().ok_or("planted family fault survived")?;
                eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
                return Ok(());
            }
            compared?;
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    std::env::remove_var("FEDERATION_LOCAL_DOMAIN");
    std::env::remove_var("GOFREE_ORACLE_RESOLV_CONF");
    drop(zone);
    for statement in &case.cleanup {
        owner.batch_execute(statement).await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role])
        .await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

/// The request path on the wire. Go serves its pinned prefixes
/// (`scripts/api-pinned-prefixes.txt`) at the root and everything else under the `/api`
/// mount; an `api-alias` case sends a pinned route through the mount, and a verbatim (`!`)
/// path goes out as written.
fn external_path(concrete: &str, label: &str, verbatim: bool) -> String {
    let pinned = include_str!("../../../../../scripts/api-pinned-prefixes.txt")
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .filter(|prefix| prefix.starts_with('/'))
        .any(|prefix| {
            concrete == prefix
                || concrete
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        });
    if verbatim || (pinned && !label.contains("api-alias")) {
        concrete.to_owned()
    } else {
        format!("/api{concrete}")
    }
}

/// The oracle request. An `origin` or `authorization` entry in `case.headers` replaces the
/// default (an empty value omits the header); `authorization` expands [`expand`]'s markers.
fn request(case: &Case, uri: &str, user: i64, body: String) -> Result<Request<Body>, BoxError> {
    let named = |wanted: &str| case.headers.iter().find(|(name, _)| *name == wanted);
    let mut request = Request::builder()
        .method(case.method)
        .uri(uri)
        .header("host", "mail.test");
    let origin = named("origin").map_or("http://mail.test".to_owned(), |(_, v)| v.clone());
    if !origin.is_empty() {
        request = request.header("origin", origin);
    }
    request = request.header("x-request-id", "gofree-plat5-oracle");
    let authorization = named("authorization")
        .map_or(format!("Bearer {}", token(user)), |(_, v)| expand(v, user));
    if !authorization.is_empty() {
        request = request.header("authorization", authorization);
    }
    if named("content-type").is_none() {
        request = request.header("content-type", "application/json");
    }
    for (name, value) in &case.headers {
        if !matches!(*name, "origin" | "authorization") {
            request = request.header(*name, value.as_str());
        }
    }
    Ok(request.body(common::full(body))?)
}

/// `{token}` is the persona's admin token; the other markers are forgeries Go must refuse,
/// or claims it must ignore.
fn expand(value: &str, user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let signed = |edit: &dyn Fn(&mut Value)| {
        format!("Bearer {}", super::admin_token_with(user, &[0x11; 32], edit))
    };
    match value {
        "Bearer {token}" => format!("Bearer {}", token(user)),
        "Bearer {token-bad-signature}" => {
            format!("Bearer {}", super::admin_token_with(user, &[0x12; 32], |_| {}))
        }
        "Bearer {token-expired}" => signed(&|claims| claims["exp"] = json!(1)),
        "Bearer {token-claims-identity-write}" => {
            signed(&|claims| claims["perms"] = json!(["identity.write"]))
        }
        "Bearer {token-act}" => signed(&|claims| claims["act"] = json!({"sub": "1"})),
        "Bearer {token-guest}" => signed(&|claims| {
            claims["acct"] = json!("guest");
            claims["admin"] = json!(false);
            claims["perms"] = json!([]);
        }),
        "Bearer {token-alg-none}" => {
            let payload = token(user).split('.').nth(1).unwrap_or_default().to_owned();
            let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
            format!("Bearer {header}.{payload}.")
        }
        other => other.to_owned(),
    }
}

/// Requests sent before the observed one to spend a route budget: Go's `setupLimit` is 60 per
/// minute and `authLimit` 20 per 15 minutes, per client IP.
fn burst(action: &str, label: &str) -> Option<usize> {
    if label != "rate-limit" {
        return None;
    }
    match group(action) {
        "setup" => Some(60),
        "auth-admin" => Some(20),
        _ => None,
    }
}

/// Root-pinned groups whose replay installs the native root mux and must reach Go zero times.
fn native_mux(action: &str) -> bool {
    matches!(group(action), "setup" | "auth-admin")
}

/// Waits out a window that would end during a burst (Go's buckets are epoch aligned).
async fn whole_window(window_secs: u64) -> Result<(), BoxError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let remaining = window_secs - now % window_secs;
    if remaining <= 30 {
        tokio::time::sleep(std::time::Duration::from_secs(remaining + 1)).await;
    }
    Ok(())
}

/// Replaces `from` only where the next character ends the id (`/`, `"`, `?`, an escaping `\\`
/// or the end of the text), so `/domains/16457` never rewrites the front of `/domains/164577`.
fn replace_bounded(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(from) {
        let (head, tail) = rest.split_at(at);
        let after = &tail[from.len()..];
        out.push_str(head);
        if after.chars().next().is_none_or(|c| matches!(c, '/' | '"' | '?' | '\\')) {
            out.push_str(to);
        } else {
            out.push_str(from);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}
