//! F03 slice `remaining` frozen-Go oracle: HTTP wire, committed rows, audit and notifications.
//! Record mode runs the covered Go binary behind the front door; replay mode serves the same
//! requests from Rust with no Go upstream. `simulate` is not in this oracle (forwarded to Go
//! until #405 ports the policy engine).
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    conditional_access::ConditionalAccessRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
use futures_util::FutureExt;

struct Probe {
    inner: ConditionalAccessRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn admin_token(user:i64)->String{admin_token_with(user,json!({}))}
fn admin_token_with(user: i64, extra:Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token_with(user,extra);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

const BASE: &str = "/admin/conditional-access";
fn route(action: &str) -> (&'static str, String) {
    let p = |tail: &str| format!("{BASE}{tail}");
    match action {
        "simulate" => ("POST", p("/simulate")),
        "gate" => ("GET", p("/break-glass")),
        "loc-list" => ("GET", p("/named-locations")),
        "loc-create" => ("POST", p("/named-locations")),
        "loc-update" => ("PUT", p("/named-locations/{id}")),
        "loc-delete" => ("DELETE", p("/named-locations/{id}")),
        "loc-restore" => ("POST", p("/named-locations/{id}/restore")),
        "str-list" => ("GET", p("/auth-strengths-list")),
        "str-create" => ("POST", p("/auth-strengths")),
        "str-update" => ("PUT", p("/auth-strengths/{id}")),
        "str-delete" => ("DELETE", p("/auth-strengths/{id}")),
        "principals" => ("GET", p("/resolve-principals")),
        "bg-get" => ("GET", p("/break-glass")),
        "bg-set" => ("PUT", p("/break-glass")),
        "signin" => ("GET", p("/signin-log")),
        "revoke" => ("POST", p("/sessions/{userId}/revoke")),
        "sessions-log" => ("GET", p("/sessions/log")),
        "tpl-list" => ("GET", p("/templates-list")),
        "tpl-instantiate" => ("POST", p("/templates/{slug}/instantiate")),
        "why" => ("GET", p("/why-lookup")),
        "impact" => ("GET", p("/policies/{id}/impact")),
        "coverage" => ("GET", p("/coverage")),
        "doctor" => ("GET", p("/doctor")),
        "export" => ("GET", p("/export")),
        "import" => ("POST", p("/import")),
        "diff" => ("POST", p("/diff")),
        "risk-list" => ("GET", "/admin/user-risk".into()),
        "risk-reset" => ("POST", "/admin/user-risk/{id}/reset".into()),
        _ => panic!("unknown F03 remaining action {action}"),
    }
}

// Fixed ids keep the goldens free of run-specific numbers.
const LOC_A: i64 = 941001; // live, cidr + country, trusted
const LOC_B: i64 = 941002; // live, countries only
const LOC_T: i64 = 941003; // tombstone
const LOC_C: i64 = 941004; // tombstone with LOC_A's name (restore clashes)
const STR_X: i64 = 941011; // custom authentication strength
const POL_A: i64 = 941401; // off, global, allow
const POL_B: i64 = 941402; // report_only, user scope, block (would-block sign-ins)
const POL_D: i64 = 941403; // on, global, allow
const MISSING: i64 = 99999999;

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Keys whose integer values name a user.
const USER_KEYS: [&str; 7] = [
    "user_id",
    "actor_id",
    "actor",
    "created_by",
    "updated_by",
    "id",
    "target_id",
];
/// Keys whose integer values may name a row the case created.
const NEW_KEYS: [&str; 5] = [
    "id",
    "target_id",
    "policy_id",
    "revocation_id",
    "created_id",
];

fn mask(v: &mut Value, users: &[(i64, &str)], new_ids: &[i64], in_users: bool) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if matches!(
                    k.as_str(),
                    "value" | "after_state" | "before_state" | "exclude_users"
                ) {
                    if let Value::Array(items) = x {
                        for item in items.iter_mut() {
                            if let Some((_, name)) = item
                                .as_i64()
                                .and_then(|n| users.iter().find(|(i, _)| *i == n))
                            {
                                *item = json!(name);
                            }
                        }
                        continue;
                    }
                }
                if let Some(n) = x.as_i64() {
                    let user = users.iter().find(|(i, _)| *i == n);
                    if let Some((_, name)) =
                        user.filter(|_| USER_KEYS.contains(&k.as_str()) && (k != "id" || in_users))
                    {
                        *x = json!(name);
                    } else if NEW_KEYS.contains(&k.as_str()) && new_ids.contains(&n) {
                        *x = json!("<new>");
                    }
                } else {
                    let users_key = k == "users" || k == "admins";
                    mask(x, users, new_ids, users_key || in_users);
                }
            }
        }
        Value::Array(xs) => xs
            .iter_mut()
            .for_each(|x| mask(x, users, new_ids, in_users)),
        Value::String(s) => {
            if timestamp_like(s) && !fixture_time(s) {
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
}
fn masked(
    mut v: Value,
    users: &[(i64, &str)],
    new_ids: &[i64],
    names: &dyn Fn(&str) -> String,
) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    check_envelopes(&mut v)?;
    mask(&mut v, users, new_ids, false);
    Ok(v)
}

/// Replace `"key":<number>` (with or without a space after the colon) when the number is
/// exactly `n`.
fn replace_number(text: &str, key: &str, n: i64, with: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let pattern = format!("\"{key}\":");
    let mut rest = text;
    while let Some(at) = rest.find(&pattern) {
        let after = &rest[at + pattern.len()..];
        let trimmed = after.trim_start_matches(' ');
        let spaces = after.len() - trimmed.len();
        let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
        out.push_str(&rest[..at + pattern.len()]);
        if digits > 0 && trimmed[..digits] == n.to_string() {
            out.push_str(&after[..spaces]);
            out.push_str(&format!("\"{with}\""));
            rest = &trimmed[digits..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Replace a bare array member `n` (`[n,`, `, n]`, `[n]`) with a quoted name.
fn replace_member(text: &str, n: i64, with: &str) -> String {
    let digits = n.to_string();
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(found) = text[at..].find(&digits) {
        let start = at + found;
        let end = start + digits.len();
        let before = text[..start].chars().rev().find(|c| *c != ' ');
        let after = text[end..].chars().find(|c| *c != ' ');
        let tight_before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let tight_after = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        out.push_str(&text[at..start]);
        if tight_before
            && tight_after
            && matches!(before, Some('[') | Some(','))
            && matches!(after, Some(',') | Some(']'))
        {
            out.push_str(&format!("\"{with}\""));
        } else {
            out.push_str(&digits);
        }
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

/// The recorded fixture instants (2026-10-01 12:00:00[.25|.5], 12:30:00, and the 2025-09 rows).
/// Matching only the date made a seeded `now() - 40 days` row look like a fixture on the one day
/// of the year that lands on 2026-10-01 (#472); a run-time instant never equals these exactly.
fn fixture_time(s: &str) -> bool {
    if s.starts_with("2025-09-") {
        return true;
    }
    let Some(rest) = s.strip_prefix("2026-10-01") else { return false };
    let Some(rest) = rest.strip_prefix(['T', ' ']) else { return false };
    let time = rest.trim_end_matches(['Z']).trim_end_matches("+00:00").trim_end_matches("+00");
    matches!(time, "12:00:00" | "12:00:00.25" | "12:00:00.5" | "12:30:00")
}

/// Quoted timestamp strings that are not fixture times become `<timestamp>`.
fn scrub_timestamps(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        out.push_str(&rest[..=start]);
        rest = &rest[start + 1..];
        let mut end = 0;
        let bytes = rest.as_bytes();
        while end < bytes.len() {
            if bytes[end] == b'\\' {
                end += 2;
                continue;
            }
            if bytes[end] == b'"' {
                break;
            }
            end += 1;
        }
        let end = end.min(bytes.len());
        let inner = &rest[..end];
        if timestamp_like(inner) && !fixture_time(inner) {
            out.push_str("<timestamp>");
        } else {
            out.push_str(inner);
        }
        if end < rest.len() {
            out.push('"');
            rest = &rest[end + 1..];
        } else {
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

const TABLES: [(&str, &str); 6] = [
    (
        "conditional_access_policies",
        "SELECT (to_jsonb(p) - 'enabled')::text FROM conditional_access_policies p ORDER BY priority, name, id",
    ),
    (
        "named_locations",
        "SELECT to_jsonb(n)::text FROM named_locations n ORDER BY name, id",
    ),
    (
        "auth_strengths",
        "SELECT to_jsonb(a)::text FROM auth_strengths a ORDER BY id",
    ),
    (
        "system_config",
        "SELECT to_jsonb(s)::text FROM system_config s WHERE key LIKE 'ca\\_%' ORDER BY key",
    ),
    (
        "user_risk",
        "SELECT to_jsonb(r)::text FROM user_risk r ORDER BY user_id",
    ),
    (
        "session_revocations",
        "SELECT to_jsonb(r)::text FROM session_revocations r ORDER BY id",
    ),
];
async fn snapshot(c: &tokio_postgres::Client,devices:bool) -> Result<Vec<(String, Vec<Value>)>, BoxError> {
    let mut out = vec![];
    for (name, sql) in TABLES {
        out.push((name.to_string(), rows(c, sql).await?));
    }
    if devices {
        for (name,sql) in [
            ("devices","SELECT to_jsonb(d)::text FROM devices d WHERE id IN (946010,946011) ORDER BY id"),
            ("device_auth_nonces","SELECT to_jsonb(n)::text FROM device_auth_nonces n WHERE device_id IN (946010,946011) ORDER BY device_id,nonce"),
            ("user_devices","SELECT to_jsonb(d)::text FROM user_devices d WHERE id=946012"),
        ] {out.push((name.into(),rows(c,sql).await?));}
    }
    Ok(out)
}
fn ids_of(snap: &[(String, Vec<Value>)]) -> Vec<i64> {
    snap.iter()
        .flat_map(|(_, rows)| rows.iter())
        .filter_map(|r| r["id"].as_i64())
        .collect()
}

/// Cases share fixed fixture keys and global windows (audit id, receipts), so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, None).await
}

/// Record or replay many cases against ONE Go process (`action:label,...`), so the container
/// start-up is paid once.
pub async fn run_many(list: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ca2-http") else {
        return Ok(());
    };
    let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
    let go = common::go_oracle::start_named(&db, s3, None, "gofree-ca2-http").await?;
    let mut failed = vec![];
    for item in list.split(',').filter(|i| !i.is_empty()) {
        let (action, kind) = item.split_once(':').ok_or("action:label")?;
        let mut outcome = run_inner(action, kind, go.as_ref()).await;
        // A loaded shared host can time out the authority read (the adapter then forwards, which
        // the replay refuses); a second identical attempt must pass, so real faults still fail.
        if outcome
            .as_ref()
            .is_err_and(|e| e.to_string().contains("replay forwarded to Go"))
        {
            outcome = run_inner(action, kind, go.as_ref()).await;
        }
        match outcome {
            Ok(()) => eprintln!("CASE-OK {item}"),
            Err(e) => {
                eprintln!("CASE-FAIL {item}: {e}");
                failed.push(item.to_string());
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed: {failed:?}").into())
    }
}

async fn run_inner(
    action: &str,
    kind: &str,
    shared: Option<&common::go_oracle::GoOracle>,
) -> Result<(), BoxError> {
    let gate_mutant=kind.ends_with("-gate-mutant");
    let status_mutant=kind.ends_with("-status-mutant");
    let mutant=gate_mutant||status_mutant;
    let label=kind.strip_suffix("-gate-mutant").or_else(||kind.strip_suffix("-status-mutant")).unwrap_or(kind);
    let Some(db) = Db::for_case("ca2-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let gate_toggles: String = owner.query_one("SELECT jsonb_object_agg(key,enabled)::text FROM feature_toggles WHERE key IN ('feature.cae_runtime','feature.conditional_access','feature.device_lockdown','feature.device_trust_enforcement','feature.token_binding')",&[]).await?.get(0);
    let a = fixture::account(&owner, "ca2-admin").await?;
    let b = fixture::account(&owner, "ca2-other").await?;
    let t = fixture::account(&owner, "ca2-target").await?;
    let email_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT email FROM users WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let (a_email, b_email, t_email) = (
        email_of(a.user).await?,
        email_of(b.user).await?,
        email_of(t.user).await?,
    );
    let emails = [
        (a_email.clone(), "admin@host-a.test"),
        (b_email.clone(), "other@host-b.test"),
        (t_email.clone(), "target@host-t.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (email, name) in &emails {
            out = out.replace(email.as_str(), name);
        }
        for (id, name) in [(a.user, "admin"), (b.user, "other"), (t.user, "target")] {
            out = out
                .replace(
                    &format!("/sessions/{id}/revoke"),
                    &format!("/sessions/<{name}>/revoke"),
                )
                .replace(
                    &format!("/user-risk/{id}/reset"),
                    &format!("/user-risk/<{name}>/reset"),
                );
        }
        out
    };
    let users: Vec<(i64, &str)> = vec![
        (t.user, "<target>"),
        (a.user, "<admin>"),
        (b.user, "<other>"),
    ];
    // Grant shapes: global admin, scoped to the other domain, or no permission.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "foreign" => (
            vec!["access.policy_read", "access.policy_write"],
            Some(b.domain),
        ),
        _ => (vec!["access.policy_read", "access.policy_write"], None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("ca2-{}", a.user), &permissions, &scope],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    // Everything the routes read or write is set aside so the case sees fixture rows only.
    let aside = |sql: &'static str| {
        let owner = &owner;
        async move {
            Ok::<Vec<String>, BoxError>(
                owner
                    .query(sql, &[])
                    .await?
                    .iter()
                    .map(|r| r.get::<_, String>(0))
                    .collect(),
            )
        }
    };
    let aside_policies =
        aside("SELECT to_jsonb(p)::text FROM conditional_access_policies p ORDER BY id").await?;
    let aside_strengths =
        aside("SELECT to_jsonb(a)::text FROM auth_strengths a WHERE NOT builtin ORDER BY id")
            .await?;
    let aside_locations =
        aside("SELECT to_jsonb(n)::text FROM named_locations n ORDER BY id").await?;
    let aside_revocations =
        aside("SELECT to_jsonb(r)::text FROM session_revocations r ORDER BY id").await?;
    let aside_risk = aside("SELECT to_jsonb(r)::text FROM user_risk r ORDER BY user_id").await?;
    let aside_config =
        aside("SELECT to_jsonb(s)::text FROM system_config s WHERE key IN ('ca_break_glass_user_ids','ca_fail_mode')")
            .await?;
    owner.batch_execute("DELETE FROM conditional_access_policies; DELETE FROM auth_strengths WHERE NOT builtin; DELETE FROM named_locations; DELETE FROM user_risk;").await?;
    owner.batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM session_revocations; COMMIT;").await?;
    for table in [
        "named_locations",
        "auth_strengths",
        "session_revocations",
        "conditional_access_policies",
    ] {
        owner
            .execute(
                &format!("SELECT setval(pg_get_serial_sequence('{table}','id'), 950000, false)"),
                &[],
            )
            .await?;
    }
    // Named locations and strengths.
    let insert_location = "INSERT INTO named_locations(id,name,description,ip_ranges,countries,is_trusted,created_at,updated_at,deleted_at) VALUES($1,$2,$3,$4::text::jsonb,$5::text::jsonb,$6,'2026-10-01T12:00:00Z'::text::timestamptz,'2026-10-01T12:00:00.5Z'::text::timestamptz,$7::text::timestamptz)";
    let none: Option<String> = None;
    let tomb = Some("2026-10-01T12:30:00Z".to_string());
    for (id, name, description, cidrs, countries, trusted, deleted) in [
        (
            LOC_A,
            "ca2-hq",
            "Head <office>",
            r#"["10.0.0.0/8"]"#,
            r#"["US"]"#,
            true,
            &none,
        ),
        (
            LOC_B,
            "ca2-branch",
            "",
            "[]",
            r#"["DE","FR"]"#,
            false,
            &none,
        ),
        (
            LOC_T,
            "ca2-old",
            "Gone",
            r#"["192.0.2.0/24"]"#,
            "[]",
            false,
            &tomb,
        ),
        (LOC_C, "ca2-hq", "Old head", "[]", r#"["CA"]"#, false, &tomb),
    ] {
        owner
            .execute(
                insert_location,
                &[
                    &id,
                    &name,
                    &description,
                    &cidrs,
                    &countries,
                    &trusted,
                    deleted,
                ],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO auth_strengths(id,slug,name,description,requirement,min_acr,builtin,created_at,updated_at) VALUES($1,'ca2-custom','Custom <strength>','d','[[\"password\",\"totp\"]]','aal2',false,'2026-10-01T12:00:00Z','2026-10-01T12:00:00.5Z')",
            &[&STR_X],
        )
        .await?;
    // Policies (for impact, coverage, doctor, export, diff and import).
    let insert_policy = "INSERT INTO conditional_access_policies(id,priority,name,description,enabled,state,scope_type,scope_target,conditions,actions,exclude_users,exclude_groups,created_at,updated_at) VALUES($1,$2,$3,$4,false,$5,$6,$7,$8::text::jsonb,$9::text::jsonb,'[]','[]',now()-$10::text::interval,'2026-10-01T12:00:00.5Z'::text::timestamptz)";
    for (
        id,
        priority,
        name,
        description,
        state,
        scope_type,
        scope_target,
        conditions,
        actions,
        age,
    ) in [
        (
            POL_A,
            9701i32,
            "ca2-alpha",
            "Alpha <policy>",
            "off",
            "global",
            "",
            r#"{"client_type":"imap"}"#,
            r#"{"action":"allow"}"#,
            "1 day",
        ),
        (
            POL_B,
            9702,
            "ca2-beta",
            "",
            "report_only",
            "user",
            "9",
            r#"{"ip_reputation":"critical"}"#,
            r#"{"action":"block"}"#,
            "40 days",
        ),
        (
            POL_D,
            9704,
            "ca2-delta",
            "",
            "on",
            "global",
            "",
            "{}",
            r#"{"action":"allow"}"#,
            "1 day",
        ),
    ] {
        owner
            .execute(
                insert_policy,
                &[
                    &id,
                    &priority,
                    &name,
                    &description,
                    &state,
                    &scope_type,
                    &scope_target,
                    &conditions,
                    &actions,
                    &age,
                ],
            )
            .await?;
    }
    // Sign-in log rows for the trace and impact reads.
    let signin = "INSERT INTO ca_signin_log(id,occurred_at,user_id,source_ip,protocol,client_type,device_fp,country,matched_policy_id,decision,would_decision,report_only,correlation_id,evaluated) OVERRIDING SYSTEM VALUE VALUES($1,now()-$2::text::interval,$3,$4::text::inet,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::text::jsonb)";
    let seeded_signins: [(
        i64,
        &str,
        i64,
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<i64>,
        &str,
        Option<&str>,
        bool,
        Option<&str>,
        &str,
    ); 4] = [
        (
            941101,
            "10 minutes",
            a.user,
            Some("203.0.113.7"),
            Some("imap"),
            Some("imap"),
            Some("fp-1"),
            Some("US"),
            Some(POL_B),
            "allow",
            Some("block"),
            true,
            Some("ca2-corr-1"),
            r#"[{"policy_id":941402,"matched":true}]"#,
        ),
        (
            941102,
            "20 minutes",
            t.user,
            Some("198.51.100.9"),
            Some("web"),
            Some("web"),
            None,
            Some("DE"),
            Some(POL_B),
            "allow",
            Some("block"),
            true,
            Some("ca2-corr-2"),
            "[]",
        ),
        (
            941103,
            "30 minutes",
            a.user,
            None,
            None,
            None,
            None,
            None,
            None,
            "allow",
            None,
            false,
            None,
            "[]",
        ),
        (
            941104,
            "40 days",
            a.user,
            Some("203.0.113.8"),
            Some("smtp"),
            Some("smtp"),
            None,
            Some("US"),
            None,
            "block",
            None,
            false,
            Some("ca2-corr-old"),
            "[]",
        ),
    ];
    for (
        id,
        age,
        user,
        ip,
        proto,
        client,
        fp,
        country,
        matched,
        decision,
        would,
        report,
        corr,
        evaluated,
    ) in seeded_signins
    {
        owner
            .execute(
                signin,
                &[
                    &id, &age, &user, &ip, &proto, &client, &fp, &country, &matched, &decision,
                    &would, &report, &corr, &evaluated,
                ],
            )
            .await?;
    }
    // Would-block sign-ins (counted by impact) for BETA, as the policies slice seeds them.
    owner
        .execute(
            "INSERT INTO ca_signin_log(id,user_id,matched_policy_id,decision,would_decision,report_only) OVERRIDING SYSTEM VALUE VALUES(941105,$1,$2,'allow','step_up',true)",
            &[&a.user, &POL_B],
        )
        .await?;
    // Revocation log and user risk.
    for (id, user, scope, jti, reason, by) in [
        (
            941201i64,
            t.user,
            "all",
            None::<&str>,
            "admin_revoke_all",
            Some(a.user),
        ),
        (941202, b.user, "jti", Some("jti-1"), "logout", None),
    ] {
        owner
            .execute(
                "INSERT INTO session_revocations(id,user_id,scope,jti,reason,created_by,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'2026-10-01T12:00:00Z','2099-01-01T00:00:00Z')",
                &[&id, &user, &scope, &jti, &reason, &by],
            )
            .await?;
    }
    for (user, score, level, signals) in [
        (t.user, 80i16, "high", r#"[{"signal":"spray","weight":50}]"#),
        (b.user, 40, "medium", r#"[{"signal":"geo"}]"#),
        (a.user, 0, "none", "[]"),
    ] {
        owner
            .execute(
                "INSERT INTO user_risk(user_id,score,level,signals,updated_at) VALUES($1,$2,$3,$4::text::jsonb,'2026-10-01T12:00:00.25Z')",
                &[&user, &score, &level, &signals],
            )
            .await?;
    }
    // Break-glass set.
    let bg = json!([a.user, t.user]).to_string();
    owner
        .execute(
            "INSERT INTO system_config(key,value,updated_by) VALUES('ca_break_glass_user_ids',$1::text::jsonb,NULL) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=NULL, updated_at='2026-10-01T12:00:00Z'",
            &[&bg],
        )
        .await?;
    owner
        .execute(
            "UPDATE system_config SET updated_at='2026-10-01T12:00:00Z' WHERE key LIKE 'ca\\_%'",
            &[],
        )
        .await?;
    // Label-specific tweaks.
    match (action, label) {
        ("bg-get", "empty") => {
            owner
                .execute(
                    "DELETE FROM system_config WHERE key='ca_break_glass_user_ids'",
                    &[],
                )
                .await?;
        }
        ("bg-get", "bad-value") => {
            owner.execute("UPDATE system_config SET value='{\"a\":1}'::jsonb WHERE key='ca_break_glass_user_ids'", &[]).await?;
        }
        ("bg-get", "list-empty") => {
            owner.execute("UPDATE system_config SET value='[]'::jsonb WHERE key='ca_break_glass_user_ids'", &[]).await?;
        }
        ("doctor", "empty") => {
            owner
                .execute("DELETE FROM conditional_access_policies", &[])
                .await?;
        }
        ("coverage", "empty") => {
            owner
                .execute("DELETE FROM conditional_access_policies", &[])
                .await?;
        }
        _ => {}
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    if (action, label) == ("doctor", "ttfp") {
        for (name, at) in [
            ("ca_policy_create", "2025-09-01 10:00:00+00"),
            ("ca_policy_promote", "2025-09-01 10:05:07+00"),
        ] {
            owner
                .execute(
                    "SELECT audit_write($1,$2,'conditional_access_policy',NULL,NULL,NULL,NULL,NULL,'core')",
                    &[&a.user, &name],
                )
                .await?;
            owner
                .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; UPDATE admin_audit_log SET occurred_at='{at}' WHERE id=(SELECT max(id) FROM admin_audit_log); COMMIT;"))
                .await?;
        }
    }
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F03'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    if action=="gate" {
        let enabled:Vec<String>=if label.starts_with("trust-"){vec!["feature.device_trust_enforcement".into()]}
        else if label.starts_with("lockdown-"){vec!["feature.conditional_access".into(),"feature.device_lockdown".into()]}
        else{vec!["feature.cae_runtime".into(),"feature.conditional_access".into()]};
        owner.execute("UPDATE feature_toggles SET enabled=(key=ANY($1::text[])) WHERE key IN ('feature.cae_runtime','feature.conditional_access','feature.device_lockdown','feature.device_trust_enforcement','feature.token_binding')",&[&enabled]).await?;
        if label.starts_with("cae-dpop") {owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.token_binding'",&[]).await?;}
        let bg=if label.ends_with("no-exclude"){json!([])}else if label.ends_with("break-glass"){json!([a.user,t.user])}else{json!([t.user])};
        owner.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='ca_break_glass_user_ids'",&[&bg.to_string()]).await?;
        owner.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='ca_fail_mode'",&[&json!(if label=="cae-fail-open"{"open"}else{"closed"}).to_string()]).await?;
        let actions=if matches!(label,"cae-allow"|"cae-notify")||label.starts_with("cae-dpop")||label.starts_with("cae-sif")||label=="cae-revoked"{json!({"grants":[{"type":"allow"}]})}
        else if matches!(label,"cae-step-up"|"cae-satisfied"){json!({"grants":[{"type":"require_acr","acr":"aal2"}],"reason":"authzgates step up"})}
        else{json!({"grants":[{"type":"block"}],"reason":"authzgates block"})};
        owner.execute("UPDATE conditional_access_policies SET scope_type='user',scope_target=$2,actions=$3::text::jsonb WHERE id=$1",&[&POL_D,&a.user.to_string(),&actions.to_string()]).await?;
        if label.starts_with("lockdown-"){
            for (id,user,fp) in [(946010i64,a.user,"authzgates-own"),(946011,b.user,"authzgates-other")] {
                let state=if id==946010&&label=="lockdown-unapproved"{"enrolled"}else{"approved"};
                owner.execute("INSERT INTO devices(id,user_id,fingerprint,hmac_secret,enroll_state,created_at,updated_at) VALUES($1,$2,$3,'authzgates-device-secret',$4,'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')",&[&id,&user,&fp,&state]).await?;
            }
            if label=="lockdown-revoked"{owner.execute("UPDATE devices SET revoked_at='2026-10-01T12:00:00Z',enroll_state='revoked' WHERE id=946010",&[]).await?;}
        }
        if label=="trust-revoked"{
            use sha2::Digest;
            let hash=sha2::Sha256::digest(b"authzgates-fingerprint").to_vec();
            owner.execute("INSERT INTO user_devices(id,user_id,device_name,platform,fingerprint_hash,offline_approval,registered_at) VALUES(946012,$1,'Revoked phone','ios',$2,'revoked','2026-10-01T12:00:00Z')",&[&b.user,&hash]).await?;
        }
        if label=="cae-revoked"{owner.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,expires_at) VALUES($1,'jti','authzgates-session','authzgates-test',now()+interval '1 hour')",&[&a.user]).await?;}
    }
    let result = std::panic::AssertUnwindSafe(async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let own = if shared.is_none() {
            common::go_oracle::start_named(&db, s3, None, "gofree-ca2-http").await?
        } else {
            None
        };
        let go = shared.or(own.as_ref());
        let recording = go.is_some();
        let app = db.app.as_deref().unwrap_or(&db.dsn);
        let exec = ScopedExecutor::from_dsn(app, 4)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn(&db.dsn, 4)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let runtime = setjoin_gateway::runtime_access::RuntimeAccess::new(exec.clone(),Arc::new(common::recovery_keys()),"mailserver".into())
            .with_workers(worker.clone(),setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?)
            .with_direct(db.direct.clone())
            .with_device_secret(b"blobs1-test-jwt-secret-for-recording".to_vec(),setjoin_config_secret::CryptoProfile::Standard);
        let adapter = Probe {
            inner: ConditionalAccessRoute { exec, worker: Some(worker), keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: status_mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F03" && r["slice"] == "remaining"  {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let table=RouteTable::proxy_all().with(adapter);
        let table=if gate_mutant{table}else{table.with_runtime(runtime)};
        let gateway = Gateway::new(
            Config {
                upstream: go.map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            table,
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let (method, pattern) = route(action);
        // The path value a case targets.
        let target: String = match (action, label) {
            (_, "invalid") if matches!(action, "loc-update" | "loc-delete" | "loc-restore" | "str-update" | "str-delete" | "revoke" | "impact" | "risk-reset") => "bad".into(),
            ("loc-update", "missing" | "deleted-target") | ("loc-delete", "missing") | ("loc-restore", "missing") | ("str-update", "missing") | ("str-delete", "missing") | ("impact", "missing") | ("risk-reset", "missing") => {
                if label == "deleted-target" { LOC_T.to_string() } else { MISSING.to_string() }
            }
            ("loc-update", _) => LOC_B.to_string(),
            ("loc-delete", _) => LOC_A.to_string(),
            ("loc-restore", "conflict") => LOC_C.to_string(),
            ("loc-restore", "live") => LOC_A.to_string(),
            ("loc-restore", _) => LOC_T.to_string(),
            ("str-update" | "str-delete", "builtin") => "1".into(),
            ("str-update" | "str-delete", _) => STR_X.to_string(),
            ("impact", _) => POL_B.to_string(),
            ("revoke", _) => t.user.to_string(),
            ("risk-reset", _) => t.user.to_string(),
            ("tpl-instantiate", "invalid") => "nope".into(),
            ("tpl-instantiate", _) => "mfa-for-admins".into(),
            _ => String::new(),
        };
        let mut path = pattern
            .replace("{id}", &target)
            .replace("{userId}", &target)
            .replace("{slug}", &target);
        let id_a = a.user.to_string();
        let query = match (action, label) {
            ("loc-list", "deleted") => "include_deleted=1".to_string(),
            ("loc-list", "invalid") => "include_deleted=yes".into(),
            ("principals", "success" | "foreign") => format!("users={},{}", a.user, t.user),
            ("principals", "invalid") => format!("users=x,,{id_a}&groups="),
            ("principals", "groups") => "groups=1".into(),
            ("principals", "spaced") => format!("users=%20{id_a}%20,%20,{}", t.user),
            ("signin", "success" | "foreign") => format!("user_id={}", a.user),
            ("signin", "corr") => "correlation_id=ca2-corr-1".into(),
            ("signin", "both") => format!("correlation_id=ca2-corr-2&user_id={}", a.user),
            ("signin", "limit") => format!("user_id={}&limit=1", a.user),
            ("signin", "bad-limit") => format!("user_id={}&limit=0", a.user),
            ("signin", "bad-user") => "user_id=x".into(),
            ("signin", "none-found") => "user_id=99999999".into(),
            ("why", "success" | "foreign") => format!("user={}", a.user),
            ("why", "email") => format!("user={a_email}"),
            ("why", "upper-email") => format!("user={}", a_email.to_uppercase()),
            ("why", "corr") => "correlation_id=ca2-corr-1".into(),
            ("why", "user-corr") => format!("user={}&correlation_id=ca2-corr-1", a.user),
            ("why", "notfound") => "user=99999999".into(),
            ("why", "notfound-email") => "user=nobody@nowhere.test".into(),
            ("why", "invalid") => format!("user={}&since=1h", a.user),
            ("why", "day") => format!("user={}&since=24h", a.user),
            ("why", "month") => format!("user={}&since=30d", a.user),
            ("why", "empty") => format!("user={}", b.user),
            ("impact", "success" | "foreign") => "window=7d".into(),
            ("impact", "day") => "window=24h".into(),
            ("impact", "month") => "window=30d".into(),
            ("impact", "list") => "window=7d&list=blocked_users".into(),
            ("impact", "default-window") => String::new(),
            ("impact", "bad-window") => "window=1h".into(),
            ("impact", "bad-list") => "window=7d&list=everyone".into(),
            ("import", "prune") => "mode=prune".into(),
            ("import", "replace") => "mode=replace".into(),
            ("import", "bad-mode") => "mode=bogus".into(),
            ("str-list" | "sessions-log" | "tpl-list" | "coverage" | "doctor" | "export" | "bg-get" | "risk-list" | "tpl-instantiate-x", "invalid") => "bogus=%ZZ&limit=x".into(),
            ("risk-list", "limit") => "limit=1".into(),
            ("risk-list", "bad-limit") => "limit=abc".into(),
            _ => String::new(),
        };
        if !query.is_empty() {
            path = format!("{path}?{query}");
        }
        let same = |text: &str| (text.to_string(), text.to_string());
        let loc_body = |l: &str| -> String {
            match l {
                "invalid" | "bad-json" => "{\"name\":".into(),
                "empty-name" => "{\"name\":\"\"}".into(),
                "no-arrays" => "{\"name\":\"ca2-bare\"}".into(),
                "countries-only" => "{\"name\":\"ca2-geo\",\"countries\":[\"JP\"]}".into(),
                "cidrs-only" => "{\"name\":\"ca2-net\",\"cidrs\":[\"203.0.113.0/24\"]}".into(),
                "bad-cidr" => "{\"name\":\"ca2-bad\",\"cidrs\":[\"not-a-cidr\"]}".into(),
                "bare-ip" => "{\"name\":\"ca2-bare-ip\",\"cidrs\":[\"10.1.2.3\"]}".into(),
                "host-bits" => "{\"name\":\"ca2-bits\",\"cidrs\":[\"10.1.2.3/8\"]}".into(),
                "bad-type" => "{\"name\":\"ca2-x\",\"is_trusted\":\"yes\"}".into(),
                "null-elements" => "{\"name\":\"ca2-null\",\"countries\":[null,\"US\"]}".into(),
                "folded" => "{\"NAME\":\"ca2-folded\",\"Cidrs\":[\"203.0.113.0/24\"],\"IS_TRUSTED\":true,\"extra\":1} trailing".into(),
                "dup-name" => "{\"name\":\"ca2-hq\",\"countries\":[\"US\"]}".into(),
                _ => "{\"name\":\"ca2-new\",\"description\":\"made <here> & now\",\"cidrs\":[\"198.51.100.0/24\"],\"countries\":[\"US\",\"CA\"],\"is_trusted\":true}".into(),
            }
        };
        let (body, recorded_body): (String, String) = match (action, label) {
            ("simulate", "invalid") => same("{\"user_id\":\"bad\"}"),
            ("simulate", "from-signin") => same("{\"from_signin\":941101}"),
            ("simulate", "missing-signin") => same("{\"from_signin\":99999999}"),
            ("simulate", "folded") => same("{\"IP\":\"203.0.113.5\",\"CLIENT_TYPE\":\"web\",\"ignored\":true} trailing"),
            ("simulate", _) => same("{}"),
            ("loc-create" | "loc-update", l) => same(&loc_body(l)),
            ("str-create", l) => match l {
                "invalid" => same("{\"slug\":"),
                "no-slug" => same("{\"name\":\"x\"}"),
                "no-name" => same("{\"slug\":\"x\"}"),
                "dup" => same("{\"slug\":\"ca2-custom\",\"name\":\"dup\"}"),
                "raw-null" => same("{\"slug\":\"ca2-null\",\"name\":\"n\",\"combinations\":null}"),
                "minimal" => same("{\"slug\":\"ca2-min\",\"name\":\"Min\"}"),
                "bad-type" => same("{\"slug\":\"ca2-x\",\"name\":5}"),
                "bad-combinations" => same("{\"slug\":\"ca2-odd\",\"name\":\"odd\",\"combinations\":{\"a\":1}}"),
                "folded" => same("{\"SLUG\":\"ca2-folded\",\"Name\":\"F\",\"MIN_ACR\":\"aal1\"} trailing"),
                _ => same("{\"slug\":\"ca2-new\",\"name\":\"New <one>\",\"combinations\":[[\"password\",\"totp\"],[\"webauthn\"]],\"min_acr\":\"aal2\"}"),
            },
            ("str-update", l) => match l {
                "bad-json" => same("{\"slug\":"),
                "partial" => same("{\"name\":\"only-name\"}"),
                "empty" => same("{}"),
                _ => same("{\"slug\":\"ca2-custom\",\"name\":\"Renamed\",\"combinations\":[[\"totp\"]],\"min_acr\":\"aal3\"}"),
            },
            ("bg-set", l) => match l {
                "invalid" => same("{}"),
                "empty" => same("[]"),
                "null" => same("null"),
                "bad-element" => same("[\"x\"]"),
                "null-element" => (format!("[null,{}]", a.user), "[null,\"<admin>\"]".to_string()),
                "unknown-user" => same("[99999999]"),
                _ => (format!("[{},{}]", a.user, t.user), "[\"<admin>\",\"<target>\"]".to_string()),
            },
            ("import", l) => match l {
                "invalid" => same("{\"policies\":"),
                "bad-version" => same("{\"schemaVersion\":99,\"policies\":[]}"),
                "bad-shape" => same("[]"),
                "scalar" => same("5"),
                "unknown-slug" => same("{\"schemaVersion\":1,\"policies\":[{\"name\":\"ca2-slug\",\"conditions\":{\"location_slug\":\"nope\"},\"actions\":{\"action\":\"allow\"}}]}"),
                "bad-document" => same("{\"schemaVersion\":1,\"policies\":[{\"name\":\"ca2-badgrant\",\"actions\":{\"action\":\"nope\"}}]}"),
                "update" => same("{\"schemaVersion\":1,\"policies\":[{\"name\":\"ca2-alpha\",\"priority\":9701,\"conditions\":{\"client_type\":\"web\"},\"actions\":{\"action\":\"allow\"}}]}"),
                _ => same("{\"schemaVersion\":1,\"generatedBy\":\"test\",\"policies\":[{\"name\":\"ca2-imp\",\"description\":\"imported <x>\",\"priority\":9760,\"scope_type\":\"global\",\"conditions\":{\"client_type\":\"web\"},\"actions\":{\"operator\":\"all\",\"grants\":[{\"type\":\"allow\"}]}}]}"),
            },
            ("diff", l) => match l {
                "invalid" => same("{\"policies\":"),
                "bad-type" => same("{\"policies\":\"x\"}"),
                "bad-priority" => same("{\"policies\":[{\"name\":\"x\",\"priority\":\"high\"}]}"),
                "bad-version" => same("{\"schemaVersion\":\"one\"}"),
                "array" => same("[]"),
                "null" => same("null"),
                "names-only" => same("{\"policies\":[{\"name\":\"ca2-alpha\"},{\"name\":\"ca2-beta\"},{\"name\":\"ca2-delta\"}]}"),
                "null-docs" => same("{\"policies\":[{\"name\":\"ca2-alpha\",\"conditions\":null,\"actions\":null},{\"name\":\"ca2-beta\"},{\"name\":\"ca2-delta\"}]}"),
                _ => same("{\"schemaVersion\":1,\"policies\":[{\"name\":\"ca2-alpha\",\"conditions\":{ \"client_type\" : \"imap\" },\"actions\":{\"action\":\"allow\"}},{\"name\":\"ca2-beta\",\"conditions\":{\"ip_reputation\":\"high\"},\"actions\":{\"action\":\"block\"}},{\"name\":\"ca2-delta\",\"conditions\":{},\"actions\":{\"action\":\"allow\"}},{\"name\":\"ca2-added\"}],\"named_locations\":[],\"auth_strengths\":null}"),
            },
            _ => (String::new(), String::new()),
        };
        let mut extra=json!({});
        let mut proof_headers=vec![];
        let mut fixed_token:Option<String>=None;
        if action=="gate"{
            extra["jti"]=json!("authzgates-session");
            if label.starts_with("trust-")&&label!="trust-missing"{
                extra["device"]=json!({"id":"authzgates-fingerprint","trust_tier":if label=="trust-quarantine"{"quarantined"}else{"compliant"},"wipe_requested":label=="trust-wipe"});
            }
            if matches!(label,"cae-step-up"|"cae-satisfied"){extra["acr"]=json!(if label=="cae-satisfied"{"aal2"}else{"aal1"});}
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
            if label.starts_with("cae-sif"){extra["sif"]=json!(60);extra["auth_time"]=json!(if label=="cae-sif-expired"{now-3600}else{now});}
            if label.starts_with("cae-dpop"){
                // Owner-approved security fix 2026-11-05 (#499): the runtime verifier binds the
                // proof to the access token (`ath`), so the proof is built for this exact token.
                let (jkt,_)=dpop_proof(now,"");
                extra["cnf"]=json!({"jkt":jkt});
                if label!="cae-dpop-missing"{
                    let bound=admin_token_with(a.user,extra.clone());
                    proof_headers.push(("dpop".to_owned(),dpop_proof(now,&bound).1));
                    fixed_token=Some(bound);
                }
            }
            if label.starts_with("lockdown-")&&!matches!(label,"lockdown-deny"|"lockdown-no-exclude"|"lockdown-break-glass"){
                proof_headers=device_headers(if label=="lockdown-foreign"{946011}else{946010},now,if label=="lockdown-external"{format!("/api{path}")}else{path.clone()},label);
            }
        }
        let send = |body: String| {
            let uri = format!("/api{path}");
            let token = fixed_token.clone().unwrap_or_else(||if action=="gate"{admin_token_with(a.user,extra.clone())}else{admin_token(a.user)});
            let proof_headers=proof_headers.clone();
            async move {
                let mut request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-ca2-oracle").header("authorization", format!("Bearer {token}"));
                for (key,value) in proof_headers{request=request.header(key,value);}
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !matches!(status, 200 | 201 | 204) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        if action=="gate"&&matches!(label,"cae-notify"|"cae-dpop-replay"){
            let warm=send(body.clone()).await?;
            let status=warm.status();let bytes=common::body_bytes(warm).await;
            if status.as_u16()!=200{return Err(format!("warm request: {status} {bytes:?}").into());}
            if label=="cae-notify"{
                owner.execute("UPDATE conditional_access_policies SET actions='{\"grants\":[{\"type\":\"block\"}],\"reason\":\"authzgates block\"}' WHERE id=$1",&[&POL_D]).await?;
                owner.execute("SELECT pg_notify('conditional_access','{}')",&[]).await?;
            }
        }
        let before = snapshot(&owner,action=="gate").await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut changes = db.listen("conditional_access").await?;
        let mut revoked = db.listen("session_revoke").await?;
        let fault=action=="gate"&&matches!(label,"cae-fail-open"|"cae-fail-closed");
        if fault{owner.batch_execute("ALTER TABLE conditional_access_policies RENAME TO authzgates_policies_missing").await?;}
        let sent=std::panic::AssertUnwindSafe(send(body.clone())).catch_unwind().await;
        if fault{owner.batch_execute("ALTER TABLE authzgates_policies_missing RENAME TO conditional_access_policies").await?;}
        let mut response=sent.map_err(|_|"HTTP send panicked")??;
        if action=="gate"&&label=="cae-notify"{
            let deadline=std::time::Instant::now()+std::time::Duration::from_secs(5);
            while response.status().as_u16()!=403&&std::time::Instant::now()<deadline{
                let _=common::body_bytes(response).await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                response=send(body.clone()).await?;
            }
            if response.status().as_u16()!=403{return Err("conditional_access NOTIFY did not invalidate the live cache within 5 s (TTL is 30 s)".into());}
        }
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(&owner,action=="gate").await?;
        let before_ids = ids_of(&before);
        let new_ids: Vec<i64> = ids_of(&after).into_iter().filter(|i| !before_ids.contains(i)).collect();
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = masked(row.clone(), &users, &new_ids, &names)?;
        }
        let mut notify = vec![];
        for event in changes.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"conditional_access","payload":masked(payload, &users, &new_ids, &names)?}));
        }
        for event in revoked.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"session_revoke","payload":masked(payload, &users, &new_ids, &names)?}));
        }
        eprintln!("RECORDED-STATUS {action}/{label}: {status}");
        // Normalize identities and times that differ per run; fixtures are otherwise deterministic.
        let mut text = scrub_timestamps(&names(&raw));
        for n in &new_ids {
            for key in NEW_KEYS {
                text = replace_number(&text, key, *n, "<new>");
            }
        }
        for (id, name) in &users {
            let name = name.trim_matches(['<', '>']);
            for key in ["id", "user_id", "created_by", "updated_by", "actor_id"] {
                text = replace_number(&text, key, *id, name);
            }
            text = replace_member(&text, *id, name);
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let mut effects = vec![];
        for ((table, b4), (_, af)) in before.iter().zip(after.iter()) {
            let mut b4 = masked(Value::Array(b4.clone()), &users, &new_ids, &names)?;
            let mut af = masked(Value::Array(af.clone()), &users, &new_ids, &names)?;
            if action=="gate" && *table=="conditional_access_policies" {
                for snapshot in [&mut b4,&mut af] {
                    for policy in snapshot.as_array_mut().ok_or("policy rows")? {
                        if policy["id"]==POL_D && policy["scope_target"]==a.user.to_string() {policy["scope_target"]=json!("<admin>");}
                    }
                }
            }
            effects.push(json!({"table":table,"before":b4,"after":af}));
        }
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !recorded_body.is_empty() { request["body"] = json!(names(&recorded_body)); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F03\"} 0") {
                return Err(format!("F03 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/conditional-access/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("remaining-{name}.json"));
        let row_file = dir.join(format!("remaining-{name}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            // Owner-approved security fix 2026-11-05 (#499): a foreign device's request no
            // longer burns the owner's nonce, so this baseline is replaced by a reviewed expectation.
            let protected = common::is_pinned(&file);
            let full = json!({"format":1,"route":route_name,"case":label,"observation":observation});
            let expected: Value = if protected { common::security_expected(file.parent().unwrap().parent().unwrap(), &file, &full) } else { serde_json::from_slice(&std::fs::read(&file)?)? };
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: {}",if gate_mutant{"gate-skipped"}else{"changed-status"});
                return Ok(());
            }
            compared?;
            let expected: Value = if protected { common::security_expected(row_file.parent().unwrap().parent().unwrap(), &row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"effects":observation["effects"]})) } else { serde_json::from_slice(&std::fs::read(row_file)?)? };
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }).catch_unwind().await.unwrap_or_else(|_| Err("oracle assertion panicked".into()));
    owner.execute("DELETE FROM user_devices WHERE id=946012",&[]).await?;
    owner.execute("DELETE FROM devices WHERE id IN (946010,946011)",&[]).await?;
    owner.execute("UPDATE feature_toggles ft SET enabled=(j.value::text)::boolean FROM jsonb_each($1::text::jsonb) j WHERE ft.key=j.key",&[&gate_toggles]).await?;
    // Cleanup runs on every path and touches only this case's rows.
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F03' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner.batch_execute("DELETE FROM conditional_access_policies; DELETE FROM auth_strengths WHERE NOT builtin; DELETE FROM named_locations; DELETE FROM user_risk;").await?;
    owner.batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM session_revocations; COMMIT;").await?;
    for (table, rows) in [
        ("conditional_access_policies", &aside_policies),
        ("auth_strengths", &aside_strengths),
        ("named_locations", &aside_locations),
        ("session_revocations", &aside_revocations),
        ("user_risk", &aside_risk),
    ] {
        for row in rows {
            owner
                .execute(
                    &format!("INSERT INTO {table} SELECT * FROM jsonb_populate_record(null::{table}, $1::text::jsonb)"),
                    &[row],
                )
                .await?;
        }
    }
    owner
        .execute(
            "DELETE FROM system_config WHERE key IN ('ca_break_glass_user_ids','ca_fail_mode')",
            &[],
        )
        .await?;
    for row in &aside_config {
        owner
            .execute(
                "INSERT INTO system_config SELECT * FROM jsonb_populate_record(null::system_config, $1::text::jsonb)",
                &[row],
            )
            .await?;
    }
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner.batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM ca_signin_log WHERE id BETWEEN 941101 AND 941199 OR matched_policy_id=941402; COMMIT;").await?;
    for account in [&a, &b, &t] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}

fn check_envelopes(value:&mut Value)->Result<(),BoxError>{
    match value{
        Value::Object(map)=>{
            if let Some(encoded)=map.get("hmac_secret_enc").and_then(Value::as_str){
                let encoded=encoded.strip_prefix("\\x").ok_or("bytea device envelope")?;
                let bytes:Vec<u8>=(0..encoded.len()).step_by(2).map(|i|u8::from_str_radix(&encoded[i..i+2],16)).collect::<Result<_,_>>()?;
                let plain=setjoin_config_secret::open_column(&bytes,b"blobs1-test-jwt-secret-for-recording").map_err(|_|"device envelope authentication failed")?;
                if plain!=b"authzgates-device-secret"||map["hmac_secret_key_id"]!="v1"{return Err("device envelope plaintext/key version changed".into());}
                map.insert("hmac_secret_enc".into(),json!("<sealed>"));
            }
            for value in map.values_mut(){check_envelopes(value)?;}
        },Value::Array(items)=>{for item in items{check_envelopes(item)?;}},_=>{}
    }Ok(())
}
fn device_headers(id:i64,now:i64,uri:String,label:&str)->Vec<(String,String)>{
    use sha2::{Digest,Sha256};use hmac::{Hmac,Mac};
    let ts=now.to_string();let hash=format!("{:x}",Sha256::digest(b""));let nonce=format!("authzgates-{label}");
    let challenge=format!("{id}:{ts}:GET:{uri}:{hash}:{nonce}");
    let mut mac=Hmac::<Sha256>::new_from_slice(b"authzgates-device-secret").unwrap();mac.update(challenge.as_bytes());
    let signature=if label=="lockdown-invalid"{"00".repeat(32)}else{format!("{:x}",mac.finalize().into_bytes())};
    vec![("x-device-id".into(),id.to_string()),("x-device-timestamp".into(),ts),("x-device-body-sha256".into(),hash),("x-device-nonce".into(),nonce),("x-device-hmac".into(),signature)]
}
fn dpop_proof(now:i64,access_token:&str)->(String,String){
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as URL,Engine};
    use p256::ecdsa::{SigningKey,signature::Signer};use sha2::Digest;
    let doc:Value=serde_json::from_str(include_str!("../../../../tests/conformance/jmap/test-jwks.json")).unwrap();
    let jwk=&doc["keys"][0];let jkt=setjoin_authz::dpop::thumbprint(jwk).unwrap();
    let h=URL.encode(json!({"alg":"ES256","typ":"dpop+jwt","jwk":jwk}).to_string());
    let p=URL.encode(json!({"htm":"GET","htu":"https://mail.test/api/admin/conditional-access/break-glass","iat":now,"jti":"authzgates-dpop-proof","ath":URL.encode(sha2::Sha256::digest(access_token.as_bytes()))}).to_string());
    let key=SigningKey::from_slice(&[0x11;32]).unwrap();let sig:p256::ecdsa::Signature=key.sign(format!("{h}.{p}").as_bytes());
    (jkt,format!("{h}.{p}.{}",URL.encode(sig.to_bytes())))
}
