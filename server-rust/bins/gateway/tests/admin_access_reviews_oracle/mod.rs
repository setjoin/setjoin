//! F01 slice `access-reviews` frozen-Go oracle: HTTP wire, committed rows and audit.
//! Record mode runs the covered Go binary behind the front door; replay mode
//! serves the same requests from Rust with no Go upstream.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_access_reviews::AdminAccessReviewsRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Probe {
    inner: AdminAccessReviewsRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
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

fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "list" => ("GET", "/admin/access-reviews"),
        "start" => ("POST", "/admin/access-reviews"),
        "get" => ("GET", "/admin/access-reviews/{id}"),
        "decide" => ("PUT", "/admin/access-reviews/{id}/items/{itemId}"),
        "bulk" => ("PUT", "/admin/access-reviews/{id}/items"),
        "close" => ("POST", "/admin/access-reviews/{id}/close"),
        _ => panic!("unknown F01 access-reviews action {action}"),
    }
}

// Fixed ids keep the goldens free of run-specific numbers.
const C1: i64 = 940001; // open, global
const C2: i64 = 940002; // closed, scoped to the target's domain
const C3: i64 = 940003; // open, global, revoke decisions
const C4: i64 = 940004; // open, scoped to the other domain
const C5: i64 = 940005; // open, one item whose user is gone
const C6: i64 = 940006; // open, no items
const ORPHAN: i64 = 999999991;

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Run-specific identities, by the kind of thing the key names.
struct Names<'a> {
    users: &'a [(i64, &'a str)],
    domains: &'a [(i64, &'a str)],
    roles: &'a [(i64, &'a str)],
    assignments: &'a [(i64, &'a str)],
    new_campaign: Option<i64>,
}
impl Names<'_> {
    fn find(list: &[(i64, &str)], n: i64) -> Option<Value> {
        list.iter().find(|(i, _)| *i == n).map(|(_, s)| json!(s))
    }
}

/// Mask run-specific identities by the key that names them.
fn mask(v: &mut Value, n: &Names) {
    match v {
        Value::Object(map) => {
            let target = map
                .get("target_type")
                .and_then(|t| t.as_str())
                .map(str::to_owned);
            let assignment_row = map.contains_key("role_group_id") && map.contains_key("user_id");
            for (k, x) in map.iter_mut() {
                if let Some(num) = x.as_i64() {
                    let replaced = match k.as_str() {
                        "user_id" | "actor_id" | "granted_by" | "decided_by" | "created_by"
                        | "closed_by" | "actor" => Names::find(n.users, num),
                        "role_group_id" => Names::find(n.roles, num),
                        "domain_id" | "domain_override" | "domain_scope" | "scope" => {
                            Names::find(n.domains, num)
                        }
                        "assignment_id" => Names::find(n.assignments, num),
                        "id" if assignment_row => Names::find(n.assignments, num),
                        "target_id" if target.as_deref() == Some("admin_role_assignment") => {
                            Names::find(n.assignments, num)
                        }
                        "target_id" | "campaign_id" | "id" if n.new_campaign == Some(num) => {
                            Some(json!("<new-campaign>"))
                        }
                        _ => None,
                    };
                    if let Some(r) = replaced {
                        *x = r;
                    }
                } else {
                    mask(x, n);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, n)),
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-01") {
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
}
fn masked(mut v: Value, n: &Names, names: &dyn Fn(&str) -> String) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    mask(&mut v, n);
    Ok(v)
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    Ok(json!({
        "campaigns": rows(c, "SELECT jsonb_build_object('id',CASE WHEN id BETWEEN 940001 AND 940099 THEN id ELSE 0 END,'name',name,'status',status,'domain_scope',domain_scope,'created_by',created_by,'created_at',created_at::text,'closed_by',closed_by,'closed_at',closed_at::text)::text FROM access_review_campaigns ORDER BY (id BETWEEN 940001 AND 940099) DESC, id").await?,
        "items": rows(c, "SELECT jsonb_build_object('campaign',CASE WHEN campaign_id BETWEEN 940001 AND 940099 THEN campaign_id ELSE 0 END,'id',CASE WHEN id BETWEEN 950001 AND 950099 THEN id ELSE 0 END,'user_id',user_id,'role_group_id',role_group_id,'domain_override',domain_override,'granted_by',granted_by,'granted_at',granted_at::text,'is_sso',is_sso,'eligible',eligible,'decision',decision,'decided_by',decided_by,'decided_at',decided_at::text,'applied_at',applied_at::text,'note',note,'live',assignment_id IS NOT NULL)::text FROM access_review_items i ORDER BY campaign_id IS NOT NULL AND campaign_id BETWEEN 940001 AND 940099 DESC, campaign_id, (SELECT email FROM users WHERE id=i.user_id) NULLS LAST, id").await?,
        "assignments": rows(c, "SELECT jsonb_build_object('user_id',ra.user_id,'role_group_id',ra.role_group_id,'granted_by',ra.granted_by)::text FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE rg.name LIKE 'admin4-%' ORDER BY (SELECT email FROM users WHERE id=ra.user_id), rg.name").await?,
    }))
}

/// Every case owns the fixed-id campaigns, the audit window, the F01 receipts and
/// the fault schemas: libtest threads must not interleave them.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The adapter's default 1 s pool and 2 s statement waits turn into a Go forward
/// on a loaded host; only the deadlines are widened, never an assertion.
fn loaded_host_exec(dsn: &str) -> Result<ScopedExecutor, BoxError> {
    let patient = std::time::Duration::from_secs(30);
    Ok(ScopedExecutor::from_dsn_with(
        dsn,
        4,
        setjoin_pg::Timeouts {
            pool_wait: patient,
            create: patient,
            statement: patient,
        },
    )
    .map_err(|e| e.0)?)
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(mut db) = Db::for_case("admin4-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    // Leftovers of an interrupted run would collide with the fixed ids.
    owner
        .execute(
            "DELETE FROM access_review_campaigns WHERE id BETWEEN 940001 AND 940099",
            &[],
        )
        .await?;
    let a = fixture::account(&owner, "admin4-admin").await?;
    let b = fixture::account(&owner, "admin4-other").await?;
    let t = fixture::account(&owner, "admin4-target").await?;
    let s = fixture::account(&owner, "admin4-sso").await?;
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
        (domain_of(t.domain).await?, "host-t.test"),
        (domain_of(s.domain).await?, "host-s.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        // Role names carry the admin's user id.
        out = out.replace(&format!("admin4-reviewed-{}", a.user), "admin4-reviewed");
        out.replace(&format!("admin4-{}", a.user), "admin4-admin-role")
    };
    // Grant shapes: global admin, scoped to the other domain, or no permission.
    let scoped = matches!(label, "foreign" | "foreign-item" | "scoped" | "scoped-skip");
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        _ if scoped => (vec!["roles.manage"], Some(b.domain)),
        _ => (vec!["roles.manage"], None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("admin4-{}", a.user), &permissions, &scope],
        )
        .await?
        .get(0);
    let reviewed_role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions) VALUES($1,'{users.read}') RETURNING id",
            &[&format!("admin4-reviewed-{}", a.user)],
        )
        .await?
        .get(0);
    let mut assignment = std::collections::BTreeMap::new();
    for (name, user, role_id, by, at) in [
        ("admin", a.user, role, Some(a.user), "2026-10-01T10:00:00Z"),
        (
            "target",
            t.user,
            reviewed_role,
            Some(a.user),
            "2026-10-01T10:00:01.5Z",
        ),
        ("sso", s.user, reviewed_role, None, "2026-10-01T10:00:02Z"),
    ] {
        let id: i64 = owner
            .query_one(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,granted_at) VALUES($1,$2,$3,$4::text::timestamptz) RETURNING id",
                &[&user, &role_id, &by, &at],
            )
            .await?
            .get(0);
        assignment.insert(name, id);
    }
    // Campaigns and items with fixed ids and times.
    for (id, name, status, scope, by, created, closed_by, closed_at) in [
        (
            C1,
            "admin4-q1",
            "open",
            None,
            a.user,
            "2026-10-01T12:00:00Z",
            None,
            None,
        ),
        (
            C2,
            "admin4-closed",
            "closed",
            Some(t.domain),
            b.user,
            "2026-10-01T12:00:01.25Z",
            Some(a.user),
            Some("2026-10-01T12:30:00Z"),
        ),
        (
            C3,
            "admin4-revokes",
            "open",
            None,
            a.user,
            "2026-10-01T12:00:02Z",
            None,
            None,
        ),
        (
            C4,
            "admin4-scoped",
            "open",
            Some(b.domain),
            b.user,
            "2026-10-01T12:00:03Z",
            None,
            None,
        ),
        (
            C5,
            "admin4-orphan",
            "open",
            None,
            a.user,
            "2026-10-01T12:00:04Z",
            None,
            None,
        ),
        (
            C6,
            "admin4-empty <&>",
            "open",
            None,
            a.user,
            "2026-10-01T12:00:05Z",
            None,
            None,
        ),
    ] {
        owner
            .execute(
                "INSERT INTO access_review_campaigns(id,name,status,domain_scope,created_by,created_at,closed_by,closed_at) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6::text::timestamptz,$7,$8::text::timestamptz)",
                &[&id, &name, &status, &scope, &by, &created, &closed_by, &closed_at],
            )
            .await?;
    }
    let (aa, at, asso) = (assignment["admin"], assignment["target"], assignment["sso"]);
    for (id, campaign, asg, user, role_id, by, sso, decision, applied, note) in [
        (
            950001_i64,
            C1,
            Some(at),
            t.user,
            reviewed_role,
            Some(a.user),
            false,
            "undecided",
            None,
            None,
        ),
        (
            950002,
            C1,
            Some(asso),
            s.user,
            reviewed_role,
            None,
            true,
            "undecided",
            None,
            None,
        ),
        (
            950003,
            C1,
            Some(aa),
            a.user,
            role,
            Some(a.user),
            false,
            "keep",
            None,
            Some("mine <&>"),
        ),
        (
            950006,
            C3,
            Some(at),
            t.user,
            reviewed_role,
            Some(a.user),
            false,
            "revoke",
            None,
            None,
        ),
        (
            950007,
            C3,
            Some(asso),
            s.user,
            reviewed_role,
            None,
            true,
            "revoke",
            None,
            None,
        ),
        (
            950008,
            C3,
            Some(aa),
            a.user,
            role,
            Some(a.user),
            false,
            "keep",
            None,
            None,
        ),
        (
            950009,
            C2,
            Some(at),
            t.user,
            reviewed_role,
            Some(a.user),
            false,
            "keep",
            None,
            None,
        ),
        // Go orders items by email only: two items of one user would tie in the get body.
        (
            950011,
            C2,
            None,
            if action == "get" && label == "closed" {
                s.user
            } else {
                t.user
            },
            reviewed_role,
            Some(a.user),
            false,
            "revoke",
            Some("2026-10-01T12:30:00Z"),
            Some("done"),
        ),
        (
            950010,
            C4,
            Some(at),
            t.user,
            reviewed_role,
            Some(a.user),
            false,
            "revoke",
            None,
            None,
        ),
        (
            950013,
            C5,
            None,
            ORPHAN,
            reviewed_role,
            None,
            true,
            "undecided",
            None,
            None,
        ),
    ] {
        owner
            .execute(
                "INSERT INTO access_review_items(id,campaign_id,assignment_id,user_id,role_group_id,granted_by,granted_at,is_sso,decision,decided_by,decided_at,applied_at,note) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,'2026-10-01T10:00:00Z'::timestamptz,$7,$8,CASE WHEN $8<>'undecided' THEN $9::bigint END,CASE WHEN $8<>'undecided' THEN '2026-10-01T12:10:00Z'::timestamptz END,$10::text::timestamptz,$11)",
                &[&id, &campaign, &asg, &user, &role_id, &by, &sso, &decision, &a.user, &applied, &note],
            )
            .await?;
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_admin4_fault_{}", a.user);
    let mut private = false;
    let mut trigger = None;
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.user_id={} THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.user)).await?;
            trigger = Some("admin_audit_log");
        }
        Some("reach-bypass") => {
            // A private admin_can_reach that always answers yes (neutralizes the reach rule).
            owner.batch_execute(&format!("CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;CREATE FUNCTION {schema}.admin_can_reach(bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO setjoin_app;")).await?;
            private = true;
        }
        _ => {}
    }
    if private {
        db.app = Some(format!(
            "{}{}options=-csearch_path%3D{schema}%2Cpublic",
            db.app.as_deref().unwrap_or(&db.dsn),
            if db.app.as_deref().unwrap_or(&db.dsn).contains('?') {
                "&"
            } else {
                "?"
            }
        ));
    }
    let users: Vec<(i64, &str)> = vec![
        (t.user, "<target>"),
        (a.user, "<admin>"),
        (b.user, "<other>"),
        (s.user, "<sso>"),
        (ORPHAN, "<orphan>"),
    ];
    let domains: Vec<(i64, &str)> = vec![
        (a.domain, "<admin-domain>"),
        (b.domain, "<other-domain>"),
        (t.domain, "<target-domain>"),
        (s.domain, "<sso-domain>"),
    ];
    let roles: Vec<(i64, &str)> = vec![(role, "<admin-role>"), (reviewed_role, "<reviewed-role>")];
    let assignments: Vec<(i64, &str)> = vec![
        (aa, "<admin-assignment>"),
        (at, "<target-assignment>"),
        (asso, "<sso-assignment>"),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin4-http").await?;
        let recording = go.is_some();
        let exec = loaded_host_exec(db.app.as_deref().unwrap_or(&db.dsn))?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: AdminAccessReviewsRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "access-reviews" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let (method, pattern) = route(action);
        // Request shape per case; mutators repeat the committed request once first.
        let campaign_part = match (action, label) {
            (_, "invalid") => "bad".to_string(),
            (_, "missing") => "99999999".to_string(),
            (_, "closed") => C2.to_string(),
            ("get", "empty") => C6.to_string(),
            ("get", "orphan") => C5.to_string(),
            ("close", "success" | "repeat") => C3.to_string(),
            ("decide" | "bulk" | "close", "foreign-item" | "scoped-skip" | "scoped") => C4.to_string(),
            ("decide", "sso-revoke" | "wrong-campaign") if label == "wrong-campaign" => C1.to_string(),
            _ => C1.to_string(),
        };
        let item_part = match label {
            "bad-item" => "bad".to_string(),
            "missing-item" => "99999999".to_string(),
            "self" => "950003".to_string(),
            "sso-revoke" | "sso-keep" => "950002".to_string(),
            "wrong-campaign" => "950006".to_string(),
            "closed" => "950009".to_string(),
            "foreign-item" => "950010".to_string(),
            _ => "950001".to_string(),
        };
        let path = pattern.replace("{id}", &campaign_part).replace("{itemId}", &item_part);
        let (mut body, mut recorded_body) = (String::new(), String::new());
        let mut both = |sent: String, recorded: String| {
            body = sent;
            recorded_body = recorded;
        };
        let same = |text: &str| (text.to_string(), text.to_string());
        match (action, label) {
            ("start", l) => {
                let (sent, rec) = match l {
                    "invalid" => same("{\"name\":"),
                    "empty" => same("{\"name\":\"\"}"),
                    "typed" => same("{\"name\":7}"),
                    "folded" => same("{\"NAME\":\"admin4-folded <&>\",\"extra\":1} trailing"),
                    "repeat" => same("{\"name\":\"admin4-again\"}"),
                    _ => same("{\"name\":\"admin4-new\"}"),
                };
                both(sent, rec);
            }
            ("decide", l) => {
                let (sent, rec) = match l {
                    "bad-json" => same("{\"decision\":"),
                    "bad-decision" => same("{\"decision\":\"maybe\"}"),
                    "typed-note" => same("{\"decision\":\"keep\",\"note\":5}"),
                    "folded" => same("{\"DECISION\":\"keep\",\"Note\":null} trailing"),
                    "keep" | "sso-keep" => same("{\"decision\":\"keep\"}"),
                    "success" => same("{\"decision\":\"revoke\",\"note\":\"stale <access> & more\"}"),
                    _ => same("{\"decision\":\"revoke\"}"),
                };
                both(sent, rec);
            }
            ("bulk", l) => {
                let (sent, rec) = match l {
                    "invalid" | "bad-json" => same("{\"itemIds\":"),
                    "empty" => same("{\"itemIds\":[],\"decision\":\"keep\"}"),
                    "bad-decision" => same("{\"itemIds\":[950001],\"decision\":\"maybe\"}"),
                    "missing-items" => same("{\"itemIds\":[99999998,99999999],\"decision\":\"keep\"}"),
                    "null-element" => same("{\"itemIds\":[null,950001],\"decision\":\"keep\"}"),
                    "revoke" => same("{\"itemIds\":[950001,950002,950003],\"decision\":\"revoke\"}"),
                    "scoped-skip" => same("{\"itemIds\":[950010],\"decision\":\"revoke\"}"),
                    _ => same("{\"itemIds\":[950001,950002,950003],\"decision\":\"keep\"}"),
                };
                both(sent, rec);
            }
            _ => {}
        }
        let send = |body: String| {
            let uri = format!("/api{path}");
            let token = admin_token(a.user);
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-admin4-oracle").header("authorization", format!("Bearer {token}"));
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
        let before = snapshot(&owner).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(&owner).await?;
        let new_campaign: Option<i64> = owner.query_opt("SELECT id FROM access_review_campaigns WHERE id NOT BETWEEN 940001 AND 940099 ORDER BY id DESC LIMIT 1", &[]).await?.map(|r| r.get(0));
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        let n = Names { users: &users, domains: &domains, roles: &roles, assignments: &assignments, new_campaign };
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            let mut inner = row.clone();
            inner.as_object_mut().map(|m| m.remove("id"));
            let mut done = masked(inner, &n, &names)?;
            done["id"] = json!("<audit>");
            *row = done;
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"admin:alert","payload":masked(payload, &n, &names)?}));
        }
        let wanted = match (action, label) {
            (_, "denied") => 403,
            ("get", "orphan") => 500,
            (_, "foreign") if action != "list" => if action == "get" { 404 } else if action == "start" { 201 } else { 403 },
            (_, "foreign-item" | "self") => 403,
            ("get" | "close" | "decide" | "bulk", "missing") => 404,
            ("decide", "missing-item" | "wrong-campaign") => 404,
            (_, "closed") if action != "get" => 409,
            ("close", "repeat") => 409,
            ("decide", "sso-revoke") => 409,
            (_, "invalid" | "bad-json" | "empty" | "typed" | "bad-decision" | "typed-note" | "bad-item") if action != "list" && !(action == "get" && label == "empty") => 400,
            ("get", "empty") => 200,
            ("start", _) => 201,
            ("decide" | "close", _) => 204,
            _ => 200,
        };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Normalize identities that differ per run; fixtures are otherwise deterministic.
        let mut text = names(&raw);
        if let Some(c) = new_campaign {
            text = text.replace(&format!("{{\"id\":{c}}}"), "{\"id\":\"<new-campaign>\"}");
        }
        for (id, name) in &domains {
            let name = name.trim_matches(['<', '>']);
            text = text.replace(&format!("\"scope\":{id},"), &format!("\"scope\":\"{name}\","));
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &n, &names)?, masked(after, &n, &names)?);
        let effects = json!([{"table":"access_review_*","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !recorded_body.is_empty() { request["body"] = json!(names(&recorded_body)); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0") {
                return Err(format!("F01 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/admin-identity/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("access-reviews-{name}.json"));
        let row_file = dir.join(format!("access-reviews-{name}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                eprintln!("FAULT-OBSERVED {fault}: {status} {}", observation["response"]["body"]);
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
    // Cleanup runs on every path and touches only this case's rows.
    if let Some(table) = trigger {
        owner
            .batch_execute(&format!("DROP TRIGGER {schema} ON {table}"))
            .await?;
    }
    if fault.is_some() {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute("DELETE FROM access_review_campaigns WHERE id BETWEEN 940001 AND 940099 OR created_by=ANY($1)", &[&vec![a.user, b.user, t.user, s.user]])
        .await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=ANY($1)", &[&vec![role, reviewed_role]]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=ANY($1)",
            &[&vec![role, reviewed_role]],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM admin_role_groups WHERE id=ANY($1)",
            &[&vec![role, reviewed_role]],
        )
        .await?;
    for account in [&a, &b, &t, &s] {
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
