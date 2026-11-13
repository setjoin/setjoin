//! F01 slice `scope-sets` frozen-Go oracle: HTTP wire, committed rows and audit.
//! Record mode runs the covered Go binary behind the front door; replay mode
//! serves the same requests from Rust with no Go upstream.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_scope_sets::AdminScopeSetsRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Probe {
    inner: AdminScopeSetsRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
        "list" => ("GET", "/admin/scope-sets"),
        "create" => ("POST", "/admin/scope-sets"),
        "get" => ("GET", "/admin/scope-sets/{id}"),
        "update" => ("PUT", "/admin/scope-sets/{id}"),
        "delete" => ("DELETE", "/admin/scope-sets/{id}"),
        "member-add" => ("POST", "/admin/scope-sets/{id}/members"),
        "member-remove" => (
            "DELETE",
            "/admin/scope-sets/{id}/members/{memberType}/{memberId}",
        ),
        _ => panic!("unknown F01 scope-sets action {action}"),
    }
}

// Fixed ids keep the goldens free of run-specific numbers: the sets, departments
// and distribution groups are far above any generated sequence value.
const ALPHA: i64 = 930001;
const BETA: i64 = 930002;
const USED: i64 = 930003;
const QUOTED: i64 = 930004;
const DEPT: i64 = 910001;
const DEPT2: i64 = 910002;
const GROUP: i64 = 920001;
const DYNAMIC: i64 = 920002;
const PLAIN: i64 = 920003;
const ORPHAN: i64 = 999999991;
const QUOTED_NAME: &str = "admin3-\"q\"\\é\u{200b}\t<&>";

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Mask run-specific identities by the key that names them.
fn mask(v: &mut Value, users: &[(i64, &str)], domains: &[(i64, &str)], new_set: Option<i64>) {
    match v {
        Value::Object(map) => {
            let member_is_user = map
                .get("memberType")
                .or_else(|| map.get("member_type"))
                .is_some_and(|t| t == "user");
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(
                        k.as_str(),
                        "createdBy"
                            | "addedBy"
                            | "created_by"
                            | "added_by"
                            | "user_id"
                            | "actor_id"
                            | "actor"
                    ) || (member_is_user
                        && matches!(k.as_str(), "memberId" | "member_id"));
                    let set = matches!(k.as_str(), "id" | "setId" | "set_id" | "target_id")
                        && new_set == Some(n);
                    let domain = matches!(k.as_str(), "domainId" | "domain_id");
                    if user {
                        if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    } else if set {
                        *x = json!("<new-set>");
                    } else if domain {
                        if let Some((_, name)) = domains.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    }
                } else {
                    mask(x, users, domains, new_set);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, users, domains, new_set)),
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-01") {
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
}
fn masked(
    mut v: Value,
    users: &[(i64, &str)],
    domains: &[(i64, &str)],
    new_set: Option<i64>,
    names: &dyn Fn(&str) -> String,
) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    mask(&mut v, users, domains, new_set);
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
        "sets": rows(c, "SELECT jsonb_build_object('id',id,'name',name,'domain_id',domain_id,'description',description,'created_by',created_by,'created_at',created_at::text,'updated_at',updated_at::text)::text FROM admin_scope_sets WHERE name LIKE 'admin3-%' OR id BETWEEN 930001 AND 930009 ORDER BY name,id").await?,
        "members": rows(c, "SELECT jsonb_build_object('set',(SELECT name FROM admin_scope_sets s WHERE s.id=m.set_id),'member_type',member_type,'member_id',member_id,'added_by',added_by,'added_at',added_at::text)::text FROM admin_scope_set_members m WHERE set_id IN (SELECT id FROM admin_scope_sets WHERE name LIKE 'admin3-%' OR id BETWEEN 930001 AND 930009) ORDER BY 1,member_type,member_id").await?,
    }))
}

/// Cases share fixed fixture keys and global windows (audit id, receipts), so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(mut db) = Db::for_case("admin3-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin3-admin").await?;
    let b = fixture::account(&owner, "admin3-other").await?;
    let t = fixture::account(&owner, "admin3-target").await?;
    let g1 = fixture::account(&owner, "admin3-group").await?;
    let g2 = fixture::account(&owner, "admin3-dynamic").await?;
    let g3 = fixture::account(&owner, "admin3-plain").await?;
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
    let (domain_a, domain_b, domain_t) = (
        domain_of(a.domain).await?,
        domain_of(b.domain).await?,
        domain_of(t.domain).await?,
    );
    let domain_names = [
        (&domain_a, "host-a.test"),
        (&domain_b, "host-b.test"),
        (&domain_t, "host-t.test"),
        (&domain_of(g1.domain).await?, "host-g1.test"),
        (&domain_of(g2.domain).await?, "host-g2.test"),
        (&domain_of(g3.domain).await?, "host-g3.test"),
    ]
    .map(|(d, n)| (d.clone(), n));
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        // Request paths name the target user (member-remove).
        for kind in ["user", "team"] {
            out = out.replace(
                &format!("/members/{kind}/{}", t.user),
                &format!("/members/{kind}/<target>"),
            );
        }
        out
    };
    // Grant shapes: global admin, scoped to the other domain, or no permission.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "foreign" | "foreign-user" | "foreign-ou" | "foreign-group" => {
            (vec!["scope_sets.manage"], Some(b.domain))
        }
        _ => (vec!["scope_sets.manage"], None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("admin3-{}", a.user), &permissions, &scope],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    // A role assignment scoped to the "used" set blocks its deletion.
    let used_role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions) VALUES($1,'{users.read}') RETURNING id",
            &[&format!("admin3-used-{}", a.user)],
        )
        .await?
        .get(0);
    // Departments, distribution groups and sets, with fixed ids and times.
    for (id, name) in [(DEPT, "admin3-dept"), (DEPT2, "admin3-dept2")] {
        owner
            .execute(
                "INSERT INTO departments(id,name,path,ldap_ou) VALUES($1,$2,'/'||$2,'ou='||$2)",
                &[&id, &name],
            )
            .await?;
    }
    for (id, mailbox, dynamic, usable) in [
        (GROUP, g1.mailbox, false, true),
        (DYNAMIC, g2.mailbox, true, true),
        (PLAIN, g3.mailbox, false, false),
    ] {
        owner
            .execute(
                "INSERT INTO distribution_groups(id,mailbox_id,is_dynamic,usable_as_admin_scope) VALUES($1,$2,$3,$4)",
                &[&id, &mailbox, &dynamic, &usable],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO distribution_group_members(group_id,mailbox_id) VALUES($1,$2)",
            &[&GROUP, &t.mailbox],
        )
        .await?;
    for (id, name, domain, description, by, created, updated) in [
        (
            ALPHA,
            "admin3-alpha".to_string(),
            None,
            Some("Alpha <set> & co"),
            Some(a.user),
            "2026-10-01T12:00:00Z",
            "2026-10-01T12:00:00.5Z",
        ),
        (
            BETA,
            "admin3-beta".to_string(),
            Some(t.domain),
            None,
            None,
            "2026-10-01T12:00:01.25Z",
            "2026-10-01T12:00:01.25Z",
        ),
        (
            USED,
            "admin3-used".to_string(),
            None,
            Some(""),
            Some(b.user),
            "2026-10-01T12:00:02Z",
            "2026-10-01T12:00:02Z",
        ),
        (
            QUOTED,
            QUOTED_NAME.to_string(),
            None,
            None,
            None,
            "2026-10-01T12:00:03Z",
            "2026-10-01T12:00:03Z",
        ),
    ] {
        owner
            .execute(
                "INSERT INTO admin_scope_sets(id,name,domain_id,description,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6::text::timestamptz,$7::text::timestamptz)",
                &[&id, &name, &domain, &description, &by, &created, &updated],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,scope_type,scope_id) VALUES($1,$2,$1,'set',$3)",
            &[&t.user, &used_role, &USED],
        )
        .await?;
    for (ty, id, by, at) in [
        ("ou", DEPT, Some(a.user), "2026-10-01T13:00:00Z"),
        ("group", GROUP, None, "2026-10-01T13:00:01.5Z"),
        ("user", t.user, Some(a.user), "2026-10-01T13:00:02Z"),
        ("user", ORPHAN, None, "2026-10-01T13:00:03Z"),
    ] {
        owner
            .execute(
                "INSERT INTO admin_scope_set_members(set_id,member_type,member_id,added_by,added_at) VALUES($1,$2,$3,$4,$5::text::timestamptz)",
                &[&ALPHA, &ty, &id, &by, &at],
            )
            .await?;
    }
    // Go's usage recount would otherwise write the fixture's message sizes anywhere.
    let policy: Vec<String> = owner
        .query_one(
            "SELECT reason_required_areas FROM audit_policy WHERE id=1",
            &[],
        )
        .await?
        .get(0);
    if label.starts_with("reason") {
        owner
            .execute(
                "UPDATE audit_policy SET reason_required_areas=array_append(reason_required_areas,'scope_sets') WHERE id=1",
                &[],
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
    let schema = format!("gofree_admin3_fault_{}", a.user);
    let mut private = false;
    let mut trigger = None;
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.user_id={} THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.user)).await?;
            trigger = Some("admin_audit_log");
        }
        Some("reach-bypass") => {
            // A private admin_can_reach that always answers yes (neutralizes the reach rule).
            owner.batch_execute(&format!("CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;CREATE FUNCTION {schema}.admin_can_reach(bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';CREATE FUNCTION {schema}.admin_scope_within(bigint,text,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO setjoin_app;")).await?;
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
    ];
    let domains: Vec<(i64, &str)> = vec![
        (a.domain, "<admin-domain>"),
        (b.domain, "<other-domain>"),
        (t.domain, "<target-domain>"),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin3-http").await?;
        let recording = go.is_some();
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: AdminScopeSetsRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "scope-sets" {
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
        let set_part = match (action, label) {
            ("get", "empty") => BETA.to_string(),
            ("get" | "update" | "delete" | "member-add" | "member-remove", "invalid") => "bad".to_string(),
            (_, "missing" | "missing-set") => "99999999".to_string(),
            ("delete", "in-use") => USED.to_string(),
            ("delete", _) => BETA.to_string(),
            ("member-add", _) => BETA.to_string(),
            _ => ALPHA.to_string(),
        };
        let (member_type, member_part) = match (action, label) {
            ("member-remove", "bad-type") => ("team".to_string(), t.user.to_string()),
            ("member-remove", "bad-member") => ("user".to_string(), "bad".to_string()),
            ("member-remove", "missing") => ("user".to_string(), "424242".to_string()),
            ("member-remove", "ou") => ("ou".to_string(), DEPT.to_string()),
            ("member-remove", "group") => ("group".to_string(), GROUP.to_string()),
            ("member-remove", "orphan") => ("user".to_string(), ORPHAN.to_string()),
            _ => ("user".to_string(), t.user.to_string()),
        };
        let path = pattern
            .replace("{id}", &set_part)
            .replace("{memberType}", &member_type)
            .replace("{memberId}", &member_part);
        // `(sent, recorded)`: the recorded form never contains run-specific numbers.
        let (mut body, mut recorded_body) = (String::new(), String::new());
        let mut both = |sent: String, recorded: String| {
            body = sent;
            recorded_body = recorded;
        };
        let same = |text: &str| (text.to_string(), text.to_string());
        let mut header_reason = false;
        match (action, label) {
            ("create", l) => {
                let (sent, rec) = match l {
                    "invalid" => same("{\"name\":"),
                    "empty" => same("{\"name\":\"\"}"),
                    "dup" => (
                        json!({"name":"admin3-beta","domainId":t.domain}).to_string(),
                        "{\"domainId\":\"<target-domain>\",\"name\":\"admin3-beta\"}".to_string(),
                    ),
                    "dup-global" => same("{\"name\":\"admin3-alpha\"}"),
                    "dup-quoted" => {
                        let text = json!({"name":QUOTED_NAME}).to_string();
                        (text.clone(), text)
                    }
                    "bad-domain" => same("{\"name\":\"admin3-fk\",\"domainId\":99999999}"),
                    "folded" => same("{\"NAME\":\"admin3-folded\",\"DESCRIPTION\":null,\"domainid\":null} trailing"),
                    "reasoned" => {
                        header_reason = true;
                        same("{\"name\":\"admin3-reasoned\"}")
                    }
                    "reason" => same("{\"name\":\"admin3-unreasoned\"}"),
                    _ => (
                        json!({"name":"admin3-new","domainId":t.domain,"description":"made <here> & now"}).to_string(),
                        "{\"description\":\"made <here> & now\",\"domainId\":\"<target-domain>\",\"name\":\"admin3-new\"}".to_string(),
                    ),
                };
                both(sent, rec);
            }
            ("update", l) => {
                let (sent, rec) = match l {
                    "invalid" | "bad-json" => same("{\"name\":"),
                    "dup" => same("{\"name\":\"admin3-used\"}"),
                    "empty" => same("{}"),
                    "empty-name" => same("{\"name\":\"\"}"),
                    "partial" => same("{\"description\":\"\"}"),
                    "typed" => same("{\"name\":7}"),
                    "folded" => same("{\"NAME\":\"admin3-folded\",\"Description\":null} trailing"),
                    _ => same("{\"name\":\"admin3-renamed\",\"description\":\"new <desc> & more\"}"),
                };
                both(sent, rec);
            }
            ("member-add", l) => {
                let user = (
                    json!({"memberType":"user","memberId":t.user}).to_string(),
                    "{\"memberId\":\"<target>\",\"memberType\":\"user\"}".to_string(),
                );
                let (sent, rec) = match l {
                    "invalid" | "bad-json" => same("{\"memberType\":"),
                    "required" => same("{}"),
                    "zero" => same("{\"memberType\":\"user\",\"memberId\":0}"),
                    "bad-type" => same("{\"memberType\":\"team\",\"memberId\":5}"),
                    "ou" | "foreign-ou" => same(&format!("{{\"memberType\":\"ou\",\"memberId\":{DEPT2}}}")),
                    "group" | "foreign-group" => same(&format!("{{\"memberType\":\"group\",\"memberId\":{GROUP}}}")),
                    "group-missing" => same("{\"memberType\":\"group\",\"memberId\":99999999}"),
                    "group-dynamic" => same(&format!("{{\"memberType\":\"group\",\"memberId\":{DYNAMIC}}}")),
                    "group-plain" => same(&format!("{{\"memberType\":\"group\",\"memberId\":{PLAIN}}}")),
                    "folded" => (
                        json!({"MEMBERTYPE":"user","memberid":t.user}).to_string() + " trailing",
                        "{\"memberId\":\"<target>\",\"membertype\":\"user\"} trailing".to_string(),
                    ),
                    _ => user,
                };
                both(sent, rec);
            }
            _ => {}
        }
        if label == "foreign-user" || (action == "member-add" && label == "foreign") {
            // Cross-tenant: an admin confined to another domain reaches nothing here.
        }
        let send = |body: String| {
            let uri = format!("/api{path}");
            let token = admin_token(a.user);
            async move {
                let mut request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-admin3-oracle").header("authorization", format!("Bearer {token}"));
                if header_reason {
                    request = request.header("x-audit-reason", "oracle");
                }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !matches!(status, 201 | 204) {
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
        let new_set: Option<i64> = owner.query_opt("SELECT id FROM admin_scope_sets WHERE name IN ('admin3-new','admin3-folded','admin3-reasoned') AND id NOT IN ($1,$2,$3,$4)", &[&ALPHA, &BETA, &USED, &QUOTED]).await?.map(|r| r.get(0));
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = masked(row.clone(), &users, &domains, new_set, &names)?;
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"admin:alert","payload":masked(payload, &users, &domains, new_set, &names)?}));
        }
        let wanted = match (action, label) {
            (_, "denied") => 403,
            ("get", "empty") => 200,
            (_, "reason") => 400,
            (_, "invalid" | "bad-json" | "empty" | "required" | "zero" | "bad-type" | "bad-member" | "typed") if action != "update" || label != "empty" => 400,
            ("update", "empty") => 204,
            ("create", "dup" | "dup-global" | "dup-quoted" | "repeat") => 409,
            ("create", "bad-domain") => 500,
            ("create", _) => 201,
            ("update", "dup") => 409,
            ("update" | "delete", "missing") => 404,
            ("delete", "in-use") => 409,
            ("delete", "repeat") => 404,
            ("update" | "delete", _) => 204,
            ("get", "missing") => 404,
            ("member-add", "missing-set" | "group-missing") => 404,
            ("member-add", "group-dynamic" | "group-plain") => 400,
            ("member-add", "foreign" | "foreign-ou" | "foreign-group") => 403,
            ("member-add", "repeat") => 200,
            ("member-add", _) => 201,
            ("member-remove", "missing" | "repeat") => 404,
            ("member-remove", _) => 204,
            _ => 200,
        };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Normalize identities that differ per run; fixtures are otherwise deterministic.
        let mut text = names(&raw);
        for (id, name) in &users {
            let name = name.trim_matches(['<', '>']);
            for end in [",", "}"] {
                for key in ["createdBy", "addedBy"] {
                    text = text.replace(&format!("\"{key}\":{id}{end}"), &format!("\"{key}\":\"{name}\"{end}"));
                }
                text = text.replace(&format!("\"memberType\":\"user\",\"memberId\":{id}{end}"), &format!("\"memberType\":\"user\",\"memberId\":\"{name}\"{end}"));
            }
        }
        for (id, name) in &domains {
            let name = name.trim_matches(['<', '>']);
            text = text.replace(&format!("\"domainId\":{id},"), &format!("\"domainId\":\"{name}\","));
        }
        if let Some(n) = new_set {
            text = text.replace(&format!("{{\"id\":{n}}}"), "{\"id\":\"<new-set>\"}");
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &users, &domains, new_set, &names)?, masked(after, &users, &domains, new_set, &names)?);
        let effects = json!([{"table":"admin_scope_sets","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !recorded_body.is_empty() { request["body"] = json!(names(&recorded_body)); }
        if header_reason { request["reason"] = json!("oracle"); }
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
        let file = dir.join(format!("scope-sets-{name}.json"));
        let row_file = dir.join(format!("scope-sets-{name}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = common::golden_doc(&file, "observation", &observation);
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                // Owner-approved security fix 2026-11-05 (#384): a foreign admin is refused at the
                // set's domain boundary before any reach rule runs, so neutralizing the reach rules
                // must leave the reviewed expectation untouched (the fault is masked, not observed).
                if fault == "reach-bypass" && common::is_pinned(&file) {
                    compared?;
                    eprintln!("FAULT-MASKED {fault}: {route_name} :: {label}");
                    return Ok(());
                }
                eprintln!("FAULT-OBSERVED {fault}: {status} {}", observation["response"]["body"]);
                compared.err().ok_or("planted family fault survived")?;
                eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
                return Ok(());
            }
            compared?;
            let expected: Value = common::golden_doc(&row_file, "effects", &observation["effects"]);
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
    owner
        .execute(
            "UPDATE audit_policy SET reason_required_areas=$1 WHERE id=1",
            &[&policy],
        )
        .await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE scope_type='set' AND scope_id=ANY($1)",
            &[&vec![ALPHA, BETA, USED, QUOTED]],
        )
        .await?;
    owner.execute("DELETE FROM admin_scope_sets WHERE name LIKE 'admin3-%' OR id BETWEEN 930001 AND 930009", &[]).await?;
    owner
        .execute(
            "DELETE FROM distribution_group_members WHERE group_id=ANY($1)",
            &[&vec![GROUP, DYNAMIC, PLAIN]],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM distribution_groups WHERE id=ANY($1)",
            &[&vec![GROUP, DYNAMIC, PLAIN]],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM departments WHERE id=ANY($1)",
            &[&vec![DEPT, DEPT2]],
        )
        .await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=ANY($1)", &[&vec![role, used_role]]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=ANY($1)",
            &[&vec![role, used_role]],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM admin_role_groups WHERE id=ANY($1)",
            &[&vec![role, used_role]],
        )
        .await?;
    for account in [&a, &b, &t, &g1, &g2, &g3] {
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
