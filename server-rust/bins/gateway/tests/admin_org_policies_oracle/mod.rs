//! F01 slice `org-policies` frozen-Go oracle: HTTP wire and committed rows of the
//! departments, email-address-policy and distribution-group routes. Record mode runs
//! the covered Go binary behind the front door; replay serves the same requests from
//! Rust with no Go upstream. Go audits none of these writes, so the audit section only
//! holds the `console.denied` rows of the denial cases.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_org_policies::AdminOrgPoliciesRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

mod expected;

struct Probe {
    inner: AdminOrgPoliciesRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
        "dept-list" => ("GET", "/admin/departments"),
        "dept-tree" => ("GET", "/admin/departments/tree"),
        "dept-create" => ("POST", "/admin/departments"),
        "dept-update" => ("PUT", "/admin/departments/{id}"),
        "dept-delete" => ("DELETE", "/admin/departments/{id}"),
        "dept-assign" => ("POST", "/admin/departments/assign-user"),
        "policy-list" => ("GET", "/admin/email-address-policies-list"),
        "policy-create" => ("POST", "/admin/email-address-policies"),
        "policy-update" => ("PUT", "/admin/email-address-policies/{id}"),
        "policy-delete" => ("DELETE", "/admin/email-address-policies/{id}"),
        "policy-reorder" => ("POST", "/admin/email-address-policies/reorder"),
        "policy-preview" => ("POST", "/admin/email-address-policies/{id}/preview"),
        "policy-match-count" => ("POST", "/admin/email-address-policies/match-count"),
        "policy-apply" => ("POST", "/admin/email-address-policies/apply"),
        "policy-apply-status" => ("GET", "/admin/email-address-policies/apply/{jobId}"),
        "groups" => ("GET", "/admin/distribution-groups"),
        _ => panic!("unknown F01 org-policies action {action}"),
    }
}

// Fixed ids keep the goldens free of run-specific numbers; generated rows (created
// departments, policies, jobs) come from sequences far below these.
const ROOT: i64 = 940001;
const CHILD: i64 = 940002;
const OPS: i64 = 940003;
const EMPTY: i64 = 940004;
const USED: i64 = 940005;
const P1: i64 = 950001;
const P2: i64 = 950002;
const P3: i64 = 950003;
const JOB_DONE: i64 = 960001;
const JOB_ERROR: i64 = 960002;
const JOB_QUEUED: i64 = 960003;
const GROUP: i64 = 970001;
const DYNAMIC: i64 = 970002;
const PLAIN: i64 = 970003;
const MISSING: i64 = 99999999;

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Mask run-specific identities by the key that names them.
fn mask(v: &mut Value, users: &[(i64, &str)], domains: &[(i64, &str)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(
                        k.as_str(),
                        "user_id" | "actor_id" | "actor" | "userId" | "target_id"
                    );
                    let domain = matches!(k.as_str(), "domainId" | "domain_id");
                    if user {
                        if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    } else if domain {
                        if let Some((_, name)) = domains.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    }
                } else if k == "cond_domain_ids" {
                    if let Value::Array(items) = x {
                        for item in items {
                            if let Some((_, name)) = item
                                .as_i64()
                                .and_then(|n| domains.iter().find(|(i, _)| *i == n))
                            {
                                *item = json!(name);
                            }
                        }
                    }
                } else {
                    mask(x, users, domains);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, users, domains)),
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
    names: &dyn Fn(&str) -> String,
) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    mask(&mut v, users, domains);
    Ok(v)
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(
    c: &tokio_postgres::Client,
    job_floor: i64,
    target: i64,
) -> Result<Value, BoxError> {
    // Generated ids are replaced by "<new>" so recordings carry no sequence numbers.
    let dept =
        "CASE WHEN id BETWEEN 940001 AND 940009 THEN to_jsonb(id) ELSE '\"<new>\"'::jsonb END";
    let dept_parent = "CASE WHEN parent_id IS NULL THEN 'null'::jsonb WHEN parent_id BETWEEN 940001 AND 940009 THEN to_jsonb(parent_id) ELSE '\"<new>\"'::jsonb END";
    Ok(json!({
        "departments": rows(c, &format!("SELECT jsonb_build_object('id',{dept},'name',name,'parent_id',{dept_parent},'path',path,'ldap_ou',ldap_ou,'sort_order',sort_order,'created_at',created_at::text,'updated_at',updated_at::text)::text FROM departments WHERE name LIKE 'admin10-%' OR id BETWEEN 940001 AND 940009 ORDER BY path,id")).await?,
        "assignments": rows(c, &format!("SELECT jsonb_build_object('user','target','department',(SELECT name FROM departments d WHERE d.id=u.department_id))::text FROM users u WHERE id={target}")).await?,
        "policies": rows(c, "SELECT jsonb_build_object('id',CASE WHEN id BETWEEN 950001 AND 950009 THEN to_jsonb(id) ELSE '\"<new>\"'::jsonb END,'priority',priority,'name',name,'enabled',enabled,'overwrite_directory_address',overwrite_directory_address,'cond_department',cond_department,'cond_domain_ids',cond_domain_ids,'cond_mailbox_type',cond_mailbox_type,'cond_ad_ou',cond_ad_ou,'primary_template',primary_template,'additional_templates',additional_templates,'duplicate_resolution',duplicate_resolution,'created_at',created_at::text,'updated_at',updated_at::text)::text FROM email_address_policies WHERE name LIKE 'admin10-%' OR id BETWEEN 950001 AND 950009 ORDER BY name,id").await?,
        "jobs": rows(c, &format!("SELECT jsonb_build_object('id',CASE WHEN id BETWEEN 960001 AND 960009 THEN to_jsonb(id) ELSE '\"<new>\"'::jsonb END,'policy_id',CASE WHEN policy_id BETWEEN 950001 AND 950009 THEN to_jsonb(policy_id) WHEN policy_id IS NULL THEN 'null'::jsonb ELSE '\"<new>\"'::jsonb END,'status',status,'total',total,'applied',applied,'error',error,'created_at',created_at::text,'updated_at',updated_at::text)::text FROM eap_apply_jobs WHERE id > {job_floor} OR id BETWEEN 960001 AND 960009 ORDER BY id")).await?,
    }))
}

/// Replace the generated `createdAt`/`updatedAt` values of a policy body (fixtures use 2026-10-01).
fn mask_times(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("At\":\"") {
        let start = at + 5;
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find('"').unwrap_or(rest.len());
        if rest[..end].starts_with("2026-10-01") {
            out.push_str(&rest[..end]);
        } else {
            out.push_str("<timestamp>");
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Cases share fixed fixture keys and global windows (audit id, receipts), so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

/// The permission the route's Go middleware wants.
fn needed(action: &str) -> &'static str {
    match action {
        "dept-create" | "dept-update" | "dept-delete" | "dept-assign" => "users.create",
        "policy-create" | "policy-update" | "policy-delete" | "policy-reorder" | "policy-apply" => {
            "identity.write"
        }
        "groups" => "scope_sets.manage",
        _ => "domains.read",
    }
}
/// A permission that is not any route's gate for `action`.
fn lacking(action: &str) -> &'static str {
    match action {
        "dept-list"
        | "dept-tree"
        | "policy-list"
        | "policy-preview"
        | "policy-match-count"
        | "policy-apply-status" => "users.create",
        _ => "queue.read",
    }
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(mut db) = Db::for_case("admin10-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin10-admin").await?;
    let b = fixture::account(&owner, "admin10-other").await?;
    let t = fixture::account(&owner, "admin10-target").await?;
    let g1 = fixture::account(&owner, "admin10-group").await?;
    let g2 = fixture::account(&owner, "admin10-dynamic").await?;
    let g3 = fixture::account(&owner, "admin10-plain").await?;
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
        (domain_of(g1.domain).await?, "host-g1.test"),
        (domain_of(g2.domain).await?, "host-g2.test"),
        (domain_of(g3.domain).await?, "host-g3.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    // Grant shapes: global admin, scoped to the other domain, or lacking the permission.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec![lacking(action)], None),
        "foreign-ou" => (vec![needed(action)], None),
        l if l.starts_with("foreign") => (vec![needed(action)], Some(b.domain)),
        _ => (vec![needed(action)], None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("admin10-{}", a.user), &permissions, &scope],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    owner
        .execute(
            "UPDATE users SET first_name='Ada', last_name='Lovelace' WHERE id=$1",
            &[&t.user],
        )
        .await?;
    // Departments (a small tree, one empty, one with a member), with fixed ids and times.
    for (id, name, parent, path, ou, sort) in [
        (ROOT, "admin10-eng", None, "admin10-eng", "ou=eng", 1),
        (
            CHILD,
            "admin10-sub",
            Some(ROOT),
            "admin10-eng/admin10-sub",
            "ou=sub",
            1,
        ),
        (OPS, "admin10-ops", None, "admin10-ops", "ou=ops", 2),
        (EMPTY, "admin10-empty", None, "admin10-empty", "ou=empty", 3),
        (USED, "admin10-used", None, "admin10-used", "ou=used", 4),
    ] {
        owner
            .execute(
                "INSERT INTO departments(id,name,parent_id,path,ldap_ou,sort_order,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')",
                &[&id, &name, &parent, &path, &ou, &sort],
            )
            .await?;
    }
    owner
        .execute(
            "UPDATE users SET department_id=$1 WHERE id=$2",
            &[&USED, &t.user],
        )
        .await?;
    if label == "foreign-ou" {
        // Confined to the "ops" department subtree: the other departments are out of reach.
        owner
            .execute(
                "UPDATE admin_role_assignments SET scope_type='ou', scope_id=$1 WHERE user_id=$2",
                &[&OPS, &a.user],
            )
            .await?;
    }
    for (id, mailbox, dynamic, usable, external) in [
        (GROUP, g1.mailbox, false, true, None),
        (DYNAMIC, g2.mailbox, true, true, Some("ext-1")),
        (PLAIN, g3.mailbox, false, false, None),
    ] {
        owner
            .execute(
                "INSERT INTO distribution_groups(id,mailbox_id,is_dynamic,usable_as_admin_scope,scim_external_id,scim_source_id) VALUES($1,$2,$3,$4,$5,$6)",
                &[&id, &mailbox, &dynamic, &usable, &external, &external.map(|_| 1_i64)],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO distribution_group_members(group_id,mailbox_id) VALUES($1,$2)",
            &[&GROUP, &t.mailbox],
        )
        .await?;
    // Policies: two enabled (10, 20) and a disabled duplicate of 20.
    for (id, priority, name, enabled, template, additional, department) in [
        (
            P1,
            10,
            "admin10-policy-one",
            true,
            "{given_name}.{surname}@{domain}",
            Some(vec!["{first_initial}{surname}@{domain}".to_string()]),
            Some(vec!["admin10-eng".to_string()]),
        ),
        (
            P2,
            20,
            "admin10-policy-two",
            true,
            "{user_name}@{domain}",
            None,
            None,
        ),
        (
            P3,
            20,
            "admin10-policy-three",
            false,
            "{given_name}@{domain}",
            None,
            None,
        ),
    ] {
        owner
            .execute(
                "INSERT INTO email_address_policies(id,priority,name,enabled,primary_template,additional_templates,cond_department,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')",
                &[&id, &priority, &name, &enabled, &template, &additional, &department],
            )
            .await?;
    }
    let job_floor: i64 = owner
        .query_one(
            "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM eap_apply_jobs_id_seq",
            &[],
        )
        .await?
        .get(0);
    for (id, policy, status, total, applied, error) in [
        (JOB_DONE, Some(P1), "done", Some(5), 5, None),
        (
            JOB_ERROR,
            None,
            "error",
            Some(2),
            1,
            Some("boom <&> failed"),
        ),
        (JOB_QUEUED, Some(P2), "queued", None, 0, None),
    ] {
        owner
            .execute(
                "INSERT INTO eap_apply_jobs(id,policy_id,status,total,applied,error,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')",
                &[&id, &policy, &status, &total, &applied, &error],
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
    // Faults run a private admin_can_reach/admin_scope_within that always say yes.
    let schema = format!("gofree_admin10_fault_{}", a.user);
    let mut private = false;
    if fault == Some("reach-bypass") {
        owner.batch_execute(&format!("CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;CREATE FUNCTION {schema}.admin_can_reach(bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';CREATE FUNCTION {schema}.admin_can_reach_perm(bigint,bigint,text[]) RETURNS boolean LANGUAGE sql AS 'SELECT true';CREATE FUNCTION {schema}.admin_scope_within(bigint,text,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO setjoin_app;")).await?;
        private = true;
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
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin10-http").await?;
        let recording = go.is_some();
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: AdminOrgPoliciesRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "org-policies" {
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
        let id_part = match (action, label) {
            (_, "invalid-id") => "bad".to_string(),
            (_, "zero-id") => "0".to_string(),
            (_, "missing") => MISSING.to_string(),
            ("dept-update", "move" | "parent-zero" | "parent-missing") => CHILD.to_string(),
            ("dept-update", _) => ROOT.to_string(),
            ("dept-delete", "success") => EMPTY.to_string(),
            ("dept-delete", "children") => ROOT.to_string(),
            ("dept-delete", "users") => USED.to_string(),
            ("dept-delete", _) => EMPTY.to_string(),
            ("policy-delete", _) => P3.to_string(),
            ("policy-preview", "empty-local") => P3.to_string(),
            ("policy-preview", _) => P1.to_string(),
            ("policy-update", _) => P2.to_string(),
            _ => "1".to_string(),
        };
        let job_part = match label {
            "invalid" => "bad".to_string(),
            "missing" => MISSING.to_string(),
            "error" => JOB_ERROR.to_string(),
            "queued" => JOB_QUEUED.to_string(),
            _ => JOB_DONE.to_string(),
        };
        let path = pattern.replace("{id}", &id_part).replace("{jobId}", &job_part);
        // `(sent, recorded)`: the recorded form never contains run-specific numbers.
        let same = |text: &str| (text.to_string(), text.to_string());
        let long_name = "x".repeat(129);
        let (sent, recorded) = match (action, label) {
            ("dept-create", l) => match l {
                "invalid" | "bad-json" => same("{\"name\":"),
                "empty-name" => same("{\"name\":\"  \"}"),
                "bad-name" => same("{\"name\":\"a/b\"}"),
                "long-name" => same(&format!("{{\"name\":\"{long_name}\"}}")),
                "parent-missing" => same("{\"name\":\"admin10-orphan\",\"parentId\":99999999}"),
                "parent-zero" => same("{\"name\":\"admin10-zero\",\"parentId\":0}"),
                "parent-negative" => same("{\"name\":\"admin10-negative\",\"parentId\":-5}"),
                "dup" => same("{\"name\":\"admin10-eng\"}"),
                "ldap-trim" => same("{\"name\":\"  admin10-trim  \",\"ldapOu\":\"  \"}"),
                "folded" => same("{\"NAME\":\"admin10-folded\",\"LDAPOU\":null,\"ParentId\":null} trailing"),
                "typed" => same("{\"name\":7}"),
                "child" | "foreign-parent" => same(&format!("{{\"name\":\"admin10-kid\",\"parentId\":{ROOT},\"ldapOu\":\"ou=kid\"}}")),
                _ => same("{\"name\":\"admin10-new\",\"ldapOu\":\"ou=new\"}"),
            },
            ("dept-update", l) => match l {
                "invalid" | "bad-json" => same("{\"name\":"),
                "typed" => same("{\"sortOrder\":\"x\"}"),
                "empty" => same("{}"),
                "move" => same(&format!("{{\"parentId\":{OPS}}}")),
                "parent-zero" => same("{\"parentId\":0}"),
                "parent-missing" => same("{\"parentId\":99999999}"),
                "sort-only" => same("{\"sortOrder\":7}"),
                "big-sort" => same("{\"sortOrder\":3000000000}"),
                "ldap-only" => same("{\"ldapOu\":\"ou=renamed\"}"),
                "name-dup" => same("{\"name\":\"admin10-ops\"}"),
                "folded" => same("{\"NAME\":\"admin10-eng3\",\"SortOrder\":null} trailing"),
                _ => same("{\"name\":\"admin10-eng2\",\"ldapOu\":\"ou=eng2\",\"sortOrder\":5}"),
            },
            ("dept-assign", l) => {
                let user = |extra: &str| {
                    (
                        format!("{{\"userId\":{}{extra}}}", t.user),
                        format!("{{\"userId\":\"<target>\"{extra}}}"),
                    )
                };
                match l {
                    "invalid" | "bad-json" => same("{\"userId\":"),
                    "no-user" => same("{}"),
                    "negative-user" => same("{\"userId\":-1,\"departmentId\":1}"),
                    "missing-user" => same(&format!("{{\"userId\":{MISSING},\"departmentId\":{ROOT}}}")),
                    "clear" => user(",\"departmentId\":null"),
                    "zero-dept" => user(",\"departmentId\":0"),
                    "dept-missing" => user(",\"departmentId\":99999999"),
                    "folded" => (
                        format!("{{\"USERID\":{},\"DepartmentID\":{ROOT}}} trailing", t.user),
                        format!("{{\"USERID\":\"<target>\",\"DepartmentID\":{ROOT}}} trailing"),
                    ),
                    _ => user(&format!(",\"departmentId\":{ROOT}")),
                }
            }
            ("policy-create", l) => match l {
                "invalid" | "bad-json" => same("{\"name\":"),
                "no-name" => same("{\"primaryTemplate\":\"{given_name}@{domain}\"}"),
                "no-template" => same("{\"name\":\"admin10-bare\"}"),
                "template-at" => same("{\"name\":\"admin10-bare\",\"primaryTemplate\":\"{given_name}\"}"),
                "template-var" => same("{\"name\":\"admin10-bare\",\"primaryTemplate\":\"first@example.test\"}"),
                "template-unknown" => same("{\"name\":\"admin10-bare\",\"primaryTemplate\":\"{nope}@{domain}\"}"),
                "dup" => same("{\"name\":\"admin10-dup\",\"priority\":10,\"primaryTemplate\":\"{given_name}@{domain}\"}"),
                "bad-dupres" => same("{\"name\":\"admin10-dupres\",\"primaryTemplate\":\"{given_name}@{domain}\",\"duplicateResolution\":\"random\"}"),
                "nulls" => same("{\"name\":\"admin10-nulls\",\"primaryTemplate\":\"{given_name}@{domain}\",\"condDepartment\":[null,\"x\"],\"condDomainIds\":[null],\"enabled\":null,\"priority\":null}"),
                "typed-array" => same("{\"name\":\"admin10-typed\",\"primaryTemplate\":\"{given_name}@{domain}\",\"condDepartment\":\"x\"}"),
                "float-priority" => same("{\"name\":\"admin10-float\",\"primaryTemplate\":\"{given_name}@{domain}\",\"priority\":1.5}"),
                "big-priority" => same("{\"name\":\"admin10-big\",\"primaryTemplate\":\"{given_name}@{domain}\",\"priority\":3000000000}"),
                "empty-arrays" => same("{\"name\":\"admin10-empties\",\"primaryTemplate\":\"{given_name}@{domain}\",\"condDepartment\":[],\"additionalTemplates\":[]}"),
                "folded" => same("{\"NAME\":\"admin10-folded\",\"PrimaryTemplate\":\"{surname}@{domain}\",\"Enabled\":false} trailing"),
                "minimal" => same("{\"name\":\"admin10-minimal\",\"primaryTemplate\":\"{surname}@{domain}\"}"),
                _ => (
                    json!({"name":"admin10-full <p> & co","priority":50,"enabled":true,"overwriteDirectoryAddress":true,"condDepartment":["admin10-eng","dept <x>"],"condDomainIds":[t.domain],"condMailboxType":["personal"],"condAdOu":["ou=eng"],"primaryTemplate":"{given_name}.{surname}@{domain}","additionalTemplates":["{first_initial}{surname}@{domain}","{user_name}@{domain}"],"duplicateResolution":"numeric_suffix"}).to_string(),
                    "{\"additionalTemplates\":[\"{first_initial}{surname}@{domain}\",\"{user_name}@{domain}\"],\"condAdOu\":[\"ou=eng\"],\"condDepartment\":[\"admin10-eng\",\"dept <x>\"],\"condDomainIds\":[\"<target-domain>\"],\"condMailboxType\":[\"personal\"],\"duplicateResolution\":\"numeric_suffix\",\"enabled\":true,\"name\":\"admin10-full <p> & co\",\"overwriteDirectoryAddress\":true,\"primaryTemplate\":\"{given_name}.{surname}@{domain}\",\"priority\":50}".to_string(),
                ),
            },
            ("policy-update", l) => match l {
                "invalid" | "bad-json" => same("{\"name\":"),
                "dup" => same("{\"priority\":10}"),
                "empty" => same("{}"),
                "partial" => same("{\"enabled\":false}"),
                "rename" => same("{\"name\":\"admin10-renamed\"}"),
                "bad-template" => same("{\"primaryTemplate\":\"nothing\"}"),
                "bad-dupres" => same("{\"duplicateResolution\":\"random\"}"),
                "empty-dupres" => same("{\"duplicateResolution\":\"\"}"),
                "arrays" => same("{\"condDepartment\":[\"admin10-used\"],\"additionalTemplates\":[\"{surname}@{domain}\"],\"condMailboxType\":[]}"),
                "typed" => same("{\"enabled\":\"yes\"}"),
                "folded" => same("{\"PRIORITY\":25,\"Name\":null} trailing"),
                _ => same("{\"priority\":25,\"name\":\"admin10-policy-two-b\",\"enabled\":true,\"overwriteDirectoryAddress\":true,\"primaryTemplate\":\"{surname}.{given_name}@{domain}\"}"),
            },
            ("policy-reorder", l) => match l {
                "invalid" | "bad-json" => same("{\"order\":"),
                "empty" => same("{\"order\":[]}"),
                "collision" => same(&format!("{{\"order\":[{P2},{P1}]}}")),
                "unknown" => same(&format!("{{\"order\":[{P1},99999999,{P2}]}}")),
                "dups" => same(&format!("{{\"order\":[{P1},{P1},{P2}]}}")),
                "with-disabled" => same(&format!("{{\"order\":[{P1},{P3},{P2}]}}")),
                "null-body" => same("null"),
                _ => same(&format!("{{\"order\":[{P1},{P2}]}}")),
            },
            ("policy-preview", l) => match l {
                "invalid" | "bad-json" => same("{\"policyId\":"),
                "empty-local" => (
                    format!("{{\"policyId\":{P3},\"userId\":{},\"mailboxId\":{}}}", a.user, a.mailbox),
                    format!("{{\"policyId\":{P3},\"userId\":\"<admin>\",\"mailboxId\":\"<admin-mailbox>\"}}"),
                ),
                "no-user" => same(&format!("{{\"policyId\":{P1}}}")),
                "missing" => same("{\"policyId\":99999999,\"userId\":1,\"mailboxId\":1}"),
                _ => (
                    format!("{{\"policyId\":{P1},\"userId\":{},\"mailboxId\":{}}}", t.user, t.mailbox),
                    format!("{{\"policyId\":{P1},\"userId\":\"<target>\",\"mailboxId\":\"<target-mailbox>\"}}"),
                ),
            },
            ("policy-match-count", l) => match l {
                "invalid" | "bad-json" => same("{\"condDepartment\":"),
                "none" => same("{\"condDepartment\":[\"admin10-nowhere\"]}"),
                "domain" => (
                    json!({"condDomainIds":[t.domain],"condMailboxType":["personal"]}).to_string(),
                    "{\"condDomainIds\":[\"<target-domain>\"],\"condMailboxType\":[\"personal\"]}".to_string(),
                ),
                "ou" => same("{\"condAdOu\":[\"ou=used\"],\"condDepartment\":[]}"),
                "typed" => same("{\"condDomainIds\":[\"x\"]}"),
                _ => same("{\"condDepartment\":[\"admin10-used\"]}"),
            },
            ("policy-apply", l) => match l {
                "invalid" | "bad-json" => same("{\"policyId\":"),
                "all" => same("{}"),
                "null-body" => same("null"),
                "typed" => same("{\"policyId\":\"x\"}"),
                "missing" => same("{\"policyId\":99999999}"),
                _ => same(&format!("{{\"policyId\":{P1}}}")),
            },
            _ => (String::new(), String::new()),
        };
        let mut body = sent;
        let recorded_body = recorded;
        if body.is_empty() && !matches!(method, "GET" | "DELETE") {
            body = "{}".into();
        }
        let send = |body: String| {
            let uri = format!("/api{path}");
            let token = admin_token(a.user);
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-admin10-oracle").header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !matches!(status, 200..=204) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let before = snapshot(&owner, job_floor, t.user).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if recording && std::env::var_os("GOFREE_ORACLE_LEARN").is_some() {
            eprintln!("LEARN {action}/{label} {status} {}", raw.chars().take(160).collect::<String>().replace('\n', " "));
        }
        let after = snapshot(&owner, job_floor, t.user).await?;
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = masked(row.clone(), &users, &domains, &names)?;
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"admin:alert","payload":masked(payload, &users, &domains, &names)?}));
        }
        let wanted = expected::status(action, label);
        if recording && std::env::var_os("GOFREE_ORACLE_LEARN").is_none() && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        if recording && std::env::var_os("GOFREE_ORACLE_LEARN").is_some() {
            return Ok(());
        }
        // Normalize identities that differ per run; fixtures are otherwise deterministic.
        let mut text = mask_times(&names(&raw));
        let new_id = |table: &str, filter: &str| {
            let owner = &owner;
            let sql = format!("SELECT id FROM {table} WHERE {filter} ORDER BY id DESC LIMIT 1");
            async move {
                owner.query_opt(&sql, &[]).await.map(|r| r.map(|r| r.get::<_, i64>(0)))
            }
        };
        if let Some(n) = new_id("departments", "name LIKE 'admin10-%' AND id NOT BETWEEN 940001 AND 940009").await? {
            text = text.replace(&format!("{{\"id\":{n}}}"), "{\"id\":\"<new>\"}");
        }
        if let Some(n) = new_id("email_address_policies", "name LIKE 'admin10-%' AND id NOT BETWEEN 950001 AND 950009").await? {
            text = text.replace(&format!("{{\"id\":{n},"), "{\"id\":\"<new>\",");
        }
        if let Some(n) = new_id("eap_apply_jobs", &format!("id > {job_floor} AND id NOT BETWEEN 960001 AND 960009")).await? {
            text = text.replace(&format!("{{\"jobId\":{n}}}"), "{\"jobId\":\"<new>\"}");
        }
        for (id, name) in &domains {
            let name = name.trim_matches(['<', '>']);
            text = text.replace(&format!("\"condDomainIds\":[{id}]"), &format!("\"condDomainIds\":[\"{name}\"]"));
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &users, &domains, &names)?, masked(after, &users, &domains, &names)?);
        let effects = json!([{"table":"org-policies","before":before,"after":after}]);
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
        let file = dir.join(format!("org-policies-{name}.json"));
        let row_file = dir.join(format!("org-policies-{name}-row-effects.json"));
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
    if fault.is_some() {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute(
            "DELETE FROM eap_apply_jobs WHERE id > $1 OR id BETWEEN 960001 AND 960009",
            &[&job_floor],
        )
        .await?;
    owner.execute("DELETE FROM email_address_policies WHERE name LIKE 'admin10-%' OR id BETWEEN 950001 AND 950009", &[]).await?;
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
    owner.execute("UPDATE users SET department_id=NULL WHERE department_id IN (SELECT id FROM departments WHERE name LIKE 'admin10-%' OR id BETWEEN 940001 AND 940009)", &[]).await?;
    owner
        .execute(
            "DELETE FROM departments WHERE name LIKE 'admin10-%' OR id BETWEEN 940001 AND 940009",
            &[],
        )
        .await?;
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
