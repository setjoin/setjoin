//! F01 slice `roles` frozen-Go oracle: HTTP wire, committed rows and audit.
//! Record mode runs the covered Go binary behind the front door; replay mode
//! serves the same requests from Rust with no Go upstream. Template: the users
//! slice oracle (`admin_identity_oracle`).
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_identity::AdminIdentityRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use std::sync::Arc;

struct Probe {
    inner: AdminIdentityRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
        "roles" => ("GET", "/admin/roles"),
        "role" => ("GET", "/admin/roles/{id}"),
        "role-create" => ("POST", "/admin/roles"),
        "role-update" => ("PUT", "/admin/roles/{id}"),
        "role-delete" => ("DELETE", "/admin/roles/{id}"),
        "member-assign" => ("POST", "/admin/roles/{id}/members"),
        "member-remove" => ("DELETE", "/admin/roles/{id}/members/{userId}"),
        "bulk-assign" => ("POST", "/admin/roles/{id}/members:bulk"),
        "bulk-revoke" => ("DELETE", "/admin/roles/{id}/members:bulk"),
        "effective" => ("GET", "/admin/users/{id}/effective-permissions"),
        "permissions" => ("GET", "/admin/permissions"),
        _ => panic!("unknown F01 roles action {action}"),
    }
}

/// Postgres `timestamptz::text` values that differ per run become one token;
/// fixed future instants (the 2031 request instants and the 2100 seeded role expiry) stay
/// visible.
fn scrub_timestamps(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let shaped = i + 19 <= b.len()
            && b[i..i + 4].iter().all(u8::is_ascii_digit)
            && b[i + 4] == b'-'
            && b[i + 7] == b'-'
            && b[i + 10] == b' '
            && b[i + 13] == b':'
            && b[i + 16] == b':';
        if shaped && !text[i..].starts_with("2031") && !text[i..].starts_with("2100") {
            let mut j = i + 19;
            if b.get(j) == Some(&b'.') {
                j += 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
            }
            if matches!(b.get(j), Some(b'+' | b'-')) {
                j += 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                out.push_str("<timestamp>");
                i = j;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Replace JSON number values equal to a known id (after `:`, `[` or `,`, before
/// `,`, `]` or `}`), so text such as `admin2` or an RFC 3339 instant is untouched.
fn name_runs(text: &str, ids: &[(i64, String)]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let after_delimiter = i > 0 && matches!(chars[i - 1], ':' | '[' | ',');
        if chars[i].is_ascii_digit() && after_delimiter {
            let mut j = i;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            let value: String = chars[i..j].iter().collect();
            let ends = j == chars.len() || matches!(chars[j], ',' | ']' | '}');
            if let Some((_, name)) = value.parse::<i64>().ok().filter(|_| ends).and_then(|n| {
                // Users and domains come from separate sequences, so numbers can collide:
                // a value under a `domain*` key is looked up among the domains first.
                let key: String = chars[..i].iter().rev().take(24).collect();
                let domain_key = key.contains("niamod") || key.contains("niamoD");
                ids.iter()
                    .find(|(id, name)| *id == n && name.contains("domain") == domain_key)
                    .or_else(|| ids.iter().find(|(id, _)| *id == n))
            }) {
                out.push_str(name);
            } else {
                out.push_str(&value);
            }
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn timestamp_like(s: &str) -> bool {
    s.len() >= 20 && s.as_bytes()[4] == b'-' && s.as_bytes()[10] == b'T'
}

/// Name database ids inside structured rows by their key.
fn mask(v: &mut Value, names: &[(&str, i64, String)], key: &str) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                mask(x, names, k);
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, names, key)),
        Value::Number(n) => {
            let kind = match key {
                "user_id" | "target_id" | "actor_id" | "user" | "by" | "targetUserId"
                | "user_ids" | "actor" => "user",
                "roleId" | "role" => "role",
                "domain" | "scope" | "override" => "domain",
                "scope_id" | "scopeId" => "set",
                _ => return,
            };
            if let Some(id) = n.as_i64() {
                if let Some((_, _, name)) = names.iter().find(|(k, i, _)| *k == kind && *i == id) {
                    *v = json!(name);
                }
            }
        }
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-01") {
                *s = "<timestamp>".into();
            } else if matches!(key, "checksum" | "prev_checksum") && !s.is_empty() {
                *s = "<checksum>".into();
            }
        }
        _ => {}
    }
}

/// Replace `"key":N` / `"key":"N"` occurrences of the named ids in rendered text.
fn name_ids(text: &str, key: &str, ids: &[(i64, String)]) -> String {
    let mut out = text.to_owned();
    for (id, name) in ids {
        for end in [",", "}", "]"] {
            out = out.replace(
                &format!("\"{key}\":{id}{end}"),
                &format!("\"{key}\":\"{name}\"{end}"),
            );
        }
        out = out.replace(
            &format!("\"{key}\":\"{id}\""),
            &format!("\"{key}\":\"{name}\""),
        );
    }
    out
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(c: &tokio_postgres::Client, users: &[i64]) -> Result<Value, BoxError> {
    let list = users
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(json!({
        "roles": rows(c, "SELECT jsonb_build_object('name',name,'description',description,'permissions',permissions,'scope',domain_scope,'builtin',is_builtin,'class',sod_class)::text FROM admin_role_groups WHERE name LIKE 'admin2-%' OR name LIKE ' admin2-%' ORDER BY name").await?,
        "assignments": rows(c, &format!("SELECT jsonb_build_object('user',ra.user_id,'role',rg.name,'override',ra.domain_override,'by',ra.granted_by,'expires',ra.expires_at,'scope_type',ra.scope_type,'scope_id',ra.scope_id,'eligible',ra.eligible)::text FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id IN ({list}) ORDER BY ra.user_id,rg.name")).await?,
        "jobs": rows(c, &format!("SELECT jsonb_build_object('op',op,'role',(SELECT name FROM admin_role_groups WHERE id=role_id),'actor',actor_id,'user_ids',user_ids,'expires',expires_at,'total',total,'status',status,'processed',processed,'scope_type',scope_type,'scope_id',scope_id,'eligible',eligible)::text FROM bulk_role_jobs WHERE actor_id IN ({list}) ORDER BY id")).await?,
    }))
}

#[allow(dead_code)]
struct Fixture {
    grant: i64,
    target_role: i64,
    high: i64,
    sec: i64,
    scoped_role: i64,
    set: i64,
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
    let Some(mut db) = Db::for_case("admin2-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    cleanup_leftovers(&owner).await?;
    let a = fixture::account(&owner, "admin2-admin").await?;
    let b = fixture::account(&owner, "admin2-other").await?;
    let t = fixture::account(&owner, "admin2-target").await?;
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
    for (user, at) in [
        (a.user, "2026-10-01T12:00:00Z"),
        (b.user, "2026-10-01T12:00:01.5Z"),
        (t.user, "2026-10-01T12:00:02.25Z"),
    ] {
        owner
            .execute(
                "UPDATE users SET created_at=$2::text::timestamptz WHERE id=$1",
                &[&user, &at],
            )
            .await?;
    }
    // Grant shapes: global admin, scoped to the other (or the target's) domain, or none.
    let granted = vec!["roles.manage", "users.read", "users.create"];
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec![], None),
        "foreign" => (granted, Some(b.domain)),
        l if l.starts_with("scoped") => (granted, Some(t.domain)),
        _ => (granted, None),
    };
    let insert_role = |name: &'static str,
                       perms: Vec<&'static str>,
                       scope: Option<i64>,
                       class: Option<&'static str>| {
        let owner = &owner;
        async move {
            Ok::<i64, BoxError>(
                owner
                    .query_one(
                        "INSERT INTO admin_role_groups(name,description,permissions,domain_scope,sod_class) VALUES($1,'',$2,$3,$4) RETURNING id",
                        &[&name, &perms, &scope, &class],
                    )
                    .await?
                    .get(0),
            )
        }
    };
    let grant: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES('admin2-grant',$1,$2) RETURNING id",
            &[&permissions, &scope],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &grant],
        )
        .await?;
    let in_domain = if label.starts_with("scoped") {
        Some(t.domain)
    } else {
        None
    };
    let target_role =
        insert_role("admin2-target-role", vec!["users.read"], in_domain, None).await?;
    let high = insert_role(
        "admin2-high",
        vec![
            "roles.manage",
            "users.read",
            "users.create",
            "domains.write",
        ],
        in_domain,
        None,
    )
    .await?;
    let sec = insert_role(
        "admin2-sec",
        vec!["users.read"],
        in_domain,
        Some("security"),
    )
    .await?;
    let sys = insert_role("admin2-sys", vec!["queue.read"], in_domain, Some("system")).await?;
    let scoped_role = insert_role(
        "admin2-domain-role",
        vec!["queue.read"],
        Some(t.domain),
        None,
    )
    .await?;
    let set: i64 = owner
        .query_one(
            "INSERT INTO admin_scope_sets(name,domain_id,created_by) VALUES('admin2-set',NULL,$1) RETURNING id",
            &[&a.user],
        )
        .await?
        .get(0);
    // Pre-existing memberships per case.
    let plain_member = !(action == "member-assign" && label != "update")
        && !(action == "effective" && label == "none")
        && !matches!(
            (action, label),
            ("role-create", _)
                | ("roles", _)
                | ("permissions", _)
                | ("bulk-assign", _)
                | ("bulk-revoke", _)
        );
    if plain_member {
        if (action, label) == ("role", "success") || (action, label) == ("role", "scoped") {
            owner
                .execute(
                    "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,domain_override,expires_at,scope_type,scope_id) VALUES($1,$2,$3,$4,'2100-01-01T00:00:00Z','set',$5)",
                    &[&t.user, &target_role, &a.user, &in_domain, &set],
                )
                .await?;
            owner
                .execute(
                    "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
                    &[&a.user, &target_role],
                )
                .await?;
        } else {
            owner
                .execute(
                    "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$3)",
                    &[&t.user, &target_role, &a.user],
                )
                .await?;
        }
    }
    if action == "effective" && label != "none" {
        owner
            .execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$3)",
                &[&t.user, &scoped_role, &a.user],
            )
            .await?;
    }
    if matches!(label, "protected") {
        owner
            .execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$3)",
                &[&t.user, &high, &a.user],
            )
            .await?;
    }
    if matches!(label, "sod" | "sod-collision") {
        owner
            .execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$3)",
                &[&t.user, &sys, &a.user],
            )
            .await?;
    }
    for mailbox in [a.mailbox, b.mailbox, t.mailbox] {
        owner
            .execute("DELETE FROM messages WHERE mailbox_id=$1", &[&mailbox])
            .await?;
        owner
            .execute("UPDATE mailboxes SET used_bytes=0 WHERE id=$1", &[&mailbox])
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
    // Policy and toggle state the case needs, restored in cleanup.
    if label.starts_with("sod") {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=true WHERE key='dengbao.sod_mode'",
                &[],
            )
            .await?;
    }
    if label == "reason" {
        owner
            .execute(
                "UPDATE audit_policy SET reason_required_areas='{roles,office}' WHERE id=1",
                &[],
            )
            .await?;
    }
    let fixture = Fixture {
        grant,
        target_role,
        high,
        sec,
        scoped_role,
        set,
    };
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_admin2_fault_{}", a.user);
    let mut private = false;
    let mut trigger = None;
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.action LIKE 'role\\_%' THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            trigger = Some("admin_audit_log");
        }
        Some("no-tenant-filter") => {
            let mut statements =
                format!("CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;");
            for (table, column) in [
                ("users", "domain_id"),
                ("admin_role_groups", "domain_scope"),
            ] {
                let columns: String = owner
                    .query_one("SELECT string_agg(quote_ident(column_name),',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name<>$2", &[&table, &column])
                    .await?
                    .get(0);
                statements.push_str(&format!("CREATE VIEW {schema}.{table} AS SELECT {columns},{}::bigint AS {column} FROM public.{table};GRANT SELECT,UPDATE,DELETE ON {schema}.{table} TO setjoin_app;", b.domain));
            }
            owner.batch_execute(&statements).await?;
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
    let users_names = [
        (t.user, "<target>"),
        (a.user, "<admin>"),
        (b.user, "<other>"),
    ];
    let mut names: Vec<(&str, i64, String)> = users_names
        .iter()
        .map(|(i, n)| ("user", *i, (*n).to_string()))
        .collect();
    names.extend([
        ("set", set, "<set>".into()),
        ("domain", a.domain, "<admin-domain>".into()),
        ("domain", b.domain, "<other-domain>".into()),
        ("domain", t.domain, "<target-domain>".into()),
    ]);
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin2-http").await?;
        let recording = go.is_some();
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: AdminIdentityRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "roles" {
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
        let role_part = match label {
            "invalid" if action != "effective" => "bad".to_string(),
            "missing" if action != "effective" && action != "member-remove" => "99999999".to_string(),
            "builtin" => "1".to_string(),
            "not-held" => fixture.high.to_string(),
            "sod" => fixture.sec.to_string(),
            _ => fixture.target_role.to_string(),
        };
        let user_part = match label {
            "invalid" if matches!(action, "effective" | "member-remove") => "bad".to_string(),
            "missing" if matches!(action, "effective" | "member-remove") => "99999999".to_string(),
            "none" => b.user.to_string(),
            _ => t.user.to_string(),
        };
        let mut path = if action == "effective" {
            pattern.replace("{id}", &user_part)
        } else {
            pattern.replace("{id}", &role_part).replace("{userId}", &user_part)
        };
        let mut query = String::new();
        let mut body = String::new();
        let users = |ids: &[i64]| ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        match (action, label) {
            ("roles" | "permissions", "invalid") => query = "limit=abc&q=%zz&x=1;2".into(),
            ("role-create", l) => body = match l {
                "invalid" => "{\"name\":".into(),
                "empty" => json!({"name":""}).to_string(),
                "bad-name" => json!({"name":"a/b","permissions":["users.read"]}).to_string(),
                "no-perms" => json!({"name":"admin2-np","permissions":[]}).to_string(),
                "unknown-perm" => json!({"name":"admin2-up","permissions":["users.read","nope.nope"]}).to_string(),
                "not-held" => json!({"name":"admin2-nh","permissions":["users.read","domains.write"]}).to_string(),
                "dup" => json!({"name":"admin2-target-role","permissions":["users.read"]}).to_string(),
                "folded" => json!({"NAME":" admin2-folded ","Permissions":["users.read"],"description":null}).to_string() + " trailing",
                "scoped" => json!({"name":"admin2-created","description":"scoped","permissions":["users.read"],"domainScope":t.domain}).to_string(),
                "scoped-wrong" => json!({"name":"admin2-created","permissions":["users.read"],"domainScope":b.domain}).to_string(),
                _ => json!({"name":"admin2-created","description":"made <by> admin2 & co","permissions":["users.read","roles.manage"]}).to_string(),
            },
            ("role-update", l) => body = match l {
                "bad-json" => "{".into(),
                "empty" => "{}".into(),
                "empty-name" => json!({"name":""}).to_string(),
                "bad-name" => json!({"name":"x\\y"}).to_string(),
                "unknown-perm" => json!({"permissions":["nope.nope"]}).to_string(),
                "not-held" => json!({"permissions":["domains.write"]}).to_string(),
                "partial" => json!({"description":"only <this>"}).to_string(),
                "scoped-move" => json!({"domainScope":b.domain}).to_string(),
                "scoped-global" => json!({"domainScope":-1}).to_string(),
                "sod-violation" => json!({"sodClass":"audit","permissions":["users.read","users.create"]}).to_string(),
                "sod-collision" => json!({"sodClass":"audit"}).to_string(),
                "folded" => json!({"NAME":"admin2-folded","sodClass":null}).to_string() + " trailing",
                _ => json!({"name":"admin2-renamed","description":"new","permissions":["users.read","roles.manage"],"sodClass":""}).to_string(),
            },
            ("member-assign", l) => body = match l {
                "bad-json" => "{".into(),
                "no-user" => json!({"userId":0}).to_string(),
                "scope-retired" => json!({"userId":t.user,"scopeType":"group","scopeId":424242}).to_string(),
                "scope-bad" => json!({"userId":t.user,"scopeType":"x"}).to_string(),
                "scope-noid" => json!({"userId":t.user,"scopeType":"ou"}).to_string(),
                "scope-orphan" => json!({"userId":t.user,"scopeId":424243}).to_string(),
                "set-missing" => json!({"userId":t.user,"scopeType":"set","scopeId":99999999}).to_string(),
                "set" => json!({"userId":t.user,"scopeType":"set","scopeId":fixture.set}).to_string(),
                "expires-bad" => json!({"userId":t.user,"expiresAt":"tomorrow"}).to_string(),
                "scoped-override" => json!({"userId":t.user,"domainOverride":t.domain}).to_string(),
                "scoped-override-wrong" => json!({"userId":t.user,"domainOverride":b.domain}).to_string(),
                "folded" => json!({"USERID":t.user,"ExpiresAt":""}).to_string() + " trailing",
                "success" => json!({"userId":t.user,"expiresAt":"2031-01-01T00:00:00+02:00","eligible":true}).to_string(),
                _ => json!({"userId":t.user}).to_string(),
            },
            ("bulk-assign", l) => body = match l {
                "bad-json" => "{".into(),
                "empty" => json!({"userIds":[]}).to_string(),
                "too-many" => json!({"userIds":(1..=1001).collect::<Vec<i64>>()}).to_string(),
                "expires-bad" => json!({"userIds":[t.user],"expiresAt":"x"}).to_string(),
                "expires-empty" => json!({"userIds":[t.user],"expiresAt":""}).to_string(),
                "expires-past" => json!({"userIds":[t.user],"expiresAt":"2001-01-01T00:00:00Z"}).to_string(),
                "scope-bad" => json!({"userIds":[t.user],"scopeType":"x"}).to_string(),
                "scope-ou" => json!({"userIds":[t.user],"scopeType":"ou","scopeId":424244}).to_string(),
                "folded" => format!("{{\"USERIDS\":[{}],\"Eligible\":null}} trailing", t.user),
                _ => format!("{{\"userIds\":[{}],\"expiresAt\":\"2031-01-01T00:00:00Z\",\"eligible\":true}}", users(&[t.user, b.user, t.user])),
            },
            ("bulk-revoke", l) => body = match l {
                "bad-json" => "{".into(),
                "empty" => json!({"userIds":[]}).to_string(),
                "folded" => format!("{{\"USERIDS\":[{}]}} trailing", t.user),
                _ => format!("{{\"userIds\":[{}],\"scopeType\":\"x\",\"eligible\":true,\"expiresAt\":\"bogus\"}}", users(&[t.user, t.user, b.user])),
            },
            _ => {}
        }
        if !query.is_empty() { path = format!("{path}?{query}"); }
        let reason = label != "reason";
        let send = |body: String, with_reason: bool| {
            let uri = format!("/api{path}");
            let token = admin_token(a.user);
            async move {
                let mut request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-admin2-oracle").header("authorization", format!("Bearer {token}"));
                if with_reason { request = request.header("x-audit-reason", "oracle"); }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone(), reason).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !matches!(status, 201 | 202 | 204) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let all_users = [t.user, a.user, b.user];
        let before = snapshot(&owner, &all_users).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let response = send(body.clone(), reason).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(&owner, &all_users).await?;
        let created_role: Option<i64> = owner.query_opt("SELECT id FROM admin_role_groups WHERE name IN ('admin2-created',' admin2-folded ')", &[]).await?.map(|r| r.get(0));
        let assignment: Option<i64> = owner.query_opt("SELECT id FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2", &[&t.user, &fixture.target_role]).await?.map(|r| r.get(0));
        let job: Option<i64> = owner.query_opt("SELECT max(id) FROM bulk_role_jobs WHERE actor_id=$1", &[&a.user]).await?.and_then(|r| r.get(0));
        let mut role_names: Vec<(i64, String)> = vec![
            (fixture.grant, "admin-grant".into()),
            (fixture.target_role, "target-role".into()),
            (fixture.high, "high".into()),
            (fixture.sec, "sec".into()),
            (sys, "sys".into()),
            (fixture.scoped_role, "domain-role".into()),
            (1, "super-admin".into()),
        ];
        if let Some(id) = created_role { role_names.push((id, "created-role".into())); }
        let audit_raw: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        let normalize_names = |text: &str| -> String {
            let mut out = text.replace(&domain_a, "host-a.test").replace(&domain_b, "host-b.test").replace(&domain_t, "host-t.test");
            out = out.replace(&format!("/admin/users/{}/", t.user), "/admin/users/<target>/").replace(&format!("/admin/users/{}/", b.user), "/admin/users/<other>/");
            out = out.replace(&format!("/members/{}", t.user), "/members/<target>");
            for (id, name) in &role_names {
                out = out.replace(&format!("/admin/roles/{id}/"), &format!("/admin/roles/<{name}>/")).replace(&format!("/admin/roles/{id}\""), &format!("/admin/roles/<{name}>\""));
            }
            out
        };
        let mut audit = audit_raw;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            // Target ids name their own kind of row.
            let kind = row["target_type"].as_str().unwrap_or("").to_owned();
            if let Some(id) = row["target_id"].as_i64() {
                row["target_id"] = match kind.as_str() {
                    "role_group" => json!(role_names.iter().find(|(i, _)| *i == id).map(|(_, n)| format!("<{n}>")).unwrap_or("<role>".into())),
                    "role_assignment" => json!("<assignment>"),
                    _ => row["target_id"].clone(),
                };
            }
            let text = normalize_names(&row.to_string());
            *row = serde_json::from_str(&text)?;
            for key in ["after_state", "before_state"] {
                if let Some(state) = row.get_mut(key) {
                    if let Some(role) = state.get("roleId").and_then(Value::as_i64) {
                        if let Some((_, n)) = role_names.iter().find(|(i, _)| *i == role) { state["roleId"] = json!(format!("<{n}>")); }
                    }
                }
            }
            mask(row, &names, "");
        }
        let wanted = expected_status(action, label);
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        let mut text = normalize_names(&raw);
        let id_names: Vec<(i64, String)> = role_names.iter().map(|(i, n)| (*i, format!("<{n}>"))).collect();
        let user_names: Vec<(i64, String)> = users_names.iter().map(|(i, n)| (*i, (*n).to_string())).collect();
        let domain_names: Vec<(i64, String)> = [(a.domain, "<admin-domain>"), (b.domain, "<other-domain>"), (t.domain, "<target-domain>")].iter().map(|(i, n)| (*i, (*n).to_string())).collect();
        text = scrub_timestamps(&text);
        text = match action {
            "roles" | "role" => name_ids(&name_ids(&text, "id", &id_names), "userId", &user_names),
            "effective" => name_ids(&text, "roleGroupId", &id_names),
            "role-create" if status == 201 => name_ids(&text, "id", &[(created_role.unwrap_or(-1), "<created-role>".into())]),
            "member-assign" if status == 201 => name_ids(&text, "id", &[(assignment.unwrap_or(-1), "<assignment>".into())]),
            "bulk-assign" | "bulk-revoke" if status == 202 => name_ids(&text, "jobId", &[(job.unwrap_or(-1), "<job>".into())]),
            _ => text,
        };
        text = name_ids(&text, "grantedBy", &user_names);
        for key in ["domainScope", "effectiveScope", "domainOverride"] { text = name_ids(&text, key, &domain_names); }
        text = name_ids(&text, "scopeId", &[(fixture.set, "<set>".into())]);
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (mut before, mut after) = (before, after);
        for state in [&mut before, &mut after] {
            let text = state.to_string().replace(&domain_a, "host-a.test").replace(&domain_b, "host-b.test").replace(&domain_t, "host-t.test");
            *state = serde_json::from_str(&text)?;
            mask(state, &names, "");
        }
        let effects = json!([{"table":"roles","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !query.is_empty() { request["query"] = json!(query); }
        if !body.is_empty() {
            let ids: Vec<(i64, String)> = vec![
                (t.user, "<target>".into()), (b.user, "<other>".into()), (a.user, "<admin>".into()),
                (t.domain, "<target-domain>".into()), (b.domain, "<other-domain>".into()), (set, "<set>".into()),
            ];
            request["body"] = if label == "too-many" {
                json!("{\"userIds\":[1..1001]}")
            } else {
                json!(name_runs(&body.replace(&domain_t, "host-t.test"), &ids))
            };
        }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":[]});
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
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
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
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
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
            "UPDATE feature_toggles SET enabled=false WHERE key='dengbao.sod_mode'",
            &[],
        )
        .await?;
    owner
        .execute(
            "UPDATE audit_policy SET reason_required_areas='{office}' WHERE id=1",
            &[],
        )
        .await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    cleanup_leftovers(&owner).await?;
    for account in [&a, &b, &t] {
        common::remove_blob_account(&owner, account).await?;
    }
    result
}

/// Every row this oracle can create, removed by name (also after a crashed run).
async fn cleanup_leftovers(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "DELETE FROM bulk_role_jobs WHERE actor_id IN (SELECT id FROM users WHERE email LIKE 'admin2-%');\
         UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'admin2-%' OR name LIKE ' admin2-%');\
         DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'admin2-%' OR name LIKE ' admin2-%');\
         DELETE FROM admin_role_assignments WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin2-%');\
         DELETE FROM admin_role_groups WHERE name LIKE 'admin2-%' OR name LIKE ' admin2-%';\
         DELETE FROM admin_scope_sets WHERE name='admin2-set';",
    ).await?;
    Ok(())
}

fn expected_status(action: &str, label: &str) -> u16 {
    match (action, label) {
        (_, "denied") => 403,
        ("role-create", "reason") => 400,
        ("roles", "foreign") => 200,
        ("role" | "role-update" | "role-delete" | "effective", "foreign") => 404,
        ("member-assign", "foreign") => 404,
        ("member-remove", "foreign") => 404,
        ("role-create", "foreign") => 403,
        ("role-create", "invalid" | "empty" | "bad-name" | "no-perms" | "unknown-perm") => 400,
        ("role-create", "not-held" | "scoped-wrong") => 403,
        ("role-create", "dup" | "repeat") => 500,
        ("role-create", _) => 201,
        ("role", "invalid") | ("effective", "invalid") => 400,
        ("role", "missing") => 404,
        ("role-update" | "role-delete", "invalid") => 400,
        ("role-update" | "role-delete", "missing") => 404,
        ("role-update" | "role-delete", "builtin") => 409,
        ("role-update", "bad-json" | "empty" | "empty-name" | "bad-name" | "unknown-perm") => 400,
        ("role-update", "not-held" | "scoped-move" | "scoped-global") => 403,
        ("role-update", "sod-violation" | "sod-collision") => 409,
        ("role-delete", "repeat") => 404,
        ("role-update" | "role-delete", _) => 204,
        (
            "member-assign",
            "invalid" | "bad-json" | "no-user" | "scope-retired" | "scope-bad" | "scope-noid"
            | "scope-orphan" | "set-missing" | "expires-bad",
        ) => 400,
        ("member-assign", "missing") => 404,
        // parity: a domain-scoped admin always fails `admin_scope_within` (NULL grant domain), so Go never lets one assign.
        ("member-assign", "not-held" | "scoped" | "scoped-override" | "scoped-override-wrong") => {
            403
        }
        ("member-assign", "protected") => 403,
        ("member-assign", "sod") => 409,
        ("member-assign", _) => 201,
        ("member-remove", "invalid") => 400,
        ("member-remove", "missing" | "repeat") => 404,
        ("member-remove", "protected") => 403,
        ("member-remove", _) => 204,
        (
            "bulk-assign" | "bulk-revoke",
            "invalid" | "bad-json" | "empty" | "too-many" | "expires-bad" | "expires-empty"
            | "expires-past" | "scope-bad",
        ) => 400,
        ("bulk-assign" | "bulk-revoke", "missing") => 404,
        ("bulk-assign" | "bulk-revoke", "not-held") => 403,
        ("bulk-assign" | "bulk-revoke", _) => 202,
        _ => 200,
    }
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
