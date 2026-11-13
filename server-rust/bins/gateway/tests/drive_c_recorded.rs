//! #276: frozen-Go HTTP, committed rows and notifications for the F14
//! sharing/ACL, lock, watch and as-of routes (20 transferred registrations).
//! Replay needs no Go; recording needs `GOFREE_RECORD_GO_BINARY` and
//! `GOFREE_GO_SOURCE` and writes exclusive-create goldens.
mod common;
#[path = "common/office_fixture.rs"]
mod fixture;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture as accounts, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

/// A CPU-starved shared host can exceed the adapter's default 1 s pool wait / 2 s
/// statement deadline, which forwards the request to Go and masquerades as a parity
/// failure (#421, as #368). Only the deadlines are widened; every assertion is unchanged.
fn patient_exec(dsn: &str, size: usize) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let patient = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        size,
        setjoin_pg::Timeouts {
            pool_wait: patient,
            create: patient,
            statement: patient,
        },
    )
    .map_err(|e| e.0)?)
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Route {
    name: &'static str,
    method: &'static str,
    canonical: &'static str,
    mutator: bool,
    ok: u16,
}
const fn r(
    name: &'static str,
    method: &'static str,
    canonical: &'static str,
    mutator: bool,
    ok: u16,
) -> Route {
    Route {
        name,
        method,
        canonical,
        mutator,
        ok,
    }
}
const ROUTES: &[Route] = &[
    r("node_access", "GET", "/drive/nodes/{id}/access", false, 200),
    r("acl_subjects", "GET", "/drive/acl-subjects", false, 200),
    r(
        "grant_preview",
        "POST",
        "/drive/nodes/{id}/acl/preview",
        false,
        200,
    ),
    r("grant", "POST", "/drive/nodes/{id}/acl", true, 200),
    r("revoke", "DELETE", "/drive/acl-grants/{id}", true, 200),
    r(
        "inheritance_preview",
        "POST",
        "/drive/nodes/{id}/inheritance/preview",
        false,
        200,
    ),
    r(
        "inheritance_set",
        "PUT",
        "/drive/nodes/{id}/inheritance",
        true,
        200,
    ),
    r("quick_views", "GET", "/drive/quick-views", false, 200),
    r(
        "request_preview",
        "POST",
        "/drive/nodes/{id}/access-requests/preview",
        false,
        200,
    ),
    r(
        "request_create",
        "POST",
        "/drive/nodes/{id}/access-requests",
        true,
        200,
    ),
    r(
        "folder_admins",
        "GET",
        "/drive/nodes/{id}/folder-admins",
        false,
        200,
    ),
    r(
        "folder_admin_put",
        "PUT",
        "/drive/nodes/{id}/folder-admins/{userId}",
        true,
        204,
    ),
    r(
        "folder_admin_delete",
        "DELETE",
        "/drive/nodes/{id}/folder-admins/{userId}",
        true,
        204,
    ),
    r("lock_put", "PUT", "/drive/files/{id}/lock", true, 200),
    r("lock_delete", "DELETE", "/drive/files/{id}/lock", true, 204),
    r("lock_list", "GET", "/drive/spaces/{id}/locks", false, 200),
    r("watch_put", "PUT", "/drive/nodes/{id}/watch", true, 204),
    r(
        "watch_delete",
        "DELETE",
        "/drive/nodes/{id}/watch",
        true,
        204,
    ),
    r("asof", "GET", "/drive/spaces/{id}/asof", false, 200),
    r("watches", "GET", "/drive/watches", false, 200),
];

macro_rules! cases {
    ($($name:ident => ($route:expr, $case:expr)),* $(,)?) => {
        $(#[tokio::test] async fn $name() -> Result<(), BoxError> { run($route, $case, false).await })*
    };
}
macro_rules! mutants {
    ($($name:ident => $route:expr),* $(,)?) => {
        $(#[tokio::test] async fn $name() -> Result<(), BoxError> { rejects($route).await })*
    };
}
cases! {
    node_access_success => ("node_access", "success"), node_access_foreign => ("node_access", "foreign"), node_access_invalid => ("node_access", "invalid"),
    acl_subjects_success => ("acl_subjects", "success"), acl_subjects_foreign => ("acl_subjects", "foreign"), acl_subjects_invalid => ("acl_subjects", "invalid"),
    acl_subjects_groups => ("acl_subjects", "groups"),
    grant_preview_success => ("grant_preview", "success"), grant_preview_foreign => ("grant_preview", "foreign"), grant_preview_invalid => ("grant_preview", "invalid"),
    grant_preview_advanced_off => ("grant_preview", "advanced_off"),
    grant_success => ("grant", "success"), grant_foreign => ("grant", "foreign"), grant_invalid => ("grant", "invalid"), grant_repeat => ("grant", "repeat"),
    grant_trailer => ("grant", "trailer"), grant_unknown_field => ("grant", "unknown_field"), grant_bad_key => ("grant", "bad_key"), grant_rate_limited => ("grant", "rate_limited"),
    grant_folded_keys => ("grant", "folded_keys"),
    revoke_success => ("revoke", "success"), revoke_foreign => ("revoke", "foreign"), revoke_invalid => ("revoke", "invalid"), revoke_repeat => ("revoke", "repeat"),
    revoke_bad_reason => ("revoke", "bad_reason"), revoke_stale_epoch => ("revoke", "stale_epoch"),
    inheritance_preview_success => ("inheritance_preview", "success"), inheritance_preview_foreign => ("inheritance_preview", "foreign"), inheritance_preview_invalid => ("inheritance_preview", "invalid"),
    inheritance_preview_null_body => ("inheritance_preview", "null_body"),
    inheritance_set_success => ("inheritance_set", "success"), inheritance_set_foreign => ("inheritance_set", "foreign"), inheritance_set_invalid => ("inheritance_set", "invalid"), inheritance_set_repeat => ("inheritance_set", "repeat"),
    quick_views_success => ("quick_views", "success"), quick_views_foreign => ("quick_views", "foreign"), quick_views_invalid => ("quick_views", "invalid"),
    quick_views_bad_max => ("quick_views", "bad_max"), quick_views_shared => ("quick_views", "shared"), quick_views_requests => ("quick_views", "requests"),
    request_preview_success => ("request_preview", "success"), request_preview_foreign => ("request_preview", "foreign"), request_preview_invalid => ("request_preview", "invalid"),
    request_create_success => ("request_create", "success"), request_create_foreign => ("request_create", "foreign"), request_create_invalid => ("request_create", "invalid"), request_create_repeat => ("request_create", "repeat"),
    folder_admins_success => ("folder_admins", "success"), folder_admins_foreign => ("folder_admins", "foreign"), folder_admins_invalid => ("folder_admins", "invalid"),
    folder_admin_put_success => ("folder_admin_put", "success"), folder_admin_put_foreign => ("folder_admin_put", "foreign"), folder_admin_put_invalid => ("folder_admin_put", "invalid"), folder_admin_put_repeat => ("folder_admin_put", "repeat"),
    folder_admin_delete_success => ("folder_admin_delete", "success"), folder_admin_delete_foreign => ("folder_admin_delete", "foreign"), folder_admin_delete_invalid => ("folder_admin_delete", "invalid"), folder_admin_delete_repeat => ("folder_admin_delete", "repeat"),
    lock_put_success => ("lock_put", "success"), lock_put_foreign => ("lock_put", "foreign"), lock_put_invalid => ("lock_put", "invalid"), lock_put_repeat => ("lock_put", "repeat"),
    lock_put_empty_body => ("lock_put", "empty_body"), lock_put_bad_type => ("lock_put", "bad_type"), lock_put_hard => ("lock_put", "hard"), lock_put_unknown_field => ("lock_put", "unknown_field"),
    lock_delete_success => ("lock_delete", "success"), lock_delete_foreign => ("lock_delete", "foreign"), lock_delete_invalid => ("lock_delete", "invalid"), lock_delete_repeat => ("lock_delete", "repeat"),
    lock_delete_break => ("lock_delete", "break"),
    lock_list_success => ("lock_list", "success"), lock_list_foreign => ("lock_list", "foreign"), lock_list_invalid => ("lock_list", "invalid"),
    watch_put_success => ("watch_put", "success"), watch_put_foreign => ("watch_put", "foreign"), watch_put_invalid => ("watch_put", "invalid"), watch_put_repeat => ("watch_put", "repeat"),
    watch_put_bad_op => ("watch_put", "bad_op"), watch_put_empty_body => ("watch_put", "empty_body"), watch_put_empty_ops => ("watch_put", "empty_ops"),
    watch_delete_success => ("watch_delete", "success"), watch_delete_foreign => ("watch_delete", "foreign"), watch_delete_invalid => ("watch_delete", "invalid"), watch_delete_repeat => ("watch_delete", "repeat"),
    asof_success => ("asof", "success"), asof_foreign => ("asof", "foreign"), asof_invalid => ("asof", "invalid"), asof_offset_time => ("asof", "offset_time"),
    watches_success => ("watches", "success"), watches_foreign => ("watches", "foreign"), watches_invalid => ("watches", "invalid"),
    feature_off_node_access => ("node_access", "feature_off"),
}
mutants! {
    node_access_rejects_status => "node_access", acl_subjects_rejects_status => "acl_subjects", grant_preview_rejects_status => "grant_preview",
    grant_rejects_status => "grant", revoke_rejects_status => "revoke", inheritance_preview_rejects_status => "inheritance_preview",
    inheritance_set_rejects_status => "inheritance_set", quick_views_rejects_status => "quick_views", request_preview_rejects_status => "request_preview",
    request_create_rejects_status => "request_create", folder_admins_rejects_status => "folder_admins", folder_admin_put_rejects_status => "folder_admin_put",
    folder_admin_delete_rejects_status => "folder_admin_delete", lock_put_rejects_status => "lock_put", lock_delete_rejects_status => "lock_delete",
    lock_list_rejects_status => "lock_list", watch_put_rejects_status => "watch_put", watch_delete_rejects_status => "watch_delete",
    asof_rejects_status => "asof", watches_rejects_status => "watches",
}

async fn rejects(route: &str) -> Result<(), BoxError> {
    let error = run(route, "success", true)
        .await
        .expect_err("mutant escaped golden")
        .to_string();
    if !error.contains("/response/status:") {
        return Err(error.into());
    }
    let spec = ROUTES.iter().find(|r| r.name == route).unwrap();
    println!(
        "MUTANT-REJECTED: {} {} :: changed-status",
        spec.method, spec.canonical
    );
    Ok(())
}

struct World {
    c: tokio_postgres::Client,
    owner: accounts::Account,
    peer: accounts::Account,
    foreign: accounts::Account,
    extra: Vec<accounts::Account>,
    space: i64,
    root: i64,
    folder: i64,
    file: i64,
    policy: Option<i64>,
}
impl World {
    fn identities(&self) -> Vec<(i64, String)> {
        let mut out = vec![];
        for (label, a) in [
            ("owner", &self.owner),
            ("peer", &self.peer),
            ("foreign", &self.foreign),
        ] {
            out.push((a.user, format!("<{label}-user>")));
            out.push((a.mailbox, format!("<{label}-mailbox>")));
            out.push((a.domain, format!("<{label}-domain>")));
        }
        for (i, a) in self.extra.iter().enumerate() {
            out.push((a.user, format!("<extra{i}-user>")));
            out.push((a.mailbox, format!("<extra{i}-mailbox>")));
        }
        out.extend([
            (self.space, "<space>".into()),
            (self.root, "<root>".into()),
            (self.folder, "<folder>".into()),
            (self.file, "<file>".into()),
        ]);
        out
    }
}

fn acl_route(route: &str) -> bool {
    matches!(
        route,
        "node_access"
            | "grant_preview"
            | "grant"
            | "revoke"
            | "inheritance_preview"
            | "inheritance_set"
            | "quick_views"
            | "request_preview"
            | "request_create"
    )
}

async fn account_in(
    c: &tokio_postgres::Client,
    label: &str,
    domain: i64,
) -> Result<accounts::Account, BoxError> {
    let a = accounts::account(c, label).await?;
    c.execute(
        "UPDATE users SET domain_id=$2 WHERE id=$1",
        &[&a.user, &domain],
    )
    .await?;
    c.execute(
        "UPDATE mailboxes SET domain_id=$2 WHERE id=$1",
        &[&a.mailbox, &domain],
    )
    .await?;
    Ok(a)
}

async fn world(db: &Db, route: &str, case: &str) -> Result<World, BoxError> {
    let c = db.connect().await?;
    // Ids are masked by value, so a user id and a mailbox id must never coincide: other
    // suites advance both sequences in step, hence the mailbox sequence is kept above users.
    c.batch_execute(
        "SELECT setval('users_id_seq',greatest((SELECT last_value FROM users_id_seq),7000000)); \
         SELECT setval('mailboxes_id_seq',greatest((SELECT last_value FROM mailboxes_id_seq),(SELECT last_value FROM users_id_seq)+500000)); \
         SELECT setval('domains_id_seq',greatest((SELECT last_value FROM domains_id_seq),5000000)); \
         SELECT setval('drive_spaces_id_seq',greatest((SELECT last_value FROM drive_spaces_id_seq),8000000)); \
         SELECT setval('drive_nodes_id_seq',greatest((SELECT last_value FROM drive_nodes_id_seq),9000000));",
    )
    .await?;
    let governed =
        matches!(route, "request_preview" | "request_create") || matches!(case, "groups");
    let acl = acl_route(route);
    c.batch_execute(&format!(
        "UPDATE feature_toggles SET enabled={} WHERE key IN('feature.drive_node_acl_reads','feature.drive_node_acl_writes','feature.directory_group_authority'); \
         UPDATE feature_toggles SET enabled={governed} WHERE key='feature.drive_access_governance'; \
         UPDATE feature_toggles SET enabled={} WHERE key='feature.drive'; \
         UPDATE feature_toggles SET enabled=true WHERE key='feature.drive_history'",
        acl || case == "groups",
        case != "feature_off",
    ))
    .await?;
    let owner = accounts::account(&c, "drive4-owner").await?;
    let peer = account_in(&c, "drive4-peer", owner.domain).await?;
    let foreign = accounts::account(&c, "drive4-foreign").await?;
    let mut extra = vec![];
    if matches!(route, "request_preview" | "request_create") {
        extra.push(account_in(&c, "drive4-requester", owner.domain).await?);
        extra.push(account_in(&c, "drive4-approver", owner.domain).await?);
    }
    let space: i64 = c
        .query_one(
            "SELECT drive_space_create($1,'Drive4','regular')",
            &[&owner.user],
        )
        .await?
        .get(0);
    let root: i64 = c
        .query_one(
            "SELECT drive_node_create($1,$2,NULL,'folder','Root')",
            &[&owner.user, &space],
        )
        .await?
        .get(0);
    let folder: i64 = c
        .query_one(
            "SELECT drive_node_create($1,$2,$3,'folder','Restricted')",
            &[&owner.user, &space, &root],
        )
        .await?
        .get(0);
    let file: i64 = c
        .query_one(
            "SELECT drive_node_create($1,$2,$3,'file','Budget.txt')",
            &[&owner.user, &space, &folder],
        )
        .await?
        .get(0);
    if matches!(route, "lock_put" | "lock_delete" | "lock_list") {
        c.query_one("SELECT drive_chunk_register($1,$2,'84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882',10)", &[&owner.user, &space]).await?;
        c.query_one("SELECT drive_file_put_version($1,$2,repeat('a',64),10,'application/octet-stream',NULL,('[{\"sha256\":\"'||'84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882'||'\",\"size\":10}]')::jsonb,'v1','test')::text", &[&owner.user, &file]).await?;
    }
    let mut w = World {
        c,
        owner,
        peer,
        foreign,
        extra,
        space,
        root,
        folder,
        file,
        policy: None,
    };
    seed(&mut w, route, case).await?;
    if acl {
        w.c.execute(
            "UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1",
            &[&w.space],
        )
        .await?;
    }
    Ok(w)
}

async fn epoch(w: &World) -> Result<i64, BoxError> {
    Ok(w.c
        .query_one("SELECT drive_acl_epoch($1)", &[&w.space])
        .await?
        .get(0))
}

async fn seed(w: &mut World, route: &str, case: &str) -> Result<(), BoxError> {
    let (o, p, s, f, fi) = (w.owner.user, w.peer.user, w.space, w.folder, w.file);
    match route {
        "revoke" | "quick_views" => {
            w.c.execute("UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1", &[&s])
                .await?;
            let e = epoch(w).await?;
            w.c.query_one(
                "SELECT drive_acl_grant($1,$2,'user',$3,'viewer',NULL,'subtree',NULL,NULL,NULL,'seed grant',$4,'drive4-seed-grant-0001')",
                &[&o, &f, &p, &e],
            )
            .await?;
        }
        "folder_admin_put" | "folder_admin_delete" => {
            w.c.query_one(
                "SELECT drive_member_grant($1,$2,$3,'editor')",
                &[&o, &s, &p],
            )
            .await?;
            if route == "folder_admin_delete" {
                w.c.query_one("SELECT drive_folder_admin_grant($1,$2,$3)", &[&o, &f, &p])
                    .await?;
            }
        }
        "folder_admins" => {
            w.c.query_one(
                "SELECT drive_member_grant($1,$2,$3,'editor')",
                &[&o, &s, &p],
            )
            .await?;
            w.c.query_one("SELECT drive_folder_admin_grant($1,$2,$3)", &[&o, &f, &p])
                .await?;
        }
        "lock_delete" | "lock_list" => {
            w.c.query_one(
                "SELECT drive_file_lock($1,$2,'soft',NULL,NULL,'drive4-device',60)",
                &[&o, &fi],
            )
            .await?;
        }
        "watch_delete" | "watches" => {
            w.c.query_one("SELECT drive_watch_set($1,$2,NULL)", &[&o, &f])
                .await?;
        }
        "request_preview" | "request_create" => {
            let (requester, approver) = (w.extra[0].user, w.extra[1].user);
            w.c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,1,$1)", &[&o]).await?;
            w.c.query_one(
                "SELECT drive_member_grant($1,$2,$3,'viewer')",
                &[&o, &s, &requester],
            )
            .await?;
            let policy: i64 = w.c.query_one(
                "INSERT INTO approval_policies(consumer_type,name,priority,conditions,requires_approval,approver_spec) VALUES('drive.access','Drive4 governed subtree',10,'{}',true,jsonb_build_object('kind','named','user_id',$1::bigint)) RETURNING id",
                &[&approver],
            )
            .await?
            .get(0);
            w.policy = Some(policy);
            w.c.execute("UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1", &[&s])
                .await?;
            w.c.query_one(
                "SELECT drive_access_request_policy_set($1,NULL,$2,$3,$4,'user',ARRAY['modify_content','rename','preview','download'],'self',120,2,true,true)",
                &[&o, &policy, &s, &f],
            )
            .await?;
        }
        _ => {}
    }
    let _ = case;
    Ok(())
}

struct Req {
    method: &'static str,
    path: String,
    body: String,
    headers: Vec<(&'static str, String)>,
    actor: i64,
}

async fn build(w: &World, spec: &Route, case: &str) -> Result<Req, BoxError> {
    let (o, p, fo) = (w.owner.user, w.peer.user, w.foreign.user);
    let (s, f, fi) = (w.space, w.folder, w.file);
    let e = epoch(w).await?;
    let key = "6a6c6f4d-5d83-4a4c-9f36-2f5a9f3c1d11".to_owned();
    let mut headers = vec![];
    let mut actor = if case == "foreign" { fo } else { o };
    let path = |tail: &str| format!("/api{tail}");
    let (mut p_, mut body) = match spec.name {
        "node_access" => (path(&format!("/drive/nodes/{f}/access")), String::new()),
        "acl_subjects" => (path(&format!("/drive/acl-subjects?node={f}&q=drive4-pe")), String::new()),
        "grant_preview" => (path(&format!("/drive/nodes/{f}/acl/preview")), json!({"subjectKind":"user","subjectId":p.to_string(),"preset":"viewer","scope":"subtree"}).to_string()),
        "grant" => {
            headers.push(("idempotency-key", key.clone()));
            (path(&format!("/drive/nodes/{f}/acl")), json!({"subjectKind":"user","subjectId":p.to_string(),"preset":"viewer","scope":"subtree","reason":"quarterly review","expectedEpoch":e.to_string(),"idempotencyKey":key}).to_string())
        }
        "revoke" => {
            let grant: i64 = w.c.query_one("SELECT id FROM drive_acl_grants WHERE space_id=$1 ORDER BY id LIMIT 1", &[&s]).await?.get(0);
            (path(&format!("/drive/acl-grants/{grant}")), json!({"expectedEpoch":e.to_string(),"reason":"cleanup"}).to_string())
        }
        "inheritance_preview" => (path(&format!("/drive/nodes/{f}/inheritance/preview")), json!({"break":true}).to_string()),
        "inheritance_set" => (path(&format!("/drive/nodes/{f}/inheritance")), json!({"break":true,"expectedEpoch":e.to_string()}).to_string()),
        "quick_views" => {
            if case == "shared" {
                actor = p;
            }
            (path("/drive/quick-views?view=shares"), String::new())
        }
        "request_preview" | "request_create" => {
            let requester = w.extra[0].user;
            actor = if case == "foreign" { fo } else { requester };
            let mut b = json!({"subjectKind":"user","subjectId":requester.to_string(),"capabilities":["modify_content","rename"],"propagation":"self","durationMinutes":60,"maxUses":2,"emergency":false,"reason":"Need to update the quarterly forecast"});
            let tail = if spec.name == "request_preview" { "access-requests/preview" } else {
                b["idempotencyKey"] = json!(key);
                headers.push(("idempotency-key", key.clone()));
                "access-requests"
            };
            (path(&format!("/drive/nodes/{fi}/{tail}")), b.to_string())
        }
        "folder_admins" => (path(&format!("/drive/nodes/{f}/folder-admins")), String::new()),
        "folder_admin_put" | "folder_admin_delete" => (path(&format!("/drive/nodes/{f}/folder-admins/{p}")), String::new()),
        "lock_put" => (path(&format!("/drive/files/{fi}/lock")), json!({"mode":"soft","deviceLabel":"drive4-device","ttlMinutes":60}).to_string()),
        "lock_delete" => (path(&format!("/drive/files/{fi}/lock")), String::new()),
        "lock_list" => (path(&format!("/drive/spaces/{s}/locks")), String::new()),
        "watch_put" => (path(&format!("/drive/nodes/{f}/watch")), json!({"ops":["create","rename"]}).to_string()),
        "watch_delete" => (path(&format!("/drive/nodes/{f}/watch")), String::new()),
        "asof" => (path(&format!("/drive/spaces/{s}/asof?at=AT")).replace("AT", &chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()), String::new()),
        "watches" => (path("/drive/watches"), String::new()),
        _ => return Err("unregistered oracle route".into()),
    };
    let set = |b: &mut String, edit: &dyn Fn(&mut Value)| {
        let mut v: Value = serde_json::from_str(b).unwrap();
        edit(&mut v);
        *b = v.to_string();
    };
    match (spec.name, case) {
        (_, "success" | "foreign" | "repeat" | "feature_off") | ("quick_views", "shared") => {}
        (
            "node_access"
            | "folder_admins"
            | "folder_admin_put"
            | "folder_admin_delete"
            | "lock_list"
            | "lock_put"
            | "lock_delete"
            | "watch_put"
            | "watch_delete"
            | "revoke"
            | "grant"
            | "grant_preview"
            | "inheritance_preview"
            | "inheritance_set"
            | "request_preview"
            | "request_create"
            | "asof",
            "invalid",
        ) => {
            if spec.name == "grant" || spec.name == "inheritance_set" {
                // Missing epoch is the wire-validation failure after a good id.
                set(&mut body, &|v| {
                    v.as_object_mut().unwrap().remove("expectedEpoch");
                });
                if spec.name == "grant" {
                    set(&mut body, &|v| {
                        v["idempotencyKey"] = json!("not-a-uuid");
                    });
                }
            } else if spec.name == "asof" {
                p_ = p_.split("at=").next().unwrap().to_owned() + "at=yesterday";
            } else if matches!(
                spec.name,
                "grant_preview"
                    | "inheritance_preview"
                    | "request_preview"
                    | "request_create"
                    | "revoke"
            ) {
                body = "{".into();
            } else {
                let mut parts: Vec<String> = p_.split('/').map(str::to_owned).collect();
                parts[4] = "bad".into();
                p_ = parts.join("/");
            }
        }
        ("acl_subjects", "invalid") => p_ = p_.replace("q=drive4-pe", "q=a"),
        ("quick_views", "invalid") => p_ = p_.replace("view=shares", "view=bad"),
        ("watches", "invalid") => p_.push_str("?invalid=bad"),
        ("acl_subjects", "groups") => p_ = p_.replace("q=drive4-pe", "q=zz"),
        ("grant_preview", "advanced_off") => set(&mut body, &|v| {
            v["expiresAt"] = json!("2099-01-01T00:00:00Z")
        }),
        ("grant", "trailer") => body.push_str(" {}"),
        ("grant", "unknown_field") => set(&mut body, &|v| v["extra"] = json!(1)),
        ("grant", "bad_key") => headers = vec![("idempotency-key", "other".into())],
        ("grant", "folded_keys") => {
            body = body
                .replace("\"subjectKind\"", "\"SUBJECTKIND\"")
                .replace("\"preset\"", "\"Preset\"")
        }
        ("grant", "rate_limited") => {
            w.c.execute("INSERT INTO rate_limit_counters(key,count,window_start,blocked_until) VALUES($1,99,now(),now()+interval '1 hour')", &[&format!("drive:acl-mutation:{o}")]).await?;
        }
        ("revoke", "bad_reason") => set(&mut body, &|v| v["reason"] = json!(" padded ")),
        ("revoke", "stale_epoch") => set(&mut body, &|v| v["expectedEpoch"] = json!("999")),
        ("inheritance_preview", "null_body") => body = "null".into(),
        ("quick_views", "bad_max") => p_.push_str("&max=500"),
        ("quick_views", "requests") => p_ = p_.replace("view=shares", "view=requests"),
        ("lock_put", "empty_body") => body.clear(),
        ("lock_put", "bad_type") => body = json!({"ttlMinutes":"soon"}).to_string(),
        ("lock_put", "hard") => body = json!({"mode":"hard"}).to_string(),
        ("lock_put", "unknown_field") => {
            body = json!({"mode":"soft","unexpected":true}).to_string()
        }
        ("lock_delete", "break") => p_.push_str("?break=1"),
        ("watch_put", "bad_op") => body = json!({"ops":["nonsense"]}).to_string(),
        ("watch_put", "empty_body") => body.clear(),
        ("watch_put", "empty_ops") => body = json!({"ops":[]}).to_string(),
        ("asof", "offset_time") => {
            p_ = p_.split("at=").next().unwrap().to_owned() + "at=2020-01-01T05:30:00%2B05:30"
        }
        _ => return Err(format!("unregistered case {} {case}", spec.name).into()),
    }
    Ok(Req {
        method: spec.method,
        path: p_,
        body,
        headers,
        actor,
    })
}

fn table_specs(w: &World) -> Vec<(&'static str, String, &'static str)> {
    let space = w.space;
    let users = [w.owner.user, w.peer.user, w.foreign.user]
        .into_iter()
        .chain(w.extra.iter().map(|a| a.user))
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let keys = [w.owner.user, w.peer.user, w.foreign.user]
        .into_iter()
        .chain(w.extra.iter().map(|a| a.user))
        .map(|u| format!("'drive:acl-mutation:{u}'"))
        .collect::<Vec<_>>()
        .join(",");
    vec![
        ("spaces", format!("SELECT to_jsonb(t)::text FROM drive_spaces t WHERE id={space} ORDER BY id"), ""),
        ("nodes", format!("SELECT to_jsonb(t)::text FROM drive_nodes t WHERE space_id={space} ORDER BY id"), ""),
        ("files", format!("SELECT to_jsonb(t)::text FROM drive_files t WHERE space_id={space} ORDER BY node_id"), ""),
        ("members", format!("SELECT to_jsonb(t)::text FROM drive_space_members t WHERE space_id={space} ORDER BY user_id"), ""),
        ("changes", format!("SELECT to_jsonb(t)::text FROM drive_changes t WHERE space_id={space} ORDER BY seq"), ""),
        ("audit", format!("SELECT (to_jsonb(t)-'checksum')::text FROM drive_audit_log t WHERE space_id={space} ORDER BY id"), ""),
        ("grants", format!("SELECT to_jsonb(t)::text FROM drive_acl_grants t WHERE space_id={space} ORDER BY id"), ""),
        ("generations", format!("SELECT to_jsonb(t)::text FROM drive_acl_generations t WHERE space_id={space}"), ""),
        ("breaks", format!("SELECT to_jsonb(t)::text FROM drive_acl_breaks t WHERE space_id={space} ORDER BY node_id"), ""),
        ("invalidations", format!("SELECT to_jsonb(t)::text FROM drive_access_invalidations t WHERE space_id={space} ORDER BY cursor"), ""),
        ("policies", format!("SELECT to_jsonb(t)::text FROM drive_access_request_policies t WHERE space_id={space} ORDER BY id"), ""),
        ("request_details", format!("SELECT to_jsonb(t)::text FROM drive_access_request_details t WHERE space_id={space} ORDER BY request_id"), ""),
        ("approvals", format!("SELECT to_jsonb(t)::text FROM approval_requests t WHERE requester_user_id IN({users}) ORDER BY id"), ""),
        ("locks", format!("SELECT to_jsonb(t)::text FROM drive_file_locks t WHERE space_id={space} ORDER BY node_id"), ""),
        ("folder_admins", format!("SELECT to_jsonb(t)::text FROM drive_folder_admins t WHERE space_id={space} ORDER BY node_id,user_id"), ""),
        ("watches", format!("SELECT to_jsonb(t)::text FROM drive_watches t WHERE node_id IN(SELECT id FROM drive_nodes WHERE space_id={space}) ORDER BY node_id,user_id"), ""),
        ("rate", format!("SELECT to_jsonb(t)::text FROM rate_limit_counters t WHERE key IN({keys}) ORDER BY key"), ""),
    ]
}

async fn snapshot(w: &World) -> Result<Value, BoxError> {
    let invalid: i64 =
        w.c.query_one(
            "SELECT count(*) FROM verify_drive_audit_chain($1) WHERE NOT valid",
            &[&w.space],
        )
        .await?
        .get(0);
    if invalid != 0 {
        return Err("invalid Drive audit chain".into());
    }
    let mut out = serde_json::Map::new();
    for (name, sql, _) in table_specs(w) {
        let rows = w.c.query(sql.as_str(), &[]).await?;
        let rows = rows
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?;
        out.insert(name.into(), Value::Array(rows));
    }
    Ok(Value::Object(out))
}

// ---- canonicalization ------------------------------------------------------

struct Norm {
    identities: Vec<(i64, String)>,
    seen: std::collections::HashMap<(String, String), usize>,
}
impl Norm {
    fn new(w: &World) -> Self {
        Norm {
            identities: w.identities(),
            seen: Default::default(),
        }
    }
    fn identity(&self, n: i64) -> Option<&str> {
        self.identities
            .iter()
            .find(|(v, _)| *v == n)
            .map(|(_, l)| l.as_str())
    }
    fn first_seen(&mut self, key: &str, raw: String) -> String {
        let next = self.seen.iter().filter(|((k, _), _)| k == key).count() + 1;
        let n = *self.seen.entry((key.to_owned(), raw)).or_insert(next);
        format!("<{key}#{n}>")
    }
    fn text(&mut self, key: &str, text: &str) -> String {
        // Throwaway fixture domains carry a random suffix.
        let mut owned = text.to_owned();
        while let Some(at) = owned.find("oracle-") {
            let end = at + "oracle-".len() + 32;
            if owned.len() >= end && owned[at + 7..end].bytes().all(|b| b.is_ascii_hexdigit()) {
                owned.replace_range(at + 7..end, "<domain>");
            } else {
                owned.replace_range(at..at + 7, "oracle_");
            }
        }
        let text = owned.replace("oracle_", "oracle-");
        let text = text.as_str();
        let mut out = String::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if let Some(len) = timestamp_len(&text[i..]) {
                out.push_str("<ts>");
                i += len;
            } else if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            {
                let mut j = i;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                let run = &text[i..j];
                let boundary = j == bytes.len() || !bytes[j].is_ascii_alphanumeric();
                match run
                    .parse::<i64>()
                    .ok()
                    .filter(|_| boundary)
                    .and_then(|n| self.identity(n).map(str::to_owned))
                {
                    Some(label) => out.push_str(&label),
                    None => out.push_str(run),
                }
                i = j;
            } else {
                let ch = text[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        let _ = key;
        out
    }
    fn value(&mut self, parent: &str, key: &str, v: &mut Value) {
        let scope = format!("{parent}.{key}");
        match v {
            Value::Object(map) => {
                map.remove("_checksum");
                for (k, x) in map.iter_mut() {
                    if matches!(k.as_str(), "request_digest" | "scan_token") {
                        *x = json!("<opaque>");
                    } else {
                        self.value(key, k, x);
                    }
                }
            }
            Value::Array(items) => {
                for x in items {
                    self.value(parent, key, x);
                }
            }
            Value::Number(n) => {
                if let Some(n) = n.as_i64() {
                    if let Some(label) = self.identity(n) {
                        *v = json!(label);
                    } else if idish(key) {
                        let label = self.first_seen(&scope, n.to_string());
                        *v = json!(label);
                    }
                }
            }
            Value::String(s) => {
                if key == "text" && matches!(parent, "response" | "first") {
                    // Raw bytes keep their formatting; digits are covered by the parsed body.
                    let t = self.text(key, s);
                    *v = json!(mask_digits(&t));
                } else if key == "instance" {
                    let t = self.text(key, s);
                    *v = json!(mask_digits(&t));
                } else if idish(key)
                    && s.parse::<i64>().is_ok()
                    && self.identity(s.parse().unwrap()).is_none()
                {
                    *v = json!(self.first_seen(&scope, s.clone()));
                } else {
                    *v = json!(self.text(key, s));
                }
            }
            _ => {}
        }
    }
}
fn mask_digits(text: &str) -> String {
    let mut out = String::new();
    let mut prev_digit = false;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            if !prev_digit {
                out.push('#');
            }
            prev_digit = true;
        } else {
            out.push(ch);
            prev_digit = false;
        }
    }
    out
}
fn idish(key: &str) -> bool {
    key == "id"
        || key == "seq"
        || key == "cursor"
        || key.ends_with("_id")
        || key.ends_with("Id")
        || key.ends_with("Cursor")
}
/// Length of an ISO-8601 timestamp at the start of `s` (`2026-11-01T07:34:53.1+00:00`).
fn timestamp_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    if !(digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && (b[10] == b'T' || b[10] == b' ')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19))
    {
        return None;
    }
    let mut i = 19;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < b.len() && b[i] == b'Z' {
        return Some(i + 1);
    }
    if i + 2 < b.len()
        && matches!(b[i], b'+' | b'-')
        && b[i + 1].is_ascii_digit()
        && b[i + 2].is_ascii_digit()
    {
        i += 3;
        if i < b.len() && b[i] == b':' {
            i += 3;
        }
        return Some(i.min(b.len()));
    }
    Some(i)
}

async fn capture(addr: std::net::SocketAddr, req: &Req, token: &str) -> Result<Value, BoxError> {
    let mut b = Request::builder()
        .method(req.method)
        .uri(&req.path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-request-id", "drive4-oracle");
    if !req.body.is_empty() {
        b = b.header("content-type", "application/json");
    }
    for (k, v) in &req.headers {
        b = b.header(*k, v);
    }
    let response = common::send(addr, b.body(common::full(req.body.clone()))?).await;
    let status = response.status().as_u16();
    let headers: Value = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "transfer-encoding" | "connection"
            )
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap())))
        .collect();
    let raw = common::body_bytes(response).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let body = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!(text));
    Ok(json!({"status":status,"headers":headers,"body":body,"text":text}))
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::drive::DriveRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let result = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = result.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}

fn ledger(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}

async fn cleanup(w: &World) -> Result<(), BoxError> {
    let c = &w.c;
    let users: Vec<i64> = [w.owner.user, w.peer.user, w.foreign.user]
        .into_iter()
        .chain(w.extra.iter().map(|a| a.user))
        .collect();
    let space = w.space;
    c.execute("DELETE FROM drive_access_use_leases WHERE grant_id IN(SELECT id FROM drive_acl_grants WHERE space_id=$1)", &[&space]).await?;
    c.execute(
        "DELETE FROM drive_access_request_details WHERE space_id=$1",
        &[&space],
    )
    .await?;
    c.execute("DELETE FROM approval_requests WHERE requester_user_id=ANY($1) AND consumer_type='drive.access'", &[&users]).await?;
    c.execute(
        "DELETE FROM drive_access_request_policies WHERE space_id=$1",
        &[&space],
    )
    .await?;
    if let Some(policy) = w.policy {
        c.execute("DELETE FROM approval_policies WHERE id=$1", &[&policy])
            .await?;
    }
    c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM drive_acl_grants WHERE space_id={space}; DELETE FROM drive_acl_breaks WHERE space_id={space}; \
         DELETE FROM drive_access_invalidations WHERE space_id={space}; DELETE FROM drive_acl_generations WHERE space_id={space}; COMMIT;"
    ))
    .await?;
    c.execute("DELETE FROM drive_nodes WHERE space_id=$1", &[&space])
        .await?;
    c.execute(
        "DELETE FROM drive_upload_authorizations WHERE user_id=$1",
        &[&w.owner.user],
    )
    .await?;
    c.execute(
        "DELETE FROM drive_upload_claims WHERE user_id=$1",
        &[&w.owner.user],
    )
    .await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_chunks WHERE scope_key='s{space}'; DELETE FROM drive_audit_log WHERE space_id={space}; COMMIT;")).await?;
    c.execute(
        "DELETE FROM drive_spaces WHERE owner_user_id=$1",
        &[&w.owner.user],
    )
    .await?;
    c.execute("DELETE FROM rate_limit_counters WHERE key LIKE 'drive:acl-mutation:%' AND key = ANY(SELECT 'drive:acl-mutation:'||u FROM unnest($1::bigint[]) u)", &[&users]).await?;
    let list = users
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_role_assignments WHERE user_id IN({list}); \
         DELETE FROM admin_audit_log WHERE user_id IN({list}); COMMIT;"
    ))
    .await?;
    for a in w.extra.iter().chain([&w.peer, &w.owner, &w.foreign]) {
        accounts::remove(c, a).await?;
    }
    Ok(())
}

async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("drive4-http") else {
        return Ok(());
    };
    let spec = ROUTES
        .iter()
        .find(|r| r.name == route)
        .ok_or("unknown route")?;
    let original = db.connect().await?;
    let toggles = original
        .query("SELECT key,enabled FROM feature_toggles WHERE key IN('feature.drive','feature.drive_history','feature.drive_node_acl_reads','feature.drive_node_acl_writes','feature.directory_group_authority','feature.drive_access_governance')", &[])
        .await?;
    let w = world(&db, route, case).await?;
    let result = std::panic::AssertUnwindSafe(execute(&db, &w, spec, case, mutant))
        .catch_unwind()
        .await;
    let cleaned = cleanup(&w).await;
    for t in toggles {
        original
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[&t.get::<_, String>(0), &t.get::<_, bool>(1)],
            )
            .await?;
    }
    cleaned?;
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}

async fn execute(
    db: &Db,
    w: &World,
    spec: &Route,
    case: &str,
    mutant: bool,
) -> Result<(), BoxError> {
    let req = build(w, spec, case).await?;
    let endpoint = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
    ledger("Plan gofree-drive4 Go oracle container for one recorded case")?;
    let oracle = common::go_oracle::start_named(db, endpoint, None, "gofree-drive4").await?;
    let recording = oracle.is_some();
    let adapter = setjoin_gateway::drive::DriveRoute {
        exec: patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 2)?
            .with_audit_keys("22".repeat(32), String::new()),
        worker: patient_exec(&db.dsn, 2)?
            .with_audit_keys("22".repeat(32), String::new()),
        store: None,
        keys: std::sync::Arc::new(common::recovery_keys()),
        issuer: "mailserver".into(),
    };
    let routes = if recording {
        RouteTable::proxy_all()
    } else if mutant {
        RouteTable::proxy_all().with(ChangedStatus(adapter))
    } else {
        RouteTable::proxy_all().with(adapter)
    };
    let gateway = Gateway::new(
        Config {
            upstream: oracle
                .as_ref()
                .map(|o| format!("http://{}", o.address).parse())
                .transpose()?,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        routes,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(gateway.serve(listener));
    let mut channels = vec![];
    for channel in ["drive", "drive_access", "drive_access_request"] {
        channels.push(db.listen(channel).await?);
    }
    if case == "repeat" {
        // `rate_limit_check('drive:acl-mutation:..',30,1,5)` counts per wall-clock minute: a
        // repeat that straddles a minute boundary on a slow host would restart the count at 1.
        // Start the pair only when at least 20 s of the current minute remain.
        loop {
            let second: f64 = w.c.query_one("SELECT extract(second FROM clock_timestamp())::float8", &[]).await?.get(0);
            if second < 40.0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    let before = snapshot(w).await?;
    let token = fixture::token(req.actor, false);
    let mut response = capture(addr, &req, &token).await?;
    let first = if case == "repeat" {
        let first = response;
        response = capture(addr, &req, &token).await?;
        Some(first)
    } else {
        None
    };
    let effects = snapshot(w).await?;
    let mut notify = vec![];
    for listener in &mut channels {
        for payload in listener.drain(&w.c).await? {
            notify.push(json!({"payload": serde_json::from_str::<Value>(&payload).unwrap_or(json!(payload))}));
        }
    }
    if !recording {
        let metrics = common::send(
            addr,
            Request::builder()
                .uri("/_gateway/metrics")
                .body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if !metrics.contains("setjoin_gateway_proxied_to_go_total 0") {
            return Err("Rust replay proxied to Go".into());
        }
    }
    task.abort();
    let _ = task.await;
    let status = response["status"].as_u64().unwrap() as u16;
    if !mutant && case == "success" && status != spec.ok {
        return Err(format!(
            "{}-{case}: expected status {}, got {status}",
            spec.name, spec.ok
        )
        .into());
    }
    let mut norm = Norm::new(w);
    let mut observation = json!({
        "request":{"method":spec.method,"path":spec.canonical},
        "response":response,"before":before,"effects":effects,"audit":Value::Null,"notify":notify,
    });
    observation["audit"] = observation["effects"]["audit"].clone();
    if let Some(first) = first {
        observation["first"] = first;
    }
    norm.value("", "", &mut observation);
    let name = format!("{}-{case}", spec.name);
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/drive-c/goldens/{name}-v1.json"
    ));
    let rows = file.with_file_name(format!("{name}-v1-row-effects.json"));
    let route = format!("{} {}", spec.method, spec.canonical);
    if recording {
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        if spec.mutator {
            setjoin_conformance::golden::record(
                &rows,
                &json!({"format":1,"route":route,"case":format!("{name}-v1-row-effects"),"go_source":source,"effects":[observation["effects"]]}),
            )?;
        }
        setjoin_conformance::golden::record(
            &file,
            &json!({"format":1,"route":route,"case":format!("{name}-v1"),"go_source":source,"normalization":["typed fixture identities","first-seen generated ids","RFC3339/PostgreSQL timestamps","verified audit chain (checksum removed)"],"observation":observation}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
        setjoin_conformance::golden::compare(&expected["observation"], &observation)?;
        if spec.mutator {
            let row: Value = serde_json::from_slice(&std::fs::read(&rows)?)?;
            setjoin_conformance::golden::compare(&row["effects"][0], &observation["effects"])?;
        }
        println!("GOLDEN-REPLAY: {route} :: {name}-v1");
    }
    Ok(())
}
