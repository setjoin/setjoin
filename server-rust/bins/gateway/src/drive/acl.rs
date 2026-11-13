//! #276 Drive ACL governance, access requests, locks, folder admins, watches and
//! as-of routes. Transport translation only; the reducers own every decision.
use super::*;
use setjoin_drive::part_c as dc;
use setjoin_pg::{CommandOutcome, StatementFailure, Type};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    NodeAccess,
    Subjects,
    GrantPreview,
    Grant,
    Revoke,
    InheritancePreview,
    InheritanceSet,
    QuickViews,
    RequestPreview,
    RequestCreate,
    FolderAdmins,
    FolderAdminGrant,
    FolderAdminRevoke,
    LockPut,
    LockDelete,
    LockList,
    WatchPut,
    WatchDelete,
    AsOf,
    Watches,
}

fn op(r: &Request<Body>) -> Option<Op> {
    let p = r.uri().path();
    let is = |pattern: &str| crate::inventory::path_score(pattern, p).is_some();
    Some(match r.method().as_str() {
        "GET" | "HEAD" => {
            if is("/api/drive/nodes/{id}/access") {
                Op::NodeAccess
            } else if is("/api/drive/acl-subjects") {
                Op::Subjects
            } else if is("/api/drive/quick-views") {
                Op::QuickViews
            } else if is("/api/drive/nodes/{id}/folder-admins") {
                Op::FolderAdmins
            } else if is("/api/drive/spaces/{id}/locks") {
                Op::LockList
            } else if is("/api/drive/spaces/{id}/asof") {
                Op::AsOf
            } else if is("/api/drive/watches") {
                Op::Watches
            } else {
                return None;
            }
        }
        "POST" => {
            if is("/api/drive/nodes/{id}/acl/preview") {
                Op::GrantPreview
            } else if is("/api/drive/nodes/{id}/acl") {
                Op::Grant
            } else if is("/api/drive/nodes/{id}/inheritance/preview") {
                Op::InheritancePreview
            } else if is("/api/drive/nodes/{id}/access-requests/preview") {
                Op::RequestPreview
            } else if is("/api/drive/nodes/{id}/access-requests") {
                Op::RequestCreate
            } else {
                return None;
            }
        }
        "PUT" => {
            if is("/api/drive/nodes/{id}/inheritance") {
                Op::InheritanceSet
            } else if is("/api/drive/nodes/{id}/folder-admins/{userId}") {
                Op::FolderAdminGrant
            } else if is("/api/drive/files/{id}/lock") {
                Op::LockPut
            } else if is("/api/drive/nodes/{id}/watch") {
                Op::WatchPut
            } else {
                return None;
            }
        }
        "DELETE" => {
            if is("/api/drive/acl-grants/{id}") {
                Op::Revoke
            } else if is("/api/drive/nodes/{id}/folder-admins/{userId}") {
                Op::FolderAdminRevoke
            } else if is("/api/drive/files/{id}/lock") {
                Op::LockDelete
            } else if is("/api/drive/nodes/{id}/watch") {
                Op::WatchDelete
            } else {
                return None;
            }
        }
        _ => return None,
    })
}
pub(super) fn matches(r: &Request<Body>) -> bool {
    op(r).is_some()
}

fn segment(r: &Request<Body>, index: usize) -> String {
    go_utf8(&crate::inventory::unescape(
        r.uri().path().split('/').nth(index).unwrap_or(""),
    ))
}

/// Go's `httputil.Problem` field order: type,title,status,detail,instance,code,holderId.
fn ordered(
    status: u16,
    detail: &str,
    path: Option<&str>,
    slug: &str,
    code: &str,
    holder: Option<i64>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut r = problem(status, detail, path, c, id);
    let title = if slug.ends_with("/validation-failed") {
        "Validation Failed"
    } else {
        crate::problem::title(status)
    };
    let kind = if slug.is_empty() {
        "about:blank".to_owned()
    } else if slug.starts_with("https://") {
        slug.to_owned()
    } else {
        format!("https://setjoin.com/problems/drive/{slug}")
    };
    let mut text = format!(
        "{{\"type\":{},\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}",
        go_string(&kind),
        go_string(title),
        go_string(detail),
        go_string(path.unwrap_or(""))
    );
    if !code.is_empty() {
        text += &format!(",\"code\":{}", go_string(code));
    }
    if let Some(holder) = holder {
        text += &format!(",\"holderId\":{holder}");
    }
    text += "}\n";
    *r.body_mut() = http_body_util::Full::new(bytes::Bytes::from(text))
        .map_err(|e| match e {})
        .boxed();
    r
}

/// Everything the response helpers need, so each arm stays short.
struct Ctx<'a> {
    path: &'a str,
    c: &'a RequestContext,
    id: String,
}
impl Ctx<'_> {
    fn problem(&self, status: u16, detail: &str) -> Response<Body> {
        ordered(
            status,
            detail,
            Some(self.path),
            "",
            "",
            None,
            self.c,
            self.id.clone(),
        )
    }
    fn wire(&self) -> Response<Body> {
        self.problem(422, "invalid Drive access input")
    }
    fn json(&self) -> Response<Body> {
        self.problem(400, "invalid JSON")
    }
    fn raw(&self, body: String) -> Response<Body> {
        crate::jmap::reply::response(body, self.c.identity.proto, self.id.clone())
    }
    fn status(&self, status: u16, body: String) -> Response<Body> {
        let mut r = self.raw(body);
        *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
        r
    }
    fn no_content(&self) -> Response<Body> {
        empty(204, self.c, self.id.clone())
    }
    /// `reducererr.WriteProblem` with Drive's options (BZ139..BZ327 slugs, the
    /// ACL codes BZ252/253/254/256 and BZ149's holder), in Go's field order.
    fn failure(&self, e: &StatementFailure) -> Response<Body> {
        let (status, detail, slug) = match e.sqlstate.as_deref() {
            Some("BZ139") => (404, "notFound", "not-found"),
            Some("BZ140") => (403, "forbidden", "forbidden"),
            Some("BZ141") => (422, "unprocessable", "invalid-arguments"),
            Some("BZ142") => (409, "conflict", "no-downgrade"),
            Some("BZ143") => (409, "conflict", "cross-space"),
            Some("BZ144") => (422, "unprocessable", "chunk-not-proven"),
            Some("BZ145") => (409, "conflict", "immutable"),
            Some("BZ146") => (409, "conflict", "invalid-grant"),
            Some("BZ147") => (409, "conflict", "duplicate-name"),
            Some("BZ148") => (413, "overQuota", "quota-exceeded"),
            Some("BZ149") => (423, "conflict", "locked"),
            Some("BZ150") => (409, "conflict", "branch-error"),
            Some("BZ252") => (400, "invalidArguments", ""),
            Some("BZ253") => (403, "forbidden", ""),
            Some("BZ254" | "BZ256") => (409, "conflict", ""),
            _ => (500, "request failed", ""),
        };
        let code = if slug.is_empty() {
            ""
        } else {
            e.sqlstate.as_deref().unwrap_or("")
        };
        let holder = (e.sqlstate.as_deref() == Some("BZ149"))
            .then(|| {
                e.hint
                    .as_deref()
                    .and_then(|h| serde_json::from_str::<Value>(h).ok())
                    .and_then(|v| v["holderId"].as_i64())
                    .filter(|n| *n != 0)
            })
            .flatten();
        ordered(
            status,
            detail,
            Some(self.path),
            slug,
            code,
            holder,
            self.c,
            self.id.clone(),
        )
    }
    fn read(&self, out: Result<Option<String>, StatementFailure>) -> Response<Body> {
        match out {
            Ok(Some(text)) => self.raw(text),
            Ok(None) => self.raw(String::new()),
            Err(e) => self.failure(&e),
        }
    }
    fn outcome(
        &self,
        out: CommandOutcome<Option<String>, StatementFailure>,
        reply: Reply,
    ) -> Response<Body> {
        match out {
            CommandOutcome::Committed(text) => match reply {
                Reply::Raw => self.raw(text.unwrap_or_default()),
                Reply::NoContent => self.no_content(),
            },
            CommandOutcome::Unknown { operation } => unknown(operation, self.c, self.id.clone()),
            CommandOutcome::RolledBack(e) => match e {
                setjoin_pg::Rejection::Statement(f) | setjoin_pg::Rejection::Body(f) => {
                    self.failure(&f)
                }
                _ => self.failure(&StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: String::new(),
                }),
            },
        }
    }
}
#[derive(Clone, Copy)]
enum Reply {
    Raw,
    NoContent,
}

pub(super) async fn handle<K: KeySource + 'static>(
    mut r: Request<Body>,
    c: RequestContext,
    exec: ScopedExecutor,
    keys: Arc<K>,
    issuer: String,
) -> Response<Body> {
    let Some(auth) =
        setjoin_authz::authorize_drive_request(&exec, &keys, &issuer, r.headers(), c.identity.proto,r.uri().path())
            .await
    else {
        return c.upstream.forward(r, &c.identity).await;
    };
    let (Some(random), Some(second)) = (crate::jmap::random(), crate::jmap::random()) else {
        return c.upstream.forward(r, &c.identity).await;
    };
    let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), random);
    let path = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
        .strip_prefix("/api")
        .unwrap_or("")
        .to_owned();
    let ctx = Ctx {
        path: &path,
        c: &c,
        id: id.clone(),
    };
    let flag = |key: &'static str| {
        let exec = exec.clone();
        async move {
            exec.read(
                "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
                &[(&key, Type::TEXT)],
            )
            .await
            .map(|rows| rows[0].get::<_, bool>(0))
        }
    };
    match flag("feature.drive").await {
        Ok(true) => {}
        Ok(false) => return ordered(404, "not found", None, "", "", None, &c, id),
        Err(_) => return c.upstream.forward(r, &c.identity).await,
    }
    let actor = auth.context();
    let Some(op) = op(&r) else {
        return c.upstream.forward(r, &c.identity).await;
    };
    let user = actor.user_id();
    let numeric = |index: usize, detail: &str| -> Result<i64, Response<Body>> {
        segment(&r, index)
            .parse::<i64>()
            .map_err(|_| ctx.problem(400, detail))
    };
    match op {
        Op::NodeAccess => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            ctx.read(
                dc::read_text(
                    &exec,
                    actor,
                    dc::NODE_DETAIL,
                    &[(&user, Type::INT8), (&node, Type::INT8)],
                )
                .await,
            )
        }
        Op::Subjects => {
            let node = decimal(query(&r, "node").as_deref().unwrap_or(""));
            let q = query(&r, "q").unwrap_or_default();
            let q = q.trim();
            let (Some(node), true) = (node, (2..=128).contains(&q.len())) else {
                return ctx.wire();
            };
            let groups = match flag("feature.drive_access_governance").await {
                Ok(v) => v,
                Err(_) => return ctx.problem(500, "request failed"),
            };
            match dc::subjects(&exec, actor, node, q, groups).await {
                Ok(rows) => ctx.status(200, subjects_json(&rows)),
                Err(e) => ctx.failure(&e),
            }
        }
        Op::GrantPreview | Op::Grant => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Ok(body) = strict_fields(&mut r, GRANT_FIELDS).await else {
                return ctx.json();
            };
            let advanced = flag("feature.drive_access_governance")
                .await
                .unwrap_or(false);
            let Some(grant) = Grant::new(&body, advanced) else {
                return ctx.wire();
            };
            if op == Op::GrantPreview {
                return ctx.read(
                    dc::read_text(
                        &exec,
                        actor,
                        dc::GRANT_PREVIEW,
                        &[
                            (&user, Type::INT8),
                            (&node, Type::INT8),
                            (&grant.kind, Type::TEXT),
                            (&grant.subject, Type::INT8),
                            (&grant.preset, Type::TEXT),
                            (&grant.scope, Type::TEXT),
                            (&grant.starts, Type::TEXT),
                            (&grant.expires, Type::TEXT),
                            (&grant.max_uses, Type::INT8),
                            (&grant.reason, Type::TEXT),
                        ],
                    )
                    .await,
                );
            }
            let (Some(epoch), true) = (
                epoch(&body.expected_epoch),
                idempotent(&r, &body.idempotency),
            ) else {
                return ctx.wire();
            };
            if let Some(stop) = throttle(&exec, actor, &ctx, random).await {
                return stop;
            }
            if grant.max_uses.is_some_and(|v| i32::try_from(v).is_err()) {
                return ctx.problem(500, "request failed");
            }
            let digest = format!("grant:{node}:{}", body.idempotency);
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_acl_grant",
                    &digest,
                    dc::GRANT,
                    &[
                        (&node, Type::INT8),
                        (&grant.kind, Type::TEXT),
                        (&grant.subject, Type::INT8),
                        (&grant.preset, Type::TEXT),
                        (&grant.scope, Type::TEXT),
                        (&grant.starts, Type::TEXT),
                        (&grant.expires, Type::TEXT),
                        (&grant.max_uses, Type::INT8),
                        (&grant.reason, Type::TEXT),
                        (&epoch, Type::INT8),
                        (&body.idempotency, Type::TEXT),
                    ],
                    second,
                )
                .await,
                Reply::Raw,
            )
        }
        Op::Revoke => {
            let grant = match numeric(4, "invalid grant id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Ok(body) = strict_fields(&mut r, REVOKE_FIELDS).await else {
                return ctx.json();
            };
            let reason = body.text("reason");
            let (Some(epoch), true) = (
                epoch(&body.expected_epoch),
                (1..=1000).contains(&reason.len()) && reason == reason.trim(),
            ) else {
                return ctx.wire();
            };
            if let Some(stop) = throttle(&exec, actor, &ctx, random).await {
                return stop;
            }
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_acl_revoke",
                    &format!("revoke:{grant}"),
                    dc::REVOKE,
                    &[
                        (&grant, Type::INT8),
                        (&epoch, Type::INT8),
                        (&reason, Type::TEXT),
                    ],
                    second,
                )
                .await,
                Reply::Raw,
            )
        }
        Op::InheritancePreview | Op::InheritanceSet => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Ok(body) = strict_fields(&mut r, INHERITANCE_FIELDS).await else {
                return ctx.json();
            };
            let breaking = body.flag("break");
            if op == Op::InheritancePreview {
                return ctx.read(
                    dc::read_text(
                        &exec,
                        actor,
                        dc::INHERITANCE_PREVIEW,
                        &[
                            (&user, Type::INT8),
                            (&node, Type::INT8),
                            (&breaking, Type::BOOL),
                        ],
                    )
                    .await,
                );
            }
            let Some(epoch) = epoch(&body.expected_epoch) else {
                return ctx.wire();
            };
            if let Some(stop) = throttle(&exec, actor, &ctx, random).await {
                return stop;
            }
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_acl_inheritance_set",
                    &format!("inheritance:{node}:{breaking}"),
                    dc::INHERITANCE_SET,
                    &[
                        (&node, Type::INT8),
                        (&breaking, Type::BOOL),
                        (&epoch, Type::INT8),
                    ],
                    second,
                )
                .await,
                Reply::Raw,
            )
        }
        Op::QuickViews => {
            let view = query(&r, "view").unwrap_or_default();
            let max = match page_size(query(&r, "max"), 100, 200) {
                Ok(v) => v,
                Err(()) => return ctx.problem(422, "invalid max"),
            };
            if !matches!(view.as_str(), "shared" | "shares" | "requests") {
                return ctx.wire();
            }
            ctx.read(
                dc::read_text(
                    &exec,
                    actor,
                    dc::QUICK_VIEW,
                    &[(&user, Type::INT8), (&view, Type::TEXT), (&max, Type::INT8)],
                )
                .await,
            )
        }
        Op::RequestPreview | Op::RequestCreate => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Ok(body) = strict_fields(&mut r, REQUEST_FIELDS).await else {
                return ctx.json();
            };
            let subject = decimal(&body.text("subjectId"));
            let kind = body.text("subjectKind");
            let caps = body.list("capabilities");
            let propagation = body.text("propagation");
            let minutes = body.int("durationMinutes");
            let reason = body.text("reason");
            let (Some(subject), true) = (
                subject,
                matches!(kind.as_str(), "user" | "group")
                    && capabilities_valid(&caps)
                    && matches!(propagation.as_str(), "self" | "children" | "subtree")
                    && (1..=525_600).contains(&minutes)
                    && (8..=1000).contains(&reason.len()),
            ) else {
                return ctx.wire();
            };
            let caps = caps.unwrap_or_default();
            let max_uses = body.optional_int("maxUses");
            let emergency = body.flag("emergency");
            let mfa = body.optional_text("mfaSessionId");
            if op == Op::RequestPreview {
                if [max_uses, Some(minutes)]
                    .iter()
                    .flatten()
                    .any(|v| i32::try_from(*v).is_err())
                {
                    return ctx.problem(500, "request failed");
                }
                return ctx.read(
                    dc::read_text(
                        &exec,
                        actor,
                        dc::REQUEST_PREVIEW,
                        &[
                            (&user, Type::INT8),
                            (&node, Type::INT8),
                            (&kind, Type::TEXT),
                            (&subject, Type::INT8),
                            (&caps, Type::TEXT_ARRAY),
                            (&propagation, Type::TEXT),
                            (&minutes, Type::INT8),
                            (&max_uses, Type::INT8),
                            (&emergency, Type::BOOL),
                            (&mfa, Type::TEXT),
                            (&reason, Type::TEXT),
                        ],
                    )
                    .await,
                );
            }
            let key = body.text("idempotencyKey");
            if !idempotent(&r, &key) {
                return ctx.wire();
            }
            if let Some(stop) = throttle(&exec, actor, &ctx, random).await {
                return stop;
            }
            if [max_uses, Some(minutes)]
                .iter()
                .flatten()
                .any(|v| i32::try_from(*v).is_err())
            {
                return ctx.problem(500, "request failed");
            }
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_access_request",
                    &format!("request:{node}:{key}"),
                    dc::REQUEST_CREATE,
                    &[
                        (&node, Type::INT8),
                        (&kind, Type::TEXT),
                        (&subject, Type::INT8),
                        (&caps, Type::TEXT_ARRAY),
                        (&propagation, Type::TEXT),
                        (&minutes, Type::INT8),
                        (&max_uses, Type::INT8),
                        (&emergency, Type::BOOL),
                        (&mfa, Type::TEXT),
                        (&reason, Type::TEXT),
                        (&key, Type::TEXT),
                    ],
                    second,
                )
                .await,
                Reply::Raw,
            )
        }
        Op::FolderAdmins => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            match dc::folder_admins(&exec, actor, node).await {
                Ok(Some(rows)) => ctx.status(200, folder_admins_json(&rows)),
                Ok(None) => ctx.problem(404, "node not found"),
                Err(e) => ctx.failure(&e),
            }
        }
        Op::FolderAdminGrant | Op::FolderAdminRevoke => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let grantee = match numeric(6, "invalid user id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let (name, sql) = if op == Op::FolderAdminGrant {
                ("drive_folder_admin_grant", dc::FOLDER_ADMIN_GRANT)
            } else {
                ("drive_folder_admin_revoke", dc::FOLDER_ADMIN_REVOKE)
            };
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    name,
                    &format!("{name}:{node}:{grantee}"),
                    sql,
                    &[(&node, Type::INT8), (&grantee, Type::INT8)],
                    random,
                )
                .await,
                Reply::NoContent,
            )
        }
        Op::LockPut => {
            let node = match numeric(4, "invalid file id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Ok(body) = optional_fields(&mut r).await else {
                return ctx.json();
            };
            let mode = body.optional_text("mode").unwrap_or_else(|| "soft".into());
            let ttl = body.optional_int("ttlMinutes").unwrap_or(480);
            if i32::try_from(ttl).is_err() {
                return ctx.problem(500, "request failed");
            }
            let (branch, version, device) = (
                body.optional_int("branchId"),
                body.optional_int("versionId"),
                body.optional_text("deviceLabel"),
            );
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_file_lock",
                    &format!("lock:{node}:{mode}"),
                    dc::LOCK_PUT,
                    &[
                        (&node, Type::INT8),
                        (&mode, Type::TEXT),
                        (&branch, Type::INT8),
                        (&version, Type::INT8),
                        (&device, Type::TEXT),
                        (&ttl, Type::INT8),
                    ],
                    random,
                )
                .await,
                Reply::Raw,
            )
        }
        Op::LockDelete => {
            let node = match numeric(4, "invalid file id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let breaking = query(&r, "break").as_deref() == Some("1");
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_file_unlock",
                    &format!("unlock:{node}:{breaking}"),
                    dc::LOCK_DELETE,
                    &[(&node, Type::INT8), (&breaking, Type::BOOL)],
                    random,
                )
                .await,
                Reply::NoContent,
            )
        }
        Op::LockList => {
            let space = match numeric(4, "invalid space id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            ctx.read(
                dc::read_text(
                    &exec,
                    actor,
                    dc::LOCK_LIST,
                    &[(&user, Type::INT8), (&space, Type::INT8)],
                )
                .await,
            )
        }
        Op::WatchPut => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Ok(body) = optional_fields(&mut r).await else {
                return ctx.json();
            };
            let ops = body.list("ops");
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_watch_set",
                    &format!("watch:{node}:{ops:?}"),
                    dc::WATCH_PUT,
                    &[(&node, Type::INT8), (&ops, Type::TEXT_ARRAY)],
                    random,
                )
                .await,
                Reply::NoContent,
            )
        }
        Op::WatchDelete => {
            let node = match numeric(4, "invalid node id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            ctx.outcome(
                dc::write_text(
                    &exec,
                    actor,
                    "drive_watch_remove",
                    &format!("unwatch:{node}"),
                    dc::WATCH_DELETE,
                    &[(&node, Type::INT8)],
                    random,
                )
                .await,
                Reply::NoContent,
            )
        }
        Op::AsOf => {
            let space = match numeric(4, "invalid space id") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Some(at) = query(&r, "at").and_then(|v| rfc3339(&v)) else {
                return ordered(
                    422,
                    "at must be an RFC3339 timestamp",
                    Some(&path),
                    "https://setjoin.com/errors/validation-failed",
                    "",
                    None,
                    &c,
                    id.clone(),
                );
            };
            match dc::read_text(
                &exec,
                actor,
                dc::AS_OF,
                &[(&user, Type::INT8), (&space, Type::INT8), (&at, Type::TEXT)],
            )
            .await
            {
                Ok(items) => ctx.status(
                    200,
                    format!("{{\"items\":{}}}\n", go_compact(&items.unwrap_or_default())),
                ),
                Err(e) => ctx.failure(&e),
            }
        }
        Op::Watches => match dc::watches(&exec, actor).await {
            Ok(rows) => ctx.status(200, watches_json(&rows)),
            Err(e) => ctx.failure(&e),
        },
    }
}

/// Go's per-user mutation budget; `None` means continue.
async fn throttle(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    ctx: &Ctx<'_>,
    operation: [u8; 16],
) -> Option<Response<Body>> {
    match dc::acl_rate(exec, actor, operation).await {
        CommandOutcome::Committed(Some(v)) if v == "true" => None,
        CommandOutcome::Committed(_) => {
            let mut r = ctx.problem(429, "too many permission changes; retry later");
            r.headers_mut().insert("retry-after", "60".parse().unwrap());
            Some(r)
        }
        other => Some(ctx.outcome(other, Reply::Raw)),
    }
}

// ---- Go-compatible request decoding -------------------------------------

type Field = (&'static str, bool);
const GRANT_FIELDS: &[Field] = &[
    ("subjectKind", false),
    ("subjectId", false),
    ("preset", false),
    ("scope", false),
    ("startsAt", false),
    ("expiresAt", false),
    ("maxUses", false),
    ("reason", false),
    ("expectedEpoch", false),
    ("idempotencyKey", false),
];
const REVOKE_FIELDS: &[Field] = &[("expectedEpoch", false), ("reason", false)];
const INHERITANCE_FIELDS: &[Field] = &[("break", false), ("expectedEpoch", false)];
const REQUEST_FIELDS: &[Field] = &[
    ("subjectKind", false),
    ("subjectId", false),
    ("capabilities", false),
    ("propagation", false),
    ("durationMinutes", false),
    ("maxUses", false),
    ("emergency", false),
    ("mfaSessionId", false),
    ("reason", false),
    ("idempotencyKey", false),
];

/// Decoded top-level object: every key folded onto the Go field it names.
struct Doc {
    fields: Vec<(String, String)>,
    expected_epoch: String,
    idempotency: String,
}
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ſ' => 'S',
            '\u{212a}' => 'K',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}
impl Doc {
    fn new(fields: Vec<(String, String)>) -> Self {
        let mut body = Doc {
            fields,
            expected_epoch: String::new(),
            idempotency: String::new(),
        };
        body.expected_epoch = body.text("expectedEpoch");
        body.idempotency = body.text("idempotencyKey");
        body
    }
    fn raws(&self, name: &str) -> impl Iterator<Item = &str> {
        let wanted = fold(name);
        self.fields
            .iter()
            .filter(move |(k, _)| fold(k) == wanted)
            .map(|(_, v)| v.as_str())
    }
    /// A `string` field: null leaves the earlier value, the last value wins.
    fn text(&self, name: &str) -> String {
        let mut out = String::new();
        for raw in self.raws(name) {
            if raw != "null" {
                out = serde_json::from_str(raw).unwrap_or_default();
            }
        }
        out
    }
    fn optional_text(&self, name: &str) -> Option<String> {
        let mut out = None;
        for raw in self.raws(name) {
            out = if raw == "null" {
                None
            } else {
                serde_json::from_str(raw).ok()
            };
        }
        out
    }
    fn int(&self, name: &str) -> i64 {
        let mut out = 0;
        for raw in self.raws(name) {
            if raw != "null" {
                out = raw.parse().unwrap_or(0);
            }
        }
        out
    }
    fn optional_int(&self, name: &str) -> Option<i64> {
        let mut out = None;
        for raw in self.raws(name) {
            out = if raw == "null" {
                None
            } else {
                raw.parse().ok()
            };
        }
        out
    }
    fn flag(&self, name: &str) -> bool {
        let mut out = false;
        for raw in self.raws(name) {
            if raw != "null" {
                out = raw == "true";
            }
        }
        out
    }
    /// A `[]string` field: null yields nil, an array (even empty) is `Some`.
    fn list(&self, name: &str) -> Option<Vec<String>> {
        let mut out = None;
        for raw in self.raws(name) {
            out = if raw == "null" {
                None
            } else {
                serde_json::from_str::<Vec<Option<String>>>(raw)
                    .ok()
                    .map(|v| v.into_iter().map(Option::unwrap_or_default).collect())
            };
        }
        out
    }
}

/// Validate one raw field value against the Go type it decodes into.
fn typed(kind: &str, raw: &str) -> bool {
    if raw == "null" {
        return true;
    }
    match kind {
        "string" => serde_json::from_str::<String>(raw).is_ok(),
        "int" => raw.parse::<i64>().is_ok(),
        "bool" => matches!(raw, "true" | "false"),
        "list" => serde_json::from_str::<Vec<Option<String>>>(raw).is_ok(),
        _ => true,
    }
}
fn kind_of(name: &str) -> &'static str {
    match name {
        "maxUses" | "durationMinutes" | "branchId" | "versionId" | "ttlMinutes" => "int",
        "break" | "emergency" => "bool",
        "capabilities" | "ops" => "list",
        _ => "string",
    }
}

async fn read_prefix(r: &mut Request<Body>, limit: usize) -> Result<(Vec<u8>, bool), ()> {
    let mut bytes = Vec::new();
    let mut over = false;
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Some(data) = frame.data_ref() {
            let take = data.len().min(limit - bytes.len());
            over |= take < data.len();
            bytes.extend_from_slice(&data[..take]);
            if over {
                break;
            }
        }
    }
    Ok((bytes, over))
}

fn fields_of(text: &str) -> Result<Vec<(String, String)>, ()> {
    use serde::Deserialize;
    let mut decoder = serde_json::Deserializer::from_str(text);
    let Fields(fields) = Fields::deserialize(&mut decoder).map_err(|_| ())?;
    Ok(fields
        .into_iter()
        .map(|(k, v)| (k, v.get().to_owned()))
        .collect())
}

/// `decodeACLJSON`: one value, no unknown fields, then EOF (16 KiB cap).
async fn strict_fields(r: &mut Request<Body>, known: &[Field]) -> Result<Doc, ()> {
    let (bytes, over) = read_prefix(r, 16 << 10).await?;
    if over {
        return Err(());
    }
    let text = go_json_text(&bytes);
    let mut decoder = serde_json::Deserializer::from_str(&text);
    use serde::Deserialize;
    let Fields(fields) = Fields::deserialize(&mut decoder).map_err(|_| ())?;
    decoder.end().map_err(|_| ())?;
    let fields: Vec<(String, String)> = fields
        .into_iter()
        .map(|(k, v)| (k, v.get().to_owned()))
        .collect();
    for (key, raw) in &fields {
        let Some((name, _)) = known.iter().find(|(n, _)| fold(n) == fold(key)) else {
            return Err(());
        };
        if !typed(kind_of(name), raw) {
            return Err(());
        }
    }
    Ok(Doc::new(fields))
}

/// `decodeOptionalJSON`: empty is fine; the first complete value wins; unknown
/// fields are ignored but known ones must have the right type.
async fn optional_fields(r: &mut Request<Body>) -> Result<Doc, ()> {
    let (bytes, _) = read_prefix(r, 16 << 10).await?;
    let text = go_json_text(&bytes);
    if text
        .bytes()
        .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Ok(Doc::new(Vec::new()));
    }
    let fields = fields_of(&text)?;
    let known = [
        "mode",
        "branchId",
        "versionId",
        "deviceLabel",
        "ttlMinutes",
        "ops",
    ];
    for (key, raw) in &fields {
        if let Some(name) = known.iter().find(|n| fold(n) == fold(key)) {
            if !typed(kind_of(name), raw) {
                return Err(());
            }
        }
    }
    Ok(Doc::new(fields))
}

struct Grant {
    kind: String,
    subject: i64,
    preset: String,
    scope: String,
    starts: Option<String>,
    expires: Option<String>,
    max_uses: Option<i64>,
    reason: Option<String>,
}
impl Grant {
    /// `validateGrantWire`.
    fn new(body: &Doc, advanced: bool) -> Option<Self> {
        let subject = decimal(&body.text("subjectId"))?;
        let preset = body.text("preset");
        let scope = body.text("scope");
        if !matches!(
            preset.as_str(),
            "viewer" | "contributor" | "editor" | "folder_manager"
        ) || !matches!(scope.as_str(), "self" | "subtree")
        {
            return None;
        }
        let kind = body.text("subjectKind");
        if kind != "user" && !(advanced && kind == "group") {
            return None;
        }
        let when = |name: &str| -> Result<Option<String>, ()> {
            body.optional_text(name)
                .map(|v| rfc3339(&v).ok_or(()))
                .transpose()
        };
        let starts = when("startsAt").ok()?;
        let expires = when("expiresAt").ok()?;
        let max_uses = body.optional_int("maxUses");
        if !advanced && (starts.is_some() || expires.is_some() || max_uses.is_some()) {
            return None;
        }
        Some(Grant {
            kind,
            subject,
            preset,
            scope,
            starts,
            expires,
            max_uses,
            reason: body.optional_text("reason"),
        })
    }
}

fn decimal(raw: &str) -> Option<i64> {
    if raw.is_empty() || raw != raw.trim() {
        return None;
    }
    raw.parse::<i64>().ok().filter(|v| *v > 0)
}
fn epoch(raw: &str) -> Option<i64> {
    if raw.is_empty() || raw != raw.trim() {
        return None;
    }
    raw.parse::<i64>().ok().filter(|v| *v >= 0)
}
fn idempotent(r: &Request<Body>, body: &str) -> bool {
    let values: Vec<_> = r.headers().get_all("idempotency-key").iter().collect();
    if values.len() != 1
        || values[0].as_bytes().is_empty()
        || values[0].as_bytes() != body.as_bytes()
        || body.len() != 36
    {
        return false;
    }
    body.bytes().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}
fn capabilities_valid(caps: &Option<Vec<String>>) -> bool {
    let Some(caps) = caps else { return false };
    if caps.is_empty() || caps.len() > 15 {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    caps.iter()
        .all(|c| !c.is_empty() && c.len() <= 64 && seen.insert(c.as_str()))
}
/// `parseBoundedPageSize`.
fn page_size(raw: Option<String>, fallback: i64, maximum: i64) -> Result<i64, ()> {
    let raw = raw.unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(fallback);
    }
    match raw.parse::<i64>() {
        Ok(v) if (1..=maximum).contains(&v) => Ok(v),
        _ => Err(()),
    }
}
/// Strict Go `time.Parse(time.RFC3339, …)`, normalized to a UTC instant.
fn rfc3339(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    if b.len() < 20 || b[10] != b'T' || !raw.is_ascii() {
        return None;
    }
    let zone_ok = raw.ends_with('Z') || {
        let z = &b[b.len() - 6..];
        matches!(z[0], b'+' | b'-') && z[3] == b':'
    };
    if !zone_ok || raw.ends_with('z') {
        return None;
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    Some(
        parsed
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    )
}

// ---- Go-compatible response encoding ------------------------------------

fn go_string(value: &str) -> String {
    let encoded = serde_json::to_string(value).unwrap();
    go_escape(&encoded)
}
fn go_escape(text: &str) -> String {
    text.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
/// `json.Marshal` of a `json.RawMessage`: whitespace outside strings removed.
fn go_compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !matches!(c, ' ' | '\t' | '\r' | '\n') {
            out.push(c);
        }
    }
    go_escape(&out)
}
fn subjects_json(rows: &[[String; 4]]) -> String {
    let items: Vec<String> = rows
        .iter()
        .map(|[kind, id, label, secondary]| {
            let mut item = format!(
                "{{\"kind\":{},\"id\":{},\"label\":{}",
                go_string(kind),
                go_string(id),
                go_string(label)
            );
            if !secondary.is_empty() {
                item += &format!(",\"secondary\":{}", go_string(secondary));
            }
            item + "}"
        })
        .collect();
    format!("[{}]\n", items.join(","))
}
fn folder_admins_json(rows: &[(i64, String, i64, String)]) -> String {
    let items: Vec<String> = rows
        .iter()
        .map(|(user, name, by, at)| {
            format!(
                "{{\"userId\":{user},\"displayName\":{},\"grantedBy\":{by},\"grantedAt\":{}}}",
                go_string(name),
                go_string(at)
            )
        })
        .collect();
    format!("[{}]\n", items.join(","))
}
fn watches_json(rows: &[(i64, String, String, Option<Vec<String>>)]) -> String {
    let items: Vec<String> = rows
        .iter()
        .map(|(node, name, kind, ops)| {
            let ops = match ops {
                None => "null".to_owned(),
                Some(v) => format!(
                    "[{}]",
                    v.iter().map(|s| go_string(s)).collect::<Vec<_>>().join(",")
                ),
            };
            format!(
                "{{\"nodeId\":{node},\"nodeName\":{},\"kind\":{},\"ops\":{ops}}}",
                go_string(name),
                go_string(kind)
            )
        })
        .collect();
    format!("[{}]\n", items.join(","))
}
