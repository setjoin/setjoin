//! #275 Drive sub-router B. Transport translation; reducers own decisions.
use super::*;
use setjoin_pg::StatementFailure;
pub(super) fn matches(r: &Request<Body>) -> bool {
    super::content::matches(r)
        || simple_match(r)
        || (r.method() == hyper::Method::POST
            && crate::inventory::path_score("/api/drive/files/{id}/branches", r.uri().path())
                .is_some())
        || matches!(r.method().as_str(), "GET" | "HEAD")
            && ["/api/drive/spaces/{id}/activity", "/api/drive/search"]
                .iter()
                .any(|p| crate::inventory::path_score(p, r.uri().path()).is_some())
}
pub(super) async fn handle<K: KeySource + 'static>(
    mut r: Request<Body>,
    c: RequestContext,
    exec: ScopedExecutor,
    worker: ScopedExecutor,
    keys: Arc<K>,
    issuer: String,
    store: Option<Arc<crate::recovery_worker::S3Store>>,
) -> Response<Body> {
    let Some(auth) =
        setjoin_authz::authorize_drive_request(&exec, &keys, &issuer, r.headers(), c.identity.proto,r.uri().path())
            .await
    else {
        return c.upstream.forward(r, &c.identity).await;
    };
    let Some(random) = crate::jmap::random() else {
        return c.upstream.forward(r, &c.identity).await;
    };
    let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), random);
    let path = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
        .strip_prefix("/api")
        .unwrap_or("")
        .to_owned();
    match exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false)",&[]).await {
        Ok(rows) if rows[0].get::<_,bool>(0)=>{},Ok(_)=>return problem(404,"not found",None,&c,id),Err(_)=>return c.upstream.forward(r,&c.identity).await
    }
    if super::content::matches(&r) {
        return super::content::serve(r, &path, exec, auth.context().clone(), store, random, c, id)
            .await;
    }
    if simple_match(&r) {
        return simple(
            r,
            &path,
            &exec,
            &worker,
            store,
            auth.context(),
            random,
            &c,
            id,
        )
        .await;
    }
    if r.method() == hyper::Method::POST {
        let node = match path_value(&r, 4).parse::<i64>() {
            Ok(v) => v,
            Err(_) => return problem(400, "invalid file id", Some(&path), &c, id),
        };
        let body = match structured_body(
            &mut r,
            &[("name", false), ("fromVersionId", true)],
            16 << 10,
            false,
        )
        .await
        {
            Ok(v) => v,
            Err(_) => return problem(400, "invalid JSON", Some(&path), &c, id),
        };
        return command_response(
            setjoin_drive::part_b::create_branch(&exec, auth.context(), node, &body, random).await,
            201,
            &path,
            &c,
            id,
        );
    }
    if path == "/drive/search" {
        return search(&r, &path, &exec, auth.context(), &c, id).await;
    }
    let value = path_value(&r, 4);
    let Ok(space) = value.parse::<i64>() else {
        return problem(400, "invalid space id", Some(&path), &c, id);
    };
    let optional = |key: &str| -> Result<Option<i64>, Response<Body>> {
        match query(&r, key).filter(|s| !s.is_empty()) {
            Some(s) => s
                .parse()
                .map(Some)
                .map_err(|_| problem(400, &format!("invalid {key}"), Some(&path), &c, id.clone())),
            None => Ok(None),
        }
    };
    let node = match optional("node") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let before = match optional("beforeId") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let max = match optional("max") {
        Ok(v) => v,
        Err(r) => return r,
    };
    match setjoin_drive::part_b::activity(&exec, auth.context(), space, node, max, before).await {
        Ok(v) => crate::jmap::reply::response(v.to_string(), c.identity.proto, id),
        Err(e) => reducer_problem(&e, &path, &c, id),
    }
}
pub(super) fn reducer_problem(
    e: &StatementFailure,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    if e.sqlstate.as_deref() == Some("D403") {
        let mut r = problem(403, &e.message, Some(path), c, id);
        let text = crate::problem::Problem::new(403, &e.message)
            .kind("https://setjoin.com/errors/forbidden")
            .instance(path)
            .body();
        crate::problem::set_body(&mut r, text);
        return r;
    }
    if e.sqlstate.as_deref() == Some("D404") {
        return problem(404, "file not found", Some(path), c, id);
    }
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
        Some("BZ260") => (409, "conflict", "name-unavailable"),
        Some("BZ321") => (404, "notFound", "office-not-found"),
        Some("BZ322") => (400, "invalidArguments", "office-invalid-arguments"),
        Some("BZ323") => (403, "forbidden", "office-forbidden"),
        Some("BZ324") => (409, "stateMismatch", "office-session-stale"),
        Some("BZ325") => (409, "conflict", "office-lock-conflict"),
        Some("BZ326") => (409, "stateMismatch", "office-replay-conflict"),
        Some("BZ327") => (409, "conflict", "office-provider-unavailable"),
        Some("BZ215") => (403, "forbidden", ""),
        _ => (500, "request failed", ""),
    };
    let mut r = problem(status, detail, Some(path), c, id);
    if !slug.is_empty() {
        let kind = format!("https://setjoin.com/problems/drive/{slug}");
        let mut p = crate::problem::Problem::new(status, detail)
            .kind(&kind)
            .instance(path)
            .code(e.sqlstate.as_deref().unwrap());
        if e.sqlstate.as_deref() == Some("BZ149") {
            if let Some(holder) = e
                .hint
                .as_deref()
                .and_then(|h| serde_json::from_str::<Value>(h).ok())
                .and_then(|v| v["holderId"].as_i64())
            {
                p = p.holder_id(holder);
            }
        }
        crate::problem::set_body(&mut r, p.body());
    }
    r
}

async fn search(
    r: &Request<Body>,
    path: &str,
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let optional = |key: &str| -> Result<Option<i64>, Response<Body>> {
        match query(r, key).filter(|s| !s.is_empty()) {
            Some(s) => s
                .parse()
                .map(Some)
                .map_err(|_| problem(400, &format!("invalid {key}"), Some(path), c, id.clone())),
            None => Ok(None),
        }
    };
    let space = match optional("space") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let max = match optional("max") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let q = query(r, "q").unwrap_or_default();
    match setjoin_drive::part_b::search(exec, actor, space, &q, max).await {
        Ok(v) => crate::jmap::reply::response(
            json!({"items":v}).to_string() + "\n",
            c.identity.proto,
            id,
        ),
        Err(e) => reducer_problem(&e, path, c, id),
    }
}

async fn structured_body(
    r: &mut Request<Body>,
    fields: &[(&str, bool)],
    limit: usize,
    allow_empty: bool,
) -> Result<Value, ()> {
    let mut bytes = Vec::new();
    let mut eof = false;
    let mut overflow = false;
    while bytes.len() < limit {
        let Some(frame) = r.body_mut().frame().await else {
            eof = true;
            break;
        };
        let frame = frame.map_err(|_| ())?;
        if let Some(data) = frame.data_ref() {
            let take = data.len().min(limit - bytes.len());
            overflow |= take < data.len();
            bytes.extend_from_slice(&data[..take]);
            if let Ok(value) = structured_decode(&bytes, fields) {
                return Ok(value);
            }
        }
    }
    if allow_empty
        && bytes
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        if overflow {
            return Err(());
        }
        if !eof {
            while let Some(frame) = r.body_mut().frame().await {
                let frame = frame.map_err(|_| ())?;
                if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                    return Err(());
                }
            }
        }
        Ok(json!({}))
    } else {
        structured_decode(&bytes, fields)
    }
}
pub(super) fn command_response(
    out: setjoin_pg::CommandOutcome<Value, StatementFailure>,
    status: u16,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    match out {
        setjoin_pg::CommandOutcome::Committed(v) => {
            if status == 204 {
                return empty(204, c, id);
            }
            let mut r = crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id);
            *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
            r
        }
        setjoin_pg::CommandOutcome::Unknown { operation } => unknown(operation, c, id),
        setjoin_pg::CommandOutcome::RolledBack(e) => {
            let f = match e {
                setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => e,
                _ => StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: String::new(),
                },
            };
            reducer_problem(&f, path, c, id)
        }
    }
}

struct Simple {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    detail: &'static str,
    fields: &'static [(&'static str, bool)],
    status: u16,
}
const SIMPLE: &[Simple] = &[
    Simple {
        name: "list_versions",
        method: "GET",
        path: "/api/drive/files/{id}/versions",
        detail: "invalid node id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "list_branches",
        method: "GET",
        path: "/api/drive/files/{id}/branches",
        detail: "invalid file id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "set_label",
        method: "POST",
        path: "/api/drive/versions/{id}/labels",
        detail: "invalid version id",
        fields: &[("label", false)],
        status: 204,
    },
    Simple {
        name: "remove_label",
        method: "DELETE",
        path: "/api/drive/versions/{id}/labels/{label}",
        detail: "invalid version id",
        fields: &[],
        status: 204,
    },
    Simple {
        name: "resolve_branch",
        method: "POST",
        path: "/api/drive/branches/{id}/resolve",
        detail: "invalid branch id",
        fields: &[("verb", false), ("newName", false)],
        status: 200,
    },
    Simple {
        name: "audit_actions",
        method: "GET",
        path: "/api/drive/audit-actions",
        detail: "",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "create_alarm",
        method: "POST",
        path: "/api/drive/audit-alarms",
        detail: "",
        fields: &[
            ("spaceId", true),
            ("actionPattern", false),
            ("threshold", true),
            ("windowMinutes", true),
        ],
        status: 201,
    },
    Simple {
        name: "delete_alarm",
        method: "DELETE",
        path: "/api/drive/audit-alarms/{id}",
        detail: "invalid alarm id",
        fields: &[],
        status: 204,
    },
    Simple {
        name: "patch_branch",
        method: "PATCH",
        path: "/api/drive/branches/{id}",
        detail: "invalid branch id",
        fields: &[("name", false)],
        status: 204,
    },
    Simple {
        name: "update_alarm",
        method: "PATCH",
        path: "/api/drive/audit-alarms/{id}",
        detail: "invalid alarm id",
        fields: &[("threshold", true)],
        status: 204,
    },
    Simple {
        name: "list_alarms",
        method: "GET",
        path: "/api/drive/audit-alarms",
        detail: "",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "verify_audit",
        method: "GET",
        path: "/api/drive/spaces/{id}/audit/verify",
        detail: "invalid space id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "trash",
        method: "GET",
        path: "/api/drive/spaces/{id}/trash",
        detail: "invalid space id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "purge_restore",
        method: "POST",
        path: "/api/drive/nodes/{id}/purge-restore",
        detail: "invalid node id",
        fields: &[],
        status: 204,
    },
    Simple {
        name: "office_choices",
        method: "GET",
        path: "/api/drive/files/{id}/office/choices",
        detail: "invalid file id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "office_local_open",
        method: "POST",
        path: "/api/drive/files/{id}/office/local-open",
        detail: "invalid file id",
        fields: &[("appId", false), ("deviceId", false)],
        status: 200,
    },
    Simple {
        name: "office_revoke",
        method: "DELETE",
        path: "/api/drive/files/{id}/office/launches/{launchId}",
        detail: "invalid file id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "history",
        method: "GET",
        path: "/api/drive/files/{id}/history",
        detail: "invalid file id",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "audit",
        method: "GET",
        path: "/api/drive/audit",
        detail: "",
        fields: &[],
        status: 200,
    },
    Simple {
        name: "put_version",
        method: "POST",
        path: "/api/drive/files/{id}/versions",
        detail: "invalid node id",
        fields: &[
            ("contentSha256", false),
            ("size", true),
            ("contentType", false),
            ("baseVersionId", true),
            ("manifest", false),
            ("note", false),
            ("deviceLabel", false),
            ("branchId", true),
        ],
        status: 201,
    },
    Simple {
        name: "restore_version",
        method: "POST",
        path: "/api/drive/files/{id}/versions/{versionId}/restore",
        detail: "invalid node id",
        fields: &[
            ("baseVersionId", true),
            ("note", false),
            ("deviceLabel", false),
            ("branchId", true),
        ],
        status: 201,
    },
    Simple {
        name: "office_launch",
        method: "POST",
        path: "/api/drive/files/{id}/office/launches",
        detail: "invalid file id",
        fields: &[
            ("baseVersionId", true),
            ("providerId", false),
            ("deviceId", false),
            ("cohortKey", false),
        ],
        status: 201,
    },
    Simple {
        name: "request_export",
        method: "POST",
        path: "/api/drive/export",
        detail: "",
        fields: &[("versionId", true), ("action", false), ("ttlMinutes", true)],
        status: 200,
    },
    // SIMPLE ROUTES
];
fn simple_spec(r: &Request<Body>) -> Option<&'static Simple> {
    SIMPLE.iter().find(|s| {
        (r.method().as_str() == s.method
            || (r.method() == hyper::Method::HEAD && s.method == "GET"))
            && crate::inventory::path_score(s.path, r.uri().path()).is_some()
    })
}
fn simple_match(r: &Request<Body>) -> bool {
    simple_spec(r).is_some()
}
async fn simple(
    mut r: Request<Body>,
    path: &str,
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    store: Option<Arc<crate::recovery_worker::S3Store>>,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let spec = simple_spec(&r).unwrap();
    let gate = match spec.name {
        "history" => Some(("feature.drive_history", None)),
        "office_choices" => Some(("feature.office_editing", Some("feature.office_local_open"))),
        "office_local_open" => Some(("feature.office_local_open", None)),
        "office_launch" | "office_revoke" => Some(("feature.office_editing", None)),
        _ => None,
    };
    if let Some((key, alternate)) = gate {
        match exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false) OR coalesce((SELECT enabled FROM feature_toggles WHERE key=$2),false)",&[(&key,setjoin_pg::Type::TEXT),(&alternate,setjoin_pg::Type::TEXT)]).await{Ok(rows)if rows[0].get::<_,bool>(0)=>{},Ok(_)=>return problem(404,"not found",None,c,id),Err(_)=>return c.upstream.forward(r,&c.identity).await}
    }
    let target = if spec.detail.is_empty() {
        0
    } else {
        let value = path_value(&r, 4);
        match value.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return problem(400, spec.detail, Some(path), c, id),
        }
    };
    if spec.name == "trash" && query(&r, "tier").as_deref() != Some("2") {
        return problem(
            400,
            "tier=2 required (tier-1 member trash is GET .../tree?deleted=1)",
            Some(path),
            c,
            id,
        );
    }
    if spec.name == "remove_label"
        && std::str::from_utf8(&crate::inventory::unescape(
            r.uri().path().rsplit('/').next().unwrap_or(""),
        ))
        .is_err()
    {
        return problem(500, "request failed", Some(path), c, id);
    }
    let restore_source = if spec.name == "restore_version" {
        let raw = r.uri().path().split('/').nth(6).unwrap_or("");
        let raw = go_utf8(&crate::inventory::unescape(raw));
        let source = match raw.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return problem(400, "invalid version id", Some(path), c, id),
        };
        Some(source)
    } else {
        None
    };
    let mut body = if spec.name == "update_alarm" {
        match alarm_patch_body(&mut r).await {
            Ok(v) => v,
            Err(_) => return problem(400, "invalid JSON", Some(path), c, id),
        }
    } else if spec.name == "patch_branch" {
        match branch_patch_body(&mut r).await {
            Ok(v) => v,
            Err(PatchError::Json) => return problem(400, "invalid JSON", Some(path), c, id),
            Err(PatchError::Field) => {
                return problem(400, "invalid patch field", Some(path), c, id)
            }
            Err(PatchError::Choice) => {
                return input_problem(
                    422,
                    "exactly one of name or status is required",
                    "invalid-arguments",
                    "BZ141",
                    path,
                    c,
                    id,
                )
            }
        }
    } else if spec.name == "purge_restore" {
        json!({})
    } else if matches!(spec.method, "POST" | "PATCH") {
        match structured_body(
            &mut r,
            spec.fields,
            if spec.name == "put_version" {
                1 << 20
            } else if spec.name == "request_export" {
                1 << 10
            } else if spec.name.starts_with("office_") {
                32 << 10
            } else {
                16 << 10
            },
            spec.name == "restore_version",
        )
        .await
        {
            Ok(v) => v,
            Err(_) => {
                return problem(
                    400,
                    "invalid JSON",
                    if spec.name == "office_local_open" {
                        None
                    } else {
                        Some(path)
                    },
                    c,
                    id,
                )
            }
        }
    } else {
        json!({"label":go_utf8(&crate::inventory::unescape(r.uri().path().rsplit('/').next().unwrap_or(""))),"space":query(&r,"space"),"all":query(&r,"all").as_deref()==Some("1")})
    };
    if spec.name == "history" {
        let limit = match query(&r, "limit").filter(|s| !s.is_empty()) {
            None => 100,
            Some(raw) => match raw.parse::<i64>() {
                Ok(v) if (1..=100).contains(&v) => v,
                _ => {
                    return input_problem(
                        422,
                        "limit must be between 1 and 100",
                        "invalid-arguments",
                        "BZ141",
                        path,
                        c,
                        id,
                    )
                }
            },
        };
        body["limit"] = json!(limit);
        if let Some(raw) = query(&r, "cursor").filter(|s| !s.is_empty()) {
            let Some(cursor) = history_cursor(&raw) else {
                return input_problem(
                    400,
                    "history cursor is invalid or expired",
                    "invalid-cursor",
                    "BZ141",
                    path,
                    c,
                    id,
                );
            };
            for (k, v) in cursor.as_object().unwrap() {
                body[k] = v.clone();
            }
        }
    }
    if let Some(source) = restore_source {
        body["sourceVersionId"] = json!(source);
    }
    if spec.name == "office_revoke" {
        let raw = go_utf8(&crate::inventory::unescape(
            r.uri().path().rsplit('/').next().unwrap_or(""),
        ));
        let Some(uuid) = launch_uuid(&raw) else {
            return problem(400, "invalid launch id", None, c, id);
        };
        body["label"] = json!(uuid);
    }
    if spec.name == "office_choices" {
        body["platform"] = json!(query(&r, "platform")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "web".into()));
    }
    if spec.name == "audit" {
        let Some(space) = query(&r, "space").and_then(|v| v.parse::<i64>().ok()) else {
            return problem(400, "space is required", Some(path), c, id);
        };
        body["space"] = json!(space);
        for key in ["actor", "beforeId"] {
            let value = match query(&r, key).filter(|v| !v.is_empty()) {
                Some(v) => match v.parse::<i64>() {
                    Ok(n) => Some(n),
                    Err(_) => return problem(400, &format!("invalid {key}"), Some(path), c, id),
                },
                None => None,
            };
            body[key] = json!(value);
        }
        for key in ["action", "q"] {
            body[key] = json!(query(&r, key).filter(|v| !v.is_empty()));
        }
        for key in ["from", "to"] {
            let value = query(&r, key).filter(|v| !v.is_empty());
            if value
                .as_deref()
                .is_some_and(|v| chrono::DateTime::parse_from_rfc3339(v).is_err())
            {
                return problem(400, &format!("invalid {key}"), Some(path), c, id);
            }
            body[key] = json!(value);
        }
        let max = match query(&r, "max").filter(|v| !v.is_empty()) {
            Some(v) => match v.parse::<i64>() {
                Ok(n) => Some(n),
                Err(_) => return problem(400, "invalid max", Some(path), c, id),
            },
            None => None,
        };
        body["max"] = json!(max);
    }
    if spec.name == "audit" && query(&r, "format").as_deref() == Some("csv") {
        return audit_csv(exec.clone(), actor.clone(), body, c, id);
    }
    let secret = if matches!(spec.name, "office_launch" | "request_export") {
        use base64::Engine;
        use sha2::Digest;
        let mut bytes = [0; 32];
        if getrandom::getrandom(&mut bytes).is_err() {
            return problem(500, "token mint failed", None, c, id);
        }
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        body["tokenHash"] = json!(format!("{:x}", sha2::Sha256::digest(token.as_bytes())));
        if spec.name == "office_launch"
            && body["cohortKey"].as_str().unwrap_or("").trim().is_empty()
        {
            body["cohortKey"] = json!(format!("file-{}", path.split('/').nth(3).unwrap_or("")));
        }
        Some(token)
    } else {
        None
    };
    if spec.method == "GET" {
        match setjoin_drive::part_b::simple_read(exec, actor, spec.name, target, &body).await {
            Ok(mut v) => {
                if spec.name == "history" {
                    let next = v
                        .as_object_mut()
                        .unwrap()
                        .remove("next")
                        .unwrap_or(Value::Null);
                    v["nextCursor"] = if v["hasMore"] == true && !next.is_null() {
                        json!(sign_history_cursor(&next))
                    } else {
                        Value::Null
                    };
                }
                crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
            }
            Err(e) => reducer_problem(&e, path, c, id),
        }
    } else {
        let mut outcome =
            setjoin_drive::part_b::simple_write(exec, actor, spec.name, target, &body, operation)
                .await;
        if let setjoin_pg::CommandOutcome::Committed(ref mut value) = outcome {
            if matches!(spec.name, "put_version" | "restore_version") {
                let manifest = if spec.name == "restore_version" {
                    let manifest = value["_manifest"].take();
                    *value = value["_result"].take();
                    manifest
                } else {
                    serde_json::from_str(body["manifestRaw"].as_str().unwrap_or("[]"))
                        .unwrap_or(Value::Null)
                };
                if let Some(pending) =
                    apply_worm(exec, worker, store, actor, target, &manifest).await
                {
                    value["wormPending"] = json!(pending);
                }
            }
        }
        if let (Some(token), setjoin_pg::CommandOutcome::Committed(ref mut v)) =
            (secret, &mut outcome)
        {
            if spec.name == "office_launch" {
                v["accessToken"] = json!(token);
                let wopi = format!(
                    "{}/api/office/wopi/files/{}",
                    v["wopiPublicBaseUrl"]
                        .as_str()
                        .unwrap_or("")
                        .trim_end_matches('/'),
                    path.split('/').nth(3).unwrap_or("")
                );
                let Some(editor) = editor_url(
                    v["editorUrl"].as_str().unwrap_or(""),
                    v["testTransport"] == true,
                    &wopi,
                ) else {
                    return problem(409, "Office provider launch URL is invalid", None, c, id);
                };
                v["editorUrl"] = json!(editor);
                v["wopiSrc"] = json!(wopi);
                v.as_object_mut().unwrap().remove("wopiPublicBaseUrl");
            } else {
                v["token"] = json!(token);
            }
        }
        command_response(outcome, spec.status, path, c, id)
    }
}

fn structured_decode(bytes: &[u8], known: &[(&str, bool)]) -> Result<Value, ()> {
    use serde::Deserialize;
    let text = go_json_text(bytes);
    let mut decoder = serde_json::Deserializer::from_str(&text);
    let Fields(fields) = Fields::deserialize(&mut decoder).map_err(|_| ())?;
    let fold = |s: &str| {
        s.chars()
            .map(|c| match c {
                'ſ' => 'S',
                'K' => 'K',
                c => c.to_ascii_uppercase(),
            })
            .collect::<String>()
    };
    let mut out = serde_json::Map::new();
    for (key, raw) in fields {
        if let Some((name, integer)) = known.iter().find(|(name, _)| fold(name) == fold(&key)) {
            if *name == "manifest" {
                out.insert("manifestRaw".into(), json!(raw.get()));
                continue;
            }
            if raw.get() == "null" {
                if matches!(
                    *name,
                    "contentType"
                        | "baseVersionId"
                        | "note"
                        | "deviceLabel"
                        | "branchId"
                        | "spaceId"
                        | "threshold"
                        | "windowMinutes"
                        | "newName"
                ) {
                    out.remove(*name);
                }
                continue;
            }
            let value = if *integer {
                json!(serde_json::from_str::<i64>(raw.get()).map_err(|_| ())?)
            } else {
                json!(serde_json::from_str::<String>(raw.get()).map_err(|_| ())?)
            };
            out.insert((*name).into(), value);
        }
    }
    Ok(Value::Object(out))
}
fn editor_url(raw: &str, test: bool, wopi: &str) -> Option<String> {
    fn escapes(raw: &str) -> bool {
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        true
    }
    let (prefix, fragment) = raw
        .split_once('#')
        .map_or((raw, None), |(a, b)| (a, Some(b)));
    if !escapes(prefix.split('?').next().unwrap_or("")) || fragment.is_some_and(|v| !escapes(v)) {
        return None;
    }
    let scheme = raw.split_once(':')?.0;
    let parsed = reqwest::Url::parse(raw).ok()?;
    if scheme != "https" && !(test && scheme == "http" && parsed.host_str() == Some("127.0.0.1")) {
        return None;
    }
    let (prefix, fragment) = raw
        .split_once('#')
        .map_or((raw, None), |(a, b)| (a, Some(b)));
    let (base, query) = prefix.split_once('?').unwrap_or((prefix, ""));
    let mut pairs: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for item in query.split('&') {
        if item.is_empty() || item.contains(';') {
            continue;
        }
        let (k, v) = item.split_once('=').unwrap_or((item, ""));
        if let (Some(k), Some(v)) = (decode_query(k), decode_query(v)) {
            pairs.entry(k).or_default().push(v)
        }
    }
    pairs.insert("WOPISrc".into(), vec![wopi.into()]);
    let encode = |raw: &str| {
        let mut out = String::new();
        for byte in raw.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char)
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    };
    let encoded = pairs
        .into_iter()
        .flat_map(|(k, vs)| vs.into_iter().map(move |v| (k.clone(), v)))
        .map(|(k, v)| format!("{}={}", encode(&k), encode(&v)))
        .collect::<Vec<_>>()
        .join("&");
    Some(format!(
        "{base}?{encoded}{}",
        fragment.map(|f| format!("#{f}")).unwrap_or_default()
    ))
}

enum PatchError {
    Json,
    Choice,
    Field,
}
async fn branch_patch_body(r: &mut Request<Body>) -> Result<Value, PatchError> {
    use serde::Deserialize;
    let mut bytes = Vec::new();
    let mut parsed = None;
    while bytes.len() < 16 << 10 {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        let frame = frame.map_err(|_| PatchError::Json)?;
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(&data[..data.len().min((16 << 10) - bytes.len())]);
            let text = go_json_text(&bytes);
            let mut decoder = serde_json::Deserializer::from_str(&text);
            if let Ok(v) = Fields::deserialize(&mut decoder) {
                parsed = Some(v);
                break;
            }
        }
    }
    let Fields(fields) = parsed.ok_or(PatchError::Json)?;
    let fields: std::collections::BTreeMap<_, _> = fields.into_iter().collect();
    let name = fields.contains_key("name");
    if name == fields.contains_key("status") {
        return Err(PatchError::Choice);
    }
    let key = if name { "name" } else { "status" };
    let raw = fields[key].get();
    let value = if raw == "null" {
        String::new()
    } else {
        serde_json::from_str::<String>(raw).map_err(|_| PatchError::Field)?
    };
    let mut out = json!({});
    out[key] = json!(value);
    Ok(out)
}
fn input_problem(
    status: u16,
    detail: &str,
    slug: &str,
    code: &str,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut r = problem(status, detail, Some(path), c, id);
    let kind = format!("https://setjoin.com/problems/drive/{slug}");
    let text = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path)
        .code(code)
        .body();
    crate::problem::set_body(&mut r, text);
    r
}

async fn alarm_patch_body(r: &mut Request<Body>) -> Result<Value, ()> {
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Some(data) = frame.data_ref() {
            if data.len() > (16 << 10) - bytes.len() {
                return Err(());
            }
            bytes.extend_from_slice(data)
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    let patch: Box<serde_json::value::RawValue> = serde_json::from_str(text).map_err(|_| ())?;
    Ok(json!({"_rawPatch":patch.get()}))
}

fn launch_uuid(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let middle = match bytes.len() {
        32 => bytes,
        36 => bytes,
        38 => &bytes[1..37],
        45 if bytes[..9].eq_ignore_ascii_case(b"urn:uuid:") => &bytes[9..],
        _ => return None,
    };
    let mut hex = String::new();
    for (i, b) in middle.iter().enumerate() {
        if middle.len() == 36 && matches!(i, 8 | 13 | 18 | 23) {
            if *b != b'-' {
                return None;
            }
        } else {
            if !b.is_ascii_hexdigit() {
                return None;
            }
            hex.push((*b as char).to_ascii_lowercase());
        }
    }
    if hex.len() != 32 {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

static HISTORY_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
fn history_key() -> ring::hmac::Key {
    let bytes = HISTORY_KEY.get_or_init(|| {
        let mut bytes = [0; 32];
        getrandom::getrandom(&mut bytes).expect("initialize process-local history cursor key");
        bytes
    });
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, bytes)
}
fn history_cursor(raw: &str) -> Option<Value> {
    use base64::Engine;
    let mut parts = raw.split('.');
    let decode = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.replace(['\r', '\n'], ""))
    };
    let payload = decode(parts.next()?).ok()?;
    let signature = decode(parts.next()?).ok()?;
    if parts.next().is_some() || ring::hmac::verify(&history_key(), &payload, &signature).is_err() {
        return None;
    }
    let fields = decode_body(
        &payload,
        &[
            ("occurredAt", false),
            ("sourceRank", true),
            ("sourceId", true),
        ],
    )
    .ok()?;
    let at = fields["occurredAt"].as_str()?;
    chrono::DateTime::parse_from_rfc3339(at).ok()?;
    let rank = fields["sourceRank"].as_i64().unwrap_or(0);
    let id = fields["sourceId"].as_i64()?;
    if rank < 0 || id < 1 {
        return None;
    }
    Some(json!({"beforeAt":at,"beforeRank":rank,"beforeId":id}))
}
fn sign_history_cursor(next: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    let payload = format!(
        "{{\"occurredAt\":{},\"sourceRank\":{},\"sourceId\":{}}}",
        serde_json::to_string(&next["occurredAt"]).unwrap(),
        next["sourceRank"],
        next["sourceId"]
    );
    format!(
        "{}.{}",
        B.encode(payload.as_bytes()),
        B.encode(ring::hmac::sign(&history_key(), payload.as_bytes()).as_ref())
    )
}

fn path_value(r: &Request<Body>, index: usize) -> String {
    go_utf8(&crate::inventory::unescape(
        r.uri().path().split('/').nth(index).unwrap_or(""),
    ))
}

fn audit_csv(
    exec: ScopedExecutor,
    actor: setjoin_authz::AuthContext,
    mut body: Value,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let space = body["space"].as_i64().unwrap();
    body["max"] = json!(1000);
    let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    response
        .headers_mut()
        .insert("content-type", "text/csv; charset=utf-8".parse().unwrap());
    response.headers_mut().insert(
        "content-disposition",
        format!(
            "attachment; filename=drive-audit-{space}-{}.csv",
            chrono::Utc::now().format("%Y%m%d")
        )
        .parse()
        .unwrap(),
    );
    let pages = futures_util::stream::unfold(
        (exec, actor, body, 0usize, false, false),
        |mut state| async move {
            if state.5 {
                return None;
            }
            if !state.4 {
                state.4 = true;
                return Some((
                    Ok(hyper::body::Frame::data(bytes::Bytes::from_static(
                        b"ID,Timestamp,User,IP,Action,Target Type,Target ID,Notes\n",
                    ))),
                    state,
                ));
            }
            let page =
                match setjoin_drive::part_b::simple_read(&state.0, &state.1, "audit", 0, &state.2)
                    .await
                {
                    Ok(v) => v,
                    Err(_) => return None,
                };
            let items = page["items"].as_array()?;
            if items.is_empty() {
                return None;
            }
            let mut output = String::new();
            for item in items {
                let text = |key: &str| item[key].as_str().unwrap_or("");
                let escaped = |key: &str| setjoin_contracts::csv::escape_formula(text(key));
                let cells = vec![
                    item["id"].as_i64().unwrap_or(0).to_string(),
                    text("occurredAt").into(),
                    escaped("userEmail"),
                    escaped("ip"),
                    escaped("action"),
                    escaped("targetType"),
                    item["targetId"]
                        .as_i64()
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                    escaped("notes"),
                ];
                output.push_str(&setjoin_contracts::csv::record(&cells));
                state.2["beforeId"] = item["id"].clone();
                state.3 += 1;
            }
            state.5 = page["hasMore"] != true || state.3 >= 50000;
            Some((
                Ok(hyper::body::Frame::data(bytes::Bytes::from(output))),
                state,
            ))
        },
    );
    *response.body_mut() = super::content::frames(pages);
    response
}

async fn apply_worm(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    store: Option<Arc<crate::recovery_worker::S3Store>>,
    actor: &setjoin_authz::AuthContext,
    node: i64,
    manifest: &Value,
) -> Option<bool> {
    let chunks = manifest.as_array().filter(|a| !a.is_empty())?;
    let config = setjoin_drive::part_b::worm_config(exec, actor, node).await?;
    let scope = config["scope"].as_str()?;
    let mode = config["mode"].as_str()?;
    let until = (chrono::Utc::now() + chrono::Duration::days(config["days"].as_i64().unwrap_or(0)))
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let mut pending = false;
    for chunk in chunks {
        let sha = chunk["sha256"].as_str().unwrap_or("");
        let Some(store) = store.as_ref() else {
            pending = true;
            continue;
        };
        if store
            .retain(&format!("drive/{scope}/{sha}"), mode, &until)
            .await
            .is_err()
        {
            pending = true;
            continue;
        }
        let Some(operation) = crate::jmap::random() else {
            pending = true;
            continue;
        };
        if !setjoin_drive::part_b::worm_applied(
            worker,
            actor,
            node,
            &json!({"scope":scope,"sha":sha,"until":until}),
            operation,
        )
        .await
        {
            pending = true;
        }
    }
    Some(pending)
}
