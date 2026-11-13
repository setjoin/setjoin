//! Core Drive HTTP translation. User identity is sealed by shared admission.
use super::*;
pub struct CoreRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
}
impl<K: KeySource + 'static> Intercept for CoreRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        (r.uri().path() == "/api/drive/spaces"
            && matches!(r.method().as_str(), "GET" | "HEAD" | "POST"))
            || (matches!(r.method().as_str(), "GET" | "HEAD" | "POST")
                && crate::inventory::path_score("/api/drive/spaces/{id}/members", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/drive/spaces/{id}/tree", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD" | "POST")
                && r.uri().path() == "/api/drive/nodes")
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && r.uri().path() == "/api/drive/changes")
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && r.uri().path() == "/api/drive/access-invalidations")
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && r.uri().path() == "/api/drive/visibility-snapshot")
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score(
                    "/api/drive/spaces/{id}/members/{userId}",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == hyper::Method::PATCH
                && crate::inventory::path_score("/api/drive/spaces/{id}", r.uri().path()).is_some())
            || (r.method() == hyper::Method::PATCH
                && crate::inventory::path_score("/api/drive/nodes/{id}", r.uri().path()).is_some())
            || (r.method() == hyper::Method::POST
                && crate::inventory::path_score("/api/drive/nodes/{id}/trash", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::POST
                && crate::inventory::path_score("/api/drive/nodes/{id}/restore", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score("/api/drive/nodes/{id}", r.uri().path()).is_some())
            || (matches!(r.method().as_str(), "HEAD" | "PUT")
                && crate::inventory::path_score("/api/drive/chunks/{sha256}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/drive/versions/{id}/preview", r.uri().path())
                    .is_some())
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_drive_user_request(&exec, &keys, &issuer, &h, s,"/api/drive/")
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, worker, keys, issuer, store) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.store.clone(),
        );
        let language = locale(r.headers());
        Box::pin(async move {
            let mut response=async move {
            let Some(auth) = setjoin_authz::authorize_drive_user_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
                r.uri().path(),
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(operation) = crate::jmap::random() else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let flag=exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false)",&[]).await;
            match flag {
                Ok(rows) if rows[0].get::<_, bool>(0) => {}
                Ok(_) => return problem(404, "not found", None, &c, id),
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            }
            let path = go_utf8(&crate::inventory::unescape(r.uri().path()))
                .strip_prefix("/api")
                .unwrap()
                .to_owned();
            if path.starts_with("/drive/versions/") {
                let Some(version) = segment(&r,3).and_then(|s|s.parse::<i64>().ok())
                else {
                    return problem(400, "invalid version id", Some(&path), &c, id);
                };
                let mut p = match setjoin_drive::core::preview_query(
                    &exec,
                    auth.context(),
                    version,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(p) => p,
                    setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(f))
                        if f.message == "no rows in result set" =>
                    {
                        return problem(404, "version not found", None, &c, id)
                    }
                    out => return result(out, 200, true, &path, &c, id),
                };
                p["manifest"]=if p["status"]=="ready" {match setjoin_drive::core::preview_manifest(&exec,auth.context(),version).await{Ok(v)=>v,Err(e)=>return rejected(&setjoin_pg::Rejection::Statement(e),Some(&path),&c,id)}}else{json!([])};
                if p["status"]=="none" {
                    let Some(request)=crate::jmap::random() else{return problem(500,"database error",None,&c,id)};
                    match setjoin_drive::core::write(&exec,auth.context(),"drive_preview_request","SELECT to_jsonb(drive_preview_request($2,$4))::text WHERE $1::bigint>0 AND $3::text IS NOT NULL",&[(&version,setjoin_pg::Type::INT8)],request).await {
                        setjoin_pg::CommandOutcome::Committed(v)=>p["status"]=v,out=>return result(out,200,true,&path,&c,id)
                    }
                }
                if p["status"] != "ready" {
                    return typed_problem(
                        404,
                        &format!(
                            "preview rendition not ready (status={})",
                            p["status"].as_str().unwrap_or("")
                        ),
                        "preview-not-ready",
                        None,
                        Some(&path),
                        &c,
                        id,
                    );
                }
                let Some(store) = store else {
                    return c.upstream.forward(r, &c.identity).await;
                };
                if p["classification"]!="regular" || p["auditReads"]==true {
                    let Some(audit)=crate::jmap::random() else{return problem(500,"database error",None,&c,id)};
                    let space=p["spaceId"].as_i64().unwrap();
                    match setjoin_drive::core::write(&exec,auth.context(),"drive_rust_preview_audit","SELECT 'null'::text FROM drive_rust_preview_audit($2,$4,$5,true) WHERE $1::bigint>0 AND $3::text IS NOT NULL",&[(&space,setjoin_pg::Type::INT8),(&version,setjoin_pg::Type::INT8)],audit).await {setjoin_pg::CommandOutcome::Committed(_)=>{},out=>return result(out,200,false,&path,&c,id)}
                }
                return preview_response(&r, &p, store, &c, id);
            }
            if matches!(r.method().as_str(), "HEAD" | "PUT") && path.starts_with("/drive/chunks/") {
                let raw_sha=segment(&r,3);let sha=raw_sha.as_deref().unwrap_or("");
                if !valid_sha(sha) {
                    return problem(400, "invalid sha256", None, &c, id);
                }
                let Some(space) = query(&r, "space").and_then(|s| s.parse::<i64>().ok()) else {
                    return problem(400, "space query param is required", None, &c, id);
                };
                let (target, epoch) = match upload_binding(&r) {
                    Ok(v) => v,
                    Err(_) => {
                        return problem(
                            400,
                            "target and aclEpoch must be valid decimal integers",
                            None,
                            &c,
                            id,
                        )
                    }
                };
                if r.method() == hyper::Method::PUT {
                    let Some(store) = store else {
                        return c.upstream.forward(r, &c.identity).await;
                    };
                    let Some(preflight) = crate::jmap::random() else {
                        return problem(500, "upload failed", None, &c, id);
                    };
                    match setjoin_drive::core::upload_authority(
                        &exec,
                        auth.context(),
                        space,
                        target,
                        epoch,
                        preflight,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(_) => {}
                        out => return result(out, 201, false, &path, &c, id),
                    }
                    let temporary = format!("tmp/upload/{}", crate::jmap::reply::hex(&operation));
                    let bytes = match store.stage_drive_chunk(&temporary,chunk_body(&mut r)).await {
                        Ok(v) => v,
                        Err(status) => {
                            return problem(
                                status,
                                if status == 413 {
                                    "chunk exceeds the 4 MiB limit"
                                } else {
                                    "upload failed"
                                },
                                None,
                                &c,
                                id,
                            )
                        }
                    };
                    use crate::recovery_worker::ObjectStore;
                    use sha2::{Digest, Sha256};
                    let digest = format!("{:x}", Sha256::digest(&bytes));
                    if digest != sha {
                        let _ = store.remove(&temporary).await;
                        return problem(400, "sha256 mismatch", None, &c, id);
                    }
                    if bytes.is_empty() {
                        let _ = store.remove(&temporary).await;
                        return problem(422, "chunk size must be 1..4194304 bytes", None, &c, id);
                    }
                    let from = temporary.clone();
                    let promoted = store.clone();
                    let out = setjoin_drive::core::commit_chunk(
                        &exec,
                        auth.context(),
                        space,
                        target,
                        epoch,
                        sha,
                        bytes.len() as i32,
                        operation,
                        move |to| async move {
                            promoted.promote(&from, &to).await.map_err(|_| {
                                setjoin_pg::StatementFailure {
                                    sqlstate: None,
                                    hint: None,
                                    message: "drive storage failed".into(),
                                }
                            })
                        },
                    )
                    .await;
                    let _ = store.remove(&temporary).await;
                    if matches!(&out,setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(f))if f.message=="drive storage failed")
                    {
                        return problem(500, "upload failed", None, &c, id);
                    }
                    return result(out, 201, false, &path, &c, id);
                }
                return match setjoin_drive::core::head_chunk(
                    &exec,
                    auth.context(),
                    space,
                    sha,
                    target,
                    epoch,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(v) if v == true => empty(200, &c, id),
                    setjoin_pg::CommandOutcome::Committed(_) => {
                        problem(404, "chunk not found", None, &c, id)
                    }
                    out => result(out, 200, false, &path, &c, id),
                };
            }
            if r.method() == hyper::Method::DELETE && path.starts_with("/drive/nodes/") {
                let Some(node) = segment(&r,3).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid node id", Some(&path), &c, id);
                };
                return result(
                    setjoin_drive::core::destroy_node(&exec, auth.context(), node, operation).await,
                    204,
                    false,
                    &path,
                    &c,
                    id,
                );
            }
            if path.ends_with("/restore") {
                if let Err(reply) = name_rate(&exec, auth.context(), &path, &c, &id).await {
                    return reply;
                }
                let Some(node) = segment(&r,3).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid node id", Some(&path), &c, id);
                };
                return result(
                    setjoin_drive::core::restore_node(&exec, auth.context(), node, operation).await,
                    204,
                    false,
                    &path,
                    &c,
                    id,
                );
            }
            if path.ends_with("/trash") {
                let Some(node) = segment(&r,3).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid node id", Some(&path), &c, id);
                };
                return result(
                    setjoin_drive::core::trash_node(&exec, auth.context(), node, operation).await,
                    204,
                    false,
                    &path,
                    &c,
                    id,
                );
            }
            if r.method() == hyper::Method::PATCH && path.starts_with("/drive/nodes/") {
                let Some(node) = segment(&r,3).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid node id", Some(&path), &c, id);
                };
                let fields = match raw_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", Some(&path), &c, id),
                };
                if fields.get("newName").is_some() || fields.get("newParentId").is_some() {
                    if let Err(reply) = name_rate(&exec, auth.context(), &path, &c, &id).await {
                        return reply;
                    }
                }
                if fields
                    .get("newName")
                    .is_some_and(|v| !v.is_string() && !v.is_null())
                    || fields
                        .get("newParentId")
                        .is_some_and(|v| v.as_i64().is_none() && !v.is_null())
                {
                    return problem(400, "invalid patch field", Some(&path), &c, id);
                };
                return result(
                    setjoin_drive::core::patch_node(
                        &exec,
                        auth.context(),
                        node,
                        &fields,
                        operation,
                    )
                    .await,
                    204,
                    false,
                    &path,
                    &c,
                    id,
                );
            }
            if path == "/drive/visibility-snapshot" {
                let Some(space) = query(&r, "space")
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|v| *v > 0)
                else {
                    return problem(400, "space is required", Some(&path), &c, id);
                };
                let after = match nonnegative_query(&r, "after") {
                    Ok(v) => v.unwrap_or(0),
                    Err(_) => return problem(422, "invalid after", Some(&path), &c, id),
                };
                let epoch = match nonnegative_query(&r, "epoch") {
                    Ok(v) => v,
                    Err(_) => return problem(422, "invalid epoch", Some(&path), &c, id),
                };
                let max = match page_size(&r, 500, 500) {
                    Ok(v) => v,
                    Err(_) => return problem(422, "invalid max", Some(&path), &c, id),
                };
                return result(
                    setjoin_drive::core::visibility_snapshot(
                        &exec,
                        auth.context(),
                        space,
                        after,
                        epoch,
                        max,
                        operation,
                    )
                    .await,
                    200,
                    true,
                    &path,
                    &c,
                    id,
                );
            }
            if path == "/drive/access-invalidations" {
                let Some(space) = query(&r, "space")
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|v| *v > 0)
                else {
                    return problem(400, "space is required", Some(&path), &c, id);
                };
                let max = match page_size(&r, 200, 1000) {
                    Ok(v) => v,
                    Err(_) => return problem(422, "invalid max", Some(&path), &c, id),
                };
                let cursor = query(&r, "cursor").filter(|s| !s.trim().is_empty());
                let cursor = match cursor {
                    Some(v) => match parse_uuid(v.trim()) {
                        Some(v) => Some(v),
                        None => return problem(422, "invalid cursor", Some(&path), &c, id),
                    },
                    None => None,
                };
                return result(
                    setjoin_drive::core::access_invalidations(
                        &exec,
                        auth.context(),
                        space,
                        cursor.as_deref(),
                        max,
                        operation,
                    )
                    .await,
                    200,
                    true,
                    &path,
                    &c,
                    id,
                );
            }
            if path == "/drive/changes" {
                let Some(space) = query(&r, "space").and_then(|s| s.parse::<i64>().ok()) else {
                    return problem(400, "space is required", Some(&path), &c, id);
                };
                let Some(since) = query(&r, "since").and_then(|s| s.parse::<i64>().ok()) else {
                    return problem(400, "since is required", Some(&path), &c, id);
                };
                return match setjoin_drive::core::changes(
                    &exec,
                    auth.context(),
                    space,
                    since,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(v)
                        if v["cannotCalculateChanges"] == true =>
                    {
                        typed_problem(
                            409,
                            "client must resync (since is older than the retained journal)",
                            "cannot-calculate-changes",
                            None,
                            Some(&path),
                            &c,
                            id,
                        )
                    }
                    out => result(out, 200, true, &path, &c, id),
                };
            }
            if path == "/drive/nodes" {
                if r.method() == hyper::Method::POST {
                    let body = match body(
                        &mut r,
                        &[
                            ("spaceId", "i"),
                            ("parentId", "i?"),
                            ("kind", "s"),
                            ("name", "s"),
                            ("contentType", "s?"),
                        ],
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(_) => return problem(400, "invalid JSON", Some(&path), &c, id),
                    };
                    if let Err(reply) = name_rate(&exec, auth.context(), &path, &c, &id).await {
                        return reply;
                    }
                    return result(
                        setjoin_drive::core::create_node(&exec, auth.context(), &body, operation)
                            .await,
                        201,
                        true,
                        &path,
                        &c,
                        id,
                    );
                }

                let raw = query(&r, "ids").unwrap_or_default();
                let raw = raw.trim();
                if raw.is_empty() {
                    return result(
                        setjoin_pg::CommandOutcome::Committed(json!([])),
                        200,
                        true,
                        &path,
                        &c,
                        id,
                    );
                }
                if raw.split(',').count()>500{return typed_problem(422,"too many ids (max 500)","invalid-arguments",Some("BZ141"),Some(&path),&c,id)}
                let ids = raw
                    .split(',')
                    .map(|s| s.trim().parse::<i64>())
                    .collect::<Result<Vec<_>, _>>();
                let ids = match ids {
                    Ok(v) if v.len() <= 500 => v,
                    _ => return typed_problem(422, "invalid id in ids list", "invalid-arguments", Some("BZ141"), Some(&path), &c, id),
                };
                return result(
                    setjoin_drive::core::nodes_meta(&exec, auth.context(), &ids, operation).await,
                    200,
                    true,
                    &path,
                    &c,
                    id,
                );
            }
            if path.ends_with("/tree") {
                let Some(space) = segment(&r,3).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid space id", Some(&path), &c, id);
                };
                let parent = match query(&r, "parent").filter(|s| !s.is_empty()) {
                    Some(v) => match v.parse::<i64>() {
                        Ok(v) => Some(v),
                        Err(_) => return problem(400, "invalid parent id", Some(&path), &c, id),
                    },
                    None => None,
                };
                let deleted = query(&r, "deleted").as_deref() == Some("1");
                return match setjoin_drive::core::tree(
                    &exec,
                    auth.context(),
                    space,
                    parent,
                    deleted,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(v) if v.is_null() => {
                        problem(404, "space not found", Some(&path), &c, id)
                    }
                    out => result(out, 200, true, &path, &c, id),
                };
            }
            if r.method() == hyper::Method::DELETE {
                let Some(space) = segment(&r,3).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid space id", Some(&path), &c, id);
                };
                let Some(user) = segment(&r,5).and_then(|s|s.parse::<i64>().ok()) else {
                    return problem(400, "invalid user id", Some(&path), &c, id);
                };
                match optional_folder(&r) {Ok(Some(folder))=>return result(setjoin_drive::core::folder_revoke(&exec,auth.context(),space,folder,user,operation).await,204,false,&path,&c,id),Err(())=>return problem(400,"invalid folder",Some(&path),&c,id),_=>{}}
                return result(
                    setjoin_drive::core::revoke_member(
                        &exec,
                        auth.context(),
                        space,
                        user,
                        operation,
                    )
                    .await,
                    204,
                    false,
                    &path,
                    &c,
                    id,
                );
            }
            if path.ends_with("/members") {
                let Some(target) = segment(&r,3).and_then(|s|s.parse::<i64>().ok())
                else {
                    return problem(400, "invalid space id", Some(&path), &c, id);
                };
                if r.method() == hyper::Method::POST {
                    let fields = match body(&mut r, &[("userId", "i"), ("role", "s")]).await {
                        Ok(v) if v["userId"].as_i64().is_some_and(|v| v > 0) => v,
                        _ => return problem(400, "invalid JSON", Some(&path), &c, id),
                    };
                    match optional_folder(&r) {Ok(Some(folder))=>return result(setjoin_drive::core::folder_grant(&exec,auth.context(),target,folder,fields["userId"].as_i64().unwrap(),fields["role"].as_str().unwrap_or(""),operation).await,200,true,&path,&c,id),Err(())=>return problem(400,"invalid folder",Some(&path),&c,id),_=>{}}
                    return result(
                        setjoin_drive::core::grant_member(
                            &exec,
                            auth.context(),
                            target,
                            fields["userId"].as_i64().unwrap(),
                            fields["role"].as_str().unwrap_or(""),
                            operation,
                        )
                        .await,
                        200,
                        true,
                        &path,
                        &c,
                        id,
                    );
                }
                return match setjoin_drive::core::members(&exec, auth.context(), target, operation)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(v)
                        if v.as_array().is_some_and(|v| v.is_empty()) =>
                    {
                        problem(404, "space not found", Some(&path), &c, id)
                    }
                    out => result(out, 200, true, &path, &c, id),
                };
            }
            if r.method() == hyper::Method::PATCH {
                let Some(target) = segment(&r,3).and_then(|s|s.parse::<i64>().ok())
                else {
                    return problem(400, "invalid space id", Some(&path), &c, id);
                };
                let fields = match raw_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", Some(&path), &c, id),
                };
                if !fields.get("classification").is_some() && ["exportPolicy","retentionDays","wormMode","vaultQuotaMb"].iter().any(|k|fields.get(*k).is_some()) {
                    if ["retentionDays","vaultQuotaMb"].iter().any(|k|fields.get(*k).is_some_and(|v|!v.is_null()&&v.as_i64().is_none())) || fields.get("wormMode").is_some_and(|v|!v.is_null()&&!v.is_string()) {return problem(400,"no recognized patch field",Some(&path),&c,id)}
                    return result(setjoin_drive::core::patch_policy(&exec,auth.context(),target,&fields,operation).await,204,false,&path,&c,id)
                }
                if fields.get("classification").is_none() && fields.get("quotaBytes").is_some() {
                    let quota=&fields["quotaBytes"];if !quota.is_null()&&quota.as_i64().is_none(){return problem(400,"no recognized patch field",Some(&path),&c,id)}
                    return result(setjoin_drive::core::patch_quota(&exec,auth.context(),target,quota.as_i64(),operation).await,204,false,&path,&c,id)
                }
                if !fields
                    .get("classification")
                    .is_some_and(|v| v.is_string() || v.is_null())
                {
                    return problem(400, "no recognized patch field", Some(&path), &c, id);
                };
                return result(
                    setjoin_drive::core::patch_classification(
                        &exec,
                        auth.context(),
                        target,
                        fields["classification"].as_str().unwrap_or(""),
                        operation,
                    )
                    .await,
                    204,
                    false,
                    &path,
                    &c,
                    id,
                );
            }
            if r.method() == hyper::Method::POST {
                let body = match body(
                    &mut r,
                    &[
                        ("name", "s"),
                        ("classification", "s"),
                        ("isPersonal", "b"),
                        ("retentionDays", "i?"),
                        ("wormMode", "s?"),
                        ("exportPolicy", "v"),
                    ],
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", Some(&path), &c, id),
                };
                return result(
                    setjoin_drive::core::create_space(&exec, auth.context(), &body, operation)
                        .await,
                    201,
                    true,
                    &path,
                    &c,
                    id,
                );
            }
            if query(&r,"admin").as_deref()==Some("1") {
                let permission=setjoin_drive::core::write(&exec,auth.context(),"drive_admin_read_permission","SELECT to_jsonb(drive_has_admin_perm($2,'drive.view'))::text WHERE $1::bigint>0 AND $3::text IS NOT NULL",&[],operation).await;
                match permission {setjoin_pg::CommandOutcome::Committed(v) if v==true=>{},setjoin_pg::CommandOutcome::Committed(_)=>return typed_problem(403,"drive.view required","forbidden",None,Some(&path),&c,id),out=>return result(out,200,true,&path,&c,id)}
                return match setjoin_drive::core::admin_spaces(&worker,auth.context()).await{Ok(v)=>result(setjoin_pg::CommandOutcome::Committed(v),200,true,&path,&c,id),Err(_)=>problem(500,"database error",None,&c,id)};
            }
            result(
                setjoin_drive::core::list_spaces(&exec, auth.context(), operation).await,
                200,
                true,
                &path,
                &c,
                id,
            )
            }.await;
            if response.headers().contains_key("content-language") {
                response.headers_mut().insert(
                    "content-language",
                    language.parse().expect("validated locale"),
                );
            }
            response
        })
    }
}
async fn body(r: &mut Request<Body>, fields: &[(&str, &str)]) -> Result<Value, ()> {
    let values = read_fields(r).await?;
    // Match MaxBytesReader's first decoder value bound, including ignored trailers.
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
    for (k, raw) in values.0 {
        if let Some((name, ty)) = fields.iter().find(|(name, _)| fold(name) == fold(&k)) {
            let v: Value = serde_json::from_str(raw.get()).map_err(|_| ())?;
            if v.is_null() {
                if ty.ends_with('?') || *ty == "v" {
                    out.insert((*name).into(), v);
                }
                continue;
            }
            if !match ty.trim_end_matches('?') {
                "s" => v.is_string(),
                "i" => v.as_i64().is_some(),
                "b" => v.is_boolean(),
                _ => true,
            } {
                return Err(());
            }
            out.insert((*name).into(), v);
        }
    }
    Ok(Value::Object(out))
}
async fn read_fields(r: &mut Request<Body>) -> Result<Fields, ()> {
    use serde::Deserialize;
    let mut bytes = Vec::new();
    while bytes.len() < 16 * 1024 {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        let frame = frame.map_err(|_| ())?;
        if let Some(data) = frame.data_ref() {
            let n = data.len().min(16 * 1024 - bytes.len());
            bytes.extend_from_slice(&data[..n]);
        }
    }
    let text = go_json_text(&bytes);
    let mut d = serde_json::Deserializer::from_str(&text);
    return Fields::deserialize(&mut d).map_err(|_| ());
}
async fn raw_body(r: &mut Request<Body>) -> Result<Value, ()> {
    let mut out = serde_json::Map::new();
    for (k, raw) in read_fields(r).await?.0 {
        out.insert(k, serde_json::from_str(raw.get()).map_err(|_| ())?);
    }
    Ok(Value::Object(out))
}
fn result(
    out: setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure>,
    status: u16,
    json_body: bool,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    match out {
        setjoin_pg::CommandOutcome::Committed(v) => {
            let mut r = if json_body {
                crate::jmap::reply::response(crate::recovery::go_json(&v), c.identity.proto, id)
            } else {
                empty(status, c, id)
            };
            *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
            r
        }
        setjoin_pg::CommandOutcome::Unknown { operation } => unknown(operation, c, id),
        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, Some(path), c, id),
    }
}

fn rejected(
    e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let f = match e {
        setjoin_pg::Rejection::Body(f) | setjoin_pg::Rejection::Statement(f) => Some(f),
        _ => None,
    };
    let code = f.and_then(|f| f.sqlstate.as_deref()).unwrap_or("");
    let (status, detail, slug) = match code {
        "BZ139" => (404, "notFound", "not-found"),
        "BZ140" => (403, "forbidden", "forbidden"),
        "BZ141" => (422, "unprocessable", "invalid-arguments"),
        "BZ142" => (409, "conflict", "no-downgrade"),
        "BZ143" => (409, "conflict", "cross-space"),
        "BZ144" => (422, "unprocessable", "chunk-not-proven"),
        "BZ145" => (409, "conflict", "immutable"),
        "BZ146" => (409, "conflict", "invalid-grant"),
        "BZ147" => (409, "conflict", "duplicate-name"),
        "BZ148" => (413, "overQuota", "quota-exceeded"),
        "BZ149" => (423, "conflict", "locked"),
        "BZ150" => (409, "conflict", "branch-error"),
        "BZ260" => (409, "conflict", "name-unavailable"),
        "BZ175" | "BZ215" | "BZ253" => (403, "forbidden", ""),
        "BZ252" => (400, "invalidArguments", ""),
        "BZ254" | "BZ255" | "BZ256" => (409, "conflict", ""),
        _ => (500, "request failed", ""),
    };
    let mut r = problem(status, detail, path, c, id);
    let kind = if slug.is_empty() {
        "about:blank".to_owned()
    } else {
        format!("https://setjoin.com/problems/drive/{slug}")
    };
    let mut p = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path.unwrap_or(""));
    if !slug.is_empty() {
        p = p.code(code);
    }
    if code == "BZ149" {
        if let Some(holder) = f
            .and_then(|f| f.hint.as_deref())
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v["holderId"].as_i64())
        {
            p = p.holder_id(holder);
        }
    }
    crate::problem::set_body(&mut r, p.body());
    r
}

fn typed_problem(
    status: u16,
    detail: &str,
    slug: &str,
    code: Option<&str>,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut r = problem(status, detail, path, c, id);
    let kind = if slug == "forbidden" {
        "https://setjoin.com/errors/forbidden".to_owned()
    } else {
        format!("https://setjoin.com/problems/drive/{slug}")
    };
    let mut p = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path.unwrap_or(""));
    if let Some(code) = code {
        p = p.code(code);
    }
    crate::problem::set_body(&mut r, p.body());
    r
}

fn page_size(r: &Request<Body>, fallback: i32, max: i32) -> Result<i32, ()> {
    match query(r, "max") {
        None => Ok(fallback),
        Some(s) if s.trim().is_empty() => Ok(fallback),
        Some(s) => s
            .trim()
            .parse::<i32>()
            .ok()
            .filter(|v| *v > 0 && *v <= max)
            .ok_or(()),
    }
}
fn parse_uuid(raw: &str) -> Option<String> {
    let raw = if raw.len() == 45
        && raw
            .get(..9)
            .is_some_and(|s| s.eq_ignore_ascii_case("urn:uuid:"))
    {
        &raw[9..]
    } else if raw.len() == 38 && raw.starts_with('{') && raw.ends_with('}') {
        &raw[1..37]
    } else {
        raw
    };
    let hex = if raw.len() == 36 {
        let bytes = raw.as_bytes();
        if [8, 13, 18, 23].iter().any(|i| bytes[*i] != b'-') {
            return None;
        }
        raw.chars().filter(|c| *c != '-').collect::<String>()
    } else if raw.len() == 32 {
        raw.to_owned()
    } else {
        return None;
    };
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
        .to_ascii_lowercase(),
    )
}

fn nonnegative_query(r: &Request<Body>, key: &str) -> Result<Option<i64>, ()> {
    match query(r, key) {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => s
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|v| *v >= 0)
            .map(Some)
            .ok_or(()),
    }
}

async fn name_rate(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    path: &str,
    c: &RequestContext,
    id: &str,
) -> Result<(), Response<Body>> {
    let Some(operation) = crate::jmap::random() else {
        return Err(problem(500, "request failed", Some(path), c, id.into()));
    };
    match setjoin_drive::core::allow_name_mutation(exec, actor, operation).await {
        setjoin_pg::CommandOutcome::Committed(v) if v == true => Ok(()),
        setjoin_pg::CommandOutcome::Committed(_) => {
            let mut r = typed_problem(
                429,
                "too many name or placement changes; retry later",
                "mutation-rate-limited",
                None,
                Some(path),
                c,
                id.into(),
            );
            r.headers_mut().insert("retry-after", "60".parse().unwrap());
            Err(r)
        }
        out => Err(result(out, 500, true, path, c, id.into())),
    }
}

fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn upload_binding(r: &Request<Body>) -> Result<(Option<i64>, Option<i64>), ()> {
    let target = query(r, "target").unwrap_or_default();
    let epoch = query(r, "aclEpoch").unwrap_or_default();
    if target.is_empty() && epoch.is_empty() {
        return Ok((None, None));
    }
    let target = target.parse::<i64>().ok().filter(|v| *v > 0).ok_or(())?;
    let epoch = epoch.parse::<i64>().ok().filter(|v| *v >= 0).ok_or(())?;
    Ok((Some(target), Some(epoch)))
}

async fn chunk_body(r: &mut Request<Body>) -> Result<Vec<u8>, u16> {
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| 500u16)?;
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() > 4 * 1024 * 1024 {
                return Err(413);
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

fn preview_response(
    r: &Request<Body>,
    p: &Value,
    store: Arc<crate::recovery_worker::S3Store>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let chunks = p["manifest"].as_array().unwrap();
    let size = chunks
        .iter()
        .map(|c| c["size"].as_u64().unwrap())
        .sum::<u64>();
    let range = r
        .headers()
        .get("range")
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty());
    let bounds = if let Some(raw) = range {
        match single_range(raw, size) {
            Some(v) => v,
            None => {
                let mut out = problem(416, "invalid or multipart Range", None, c, id);
                out.headers_mut()
                    .insert("content-disposition", "inline".parse().unwrap());
                out.headers_mut()
                    .insert("accept-ranges", "bytes".parse().unwrap());
                return out;
            }
        }
    } else {
        (0, size.saturating_sub(1))
    };
    let mut requests = Vec::new();
    if size > 0 {
        for (index, chunk) in chunks.iter().enumerate() {
            let first = bounds.0 / (4 * 1024 * 1024);
            let last = bounds.1 / (4 * 1024 * 1024);
            let index = index as u64;
            if index < first || index > last {
                continue;
            }
            let lo = if index == first {
                bounds.0 % (4 * 1024 * 1024)
            } else {
                0
            };
            let hi = if index == last {
                bounds.1 - index * 4 * 1024 * 1024
            } else {
                chunk["size"].as_u64().unwrap() - 1
            };
            let fetched = if range.is_some() {
                hi - lo + 1
            } else {
                chunk["size"].as_u64().unwrap()
            };
            requests.push((
                chunk["storageRef"].as_str().unwrap().to_owned(),
                fetched,
                range.map(|_| (lo, hi)),
            ));
        }
    }
    let stream = futures_util::stream::try_unfold(
        (store, requests, 0usize, None::<Body>),
        |(store, requests, mut index, mut body)| async move {
            loop {
                if let Some(current) = body.as_mut() {
                    match current.frame().await {
                        Some(Ok(frame)) => {
                            return Ok::<_, crate::BoxError>(Some((
                                frame,
                                (store, requests, index, body),
                            )))
                        }
                        Some(Err(e)) => return Err(e),
                        None => body = None,
                    }
                } else {
                    if index >= requests.len() {
                        return Ok(None);
                    }
                    let (key, length, range) = &requests[index];
                    body =
                        Some(store.stream_blob(key, *length, *range).await.map_err(
                            |_| -> crate::BoxError { "preview stream interrupted".into() },
                        )?);
                    index += 1;
                }
            }
        },
    );
    let mut out = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *out.body_mut() = PreviewStream(std::sync::Mutex::new(Box::pin(stream))).boxed();
    out.headers_mut()
        .insert("content-type", "application/pdf".parse().unwrap());
    out.headers_mut()
        .insert("content-disposition", "inline".parse().unwrap());
    out.headers_mut()
        .insert("accept-ranges", "bytes".parse().unwrap());
    let length = if range.is_some() {
        *out.status_mut() = hyper::StatusCode::PARTIAL_CONTENT;
        out.headers_mut().insert(
            "content-range",
            format!("bytes {}-{}/{size}", bounds.0, bounds.1)
                .parse()
                .unwrap(),
        );
        bounds.1 - bounds.0 + 1
    } else {
        size
    };
    out.headers_mut()
        .insert("content-length", length.to_string().parse().unwrap());
    out
}
fn single_range(raw: &str, size: u64) -> Option<(u64, u64)> {
    let raw = raw.strip_prefix("bytes=")?;
    if raw.contains(',') {
        return None;
    }
    let (start, end) = raw.split_once('-')?;
    let start = start.parse::<i64>().ok()?;
    if start < 0 || start as u64 >= size {
        return None;
    }
    let end = if end.is_empty() {
        size as i64 - 1
    } else {
        end.parse::<i64>().ok()?
    };
    if end < start {
        return None;
    }
    Some((start as u64, (end as u64).min(size - 1)))
}

type PreviewFrames = std::pin::Pin<
    Box<
        dyn futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, crate::BoxError>>
            + Send,
    >,
>;
struct PreviewStream(std::sync::Mutex<PreviewFrames>);
impl hyper::body::Body for PreviewStream {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.get_mut()
            .0
            .get_mut()
            .expect("owned preview stream")
            .as_mut()
            .poll_next(cx)
    }
}

fn optional_folder(r: &Request<Body>) -> Result<Option<i64>, ()> {
    query(r, "folder")
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| ()))
        .transpose()
}

fn problem(
    status: u16,
    detail: &str,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut r = super::problem(status, detail, path, c, id);
    if matches!(status, 413 | 416) {
        let text = crate::problem::Problem::new(status, detail)
            .instance(path.unwrap_or(""))
            .body();
        crate::problem::set_body(&mut r, text);
    }
    r
}

fn segment(r: &Request<Body>, index: usize) -> Option<String> {
    let raw = r.uri().path().strip_prefix("/api")?.split('/').nth(index)?;
    String::from_utf8(crate::inventory::unescape(raw)).ok()
}
