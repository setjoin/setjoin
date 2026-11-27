//! F02 SCIM 2.0 provisioning adapter (#375): the twelve root-pinned `/scim/v2/*`
//! routes. Authentication is Go's SCIM bearer check (SHA-256 indexed lookup then a
//! bcrypt compare, with the legacy scan fallback); every statement is fenced by
//! the verified token's source and generation. Frozen Go's rate limit, CSRF and
//! guest belt run in the gateway edge before this adapter.
use crate::directory_sync_input as input;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use serde_json::Value;
use setjoin_authz::token::KeySource;
use setjoin_directory_sync::scim::{
    self, patch,
    wire::{self, CONTENT_TYPE},
    Token,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Go's `maxBodyBytes`.
const BODY_LIMIT: usize = 1 << 20;

pub struct ScimRoute<K: KeySource + 'static> {
    /// Request-pool credential (token and group statements, as Go's `pool`).
    pub exec: ScopedExecutor,
    /// Worker credential (identity-link reads and reducers, as Go's `workerPool`).
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// `SCIM_AUTHSERVER_URL` (Go default `http://localhost:8443`) and `INTERNAL_API_KEY`.
    pub authserver_url: String,
    pub internal_key: String,
    /// Optional [`AuthAuthority`] seam for session revocation (#543).
    pub authority: Option<Arc<dyn setjoin_authz::auth_authority::AuthAuthority>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    ListUsers,
    CreateUser,
    GetUser,
    ReplaceUser,
    PatchUser,
    DeleteUser,
    ListGroups,
    CreateGroup,
    GetGroup,
    PatchGroup,
    DeleteGroup,
    ProviderConfig,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 12] = [
        (reads, "/scim/v2/Users", Action::ListUsers),
        (
            *method == Method::POST,
            "/scim/v2/Users",
            Action::CreateUser,
        ),
        (reads, "/scim/v2/Users/{id}", Action::GetUser),
        (
            *method == Method::PUT,
            "/scim/v2/Users/{id}",
            Action::ReplaceUser,
        ),
        (
            *method == Method::PATCH,
            "/scim/v2/Users/{id}",
            Action::PatchUser,
        ),
        (
            *method == Method::DELETE,
            "/scim/v2/Users/{id}",
            Action::DeleteUser,
        ),
        (reads, "/scim/v2/Groups", Action::ListGroups),
        (
            *method == Method::POST,
            "/scim/v2/Groups",
            Action::CreateGroup,
        ),
        (reads, "/scim/v2/Groups/{id}", Action::GetGroup),
        (
            *method == Method::PATCH,
            "/scim/v2/Groups/{id}",
            Action::PatchGroup,
        ),
        (
            *method == Method::DELETE,
            "/scim/v2/Groups/{id}",
            Action::DeleteGroup,
        ),
        (
            reads,
            "/scim/v2/ServiceProviderConfig",
            Action::ProviderConfig,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// `r.PathValue("id")`: the unescaped fourth segment.
fn path_id(path: &str) -> String {
    let segment = path.split('/').nth(4).unwrap_or("");
    crate::guests_input::go_utf8(&crate::inventory::unescape(segment))
}

impl<K: KeySource + 'static> Intercept for ScimRoute<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
    }
    /// Go's guest belt passes bearer tokens that are not live JWTs straight through
    /// (SCIM tokens are opaque). A verifiable session token stays with Go.
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_none()
        })
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let route = Handler {
            exec: self.exec.clone(),
            worker: self.worker.clone(),
            authserver_url: self.authserver_url.clone(),
            internal_key: self.internal_key.clone(),
            authority: self.authority.clone(),
        };
        Box::pin(async move { route.serve(r, c).await })
    }
}

struct Handler {
    exec: ScopedExecutor,
    worker: ScopedExecutor,
    authserver_url: String,
    internal_key: String,
    authority: Option<Arc<dyn setjoin_authz::auth_authority::AuthAuthority>>,
}

struct Out<'a> {
    c: &'a RequestContext,
    id: String,
}
impl Out<'_> {
    fn send(&self, status: u16, body: String) -> Response<Body> {
        let mut r = crate::jmap::reply::response(body, self.c.identity.proto, self.id.clone());
        *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        r.headers_mut().insert(
            "content-type",
            hyper::header::HeaderValue::from_static(CONTENT_TYPE),
        );
        r
    }
    fn error(&self, status: u16, detail: &str, scim_type: &str) -> Response<Body> {
        self.send(status, wire::error_json(status, detail, scim_type))
    }
    fn http(&self, e: &patch::HttpError) -> Response<Body> {
        self.error(e.status, &e.detail, e.scim_type)
    }
    fn json(&self, status: u16, body: String) -> Response<Body> {
        self.send(status, body + "\n")
    }
    fn no_content(&self) -> Response<Body> {
        let mut r =
            crate::jmap::reply::response(String::new(), self.c.identity.proto, self.id.clone());
        *r.status_mut() = hyper::StatusCode::NO_CONTENT;
        r.headers_mut().remove("content-type");
        r
    }
}

enum Authentication {
    Token(Token),
    Reply(u16, &'static str, &'static str),
}

impl Handler {
    async fn authenticate(&self, headers: &hyper::HeaderMap) -> Authentication {
        let header = headers
            .get(hyper::header::AUTHORIZATION)
            .map_or(&b""[..], |v| v.as_bytes());
        let Some(token) = header.strip_prefix(b"Bearer ") else {
            return Authentication::Reply(
                401,
                "Missing or invalid Authorization header",
                "invalidToken",
            );
        };
        if token.is_empty() {
            return Authentication::Reply(401, "Empty SCIM token", "invalidToken");
        }
        let lookup: String = Sha256::digest(token)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let unavailable = Authentication::Reply(500, "Authentication service unavailable", "");
        let found = match scim_token_by_hash(&self.worker, &lookup).await {
            Ok(found) => found,
            Err(_) => return unavailable,
        };
        let invalid =
            || Authentication::Reply(401, "Invalid or expired SCIM token", "invalidToken");
        if let Some((candidate, hash)) = found {
            // The index only narrows the candidate; bcrypt stays the verifier.
            if !verify(token, hash).await {
                return invalid();
            }
            self.used(candidate.id);
            return Authentication::Token(candidate);
        }
        let Ok(legacy) = scim_legacy_tokens(&self.worker).await else {
            return unavailable;
        };
        for (candidate, hash) in legacy {
            if verify(token, hash).await {
                self.used(candidate.id);
                return Authentication::Token(candidate);
            }
        }
        invalid()
    }

    /// Go bumps `last_used_at` asynchronously and ignores failure.
    fn used(&self, token: i64) {
        let worker = self.worker.clone();
        tokio::spawn(async move { scim_record_usage(&worker, token).await });
    }

    async fn serve(&self, mut r: Request<Body>, c: RequestContext) -> Response<Body> {
        let what = action(r.method(), r.uri().path()).expect("matched route");
        let Some(operation) = crate::jmap::random() else {
            return crate::proxy::status(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable\n",
            );
        };
        let out = Out {
            id: crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation),
            c: &c,
        };
        let token = match self.authenticate(r.headers()).await {
            Authentication::Token(token) => token,
            Authentication::Reply(status, detail, kind) => return out.error(status, detail, kind),
        };
        if !matches!(*r.method(), Method::GET | Method::DELETE) {
            let ok = r
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .map(|v| v.as_bytes())
                .is_some_and(|ct| {
                    !ct.is_empty()
                        && (ct.starts_with(CONTENT_TYPE.as_bytes())
                            || ct.starts_with(b"application/json"))
                });
            if !ok {
                return out.error(
                    400,
                    "Content-Type must be application/scim+json",
                    "invalidValue",
                );
            }
        }
        let id = path_id(r.uri().path());
        match what {
            Action::ProviderConfig => out.json(200, PROVIDER_CONFIG.into()),
            Action::ListUsers => self.list_users(&r, &token, &out).await,
            Action::GetUser => self.get_user(&token, &id, &out).await,
            Action::CreateUser => self.create_user(&mut r, &token, &out).await,
            Action::ReplaceUser => self.replace_user(&mut r, &token, &id, &out).await,
            Action::PatchUser => self.patch_user(&mut r, &token, &id, &out).await,
            Action::DeleteUser => self.delete_user(&token, &id, &out).await,
            Action::ListGroups => self.list_groups(&r, &token, &out).await,
            Action::GetGroup => self.get_group(&token, &id, &out).await,
            Action::CreateGroup => self.create_group(&mut r, &token, &out).await,
            Action::PatchGroup => self.patch_group(&mut r, &token, &id, &out).await,
            Action::DeleteGroup => self.delete_group(&token, &id, &out).await,
        }
    }

    // ---- users ------------------------------------------------------------------

    async fn list_users(&self, r: &Request<Body>, token: &Token, out: &Out<'_>) -> Response<Body> {
        let source = token.fence.source_id;
        let (start, count) = paging(r);
        let filter = input::query(r.uri(), "filter").unwrap_or_default();
        let sync = input::query(r.uri(), "syncToken").unwrap_or_default();
        let page = if !filter.is_empty() {
            match scim::filter::parse(&filter) {
                Ok(node) => scim::Page::Filter(node, start, count),
                Err(()) => {
                    return out.error(400, "Invalid filter syntax", "invalidFilter");
                }
            }
        } else if !sync.is_empty() {
            scim::Page::Sync(sync.clone(), count)
        } else {
            scim::Page::All(start, count)
        };
        let listed = match scim_list_users(&self.worker, source, page).await {
            Ok(listed) => listed,
            Err(scim::ListError::Http(e)) => return out.http(&e),
            Err(scim::ListError::Query) => return out.error(500, "Query failed", ""),
        };
        let syncing = !sync.is_empty() && filter.is_empty();
        let total = if syncing {
            listed.rows.len() as i64
        } else {
            listed.total
        };
        let resources: Vec<String> = listed
            .rows
            .iter()
            .map(|row| scim::user_resource(row).json())
            .collect();
        let mut response = out.json(200, wire::list_json(total, start, &resources));
        if syncing {
            // The newest row by updated_at (first wins on a tie, as `After`).
            let mut best: Option<&scim::UserRow> = None;
            for row in &listed.rows {
                if best.is_none_or(|b| row.updated_micros > b.updated_micros)
                    && row.updated_micros > i64::MIN
                {
                    best = Some(row);
                }
            }
            if let Some(row) = best {
                let token = scim::sync_token(source, &row.updated_nano);
                if let Ok(value) = hyper::header::HeaderValue::from_str(&format!(
                    "/scim/v2/Users?syncToken={token}"
                )) {
                    response.headers_mut().insert("location", value);
                }
            }
        }
        response
    }

    async fn get_user(&self, token: &Token, id: &str, out: &Out<'_>) -> Response<Body> {
        let Some(user) = scim::go_parse_int(id) else {
            return out.error(400, "Invalid user ID", "invalidValue");
        };
        match scim_get_user(&self.worker, token.fence.source_id, user).await {
            Some(row) => out.json(200, scim::user_resource(&row).json()),
            None => out.error(404, &format!("User {id} not found"), "invalidValue"),
        }
    }

    async fn create_user(
        &self,
        r: &mut Request<Body>,
        token: &Token,
        out: &Out<'_>,
    ) -> Response<Body> {
        let req = match body(r)
            .await
            .and_then(|v| wire::decode_user(&v).map_err(|()| Bad::Syntax))
        {
            Ok(req) => req,
            Err(bad) => return bad.reply(out),
        };
        if req.user_name.is_empty() {
            return out.error(400, "userName is required", "invalidValue");
        }
        let fields = scim::extract_user_fields(&req);
        let id = match self
            .apply(token, &req.external_id, &fields, &req.title, 0, None)
            .await
        {
            Ok(id) => id,
            Err(scim::ApplyError::Http(e)) => return out.http(&e),
            Err(scim::ApplyError::Status(s)) => return out.error(s, "Failed to create user", ""),
        };
        // Go starts the welcome email from a goroutine and answers without it.
        let worker = self.worker.clone();
        tokio::spawn(async move { send_welcome(&worker, id).await });
        let now = now();
        let user = scim::resource_from(
            id,
            Some(&req.external_id),
            Some(&req.user_name),
            Some(&fields.primary_email),
            Some(&fields.display_name),
            Some(&fields.first_name),
            Some(&fields.last_name),
            Some(&req.title),
            Some(&fields.phone),
            Some(fields.active),
            &now,
            &now,
        );
        out.json(201, user.json())
    }

    async fn replace_user(
        &self,
        r: &mut Request<Body>,
        token: &Token,
        id_text: &str,
        out: &Out<'_>,
    ) -> Response<Body> {
        let Some(path_id) = scim::go_parse_int(id_text) else {
            return out.error(400, "Invalid user ID", "invalidValue");
        };
        let mut req = match body(r)
            .await
            .and_then(|v| wire::decode_user(&v).map_err(|()| Bad::Syntax))
        {
            Ok(req) => req,
            Err(bad) => return bad.reply(out),
        };
        if req.user_name.is_empty() {
            return out.error(400, "userName is required", "invalidValue");
        }
        let Some(external) =
            scim_source_subject(&self.worker, token.fence.source_id, path_id).await
        else {
            return out.error(
                404,
                &format!("User {id_text} is not managed by this SCIM source"),
                "invalidValue",
            );
        };
        if !req.external_id.is_empty() && req.external_id != external {
            return out.error(
                409,
                "externalId is immutable for this SCIM source",
                "uniqueness",
            );
        }
        req.external_id = external.clone();
        let fields = scim::extract_user_fields(&req);
        let id = match self
            .apply(token, &external, &fields, &req.title, path_id, None)
            .await
        {
            Ok(id) => id,
            Err(scim::ApplyError::Http(e)) => return out.http(&e),
            Err(scim::ApplyError::Status(s)) => return out.error(s, "Failed to replace user", ""),
        };
        let now = now();
        let user = scim::resource_from(
            id,
            Some(&req.external_id),
            Some(&req.user_name),
            Some(&fields.primary_email),
            Some(&fields.display_name),
            Some(&fields.first_name),
            Some(&fields.last_name),
            Some(&req.title),
            Some(&fields.phone),
            Some(fields.active),
            &now,
            &now,
        );
        if !fields.active {
            self.revoke(id);
        }
        out.json(200, user.json())
    }

    async fn patch_user(
        &self,
        r: &mut Request<Body>,
        token: &Token,
        id_text: &str,
        out: &Out<'_>,
    ) -> Response<Body> {
        let Some(id) = scim::go_parse_int(id_text) else {
            return out.error(400, "Invalid user ID", "invalidValue");
        };
        let ops = match body(r)
            .await
            .and_then(|v| wire::decode_patch(&v).map_err(|()| Bad::Syntax))
        {
            Ok(ops) => ops,
            Err(bad) => return bad.reply(out),
        };
        let Some((mut current, external)) =
            scim_user_for_patch(&self.worker, token.fence.source_id, id, &now()).await
        else {
            return out.error(
                404,
                &format!("User {id_text} is not managed by this SCIM source"),
                "invalidValue",
            );
        };
        let touched = match patch::apply_user(&mut current, &ops) {
            Ok(touched) => touched,
            Err(e) => return out.http(&e),
        };
        let fields = scim::extract_user_fields(&current);
        match self
            .apply(
                token,
                &external,
                &fields,
                &current.title,
                id,
                Some(&touched),
            )
            .await
        {
            Ok(_) => {}
            Err(scim::ApplyError::Http(_)) => return out.error(500, "PATCH failed", ""),
            Err(scim::ApplyError::Status(s)) => return out.error(s, "PATCH failed", ""),
        }
        if !fields.active {
            self.revoke(id);
        }
        // Go answers with the freshly read resource.
        self.get_user(token, id_text, out).await
    }

    async fn delete_user(&self, token: &Token, id_text: &str, out: &Out<'_>) -> Response<Body> {
        let Some(id) = scim::go_parse_int(id_text) else {
            return out.error(400, "Invalid user ID", "invalidValue");
        };
        let Some((mut current, external)) =
            scim_user_for_patch(&self.worker, token.fence.source_id, id, &now()).await
        else {
            return out.error(
                404,
                &format!("User {id_text} is not managed by this SCIM source"),
                "invalidValue",
            );
        };
        if token.deletion_policy == "hard" {
            return out.error(
                409,
                "hard delete is unavailable for normalized identities; use an identity transition so the subject tombstone is retained",
                "mutability",
            );
        }
        current.active = Some(false);
        let fields = scim::extract_user_fields(&current);
        if let Err(e) = self
            .apply(token, &external, &fields, &current.title, id, None)
            .await
        {
            let status = match e {
                scim::ApplyError::Http(_) => 500,
                scim::ApplyError::Status(s) => s,
            };
            return out.error(status, "Failed to delete user", "");
        }
        self.revoke(id);
        out.no_content()
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply(
        &self,
        token: &Token,
        external: &str,
        fields: &scim::UserFields,
        title: &str,
        expected: i64,
        touched: Option<&patch::Touched>,
    ) -> Result<i64, scim::ApplyError> {
        let request = crate::jmap::random()
            .map(uuid)
            .ok_or(scim::ApplyError::Status(500))?;
        scim_apply_user(
            &self.worker,
            token.fence,
            &request,
            external,
            fields,
            title,
            expected,
            touched,
        )
        .await
    }

    /// Go's best-effort `RevokeAuthSessions`: delegates to [`AuthAuthority`] when
    /// wired (#543), else falls back to a bounded POST to the authserver.
    fn revoke(&self, user: i64) {
        if let Some(authority) = self.authority.clone() {
            tokio::spawn(async move {
                let _ = authority
                    .disable_user_sessions(setjoin_authz::auth_authority::DisableTarget::UserId(
                        user,
                    ))
                    .await;
            });
            return;
        }
        if self.authserver_url.is_empty() || self.internal_key.is_empty() {
            return;
        }
        let (url, key) = (
            format!("{}/auth/scim/disable", self.authserver_url),
            self.internal_key.clone(),
        );
        tokio::spawn(async move {
            let Ok(client) = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
            else {
                return;
            };
            let _ = client
                .post(url)
                .header("Authorization", format!("Bearer {key}"))
                .header("Content-Type", "application/json")
                .body(format!("{{\"user_id\":{user}}}"))
                .send()
                .await;
        });
    }

    // ---- groups -----------------------------------------------------------------

    async fn list_groups(&self, r: &Request<Body>, token: &Token, out: &Out<'_>) -> Response<Body> {
        let source = token.fence.source_id;
        let (start, count) = paging(r);
        let Ok(total) = scim_group_total(&self.worker, source).await else {
            return out.error(500, "Query failed", "");
        };
        let Ok(rows) = scim_list_groups(&self.worker, source, start, count).await else {
            return out.error(500, "Query failed", "");
        };
        let mut resources = vec![];
        for row in &rows {
            let members = scim_group_members(&self.worker, source, row.id).await;
            resources.push(scim::group_resource(row, &row.id.to_string(), members).json());
        }
        out.json(200, wire::list_json(total, start, &resources))
    }

    async fn get_group(&self, token: &Token, id_text: &str, out: &Out<'_>) -> Response<Body> {
        let source = token.fence.source_id;
        let Some(id) = scim::go_parse_int(id_text) else {
            return out.error(400, "Invalid group ID", "invalidValue");
        };
        match scim_get_group(&self.worker, source, id).await {
            Ok(Some(row)) => {
                let members = scim_group_members(&self.worker, source, id).await;
                out.json(200, scim::group_resource(&row, id_text, members).json())
            }
            Ok(None) => out.error(404, &format!("Group {id_text} not found"), "invalidValue"),
            Err(_) => out.error(500, "Query failed", ""),
        }
    }

    /// Owner-approved security fix 2026-11-05 (#390): the member reducers read the RLS-protected
    /// `user_identity_links`, so they run on the worker credential (frozen Go ran them on the
    /// request pool, which fails under the RLS-bound application role).
    fn member_pool(&self) -> &ScopedExecutor {
        if setjoin_contracts::mutants::on("scim-members-request-pool") {
            &self.exec
        } else {
            &self.worker
        }
    }

    async fn create_group(
        &self,
        r: &mut Request<Body>,
        token: &Token,
        out: &Out<'_>,
    ) -> Response<Body> {
        let req = match body(r)
            .await
            .and_then(|v| wire::decode_group(&v).map_err(|()| Bad::Syntax))
        {
            Ok(req) => req,
            Err(bad) => return bad.reply(out),
        };
        if req.display_name.is_empty() {
            return out.error(400, "displayName is required", "invalidValue");
        }
        let ids: Vec<String> = req.members.iter().map(|m| m.value.clone()).collect();
        let id = match scim_create_group(
            self.member_pool(),
            token.fence,
            &req.external_id,
            &req.display_name,
            &ids,
        )
        .await
        {
            Ok(id) => id,
            Err(status) => return out.error(status, "Failed to create group", ""),
        };
        let group = wire::Group {
            id: id.to_string(),
            external_id: req.external_id,
            display_name: req.display_name,
            members: scim_group_members(&self.worker, token.fence.source_id, id).await,
            meta: Some(wire::Meta {
                resource_type: "Group".into(),
                location: format!("/scim/v2/Groups/{id}"),
                ..Default::default()
            }),
        };
        out.json(201, group.json())
    }

    async fn patch_group(
        &self,
        r: &mut Request<Body>,
        token: &Token,
        id_text: &str,
        out: &Out<'_>,
    ) -> Response<Body> {
        let Some(id) = scim::go_parse_int(id_text) else {
            return out.error(400, "Invalid group ID", "invalidValue");
        };
        let external = match scim_group_external_id(&self.worker, token.fence.source_id, id).await {
            Some(e) if !e.is_empty() => e,
            _ => return out.error(404, &format!("Group {id_text} not found"), "invalidValue"),
        };
        let ops = match body(r)
            .await
            .and_then(|v| wire::decode_patch(&v).map_err(|()| Bad::Syntax))
        {
            Ok(ops) => ops,
            Err(bad) => return bad.reply(out),
        };
        for op in &ops {
            let step = match patch::group_step(op) {
                Ok(step) => step,
                Err(e) => return out.http(&e),
            };
            match scim_run_group_step(self.member_pool(), token.fence, id, &external, step).await {
                Ok(()) => {}
                Err(scim::GroupFailure::Http(e)) => return out.http(&e),
                Err(scim::GroupFailure::Status(s)) => return out.error(s, "PATCH failed", ""),
            }
        }
        self.get_group(token, id_text, out).await
    }

    async fn delete_group(&self, token: &Token, id_text: &str, out: &Out<'_>) -> Response<Body> {
        let Some(id) = scim::go_parse_int(id_text) else {
            return out.error(400, "Invalid group ID", "invalidValue");
        };
        match scim_delete_group(&self.worker, token.fence, id).await {
            Err(status) => out.error(status, "Failed to delete group", ""),
            Ok(false) => out.error(404, &format!("Group {id_text} not found"), "invalidValue"),
            Ok(true) => out.no_content(),
        }
    }
}

fn scim_failure(msg: &str) -> setjoin_pg::StatementFailure {
    setjoin_pg::StatementFailure {
        sqlstate: None,
        hint: None,
        message: msg.into(),
    }
}

async fn worker_query(
    exec: &ScopedExecutor,
    contract: &'static setjoin_pg::SqlContract,
    values: &[&(dyn setjoin_pg::ToSql + Sync)],
) -> Result<Vec<setjoin_pg::Row>, setjoin_pg::StatementFailure> {
    let pool = exec
        .try_worker_pool()
        .ok_or_else(|| scim_failure("worker pool unavailable"))?;
    let mut tx = pool.begin_repeatable_read_only().await?;
    let rows = tx.query_contract(contract, values).await?;
    tx.commit().await?;
    Ok(rows)
}

async fn worker_mutate(
    exec: &ScopedExecutor,
    contract: &'static setjoin_pg::SqlContract,
    values: &[&(dyn setjoin_pg::ToSql + Sync)],
) -> Result<Vec<setjoin_pg::Row>, setjoin_pg::StatementFailure> {
    let pool = exec
        .try_worker_pool()
        .ok_or_else(|| scim_failure("worker pool unavailable"))?;
    let mut tx = pool.begin_read_write().await?;
    match tx.query_contract(contract, values).await {
        Ok(rows) => {
            tx.commit().await?;
            Ok(rows)
        }
        Err(e) => {
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}

async fn scim_token_by_hash(
    exec: &ScopedExecutor,
    sha256: &str,
) -> Result<Option<(Token, String)>, setjoin_pg::StatementFailure> {
    let rows = worker_query(
        exec,
        &setjoin_directory_sync::sql::SCIM_TOKEN_BY_HASH,
        &[&sha256],
    )
    .await?;
    rows.first().map(scim::candidate).transpose()
}

async fn scim_legacy_tokens(
    exec: &ScopedExecutor,
) -> Result<Vec<(Token, String)>, setjoin_pg::StatementFailure> {
    let rows = worker_query(exec, &setjoin_directory_sync::sql::SCIM_LEGACY_TOKENS, &[]).await?;
    rows.iter().map(scim::candidate).collect()
}

async fn scim_record_usage(exec: &ScopedExecutor, token_id: i64) {
    let _ = worker_mutate(
        exec,
        &setjoin_directory_sync::sql::SCIM_RECORD_USAGE,
        &[&token_id],
    )
    .await;
}

async fn scim_list_users(
    worker: &ScopedExecutor,
    source: i64,
    page: scim::Page,
) -> Result<scim::Listed, scim::ListError> {
    use setjoin_directory_sync::sql;
    let query_err = |_| scim::ListError::Query;
    match page {
        scim::Page::Filter(node, start, count) => {
            let fp = scim::resolve_filter(&node)?;
            let total_rows = worker_query(
                worker,
                &sql::SCIM_USERS_FILTER_COUNT,
                &[&source, &fp.attribute, &fp.operator, &fp.value],
            )
            .await
            .map_err(query_err)?;
            let total: i64 = total_rows
                .first()
                .ok_or(scim::ListError::Query)?
                .try_get(0)
                .map_err(|_| scim::ListError::Query)?;
            let offset = start - 1;
            let rows = worker_query(
                worker,
                &sql::SCIM_USERS_FILTER_LIST,
                &[
                    &source,
                    &fp.attribute,
                    &fp.operator,
                    &fp.value,
                    &count,
                    &offset,
                ],
            )
            .await
            .map_err(query_err)?;
            Ok(scim::Listed {
                rows: rows.iter().filter_map(scim::user_row).collect(),
                total,
            })
        }
        scim::Page::Sync(token, count) => {
            let cursor =
                scim::decode_sync_token(&token, source).map_err(|()| scim::ListError::Query)?;
            let rows = worker_query(
                worker,
                &sql::SCIM_USERS_SYNC_LIST,
                &[&source, &cursor, &count],
            )
            .await
            .map_err(query_err)?;
            Ok(scim::Listed {
                rows: rows.iter().filter_map(scim::user_row).collect(),
                total: 0,
            })
        }
        scim::Page::All(start, count) => {
            let total_rows = worker_query(worker, &sql::SCIM_USERS_ALL_COUNT, &[&source])
                .await
                .map_err(query_err)?;
            let total: i64 = total_rows
                .first()
                .ok_or(scim::ListError::Query)?
                .try_get(0)
                .map_err(|_| scim::ListError::Query)?;
            let offset = start - 1;
            let rows = worker_query(
                worker,
                &sql::SCIM_USERS_ALL_LIST,
                &[&source, &count, &offset],
            )
            .await
            .map_err(query_err)?;
            Ok(scim::Listed {
                rows: rows.iter().filter_map(scim::user_row).collect(),
                total,
            })
        }
    }
}

async fn scim_get_user(worker: &ScopedExecutor, source: i64, id: i64) -> Option<scim::UserRow> {
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_USER_GET,
        &[&source, &id],
    )
    .await
    .ok()?;
    rows.first().and_then(scim::user_row)
}

async fn scim_source_subject(worker: &ScopedExecutor, source: i64, user: i64) -> Option<String> {
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_SOURCE_SUBJECT,
        &[&source, &user],
    )
    .await
    .ok()?;
    rows.first()?.try_get(0).ok()
}

async fn scim_user_for_patch(
    worker: &ScopedExecutor,
    source: i64,
    user: i64,
    now: &str,
) -> Option<(wire::User, String)> {
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_USER_FOR_PATCH,
        &[&source, &user],
    )
    .await
    .ok()?;
    rows.first()
        .and_then(|row| scim::decode_patch_row(row, user, now))
}

#[allow(clippy::too_many_arguments)]
async fn scim_apply_user(
    worker: &ScopedExecutor,
    fence: scim::Fence,
    request: &str,
    external_id: &str,
    fields: &scim::UserFields,
    title: &str,
    expected: i64,
    touched: Option<&patch::Touched>,
) -> Result<i64, scim::ApplyError> {
    let payload =
        scim::build_apply_user_payload(fence, external_id, fields, title, expected, touched)?;
    let rows = worker_mutate(
        worker,
        &setjoin_directory_sync::sql::SCIM_USER_APPLY,
        &[
            &fence.source_id,
            &fence.generation,
            &request,
            &external_id,
            &payload,
        ],
    )
    .await
    .map_err(|e| scim::ApplyError::Status(scim::reducer_status(&e)))?;
    let raw: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or(scim::ApplyError::Status(500))?;
    scim::parse_apply_user_result(&raw)
}

async fn scim_group_total(
    worker: &ScopedExecutor,
    source: i64,
) -> Result<i64, setjoin_pg::StatementFailure> {
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_GROUP_TOTAL,
        &[&source],
    )
    .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| scim_failure("count"))
}

async fn scim_list_groups(
    worker: &ScopedExecutor,
    source: i64,
    start: i64,
    count: i64,
) -> Result<Vec<scim::GroupRow>, setjoin_pg::StatementFailure> {
    let offset = start - 1;
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_GROUP_LIST,
        &[&source, &count, &offset],
    )
    .await?;
    Ok(rows.iter().filter_map(scim::group_row).collect())
}

async fn scim_get_group(
    worker: &ScopedExecutor,
    source: i64,
    id: i64,
) -> Result<Option<scim::GroupRow>, setjoin_pg::StatementFailure> {
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_GROUP_GET,
        &[&id, &source],
    )
    .await?;
    Ok(rows.first().and_then(scim::group_row))
}

async fn scim_group_members(worker: &ScopedExecutor, source: i64, group: i64) -> Vec<wire::Member> {
    let Ok(rows) = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_GROUP_MEMBERS,
        &[&group, &source],
    )
    .await
    else {
        return vec![];
    };
    rows.iter().filter_map(scim::group_member_row).collect()
}

async fn scim_group_external_id(worker: &ScopedExecutor, source: i64, id: i64) -> Option<String> {
    let rows = worker_query(
        worker,
        &setjoin_directory_sync::sql::SCIM_GROUP_EXTERNAL_ID,
        &[&id, &source],
    )
    .await
    .ok()?;
    rows.first()?.try_get(0).ok()
}

async fn scim_create_group(
    exec: &ScopedExecutor,
    fence: scim::Fence,
    external_id: &str,
    display_name: &str,
    members: &[String],
) -> Result<i64, u16> {
    let members = members.to_vec();
    let rows = worker_mutate(
        exec,
        &setjoin_directory_sync::sql::SCIM_GROUP_CREATE,
        &[
            &fence.source_id,
            &fence.generation,
            &external_id,
            &display_name,
            &members,
        ],
    )
    .await
    .map_err(|e| scim::reducer_status(&e))?;
    rows.first().and_then(|r| r.try_get(0).ok()).ok_or(500)
}

async fn scim_run_group_step(
    exec: &ScopedExecutor,
    fence: scim::Fence,
    group: i64,
    external_id: &str,
    step: patch::GroupStep,
) -> Result<(), scim::GroupFailure> {
    use patch::GroupStep::*;
    use setjoin_directory_sync::sql;
    let status =
        |e: setjoin_pg::StatementFailure| scim::GroupFailure::Status(scim::reducer_status(&e));
    match step {
        Rename(name) => {
            let rows = worker_mutate(
                exec,
                &sql::SCIM_GROUP_UPSERT,
                &[&fence.source_id, &fence.generation, &external_id, &name],
            )
            .await
            .map_err(status)?;
            let updated: i64 = rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or(scim::GroupFailure::Status(500))?;
            if updated != group {
                return Err(scim::GroupFailure::Http(patch::http(
                    404,
                    "Group is not managed by this SCIM source",
                    "noTarget",
                )));
            }
            Ok(())
        }
        Replace(ids) => {
            worker_mutate(
                exec,
                &sql::SCIM_GROUP_APPLY_MEMBERS,
                &[
                    &fence.source_id,
                    &fence.generation,
                    &external_id,
                    &ids,
                    &true,
                ],
            )
            .await
            .map_err(status)?;
            Ok(())
        }
        Add(ids) => {
            worker_mutate(
                exec,
                &sql::SCIM_GROUP_APPLY_MEMBERS,
                &[
                    &fence.source_id,
                    &fence.generation,
                    &external_id,
                    &ids,
                    &false,
                ],
            )
            .await
            .map_err(status)?;
            Ok(())
        }
        Remove(ids) => {
            worker_mutate(
                exec,
                &sql::SCIM_GROUP_REMOVE_MEMBERS,
                &[&fence.source_id, &fence.generation, &external_id, &ids],
            )
            .await
            .map_err(status)?;
            Ok(())
        }
    }
}

async fn scim_delete_group(
    worker: &ScopedExecutor,
    fence: scim::Fence,
    group: i64,
) -> Result<bool, u16> {
    let rows = worker_mutate(
        worker,
        &setjoin_directory_sync::sql::SCIM_GROUP_DELETE,
        &[&fence.source_id, &fence.generation, &group],
    )
    .await
    .map_err(|e| scim::reducer_status(&e))?;
    rows.first().and_then(|r| r.try_get(0).ok()).ok_or(500)
}

/// Go `notify.SendWelcomeEmail(ctx, workerPool, id, "", logger)`: idempotent,
/// best effort, never fails the request. Delivery is the `deliver` reducer.
pub(crate) async fn send_welcome(worker: &ScopedExecutor, user: i64) {
    use setjoin_directory_sync::sql;
    let sentinel = format!("system:welcome:{user}");
    let Ok(rows) = worker_query(worker, &sql::WELCOME_SENTINEL_EXISTS, &[&user, &sentinel]).await
    else {
        return;
    };
    if rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()) != Some(false) {
        return;
    }
    let Ok(rows) = worker_query(worker, &sql::WELCOME_CONFIG_GET, &[]).await else {
        return;
    };
    let Some(Some(raw)) = rows
        .first()
        .map(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
    else {
        return;
    };
    let Ok(config) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let Some(template) = scim::welcome_template(&config) else {
        return;
    };
    let Ok(rows) = worker_query(worker, &sql::WELCOME_PRIMARY_MAILBOX, &[&user]).await else {
        return;
    };
    let Some(mailbox) = rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()) else {
        return;
    };
    let Ok(rows) = worker_query(worker, &sql::WELCOME_RECIPIENT_PROFILE, &[&mailbox]).await else {
        return;
    };
    let Some(row) = rows.first() else { return };
    let (Ok(mut display), Ok(username), Ok(email)) = (
        row.try_get::<_, String>(0),
        row.try_get::<_, String>(1),
        row.try_get::<_, String>(2),
    ) else {
        return;
    };
    let (local, domain) = match email.rfind('@') {
        Some(at) => (&email[..at], &email[at + 1..]),
        None => ("", email.as_str()),
    };
    if display.is_empty() {
        display = if local.is_empty() {
            email.clone()
        } else {
            local.to_owned()
        };
    }
    let values = [
        ("DisplayName", display),
        ("Email", email.clone()),
        ("Username", username),
        ("OrgName", domain.to_owned()),
        ("WebmailURL", format!("https://{domain}")),
    ];
    let substitute = |text: &str| {
        let mut out = text.to_owned();
        for (key, value) in &values {
            out = out.replace(&format!("{{{{{key}}}}}"), value);
        }
        out
    };
    let (subject, body_text, body_html) = (
        substitute(&template.0),
        substitute(&template.1),
        substitute(&template.2),
    );
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let message_id = format!("welcome-{user}-{nanos}@setjoin");
    let from = format!("noreply@{domain}");
    let to = format!(
        "[{{\"email\":{},\"name\":\"\"}}]",
        serde_json::to_string(&email).unwrap_or_default()
    );
    let size = (body_text.len() + body_html.len()) as i64;
    let _ = worker_mutate(
        worker,
        &sql::WELCOME_DELIVER,
        &[
            &sentinel,
            &message_id,
            &from,
            &"SetJoin Team",
            &email,
            &to,
            &"[]",
            &"[]",
            &subject,
            &"",
            &"",
            &body_text,
            &body_html,
            &size,
            &"none",
            &"none",
            &"none",
            &"{}",
        ],
    )
    .await;
}

const PROVIDER_CONFIG: &str = "{\"authenticationSchemes\":[{\"description\":\"SCIM API token\",\"name\":\"OAuth Bearer Token\",\"primary\":true,\"specUri\":\"http://tools.ietf.org/html/rfc6750\",\"type\":\"oauthbearertoken\"}],\"bulk\":{\"maxOperations\":0,\"maxPayloadSize\":0,\"supported\":false},\"changePassword\":{\"supported\":false},\"documentationUri\":\"\",\"etag\":{\"supported\":false},\"filter\":{\"maxResults\":1000,\"supported\":true},\"patch\":{\"supported\":true},\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig\"],\"sort\":{\"supported\":false}}";

fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn uuid(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    )
}

/// `startIndex` (>=1, default 1) and `count` (1..=1000, default 100), as Go's `Atoi` parse.
fn paging(r: &Request<Body>) -> (i64, i64) {
    let number = |name: &str| {
        input::query(r.uri(), name)
            .filter(|v| !v.is_empty())
            .and_then(|v| scim::atoi(&v))
    };
    let start = number("startIndex").filter(|n| *n >= 1).unwrap_or(1);
    let count = number("count")
        .filter(|n| (1..=1000).contains(n))
        .unwrap_or(100);
    (start, count)
}

async fn verify(token: &[u8], hash: String) -> bool {
    let token = token.to_vec();
    tokio::task::spawn_blocking(move || bcrypt::verify(token, &hash).unwrap_or(false))
        .await
        .unwrap_or(false)
}

enum Bad {
    TooLarge,
    Syntax,
}
impl Bad {
    fn reply(&self, out: &Out<'_>) -> Response<Body> {
        match self {
            // net/http also closes the connection after a MaxBytesReader overrun; the
            // front door's proxy hop strips that header, so Rust leaves it out too.
            Bad::TooLarge => out.error(413, "Request body exceeds the 1 MiB SCIM limit", ""),
            Bad::Syntax => out.error(400, "Invalid JSON body", "invalidSyntax"),
        }
    }
}

/// `json.NewDecoder(http.MaxBytesReader(w, r.Body, 1 MiB)).Decode(v)`: the first
/// JSON value, 413 only when the limit is reached before it is complete.
async fn body(r: &mut Request<Body>) -> Result<Value, Bad> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut exceeded = false;
    while let Some(frame) = r.body_mut().frame().await {
        let Ok(frame) = frame else {
            return Err(Bad::Syntax);
        };
        if let Ok(data) = frame.into_data() {
            let room = BODY_LIMIT - bytes.len();
            if data.len() > room {
                bytes.extend_from_slice(&data[..room]);
                exceeded = true;
                break;
            }
            bytes.extend_from_slice(&data);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<Value>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        Some(Err(e)) if e.is_eof() && exceeded => Err(Bad::TooLarge),
        _ => Err(Bad::Syntax),
    }
}
