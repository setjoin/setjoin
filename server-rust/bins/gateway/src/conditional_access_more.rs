//! F03 Conditional access, slice `remaining` (#314): everything but the policy lifecycle routes
//! of `conditional_access.rs`. Handlers answer in Go's order of checks (path id, body decode,
//! required fields, then the database) and render Go's bytes. The simulator (#405)
//! loads a fresh snapshot and uses `setjoin_conditional_access::policy::eval`.
use crate::admin_identity_input::{first, query};
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use setjoin_authz::AuthContext;
use setjoin_conditional_access as ca;
use setjoin_conditional_access::policies::{project, project_rejection, Projected};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum More {
    Simulate,
    LocationList,
    LocationCreate,
    LocationUpdate,
    LocationDelete,
    LocationRestore,
    StrengthList,
    StrengthCreate,
    StrengthUpdate,
    StrengthDelete,
    Principals,
    BreakGlassGet,
    BreakGlassSet,
    SigninLog,
    SessionRevoke,
    SessionsLog,
    TemplatesList,
    TemplateInstantiate,
    Why,
    Impact,
    Coverage,
    Doctor,
    Export,
    Import,
    Diff,
    RiskList,
    RiskReset,
}

impl More {
    /// Go gates these with `requireCAPolicyRead` (diff is a POST but a read).
    pub(crate) fn reads(self) -> bool {
        use More::*;
        matches!(
            self,
            Simulate | LocationList
                | StrengthList
                | Principals
                | BreakGlassGet
                | SigninLog
                | SessionsLog
                | TemplatesList
                | Why
                | Impact
                | Coverage
                | Doctor
                | Export
                | Diff
                | RiskList
        )
    }
}

const BASE: &str = "/api/admin/conditional-access";

pub(crate) fn action(method: &Method, path: &str) -> Option<More> {
    use More::*;
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let (post, put, delete) = (
        *method == Method::POST,
        *method == Method::PUT,
        *method == Method::DELETE,
    );
    let rows: [(bool, String, More); 27] = [
        (reads, format!("{BASE}/named-locations"), LocationList),
        (post, format!("{BASE}/named-locations"), LocationCreate),
        (
            put,
            format!("{BASE}/named-locations/{{id}}"),
            LocationUpdate,
        ),
        (
            delete,
            format!("{BASE}/named-locations/{{id}}"),
            LocationDelete,
        ),
        (
            post,
            format!("{BASE}/named-locations/{{id}}/restore"),
            LocationRestore,
        ),
        (reads, format!("{BASE}/auth-strengths-list"), StrengthList),
        (post, format!("{BASE}/auth-strengths"), StrengthCreate),
        (put, format!("{BASE}/auth-strengths/{{id}}"), StrengthUpdate),
        (
            delete,
            format!("{BASE}/auth-strengths/{{id}}"),
            StrengthDelete,
        ),
        (reads, format!("{BASE}/resolve-principals"), Principals),
        (reads, format!("{BASE}/break-glass"), BreakGlassGet),
        (put, format!("{BASE}/break-glass"), BreakGlassSet),
        (reads, format!("{BASE}/signin-log"), SigninLog),
        (
            post,
            format!("{BASE}/sessions/{{userId}}/revoke"),
            SessionRevoke,
        ),
        (reads, format!("{BASE}/sessions/log"), SessionsLog),
        (reads, format!("{BASE}/templates-list"), TemplatesList),
        (
            post,
            format!("{BASE}/templates/{{slug}}/instantiate"),
            TemplateInstantiate,
        ),
        (reads, format!("{BASE}/why-lookup"), Why),
        (reads, format!("{BASE}/policies/{{id}}/impact"), Impact),
        (reads, format!("{BASE}/coverage"), Coverage),
        (reads, format!("{BASE}/doctor"), Doctor),
        (reads, format!("{BASE}/export"), Export),
        (post, format!("{BASE}/import"), Import),
        (post, format!("{BASE}/diff"), Diff),
        (reads, "/api/admin/user-risk".to_string(), RiskList),
        (
            post,
            "/api/admin/user-risk/{id}/reset".to_string(),
            RiskReset,
        ),
        // Placeholder keeping the table a fixed size; never matches a real path.
        (post, format!("{BASE}/simulate"), Simulate),
    ];
    rows.iter()
        .filter(|(ok, pattern, _)| {
            *ok && !pattern.is_empty() && crate::inventory::path_score(pattern, path).is_some()
        })
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, what)| *what)
}

/// What a handler needs from the front door.
pub(crate) struct Ctx<'a> {
    pub exec: &'a ScopedExecutor,
    pub worker: &'a ScopedExecutor,
    pub actor: &'a AuthContext,
    pub c: &'a RequestContext,
    pub id: &'a str,
    pub operation: [u8; 16],
    pub ip: &'a str,
    pub path: &'a str,
    pub head: bool,
}

impl Ctx<'_> {
    /// `httputil.WriteJSON`: `Cache-Control: no-store` and the JSON content type.
    fn json(&self, body: String, status: u16) -> Response<Body> {
        // net/http buffers 2 KiB of a handler's output; a larger single write is flushed
        // before the handler returns and sent chunked.
        let chunked = body.len() > 2048 && !self.head;
        let mut response =
            crate::jmap::reply::response(body, self.c.identity.proto, self.id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    }
    /// A handler that sets only the content type and writes the bytes itself.
    fn raw(&self, body: String, status: u16) -> Response<Body> {
        // Go's middleware still adds `Cache-Control: no-store` to these.
        self.json(body, status)
    }
    fn no_content(&self) -> Response<Body> {
        let mut response =
            crate::jmap::reply::response(String::new(), self.c.identity.proto, self.id.to_owned());
        *response.status_mut() = hyper::StatusCode::NO_CONTENT;
        response.headers_mut().remove("content-type");
        response
    }
    fn bare(&self, status: u16, detail: &str) -> Response<Body> {
        bare(status, detail, self.c, self.id)
    }
    fn failed(&self, p: Projected) -> Response<Body> {
        self.bare(p.status, &p.detail)
    }
    fn database(&self) -> Response<Body> {
        self.bare(500, "database error")
    }
    fn unknown(&self, operation: setjoin_contracts::ids::OperationId) -> Response<Body> {
        unknown_outcome(operation, self.c, self.id)
    }
}

/// Field-by-field decoder like Go's `json.Decoder` into a struct: keys fold case, the last
/// duplicate wins, `null` leaves a plain field at its zero value, unknown keys are ignored and a
/// wrongly typed value is a decode error.
macro_rules! body {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        struct $name { $($field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<$name, E> {
                        Ok($name::default())
                    }
                    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<$name, M::Error> {
                        let mut body = $name::default();
                        while let Some(key) = map.next_key::<String>()? {
                            match crate::guests_input::fold(&key).as_str() {
                                $($key => {
                                    if let Some(value) = map.next_value::<Option<$ty>>()? {
                                        body.$field = value;
                                    }
                                })+
                                _ => {
                                    let _: serde::de::IgnoredAny = map.next_value()?;
                                }
                            }
                        }
                        Ok(body)
                    }
                }
                decoder.deserialize_any(Fields)
            }
        }
    };
}

/// `[]string`: `null` is empty, a `null` element is the empty string.
#[derive(Default)]
struct Strings(Vec<String>);
impl<'de> serde::Deserialize<'de> for Strings {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let list = Option::<Vec<Option<String>>>::deserialize(decoder)?;
        Ok(Strings(
            list.unwrap_or_default()
                .into_iter()
                .map(Option::unwrap_or_default)
                .collect(),
        ))
    }
}

body!(LocationBody {
    name: String = "name",
    description: String = "description",
    cidrs: Strings = "cidrs",
    countries: Strings = "countries",
    trusted: bool = "is_trusted"
});

/// `authStrengthRequest`: `combinations` is a `json.RawMessage`, so a literal `null` stays text.
#[derive(Default)]
struct StrengthBody {
    slug: String,
    name: String,
    combinations: Option<Box<RawValue>>,
    min_acr: String,
}
impl<'de> serde::Deserialize<'de> for StrengthBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = StrengthBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<StrengthBody, E> {
                Ok(StrengthBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<StrengthBody, M::Error> {
                let mut body = StrengthBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "slug" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.slug = v;
                            }
                        }
                        "name" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.name = v;
                            }
                        }
                        "min_acr" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.min_acr = v;
                            }
                        }
                        "combinations" => body.combinations = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// `[]int64`: `null` is empty, a `null` element is zero, a non-array is a decode error.
struct Ids(Vec<i64>);
impl<'de> serde::Deserialize<'de> for Ids {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let list = Option::<Vec<Option<i64>>>::deserialize(decoder)?;
        Ok(Ids(list
            .unwrap_or_default()
            .into_iter()
            .map(|id| id.unwrap_or(0))
            .collect()))
    }
}

/// Go's `importDoc` as `diff` decodes it: the types of every declared field are checked.
#[derive(Default)]
struct DocPolicy {
    name: String,
    conditions: Option<Box<RawValue>>,
    actions: Option<Box<RawValue>>,
}
impl<'de> serde::Deserialize<'de> for DocPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = DocPolicy;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<DocPolicy, E> {
                Ok(DocPolicy::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<DocPolicy, M::Error> {
                let mut body = DocPolicy::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "name" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.name = v;
                            }
                        }
                        "description" | "scope_type" | "scope_target" => {
                            let _ = map.next_value::<Option<String>>()?;
                        }
                        "priority" => {
                            let _ = map.next_value::<Option<i64>>()?;
                        }
                        "conditions" => body.conditions = Some(map.next_value()?),
                        "actions" => body.actions = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
/// `[]importDocPolicy`: `null` is empty and a `null` element a zero policy.
struct DocPolicies(Vec<DocPolicy>);
impl<'de> serde::Deserialize<'de> for DocPolicies {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let list = Option::<Vec<Option<DocPolicy>>>::deserialize(decoder)?;
        Ok(DocPolicies(
            list.unwrap_or_default()
                .into_iter()
                .map(Option::unwrap_or_default)
                .collect(),
        ))
    }
}
/// A declared array field whose elements Diff never reads (`[]json.RawMessage`).
struct AnyArray;
impl<'de> serde::Deserialize<'de> for AnyArray {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        Option::<Vec<serde::de::IgnoredAny>>::deserialize(decoder).map(|_| AnyArray)
    }
}
#[derive(Default)]
struct Doc {
    policies: Vec<DocPolicy>,
}
impl<'de> serde::Deserialize<'de> for Doc {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Doc;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Doc, E> {
                Ok(Doc::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Doc, M::Error> {
                let mut body = Doc::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "schemaversion" => {
                            let _ = map.next_value::<Option<i64>>()?;
                        }
                        "generatedby" => {
                            let _ = map.next_value::<Option<String>>()?;
                        }
                        "policies" => {
                            body.policies = map.next_value::<DocPolicies>()?.0;
                        }
                        "named_locations" | "auth_strengths" => {
                            let _ = map.next_value::<AnyArray>()?;
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// The whole first value as raw text (`json.RawMessage` target); any JSON value decodes.
struct Whole(Box<RawValue>);
impl<'de> serde::Deserialize<'de> for Whole {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        Box::<RawValue>::deserialize(decoder).map(Whole)
    }
}

fn parse_ids(text: &str) -> Vec<i64> {
    text.split(',')
        .filter_map(|part| part.trim().parse::<i64>().ok())
        .collect()
}

fn some_ids(list: Vec<String>) -> Option<Vec<String>> {
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

/// Go's `strconv.Atoi` with the error ignored.
fn atoi(text: &str) -> i64 {
    crate::admin_identity_input::atoi(text)
}

pub(crate) async fn serve(what: More, r: &mut Request<Body>, x: &Ctx<'_>) -> Response<Body> {
    use More::*;
    let (exec, actor, ip, operation) = (x.exec, x.actor, x.ip, x.operation);
    let seg = |index: usize| crate::mail_security::segment(x.path, index);
    let path_id = |index: usize| seg(index).parse::<i64>().ok();
    // Owner-approved security fix 2026-11-05 (#467, #510): organization-wide CA objects (named
    // locations, auth strengths, break-glass) and the analysis reads over every policy need an
    // organization-wide access.policy grant; frozen Go gave them to any domain-scoped holder.
    let org_wide = match what {
        LocationCreate | LocationUpdate | LocationDelete | LocationRestore | StrengthCreate
        | StrengthUpdate | StrengthDelete | BreakGlassSet => Some(false),
        Simulate | Why | Coverage | BreakGlassGet => Some(true),
        // #529: the object lists, the doctor report and principal resolution answer for every
        // organization-wide CA object / user; frozen Go gave them to any domain-scoped holder.
        LocationList | StrengthList | TemplatesList | Doctor | Principals
            if !setjoin_contracts::mutants::on("ca-list-reads-any-grant") =>
        {
            Some(true)
        }
        _ => None,
    };
    if let Some(read) = org_wide {
        if let Some(refused) = org_wide_only(x, read).await {
            return refused;
        }
    }
    match what {
        Simulate => simulate(r,x).await,
        LocationList => {
            let include = query(r.uri(), "include_deleted").as_deref() == Some("1");
            match ca::locations::list(exec, include).await {
                Ok(body) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        LocationCreate | LocationUpdate => {
            let update = what == LocationUpdate;
            let id = if update {
                let Some(id) = path_id(5) else {
                    return x.bare(400, "invalid location ID");
                };
                id
            } else {
                0
            };
            let Ok(body) = first::<LocationBody>(r, 1 << 16).await else {
                return x.bare(400, "invalid JSON");
            };
            if body.name.is_empty() {
                return x.bare(400, "name is required");
            }
            let (cidrs, countries) = (some_ids(body.cidrs.0), some_ids(body.countries.0));
            let location = ca::locations::Location {
                name: &body.name,
                description: &body.description,
                cidrs: cidrs.as_deref(),
                countries: countries.as_deref(),
                trusted: body.trusted,
            };
            match ca::locations::save(exec, actor, ip, id, &location, operation).await {
                CommandOutcome::Committed(id) => x.json(ca::done(format!("{{\"id\":{id}}}")), 200),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        LocationDelete => {
            let Some(id) = path_id(5) else {
                return x.bare(400, "invalid location ID");
            };
            match ca::locations::soft_delete(exec, actor, ip, id, operation).await {
                CommandOutcome::Committed(()) => x.no_content(),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        LocationRestore => {
            let Some(id) = path_id(5) else {
                return x.bare(400, "invalid location ID");
            };
            match ca::locations::restore(exec, actor, ip, id, operation).await {
                CommandOutcome::Committed(id) => x.json(ca::done(format!("{{\"id\":{id}}}")), 200),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        StrengthList => match ca::strengths::list(exec).await {
            Ok(body) => x.json(body, 200),
            Err(_) => x.database(),
        },
        StrengthCreate | StrengthUpdate => {
            let update = what == StrengthUpdate;
            let id = if update {
                let Some(id) = path_id(5) else {
                    return x.bare(400, "invalid strength ID");
                };
                id
            } else {
                0
            };
            let Ok(body) = first::<StrengthBody>(r, 1 << 16).await else {
                return x.bare(400, "invalid JSON");
            };
            if !update {
                if body.slug.is_empty() {
                    return x.bare(400, "slug is required");
                }
                if body.name.is_empty() {
                    return x.bare(400, "name is required");
                }
            }
            let strength = ca::strengths::Strength {
                slug: &body.slug,
                name: &body.name,
                combinations: body.combinations.as_deref().map(RawValue::get),
                min_acr: &body.min_acr,
            };
            match ca::strengths::save(exec, actor, ip, id, &strength, operation).await {
                CommandOutcome::Committed(id) => x.json(ca::done(format!("{{\"id\":{id}}}")), 200),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        StrengthDelete => {
            let Some(id) = path_id(5) else {
                return x.bare(400, "invalid strength ID");
            };
            match ca::strengths::delete(exec, actor, ip, id, operation).await {
                CommandOutcome::Committed(()) => x.no_content(),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        Principals => {
            let users = query(r.uri(), "users")
                .map(|t| parse_ids(&t))
                .unwrap_or_default();
            let groups = query(r.uri(), "groups")
                .map(|t| parse_ids(&t))
                .unwrap_or_default();
            match ca::console::principals(exec, &users, &groups).await {
                Ok(body) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        BreakGlassGet => match ca::console::break_glass(exec).await {
            Ok(body) => x.json(body, 200),
            Err(_) => x.database(),
        },
        BreakGlassSet => {
            let Ok(ids) = first::<Ids>(r, 1 << 16).await else {
                return x.bare(400, "invalid JSON: expected array of user IDs");
            };
            if ids.0.is_empty() {
                return x.bare(400, "at least one user ID required");
            }
            match ca::console::set_break_glass(exec, actor, ip, &ids.0, operation).await {
                CommandOutcome::Committed(()) => x.no_content(),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        SigninLog => {
            let limit = atoi(&query(r.uri(), "limit").unwrap_or_default());
            let limit = if limit <= 0 || limit > 500 { 50 } else { limit };
            let corr = query(r.uri(), "correlation_id").unwrap_or_default();
            let user = query(r.uri(), "user_id")
                .unwrap_or_default()
                .parse::<i64>()
                .ok();
            if corr.is_empty() && user.is_none() {
                return x.bare(400, "user_id or correlation_id required");
            }
            // A correlation-id lookup spans every user: org-wide grant; a user lookup: reach.
            if !corr.is_empty() {
                if let Some(refused) = org_wide_only(x, true).await {
                    return refused;
                }
            } else if let Some(user) = user {
                match ca::policies::user_in_reach(exec, actor, user).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return x.bare(403, "target user is outside your administrative scope")
                    }
                    Err(_) => return x.database(),
                }
            }
            match ca::console::signin_log(
                exec,
                (!corr.is_empty()).then_some(corr.as_str()),
                user,
                limit,
            )
            .await
            {
                Ok(body) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        SessionRevoke => {
            let Some(target) = path_id(5) else {
                return x.bare(400, "invalid user id");
            };
            match ca::console::can_reach(exec, actor.user_id(), target).await {
                Err(_) => return x.database(),
                Ok(false) => {
                    return x.bare(403, "target user is outside your administrative scope");
                }
                Ok(true) => {}
            }
            match ca::console::revoke_sessions(exec, actor, target, operation).await {
                CommandOutcome::Committed(id) => {
                    x.json(ca::done(format!("{{\"revocation_id\":{id}}}")), 200)
                }
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        SessionsLog => match ca::console::sessions_log(x.worker, actor).await {
            Ok(body) => x.json(body, 200),
            Err(_) => x.database(),
        },
        TemplatesList => match ca::console::templates(exec).await {
            Ok(body) => x.json(body, 200),
            Err(_) => x.database(),
        },
        TemplateInstantiate => {
            let slug = seg(5);
            if slug.is_empty() {
                return x.bare(400, "slug is required");
            }
            if let Some(refused) = org_wide_only(x, false).await {
                return refused;
            }
            match ca::console::instantiate(exec, actor, &slug, operation).await {
                CommandOutcome::Committed(id) => match ca::console::instantiated(exec, id).await {
                    Ok(body) => x.raw(body, 201),
                    Err(_) => x.bare(500, "policy created but read failed"),
                },
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        Why => {
            let user = query(r.uri(), "user").unwrap_or_default();
            let corr = query(r.uri(), "correlation_id").unwrap_or_default();
            let since = query(r.uri(), "since").unwrap_or_default();
            if user.is_empty() && corr.is_empty() {
                return x.bare(400, "user or correlation_id is required");
            }
            let seconds = match since.as_str() {
                "" | "7d" => 7 * 86400,
                "24h" => 86400,
                "30d" => 30 * 86400,
                _ => return x.bare(400, "since must be one of: 24h, 7d, 30d"),
            };
            match ca::console::why(exec, &user, &corr, seconds).await {
                Ok(ca::console::Why::NotFound) => x.json(ca::done("{\"found\":false}".into()), 404),
                Ok(ca::console::Why::Found(body)) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        Impact => {
            let Some(policy) = path_id(5) else {
                return x.bare(400, "invalid policy ID");
            };
            let window = query(r.uri(), "window")
                .filter(|w| !w.is_empty())
                .unwrap_or("7d".into());
            let list = query(r.uri(), "list").filter(|l| !l.is_empty());
            // Owner-approved security fix 2026-11-05 (#467): only a policy in the caller's reach.
            match ca::policies::gate(exec, actor, Some(policy), None, None, true).await {
                Ok(ca::policies::Gate::Allowed) => {}
                Ok(_) => return x.failed(ca::policies::not_found()),
                Err(_) => return x.database(),
            }
            match ca::console::impact(exec, actor, policy, &window, list.as_deref()).await {
                Ok(body) => x.raw(body, 200),
                Err(e) => {
                    // 22023 (bad window or list) is a 400 whose detail is the generic text.
                    if e.sqlstate.as_deref() == Some("22023") {
                        x.bare(400, "request failed")
                    } else {
                        x.failed(project(&e))
                    }
                }
            }
        }
        Coverage => match ca::console::coverage(exec).await {
            Ok(body) => x.raw(body, 200),
            Err(_) => x.database(),
        },
        Doctor => match ca::console::doctor(exec).await {
            Ok(body) => x.raw(body, 200),
            Err(_) => x.database(),
        },
        Export => {
            if let Some(refused) = org_wide_only(x, true).await {
                return refused;
            }
            match ca::exchange::export(exec).await {
                Ok(body) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        Import => {
            let Ok(document) = first::<Whole>(r, 4 << 20).await else {
                return x.bare(400, "invalid JSON");
            };
            if let Some(refused) = org_wide_only(x, false).await {
                return refused;
            }
            let mode = query(r.uri(), "mode")
                .filter(|m| !m.is_empty())
                .unwrap_or("merge".into());
            match ca::console::import(exec, actor, document.0.get(), &mode, operation).await {
                CommandOutcome::Committed(body) => x.raw(body, 200),
                CommandOutcome::RolledBack(e) => x.failed(project_rejection(&e)),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
        Diff => {
            let Ok(doc) = first::<Doc>(r, 4 << 20).await else {
                return x.bare(400, "invalid JSON");
            };
            if let Some(refused) = org_wide_only(x, true).await {
                return refused;
            }
            let policies: Vec<ca::exchange::DocPolicy> = doc
                .policies
                .into_iter()
                .map(|p| ca::exchange::DocPolicy {
                    name: p.name,
                    conditions: p.conditions.map(|c| c.get().to_owned()),
                    actions: p.actions.map(|a| a.get().to_owned()),
                })
                .collect();
            match ca::exchange::diff(exec, &policies).await {
                Ok(body) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        RiskList => {
            let limit = match query(r.uri(), "limit").filter(|v| !v.is_empty()) {
                Some(v) => match v.parse::<i64>() {
                    Ok(n) if n > 0 => n.min(500),
                    _ => 100,
                },
                None => 100,
            };
            match ca::risk::list(x.worker, limit).await {
                Ok(body) => x.json(body, 200),
                Err(_) => x.database(),
            }
        }
        RiskReset => {
            let Some(user) = path_id(4) else {
                return x.bare(400, "invalid user id");
            };
            match ca::risk::reset(x.worker, actor, ip, user, operation).await {
                CommandOutcome::Committed(true) => x.no_content(),
                CommandOutcome::Committed(false) => x.bare(404, "user_risk not found"),
                CommandOutcome::RolledBack(_) => x.database(),
                CommandOutcome::Unknown { operation } => x.unknown(operation),
            }
        }
    }
}

#[derive(Default)]
struct SimulateBody {
    from_signin:Option<i64>, user_id:Option<i64>, is_guest:Option<bool>,
    ip:String,client_type:String,protocol:String,country:String,device_fp:String,
    auth_method:String,device_trust:String,user_agent:String,
}
impl<'de> serde::Deserialize<'de> for SimulateBody {
    fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
        struct Fields;
        impl<'de> Visitor<'de> for Fields{
            type Value=SimulateBody;
            fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("a JSON object")}
            fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(SimulateBody::default())}
            fn visit_map<M:MapAccess<'de>>(self,mut map:M)->Result<Self::Value,M::Error>{
                let mut b=SimulateBody::default();
                while let Some(key)=map.next_key::<String>()?{
                    macro_rules! text{($field:ident)=>{if let Some(v)=map.next_value::<Option<String>>()?{b.$field=v;}}}
                    match crate::guests_input::fold(&key).as_str(){
                        "from_signin"=>b.from_signin=map.next_value()?,"user_id"=>b.user_id=map.next_value()?,"is_guest"=>b.is_guest=map.next_value()?,
                        "ip"=>text!(ip),"client_type"=>text!(client_type),"protocol"=>text!(protocol),"country"=>text!(country),"device_fp"=>text!(device_fp),
                        "auth_method"=>text!(auth_method),"device_trust"=>text!(device_trust),"user_agent"=>text!(user_agent),
                        _=>{let _:serde::de::IgnoredAny=map.next_value()?;}
                    }
                }Ok(b)
            }
        }d.deserialize_any(Fields)
    }
}
async fn simulate(r:&mut Request<Body>,x:&Ctx<'_>)->Response<Body>{
    use ca::policy::{eval::{Context,Snapshot,simulate_json},store};
    use setjoin_pg::Type;
    let Ok(b)=first::<SimulateBody>(r,1<<16).await else{return x.bare(400,"invalid JSON");};
    let mut c=Context::default();
    if let Some(id)=b.from_signin{
        let rows=x.exec.read("SELECT user_id,host(source_ip),protocol,client_type,country FROM ca_signin_log WHERE id=$1",&[(&id,Type::INT8)]).await;
        let Ok(rows)=rows else{return x.bare(400,"from_signin: row not found or invalid");};
        let Some(row)=rows.first()else{return x.bare(400,"from_signin: row not found or invalid");};
        c.user_id=row.get::<_,Option<i64>>(0).unwrap_or(0);
        c.source_ip=row.get::<_,Option<String>>(1).unwrap_or_default();
        c.protocol=row.get::<_,Option<String>>(2).unwrap_or_default();
        c.client_type=row.get::<_,Option<String>>(3).unwrap_or_default();
        c.country=row.get::<_,Option<String>>(4).unwrap_or_default();
    }
    if let Some(user)=b.user_id{c.user_id=user;}
    if c.user_id!=0{
        // The frozen simulator drops membership lookup errors, unlike live eval.
        (c.group_ids,c.role_group_ids)=store::resolve_scope(x.exec,c.user_id).await.unwrap_or_default();
        let Ok(rows)=x.exec.read("SELECT is_guest_account($1)",&[(&c.user_id,Type::INT8)]).await else{return x.database();};
        c.is_guest=rows[0].get(0);
    }else{c.is_guest=b.is_guest.unwrap_or(false);}
    for (target,value) in [(&mut c.source_ip,b.ip),(&mut c.client_type,b.client_type),(&mut c.protocol,b.protocol),(&mut c.country,b.country),(&mut c.device_fp,b.device_fp),(&mut c.auth_method,b.auth_method),(&mut c.user_agent,b.user_agent)]{if !value.is_empty(){*target=value;}}
    c.trust_tier=if b.device_trust.is_empty(){store::resolve_trust(x.exec,&c).await}else{b.device_trust};
    let Ok(geo)=store::resolve_geo(x.exec,&c.country).await else{return x.database();};c.geo_tier=geo;
    c.score_band=if matches!(c.geo_tier.as_str(),"high"|"critical"){"medium"}else{"low"}.into();
    let Ok(snapshot)=Snapshot::load(x.exec).await else{return x.database();};
    x.json(simulate_json(&snapshot,&c),200)
}

/// Owner-approved security fix 2026-11-05 (#467): the bulk policy routes (export, diff,
/// import, template instantiate) read or create organization-wide policies, so a
/// domain-scoped admin needs an organization-wide `access.policy_*` grant for them.
async fn org_wide_only(x: &Ctx<'_>, read: bool) -> Option<Response<Body>> {
    match ca::policies::org_wide(x.exec, x.actor, read).await {
        Ok(true) => None,
        Ok(false) => Some(x.bare(403, "organization-wide access.policy grant required")),
        Err(_) => Some(x.database()),
    }
}
