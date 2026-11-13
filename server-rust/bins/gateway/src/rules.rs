//! F09 transport and admission; business operations live in setjoin-rules.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct RulesRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Intercept for RulesRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        let method = if *r.method() == Method::HEAD {
            "GET"
        } else {
            r.method().as_str()
        };
        [
            ("GET", "/api/settings/rules-list"),
            ("POST", "/api/settings/rules"),
            ("PUT", "/api/settings/rules/{id}"),
            ("DELETE", "/api/settings/rules/{id}"),
            ("POST", "/api/settings/rules/{id}/apply"),
            ("GET", "/api/settings/rules/apply/{actionId}"),
            ("GET", "/api/admin/rules"),
            ("GET", "/api/admin/rules/{id}"),
            ("POST", "/api/admin/rules"),
            ("PUT", "/api/admin/rules/{id}"),
            ("DELETE", "/api/admin/rules/{id}"),
            ("POST", "/api/admin/rules/{id}/test"),
            ("GET", "/api/admin/rule-templates"),
            ("GET", "/api/admin/rule-templates/{id}"),
            ("GET", "/api/admin/rule-templates/{id}/resolve"),
            ("POST", "/api/admin/rule-templates"),
            ("PUT", "/api/admin/rule-templates/{id}"),
            ("DELETE", "/api/admin/rule-templates/{id}"),
            ("GET", "/api/admin/rule-templates/{id}/visibility"),
            ("POST", "/api/admin/rule-templates/{id}/visibility"),
            ("GET", "/api/settings/rule-templates"),
        ]
        .iter()
        .any(|(m, p)| method == *m && crate::inventory::path_score(p, r.uri().path()).is_some())
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (e, k, i) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&e, &k, &i, &h, s)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (e, w, k, i) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        Box::pin(async move {
            let external_path = decoded(r.uri().path());
            // Shared admission still defers security shapes owned by #420/#405.
            let Some(auth) =
                setjoin_authz::authorize_request(&e, &k, &i, r.headers(), c.identity.proto).await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(op) = crate::jmap::random() else {
                return crate::mailboxes::bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), op);
            if external_path.as_str() == "/api/settings/rule-templates" {
                return match setjoin_rules::templates::list(&e, auth.context()).await {
                    Ok(body) => reply(body, 200, &c, &id),
                    Err(_) => crate::mailboxes::bare(500, "database error", &c, &id),
                };
            }
            if external_path.as_str().starts_with("/api/admin/") {
                let required: &[&str] = if matches!(*r.method(), Method::GET | Method::HEAD)
                    || external_path.as_str().ends_with("/test")
                {
                    &setjoin_rules::authority::MAIL_CONSOLE
                } else {
                    &setjoin_rules::authority::PIPELINE
                };
                let authority = match setjoin_rules::authority::resolve(&e, auth.context()).await {
                    Ok(v) => v,
                    // Owner-approved security fix 2026-11-05 (#484): a failed authority
                    // lookup drops the signed grants (fail closed) instead of keeping them.
                    Err(_) => setjoin_rules::authority::lookup_failed(auth.context()),
                };
                let path = external_path
                    .as_str()
                    .strip_prefix("/api")
                    .unwrap_or(external_path.as_str());
                if !authority.allows(required) {
                    setjoin_rules::authority::denied(
                        &e,
                        auth.context(),
                        path,
                        &required.join("|"),
                        op,
                    )
                    .await;
                    return crate::mailboxes::bare(403, "Forbidden", &c, &id);
                }
                if let Some(domain) = authority
                    .domain
                    .filter(|_| external_path.as_str().starts_with("/api/admin/rules"))
                {
                    setjoin_rules::authority::denied(
                        &e,
                        auth.context(),
                        path,
                        &format!(
                            "org-wide-only surface (domain-scoped principal; domain={domain})"
                        ),
                        op,
                    )
                    .await;
                    return crate::mailboxes::bare(403, "Forbidden", &c, &id);
                }
                if external_path
                    .as_str()
                    .starts_with("/api/admin/rule-templates/")
                    && external_path.as_str().ends_with("/visibility")
                {
                    let Some(target) = numeric_target(&r) else {
                        return crate::mailboxes::bare(400, "invalid template id", &c, &id);
                    };
                    if *r.method() == Method::POST {
                        let Some(body) =
                            decode::<setjoin_rules::input::Visibility>(&mut r, usize::MAX).await
                        else {
                            return crate::mailboxes::bare(400, "invalid JSON", &c, &id);
                        };
                        return match setjoin_rules::templates::set_visibility(
                            &e,
                            auth.context(),
                            target,
                            &body,
                            op,
                        )
                        .await
                        {
                            setjoin_pg::CommandOutcome::Committed(_) => {
                                reply(String::new(), 204, &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    return match setjoin_rules::templates::visibility(&e, target).await {
                        Ok(body) => reply(body, 200, &c, &id),
                        Err(_) => crate::mailboxes::bare(500, "database error", &c, &id),
                    };
                }
                if external_path
                    .as_str()
                    .starts_with("/api/admin/rule-templates/")
                    && external_path.as_str().ends_with("/resolve")
                {
                    let Some(target) = numeric_target(&r) else {
                        return crate::mailboxes::bare(400, "invalid template id", &c, &id);
                    };
                    return match setjoin_rules::templates::resolve(&e, target).await {
                        Ok(Some(body)) => reply(body, 200, &c, &id),
                        _ => crate::mailboxes::bare(404, "template not found", &c, &id),
                    };
                }
                if crate::inventory::path_score("/api/admin/rule-templates/{id}", r.uri().path())
                    .is_some()
                {
                    let Some(target) = numeric_target(&r) else {
                        return crate::mailboxes::bare(400, "invalid template id", &c, &id);
                    };
                    if *r.method() == Method::DELETE {
                        return match setjoin_rules::templates::delete(
                            &e,
                            auth.context(),
                            target,
                            op,
                        )
                        .await
                        {
                            setjoin_pg::CommandOutcome::Committed(v) if v == "true" => {
                                reply(String::new(), 204, &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Committed(_) => crate::mailboxes::bare(
                                403,
                                "cannot delete system template or template not found",
                                &c,
                                &id,
                            ),
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    if *r.method() == Method::PUT {
                        let Some(body) =
                            decode::<setjoin_rules::input::Template>(&mut r, usize::MAX).await
                        else {
                            return crate::mailboxes::bare(400, "invalid JSON", &c, &id);
                        };
                        return match setjoin_rules::templates::update(
                            &e,
                            auth.context(),
                            target,
                            &body,
                            op,
                        )
                        .await
                        {
                            setjoin_pg::CommandOutcome::Committed(v) if v == "true" => {
                                reply(String::new(), 204, &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Committed(_) => {
                                crate::mailboxes::bare(404, "template not found", &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    return match setjoin_rules::templates::get(&e, target).await {
                        Ok(Some(body)) => reply(body, 200, &c, &id),
                        _ => crate::mailboxes::bare(404, "template not found", &c, &id),
                    };
                }
                if external_path.as_str() == "/api/admin/rule-templates" {
                    if *r.method() == Method::POST {
                        let Some(body) =
                            decode::<setjoin_rules::input::Template>(&mut r, usize::MAX).await
                        else {
                            return crate::mailboxes::bare(400, "invalid JSON", &c, &id);
                        };
                        return match setjoin_rules::templates::create(&e, auth.context(), &body, op)
                            .await
                        {
                            setjoin_pg::CommandOutcome::Committed(v) => {
                                reply(format!("{{\"id\":{v}}}\n"), 201, &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    return match setjoin_rules::templates::list(&e, auth.context()).await {
                        Ok(body) => reply(body, 200, &c, &id),
                        Err(_) => crate::mailboxes::bare(500, "database error", &c, &id),
                    };
                }
                if *r.method() == Method::POST && external_path.as_str() == "/api/admin/rules" {
                    if let Some(value) =
                        crate::admin_identity_input::query(r.uri(), "from_template")
                            .filter(|s| !s.is_empty())
                    {
                        let Some(target) = value.parse::<i64>().ok() else {
                            return crate::mailboxes::bare(400, "invalid template id", &c, &id);
                        };
                        let template = match setjoin_rules::templates::load(&w, target).await {
                            Ok(Some(t)) => t,
                            _ => return crate::mailboxes::bare(404, "template not found", &c, &id),
                        };
                        let Some(params) = decode::<
                            Option<std::collections::HashMap<String, Option<String>>>,
                        >(&mut r, usize::MAX)
                        .await
                        else {
                            return crate::mailboxes::bare(400, "invalid parameters JSON", &c, &id);
                        };
                        return match setjoin_rules::templates::instantiate(
                            &w,
                            auth.context(),
                            &template,
                            &params.unwrap_or_default(),
                            op,
                        )
                        .await
                        {
                            setjoin_pg::CommandOutcome::Committed(v) => reply(
                                format!(
                                    "{{\"category\":{},\"id\":{v},\"name\":{}}}\n",
                                    crate::problem::go_string(&template.category),
                                    crate::problem::go_string(&template.name)
                                ),
                                201,
                                &c,
                                &id,
                            ),
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    let Some(mut body) =
                        decode::<setjoin_rules::input::Rule>(&mut r, usize::MAX).await
                    else {
                        return crate::mailboxes::bare(400, "invalid JSON", &c, &id);
                    };
                    if body.name.is_empty() {
                        return crate::mailboxes::bare(400, "name is required", &c, &id);
                    }
                    if body.run_on.is_empty() {
                        body.run_on = "server".into()
                    }
                    if let Some(mb) = body.mailbox_id {
                        if !setjoin_rules::mailbox_exists(&w, mb).await {
                            return crate::mailboxes::bare(400, "mailbox not found", &c, &id);
                        }
                    } else if !body.transport {
                        return crate::mailboxes::bare(
                            400,
                            "mailbox_id required for non-transport rules",
                            &c,
                            &id,
                        );
                    }
                    return match setjoin_rules::admin_create(&w, auth.context(), &body, op).await {
                        setjoin_pg::CommandOutcome::Committed(v) => {
                            reply(format!("{{\"id\":{v}}}\n"), 201, &c, &id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            crate::mailboxes::unknown_outcome(operation, &c, &id)
                        }
                        _ => crate::mailboxes::bare(500, "database error", &c, &id),
                    };
                }
                if external_path.as_str() != "/api/admin/rules" {
                    let Some(target) = numeric_target(&r) else {
                        return crate::mailboxes::bare(400, "invalid rule id", &c, &id);
                    };
                    if *r.method() == Method::POST && external_path.as_str().ends_with("/test") {
                        return match setjoin_rules::admin_test(&w, target).await {
                            Ok(false) => crate::mailboxes::bare(404, "rule not found", &c, &id),
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    if *r.method() == Method::DELETE {
                        return match setjoin_rules::admin_delete(&w, auth.context(), target, op)
                            .await
                        {
                            setjoin_pg::CommandOutcome::Committed(v) if v == "true" => {
                                reply(String::new(), 204, &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Committed(_) => {
                                crate::mailboxes::bare(404, "rule not found", &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    if *r.method() == Method::PUT {
                        let Some(body) =
                            decode::<setjoin_rules::input::Rule>(&mut r, usize::MAX).await
                        else {
                            return crate::mailboxes::bare(400, "invalid JSON", &c, &id);
                        };
                        return match setjoin_rules::admin_update(
                            &w,
                            auth.context(),
                            target,
                            &body,
                            op,
                        )
                        .await
                        {
                            setjoin_pg::CommandOutcome::Committed(v) if v == "true" => {
                                reply(String::new(), 204, &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Committed(_) => {
                                crate::mailboxes::bare(404, "rule not found", &c, &id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                crate::mailboxes::unknown_outcome(operation, &c, &id)
                            }
                            _ => crate::mailboxes::bare(500, "database error", &c, &id),
                        };
                    }
                    return match setjoin_rules::admin_get(&w, target).await {
                        Ok(Some(body)) => reply(body, 200, &c, &id),
                        Ok(None) => crate::mailboxes::bare(404, "rule not found", &c, &id),
                        Err(_) => crate::mailboxes::bare(500, "database error", &c, &id),
                    };
                }
                let mailbox = crate::admin_identity_input::query(r.uri(), "mailboxId")
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::admin_identity_input::atoi(&v));
                return match setjoin_rules::admin_list(&w, mailbox).await {
                    Ok(body) => reply(body, 200, &c, &id),
                    Err(_) => crate::mailboxes::bare(500, "database error", &c, &id),
                };
            }
            if matches!(*r.method(), Method::GET | Method::HEAD)
                && external_path
                    .as_str()
                    .starts_with("/api/settings/rules/apply/")
            {
                let target = segment(&r, 5);
                return match setjoin_rules::apply_status(&e, auth.context(), &target).await {
                    Ok(Some(body)) => reply(body, 200, &c, &id),
                    _ => typed(&r, &c, &id, 404, "not-found", "apply job not found", None),
                };
            }
            if *r.method() == Method::POST && external_path.as_str().ends_with("/apply") {
                let Some(target) = numeric_target(&r) else {
                    return typed(
                        &r,
                        &c,
                        &id,
                        400,
                        "validation-failed",
                        "invalid rule id",
                        None,
                    );
                };
                let Some(mut body) = decode::<setjoin_rules::input::Retro>(&mut r, 4 << 10).await
                else {
                    return typed(&r, &c, &id, 400, "invalid-json", "invalid JSON", None);
                };
                if body.window.is_empty() {
                    body.window = "90d".into()
                }
                if !["90d", "1y", "all"].contains(&body.window.as_str()) {
                    return typed(
                        &r,
                        &c,
                        &id,
                        400,
                        "validation-failed",
                        "window must be 90d, 1y, or all",
                        None,
                    );
                }
                match setjoin_rules::active_sweeps(&e,auth.context()).await {
                    Ok(n) if n>=3=>return typed(&r,&c,&id,429,"rate-limited","this mailbox already has the maximum number of rule sweeps in progress; wait for one to finish",Some("Too many active rule sweeps")),
                    Err(_)=>return typed(&r,&c,&id,500,"internal-error","database error",None),_=>{}
                }
                return match setjoin_rules::apply(&e, auth.context(), target, &body.window, op)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(v) if v == "cap" => typed(&r,&c,&id,429,"rate-limited","this mailbox already has the maximum number of rule sweeps in progress; wait for one to finish",Some("Too many active rule sweeps")),
                    setjoin_pg::CommandOutcome::Committed(v) => reply(
                        format!(
                            "{{\"actionId\":{},\"status\":\"queued\"}}\n",
                            crate::problem::go_string(&v)
                        ),
                        202,
                        &c,
                        &id,
                    ),
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        crate::mailboxes::unknown_outcome(operation, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(reason) => {
                        let state = match &reason {
                            setjoin_pg::Rejection::Statement(e)
                            | setjoin_pg::Rejection::Body(e) => e.sqlstate.as_deref(),
                            _ => None,
                        };
                        match state {
                            Some("BZ121") => {
                                typed(&r, &c, &id, 404, "not-found", "rule not found", None)
                            }
                            Some("BZ120") => typed(
                                &r,
                                &c,
                                &id,
                                400,
                                "validation-failed",
                                "invalid request",
                                None,
                            ),
                            _ => typed(&r, &c, &id, 500, "internal-error", "database error", None),
                        }
                    }
                };
            }
            if *r.method() == Method::DELETE {
                let Some(target) = numeric_target(&r) else {
                    return crate::mailboxes::bare(400, "invalid rule id", &c, &id);
                };
                return match setjoin_rules::personal_delete(&e, auth.context(), target, op).await {
                    setjoin_pg::CommandOutcome::Committed(v) if v == "true" => {
                        reply(String::new(), 204, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Committed(_) => {
                        crate::mailboxes::bare(404, "rule not found", &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        crate::mailboxes::unknown_outcome(operation, &c, &id)
                    }
                    _ => crate::mailboxes::bare(500, "database error", &c, &id),
                };
            }
            if matches!(*r.method(), Method::POST | Method::PUT) {
                let creating = *r.method() == Method::POST;
                let target = if creating {
                    0
                } else {
                    match numeric_target(&r) {
                        Some(v) => v,
                        None => return crate::mailboxes::bare(400, "invalid rule id", &c, &id),
                    }
                };
                let Some(mut body) = decode::<setjoin_rules::input::Rule>(&mut r, 64 << 10).await
                else {
                    return crate::mailboxes::bare(400, "invalid JSON", &c, &id);
                };
                if let Err(detail) = setjoin_rules::input::validate(&mut body, creating) {
                    return crate::mailboxes::bare(400, &detail, &c, &id);
                }
                if creating {
                    match setjoin_rules::personal_count(&e, auth.context()).await {
                        Ok(n) if n >= 100 => {
                            return crate::mailboxes::bare(
                                400,
                                "rule limit reached for this mailbox",
                                &c,
                                &id,
                            )
                        }
                        Err(_) => return crate::mailboxes::bare(500, "database error", &c, &id),
                        _ => {}
                    }
                }
                let outcome = if creating {
                    setjoin_rules::personal_create(&e, auth.context(), &body, op).await
                } else {
                    setjoin_rules::personal_update(&e, auth.context(), target, &body, op).await
                };
                return match outcome {
                    setjoin_pg::CommandOutcome::Committed(v) if creating && v == "cap" => {
                        crate::mailboxes::bare(400, "rule limit reached for this mailbox", &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Committed(v) if creating => {
                        reply(format!("{{\"id\":{v}}}\n"), 201, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Committed(v) if v == "true" => {
                        reply(String::new(), 204, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Committed(_) => {
                        crate::mailboxes::bare(404, "rule not found", &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        crate::mailboxes::unknown_outcome(operation, &c, &id)
                    }
                    _ => crate::mailboxes::bare(500, "database error", &c, &id),
                };
            }
            match setjoin_rules::personal_list(&e, auth.context()).await {
                Ok(body) => crate::jmap::reply::response(body, c.identity.proto, id),
                Err(_) => crate::mailboxes::bare(500, "database error", &c, &id),
            }
        })
    }
}

fn decoded(path: &str) -> String {
    String::from_utf8_lossy(&crate::inventory::unescape(path)).into_owned()
}
fn segment(r: &Request<Body>, index: usize) -> String {
    decoded(r.uri().path().split('/').nth(index).unwrap_or_default())
}
fn numeric_target(r: &Request<Body>) -> Option<i64> {
    segment(r, 4).parse().ok()
}

fn reply(body: String, status: u16, c: &RequestContext, id: &str) -> Response<Body> {
    let mut response = crate::jmap::reply::response(body, c.identity.proto, id.into());
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    if status == 204 {
        response.headers_mut().remove("content-type");
    }
    response
}
// Go decodes ordinary strings with replacement runes but retains RawMessage bytes.
trait Input: serde::de::DeserializeOwned {
    fn restore(&mut self, _: Vec<(String, String)>) {}
}
impl Input for setjoin_rules::input::Retro {}
impl Input for setjoin_rules::input::Visibility {}
impl Input for Option<std::collections::HashMap<String, Option<String>>> {}
macro_rules! raw_input {($t:ty,$($field:ident),+)=>{impl Input for $t {
    fn restore(&mut self,fields:Vec<(String,String)>){$(self.$field.1=self.$field.0.clone();)+ for(key,raw)in fields{match crate::guests_input::fold(&key).as_str(){
        $(stringify!($field)=>{self.$field.0=Some(raw);},)+ _=>{}
    }}}
}};}
raw_input!(setjoin_rules::input::Rule, conditions, actions);
raw_input!(
    setjoin_rules::input::Template,
    conditions,
    actions,
    parameters
);
struct RawFields(Vec<(String, String)>);
impl<'de> serde::Deserialize<'de> for RawFields {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = RawFields;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut m: M,
            ) -> Result<RawFields, M::Error> {
                let mut out = Vec::new();
                while let Some(key) = m.next_key::<String>()? {
                    out.push((
                        key,
                        m.next_value::<Box<serde_json::value::RawValue>>()?
                            .get()
                            .to_owned(),
                    ));
                }
                Ok(RawFields(out))
            }
        }
        d.deserialize_map(Fields)
    }
}
async fn decode<T: Input>(r: &mut Request<Body>, cap: usize) -> Option<T> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() <= cap {
        match r.body_mut().frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    let room = cap.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&data[..data.len().min(room)]);
                    if data.len() > room {
                        break;
                    }
                }
            }
            Some(Err(_)) => return None,
            None => break,
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut value = serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()?
        .ok()?;
    if let Some(Ok(fields)) = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<RawFields>()
        .next()
    {
        value.restore(fields.0);
    }
    Some(value)
}

fn typed(
    r: &Request<Body>,
    c: &RequestContext,
    id: &str,
    status: u16,
    kind: &str,
    detail: &str,
    title: Option<&str>,
) -> Response<Body> {
    let kind = format!("https://setjoin.com/errors/{kind}");
    let external_path = decoded(r.uri().path());
    let path = external_path.strip_prefix("/api").unwrap_or(&external_path);
    let mut p = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path);
    if let Some(title) = title {
        p = p.title(title)
    }
    crate::mailboxes::render(p, Some(&crate::mailboxes::language(r)), c, id)
}
