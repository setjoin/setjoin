//! Frozen Go's one-item contact accounting over canonical reducers.
use super::{body_error, path, read_body, reply};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use setjoin_authz::AuthContext;
use setjoin_calendar::carddav::{self, Operation};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[derive(Default, Deserialize)]
#[serde(default)]
struct Set {
    created: Option<HashMap<String, Value>>,
    #[serde(rename = "notCreated")]
    not_created: Option<HashMap<String, Value>>,
    updated: Option<Vec<i64>>,
    #[serde(rename = "notUpdated")]
    not_updated: Option<HashMap<String, Value>>,
    destroyed: Option<Vec<i64>>,
    #[serde(rename = "notDestroyed")]
    not_destroyed: Option<HashMap<String, Value>>,
}
fn failure(value: &Value) -> u16 {
    match value["type"].as_str() {
        Some("notFound") => 404,
        Some("invalidArguments")
            if !value["description"]
                .as_str()
                .unwrap_or("")
                .contains("addressbook not found") =>
        {
            400
        }
        _ => 500,
    }
}
fn matches(value: &str, etag: &str) -> bool {
    value.is_empty() || value == "*" || value.trim_matches('"') == etag.trim_matches('"')
}
fn payload(vc: &crate::contacts_vcard::VCard, book: i64) -> Value {
    let parts = vc.n.split(';').collect::<Vec<_>>();
    let mut value = json!({"addressbookId":book,"uid":vc.uid,"displayName":vc.fn_,"firstName":if vc.n.is_empty(){""}else{parts.get(1).copied().unwrap_or("")},"lastName":if vc.n.is_empty(){""}else{parts[0]},"company":vc.org,"jobTitle":vc.title,"department":vc.role,"notes":vc.note,"emails":vc.emails.iter().map(|e|json!({"type":e.kind,"address":e.value})).collect::<Vec<_>>(),"phones":vc.phones.iter().map(|e|json!({"type":e.kind,"number":e.value})).collect::<Vec<_>>(),"addresses":vc.addresses.iter().map(|a|json!({"type":a.kind,"street":a.street,"city":a.city,"region":a.region,"postcode":a.code,"country":a.country})).collect::<Vec<_>>(),"urls":vc.urls.iter().map(|e|json!({"type":e.kind,"url":e.value})).collect::<Vec<_>>(),"categories":vc.categories});
    if let Some(day) = &vc.birthday {
        value["birthday"] = json!(day);
    }
    if !vc.photo_uri.is_empty() {
        value["avatar"] = json!(vc.photo_uri);
    }
    value
}
pub(super) fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut response = reply(
        503,
        crate::problem::Problem::new(503, "operation outcome unknown").body(),
        Some("application/problem+json"),
        c.identity.proto,
        id,
    );
    response.headers_mut().insert(
        "x-operation-id",
        setjoin_pg::operation_hex(operation)
            .parse()
            .expect("operation hex"),
    );
    response
}
pub(super) async fn handle(
    exec: &ScopedExecutor,
    mut r: Request<Body>,
    c: &RequestContext,
    actor: &AuthContext,
    id: String,
) -> Response<Body> {
    let (_, parts) = path(&r);
    if parts.first().is_some_and(|p| p == "gal") {
        return super::gal::read_only(c, id);
    }
    let put = r.method() == hyper::Method::PUT;
    let empty = |status, id| reply(status, String::new(), None, c.identity.proto, id);
    if parts.len() != 2 {
        return empty(if put { 409 } else { 404 }, id);
    }
    let book = match parts[0].parse::<i64>() {
        Ok(id) => id,
        Err(_) => return empty(if put { 409 } else { 404 }, id),
    };
    let uid = parts[1].strip_suffix(".vcf").unwrap_or(&parts[1]);
    if put
        && carddav::book(exec, actor.user_id(), book)
            .await
            .ok()
            .flatten()
            .is_none()
    {
        return empty(404, id);
    }
    let vc = if put {
        let bytes = match read_body(&mut r, 10 << 20).await {
            Ok(b) => b,
            Err(status) => return body_error(status, &r, c, id),
        };
        match crate::contacts_vcard::parse(&crate::guests_input::go_utf8(&bytes)) {
            Ok(vc) => Some(vc),
            Err(_) => return empty(400, id),
        }
    } else {
        None
    };
    let existing = carddav::get_contact(exec, actor.user_id(), book, uid)
        .await
        .ok()
        .flatten()
        .filter(|contact| crate::contacts_vcard::render(&contact.row).is_some());
    if !put && existing.is_none() {
        return empty(404, id);
    }
    let if_match = r
        .headers()
        .get("if-match")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let if_none = r
        .headers()
        .get("if-none-match")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if (put && existing.is_some() && if_none == "*")
        || existing
            .as_ref()
            .is_some_and(|e| !matches(if_match, &e.etag))
        || (put && existing.is_none() && !if_match.is_empty())
    {
        return empty(412, id);
    }
    if !put
        && carddav::book(exec, actor.user_id(), book)
            .await
            .ok()
            .flatten()
            .is_none()
    {
        return empty(404, id);
    }
    let (kind, key, contact) = if !put {
        (
            Operation::Delete,
            existing.as_ref().unwrap().id.to_string(),
            existing.as_ref().unwrap().id,
        )
    } else if let Some(e) = &existing {
        (Operation::Update, e.id.to_string(), e.id)
    } else {
        (Operation::Create, "k1".into(), 0)
    };
    let payload = vc
        .as_ref()
        .map(|vc| json!({key.clone():payload(vc,book)}).to_string())
        .unwrap_or_default();
    let Some(operation) = crate::jmap::random() else {
        return reply(
            503,
            crate::problem::Problem::new(503, "service unavailable").body(),
            Some("application/problem+json"),
            c.identity.proto,
            id,
        );
    };
    let raw = match carddav::publish(exec, actor, book, contact, &payload, kind, operation).await {
        CommandOutcome::Committed(raw) => raw,
        CommandOutcome::Unknown { operation } => return unknown(operation, c, id),
        CommandOutcome::RolledBack(_) => return empty(500, id),
    };
    let Ok(set) = serde_json::from_str::<Set>(&raw) else {
        return empty(500, id);
    };
    let (failed, acknowledged) = match kind {
        Operation::Create => (
            set.not_created.as_ref().and_then(|m| m.get(&key)),
            set.created.as_ref().is_some_and(|m| m.contains_key(&key)),
        ),
        Operation::Update => (
            set.not_updated.as_ref().and_then(|m| m.get(&key)),
            set.updated
                .as_ref()
                .is_some_and(|ids| ids.contains(&contact)),
        ),
        Operation::Delete => (
            set.not_destroyed.as_ref().and_then(|m| m.get(&key)),
            set.destroyed
                .as_ref()
                .is_some_and(|ids| ids.contains(&contact)),
        ),
    };
    if let Some(failed) = failed {
        return empty(failure(failed), id);
    }
    if !acknowledged {
        return empty(500, id);
    }
    if !put {
        return empty(204, id);
    }
    let etag = carddav::get_contact(exec, actor.user_id(), book, uid)
        .await
        .ok()
        .flatten()
        .map(|c| c.etag)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{:x}", Sha256::digest(raw.as_bytes())));
    let mut response = empty(
        if matches!(kind, Operation::Create) {
            201
        } else {
            204
        },
        id,
    );
    if let Ok(etag) = format!("\"{etag}\"").parse() {
        response.headers_mut().insert("etag", etag);
    }
    response
}
