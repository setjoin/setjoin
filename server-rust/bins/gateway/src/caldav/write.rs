//! Per-command reducer authority. Every publishing statement rechecks the
//! verified actor's current collection owner. Recurrence calls stay independent
//! best-effort transactions, as Go does; uncertain commits never claim success.
use super::{body_error, path, read_body, reply};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::collections::{HashMap, HashSet};

fn timestamp(unix: Option<i64>) -> String {
    chrono::DateTime::from_timestamp(unix.unwrap_or(-62_135_596_800), 0)
        .expect("parsed calendar time")
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
fn unknown(
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
fn unavailable(c: &RequestContext, id: String) -> Response<Body> {
    reply(
        503,
        crate::problem::Problem::new(503, "service unavailable").body(),
        Some("application/problem+json"),
        c.identity.proto,
        id,
    )
}
fn object(event: &crate::ics::Event) -> Value {
    json!({"uid":event.uid,"title":event.title,"description":event.description,"location":event.location,"start":timestamp(event.start),"end":timestamp(event.end),"isAllDay":event.all_day,"timeZone":event.timezone,"status":event.status,"recurrenceRule":event.rrule,"attendees":event.attendees})
}
pub(super) async fn put(
    exec: &ScopedExecutor,
    mut r: Request<Body>,
    c: RequestContext,
    actor: &AuthContext,
) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let (_, parts) = path(&r);
    if parts.len() != 2 {
        return reply(409, String::new(), None, c.identity.proto, id);
    }
    let Ok(calendar) = parts[0].parse::<i64>() else {
        return reply(409, String::new(), None, c.identity.proto, id);
    };
    let uid = parts[1].strip_suffix(".ics").unwrap_or(&parts[1]);
    if setjoin_calendar::dav::calendar(exec, calendar, actor.user_id())
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let bytes = match read_body(&mut r, 10 << 20).await {
        Ok(b) => b,
        Err(status) => return body_error(status, &r, &c, id),
    };
    let objects = match crate::ics::parse_objects(&crate::guests_input::go_utf8(&bytes)) {
        Ok(events) => events,
        Err(_) => return reply(400, String::new(), None, c.identity.proto, id),
    };
    let event = &objects[0];
    if event.uid != uid {
        return reply(403, String::new(), None, c.identity.proto, id);
    }
    let existing = setjoin_calendar::dav::event(exec, calendar, uid, actor.user_id())
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
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
    if (existing.is_some() && if_none == "*")
        || (!if_match.is_empty()
            && existing.as_ref().is_none_or(|ev| {
                if_match != "*"
                    && if_match.trim_matches('"')
                        != ev["etag"].as_str().unwrap_or("").trim_matches('"')
            }))
    {
        return reply(412, String::new(), None, c.identity.proto, id);
    }
    let Some(operation) = crate::jmap::random() else {
        return unavailable(&c, id);
    };
    let mut value = object(event);
    let outcome = if let Some(existing) = &existing {
        let event_id = existing["id"].as_i64().unwrap_or(0);
        let payload = json!({event_id.to_string():value}).to_string();
        setjoin_calendar::dav::update(exec, actor, calendar, event_id, &payload, operation).await
    } else {
        value["calendarId"] = json!(calendar);
        setjoin_calendar::dav::create(
            exec,
            actor,
            calendar,
            &json!({"k1":value}).to_string(),
            operation,
        )
        .await
    };
    let result = match outcome {
        CommandOutcome::Committed(raw) => {
            serde_json::from_str::<Value>(&raw).unwrap_or(Value::Null)
        }
        CommandOutcome::Unknown { operation } => return unknown(operation, &c, id),
        CommandOutcome::RolledBack(_) => {
            return reply(
                500,
                crate::problem::Problem::new(500, "request failed")
                    .instance(r.uri().path())
                    .body(),
                Some("application/problem+json"),
                c.identity.proto,
                id,
            )
        }
    };
    let created = result["created"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok());
    // Go reads only created, so PUT-update returns a quoted empty ETag. For a
    // recurring create this value is captured BEFORE reconciliation changes it.
    let etag = if let Some(created) = created {
        setjoin_calendar::dav::event_etag(exec, created, actor.user_id())
            .await
            .unwrap_or_default()
    } else {
        String::new()
    };
    let master = existing
        .as_ref()
        .and_then(|v| v["id"].as_i64())
        .or(created)
        .unwrap_or(0);
    if master > 0 && !event.rrule.is_empty() {
        let mut exceptions = HashMap::new();
        for exception in objects.iter().skip(1) {
            if let Some(instant) = exception.recurrence_id.filter(|v| *v != -62_135_596_800) {
                exceptions.insert(instant, exception);
            }
        }
        let exclusions: HashSet<i64> = event.exdates.iter().copied().collect();
        let overrides =
            setjoin_calendar::dav::overrides(exec, calendar, uid, actor.user_id()).await;
        // A failed list aborts only reconciliation, retaining the master result.
        if let Ok(overrides) = overrides {
            let mut patches = vec![];
            for raw in overrides {
                if let Ok(ov) = serde_json::from_str::<Value>(&raw) {
                    if let Some(instant) = ov["recurrence_override"]
                        .as_str()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|t| t.timestamp())
                    {
                        if !exceptions.contains_key(&instant) && !exclusions.contains(&instant) {
                            patches.push((instant, json!({"excluded":true})));
                        }
                    }
                }
            }
            for (&instant, exception) in &exceptions {
                patches.push((instant,json!({"title":exception.title,"description":exception.description,"location":exception.location,"start":timestamp(exception.start),"end":timestamp(exception.end),"isAllDay":exception.all_day})));
            }
            for &instant in &exclusions {
                if !exceptions.contains_key(&instant) {
                    patches.push((instant, json!({"excluded":true})));
                }
            }
            for (instant, patch) in patches {
                let Some(operation) = crate::jmap::random() else {
                    return unavailable(&c, id);
                };
                if let CommandOutcome::Unknown { operation } = setjoin_calendar::dav::occurrence(
                    exec,
                    actor,
                    calendar,
                    master,
                    &timestamp(Some(instant)),
                    &patch.to_string(),
                    operation,
                )
                .await
                {
                    return unknown(operation, &c, id);
                }
            }
        }
    }
    let mut response = reply(
        if existing.is_some() { 204 } else { 201 },
        String::new(),
        None,
        c.identity.proto,
        id,
    );
    response.headers_mut().insert(
        "etag",
        format!("\"{etag}\"").parse().expect("database etag"),
    );
    response
}

pub(super) async fn delete(
    exec: &ScopedExecutor,
    r: Request<Body>,
    c: RequestContext,
    actor: &AuthContext,
) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let (_, parts) = path(&r);
    if parts.len() != 2 {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let calendar = parts[0].parse::<i64>().unwrap_or(0);
    let uid = parts[1].strip_suffix(".ics").unwrap_or(&parts[1]);
    let Some(event) = setjoin_calendar::dav::event(exec, calendar, uid, actor.user_id())
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    else {
        return reply(404, String::new(), None, c.identity.proto, id);
    };
    let if_match = r
        .headers()
        .get("if-match")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !if_match.is_empty()
        && if_match != "*"
        && if_match.trim_matches('"') != event["etag"].as_str().unwrap_or("").trim_matches('"')
    {
        return reply(412, String::new(), None, c.identity.proto, id);
    }
    if setjoin_calendar::dav::calendar(exec, calendar, actor.user_id())
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let Some(operation) = crate::jmap::random() else {
        return unavailable(&c, id);
    };
    match setjoin_calendar::dav::destroy(
        exec,
        actor,
        calendar,
        event["id"].as_i64().unwrap_or(0),
        operation,
    )
    .await
    {
        CommandOutcome::Committed(_) => reply(204, String::new(), None, c.identity.proto, id),
        CommandOutcome::Unknown { operation } => unknown(operation, &c, id),
        CommandOutcome::RolledBack(_) => reply(
            500,
            crate::problem::Problem::new(500, "request failed")
                .instance(r.uri().path())
                .body(),
            Some("application/problem+json"),
            c.identity.proto,
            id,
        ),
    }
}

pub(super) async fn mkcalendar(mut r: Request<Body>, c: RequestContext) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    if let Err(status) = read_body(&mut r, 1 << 20).await {
        return body_error(status, &r, &c, id);
    }
    // Go's LIMIT-before-UNION mailbox query is always a syntax error. It
    // publishes no calendar, irrespective of the parsed name or target path.
    let body="<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\">\n  <c:valid-calendar-object-resource/>\n  <d:responsedescription>no mailbox found</d:responsedescription>\n</d:error>";
    reply(
        403,
        body.into(),
        Some("application/xml; charset=utf-8"),
        c.identity.proto,
        id,
    )
}
