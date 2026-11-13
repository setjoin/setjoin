//! Go's REPORT dispatch is substring-based, followed by strict root decoding.
use super::{body_error, path, read_body, reply, xml};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use serde_json::Value;
use setjoin_pg::ScopedExecutor;

fn instant(value: &str) -> String {
    chrono::NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ")
        .map(|t| {
            t.and_utc()
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
        })
        .unwrap_or_default()
}
fn valid_token(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return Some(String::new());
    }
    let value = value.rsplit('/').next()?;
    let number = value.parse::<i64>().ok()?;
    (number >= 0).then(|| number.to_string())
}
fn invalid_token(c: &RequestContext, id: String) -> Response<Body> {
    reply(
        403,
        format!(
            "{}<D:error xmlns:D=\"DAV:\"><D:valid-sync-token/></D:error>",
            xml::HEADER
        ),
        Some("application/xml; charset=utf-8"),
        c.identity.proto,
        id,
    )
}
fn failure(r: &Request<Body>, c: &RequestContext, id: String) -> Response<Body> {
    let body = crate::problem::Problem::new(500, "request failed")
        .instance(r.uri().path())
        .body();
    let mut response = reply(
        500,
        body,
        Some("application/problem+json"),
        c.identity.proto,
        id,
    );
    response.headers_mut().insert(
        "content-language",
        hyper::header::HeaderValue::from_static("en"),
    );
    response
}
pub(super) async fn handle(
    exec: &ScopedExecutor,
    r: &mut Request<Body>,
    c: &RequestContext,
    user: i64,
    mailbox: i64,
    id: String,
) -> Response<Body> {
    let bytes = match read_body(r, 1 << 20).await {
        Ok(b) => b,
        Err(status) => return body_error(status, r, c, id),
    };
    let body = String::from_utf8_lossy(&bytes);
    let sync = body.contains("sync-collection");
    let freebusy = !sync && body.contains("free-busy-query");
    if !sync && !freebusy && !body.contains("calendar-query") && !body.contains("calendar-multiget")
    {
        return reply(501, String::new(), None, c.identity.proto, id);
    }
    let name = if sync {
        "sync-collection"
    } else if freebusy {
        "free-busy-query"
    } else {
        "calendar-query"
    };
    let namespace = if sync { "DAV:" } else { xml::CAL };
    let Some(root) = xml::parse(&bytes)
        .ok()
        .filter(|n| n.name == name && n.ns == namespace)
    else {
        return reply(400, String::new(), None, c.identity.proto, id);
    };
    let (_, parts) = path(r);
    let calendar = parts
        .first()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if sync {
        // Unlike query, an absent/non-numeric collection is never a home query.
        if parts.first().is_none_or(|s| s.parse::<i64>().is_err()) {
            return reply(404, String::new(), None, c.identity.proto, id);
        }
        let Some(cal) = setjoin_calendar::dav::calendar(exec, calendar, user)
            .await
            .ok()
            .flatten()
        else {
            return reply(404, String::new(), None, c.identity.proto, id);
        };
        let token = root
            .children
            .iter()
            .find(|n| n.name == "sync-token" && n.ns == "DAV:")
            .map_or("", |n| n.text.as_str());
        let Some(since) = valid_token(token) else {
            return invalid_token(c, id);
        };
        let changes =
            match setjoin_calendar::dav::sync(exec, user, cal.mailbox, cal.id, &since).await {
                Ok(Some(raw)) => serde_json::from_str::<Value>(&raw).ok(),
                Ok(None) => return reply(404, String::new(), None, c.identity.proto, id),
                Err(_) => return failure(r, c, id),
            };
        let Some(changes) = changes else {
            return failure(r, c, id);
        };
        if changes["resync"] == true {
            return invalid_token(c, id);
        }
        let mut responses = vec![];
        if let Some(changed) = changes["changed"].as_array() {
            for ch in changed {
                let href = format!("/{calendar}/{}.ics", ch["uid"].as_str().unwrap_or(""));
                responses.push(xml::response(
                    &href,
                    vec![xml::text(
                        "getetag",
                        format!("\"{}\"", ch["etag"].as_str().unwrap_or("")),
                    )],
                    vec![],
                    false,
                ));
            }
        }
        if let Some(removed) = changes["removed"].as_array() {
            for uid in removed {
                responses.push(xml::node(
                    "response",
                    vec![
                        xml::text(
                            "href",
                            format!("/{calendar}/{}.ics", uid.as_str().unwrap_or("")),
                        ),
                        xml::text("status", "HTTP/1.1 404 Not Found"),
                    ],
                ));
            }
        }
        let seq = changes["newToken"]
            .as_str()
            .unwrap_or("")
            .parse::<i64>()
            .unwrap_or(0);
        let token = format!("https://setjoin.invalid/ns/sync/{seq}");
        return reply(
            207,
            xml::multistatus(responses, Some(&token)),
            Some("application/xml; charset=utf-8"),
            c.identity.proto,
            id,
        );
    }
    if freebusy {
        let range = root
            .children
            .iter()
            .find(|n| n.name == "time-range" && n.ns == xml::CAL);
        if let Some(range) = range {
            let start = instant(range.attr("start"));
            let end = instant(range.attr("end"));
            if !start.is_empty()
                && !end.is_empty()
                && setjoin_calendar::dav::calendar(exec, calendar, user)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            {
                let _ =
                    setjoin_calendar::dav::free_busy(exec, user, mailbox, calendar, &start, &end)
                        .await;
            }
        }
        // Frozen Go's follow-up SELECT email FROM users JOIN mailboxes is
        // ambiguous (both tables have email), so it never emits a principal.
        // Preserve the reducer call and the empty multistatus (#426 parity).
        return reply(
            207,
            xml::multistatus(vec![], None),
            Some("application/xml; charset=utf-8"),
            c.identity.proto,
            id,
        );
    }
    let req = xml::requested(Some(&root));
    let range = root
        .child("filter")
        .and_then(|f| {
            f.children
                .iter()
                .find(|n| n.name == "comp-filter" && n.ns == xml::CAL)
        })
        .and_then(|f| {
            f.children
                .iter()
                .find(|n| n.name == "time-range" && n.ns == xml::CAL)
        });
    let after = range.map_or_else(String::new, |r| instant(r.attr("start")));
    let before = range.map_or_else(String::new, |r| instant(r.attr("end")));
    let calendars = if calendar > 0 {
        match setjoin_calendar::dav::calendar(exec, calendar, user)
            .await
            .ok()
            .flatten()
        {
            Some(cal) => vec![cal],
            None => return reply(404, String::new(), None, c.identity.proto, id),
        }
    } else {
        setjoin_calendar::dav::calendars(exec, user)
            .await
            .unwrap_or_default()
    };
    let mut responses = vec![];
    for cal in calendars {
        for event in setjoin_calendar::dav::events(exec, cal.id, user, &after, &before, None)
            .await
            .unwrap_or_default()
        {
            if let Ok(event) = serde_json::from_str::<Value>(&event) {
                let href = format!("/{}/{}.ics", cal.id, super::ical::text(&event, "uid"));
                responses.push(super::event_props(exec, user, &href, req.as_deref(), &event).await);
            }
        }
    }
    reply(
        207,
        xml::multistatus(responses, None),
        Some("application/xml; charset=utf-8"),
        c.identity.proto,
        id,
    )
}
