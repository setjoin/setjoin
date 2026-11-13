//! Frozen Go's substring REPORT dispatch, strict XML roots and scoped deltas.
use super::{body_error, contact_props, path, read_body, reply, xml};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use serde_json::Value;
use setjoin_pg::ScopedExecutor;

pub(super) const TOKEN: &str = "https://setjoin.invalid/ns/sync/";
fn valid_token(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return Some(String::new());
    }
    let number = value.rsplit('/').next()?.parse::<i64>().ok()?;
    (number >= 0).then(|| number.to_string())
}
pub(super) fn invalid_token(c: &RequestContext, id: String) -> Response<Body> {
    reply(
        403,
        format!(
            "{}<D:error xmlns:D=\"DAV:\"><D:valid-sync-token/></D:error>",
            crate::caldav::xml::HEADER
        ),
        Some("application/xml; charset=utf-8"),
        c.identity.proto,
        id,
    )
}
pub(super) fn sync_response(changes: &Value, book: i64) -> String {
    let mut responses = vec![];
    for row in changes["changed"].as_array().into_iter().flatten() {
        responses.push(crate::caldav::xml::response(
            &format!("/{book}/{}.vcf", row["uid"].as_str().unwrap_or("")),
            vec![xml::text(
                "getetag",
                format!("\"{}\"", row["etag"].as_str().unwrap_or("")),
            )],
            vec![],
            false,
        ));
    }
    for uid in changes["removed"].as_array().into_iter().flatten() {
        responses.push(xml::node(
            "response",
            vec![
                xml::text(
                    "href",
                    format!("/{book}/{}.vcf", uid.as_str().unwrap_or("")),
                ),
                xml::text("status", "HTTP/1.1 404 Not Found"),
            ],
        ));
    }
    let seq = changes["newToken"]
        .as_str()
        .unwrap_or("")
        .parse::<i64>()
        .unwrap_or(0);
    xml::multistatus(responses, Some(&format!("{TOKEN}{seq}")))
}
pub(super) async fn handle(
    exec: &ScopedExecutor,
    r: &mut Request<Body>,
    c: &RequestContext,
    actor: &setjoin_authz::AuthContext,
    id: String,
) -> Response<Body> {
    let user = actor.user_id();
    let bytes = match read_body(r, 1 << 20).await {
        Ok(b) => b,
        Err(status) => return body_error(status, r, c, id),
    };
    if path(r).1.first().is_some_and(|p| p == "gal") {
        return super::gal::report(exec, &bytes, c, actor, id).await;
    }
    let body = String::from_utf8_lossy(&bytes);
    let kind = if body.contains("sync-collection") {
        "sync-collection"
    } else if body.contains("addressbook-multiget") {
        "addressbook-multiget"
    } else if body.contains("addressbook-query") {
        "addressbook-query"
    } else {
        return reply(501, String::new(), None, c.identity.proto, id);
    };
    let namespace = if kind == "sync-collection" {
        "DAV:"
    } else {
        xml::CARD
    };
    let Some(root) = xml::parse(&bytes)
        .ok()
        .filter(|r| r.name == kind && r.ns == namespace)
    else {
        return reply(400, String::new(), None, c.identity.proto, id);
    };
    let (_, parts) = path(r);
    let book = parts
        .first()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if kind == "sync-collection" {
        if parts.first().is_none_or(|s| s.parse::<i64>().is_err()) {
            return reply(404, String::new(), None, c.identity.proto, id);
        }
        let Some(book) = setjoin_calendar::carddav::book(exec, user, book)
            .await
            .ok()
            .flatten()
        else {
            return reply(404, String::new(), None, c.identity.proto, id);
        };
        let token = root
            .children
            .iter()
            .find(|p| p.name == "sync-token" && p.ns == "DAV:")
            .map_or("", |p| p.text.as_str());
        let Some(since) = valid_token(token) else {
            return invalid_token(c, id);
        };
        let Some(changes) = setjoin_calendar::carddav::sync(exec, user, &book, &since)
            .await
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        else {
            return reply(500, String::new(), None, c.identity.proto, id);
        };
        if changes["resync"] == true {
            return invalid_token(c, id);
        }
        return reply(
            207,
            sync_response(&changes, book.id),
            Some("application/xml; charset=utf-8"),
            c.identity.proto,
            id,
        );
    }
    let req = xml::requested(Some(&root));
    let multi = kind == "addressbook-multiget";
    let contacts = if multi {
        let mut keys = std::collections::HashSet::new();
        let mut uids = vec![];
        for href in root.children.iter().filter(|p| p.name == "href") {
            let parts = href.text.trim_matches('/').split('/').collect::<Vec<_>>();
            if parts.len() != 2 {
                continue;
            }
            let book = parts[0].parse::<i64>().unwrap_or(0);
            let uid = parts[1].strip_suffix(".vcf").unwrap_or(parts[1]);
            if keys.insert((book, uid.to_owned())) {
                uids.push(uid.to_owned());
            }
        }
        if uids.is_empty() {
            vec![]
        } else {
            setjoin_calendar::carddav::contacts_by_uids(exec, user, &uids)
                .await
                .unwrap_or_default()
        }
    } else {
        if book > 0
            && setjoin_calendar::carddav::book(exec, user, book)
                .await
                .ok()
                .flatten()
                .is_none()
        {
            return reply(404, String::new(), None, c.identity.proto, id);
        }
        let text = root
            .child("filter")
            .and_then(|f| {
                f.children
                    .iter()
                    .find(|n| n.name == "prop-filter" && n.ns == xml::CARD)
            })
            .and_then(|f| {
                f.children
                    .iter()
                    .find(|n| n.name == "text-match" && n.ns == xml::CARD)
            })
            .map_or("", |n| n.text.as_str());
        setjoin_calendar::carddav::search_contacts(exec, user, book, text)
            .await
            .unwrap_or_default()
    };
    let rendered = contacts
        .iter()
        .map(|c| crate::contacts_vcard::render(&c.row))
        .collect::<Vec<_>>();
    let mut responses = vec![];
    if multi || rendered.iter().all(Option::is_some) {
        for (contact, data) in contacts.iter().zip(rendered) {
            if let Some(data) = data {
                responses.push(contact_props(
                    &format!("/{}/{}.vcf", contact.book, contact.row.uid),
                    req.as_deref(),
                    contact,
                    &data,
                ));
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
