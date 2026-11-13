//! Read-only, org-wide GAL through the canonical visibility seam.
use super::{book_props, reply, report, write, xml};
use crate::{Body, RequestContext};
use hyper::Response;
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_calendar::carddav;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
fn string<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name].as_str().unwrap_or("")
}
fn member(segment: &str) -> Option<i64> {
    let value = segment.strip_suffix(".vcf").unwrap_or(segment);
    value.strip_prefix('u').unwrap_or(value).parse().ok()
}
fn etag(v: &Value) -> String {
    format!(
        "u{}-{}",
        v["id"].as_i64().unwrap_or(0),
        v["updated_micros"].as_i64().unwrap_or(0)
    )
}
fn render(v: &Value) -> String {
    use crate::contacts_vcard::{escape, escape_line};
    let mut body = "BEGIN:VCARD\r\nVERSION:3.0\r\n".to_owned();
    let mut line = |s: String| {
        body.push_str(&escape_line(&s));
        body.push_str("\r\n");
    };
    line(format!(
        "UID:setjoin-gal-u{}",
        v["id"].as_i64().unwrap_or(0)
    ));
    line(format!("FN:{}", escape(string(v, "display_name"))));
    line(format!(
        "N:{};{};;;",
        escape(string(v, "last_name")),
        escape(string(v, "first_name"))
    ));
    for address in v["addresses"].as_array().into_iter().flatten() {
        line(format!(
            "EMAIL;TYPE=INTERNET,WORK{}:{}",
            if address["isPrimary"] == true {
                ",PREF"
            } else {
                ""
            },
            escape(string(address, "email"))
        ));
    }
    for (field, property) in [
        ("phone", "TEL;TYPE=WORK"),
        ("job_title", "TITLE"),
        ("dept_name", "ORG"),
        ("manager_name", "X-MANAGER"),
    ] {
        let value = string(v, field);
        if !value.is_empty() {
            line(format!("{property}:{}", escape(value)));
        }
    }
    if !string(v, "avatar_sha256").is_empty() {
        body.push_str(&format!(
            "PHOTO;VALUE=URI:/blobs/{}\r\n",
            string(v, "avatar_sha256")
        ));
    }
    body.push_str(&format!(
        "KIND:individual\r\nPRODID:-//Mailserver//CardDAV//EN\r\nREV:{}\r\nEND:VCARD\r\n",
        string(v, "rev")
    ));
    body
}
async fn rows(
    exec: &ScopedExecutor,
    user: i64,
    id: Option<i64>,
    text: &str,
    limit: Option<i64>,
) -> Vec<Value> {
    carddav::gal_users(exec, user, id, text, limit)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|raw| serde_json::from_str(raw).ok())
        .collect()
}
async fn record(exec: &ScopedExecutor, user: i64, rows: &[Value]) {
    let ids = rows
        .iter()
        .filter_map(|r| r["id"].as_i64())
        .collect::<Vec<_>>();
    let _ = carddav::gal_record(exec, user, &ids).await;
}
fn props(href: &str, req: Option<&[&str]>, row: &Value) -> xml::Element {
    xml::properties(href, req, |name| {
        Some(Some(match name {
            "displayname" => {
                if string(row, "display_name").is_empty() {
                    return Some(None);
                } else {
                    xml::text(name, string(row, "display_name"))
                }
            }
            "getetag" => xml::text(name, format!("\"{}\"", etag(row))),
            "getcontenttype" => xml::text(name, "text/vcard; charset=utf-8"),
            "getcontentlength" => return Some(None),
            "address-data" => xml::property(name, render(row)),
            _ => return None,
        }))
    })
}
async fn enabled(exec: &ScopedExecutor) -> bool {
    setjoin_calendar::flag(exec, "feature.gal_carddav", false)
        .await
        .unwrap_or(false)
}
pub(super) async fn get(
    exec: &ScopedExecutor,
    parts: &[String],
    c: &RequestContext,
    user: i64,
    id: String,
) -> Response<Body> {
    if !enabled(exec).await || parts.len() != 2 {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let Some(member) = member(&parts[1]) else {
        return reply(404, String::new(), None, c.identity.proto, id);
    };
    let rows = rows(exec, user, Some(member), "", None).await;
    let Some(row) = rows.first() else {
        return reply(404, String::new(), None, c.identity.proto, id);
    };
    record(exec, user, &rows).await;
    let mut response = reply(
        200,
        render(row),
        Some("text/vcard; charset=utf-8"),
        c.identity.proto,
        id,
    );
    if let Ok(etag) = format!("\"{}\"", etag(row)).parse() {
        response.headers_mut().insert("etag", etag);
    }
    response
}
pub(super) async fn propfind(
    exec: &ScopedExecutor,
    parts: &[String],
    req: Option<&[&str]>,
    depth: bool,
    c: &RequestContext,
    user: i64,
    id: String,
) -> Response<Body> {
    if !enabled(exec).await {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let mut responses = vec![];
    if parts.len() == 1 {
        responses.push(book_props(
            "/gal/",
            req,
            "Global Address List",
            "Company directory (read-only)",
        ));
        if depth {
            let rows = rows(exec, user, None, "", None).await;
            record(exec, user, &rows).await;
            for row in rows {
                responses.push(props(
                    &format!("/gal/u{}.vcf", row["id"].as_i64().unwrap_or(0)),
                    req,
                    &row,
                ));
            }
        }
    } else {
        let Some(member) = member(&parts[1]) else {
            return reply(404, String::new(), None, c.identity.proto, id);
        };
        let rows = rows(exec, user, Some(member), "", None).await;
        let Some(row) = rows.first() else {
            return reply(404, String::new(), None, c.identity.proto, id);
        };
        record(exec, user, &rows).await;
        responses.push(props(&format!("/gal/{}", parts[1]), req, row));
    }
    reply(
        207,
        xml::multistatus(responses, None),
        Some("application/xml; charset=utf-8"),
        c.identity.proto,
        id,
    )
}
pub(super) fn read_only(c: &RequestContext, id: String) -> Response<Body> {
    reply(403,format!("{}<D:error xmlns:D=\"DAV:\"><D:cannot-modify-protected-property/><D:responsedescription>The Global Address List is read-only; directory changes come from the admin console / AD sync.</D:responsedescription></D:error>",crate::caldav::xml::HEADER),Some("application/xml; charset=utf-8"),c.identity.proto,id)
}
pub(super) async fn report(
    exec: &ScopedExecutor,
    bytes: &[u8],
    c: &RequestContext,
    actor: &AuthContext,
    id: String,
) -> Response<Body> {
    let user = actor.user_id();
    if !enabled(exec).await {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let body = String::from_utf8_lossy(bytes);
    let name = if body.contains("sync-collection") {
        "sync-collection"
    } else if body.contains("addressbook-multiget") {
        "addressbook-multiget"
    } else if body.contains("addressbook-query") {
        "addressbook-query"
    } else {
        return reply(501, String::new(), None, c.identity.proto, id);
    };
    let ns = if name == "sync-collection" {
        "DAV:"
    } else {
        xml::CARD
    };
    let Some(root) = xml::parse(bytes)
        .ok()
        .filter(|r| r.name == name && r.ns == ns)
    else {
        return reply(400, String::new(), None, c.identity.proto, id);
    };
    if name == "sync-collection" {
        let token = root
            .children
            .iter()
            .find(|n| n.name == "sync-token" && n.ns == "DAV:")
            .map_or("", |n| n.text.trim());
        let pair = if token.is_empty() {
            Some((0, 0))
        } else {
            token
                .rsplit('/')
                .next()
                .and_then(|s| s.split_once('-'))
                .and_then(|(m, c)| Some((m.parse::<i64>().ok()?, c.parse::<i64>().ok()?)))
                .filter(|(m, c)| *m >= 0 && *c >= 0)
        };
        let Some((micros, count)) = pair else {
            return report::invalid_token(c, id);
        };
        let Some(operation) = crate::jmap::random() else {
            return reply(503, String::new(), None, c.identity.proto, id);
        };
        let raw = match carddav::gal_sync(exec, actor, micros, count, operation).await {
            CommandOutcome::Committed(raw) => raw,
            CommandOutcome::Unknown { operation } => return write::unknown(operation, c, id),
            CommandOutcome::RolledBack(_) => {
                return reply(500, String::new(), None, c.identity.proto, id)
            }
        };
        if raw.is_empty() {
            return reply(404, String::new(), None, c.identity.proto, id);
        }
        let Ok(changes) = serde_json::from_str::<Value>(&raw) else {
            return reply(500, String::new(), None, c.identity.proto, id);
        };
        if changes["resync"] == true {
            return report::invalid_token(c, id);
        }
        let mut responses = vec![];
        for row in changes["changed"].as_array().into_iter().flatten() {
            responses.push(crate::caldav::xml::response(
                &format!("/gal/u{}.vcf", row["id"].as_i64().unwrap_or(0)),
                vec![xml::text("getetag", format!("\"{}\"", string(row, "etag")))],
                vec![],
                false,
            ));
        }
        for row in changes["removed"].as_array().into_iter().flatten() {
            responses.push(xml::node(
                "response",
                vec![
                    xml::text(
                        "href",
                        format!("/gal/u{}.vcf", row["id"].as_i64().unwrap_or(0)),
                    ),
                    xml::text("status", "HTTP/1.1 404 Not Found"),
                ],
            ));
        }
        let token = format!(
            "{}gal/{}-{}",
            report::TOKEN,
            changes["newMicros"].as_i64().unwrap_or(0),
            changes["newCount"].as_i64().unwrap_or(0)
        );
        return reply(
            207,
            xml::multistatus(responses, Some(&token)),
            Some("application/xml; charset=utf-8"),
            c.identity.proto,
            id,
        );
    }
    if carddav::primary_mailbox(exec, user)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return reply(404, String::new(), None, c.identity.proto, id);
    }
    let req = xml::requested(Some(&root));
    let mut selected = vec![];
    if name == "addressbook-multiget" {
        for href in root.children.iter().filter(|h| h.name == "href") {
            let value = href.text.trim_matches('/');
            let value = value.strip_prefix("gal/").unwrap_or(value);
            if let Some(id) = member(value) {
                selected.extend(rows(exec, user, Some(id), "", None).await);
            }
        }
    } else {
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
        selected = rows(exec, user, None, text, Some(1000)).await;
    }
    record(exec, user, &selected).await;
    let responses = selected
        .iter()
        .map(|row| {
            props(
                &format!("/gal/u{}.vcf", row["id"].as_i64().unwrap_or(0)),
                req.as_deref(),
                row,
            )
        })
        .collect();
    reply(
        207,
        xml::multistatus(responses, None),
        Some("application/xml; charset=utf-8"),
        c.identity.proto,
        id,
    )
}
