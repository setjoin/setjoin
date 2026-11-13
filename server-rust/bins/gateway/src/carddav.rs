//! CardDAV HTTP compatibility over dav-server's method model (#427).
use crate::caldav::{read_body, reply};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use dav_server::DavMethod;
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
mod gal;
mod report;
mod write;
mod xml;

pub struct CardDavRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Intercept for CardDavRoute<K> {
    fn requires_session(&self, _: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()))
            .starts_with("/carddav/")
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_user_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            let Some(auth) = setjoin_authz::authorize_user_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                // Shared Basic/Negotiate proof remains owned by #420/#339.
                return c.upstream.forward(r, &c.identity).await;
            };
            let id = crate::jmap::reply::request_id(
                r.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            if !setjoin_calendar::entitled_app(&exec, auth.context(), "contacts")
                .await
                .unwrap_or(false)
            {
                let _ = setjoin_calendar::carddav::blocked_audit(
                    &exec,
                    auth.context().user_id(),
                    &c.identity.client_ip.to_string(),
                )
                .await;
                let instance =
                    crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()));
                let mut response = reply(
                    403,
                    crate::problem::Problem::new(
                        403,
                        "Access to this application is not permitted for your account.",
                    )
                    .kind("https://setjoin.com/errors/forbidden")
                    .instance(&instance)
                    .body(),
                    Some("application/problem+json"),
                    c.identity.proto,
                    id,
                );
                if let Ok(language) = crate::chat_channels::problem_language(r.headers()).parse() {
                    response.headers_mut().insert("content-language", language);
                }
                return response;
            }
            if !r.uri().path().starts_with("/carddav") {
                return reply(
                    404,
                    "404 page not found\n".into(),
                    Some("text/plain; charset=utf-8"),
                    c.identity.proto,
                    id,
                );
            }
            if matches!(DavMethod::try_from(r.method()), Ok(DavMethod::Options)) {
                let mut response = reply(200, String::new(), None, c.identity.proto, id);
                response.headers_mut().insert(
                    "dav",
                    hyper::header::HeaderValue::from_static("1, 2, addressbook"),
                );
                response.headers_mut().insert(
                    "allow",
                    hyper::header::HeaderValue::from_static(
                        if path(&r).1.first().is_some_and(|p| p == "gal") {
                            "OPTIONS, GET, PROPFIND, REPORT"
                        } else {
                            "OPTIONS, GET, PUT, DELETE, PROPFIND, REPORT"
                        },
                    ),
                );
                return response;
            }
            if matches!(*r.method(), hyper::Method::PUT | hyper::Method::DELETE) {
                return write::handle(&exec, r, &c, auth.context(), id).await;
            }
            if r.method().as_str() == "REPORT" {
                return report::handle(&exec, &mut r, &c, auth.context(), id).await;
            }
            if r.method() == hyper::Method::GET {
                let (_, parts) = path(&r);
                if parts.first().is_some_and(|p| p == "gal") {
                    return gal::get(&exec, &parts, &c, auth.context().user_id(), id).await;
                }
                if parts.len() != 2 {
                    return reply(404, String::new(), None, c.identity.proto, id);
                }
                let uid = parts[1].strip_suffix(".vcf").unwrap_or(&parts[1]);
                let contact = setjoin_calendar::carddav::get_contact(
                    &exec,
                    auth.context().user_id(),
                    parts[0].parse().unwrap_or(0),
                    uid,
                )
                .await
                .ok()
                .flatten();
                let Some((data, etag)) = contact
                    .and_then(|c| crate::contacts_vcard::render(&c.row).map(|data| (data, c.etag)))
                else {
                    return reply(404, String::new(), None, c.identity.proto, id);
                };
                let mut response = reply(
                    200,
                    data,
                    Some("text/vcard; charset=utf-8"),
                    c.identity.proto,
                    id,
                );
                if let Ok(etag) = format!("\"{etag}\"").parse() {
                    response.headers_mut().insert("etag", etag);
                }
                return response;
            }
            if matches!(DavMethod::try_from(r.method()), Ok(DavMethod::PropFind)) {
                let bytes = match read_body(&mut r, 1 << 20).await {
                    Ok(b) => b,
                    Err(status) => return body_error(status, &r, &c, id),
                };
                let parsed = xml::parse(&bytes).ok().filter(|p| p.name == "propfind");
                let req = xml::requested(parsed.as_ref());
                let (path, parts) = path(&r);
                if parts.first().is_some_and(|p| p == "gal") {
                    return gal::propfind(
                        &exec,
                        &parts,
                        req.as_deref(),
                        r.headers().get("depth").and_then(|h| h.to_str().ok()) != Some("0"),
                        &c,
                        auth.context().user_id(),
                        id,
                    )
                    .await;
                }
                let mut responses = vec![];
                if parts.is_empty() {
                    let user = auth.context().user_id();
                    responses.push(xml::properties(&path, req.as_deref(), |name| {
                        Some(Some(match name {
                            "resourcetype" => xml::text(name, ""),
                            "displayname" => xml::text(name, "Contacts"),
                            "addressbook-home-set" => xml::node(name, vec![xml::text("href", "/")])
                                .attr("xmlns", xml::CARD),
                            "principal-URL" | "current-user-principal" => xml::node(
                                name,
                                vec![xml::text("href", format!("/principals/{user}"))],
                            ),
                            _ => return None,
                        }))
                    }));
                    if r.headers().get("depth").and_then(|h| h.to_str().ok()) != Some("0") {
                        for book in setjoin_calendar::carddav::books(&exec, user)
                            .await
                            .unwrap_or_default()
                        {
                            responses.push(book_props(
                                &format!("/{}/", book.id),
                                req.as_deref(),
                                &book.name,
                                &book.description,
                            ));
                        }
                        if setjoin_calendar::flag(&exec, "feature.gal_carddav", false)
                            .await
                            .unwrap_or(false)
                        {
                            responses.push(book_props(
                                "/gal/",
                                req.as_deref(),
                                "Global Address List",
                                "Company directory (read-only)",
                            ));
                        }
                    }
                } else if parts.len() == 1 {
                    if let Ok(Some(book)) = setjoin_calendar::carddav::book(
                        &exec,
                        auth.context().user_id(),
                        parts[0].parse().unwrap_or(0),
                    )
                    .await
                    {
                        responses.push(book_props(
                            &path,
                            req.as_deref(),
                            &book.name,
                            &book.description,
                        ));
                        if r.headers().get("depth").and_then(|h| h.to_str().ok()) != Some("0") {
                            let contacts = setjoin_calendar::carddav::list_contacts(
                                &exec,
                                auth.context().user_id(),
                                book.id,
                            )
                            .await
                            .unwrap_or_default();
                            // Go's row scan rejects the whole list on a malformed JSON column.
                            let rendered = contacts
                                .iter()
                                .map(|c| crate::contacts_vcard::render(&c.row))
                                .collect::<Option<Vec<_>>>();
                            if let Some(rendered) = rendered {
                                for (contact, data) in contacts.iter().zip(rendered) {
                                    responses.push(contact_props(
                                        &format!("/{}/{}.vcf", book.id, contact.row.uid),
                                        req.as_deref(),
                                        contact,
                                        &data,
                                    ));
                                }
                            }
                        }
                    }
                } else if let Ok(Some(contact)) = setjoin_calendar::carddav::get_contact(
                    &exec,
                    auth.context().user_id(),
                    parts[0].parse().unwrap_or(0),
                    parts[1].strip_suffix(".vcf").unwrap_or(&parts[1]),
                )
                .await
                {
                    if let Some(data) = crate::contacts_vcard::render(&contact.row) {
                        responses.push(contact_props(&path, req.as_deref(), &contact, &data));
                    }
                }
                return reply(
                    207,
                    xml::multistatus(responses, None),
                    Some("application/xml; charset=utf-8"),
                    c.identity.proto,
                    id,
                );
            }
            reply(405, String::new(), None, c.identity.proto, id)
        })
    }
}

fn path(r: &Request<Body>) -> (String, Vec<String>) {
    let decoded = crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()));
    let raw = decoded.strip_prefix("/carddav").unwrap_or(&decoded);
    let mut parts = vec![];
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_owned()),
        }
    }
    (format!("/{}", parts.join("/")), parts)
}
fn book_props(href: &str, req: Option<&[&str]>, name: &str, description: &str) -> xml::Element {
    xml::properties(href, req, |prop| {
        Some(Some(match prop {
            "resourcetype" => xml::text(prop, ""),
            "displayname" => {
                if name.is_empty() {
                    return Some(None);
                } else {
                    xml::text(prop, name)
                }
            }
            "addressbook-description" => {
                if description.is_empty() {
                    return Some(None);
                } else {
                    xml::property(prop, description)
                }
            }
            "getcontenttype" => xml::text(prop, "text/vcard"),
            "supported-address-data" => xml::supported_data(),
            "supported-report-set" => xml::reports(),
            _ => return None,
        }))
    })
}
fn body_error(status: u16, r: &Request<Body>, c: &RequestContext, id: String) -> Response<Body> {
    let mut p = crate::problem::Problem::new(
        status,
        if status == 413 {
            "request body exceeds the allowed size"
        } else {
            "could not read request body"
        },
    );
    if status == 413 {
        p.kind = "https://setjoin.com/errors/too-large";
    }
    let decoded = crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()));
    let instance = decoded.strip_prefix("/carddav").unwrap_or(&decoded);
    p.instance = instance;
    let mut response = reply(
        status,
        p.body(),
        Some("application/problem+json"),
        c.identity.proto,
        id,
    );
    if let Ok(language) = crate::chat_channels::problem_language(r.headers()).parse() {
        response.headers_mut().insert("content-language", language);
    }
    response
}

fn contact_props(
    href: &str,
    req: Option<&[&str]>,
    contact: &setjoin_calendar::carddav::Contact,
    data: &str,
) -> xml::Element {
    xml::properties(href, req, |name| {
        Some(Some(match name {
            "displayname" => {
                if contact.row.display_name.is_empty() {
                    return Some(None);
                } else {
                    xml::text(name, &contact.row.display_name)
                }
            }
            "getetag" => xml::text(name, format!("\"{}\"", contact.etag)),
            "getcontenttype" => xml::text(name, "text/vcard; charset=utf-8"),
            "getcontentlength" => return Some(None),
            "address-data" => xml::property(name, data),
            _ => return None,
        }))
    })
}

/// A product-disabled Go registration falls through to the native root mux.
/// Retain its website/SPA behavior without reintroducing a Go rollback path.
pub struct Unregistered {
    pub fallback: crate::catchall::CatchallRoute,
}
impl Intercept for Unregistered {
    fn matches(&self, r: &Request<Body>) -> bool {
        crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()))
            .starts_with("/carddav/")
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        // The absent pinned registration is root-mux traffic. Go serves a
        // website only for GET/HEAD; all other methods are the plain root 404.
        if !matches!(*r.method(), hyper::Method::GET | hyper::Method::HEAD) {
            return Box::pin(async move { crate::surface::unregistered(&r, c.identity.proto) });
        }
        self.fallback.handle(r, c)
    }
}
