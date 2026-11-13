//! CalDAV HTTP compatibility layer over dav-server (#426).
use crate::{Body, BoxFuture, Intercept, RequestContext};
use dav_server::DavMethod;
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
mod ical;
mod report;
mod timezone;
mod write;
pub(crate) mod xml;

pub struct CalDavRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    timezones: Arc<timezone::Timezones>,
}
impl<K: KeySource + 'static> CalDavRoute<K> {
    pub async fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        let timezones = timezone::Timezones::warm(&exec).await;
        Self {
            exec,
            keys,
            issuer,
            timezones,
        }
    }
    pub fn start_timezone_listener(&self, direct: String) {
        self.timezones.start(self.exec.clone(), direct);
    }
    pub fn timezone_listening(&self) -> bool {
        self.timezones.listening()
    }
}
impl<K: KeySource + 'static> Intercept for CalDavRoute<K> {
    fn shutdown(&self) {
        self.timezones.stop();
    }
    fn requires_session(&self, _r: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()))
            .starts_with("/caldav/")
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
        let (exec, keys, issuer, timezones) = (
            self.exec.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.timezones.clone(),
        );
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
                // Shared Basic/Negotiate proof is owned by #420/#339.
                return c.upstream.forward(r, &c.identity).await;
            };
            if !setjoin_calendar::entitled(&exec, auth.context())
                .await
                .unwrap_or(false)
            {
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                let _ = setjoin_calendar::dav::blocked_audit(
                    &exec,
                    auth.context().user_id(),
                    &c.identity.client_ip.to_string(),
                )
                .await;
                let instance =
                    crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()));
                let body = crate::problem::Problem::new(
                    403,
                    "Access to this application is not permitted for your account.",
                )
                .kind("https://setjoin.com/errors/forbidden")
                .instance(&instance)
                .body();
                let mut response = reply(
                    403,
                    body,
                    Some("application/problem+json"),
                    c.identity.proto,
                    id,
                );
                if let Ok(language) = crate::chat_channels::problem_language(r.headers()).parse() {
                    response.headers_mut().insert("content-language", language);
                }
                return response;
            }
            if !r.uri().path().starts_with("/caldav") {
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                return reply(
                    404,
                    "404 page not found\n".into(),
                    Some("text/plain; charset=utf-8"),
                    c.identity.proto,
                    id,
                );
            }
            if r.method() == hyper::Method::GET {
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                let (_, parts) = path(&r);
                if parts.len() != 2 {
                    return reply(404, String::new(), None, c.identity.proto, id);
                }
                let event = setjoin_calendar::dav::event(
                    &exec,
                    parts[0].parse().unwrap_or(0),
                    parts[1].strip_suffix(".ics").unwrap_or(&parts[1]),
                    auth.context().user_id(),
                )
                .await
                .ok()
                .flatten();
                let Some(event) =
                    event.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                else {
                    return reply(404, String::new(), None, c.identity.proto, id);
                };
                let mut response = reply(
                    200,
                    render_event(&exec, auth.context().user_id(), &event).await,
                    Some("text/calendar; charset=utf-8"),
                    c.identity.proto,
                    id,
                );
                if let Ok(etag) = format!("\"{}\"", ical::text(&event, "etag")).parse() {
                    response.headers_mut().insert("etag", etag);
                }
                return response;
            }
            if r.method() == hyper::Method::DELETE {
                return write::delete(&exec, r, c, auth.context()).await;
            }
            if r.method().as_str() == "MKCALENDAR" {
                return write::mkcalendar(r, c).await;
            }
            if r.method() == hyper::Method::PUT {
                return write::put(&exec, r, c, auth.context()).await;
            }
            if r.method().as_str() == "REPORT" {
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                return report::handle(
                    &exec,
                    &mut r,
                    &c,
                    auth.context().user_id(),
                    auth.context().mailbox_id(),
                    id,
                )
                .await;
            }
            if matches!(DavMethod::try_from(r.method()), Ok(DavMethod::Options)) {
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                let mut response = reply(200, String::new(), None, c.identity.proto, id);
                response.headers_mut().insert(
                    "dav",
                    hyper::header::HeaderValue::from_static("1, 2, calendar-access"),
                );
                response.headers_mut().insert(
                    "allow",
                    hyper::header::HeaderValue::from_static(
                        "OPTIONS, GET, PUT, DELETE, PROPFIND, REPORT, MKCALENDAR",
                    ),
                );
                return response;
            }
            if matches!(DavMethod::try_from(r.method()), Ok(DavMethod::PropFind)) {
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                let bytes = match read_body(&mut r, 1 << 20).await {
                    Ok(b) => b,
                    Err(status) => return body_error(status, &r, &c, id),
                };
                let parsed = xml::parse(&bytes).ok().filter(|p| p.name == "propfind");
                let req = xml::requested(parsed.as_ref());
                let (path, parts) = path(&r);
                let user = auth.context().user_id();
                let mut responses = vec![];
                if parts.is_empty() {
                    responses.push(xml::properties("/", req.as_deref(), |name| {
                        Some(Some(match name {
                            "resourcetype" => xml::text(name, ""),
                            "displayname" => xml::text(name, "Calendars"),
                            "calendar-home-set" => {
                                xml::node(name, vec![xml::text("href", "/")]).cal()
                            }
                            "principal-URL"
                            | "current-user-principal"
                            | "calendar-user-address-set" => {
                                let e = xml::node(
                                    name,
                                    vec![xml::text("href", format!("/principals/{user}"))],
                                );
                                if xml::is_cal(name) {
                                    e.cal()
                                } else {
                                    e
                                }
                            }
                            _ => return None,
                        }))
                    }));
                    if r.headers().get("depth").and_then(|h| h.to_str().ok()) != Some("0") {
                        for cal in setjoin_calendar::dav::calendars(&exec, user)
                            .await
                            .unwrap_or_default()
                        {
                            responses.push(
                                calendar_props(
                                    &exec,
                                    &timezones,
                                    user,
                                    &format!("/{}/", cal.id),
                                    req.as_deref(),
                                    &cal,
                                )
                                .await,
                            );
                        }
                    }
                } else if parts.len() == 1 {
                    if let Ok(Some(cal)) =
                        setjoin_calendar::dav::calendar(&exec, parts[0].parse().unwrap_or(0), user)
                            .await
                    {
                        responses.push(
                            calendar_props(&exec, &timezones, user, &path, req.as_deref(), &cal)
                                .await,
                        );
                        if r.headers().get("depth").and_then(|h| h.to_str().ok()) != Some("0") {
                            for event in setjoin_calendar::dav::events(
                                &exec,
                                cal.id,
                                user,
                                "",
                                "",
                                Some(500),
                            )
                            .await
                            .unwrap_or_default()
                            {
                                if let Ok(event) = serde_json::from_str::<serde_json::Value>(&event)
                                {
                                    let href =
                                        format!("/{}/{}.ics", cal.id, ical::text(&event, "uid"));
                                    responses.push(
                                        event_props(&exec, user, &href, req.as_deref(), &event)
                                            .await,
                                    );
                                }
                            }
                        }
                    }
                } else if let Ok(Some(raw)) = setjoin_calendar::dav::event(
                    &exec,
                    parts[0].parse().unwrap_or(0),
                    parts[1].strip_suffix(".ics").unwrap_or(&parts[1]),
                    user,
                )
                .await
                {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&raw) {
                        responses
                            .push(event_props(&exec, user, &path, req.as_deref(), &event).await);
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
            let id = crate::jmap::reply::request_id(
                r.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            reply(405, String::new(), None, c.identity.proto, id)
        })
    }
}
pub(crate) fn reply(
    status: u16,
    body: String,
    content_type: Option<&'static str>,
    scheme: &str,
    id: String,
) -> Response<Body> {
    let mut response = crate::jmap::reply::response(body, scheme, id);
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("literal status");
    response.headers_mut().remove("content-type");
    if let Some(ct) = content_type {
        response
            .headers_mut()
            .insert("content-type", hyper::header::HeaderValue::from_static(ct));
    }
    response
}

async fn calendar_props(
    exec: &ScopedExecutor,
    timezones: &timezone::Timezones,
    user: i64,
    href: &str,
    req: Option<&[&str]>,
    cal: &setjoin_calendar::dav::Calendar,
) -> xml::Element {
    let timezone = if req.is_some_and(|r| r.contains(&"calendar-timezone")) {
        timezones.lookup(exec, cal.id, user, &cal.timezone).await
    } else {
        None
    };
    xml::properties(href, req, |name| {
        Some(Some(match name {
            "resourcetype" => xml::text(name, ""),
            "displayname" => {
                if cal.name.is_empty() {
                    return Some(None);
                } else {
                    xml::text(name, &cal.name)
                }
            }
            "getcontenttype" => xml::text(name, "text/calendar"),
            "supported-calendar-component-set" => xml::components(),
            "supported-report-set" => xml::reports(),
            "calendar-timezone" => match &timezone {
                Some(t) => xml::property(name, t),
                None => return None,
            },
            _ => return None,
        }))
    })
}
fn stripped_path(r: &Request<Body>) -> String {
    let decoded = crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()));
    decoded
        .strip_prefix("/caldav")
        .unwrap_or(&decoded)
        .to_owned()
}
fn path(r: &Request<Body>) -> (String, Vec<String>) {
    let raw = stripped_path(r);
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
pub(crate) async fn read_body(r: &mut Request<Body>, cap: usize) -> Result<Vec<u8>, u16> {
    use http_body_util::BodyExt;
    let mut out = vec![];
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| 400u16)?;
        if let Ok(data) = frame.into_data() {
            if data.len() > cap - out.len() {
                return Err(413);
            }
            out.extend_from_slice(&data)
        }
    }
    Ok(out)
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
    let instance = stripped_path(r);
    p.instance = &instance;
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

fn stored_timezone(tzid: &str, standard: &str) -> String {
    format!("BEGIN:VTIMEZONE\r\nTZID:{tzid}\r\nBEGIN:STANDARD\r\nDTSTART:19700101T000000\r\nTZOFFSETFROM:{standard}\r\nTZOFFSETTO:{standard}\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n")
}

async fn render_event(exec: &ScopedExecutor, user: i64, event: &serde_json::Value) -> String {
    let overrides = if matches!(ical::text(event, "component_type"), "" | "VEVENT")
        && !ical::text(event, "rrule").is_empty()
    {
        setjoin_calendar::dav::overrides(
            exec,
            event["calendar_id"].as_i64().unwrap_or(0),
            ical::text(event, "uid"),
            user,
        )
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect::<Vec<serde_json::Value>>()
    } else {
        vec![]
    };
    ical::render(event, &overrides)
}

async fn event_props(
    exec: &ScopedExecutor,
    user: i64,
    href: &str,
    req: Option<&[&str]>,
    event: &serde_json::Value,
) -> xml::Element {
    let data = if req.is_some_and(|r| r.contains(&"calendar-data")) {
        render_event(exec, user, event).await
    } else {
        String::new()
    };
    xml::properties(href, req, |name| {
        Some(Some(match name {
            "displayname" => {
                let name = ical::text(event, "title");
                if name.is_empty() {
                    return Some(None);
                }
                xml::text("displayname", name)
            }
            "getetag" => xml::text(name, format!("\"{}\"", ical::text(event, "etag"))),
            "getcontenttype" => {
                let kind = ical::text(event, "component_type");
                let kind = if kind.is_empty() { "VEVENT" } else { kind };
                xml::text(
                    name,
                    format!("text/calendar; component={}", kind.to_ascii_lowercase()),
                )
            }
            "getcontentlength" => return Some(None),
            "calendar-data" => xml::property(name, &data),
            _ => return None,
        }))
    })
}
