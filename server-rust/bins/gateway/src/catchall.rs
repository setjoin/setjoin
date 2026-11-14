//! Frozen Go's root mux and SPA fallback (#416).
mod static_file;
use crate::{inventory::Inventory, Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response, StatusCode};

use setjoin_authz::{token::KeySource, Authorized};
use setjoin_pg::{ScopedExecutor, Type};
use std::sync::Arc;
type Admission =
    Arc<dyn Fn(hyper::HeaderMap, &'static str) -> BoxFuture<Option<Authorized>> + Send + Sync>;

#[derive(Clone)]
pub struct CatchallRoute {
    inventory: Arc<Inventory>,
    exec: Option<ScopedExecutor>,
    admission: Option<Admission>,
    terminal_auth: bool,
    pub meet_configured: bool,
    pub website: Option<Arc<setjoin_static::website::Website>>,
}
impl Default for CatchallRoute {
    fn default() -> Self {
        Self::new()
    }
}
impl CatchallRoute {
    pub fn new() -> Self {
        Self {
            inventory: Arc::new(
                Inventory::parse(crate::inventory::BUNDLED).expect("bundled inventory"),
            ),
            exec: None,
            admission: None,
            terminal_auth:false,
            meet_configured: false,
            website: None,
        }
    }
    pub fn with_auth<K: KeySource + 'static>(self,exec:ScopedExecutor,keys:Arc<K>,issuer:String)->Self {
        self.with_auth_mode(exec,keys,issuer,false)
    }
    /// Main pairs this with RouteTable::with_admission: the outer guest belt
    /// has already answered its errors before mux/alias dispatch.
    pub fn with_terminal_auth<K: KeySource + 'static>(self,exec:ScopedExecutor,keys:Arc<K>,issuer:String)->Self {
        self.with_auth_mode(exec,keys,issuer,true)
    }
    fn with_auth_mode<K:KeySource+'static>(mut self,exec:ScopedExecutor,keys:Arc<K>,issuer:String,terminal:bool)->Self {
        self.exec=Some(exec.clone());self.terminal_auth=terminal;
        self.admission=Some(Arc::new(move|headers,scheme|{
            let(exec,keys,issuer)=(exec.clone(),keys.clone(),issuer.clone());
            Box::pin(async move{
                if terminal{setjoin_authz::authorize_user_request(&exec,&keys,&issuer,&headers,scheme).await}
                else{setjoin_authz::authorize_request(&exec,&keys,&issuer,&headers,scheme).await}
            })
        }));self
    }
}
impl Intercept for CatchallRoute {
    fn requires_session(&self,r:&Request<Body>)->bool{
        r.uri().path().strip_prefix("/api").and_then(|path|self.inventory.go_match(r.method(),path,None))
            .is_some_and(|route|matches!(route.path.as_str(),"/chat/"|"/drive/"|"/meet"|"/meet/"))
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inventory
            .find(r.method(), r.uri().path())
            .is_some_and(|route| {
                matches!(
                    route.path.as_str(),
                    "/" | "/api/" | "/chat/" | "/drive/" | "/meet" | "/meet/"
                )
            })
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let admission = self.admission.clone();
        Box::pin(async move {
            match admission {
                Some(f) => f(h, s).await.is_some(),
                None => false,
            }
        })
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let terminal_auth=self.terminal_auth;
        let website = self.website.clone();
        let inventory = self.inventory.clone();
        let (exec, admission, configured) = (
            self.exec.clone(),
            self.admission.clone(),
            self.meet_configured,
        );
        Box::pin(async move {
            let path = r.uri().path();
            // StripPrefix checks the escaped spelling as well as decoded Path.
            if path
                .split('/')
                .nth(1)
                .is_some_and(|p| p != "api" && crate::inventory::unescape(p) == b"api")
            {
                return plain(&r, &c, 404, "404 page not found\n");
            }
            if let Some(path) = path.strip_prefix("/api/") {
                // The mount's guest belt authenticates JWT-borne credentials.
                let auth = if jwt_credential(&r) {
                    match &admission {
                        Some(f) => f(r.headers().clone(), c.identity.proto).await,
                        None => None,
                    }
                } else {
                    None
                };
                if !terminal_auth && jwt_credential(&r) && auth.is_none() {
                    return c.upstream.forward(r, &c.identity).await;
                }
                let stripped = format!("/{path}");
                if let Some(reply) = mux_redirect(&inventory, &r, &c, &stripped, None) {
                    return reply;
                }
                if let Some(route) = inventory.go_match(r.method(), &stripped, None) {
                    if matches!(
                        route.path.as_str(),
                        "/chat/" | "/drive/" | "/meet" | "/meet/"
                    ) {
                        let Some(auth) = auth else {
                            if credential(&r) {
                                return c.upstream.forward(r, &c.identity).await;
                            }
                            let mut reply = problem(&r, &c, 401, "Unauthorized");
                            reply.headers_mut().insert(
                                "www-authenticate",
                                "Negotiate, Bearer realm=\"mailserver\"".parse().unwrap(),
                            );
                            return reply;
                        };
                        let Some(exec) = exec else {
                            return c.upstream.forward(r, &c.identity).await;
                        };
                        let app = match route.family {
                            12 => "chat",
                            14 => "drive",
                            _ => "meet",
                        };
                        let key = format!("feature.{app}");
                        let on=exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false)",&[(&key,Type::TEXT)]).await;
                        match on {
                            Ok(rows) if !rows[0].get::<_, bool>(0) => {
                                return problem(&r, &c, 404, "not found")
                            }
                            Ok(_) => {}
                            Err(_) => return c.upstream.forward(r, &c.identity).await,
                        }
                        let user = auth.context().user_id();
                        let entitled = exec
                            .read(
                                "SELECT check_user_app_entitlement($1,$2)",
                                &[(&user, Type::INT8), (&app, Type::TEXT)],
                            )
                            .await;
                        if !entitled.is_ok_and(|rows| rows[0].get::<_, bool>(0)) {
                            return c.upstream.forward(r, &c.identity).await;
                        }
                        if app == "meet" && !configured {
                            let id = crate::jmap::reply::request_id(
                                r.headers().get("x-request-id"),
                                crate::jmap::random().unwrap_or([0; 16]),
                            );
                            return crate::meet::unconfigured(
                                &String::from_utf8_lossy(&crate::inventory::unescape(&stripped)),
                                &c,
                                id,
                                &crate::chat_channels::problem_language(r.headers()),
                            );
                        }
                        if let Some(reply) =
                            mux_redirect(&inventory, &r, &c, &stripped, Some(route.family))
                        {
                            return reply;
                        }
                        return mux_error(&inventory, &r, &c, &stripped, Some(route.family));
                    }
                    // A concrete handler is owned by its family, even when its
                    // adapter cannot handle this spelling or configuration.
                    return c.upstream.forward(r, &c.identity).await;
                }
                return mux_error(&inventory, &r, &c, &stripped, None);
            } else if !matches!(*r.method(), Method::GET | Method::HEAD)
                && (inventory.go_match(r.method(), path, None).is_some()
                    || trailing(&inventory, r.method(), path, None))
                && !pinned(path)
            {
                if !terminal_auth && jwt_credential(&r)
                    && match &admission {
                        Some(f) => f(r.headers().clone(), c.identity.proto).await.is_none(),
                        None => true,
                    }
                {
                    return c.upstream.forward(r, &c.identity).await;
                }
                return redirect(
                    &r,
                    &c,
                    308,
                    &format!(
                        "/api{}",
                        r.uri().path_and_query().map_or("/", |path| path.as_str())
                    ),
                );
            }
            if let Some(website) = website {
                if r.uri().path() == "/" && matches!(*r.method(), Method::GET | Method::HEAD) {
                    if let Some(exec) = exec.as_ref() {
                        if setjoin_static::website::needs_setup(exec).await {
                            return redirect(&r, &c, 302, "/setup");
                        }
                    }
                }
                return static_file::serve(&website, &r, &c).await;
            }
            plain(&r, &c, 404, "404 page not found\n")
        })
    }
}
fn token_cookie(r: &Request<Body>) -> bool {
    r.headers().get_all("cookie").iter().any(|v| {
        v.to_str().map_or(true, |s| {
            s.split(';').any(|p| {
                p.trim().strip_prefix("access_token=").is_some_and(|value| {
                    let value = value.trim();
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(value);
                    !value.is_empty()
                })
            })
        })
    })
}
fn credential(r: &Request<Body>) -> bool {
    r.headers().contains_key("authorization") || token_cookie(r)
}
/// Go's guest belt intentionally ignores Basic/Negotiate and empty cookies.
fn jwt_credential(r: &Request<Body>) -> bool {
    r.headers()
        .get("authorization")
        .is_some_and(|v| v.as_bytes().starts_with(b"Bearer "))
        || token_cookie(r)
}

fn problem(r: &Request<Body>, c: &RequestContext, status: u16, detail: &str) -> Response<Body> {
    let mut reply = plain(r, c, status, "");
    reply
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    crate::problem::set_body(
        &mut reply,
        crate::problem::Problem::new(status, detail).body(),
    );
    reply
}
fn mux_error(
    i: &Inventory,
    r: &Request<Body>,
    c: &RequestContext,
    path: &str,
    inner: Option<usize>,
) -> Response<Body> {
    let allowed = i.go_allowed(path, inner);
    if allowed.is_empty() {
        plain(r, c, 404, "404 page not found\n")
    } else {
        let mut reply = plain(r, c, 405, "Method Not Allowed\n");
        reply
            .headers_mut()
            .insert("allow", allowed.parse().unwrap());
        reply
    }
}

fn pinned(path: &str) -> bool {
    include_str!("../../../../scripts/api-pinned-prefixes.txt")
        .lines()
        .map(str::trim)
        .filter(|p| p.starts_with('/'))
        .any(|p| path == p || path.strip_prefix(p).is_some_and(|s| s.starts_with('/')))
}
/// The root mux owns only /api/ and /. CONNECT bypasses path cleaning.
pub(crate) fn root_redirect(r: &Request<Body>, c: &RequestContext) -> Option<Response<Body>> {
    let path = r.uri().path();
    let clean = if *r.method() == Method::CONNECT {
        path.to_owned()
    } else {
        clean(path)
    };
    if crate::inventory::unescape(&clean) == b"/api" {
        return Some(redirect(r, c, 307, &with_query("/api/", r)));
    }
    (path != clean).then(|| redirect(r, c, 307, &with_query(&escape_path(clean.as_bytes()), r)))
}
fn clean(path: &str) -> String {
    let mut parts = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut out = format!("/{}", parts.join("/"));
    if path.ends_with('/') && out != "/" {
        out.push('/');
    }
    out
}
fn escape_path(path: &[u8]) -> String {
    let mut out = String::new();
    for &b in path {
        if b.is_ascii_alphanumeric() || b"-._~/:@&=+$,;".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
fn with_query(path: &str, r: &Request<Body>) -> String {
    match r.uri().query() {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.into(),
    }
}
fn trailing(i: &Inventory, m: &Method, path: &str, inner: Option<usize>) -> bool {
    if path.ends_with('/') {
        return false;
    }
    let slash = format!("{path}/");
    let exact = |pattern: &str, path: &str| {
        if pattern.ends_with('/') || pattern.ends_with("...}") {
            path.ends_with('/') && pattern.split('/').count() == path.split('/').count()
        } else {
            true
        }
    };
    i.go_match(m, &slash, inner)
        .is_some_and(|route| exact(&route.path, &slash))
        && !i
            .go_match(m, path, inner)
            .is_some_and(|route| exact(&route.path, path))
}
fn mux_redirect(
    i: &Inventory,
    r: &Request<Body>,
    c: &RequestContext,
    path: &str,
    inner: Option<usize>,
) -> Option<Response<Body>> {
    trailing(i, r.method(), path, inner).then(|| {
        redirect(
            r,
            c,
            307,
            &with_query(
                &format!("{}/", escape_path(&crate::inventory::unescape(path))),
                r,
            ),
        )
    })
}
fn html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}
fn redirect(r: &Request<Body>, c: &RequestContext, status: u16, location: &str) -> Response<Body> {
    let title = crate::problem::title(status);
    let mut reply = plain(r, c, status, "");
    reply.headers_mut().remove("content-type");
    if matches!(*r.method(), Method::GET | Method::HEAD) {
        reply
            .headers_mut()
            .insert("content-type", "text/html; charset=utf-8".parse().unwrap());
        if *r.method() == Method::GET {
            crate::problem::set_body(
                &mut reply,
                format!("<a href=\"{}\">{title}</a>.\n\n", html(location)),
            );
        }
    }
    reply
        .headers_mut()
        .insert("location", location.parse().expect("escaped location"));
    reply
}
/// Go's `http.NotFound` behind the root mux's middleware: every unknown route's bare 404.
pub(crate) fn not_found(r: &Request<Body>, c: &RequestContext) -> Response<Body> {
    plain(r, c, 404, "404 page not found\n")
}

fn plain(r: &Request<Body>, c: &RequestContext, status: u16, body: &str) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let mut response = crate::jmap::reply::response(body.into(), c.identity.proto, id);
    *response.status_mut() = StatusCode::from_u16(status).expect("HTTP status");
    response
        .headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    response
}
