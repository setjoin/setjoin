//! Reviewed HTTP transfer inventory. ON selects a Rust adapter; OFF selects Go.
//! The pilot adapter still owns its existing body-level flags and decline path.

use hyper::Method;
use serde_json::Value;
use std::collections::HashSet;

pub const BUNDLED: &str = include_str!("../route-inventory.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    LocalRust,
    RustAuth,
    GoMail,
    GoAuth,
}

pub struct Route {
    listener: String,
    method: String,
    pub(crate) path: String,
    outer: bool,
    _slice: String,
    pub family: usize,
    pub target: Target,
}

pub struct Inventory(Vec<Route>);

impl Inventory {
    pub fn parse(json: &str) -> Result<Self, String> {
        let data: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if data["version"] != 1 {
            return Err("unsupported route inventory version".into());
        }
        let rows = data["routes"].as_array().ok_or("inventory needs routes")?;
        let mut routes = Vec::new();
        let mut keys = HashSet::new();
        for row in rows {
            let field = |key| {
                row[key]
                    .as_str()
                    .ok_or_else(|| format!("missing inventory {key}"))
            };
            let listener = field("listener")?;
            let method = field("method")?;
            let path = field("path")?;
            let fid = field("family")?;
            let family = fid
                .strip_prefix('F')
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|n| (1..=22).contains(n))
                .ok_or("invalid inventory family")?;
            if !path.starts_with('/')
                || field("slice")?.is_empty()
                || (method != "*" && Method::from_bytes(method.as_bytes()).is_err())
            {
                return Err("invalid inventory method/path/slice".into());
            }
            if !keys.insert((listener.to_owned(), method.to_owned(), path.to_owned())) {
                return Err(format!(
                    "duplicate inventory route: {listener} {method} {path}"
                ));
            }
            let on = match field("state")? {
                "ON" => true,
                "OFF" => false,
                _ => return Err("invalid inventory state".into()),
            };
            let target = match field("upstream")? {
                "local-rust" if on => Target::LocalRust,
                "rust-auth" if on => Target::RustAuth,
                "local-rust" | "rust-auth" => {
                    if family == 21 {
                        Target::GoAuth
                    } else {
                        Target::GoMail
                    }
                }
                "go-mail" if !on => Target::GoMail,
                "go-auth" if !on => Target::GoAuth,
                // The captions bot is a separate listener process the gateway never proxies.
                "go-asrbot" if !on && listener == "asrbot" => continue,
                "rust-asrbot" if on && listener == "asrbot" => continue,
                _ => return Err("invalid inventory upstream/state".into()),
            };
            routes.push(Route {
                listener: listener.into(),
                method: method.into(),
                path: path.into(),
                outer: row["sources"].as_array().is_none_or(|sources| {
                    sources
                        .iter()
                        .any(|s| s.as_str().is_some_and(|s| s.contains("cmd/mailserverd/")))
                }),
                _slice: field("slice")?.into(),
                family,
                target,
            });
        }
        Ok(Self(routes))
    }

    /// A deployment override may turn a qualified entry off, but cannot
    /// promote an entry that was not qualified in the bundled inventory.
    pub fn require_qualified(&self, qualified: &Self) -> Result<(), String> {
        for route in &self.0 {
            if !matches!(route.target, Target::LocalRust | Target::RustAuth) {
                continue;
            }
            let approved = qualified.0.iter().any(|entry| {
                entry.listener == route.listener
                    && entry.method == route.method
                    && entry.path == route.path
                    && entry.family == route.family
                    && entry.target == route.target
            });
            if !approved {
                return Err(format!(
                    "unqualified ON route in custom inventory: {} {} {}",
                    route.listener, route.method, route.path
                ));
            }
        }
        Ok(())
    }

    /// The wildcard-method SPA/mux subtree rows (`/`, `/api/`, `/chat/`, `/drive/`,
    /// `/meet`, `/meet/`): only the catch-all may serve a request they alone claim.
    /// `GET /meet` and `POST /meet` are concrete rows and are not subtree rows.
    pub(crate) fn is_subtree_row(route: &Route) -> bool {
        route.method == "*"
            && matches!(route.path.as_str(), "/" | "/api/" | "/chat/" | "/drive/" | "/meet" | "/meet/")
    }

    /// Go-proxy attribution for a forwarded request. A rolled-back F15/F16 route is
    /// registered at its bare path but Go mounts it under `/api`, so the mounted request
    /// is claimed only by the F22 `/api/` row; count it under the owning family instead.
    pub(crate) fn proxy_family(&self, method: &Method, path: &str, route: Option<&Route>) -> Option<usize> {
        let route = route?;
        if route.path != "/api/" || route.family != 22 {
            return Some(route.family);
        }
        let owner = path
            .strip_prefix("/api")
            .and_then(|stripped| self.go_match(method, stripped, None))
            .filter(|owner| matches!(owner.family, 15 | 16));
        Some(owner.map_or(route.family, |owner| owner.family))
    }

    /// Frozen Go's concrete API mux, before /api mounting. Inner routers
    /// have their own method checks after authentication and feature gates.
    pub(crate) fn go_match(
        &self,
        method: &Method,
        path: &str,
        inner: Option<usize>,
    ) -> Option<&Route> {
        self.0
            .iter()
            .filter(|r| self.in_mux(r, inner))
            .filter_map(|r| {
                let m = if r.method == method.as_str() {
                    2
                } else if *method == Method::HEAD && r.method == "GET" {
                    1
                } else if r.method == "*" {
                    0
                } else {
                    return None;
                };
                let mut score = path_score(&r.path, path)?;
                score.push(m);
                Some((score, r))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, r)| r)
    }
    fn in_mux(&self, r: &Route, inner: Option<usize>) -> bool {
        r.listener == "gateway"
            && r.path != "/"
            && r.path != "/api/"
            && match inner {
                Some(f) => !r.outer && r.family == f,
                None => r.outer,
            }
    }
    pub(crate) fn go_allowed(&self, path: &str, inner: Option<usize>) -> String {
        let mut methods = std::collections::BTreeSet::new();
        for r in self.0.iter().filter(|r| self.in_mux(r, inner)) {
            if path_score(&r.path, path).is_some()
                || (!path.ends_with('/') && path_score(&r.path, &format!("{path}/")).is_some())
            {
                if r.method == "*" {
                    return String::new();
                }
                methods.insert(r.method.clone());
                if r.method == "GET" {
                    methods.insert("HEAD".into());
                }
            }
        }
        methods.into_iter().collect::<Vec<_>>().join(", ")
    }
    pub(crate) fn root_on(&self) -> bool {
        self.0.iter().any(|r| {
            r.listener == "gateway"
                && r.method == "*"
                && r.path == "/"
                && r.target == Target::LocalRust
        })
    }

    /// Recording/replay of authserverd directly has no mailserver outer mux.
    pub(crate) fn auth_only(&self) -> bool {
        self.0.iter().any(|r| r.listener == "auth")
            && !self.0.iter().any(|r| r.listener == "gateway")
    }

    /// Match Go's method, segment wildcard, subtree and GET→HEAD semantics.
    /// Auxiliary listeners never become routes on the public front door.
    pub fn find(&self, method: &Method, path: &str) -> Option<&Route> {
        // #523 (owner-approved security fix): Rust binds an OP authorization
        // request through a CSRF-protected POST that frozen Go never registered.
        // It is served by the GET registration's owner; the census stays Go's.
        let method = if method == Method::POST && path == "/auth/oidc/op/complete" {
            &Method::GET
        } else {
            method
        };
        self.0
            .iter()
            .filter_map(|route| {
                if path.starts_with("/auth/") && route.family != 21 {
                    return None;
                }
                if route.listener != "gateway" && route.listener != "auth" {
                    return None;
                }
                // Auth's /admin/reload belongs to its direct listener. An
                // auth-only recording/replay inventory must still select it;
                // with a gateway listener, preserve the public /api alias.
                if route.listener == "auth"
                    && route.path == "/admin/reload"
                    && self.0.iter().any(|r| r.listener == "gateway")
                {
                    return None;
                }
                let method_score = if route.method == method.as_str() {
                    2
                } else if method == Method::HEAD && route.method == "GET" {
                    1
                } else if route.method == "*" {
                    0
                } else {
                    return None;
                };
                // Go mounts non-pinned F10/F11/F12/F13/F14/F15/F16 handlers at /api. Bare GETs
                // belong to the SPA; bare mutations use Go's 308 alias. F10
                // F01/F11/F12/F14 rollback retain their external paths and family counters.
                // F15/F16's OFF census stays at registration paths.
                let mounted_api = route.listener == "gateway"
                    && (matches!(
                        route.family,
                        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 19 | 20
                    ) || (route.family == 22 && route.path == "/telemetry")
                        || (route.family == 18 && (route.path == "/mail/attachment-transfer-token" || route.path.starts_with("/messages/"))))
                    // Go pins the public link-protect click at the root. The
                    // LocalRust fallback below must not remount it under /api.
                    && !(route.family == 6 && route.path == "/link-protect")
                    // F13's SFU signal proxy stays at the root even when ON.
                    && !(route.family == 13 && route.path.starts_with("/rtc"))
                    // DAV roots stay pinned even when the LocalRust fallback below applies.
                    && !(route.family == 17
                        && (route.path.starts_with("/caldav") || route.path.starts_with("/carddav")))
                    && !route.path.starts_with("/scim/")
                    && !route.path.starts_with("/mail-attachment/")
                    && !route.path.starts_with("/approvals/email/")
                    && (route.family == 1
                        || route.family == 2
                        // F03: every Conditional access console route mounts at /api.
                        || route.family == 3
                        // F04: all Compliance console routes mount at /api.
                        || route.family == 4
                        // F05: every registration is an /admin console route mounted at /api.
                        || route.family == 5
                        // F07: both admin and end-user JSON registrations mount at /api,
                        // including when rolled back to Go.
                        || route.family == 7
                        // F06: every registration mounts at /api except the unauthenticated
                        // `/link-protect` click handler, which Go pins at the root.
                        || (route.family == 6 && route.path != "/link-protect")
                        // F08: the admin console mounts at /api; /setup, /updates, /terms and
                        // the `.well-known` ACME root are pinned in Go and stay at the root.
                        || (route.family == 8 && route.path.starts_with("/admin/"))
                        // F19: every `/settings/*` and `/user/*` registration mounts at /api.
                        // F18 message REST actions use Go's API mux; JMAP itself stays pinned.
                        || (route.family == 18 && route.path.starts_with("/messages/"))
                        || route.family == 19
                        || route.family == 9
                        || route.family == 10
                        || route.family == 20
                        || route.path == "/telemetry"
                        || (route.family == 18 && route.path == "/mail/attachment-transfer-token")
                        || route.family == 11
                        || route.family == 12
                        // F17: calendar, booking and contacts mount at /api; the DAV
                        // protocol roots stay pinned at /caldav and /carddav.
                        || (route.family == 17
                            && !route.path.starts_with("/caldav")
                            && !route.path.starts_with("/carddav"))
                        // F13: every registration but the SFU `/rtc` proxy mounts at /api.
                        || (route.family == 13 && !route.path.starts_with("/rtc"))
                        || (route.family == 14
                            && (route.path.contains("/sharing")
                                || route.path.starts_with("/drive")))
                        || route.target == Target::LocalRust);
                let external = mounted_api.then(|| format!("/api{}", route.path));
                let pattern = external.as_deref().unwrap_or(&route.path);
                let mut score = path_score(pattern, path)?;
                score.push(method_score);
                // A literal /api registration beats a mounted API route,
                // matching buildRootDispatch's unstripped lookup.
                score.push(u8::from(!mounted_api));
                // Auth's real /auth route wins over a proxy stub. On shared
                // paths (health, discovery, admin reload), preserve gateway
                // ownership; exclusive auth paths still beat its SPA subtree.
                let preferred = if path.starts_with("/auth/") {
                    "auth"
                } else {
                    "gateway"
                };
                score.push(u8::from(route.listener == preferred));
                Some((score, route))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, route)| route)
    }
}

pub(crate) fn unescape(segment: &str) -> Vec<u8> {
    let bytes = segment.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

pub(crate) fn path_score(pattern: &str, path: &str) -> Option<Vec<u8>> {
    // CONNECT authority form has an empty URL path; Go's root fallback still owns it.
    if pattern == "/" && path.is_empty() {
        return Some(vec![0]);
    }
    let want: Vec<_> = pattern.split('/').skip(1).collect();
    let got: Vec<_> = path.split('/').skip(1).collect();
    let mut score = Vec::new();
    for (i, part) in want.iter().enumerate() {
        if (part.is_empty() && i == want.len() - 1) || part.ends_with("...}") {
            if i >= got.len() {
                return None;
            }
            score.push(0);
            return Some(score);
        }
        let value = got.get(i)?;
        if *part == "{$}" {
            if !value.is_empty() {
                return None;
            }
            score.push(3);
        } else if part.starts_with('{') && part.ends_with('}') {
            if value.is_empty() {
                return None;
            }
            score.push(1);
        } else {
            if unescape(part) != unescape(value) {
                return None;
            }
            score.push(2);
        }
    }
    (want.len() == got.len()).then_some(score)
}
