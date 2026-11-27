//! Frozen Go net/url authority parser, moved verbatim from gateway link_protect.
fn ishex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// `unescape(s, mode)` validity. `host` adds the host-mode refusals.
fn escapes_ok(s: &str, host: bool) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return false;
                }
                if !ishex(b[i + 1]) || !ishex(b[i + 2]) {
                    return false;
                }
                if host {
                    let high = (b[i + 1] as char).to_digit(16).unwrap_or(0);
                    if high < 8 && &s[i..i + 3] != "%25" {
                        return false;
                    }
                }
                i += 3;
                continue;
            }
            c if host && c < 0x80 => {
                let allowed = c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        b'-' | b'_'
                            | b'.'
                            | b'~'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                            | b':'
                            | b'['
                            | b']'
                            | b'<'
                            | b'>'
                            | b'"'
                    );
                if !allowed {
                    return false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    true
}

/// `unescape` (percent-decoding) of a host that already passed `escapes_ok(.., true)`.
fn decode_percent(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let v = u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(0);
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn valid_optional_port(port: &str) -> bool {
    match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(digits) => digits.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// What `url.Parse` yields that the handlers need: scheme and decoded `Host` (with port).
pub struct GoUrl {
    pub scheme: String,
    pub host: String,
}

/// `url.Parse(raw)`: `Err` where Go errors. Only the pieces whose failure or value matters here
/// (scheme, authority, escape validity of path and fragment) are modelled.
#[allow(clippy::result_unit_err)]
pub fn go_url_parse(raw: &str) -> Result<GoUrl, ()> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(());
    }
    let (u, fragment) = match raw.split_once('#') {
        Some((u, f)) => (u, Some(f)),
        None => (raw, None),
    };
    // getScheme
    let mut scheme = String::new();
    let mut rest = u;
    for (i, ch) in u.bytes().enumerate() {
        match ch {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    break;
                }
            }
            b':' => {
                if i == 0 {
                    return Err(());
                }
                scheme = u[..i].to_ascii_lowercase();
                rest = &u[i + 1..];
                break;
            }
            _ => break,
        }
    }
    let rest = if rest.ends_with('?') && rest.matches('?').count() == 1 {
        &rest[..rest.len() - 1]
    } else {
        rest.split_once('?').map_or(rest, |(p, _)| p)
    };
    let mut host = String::new();
    if !rest.starts_with('/') {
        if !scheme.is_empty() {
            // Opaque URL: no authority.
            return Ok(GoUrl { scheme, host });
        }
        if rest.split('/').next().is_some_and(|s| s.contains(':')) {
            return Err(());
        }
    }
    let path = if (!scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let after = &rest[2..];
        let (authority, path) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        };
        let host_part = match authority.rfind('@') {
            Some(i) => {
                let info = &authority[..i];
                let valid = info.chars().all(|c| {
                    c.is_alphanumeric()
                        || matches!(
                            c,
                            '-' | '.'
                                | '_'
                                | ':'
                                | '~'
                                | '!'
                                | '$'
                                | '&'
                                | '\''
                                | '('
                                | ')'
                                | '*'
                                | '+'
                                | ','
                                | ';'
                                | '='
                                | '%'
                                | '@'
                        )
                });
                if !valid || !escapes_ok(info, false) {
                    return Err(());
                }
                &authority[i + 1..]
            }
            None => authority,
        };
        host = parse_host(host_part)?;
        path
    } else {
        rest
    };
    if !escapes_ok(path, false) {
        return Err(());
    }
    if let Some(f) = fragment {
        if !escapes_ok(f, false) {
            return Err(());
        }
    }
    Ok(GoUrl { scheme, host })
}

fn parse_host(host: &str) -> Result<String, ()> {
    if host.starts_with('[') {
        let close = host.rfind(']').ok_or(())?;
        if !valid_optional_port(&host[close + 1..]) {
            return Err(());
        }
        if let Some(zone) = host[..close].find("%25") {
            if !escapes_ok(&host[..zone], true)
                || !escapes_ok(&host[zone..close], false)
                || !escapes_ok(&host[close..], true)
            {
                return Err(());
            }
            return Ok(format!(
                "{}{}{}",
                decode_percent(&host[..zone]),
                decode_percent(&host[zone..close]),
                decode_percent(&host[close..])
            ));
        }
    } else if let Some(colon) = host.rfind(':') {
        if !valid_optional_port(&host[colon..]) {
            return Err(());
        }
    }
    if !escapes_ok(host, true) {
        return Err(());
    }
    Ok(decode_percent(host))
}

/// `parseURLHost`: the lower-cased `Hostname()` of an authority-bearing URL.
#[allow(clippy::result_unit_err)]
pub fn parse_url_host(raw: &str) -> Result<String, ()> {
    if raw.is_empty() {
        return Err(());
    }
    let parsed = go_url_parse(raw)?;
    if parsed.host.is_empty() {
        return Err(());
    }
    let mut host = parsed.host.as_str();
    if let Some(colon) = host.rfind(':') {
        if valid_optional_port(&host[colon..]) {
            host = &host[..colon];
        }
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    let host = host.to_lowercase();
    if host.is_empty() {
        return Err(());
    }
    Ok(host)
}

/// `url.URL.Path` of a request path: Go's `unescape(s, encodePath)` decodes every `%XX`
/// (`%2F` included) and keeps other bytes. `None` where Go's request parsing fails
/// (a malformed escape answers 400 before any handler).
pub fn request_path(raw: &str) -> Option<Vec<u8>> {
    if !escapes_ok(raw, false) {
        return None;
    }
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&raw[i + 1..i + 3], 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// The GET-only `apiMux` registrations with a literal `/api` path
/// (mailserver/cmd/mailserverd/main.go:3594-3605, 3651, 3791). `buildRootDispatch`
/// serves these unstripped for GET and HEAD (a `GET` pattern also matches HEAD); any
/// other method finds no pattern there and goes through `StripPrefix` like every path.
const LITERAL_API: [&str; 11] = [
    "/api/openapi.yaml",
    "/api/openapi.json",
    "/api/docs",
    "/api/redoc.standalone.js",
    "/api/logo.svg",
    "/api/fonts/ibm-plex-sans-400.woff2",
    "/api/fonts/ibm-plex-sans-500.woff2",
    "/api/openapi.full.yaml",
    "/api/openapi.full.json",
    "/api/discover",
    "/api/cert-hint",
];

/// `apiPinnedPrefixes` (main.go:5032-5039): bare paths the root `/` branch serves.
const PINNED: [&str; 26] = [
    "/auth",
    "/jmap",
    "/.well-known",
    "/caldav",
    "/carddav",
    "/scim",
    "/setup",
    "/approvals/email",
    "/link-protect",
    "/admin/migration/m365",
    "/updates",
    "/downloads",
    "/health",
    "/ready",
    "/metrics",
    "/api",
    "/mail-attachment",
    "/favicon.ico",
    "/terms",
    "/rtc",
    "/authorize",
    "/oauth",
    "/userinfo",
    "/keys",
    "/end_session",
    "/revoke",
];

/// net/url `shouldEscape(c, encodePath)`.
fn should_escape_path(c: u8) -> bool {
    !(c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'$'
                | b'&'
                | b'+'
                | b','
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'@'
        ))
}

/// net/url `escape(s, encodePath)`: what `URL.EscapedPath` falls back to.
fn escape_path(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for &c in path {
        if should_escape_path(c) {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(c as char);
        }
    }
    out
}

/// net/url `validEncoded(s, encodePath)`.
fn valid_encoded(s: &str) -> bool {
    s.bytes().all(|c| {
        matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape_path(c)
    })
}

/// `cleanPath(p) == p` (net/http server.go:2591): rooted, no empty segment except a
/// trailing slash, no `.`/`..` segment. A request whose escaped path is not clean is
/// answered with a redirect to the cleaned path before any handler runs.
fn is_clean(p: &str) -> bool {
    let Some(rest) = p.strip_prefix('/') else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let segs: Vec<&str> = rest.split('/').collect();
    let last = segs.len() - 1;
    segs.iter()
        .enumerate()
        .all(|(i, s)| *s != "." && *s != ".." && (!s.is_empty() || i == last))
}

/// The `r.URL.Path` a mailserverd handler sees for request `method` and raw request path
/// `raw`, which is what chain.go:434 `pathWithinScope` compares. `None` = Go reaches no
/// handler. Mirrors Go 1.26 net/http and `buildRootDispatch` (main.go:5067-5107):
/// - `url.ParseRequestURI` fails on a malformed escape: 400.
/// - `ServeMux.findHandler` (server.go:2657) works on `URL.EscapedPath()` (the raw path
///   when `validEncoded`, else `escape(Path)`); an unclean one (`//`, `.`, `..`) gets a
///   redirect to the cleaned path; `/api` alone gets the trailing-slash redirect to `/api/`.
/// - Patterns match segment by segment, each `url.PathUnescape`d, so `/api%2Fdrive/x`
///   (first segment `api/drive`) misses the `/api/` mount and every `apiMux` pattern
///   (none has a wildcard first segment): the SPA answers.
/// - Under `/api/`: a literal `/api` registration is served unstripped for GET/HEAD;
///   otherwise `http.StripPrefix("/api")` trims `Path` and `RawPath` and answers 404
///   when the raw path's `/api` was escaped.
/// - Elsewhere only `apiPinnedPrefixes` reach a handler (unchanged path); other bare
///   paths get the SPA (GET/HEAD) or the legacy 308 to `/api/...`.
pub fn mailserver_handler_path(method: &str, raw: &str) -> Option<Vec<u8>> {
    let path = request_path(raw)?;
    let escaped = if valid_encoded(raw) {
        raw.to_owned()
    } else {
        escape_path(&path)
    };
    if !is_clean(&escaped) {
        return None;
    }
    // Every escape in `escaped` is valid here, so `PathUnescape` equals `request_path`.
    let segs: Vec<Vec<u8>> = escaped[1..]
        .split('/')
        .map(|s| request_path(s).unwrap_or_default())
        .collect();
    if segs[0] == b"api" {
        if segs.len() == 1 {
            return None;
        }
        let get = matches!(method, "GET" | "HEAD");
        if get
            && LITERAL_API.iter().any(|l| {
                l[1..]
                    .split('/')
                    .map(str::as_bytes)
                    .eq(segs.iter().map(Vec::as_slice))
            })
        {
            return Some(path);
        }
        // `setPath` keeps `RawPath` only when it differs from `escape(Path)`.
        let raw_path = if escape_path(&path) == raw { "" } else { raw };
        return (raw_path.is_empty() || raw_path.starts_with("/api")).then(|| path[4..].to_vec());
    }
    if segs[0].contains(&b'/') {
        return None;
    }
    PINNED
        .iter()
        .any(|p| {
            path == p.as_bytes()
                || (path.starts_with(p.as_bytes()) && path.get(p.len()) == Some(&b'/'))
        })
        .then_some(path)
}

#[cfg(test)]
mod handler_path_tests {
    use super::mailserver_handler_path;

    fn h(p: &str) -> Option<Vec<u8>> {
        mailserver_handler_path("GET", p)
    }
    fn s(p: &str) -> Option<Vec<u8>> {
        Some(p.as_bytes().to_vec())
    }

    #[test]
    fn mirrors_go_root_dispatch_and_url_path() {
        assert_eq!(h("/api/admin/users"), s("/admin/users"));
        assert_eq!(h("/api/admin/users/"), s("/admin/users/"));
        assert_eq!(h("/api/"), s("/"));
        assert_eq!(h("/jmap"), s("/jmap"));
        assert_eq!(h("/jmap/session"), s("/jmap/session"));
        assert_eq!(h("/jm%61p"), s("/jmap"));
        assert_eq!(h("/admin/migration/m365/x"), s("/admin/migration/m365/x"));
        assert_eq!(h("/api/adm%69n"), s("/admin"));
        assert_eq!(h("/api/a%2Fb"), s("/a/b"));
        assert_eq!(h("/api/a+b%20c"), s("/a+b c"));
        assert_eq!(h("/api/%ff"), Some(b"/\xff".to_vec()));
        // An encoded dot is a literal segment to cleanPath.
        assert_eq!(h("/api/%2E%2E/admin"), s("/../admin"));
        // StripPrefix: RawPath "/%61pi/x" does not start with "/api" -> 404.
        assert_eq!(h("/%61pi/x"), None);
        assert_eq!(h("/api/a%zz"), None);
        assert_eq!(h("/api/a%2"), None);
        assert_eq!(h("/api/openapi.full.yaml"), s("/api/openapi.full.yaml"));
        assert_eq!(h("/api/openapi.full.yaml/"), s("/openapi.full.yaml/"));
        assert_eq!(h("/api/cert-hint"), s("/api/cert-hint"));
        assert_eq!(h("/api/d%6Fcs"), s("/api/docs"));
    }

    /// Go's ServeMux redirects an unclean escaped path (307 in Go 1.26) and `/api` to
    /// `/api/` before any handler runs.
    #[test]
    fn unclean_paths_and_bare_api_reach_no_handler() {
        for p in [
            "/api/drive/../admin/x",
            "/api/drive/./x",
            "/api//drive/x",
            "//api/drive/x",
            "/api/drive//",
            "/api/..",
            "/jmap/../api/x",
            "/api",
            "/%61pi",
            "/api/x/.",
        ] {
            assert_eq!(h(p), None, "{p}");
        }
        // A byte that is not validEncoded makes EscapedPath re-escape Path, so the
        // decoded `%2F` becomes a real separator for matching (and stays clean).
        assert_eq!(h("/api%2Fdrive/\u{e9}"), s("/drive/\u{e9}"));
        assert_eq!(h("/api/a%2F..%2Fb/\u{e9}"), None);
    }

    /// An escaped slash in the first segment misses the `/api/` mount and every apiMux
    /// pattern: the SPA answers.
    #[test]
    fn encoded_slash_in_the_mount_segment_reaches_no_handler() {
        assert_eq!(h("/api%2Fdrive/x"), None);
        assert_eq!(h("/api%2fadmin/users"), None);
        assert_eq!(mailserver_handler_path("POST", "/api%2Fdrive/x"), None);
    }

    /// Bare paths outside apiPinnedPrefixes get the SPA (GET/HEAD) or the legacy 308.
    #[test]
    fn unpinned_bare_paths_reach_no_handler() {
        for m in ["GET", "HEAD", "POST", "DELETE"] {
            for p in [
                "/drive/x",
                "/drive",
                "/admin/users",
                "/apix/y",
                "/jmapx",
                "/admin/migration",
            ] {
                assert_eq!(mailserver_handler_path(m, p), None, "{m} {p}");
            }
            assert_eq!(mailserver_handler_path(m, "/auth/x"), s("/auth/x"), "{m}");
        }
    }

    /// The literal `/api` registrations are `GET` patterns (HEAD matches them too); any
    /// other method is stripped like every other `/api/...` path.
    #[test]
    fn literal_api_routes_are_method_aware() {
        for m in ["GET", "HEAD"] {
            assert_eq!(
                mailserver_handler_path(m, "/api/docs"),
                s("/api/docs"),
                "{m}"
            );
            assert_eq!(
                mailserver_handler_path(m, "/api/discover"),
                s("/api/discover"),
                "{m}"
            );
        }
        for m in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "get"] {
            assert_eq!(mailserver_handler_path(m, "/api/docs"), s("/docs"), "{m}");
            assert_eq!(
                mailserver_handler_path(m, "/api/cert-hint"),
                s("/cert-hint"),
                "{m}"
            );
        }
    }
}
