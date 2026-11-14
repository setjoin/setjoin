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
/// serves these unstripped; other methods answer 405/404 before any auth.
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

/// The `r.URL.Path` a mailserverd handler sees for raw request path `raw`, which is
/// what chain.go:434 `pathWithinScope` compares. `buildRootDispatch` (main.go:5067-5093)
/// serves a literal `/api` registration unstripped and every other `/api/...` path through
/// `http.StripPrefix("/api")`, which trims `Path` and `RawPath` and answers 404 when the
/// raw path's `/api` was escaped. Paths outside `/api/` reach handlers unchanged.
/// `None` = Go reaches no handler.
pub fn mailserver_handler_path(raw: &str) -> Option<Vec<u8>> {
    let path = request_path(raw)?;
    if !path.starts_with(b"/api/") || LITERAL_API.iter().any(|l| path == l.as_bytes()) {
        return Some(path);
    }
    raw.starts_with("/api").then(|| path[4..].to_vec())
}

#[cfg(test)]
mod handler_path_tests {
    use super::mailserver_handler_path as h;

    #[test]
    fn mirrors_go_root_dispatch_and_url_path() {
        let s = |p: &str| Some(p.as_bytes().to_vec());
        assert_eq!(h("/api/admin/users"), s("/admin/users"));
        assert_eq!(h("/api/admin/users/"), s("/admin/users/"));
        assert_eq!(h("/api/"), s("/"));
        assert_eq!(h("/api"), s("/api"));
        assert_eq!(h("/apix/y"), s("/apix/y"));
        assert_eq!(h("/admin/users"), s("/admin/users"));
        assert_eq!(h("/jmap"), s("/jmap"));
        assert_eq!(h("/api/adm%69n"), s("/admin"));
        assert_eq!(h("/api/a%2Fb"), s("/a/b"));
        assert_eq!(h("/api/a+b%20c"), s("/a+b c"));
        assert_eq!(h("/api/%ff"), Some(b"/\xff".to_vec()));
        // StripPrefix: RawPath "/%61pi/x" does not start with "/api" -> 404.
        assert_eq!(h("/%61pi/x"), None);
        assert_eq!(h("/api/a%zz"), None);
        assert_eq!(h("/api/a%2"), None);
        assert_eq!(h("/api/openapi.full.yaml"), s("/api/openapi.full.yaml"));
        assert_eq!(h("/api/openapi.full.yaml/"), s("/openapi.full.yaml/"));
        assert_eq!(h("/api/cert-hint"), s("/api/cert-hint"));
    }
}
