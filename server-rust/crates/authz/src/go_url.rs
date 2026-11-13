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
