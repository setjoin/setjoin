//! Ports of the Go helpers the global source profiles are validated with:
//! `shared/ssrf` (`CompilePrivatePolicy`, `IsBlockedIP`,
//! `ValidateURLWithPrivatePolicy`), `net/url.Parse` as far as scheme, user
//! info and host are concerned, `net.ParseCIDR`, and `strconv.Quote`.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Go's `ssrf.ErrUnsafeURL` text.
pub const UNSAFE_URL: &str = "URL is not allowed (must be http/https to a public host)";
/// Go's `errInvalidEWSScheme` text.
pub const EWS_SCHEME: &str = "EWS server URL must use https scheme";

/// `strconv.Quote`: printable runes stay, the rest are escaped.
pub fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if c == '\u{fffd}' => out.push(c),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if is_print(c) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// Go's `unicode.IsPrint` approximated: letters, marks, numbers, punctuation,
/// symbols and the ASCII space; every other space, format or control rune is not.
fn is_print(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    let n = c as u32;
    if n < 0x20 || (0x7f..0xa0).contains(&n) {
        return false;
    }
    if c.is_whitespace() || c.is_control() {
        return false;
    }
    !matches!(n,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x8e2 | 0x180e | 0x200b..=0x200f
        | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff | 0xfff9..=0xfffb | 0xe000..=0xf8ff
        | 0xf0000..=0x10ffff | 0xd800..=0xdfff)
}

fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    }
}

fn private(ip: IpAddr) -> bool {
    match v4(ip) {
        Some(a) => a.is_private(),
        None => matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xfe00 == 0xfc00),
    }
}
fn loopback(ip: IpAddr) -> bool {
    match v4(ip) {
        Some(a) => a.is_loopback(),
        None => matches!(ip, IpAddr::V6(a) if a.is_loopback()),
    }
}
fn link_local_unicast(ip: IpAddr) -> bool {
    match v4(ip) {
        Some(a) => a.octets()[0] == 169 && a.octets()[1] == 254,
        None => matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80),
    }
}
fn multicast(ip: IpAddr) -> bool {
    match v4(ip) {
        Some(a) => a.is_multicast(),
        None => matches!(ip, IpAddr::V6(a) if a.octets()[0] == 0xff),
    }
}
fn unspecified(ip: IpAddr) -> bool {
    match v4(ip) {
        Some(a) => a.is_unspecified(),
        None => matches!(ip, IpAddr::V6(a) if a.is_unspecified()),
    }
}

fn in_v4(a: Ipv4Addr, net: [u8; 4], bits: u32) -> bool {
    let (x, n) = (u32::from(a), u32::from(Ipv4Addr::from(net)));
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    x & mask == n & mask
}
fn in_v6(a: Ipv6Addr, net: u128, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    u128::from(a) & mask == net & mask
}

/// `ssrf.blockedNets`.
fn blocked_net(ip: IpAddr) -> bool {
    if let Some(a) = v4(ip) {
        return [
            ([0, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([192, 31, 196, 0], 24),
            ([192, 52, 193, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 175, 48, 0], 24),
            ([198, 18, 0, 0], 15),
            ([240, 0, 0, 0], 4),
        ]
        .iter()
        .any(|(n, b)| in_v4(a, *n, *b));
    }
    let IpAddr::V6(a) = ip else { return false };
    in_v6(a, 0x0100_0000_0000_0000_0000_0000_0000_0000, 64)
        || in_v6(a, 0x2001_0db8_0000_0000_0000_0000_0000_0000, 32)
        || in_v6(a, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96)
}

/// `ssrf.IsBlockedIP`.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    loopback(ip)
        || private(ip)
        || link_local_unicast(ip)
        || multicast(ip)
        || unspecified(ip)
        || blocked_net(ip)
}

/// Go's `net.ParseIP`: dotted decimal without leading zeros, or IPv6 without a zone.
fn parse_ip(s: &str) -> Option<IpAddr> {
    if s.contains('%') {
        return None;
    }
    s.parse().ok()
}

/// `net.ParseCIDR` reduced to (first, last) address of the masked network.
fn parse_cidr(s: &str) -> Option<(IpAddr, IpAddr)> {
    let (addr, bits) = s.split_once('/')?;
    if addr.contains('%') {
        return None;
    }
    let ip: IpAddr = addr.parse().ok()?;
    if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = bits.parse().ok()?;
    if addr.contains(':') {
        if n > 128 {
            return None;
        }
        let x = match ip {
            IpAddr::V6(a) => u128::from(a),
            IpAddr::V4(_) => return None,
        };
        let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
        Some((
            IpAddr::V6(Ipv6Addr::from(x & mask)),
            IpAddr::V6(Ipv6Addr::from((x & mask) | !mask)),
        ))
    } else {
        if n > 32 {
            return None;
        }
        let IpAddr::V4(a) = ip else { return None };
        let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
        let x = u32::from(a);
        Some((
            IpAddr::V4(Ipv4Addr::from(x & mask)),
            IpAddr::V4(Ipv4Addr::from((x & mask) | !mask)),
        ))
    }
}

/// `permanentlyBlockedIP`: ranges no policy can allow.
fn permanently_blocked(ip: IpAddr) -> bool {
    loopback(ip) || link_local_unicast(ip) || multicast(ip) || unspecified(ip) || blocked_net(ip)
}

/// Whether `ip` lies within the (first, last) range of one CIDR.
fn within(ip: IpAddr, first: IpAddr, last: IpAddr) -> bool {
    match (ip, first, last) {
        (IpAddr::V4(a), IpAddr::V4(f), IpAddr::V4(l)) => f <= a && a <= l,
        (IpAddr::V6(a), IpAddr::V6(f), IpAddr::V6(l)) => f <= a && a <= l,
        _ => false,
    }
}

/// The dial-time verdict of `ssrf.dialContextWithPrivatePolicy` for one resolved
/// answer: allowed unless blocked, and a blocked private address is allowed only for an
/// allowlisted host name whose address lies in an allowlisted CIDR.
pub fn dial_allowed(hosts: &[String], cidrs: &[String], host: &str, ip: IpAddr) -> bool {
    if !is_blocked_ip(ip) {
        return true;
    }
    let host_ok = {
        let h = host.strip_suffix('.').unwrap_or(host).to_lowercase();
        hosts.iter().any(|raw| {
            let t = go_trim_space(raw);
            t.strip_suffix('.').unwrap_or(t).to_lowercase() == h
        })
    };
    host_ok
        && private(ip)
        && !permanently_blocked(ip)
        && cidrs.iter().any(|raw| {
            parse_cidr(go_trim_space(raw)).is_some_and(|(first, last)| within(ip, first, last))
        })
}

/// `ssrf.CompilePrivatePolicy`: the error text Go returns, or `Ok`.
pub fn compile_private_policy(hosts: &[String], cidrs: &[String]) -> Result<(), String> {
    for raw in hosts {
        let trimmed = go_trim_space(raw);
        let host = trimmed.strip_suffix('.').unwrap_or(trimmed).to_lowercase();
        if host.is_empty() || host.contains(['/', ':', '@', '[', ']']) || parse_ip(&host).is_some()
        {
            return Err(format!("invalid private-policy hostname {}", quote(raw)));
        }
    }
    let mut nets = 0usize;
    for raw in cidrs {
        let ok = parse_cidr(go_trim_space(raw)).is_some_and(|(a, b)| private(a) && private(b));
        if !ok {
            return Err(format!("invalid private-policy CIDR {}", quote(raw)));
        }
        nets += 1;
    }
    // The compiled policy stores hosts in a set: duplicates collapse.
    let distinct = {
        let mut set = std::collections::BTreeSet::new();
        for raw in hosts {
            let t = go_trim_space(raw);
            set.insert(t.strip_suffix('.').unwrap_or(t).to_lowercase());
        }
        set.len()
    };
    if (distinct == 0 && nets != 0) || (distinct != 0 && nets == 0) {
        return Err("private-policy hosts and CIDRs must be configured together".into());
    }
    Ok(())
}

/// `strings.TrimSpace` (Unicode white space).
fn go_trim_space(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{85}')
}

/// What the validators read from Go's `url.Parse` result.
pub struct GoUrl {
    pub scheme: String,
    pub has_user: bool,
    pub hostname: String,
    /// Go's `u.Host` after percent decoding (before the port is split off).
    pub host: String,
}

fn unhex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// `validOptionalPort`.
fn valid_optional_port(port: &str) -> bool {
    match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(rest) => rest.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// `unescape(host, encodeHost)`.
fn unescape_host(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let (h, l) = (
                    b.get(i + 1).copied().and_then(unhex)?,
                    b.get(i + 2).copied().and_then(unhex)?,
                );
                if h < 8 && &b[i..i + 3] != b"%25" {
                    return None;
                }
                out.push(h << 4 | l);
                i += 3;
            }
            c if c < 0x80 && !host_char(c) => return None,
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Characters `shouldEscape(c, encodeHost)` leaves alone.
fn host_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&c)
}

/// `url.parseHost`.
fn parse_host(host: &str) -> Option<String> {
    if host.starts_with('[') {
        let end = host.rfind(']')?;
        let colon_port = &host[end + 1..];
        if !valid_optional_port(colon_port) {
            return None;
        }
        // A zone is introduced by `%25`; anything else escaped is decoded as for hosts.
        if let Some(zone) = host[..end].find("%25") {
            let (head, zone_part) = host.split_at(zone);
            let head = unescape_host(head)?;
            let zone_part = unescape_zone(&zone_part[..end - zone])?;
            return Some(format!("{head}{zone_part}{colon_port}"));
        }
    } else if let Some(i) = host.rfind(':') {
        if !valid_optional_port(&host[i..]) {
            return None;
        }
    }
    unescape_host(host)
}

fn unescape_zone(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (h, l) = (
                b.get(i + 1).copied().and_then(unhex)?,
                b.get(i + 2).copied().and_then(unhex)?,
            );
            out.push(h << 4 | l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `url.validUserinfo`.
fn valid_userinfo(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&c))
}

/// The part of Go's `url.Parse` the EWS validators depend on; `None` is a parse error.
pub fn parse_url(raw: &str) -> Option<GoUrl> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let rest = raw.split('#').next().unwrap_or("");
    // getScheme
    let mut scheme = String::new();
    let mut tail = rest;
    for (i, c) in rest.char_indices() {
        match c {
            'a'..='z' | 'A'..='Z' => {}
            '0'..='9' | '+' | '-' | '.' if i > 0 => {}
            ':' => {
                if i == 0 {
                    return None;
                }
                scheme = rest[..i].to_ascii_lowercase();
                tail = &rest[i + 1..];
                break;
            }
            _ => break,
        }
    }
    let (path_part, _query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    if scheme.is_empty() && !path_part.starts_with('/') {
        if let Some(first) = path_part.split('/').next() {
            if first.contains(':') {
                return None;
            }
        }
    }
    let mut url = GoUrl {
        scheme,
        has_user: false,
        hostname: String::new(),
        host: String::new(),
    };
    if let Some(after) = path_part.strip_prefix("//") {
        {
            let end = after.find('/').unwrap_or(after.len());
            let authority = &after[..end];
            let host_part = match authority.rfind('@') {
                None => authority,
                Some(i) => {
                    let info = &authority[..i];
                    if !valid_userinfo(info) {
                        return None;
                    }
                    // percent escapes must be well formed
                    let b = info.as_bytes();
                    let mut k = 0;
                    while k < b.len() {
                        if b[k] == b'%' {
                            b.get(k + 1).copied().and_then(unhex)?;
                            b.get(k + 2).copied().and_then(unhex)?;
                            k += 3;
                        } else {
                            k += 1;
                        }
                    }
                    url.has_user = true;
                    &authority[i + 1..]
                }
            };
            url.host = parse_host(host_part)?;
        }
    }
    // Hostname(): strip a valid port, then the brackets.
    let mut h = url.host.as_str();
    if let Some(i) = h.rfind(':') {
        if valid_optional_port(&h[i..]) {
            h = &h[..i];
        }
    }
    if h.starts_with('[') && h.ends_with(']') && h.len() >= 2 {
        h = &h[1..h.len() - 1];
    }
    url.hostname = h.to_owned();
    Some(url)
}

/// `validateEWSServerURL` with the policy hosts that are allowed to name a private target.
/// The error text is what Go's `ValidateGlobalEWSProfile` wraps after `invalid serverURL: `.
pub fn validate_ews_url(raw: &str, allowed_hosts: &[String]) -> Result<(), &'static str> {
    let u = parse_url(raw).ok_or(EWS_SCHEME)?;
    if u.scheme != "https" || u.hostname.is_empty() {
        return Err(EWS_SCHEME);
    }
    if u.has_user {
        return Err(UNSAFE_URL);
    }
    if let Some(ip) = parse_ip(&u.hostname) {
        return if is_blocked_ip(ip) {
            Err(UNSAFE_URL)
        } else {
            Ok(())
        };
    }
    let lower = u.hostname.to_lowercase();
    let host = lower.strip_suffix('.').unwrap_or(&lower);
    let allowed = allowed_hosts.iter().any(|h| {
        let t = go_trim_space(h);
        t.strip_suffix('.').unwrap_or(t).to_lowercase() == host
    });
    if !allowed && lower.ends_with(".local") {
        return Err(UNSAFE_URL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn quote_matches_go() {
        assert_eq!(quote("ssl3"), "\"ssl3\"");
        assert_eq!(quote("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        assert_eq!(quote("é\u{1}\u{7f}\u{200b}"), "\"é\\x01\\x7f\\u200b\"");
    }

    #[test]
    fn policy_rules() {
        assert!(compile_private_policy(&[], &[]).is_ok());
        assert!(compile_private_policy(&s(&["Mail.Example.COM."]), &s(&["10.0.0.0/8"])).is_ok());
        assert!(compile_private_policy(&s(&["mail.example.com"]), &[])
            .unwrap_err()
            .contains("together"));
        assert!(compile_private_policy(&[], &s(&["10.0.0.0/8"]))
            .unwrap_err()
            .contains("together"));
        assert_eq!(
            compile_private_policy(&s(&["1.2.3.4"]), &s(&["10.0.0.0/8"])).unwrap_err(),
            "invalid private-policy hostname \"1.2.3.4\""
        );
        assert!(compile_private_policy(&s(&["a:b"]), &s(&["10.0.0.0/8"])).is_err());
        assert!(compile_private_policy(&s(&["h"]), &s(&["8.8.8.0/24"]))
            .unwrap_err()
            .contains("CIDR"));
        assert!(compile_private_policy(&s(&["h"]), &s(&["10.0.0.0/7"])).is_err());
        assert!(compile_private_policy(&s(&["h"]), &s(&["fd00::/8"])).is_ok());
        assert!(compile_private_policy(&s(&["h"]), &s(&["127.0.0.0/8"])).is_err());
        assert!(compile_private_policy(&s(&["h"]), &s(&["10.0.0.0"])).is_err());
    }

    #[test]
    fn blocked_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "224.0.0.1",
            "0.0.0.0",
            "::ffff:10.0.0.1",
            "64:ff9b::1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700::1"] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ews_urls() {
        let none: Vec<String> = vec![];
        assert_eq!(
            validate_ews_url("https://mail.example.com/EWS/Exchange.asmx", &none),
            Ok(())
        );
        assert_eq!(
            validate_ews_url("http://mail.example.com", &none),
            Err(EWS_SCHEME)
        );
        assert_eq!(validate_ews_url("https://", &none), Err(EWS_SCHEME));
        assert_eq!(validate_ews_url("mail.example.com", &none), Err(EWS_SCHEME));
        assert_eq!(
            validate_ews_url("https://u:p@mail.example.com", &none),
            Err(UNSAFE_URL)
        );
        assert_eq!(
            validate_ews_url("https://10.0.0.5/x", &s(&["10.0.0.5"])),
            Err(UNSAFE_URL)
        );
        assert_eq!(
            validate_ews_url("https://exch.local/x", &none),
            Err(UNSAFE_URL)
        );
        assert_eq!(
            validate_ews_url("https://exch.local/x", &s(&["exch.local"])),
            Ok(())
        );
        assert_eq!(validate_ews_url("https://8.8.8.8/x", &none), Ok(()));
        assert_eq!(
            validate_ews_url("https://[::1]:443/x", &none),
            Err(UNSAFE_URL)
        );
        assert_eq!(
            validate_ews_url("https://host:99x/x", &none),
            Err(EWS_SCHEME)
        );
        assert_eq!(validate_ews_url("HTTPS://Host/x", &none), Ok(()));
        assert_eq!(validate_ews_url("https://ho st/x", &none), Err(EWS_SCHEME));
    }
}
