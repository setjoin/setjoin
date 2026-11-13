//! Client identity the gateway forwards to Go (#220).
//!
//! Mirrors `shared/clientip` exactly so the Go side resolves the same client
//! as it would without the gateway:
//!
//! - Trust is anchored to the immediate socket peer, never to request data.
//!   Forwarded headers are read only when that peer is in the configured
//!   trusted-proxy set (default: empty, so client headers are never trusted).
//! - From a trusted peer the RIGHTMOST `X-Forwarded-For` entry across every
//!   header line is the client; a malformed rightmost entry fails closed to
//!   the socket peer (earlier entries are never a fallback).
//! - `X-Forwarded-Proto` is honoured only from a trusted peer, last line wins,
//!   `http`/`https` case-insensitive; anything else fails closed to `http`
//!   (this listener is plaintext).
//!
//! Every client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`,
//! `X-Forwarded-Proto` and `X-Real-IP` is removed before forwarding and the
//! gateway sets exactly one `X-Forwarded-For` (the resolved client IP),
//! `X-Forwarded-Proto` and `X-Forwarded-Host` (the inbound `Host`), the shape
//! `mailserver/internal/authproxy` already sends to authserver.

use std::net::IpAddr;

use hyper::header::{HeaderMap, HeaderValue, HOST};

/// Client-supplied identity headers that are always removed.
pub const STRIPPED: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Peers whose forwarded headers are trusted: exact IPs and CIDR ranges.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    nets: Vec<(IpAddr, u8)>,
}

impl TrustedProxies {
    /// Parses a comma-separated list of IPs and CIDRs (`""` = trust nobody).
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (addr, bits) = match item.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (item, None),
            };
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| format!("invalid trusted proxy address {item:?}"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let bits = match bits {
                Some(b) => b
                    .parse::<u8>()
                    .ok()
                    .filter(|b| *b <= max)
                    .ok_or_else(|| format!("invalid trusted proxy prefix {item:?}"))?,
                None => max,
            };
            // Canonicalizing a mapped address also changes its prefix width:
            // ::ffff:127.0.0.1/128 is IPv4 127.0.0.1/32, as Go's IPNet.Contains.
            // Prefixes shorter than the mapping remain IPv6 networks.
            let (ip, bits) = match ip {
                IpAddr::V6(v6) if bits >= 96 => match v6.to_ipv4_mapped() {
                    Some(v4) => (IpAddr::V4(v4), bits - 96),
                    None => (ip, bits),
                },
                _ => (ip, bits),
            };
            nets.push((ip, bits));
        }
        Ok(Self { nets })
    }

    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = canonical(peer);
        self.nets
            .iter()
            .any(|(net, bits)| in_prefix(peer, *net, *bits))
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn in_prefix(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            mask_eq(u32::from(a).into(), u32::from(b).into(), bits, 32)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => mask_eq(u128::from(a), u128::from(b), bits, 128),
        _ => false,
    }
}

fn mask_eq(a: u128, b: u128, bits: u8, width: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let shift = u32::from(width - bits);
    (a >> shift) == (b >> shift)
}

/// The identity the gateway forwards for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    pub client_ip: IpAddr,
    pub proto: &'static str,
}

/// Resolves the client from the socket peer and (only if trusted) the
/// inbound forwarded headers.
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &TrustedProxies) -> ClientIdentity {
    let peer = canonical(peer);
    if !trusted.contains(peer) {
        return ClientIdentity {
            client_ip: peer,
            proto: "http",
        };
    }
    let client_ip = rightmost_forwarded_for(headers).unwrap_or(peer);
    let proto = headers
        .get_all("x-forwarded-proto")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase());
    let proto = match proto.as_deref() {
        Some("https") => "https",
        _ => "http",
    };
    ClientIdentity { client_ip, proto }
}

fn rightmost_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    // Only the last line can hold the rightmost entry; a non-UTF-8 last line
    // is malformed and fails closed.
    let last = headers.get_all("x-forwarded-for").iter().next_back()?;
    let entry = last.to_str().ok()?.rsplit(',').next()?.trim();
    let entry = entry
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(entry);
    let entry = entry.split('%').next()?;
    entry.parse::<IpAddr>().ok().map(canonical)
}

/// Removes client-supplied identity headers and sets the gateway's own.
pub fn apply(headers: &mut HeaderMap, id: &ClientIdentity) {
    let host = headers.get(HOST).cloned();
    for name in STRIPPED {
        headers.remove(name);
    }
    // An IP's text form is always a valid header value; no panic path.
    if let Ok(ip) = HeaderValue::from_str(&id.client_ip.to_string()) {
        headers.insert("x-forwarded-for", ip);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static(id.proto));
    if let Some(host) = host {
        headers.insert("x-forwarded-host", host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_ignores_every_forwarded_header() {
        let h = headers(&[
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-proto", "https"),
        ]);
        let id = resolve(ip("198.51.100.4"), &h, &TrustedProxies::parse("").unwrap());
        assert_eq!(
            id,
            ClientIdentity {
                client_ip: ip("198.51.100.4"),
                proto: "http"
            }
        );
    }

    #[test]
    fn trusted_peer_uses_rightmost_entry_across_all_lines() {
        let h = headers(&[
            ("x-forwarded-for", "1.1.1.1, 2.2.2.2"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-proto", "HTTPS"),
        ]);
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let id = resolve(ip("10.1.2.3"), &h, &trusted);
        assert_eq!(
            id,
            ClientIdentity {
                client_ip: ip("203.0.113.9"),
                proto: "https"
            }
        );
    }

    #[test]
    fn malformed_rightmost_entry_fails_closed_to_peer_not_earlier_entries() {
        let h = headers(&[("x-forwarded-for", "203.0.113.9, not-an-ip")]);
        let trusted = TrustedProxies::parse("127.0.0.1").unwrap();
        assert_eq!(
            resolve(ip("127.0.0.1"), &h, &trusted).client_ip,
            ip("127.0.0.1")
        );
    }

    #[test]
    fn bracketed_and_zoned_ipv6_entries_are_normalised() {
        let trusted = TrustedProxies::parse("::1").unwrap();
        let h = headers(&[("x-forwarded-for", "[fe80::1%25eth0]")]);
        assert_eq!(resolve(ip("::1"), &h, &trusted).client_ip, ip("fe80::1"));
        let h = headers(&[("x-forwarded-for", "2001:db8::7%eth0")]);
        assert_eq!(
            resolve(ip("::1"), &h, &trusted).client_ip,
            ip("2001:db8::7")
        );
    }

    #[test]
    fn unknown_proto_from_trusted_peer_fails_closed_to_http() {
        let h = headers(&[("x-forwarded-proto", "gopher")]);
        let trusted = TrustedProxies::parse("127.0.0.1").unwrap();
        assert_eq!(resolve(ip("127.0.0.1"), &h, &trusted).proto, "http");
    }

    #[test]
    fn ipv4_mapped_peer_matches_ipv4_trust_entry() {
        let trusted = TrustedProxies::parse("127.0.0.1").unwrap();
        assert!(trusted.contains(ip("::ffff:127.0.0.1")));
        assert!(!trusted.contains(ip("127.0.0.2")));
    }

    #[test]
    fn bad_trust_entries_are_rejected() {
        assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
        assert!(TrustedProxies::parse("example.com").is_err());
        assert!(TrustedProxies::parse(" 10.0.0.1 , ::1/128 ").is_ok());
    }
}
