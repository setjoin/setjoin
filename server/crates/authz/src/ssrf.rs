//! Frozen shared/ssrf literal-IP policy. DNS/dial enforcement belongs to the sender.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_v4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => blocked_v4(v4),
            None => blocked_v6(ip),
        },
    }
}

fn blocked_v4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
    {
        return true;
    }
    let number = u32::from(ip);
    [
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
    .into_iter()
    .any(|(network, bits): ([u8; 4], u32)| {
        number & (u32::MAX << (32 - bits)) == u32::from(Ipv4Addr::from(network))
    })
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
    {
        return true;
    }
    let number = u128::from(ip);
    [
        (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64),
        (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
    ]
    .into_iter()
    .any(|(network, bits): (Ipv6Addr, u32)| {
        number & (u128::MAX << (128 - bits)) == u128::from(network)
    })
}

/// Go ValidateURL: public http(s) authority, retaining net/url's hostname rules.
pub fn valid_public_http(raw: &str) -> bool {
    let Ok(url) = crate::go_url::go_url_parse(raw) else {
        return false;
    };
    if !matches!(url.scheme.as_str(), "http" | "https") {
        return false;
    }
    let Ok(host) = crate::go_url::parse_url_host(raw) else {
        return false;
    };
    host.parse::<IpAddr>().map_or(true, |ip| !blocked(ip))
}
