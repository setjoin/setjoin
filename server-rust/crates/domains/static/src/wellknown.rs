//! `mailserver/internal/wellknown`: `/.well-known/setjoin` and the
//! Thunderbird autoconfig document.
use setjoin_pg::{ScopedExecutor, Type};

/// Go's `encoding/json` string form (HTML-escaped `<`, `>`, `&`, U+2028/9).
pub fn go_json_string(s: &str) -> String {
    let raw = serde_json::to_string(s).expect("string JSON");
    raw.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Process configuration the `/.well-known/setjoin` document reports.
#[derive(Clone, Debug)]
pub struct SetJoinConfig {
    /// `crypto.algorithm_profile`: standard, smx or hybrid.
    pub crypto_profile: String,
    /// `auth.login_field`; empty means `email`.
    pub login_field: String,
    pub login_domain_hint: String,
}

/// `SetJoinResponse` as `httputil.WriteJSON` encodes it (declaration order,
/// `push_relay` and an empty hint omitted, trailing newline).
pub fn setjoin_document(config: &SetJoinConfig) -> String {
    let algorithm = if config.crypto_profile == "smx" {
        "SM4-GCM"
    } else {
        "AES-256-GCM"
    };
    let login_field = if config.login_field.is_empty() {
        "email"
    } else {
        &config.login_field
    };
    let profile = go_json_string(&config.crypto_profile);
    let mut out = format!(
        "{{\"version\":\"1.0\",\"crypto_profile\":{profile},\"crypto_algorithm\":\"{algorithm}\",\"mam_enabled\":true,\"mam_min_version\":1,\"features\":[\"jmap\",\"mam\",\"push\",{profile}],\"login_field\":{}",
        go_json_string(login_field)
    );
    if !config.login_domain_hint.is_empty() {
        out.push_str(&format!(
            ",\"login_domain_hint\":{}",
            go_json_string(&config.login_domain_hint)
        ));
    }
    out.push_str("}\n");
    out
}

/// `html/template`'s HTML escaper (text and quoted-attribute contexts).
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\0' => out.push('\u{FFFD}'),
            '"' => out.push_str("&#34;"),
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '+' => out.push_str("&#43;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

/// The host part of a `Host` header, lowercased, the way `HandleAutoconfig`
/// derives the domain (`net.SplitHostPort` when it succeeds).
pub fn autoconfig_domain(host: &str) -> String {
    split_host_port(host).unwrap_or(host).to_lowercase()
}

/// `net.SplitHostPort`'s host, or `None` where Go returns an error.
fn split_host_port(h: &str) -> Option<&str> {
    if let Some(rest) = h.strip_prefix('[') {
        let end = rest.find(']')?;
        let port = rest[end + 1..].strip_prefix(':')?;
        return (!port.contains(':')).then_some(&rest[..end]);
    }
    let i = h.rfind(':')?;
    let host = &h[..i];
    (!host.contains([':', '[', ']']) && !h[i + 1..].contains(['[', ']'])).then_some(host)
}

/// `domains` lookup of `HandleAutoconfig`: a local domain by lowercase name.
/// `None` is "unknown or the lookup failed" (Go answers 404 for both).
pub async fn local_domain_exists(exec: &ScopedExecutor, domain: &str) -> bool {
    exec.read(
        "SELECT 1 FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1",
        &[(&domain, Type::TEXT)],
    )
    .await
    .is_ok_and(|rows| !rows.is_empty())
}

/// The autoconfig-v1.1 document. Go renders it with `html/template`, whose
/// escaper turns the leading `<?xml` declaration into `&lt;?xml` (recorded). `imap_tls` selects 993/SSL; submission is
/// always 587/STARTTLS (no implicit-TLS submission listener is configured).
pub fn autoconfig_xml(domain: &str, imap_tls: bool) -> String {
    let d = html_escape(domain);
    let (imap_port, imap_socket) = if imap_tls {
        ("993", "SSL")
    } else {
        ("143", "STARTTLS")
    };
    format!(
        "&lt;?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<clientConfig version=\"1.1\">\n  <emailProvider id=\"{d}\">\n    <domain>{d}</domain>\n    <displayName>{d}</displayName>\n    <incomingServer type=\"imap\">\n      <hostname>{d}</hostname>\n      <port>{imap_port}</port>\n      <socketType>{imap_socket}</socketType>\n      <username>%EMAILADDRESS%</username>\n      <authentication>password-cleartext</authentication>\n    </incomingServer>\n    <outgoingServer type=\"smtp\">\n      <hostname>{d}</hostname>\n      <port>587</port>\n      <socketType>STARTTLS</socketType>\n      <username>%EMAILADDRESS%</username>\n      <authentication>password-cleartext</authentication>\n    </outgoingServer>\n  </emailProvider>\n</clientConfig>\n"
    )
}
