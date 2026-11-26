//! ACME on :80 and the `acme-renewal` worker (#305): the HTTP-01 challenge responder that
//! frozen Go mounts on its :80 server, plus the managed renewal loop (`setjoin-acme`).
//!
//! Rust owns :80 only when systemd hands the process a descriptor named `acme`; it then needs
//! `GO_WORKERS_OFF=http-port80` so Go never binds the port. The worker starts only with
//! `RUST_WORKERS_ON=acme-renewal` plus `GO_WORKERS_OFF=acme-renewal`, with challenge-specific listener ownership.
//! HTTP-01 needs :80; TLS-ALPN-01 needs :443; DNS-01 needs neither descriptor. TLS-ALPN-01 shares the :443 frontend; DNS-01 uses the configured provider APIs.
use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use setjoin_acme::{Config, Http01Store, Manager};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::TcpListener;

pub const RENEWAL: &str = "acme-renewal";
pub const HTTP80: &str = "http-port80";

fn listed(list: Option<&str>, name: &str) -> bool {
    list.unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == name)
}

/// Go `strconv.ParseBool` / Rust bool parity for `TLS_AUTOCERT_ROLLOUT`.
fn is_truthy_rollout(value: &str) -> bool {
    matches!(value.trim(), "1" | "t" | "T" | "TRUE" | "true" | "True")
}

/// Release N (#559) deprecation detector for built-in ACME (`setjoin-acme`).
///
/// Logs ONLY active trigger names (never secret values such as `TLS_DNS_CONFIG`)
/// and points operators to `docs/guides/EDGE_TLS_ACME_MIGRATION.md` and Release
/// N+1 (`#560`). Returns `None` when only static PEM files (`TLS_CERT`/`TLS_KEY`)
/// or no built-in ACME configuration is present.
pub fn deprecation_warning(
    get: &dyn Fn(&str) -> Option<String>,
    acme_socket_activated: bool,
) -> Option<String> {
    let mut triggers: Vec<&'static str> = Vec::new();
    let non_empty = |key: &str| get(key).is_some_and(|v| !v.trim().is_empty());
    if non_empty("TLS_AUTOCERT_DOMAINS") {
        triggers.push("TLS_AUTOCERT_DOMAINS");
    }
    if listed(get("RUST_WORKERS_ON").as_deref(), RENEWAL) {
        triggers.push("RUST_WORKERS_ON=acme-renewal");
    }
    if acme_socket_activated {
        triggers.push("activated_socket:acme");
    }
    if non_empty("TLS_AUTOCERT_EMAIL") {
        triggers.push("TLS_AUTOCERT_EMAIL");
    }
    if non_empty("TLS_AUTOCERT_KEY_FILE") {
        triggers.push("TLS_AUTOCERT_KEY_FILE");
    }
    if non_empty("TLS_DNS_PROVIDER") {
        triggers.push("TLS_DNS_PROVIDER");
    }
    if non_empty("TLS_DNS_CONFIG") {
        triggers.push("TLS_DNS_CONFIG");
    }
    if get("TLS_AUTOCERT_ROLLOUT").is_some_and(|v| is_truthy_rollout(&v)) {
        triggers.push("TLS_AUTOCERT_ROLLOUT");
    }
    if triggers.is_empty() {
        return None;
    }
    Some(format!(
        "DEPRECATION WARNING: built-in ACME (setjoin-acme, triggers=[{}]) is deprecated in Release N and will be removed in Release N+1 (#560). Migrate to an edge TLS/ACME terminator (Caddy or certbot) exporting PEM files to TLS_CERT/TLS_KEY (hot-reloaded without restart); see docs/guides/EDGE_TLS_ACME_MIGRATION.md.",
        triggers.join(",")
    ))
}

/// Settings read from the environment exactly as frozen Go's koanf environment layer names them.
pub struct Settings {
    pub config: Config,
    pub hostname: String,
    pub challenge: String,
    pub dns_provider: String,
    pub dns_config: String,
    pub dns_resolvers: Vec<String>,
}

/// `Ok(None)` when no managed domains are configured (Go starts no manager then).
pub fn settings(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Settings>, String> {
    let value = |name: &str| get(name).unwrap_or_default();
    let domains = value("TLS_AUTOCERT_DOMAINS");
    if domains.is_empty() {
        return Ok(None);
    }
    let challenge = match value("TLS_AUTOCERT_CHALLENGE").as_str() {
        "" | "tls-alpn-01" => "tls-alpn-01".to_owned(),
        other => other.to_owned(),
    };
    if !["http-01", "tls-alpn-01", "dns-01"].contains(&challenge.as_str()) {
        return Err(format!("acme-renewal: unsupported challenge {challenge:?}"));
    }
    let raw = value("TLS_DNS_CONFIG");
    let dns_config = if challenge == "dns-01" && (raw.starts_with('/') || raw.starts_with("./")) {
        std::fs::read_to_string(&raw).map_err(|e| format!("TLS_DNS_CONFIG: {e}"))?
    } else {
        raw
    };
    let cache = match value("TLS_AUTOCERT_CACHE_DIR") {
        d if d.is_empty() => "/var/cache/mailserver/autocert".to_owned(),
        d => d,
    };
    let key_file = Some(value("TLS_AUTOCERT_KEY_FILE"))
        .filter(|k| !k.is_empty())
        .map(PathBuf::from);
    Ok(Some(Settings {
        config: Config {
            domains: domains.split(',').map(|d| d.trim().to_owned()).collect(),
            email: value("TLS_AUTOCERT_EMAIL"),
            cache_dir: PathBuf::from(cache),
            key_file,
            ca_dir_url: None,
            ca_root: None,
            backoff: None,
        },
        hostname: value("HOSTNAME"),
        challenge,
        dns_provider: value("TLS_DNS_PROVIDER"),
        dns_config,
        dns_resolvers: value("TLS_DNS_RESOLVERS")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
    }))
}

/// The startup guard: challenge-specific socket descriptors must be activated.
pub fn guard(
    rust_on: Option<&str>,
    _go_off: Option<&str>,
    http80_activated: bool,
    https_activated: bool,
    challenge: &str,
) -> Result<(), String> {
    if listed(rust_on, RENEWAL) && challenge == "http-01" && !http80_activated {
        return Err(format!(
            "{RENEWAL} needs the socket-activated :80 descriptor named `acme` to answer HTTP-01"
        ));
    }
    if listed(rust_on, RENEWAL) && matches!(challenge, "" | "tls-alpn-01") && !https_activated {
        return Err(format!("{RENEWAL} needs the socket-activated :443 descriptor named `https` to answer TLS-ALPN-01"));
    }
    Ok(())
}

pub struct Renewal {
    manager: Manager,
}

impl Renewal {
    pub fn new(
        settings: Settings,
        store: Http01Store,
        alpn: Option<setjoin_acme::TlsAlpnStore>,
    ) -> Result<Self, String> {
        let challenge = match settings.challenge.as_str() {
            "http-01" => setjoin_acme::Challenge::Http01(store),
            "tls-alpn-01" => setjoin_acme::Challenge::TlsAlpn01(
                alpn.ok_or("acme-renewal requires the active TLS frontend")?,
            ),
            "dns-01" => setjoin_acme::Challenge::Dns01(setjoin_acme::dns::Provider::new(
                &settings.dns_provider,
                &settings.dns_config,
                &settings.dns_resolvers,
            )?),
            _ => return Err("acme-renewal: unsupported challenge".into()),
        };
        Ok(Self {
            manager: Manager::new_with_challenge(settings.config, challenge)?,
        })
    }
    pub async fn run_until(self, stop: impl std::future::Future<Output = ()>) {
        self.manager.run(stop).await;
    }
}

/// Go's `html.escape` as `http.Redirect` applies it to the Location.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Go's `httpsRedirectHandler` through `http.Redirect(w, r, target, 301)`.
fn redirect(hostname: &str, req: &Request<Incoming>) -> Response<Full<Bytes>> {
    let query = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target = format!("https://{hostname}{}{query}", req.uri().path());
    let mut builder = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, &target);
    let method = req.method();
    let mut body = Bytes::new();
    if method == Method::GET || method == Method::HEAD {
        builder = builder.header(header::CONTENT_TYPE, "text/html; charset=utf-8");
    }
    if method == Method::GET {
        body = Bytes::from(format!(
            "<a href=\"{}\">Moved Permanently</a>.\n\n",
            html_escape(&target)
        ));
    }
    builder.body(Full::new(body)).unwrap()
}

/// One :80 request: a pending HTTP-01 token is answered with its key authorization; everything
/// else is redirected to https (Go's default `HTTP_MODE=redirect`).
pub fn answer(
    store: &Http01Store,
    hostname: &str,
    req: &Request<Incoming>,
) -> Response<Full<Bytes>> {
    if let Some(key_authorization) = store.answer(req.uri().path()) {
        return Response::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(key_authorization)))
            .unwrap();
    }
    redirect(hostname, req)
}

/// Serve the activated :80 descriptor until `stop` resolves. Go's server timeouts apply.
pub async fn serve_http80(
    listener: TcpListener,
    store: Http01Store,
    hostname: String,
    stop: impl std::future::Future<Output = ()>,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioIo, TokioTimer};
    let hostname = Arc::new(hostname);
    tokio::pin!(stop);
    loop {
        let accepted =
            tokio::select! {biased; () = &mut stop => return, r = listener.accept() => r};
        let Ok((stream, _)) = accepted else { continue };
        let (store, hostname) = (store.clone(), hostname.clone());
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let response = answer(&store, &hostname, &req);
                async move { Ok::<_, Infallible>(response) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod challenge_settings_tests {
    use super::*;
    #[test]
    fn default_alpn_and_dns_settings_are_native() {
        for mode in ["", "tls-alpn-01", "http-01", "dns-01"] {
            let settings = settings(&|k| match k {
                "TLS_AUTOCERT_DOMAINS" => Some("localhost".into()),
                "TLS_AUTOCERT_EMAIL" => Some("ops@example.test".into()),
                "TLS_AUTOCERT_CHALLENGE" => Some(mode.into()),
                "TLS_DNS_PROVIDER" => Some("cloudflare".into()),
                "TLS_DNS_CONFIG" => Some(r#"{"CF_API_TOKEN":"public-test-token"}"#.into()),
                _ => None,
            });
            assert!(
                settings.is_ok(),
                "{mode}: {}",
                settings.err().unwrap_or_default()
            );
        }
    }
}

#[cfg(test)]
mod listener_ownership_tests {
    use super::*;
    #[test]
    fn each_challenge_requires_its_listener() {
        assert!(guard(Some(RENEWAL), None, false, true, "http-01").is_err());
        assert!(guard(Some(RENEWAL), None, true, false, "tls-alpn-01").is_err());
        assert!(guard(Some(RENEWAL), None, true, false, "http-01").is_ok());
        assert!(guard(Some(RENEWAL), None, false, true, "tls-alpn-01").is_ok());
        assert!(guard(Some(RENEWAL), None, false, false, "dns-01").is_ok());
    }
}

#[cfg(test)]
mod deprecation_warning_tests {
    use super::*;

    #[test]
    fn silent_when_only_static_pem_is_configured() {
        let warning = deprecation_warning(
            &|k| match k {
                "TLS_CERT" => Some("/etc/mail/tls/server.pem".into()),
                "TLS_KEY" => Some("/etc/mail/tls/server-key.pem".into()),
                "RUST_WORKERS_ON" => Some("http-tls,cert-monitor,tls-ticket-keys".into()),
                "TLS_AUTOCERT_ROLLOUT" => Some("false".into()),
                _ => None,
            },
            false,
        );
        assert!(warning.is_none(), "static PEM must not warn: {warning:?}");
    }

    #[test]
    fn each_trigger_emits_deprecation_naming_guide_and_release_n_plus_1() {
        let cases: &[(&str, &str, bool, &str)] = &[
            (
                "TLS_AUTOCERT_DOMAINS",
                "mail.example.test",
                false,
                "TLS_AUTOCERT_DOMAINS",
            ),
            (
                "RUST_WORKERS_ON",
                "http-tls,acme-renewal",
                false,
                "RUST_WORKERS_ON=acme-renewal",
            ),
            ("", "", true, "activated_socket:acme"),
            (
                "TLS_AUTOCERT_EMAIL",
                "ops@example.test",
                false,
                "TLS_AUTOCERT_EMAIL",
            ),
            (
                "TLS_AUTOCERT_KEY_FILE",
                "/etc/mail/acme-account.key",
                false,
                "TLS_AUTOCERT_KEY_FILE",
            ),
            ("TLS_DNS_PROVIDER", "cloudflare", false, "TLS_DNS_PROVIDER"),
            (
                "TLS_DNS_CONFIG",
                r#"{"CF_API_TOKEN":"sentinel-secret-999"}"#,
                false,
                "TLS_DNS_CONFIG",
            ),
        ];
        for &(key, val, sock, expected_trigger) in cases {
            let msg = deprecation_warning(
                &|k| (!key.is_empty() && k == key).then(|| val.to_owned()),
                sock,
            )
            .unwrap_or_else(|| panic!("expected warning for {expected_trigger}"));
            assert!(
                msg.contains(expected_trigger),
                "missing trigger {expected_trigger} in: {msg}"
            );
            assert!(
                msg.contains("docs/guides/EDGE_TLS_ACME_MIGRATION.md"),
                "missing migration guide path in: {msg}"
            );
            assert!(msg.contains("#560"), "missing #560 reference in: {msg}");
            assert!(
                !msg.contains("sentinel-secret-999"),
                "secret value leaked into deprecation warning: {msg}"
            );
        }
    }

    #[test]
    fn rollout_flag_matches_go_rust_bool_parity() {
        for truthy in ["1", "t", "T", "TRUE", "true", "True", " TRUE "] {
            let msg = deprecation_warning(
                &|k| (k == "TLS_AUTOCERT_ROLLOUT").then(|| truthy.to_owned()),
                false,
            )
            .unwrap_or_else(|| panic!("expected trigger for TLS_AUTOCERT_ROLLOUT={truthy:?}"));
            assert!(msg.contains("TLS_AUTOCERT_ROLLOUT"), "{msg}");
        }
        for falsy in ["", "0", "f", "F", "false", "FALSE", "False", "no", "yes"] {
            assert!(
                deprecation_warning(
                    &|k| (k == "TLS_AUTOCERT_ROLLOUT").then(|| falsy.to_owned()),
                    false,
                )
                .is_none(),
                "unexpected warning for TLS_AUTOCERT_ROLLOUT={falsy:?}"
            );
        }
    }
}
