//! Boot configuration for the ported auth process. JWT key custody is startup-only in Go.
use serde_json::Value;
use setjoin_config_secret::CryptoProfile;
pub struct Config {
    pub saml_enabled: bool,
    pub saml_cert_file: String,
    pub saml_key_file: String,
    pub oidc_rp_enabled: bool,
    pub jit_enabled: bool,
    pub sso_allow_super_admin_mapping: bool,
    pub oidc_enabled: bool,
    pub oidc_hostname: String,
    pub oidc_private_key: String,
    pub oidc_public_key: String,
    pub oidc_origins: String,
    pub vapid_private_key: String,
    pub threat: setjoin_threat::Config,
    pub direct_dsn:String,
    pub geoip_path:String,
    pub webauthn_rp_id:String,
    pub webauthn_rp_name:String,
    pub webauthn_rp_origin:String,
    pub db_encryption_key: String,
    pub audit_hmac_key: String,
    pub internal_api_key: String,
    pub client_proxy: String,
    pub secret: String,
    pub issuer: String,
    pub signing_alg: String,
    pub profile: CryptoProfile,
    pub sm2_pem: Option<String>,
    pub access_seconds: i64,
    pub refresh_seconds: i64,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub trust_proxy: bool,
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub threat_controls: [bool; 5],
    pub listen: String,
    pub dsn: String,
    pub worker_dsn: Option<String>,
    pub go_upstream: Option<String>,
    pub cookie_secure: bool,
}
impl Config {
    pub fn for_secret(secret: String) -> Self {
        Self {
            saml_enabled: false,
            saml_cert_file: String::new(),
            saml_key_file: String::new(),
            oidc_rp_enabled: false,
            jit_enabled: false,
            sso_allow_super_admin_mapping: false,
            oidc_enabled: false,
            oidc_hostname: "localhost".into(),
            oidc_private_key: "/opt/setjoin/oidc_key.pem".into(),
            oidc_public_key: "/opt/setjoin/oidc_pub.pem".into(),
            oidc_origins: String::new(),
            vapid_private_key: String::new(),
            threat: Self::quiet_threat(&secret),
            direct_dsn:String::new(),
            geoip_path:String::new(),
            webauthn_rp_id:"localhost".into(),
            webauthn_rp_name:"SetJoin".into(),
            webauthn_rp_origin:"http://localhost:8080".into(),
            db_encryption_key: String::new(),
            audit_hmac_key: String::new(),
            internal_api_key: String::new(),
            client_proxy: String::new(),
            secret,
            issuer: "mailserver".into(),
            signing_alg: "HS256".into(),
            profile: CryptoProfile::Standard,
            sm2_pem: None,
            access_seconds: 3600,
            refresh_seconds: 2592000,
            tls_cert: None,
            tls_key: None,
            trust_proxy: false,
            trusted_proxies: Vec::new(),
            threat_controls: [false; 5],
            listen: "127.0.0.1:8443".into(),
            dsn: String::new(),
            worker_dsn: std::env::var("DB_WORKER_DSN").ok(),
            go_upstream: None,
            cookie_secure: false,
        }
    }
    /// Library/test default (#349): the five env-overridable admission controls
    /// off, as the former `threat_controls: [false; 5]`; `from_env` replaces it.
    /// The captcha key is Go's derived default, and empty for an empty secret (F7).
    fn quiet_threat(secret: &str) -> setjoin_threat::Config {
        let mut threat = setjoin_threat::Config::default();
        for key in ["threat_feed", "geo_block", "spray_detect", "captcha", "tarpit"] {
            threat.overrides.insert(format!("feature.{key}"), false);
        }
        if !secret.is_empty() {
            threat.captcha_secret =
                crate::captcha::derive_secret(secret.as_bytes(), CryptoProfile::Standard);
        }
        threat
    }
    /// Shared threat configuration (#349): Go's env/YAML knobs, then
    /// authserver/internal/config/config.go:271-273: an unset CAPTCHA_SECRET is
    /// HKDF-SHA256(JWT_SECRET, salt "mailserver-captcha-token-v1"), 32 bytes (16 for
    /// smx). An empty JWT secret leaves the key empty, so every solve fails (F7;
    /// `from_env` refuses short secrets anyway).
    pub fn threat_from_lookup(
        get: &dyn Fn(&str, &str) -> Option<String>,
        jwt_secret: &str,
        profile: CryptoProfile,
    ) -> Result<setjoin_threat::Config, String> {
        let mut threat = setjoin_threat::Config::from_lookup(get)?;
        if threat.captcha_secret.is_empty() && !jwt_secret.is_empty() {
            threat.captcha_secret = crate::captcha::derive_secret(jwt_secret.as_bytes(), profile);
        }
        Ok(threat)
    }
    pub fn from_env() -> Result<Self, String> {
        let yaml: Value = match std::env::var("SETJOIN_CONFIG")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(path) => {
                serde_saphyr::from_slice(&std::fs::read(path).map_err(|_| "read SETJOIN_CONFIG")?)
                    .map_err(|_| "parse SETJOIN_CONFIG")?
            }
            None => Value::Null,
        };
        let get = |env: &str, path: &str| -> Option<String> {
            std::env::var(env).ok().or_else(|| {
                let v = path.split('.').try_fold(&yaml, |v, k| v.get(k))?;
                match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Bool(b) => Some(b.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                }
            })
        };
        let mut c = Self::for_secret(get("JWT_SECRET", "jwt.secret").unwrap_or_default());
        c.saml_enabled = get("SAML_ENABLED", "saml.enabled").is_some_and(|s| go_bool(&s));
        c.saml_cert_file = get("SAML_CERT_FILE", "saml.cert_file").unwrap_or_default();
        c.saml_key_file = get("SAML_KEY_FILE", "saml.key_file").unwrap_or_default();
        c.jit_enabled = get("JIT_ENABLED","jit.enabled").is_some_and(|s|go_bool(&s));
        c.sso_allow_super_admin_mapping = get("SSO_ALLOW_SUPER_ADMIN_MAPPING","sso.allow_super_admin_mapping").is_some_and(|s|go_bool(&s));
        c.oidc_rp_enabled = get("OIDC_ENABLED", "oidc.enabled").is_some_and(|s| go_bool(&s));
        c.oidc_enabled = get("OIDC_PROVIDER_ENABLED", "oidc_provider.enabled").is_some_and(|s| go_bool(&s));
        c.oidc_hostname = get("HOSTNAME", "hostname").unwrap_or(c.oidc_hostname);
        c.oidc_private_key = get("OIDC_PROVIDER_PRIVATE_KEY_FILE", "oidc_provider.private_key_file").unwrap_or(c.oidc_private_key);
        c.oidc_public_key = get("OIDC_PROVIDER_PUBLIC_KEY_FILE", "oidc_provider.public_key_file").unwrap_or(c.oidc_public_key);
        c.oidc_origins = get("OIDC_PROVIDER_ALLOWED_ORIGINS", "oidc_provider.allowed_origins").unwrap_or_default();
        if c.oidc_enabled && !setjoin_identity::oidc::valid_origins(&c.oidc_origins) {
            return Err("OIDC_PROVIDER_ALLOWED_ORIGINS requires exact HTTPS origins (HTTP only for loopback development)".into());
        }
        if c.oidc_enabled && (c.oidc_private_key.is_empty() || c.oidc_public_key.is_empty() || c.oidc_private_key==c.oidc_public_key) {
            return Err("OIDC provider key files must be non-empty and distinct".into());
        }
        c.vapid_private_key = get("VAPID_PRIVATE_KEY", "vapid.private_key").unwrap_or_default();
        c.webauthn_rp_id=get("WEBAUTHN_RP_ID","webauthn.rp_id").unwrap_or(c.webauthn_rp_id);
        c.webauthn_rp_name=get("WEBAUTHN_RP_NAME","webauthn.rp_name").unwrap_or(c.webauthn_rp_name);
        c.webauthn_rp_origin=get("WEBAUTHN_RP_ORIGIN","webauthn.rp_origin").unwrap_or(c.webauthn_rp_origin);
        c.db_encryption_key = get("DB_ENCRYPTION_KEY", "db.encryption_key").unwrap_or_default();
        c.audit_hmac_key = get("AUDIT_HMAC_KEY", "audit.hmac_key").unwrap_or_default();
        c.internal_api_key = get("INTERNAL_API_KEY", "internal.api_key").unwrap_or_default();
        c.client_proxy = std::env::var("TRUSTED_PROXY_IP").unwrap_or_default();
        c.dsn = get("DB_DSN", "db.dsn").ok_or("DB_DSN required")?;
        c.worker_dsn = get("DB_WORKER_DSN", "db.worker_dsn");
        c.direct_dsn=get("DB_DIRECT_DSN","db.direct_dsn").filter(|s|!s.is_empty()).unwrap_or_else(||c.dsn.clone());
        c.geoip_path=get("GEOIP_DB_PATH","geoip.db_path").unwrap_or_default();
        c.issuer = get("JWT_ISSUER", "jwt.issuer").unwrap_or(c.issuer);
        c.signing_alg = get("JWT_SIGNING_ALG", "jwt.signing_alg").unwrap_or(c.signing_alg);
        let profile =
            get("CRYPTO_ALGORITHM_PROFILE", "crypto.algorithm_profile").unwrap_or_default();
        if !matches!(profile.as_str(), "" | "standard" | "smx" | "hybrid") {
            return Err("CRYPTO_ALGORITHM_PROFILE must be standard, smx, or hybrid".into());
        }
        c.profile = CryptoProfile::parse(&profile);
        c.threat = Self::threat_from_lookup(&get, &c.secret, c.profile)?;
        if matches!(c.profile, CryptoProfile::Smx | CryptoProfile::Hybrid) {
            if let Some(path) =
                get("SM2_PRIVATE_KEY_FILE", "sm2.private_key_file").filter(|s| !s.is_empty())
            {
                c.sm2_pem =
                    Some(std::fs::read_to_string(path).map_err(|_| "read SM2_PRIVATE_KEY_FILE")?);
            }
        }
        c.access_seconds = duration(&get("JWT_EXPIRY", "jwt.expiry").unwrap_or("1h".into()))?;
        c.refresh_seconds =
            duration(&get("JWT_REFRESH_EXPIRY", "jwt.refresh_expiry").unwrap_or("720h".into()))?;
        let min_secret = if c.profile == CryptoProfile::Smx {
            16
        } else {
            32
        };
        if !c.db_encryption_key.is_empty() {
            if c.profile==CryptoProfile::Smx && c.db_encryption_key.len()<16 {
                return Err("DB_ENCRYPTION_KEY must be at least 16 characters for profile smx".into());
            }
            if c.profile!=CryptoProfile::Smx && c.db_encryption_key.len()<32 {
                return Err("DB_ENCRYPTION_KEY must be at least 32 characters or empty".into());
            }
        }
        if c.profile == CryptoProfile::Smx && c.sm2_pem.is_none() {
            return Err("SM2_PRIVATE_KEY_FILE required for smx".into());
        }
        if c.access_seconds <= 0 || c.access_seconds > 2592000 {return Err("JWT_EXPIRY must be greater than zero and no more than 720h".into());}
        if c.refresh_seconds <= 0 {return Err("JWT_REFRESH_EXPIRY must be greater than zero".into());}
        if c.secret.len() < min_secret
            || c.issuer.is_empty()
            || c.access_seconds <= 0
            || c.access_seconds > 2592000
            || c.refresh_seconds <= 0
        {
            return Err("invalid JWT configuration".into());
        }
        let auth = get("AUTHSERVER_URL", "authserver.url");
        let uri = auth
            .as_ref()
            .and_then(|s| s.parse::<hyper::Uri>().ok())
            .filter(|u| matches!(u.scheme_str(), Some("http" | "https")) && u.host().is_some());
        c.listen = get("LISTEN_ADDR", "listen.addr")
            .or_else(|| {
                uri.as_ref().map(|u| {
                    format!(
                        "{}:{}",
                        u.host().unwrap(),
                        u.port_u16().unwrap_or(8443)
                    )
                })
            })
            .unwrap_or("127.0.0.1:8443".into());
        let loopback = c
            .listen
            .rsplit_once(':')
            .and_then(|(h, _)| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
            || c.listen.starts_with("localhost:");
        c.tls_cert = get("TLS_CERT", "tls.cert").filter(|s| !s.is_empty());
        c.tls_key = get("TLS_KEY", "tls.key").filter(|s| !s.is_empty());
        if c.tls_cert.is_some() != c.tls_key.is_some() {
            return Err("TLS_CERT and TLS_KEY must be configured together".into());
        }
        if !loopback && c.tls_cert.is_none() {
            return Err("non-loopback auth listener requires TLS".into());
        }
        c.trust_proxy = get("AUTH_TRUST_PROXY", "auth.trust_proxy").is_some_and(|s| go_bool(&s));
        for entry in get("AUTH_TRUSTED_PROXY_CIDRS", "auth.trusted_proxy_cidrs")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            c.trusted_proxies.push(
                entry
                    .parse()
                    .map_err(|_| "invalid AUTH_TRUSTED_PROXY_CIDRS")?,
            );
        }
        if !loopback && uri.is_none() {
            return Err("non-loopback auth listener requires valid AUTHSERVER_URL".into());
        }
        if c.listen.starts_with(':') {
            c.listen = format!("0.0.0.0{}", c.listen);
        }
        c.go_upstream = std::env::var("AUTHSERVER_GO_UPSTREAM")
            .ok()
            .filter(|s| !s.is_empty());
        for (i, (env, path)) in [
            ("THREAT_FEED_ENABLED", "threat_feed.enabled"),
            ("GEO_BLOCK_ENABLED", "geo_block.enabled"),
            ("SPRAY_DETECT_ENABLED", "spray_detect.enabled"),
            ("CAPTCHA_ENABLED", "captcha.enabled"),
            ("TARPIT_ENABLED", "tarpit.enabled"),
        ]
        .iter()
        .enumerate()
        {
            c.threat_controls[i] = get(env, path).map_or(true, |v| go_bool(&v));
        }
        // authserverd derives HandlerConfig.CookieSecure from TLSCertFile.
        c.cookie_secure = c.tls_cert.is_some();
        Ok(c)
    }
}
fn duration(raw: &str) -> Result<i64, String> {
    // Go config accepts compound hours/minutes/seconds. Use the maintained parser.
    humantime::parse_duration(raw)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| "invalid JWT duration".into())
}

fn go_bool(raw: &str) -> bool {
    matches!(raw, "1" | "t" | "T" | "true" | "TRUE" | "True")
}
