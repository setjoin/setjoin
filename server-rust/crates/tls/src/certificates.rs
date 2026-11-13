//! Frozen Go's serving-only certificate selection. Issuance never runs on this path.
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};
use setjoin_acme::{cache::DirCache, normalize};
use std::{path::PathBuf, sync::Arc, time::SystemTime};

#[derive(Debug)]
pub(crate) struct Certificates {
    pub domains: Vec<String>,
    cache: PathBuf,
    static_pair: Option<Arc<CertifiedKey>>,
}

impl Certificates {
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Arc<Self>>, String> {
        let domains: Vec<_> = get("TLS_AUTOCERT_DOMAINS")
            .unwrap_or_default()
            .split(',')
            .map(normalize)
            .filter(|s| !s.is_empty())
            .collect();
        // Go's deployed spellings are TLS_CERT/TLS_KEY. Retain the native
        // *_FILE aliases used by earlier Rust activation fixtures/IMAP tooling.
        let go_cert = get("TLS_CERT");
        let go_key = get("TLS_KEY");
        let (cert_file, key_file) = if go_cert.is_some() || go_key.is_some() {
            (go_cert, go_key)
        } else {
            (get("TLS_CERT_FILE"), get("TLS_KEY_FILE"))
        };
        let cert_file = cert_file.filter(|s| !s.is_empty());
        let key_file = key_file.filter(|s| !s.is_empty());
        if cert_file.is_some() != key_file.is_some() {
            return Err("TLS_CERT and TLS_KEY must both be set or both empty".into());
        }
        let static_pair = cert_file
            .map(|file| {
                let mut blob = std::fs::read(file).map_err(|e| format!("TLS certificate: {e}"))?;
                blob.extend(
                    std::fs::read(key_file.as_ref().unwrap())
                        .map_err(|e| format!("TLS private key: {e}"))?,
                );
                pair(&blob).ok_or_else(|| "TLS certificate/key pair is unusable".to_owned())
            })
            .transpose()?;
        if domains.is_empty() && static_pair.is_none() {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self {
            domains,
            cache: get("TLS_AUTOCERT_CACHE_DIR")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/var/cache/mailserver/autocert".into())
                .into(),
            static_pair,
        })))
    }

    pub fn select(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let name = normalize(name);
        if !name.is_empty() {
            let wildcard = name
                .find('.')
                .filter(|i| *i > 0)
                .map(|i| format!("*{}", &name[i..]));
            let key = self
                .domains
                .iter()
                .find(|d| **d == name)
                .or_else(|| self.domains.iter().find(|d| Some(*d) == wildcard.as_ref()));
            if let Some(key) = key {
                if let Ok(blob) = DirCache::new(&self.cache).get(key) {
                    if setjoin_acme::not_after(&blob).is_some_and(|end| SystemTime::now() < end) {
                        if let Some(pair) = pair(&blob) {
                            return Some(pair);
                        }
                    }
                }
            }
            // autocert.DirCache has a distinct literal filename namespace. Its
            // whitelist is exact; only the managed cache expands wildcard names.
            if self.domains.iter().any(|d| *d == name) {
                for file in [name.clone(), format!("{name}-rsa")] {
                    let Ok(blob) = std::fs::read(self.cache.join(file)) else {
                        continue;
                    };
                    if !setjoin_acme::not_after(&blob).is_some_and(|end| SystemTime::now() < end) {
                        continue;
                    }
                    let Some(pair) = pair(&blob) else { continue };
                    let Ok(cert) = rustls::server::ParsedCertificate::try_from(&pair.cert[0])
                    else {
                        continue;
                    };
                    let Ok(server_name) = rustls::pki_types::ServerName::try_from(name.as_str())
                    else {
                        continue;
                    };
                    if rustls::client::verify_server_name(&cert, &server_name).is_ok() {
                        return Some(pair);
                    }
                }
            }
        }
        self.static_pair.clone()
    }
}

impl rustls::server::ResolvesServerCert for Certificates {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.select(hello.server_name().unwrap_or_default())
    }
}

fn pair(blob: &[u8]) -> Option<Arc<CertifiedKey>> {
    let certs = CertificateDer::pem_slice_iter(blob)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let key = PrivateKeyDer::from_pem_slice(blob).ok()?;
    CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
        .ok()
        .map(Arc::new)
}
