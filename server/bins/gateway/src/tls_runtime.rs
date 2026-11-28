//! Native HTTPS listener and certificate expiry monitoring (#413, #560).
pub const CERT_MONITOR: &str = "cert-monitor";
pub const HTTP_TLS: &str = "http-tls";
pub const HTTP_H2C: &str = "http-h2c";

fn listed(get: &dyn Fn(&str) -> Option<String>, key: &str, name: &str) -> bool {
    get(key)
        .unwrap_or_default()
        .split(',')
        .any(|part| part.trim() == name)
}

/// Retained for caller compatibility; Go-free cutover (#359) no longer requires `GO_WORKERS_OFF`.
pub fn guard(_get: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    Ok(())
}

use crate::cert_monitor::{CertMonitor, Certificate};
use setjoin_pg::cert_monitor::CertMonitorDatabase;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

/// Owned TLS background worker lifetime. Explicit shutdown cancels and joins `CertMonitor`.
pub struct Running {
    stop: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<Result<(), String>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Running {
    pub async fn failed(&mut self) -> String {
        if self.tasks.is_empty() {
            return std::future::pending().await;
        }
        let (result, index, remaining) =
            futures_util::future::select_all(self.tasks.iter_mut()).await;
        drop(remaining);
        drop(self.tasks.swap_remove(index));
        match result {
            Ok(Err(error)) => error,
            Err(error) => error.to_string(),
            Ok(Ok(())) => "TLS worker ended unexpectedly".into(),
        }
    }

    pub async fn shutdown(mut self) -> Result<(), String> {
        self.stop.cancel();
        let mut failure = None;
        for mut task in self.tasks.drain(..) {
            let result = tokio::time::timeout(Duration::from_secs(15), &mut task).await;
            let error = match result {
                Ok(Ok(Ok(()))) => None,
                Ok(Ok(Err(error))) => Some(error),
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Some("TLS worker shutdown timeout".into())
                }
            };
            if failure.is_none() {
                failure = error;
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Start immediate + 24h certificate expiry monitoring over the live
/// `ReloadingPem`-backed TLS frontend.
pub async fn start(
    frontend: Arc<setjoin_tls::Frontend>,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<Running, String> {
    guard(get)?;
    let mut running = Running {
        stop: CancellationToken::new(),
        tasks: Vec::new(),
    };
    let monitor = listed(get, "RUST_WORKERS_ON", CERT_MONITOR);
    if !monitor {
        return Ok(running);
    }
    let request = get("DB_DSN")
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for TLS workers")?;
    let dsn = get("DB_WORKER_DSN")
        .filter(|s| !s.is_empty())
        .unwrap_or(request);
    let monitor = CertMonitor::new(CertMonitorDatabase::new(&dsn).map_err(|e| e.to_string())?);
    let stop = running.stop.clone();
    running.tasks.push(tokio::spawn(async move {
        monitor
            .run_until(
                move || monitored_chain(&frontend),
                Duration::from_secs(86400),
                stop.cancelled_owned(),
            )
            .await;
        Ok(())
    }));
    Ok(running)
}

fn monitored_chain(frontend: &setjoin_tls::Frontend) -> Vec<Certificate> {
    frontend
        .served_chain()
        .iter()
        .filter_map(|der| {
            let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
            let not_after =
                chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)?;
            let common_name = cert
                .subject()
                .iter_common_name()
                .find_map(|cn| cn.as_str().ok())
                .unwrap_or_default()
                .to_owned();
            let dns_names = cert
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|san| {
                    san.value
                        .general_names
                        .iter()
                        .filter_map(|name| match name {
                            x509_parser::extensions::GeneralName::DNSName(name) => {
                                Some((*name).to_owned())
                            }
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(Certificate {
                not_after,
                common_name,
                dns_names,
            })
        })
        .collect()
}

/// Ensure the `https` socket-activated listener and `cert-monitor` worker are
/// wired unambiguously.
pub fn guard_activation(
    get: &dyn Fn(&str) -> Option<String>,
    has_https: bool,
) -> Result<(), String> {
    guard(get)?;
    if has_https && !listed(get, "RUST_WORKERS_ON", HTTP_TLS) {
        return Err("the https descriptor requires RUST_WORKERS_ON=http-tls".into());
    }
    if listed(get, "RUST_WORKERS_ON", HTTP_TLS) && !has_https {
        return Err("http-tls requires the socket-activated descriptor named `https`".into());
    }
    if has_https && matches!(get("GATEWAY_ENABLED").as_deref(), Some("false" | "0")) {
        return Err("the native https listener requires the Rust front door".into());
    }
    if !has_https && listed(get, "RUST_WORKERS_ON", CERT_MONITOR) {
        return Err("TLS workers require the activated https listener".into());
    }
    Ok(())
}

/// Optional HTTP mTLS client certificate verifier (VerifyClientCertIfGiven).
/// Reads operator-owned `auth_methods` CAs at startup on the request credential,
/// falling back to system roots when no custom CA bundle is configured.
pub async fn client_verifier(
    exec: Option<&setjoin_pg::ScopedExecutor>,
) -> Result<Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>, String> {
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer},
    };
    #[derive(serde::Deserialize)]
    struct CertificateMethod {
        ca_bundle_path: Option<String>,
        crl_paths: Option<Vec<String>>,
    }
    let mut roots = rustls::RootCertStore::empty();
    if let Some(exec) = exec {
        if let Ok(rows) = exec
            .read(
                "SELECT config_json::text FROM auth_methods WHERE enabled AND slug='certificate' ORDER BY priority",
                &[],
            )
            .await
        {
            for row in rows {
                let Ok(raw) = row.try_get::<_, String>(0) else {
                    continue;
                };
                let Ok(method) = serde_json::from_str::<CertificateMethod>(&raw) else {
                    continue;
                };
                let Some(path) = method.ca_bundle_path.filter(|p| !p.is_empty()) else {
                    continue;
                };
                let Ok(pem) = tokio::fs::read(path).await else {
                    continue;
                };
                let mut candidates = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(&pem).flatten() {
                    if setjoin_mail_security::certificate::accepts_der(cert.as_ref()) {
                        let _ = candidates.add(cert);
                    }
                }
                if candidates.is_empty() {
                    continue;
                }
                let mut valid_crls = true;
                for path in method.crl_paths.unwrap_or_default() {
                    let Ok(der) = tokio::fs::read(path).await else {
                        valid_crls = false;
                        break;
                    };
                    if x509_parser::parse_x509_crl(&der).is_err() {
                        valid_crls = false;
                        break;
                    }
                }
                if valid_crls {
                    roots = candidates;
                    break;
                }
            }
        }
    }
    let system = roots.is_empty();
    if system {
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
    }
    if roots.is_empty() {
        return Ok(Arc::new(NoClientRoots));
    }
    let builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .allow_unauthenticated();
    let builder = if system {
        builder.clear_root_hint_subjects()
    } else {
        builder
    };
    builder
        .build()
        .map_err(|e| format!("client certificate verifier: {e}"))
}

/// Empty trust is a rejection policy, never a cryptographic verifier. No path
/// returns a verification assertion or performs any signature operation.
#[derive(Debug)]
struct NoClientRoots;
impl tokio_rustls::rustls::server::danger::ClientCertVerifier for NoClientRoots {
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _leaf: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _chain: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::server::danger::ClientCertVerified, tokio_rustls::rustls::Error>
    {
        Err(tokio_rustls::rustls::Error::InvalidCertificate(
            tokio_rustls::rustls::CertificateError::UnknownIssuer,
        ))
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _signature: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Err(tokio_rustls::rustls::Error::InvalidCertificate(
            tokio_rustls::rustls::CertificateError::UnknownIssuer,
        ))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        signature: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.verify_tls12_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
