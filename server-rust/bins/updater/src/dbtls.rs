//! `sslmode` for the updater's control/owner DB sessions (pgx parity: default
//! `prefer`). tokio-postgres only knows disable/prefer/require and rejects
//! `sslrootcert`, so the DSN is split here: this module strips those two
//! parameters, and the rest goes to tokio-postgres unchanged.
//!
//! disable: plaintext. allow/prefer: TLS when the server offers it, else plaintext
//! (pgx treats `allow` like `prefer` after a plaintext attempt; we try TLS first).
//! require: TLS, no certificate verification (pgx semantics, unless a root file is
//! given). verify-ca: chain verified, name not. verify-full: chain and name.
use anyhow::{anyhow, bail, Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use std::{path::PathBuf, sync::Arc};
use tokio_postgres::config::SslMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}
pub struct Parsed {
    pub dsn: String,
    pub mode: Mode,
    pub root_cert: Option<PathBuf>,
}

fn mode(value: &str) -> Result<Mode> {
    Ok(match value {
        "disable" => Mode::Disable,
        "allow" | "prefer" => Mode::Prefer,
        "require" => Mode::Require,
        "verify-ca" => Mode::VerifyCa,
        "verify-full" => Mode::VerifyFull,
        other => bail!("unsupported sslmode {other:?}"),
    })
}
fn unescape_percent(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
/// Splits `key=value` DSN words (single-quoted values, backslash escapes).
fn words(dsn: &str) -> Result<Vec<(String, String, String)>> {
    let c: Vec<char> = dsn.chars().collect();
    let (mut i, mut out) = (0, Vec::new());
    while i < c.len() {
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        if i >= c.len() {
            break;
        }
        let start = i;
        while i < c.len() && c[i] != '=' && !c[i].is_whitespace() {
            i += 1;
        }
        let key: String = c[start..i].iter().collect();
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        if i >= c.len() || c[i] != '=' {
            bail!("invalid keyword/value DSN near {key:?}");
        }
        i += 1;
        while i < c.len() && c[i].is_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < c.len() && c[i] == '\'' {
            i += 1;
            loop {
                match c.get(i) {
                    None => bail!("unterminated quote in DSN"),
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    Some('\\') if i + 1 < c.len() => {
                        value.push(c[i + 1]);
                        i += 2;
                    }
                    Some(ch) => {
                        value.push(*ch);
                        i += 1;
                    }
                }
            }
        } else {
            while i < c.len() && !c[i].is_whitespace() {
                if c[i] == '\\' && i + 1 < c.len() {
                    i += 1;
                }
                value.push(c[i]);
                i += 1;
            }
        }
        let raw: String = c[start..i].iter().collect();
        out.push((key, value, raw));
    }
    Ok(out)
}
pub fn parse(dsn: &str) -> Result<Parsed> {
    let (mut found, mut root) = (None, None);
    let rest;
    if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        let (base, query) = dsn.split_once('?').unwrap_or((dsn, ""));
        let mut keep = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "sslmode" => found = Some(unescape_percent(v)),
                "sslrootcert" => root = Some(unescape_percent(v)),
                _ => keep.push(pair),
            }
        }
        rest = if keep.is_empty() {
            base.to_owned()
        } else {
            format!("{base}?{}", keep.join("&"))
        };
    } else {
        let mut keep = Vec::new();
        for (k, v, raw) in words(dsn)? {
            match k.as_str() {
                "sslmode" => found = Some(v),
                "sslrootcert" => root = Some(v),
                _ => keep.push(raw),
            }
        }
        rest = keep.join(" ");
    }
    Ok(Parsed {
        dsn: rest,
        mode: match found {
            Some(v) => mode(&v)?,
            None => Mode::Prefer,
        },
        root_cert: root.filter(|r| !r.is_empty() && r != "system").map(PathBuf::from),
    })
}

/// Chain checked by webpki; the host name is not (verify-ca).
#[derive(Debug)]
struct ChainOnly(Arc<rustls::client::WebPkiServerVerifier>);
/// Encryption without authentication (`require`, pgx semantics).
#[derive(Debug)]
struct Unverified;
fn algs() -> rustls::crypto::WebPkiSupportedAlgorithms {
    default_provider().signature_verification_algorithms
}
macro_rules! signatures {
    () => {
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &algs())
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &algs())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            algs().supported_schemes()
        }
    };
}
impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    signatures!();
}
impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        inter: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(end, inter, name, ocsp, now) {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }
    signatures!();
}
fn roots(file: &Option<PathBuf>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    if let Some(path) = file {
        let pem = std::fs::read(path).with_context(|| format!("sslrootcert {}", path.display()))?;
        for cert in rustls_pemfile_certs(&pem)? {
            store.add(cert)?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = store.add(cert);
        }
    }
    if store.is_empty() {
        bail!("no trusted root certificates available for sslmode verification");
    }
    Ok(store)
}
fn rustls_pemfile_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid PEM in sslrootcert: {e}"))
}
pub fn client_config(p: &Parsed) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?;
    let config = match p.mode {
        Mode::VerifyFull => builder
            .with_root_certificates(roots(&p.root_cert)?)
            .with_no_client_auth(),
        Mode::VerifyCa => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChainOnly(
                rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots(&p.root_cert)?),
                    Arc::new(default_provider()),
                )
                .build()?,
            )))
            .with_no_client_auth(),
        _ => match &p.root_cert {
            // An explicit root file upgrades prefer/require to a verified chain.
            Some(_) => builder
                .with_root_certificates(roots(&p.root_cert)?)
                .with_no_client_auth(),
            None => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Unverified))
                .with_no_client_auth(),
        },
    };
    Ok(config)
}
pub fn ssl_mode(m: Mode) -> SslMode {
    match m {
        Mode::Disable => SslMode::Disable,
        Mode::Prefer => SslMode::Prefer,
        _ => SslMode::Require,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_prefer_and_params_are_stripped() {
        let p = parse("postgres://u:p@h/db").unwrap();
        assert_eq!((p.mode, p.dsn.as_str()), (Mode::Prefer, "postgres://u:p@h/db"));
        let p = parse("postgres://u@h/db?sslmode=verify-full&application_name=x&sslrootcert=%2Fca.pem")
            .unwrap();
        assert_eq!(p.mode, Mode::VerifyFull);
        assert_eq!(p.dsn, "postgres://u@h/db?application_name=x");
        assert_eq!(p.root_cert.unwrap(), PathBuf::from("/ca.pem"));
        let p = parse("host=h dbname=db sslmode=require user='a b'").unwrap();
        assert_eq!((p.mode, p.dsn.as_str()), (Mode::Require, "host=h dbname=db user='a b'"));
        assert_eq!(parse("host=h sslmode=disable").unwrap().mode, Mode::Disable);
        assert_eq!(parse("host=h sslmode=verify-ca").unwrap().mode, Mode::VerifyCa);
        assert!(parse("host=h sslmode=bogus").is_err());
    }
}
