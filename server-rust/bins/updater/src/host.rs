//! Fixed loopback application checks and fixed core systemd units.
use crate::files::*;
use anyhow::{bail, ensure, Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
const START: [&str; 3] = ["setjoin-auth", "setjoin", "setjoin-gateway"];
const STOP: [&str; 3] = ["setjoin-gateway", "setjoin", "setjoin-auth"];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    email: String,
    password: String,
}
impl Probe {
    pub fn read(path: &Path) -> Result<Self> {
        let p: Self = serde_json::from_slice(&read(path, 16384, true)?)?;
        ensure!(
            (3..=254).contains(&p.email.len())
                && p.email.contains('@')
                && !p.email.contains("..")
                && p.email
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-@".contains(&b))
                && (12..=1024).contains(&p.password.len())
                && !p.password.contains(['\r', '\n', '\0']),
            "invalid application probe credential"
        );
        Ok(p)
    }
    async fn login(&self) -> Result<()> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        let response = client
            .post("https://127.0.0.1/auth/login")
            .json(&json!({"email":self.email,"password":self.password}))
            .send()
            .await?;
        let status = response.status().as_u16();
        ensure!(
            response.content_length().unwrap_or(0) <= 65536,
            "login response exceeds limit"
        );
        let mut response = response;
        let mut raw = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                raw.len() + chunk.len() <= 65536,
                "login response exceeds limit"
            );
            raw.extend_from_slice(&chunk);
        }
        if status != 200 {
            let v: Value = serde_json::from_slice(&raw)?;
            ensure!(
                !v["mfa_token"].as_str().unwrap_or("").is_empty()
                    && v["mfa_required"] == true
                    && ((status == 202 && v["status"] == "mfa_required")
                        || (status == 403
                            && v["status"] == "mfa_enrollment_required"
                            && v["reason"] == "enrollment_required")),
                "login returned HTTP {status}"
            );
        }
        Ok(())
    }
    pub async fn data_contract(&self) -> Result<()> {
        self.login()
            .await
            .map_err(|e| anyhow::anyhow!("fixed login contract: {e}"))?;
        self.search("setjoin-updater-connectivity-check-never-matches")
            .await
            .map_err(|e| anyhow::anyhow!("fixed IMAP fetch contract: {e}"))?;
        Ok(())
    }
    pub async fn post_commit(&self) -> Result<()> {
        let message_id = format!("<setjoin-updater-{}@localhost>", uuid::Uuid::new_v4());
        tokio::time::timeout(Duration::from_secs(10), self.send(&message_id))
            .await?
            .map_err(|e| anyhow::anyhow!("fixed SMTP send contract: {e}"))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if self
                .search(&message_id)
                .await
                .map_err(|e| anyhow::anyhow!("fixed IMAP delivery contract: {e}"))?
            {
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "fixed mail send/fetch contract timed out"
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
    async fn search(&self, id: &str) -> Result<bool> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let tcp = TcpStream::connect("127.0.0.1:993").await?;
            let tls = tls(tcp).await?;
            let mut io = BufReader::new(tls);
            let greeting = line(&mut io).await?;
            ensure!(greeting.starts_with("* OK"), "IMAP greeting failed");
            imap(
                &mut io,
                "a1",
                &format!("LOGIN {} {}", quote(&self.email), quote(&self.password)),
            )
            .await?;
            imap(&mut io, "a2", "EXAMINE INBOX").await?;
            let lines = imap(
                &mut io,
                "a3",
                &format!("SEARCH CHARSET UTF-8 HEADER Message-ID {}", quote(id)),
            )
            .await?;
            let search = lines
                .iter()
                .find(|l| l.to_ascii_uppercase().starts_with("* ESEARCH "))
                .context("IMAP search omitted ESEARCH")?;
            let found = search
                .split_ascii_whitespace()
                .any(|v| v.eq_ignore_ascii_case("ALL"));
            let _ = imap(&mut io, "a4", "LOGOUT").await;
            Ok(found)
        })
        .await?
    }
    async fn send(&self, id: &str) -> Result<()> {
        let mut io = BufReader::new(TcpStream::connect("127.0.0.1:587").await?);
        smtp_reply(&mut io, 220).await?;
        smtp(&mut io, "EHLO localhost", 250).await?;
        smtp(&mut io, "STARTTLS", 220).await?;
        let mut io = BufReader::new(tls(io.into_inner()).await?);
        smtp(&mut io, "EHLO localhost", 250).await?;
        use base64::Engine;
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("\0{}\0{}", self.email, self.password));
        smtp(&mut io, &format!("AUTH PLAIN {credentials}"), 235).await?;
        smtp(&mut io, &format!("MAIL FROM:<{}>", self.email), 250).await?;
        smtp(&mut io, &format!("RCPT TO:<{}>", self.email), 250).await?;
        smtp(&mut io, "DATA", 354).await?;
        let message=format!("From: {}\r\nTo: {}\r\nMessage-ID: {id}\r\nSubject: Setjoin transactional updater probe\r\nAuto-Submitted: auto-generated\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic post-upgrade delivery contract.\r\n.\r\n",self.email,self.email);
        io.get_mut().write_all(message.as_bytes()).await?;
        io.get_mut().flush().await?;
        smtp_reply(&mut io, 250).await?;
        smtp(&mut io, "QUIT", 221).await
    }
}
fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
async fn line<S: AsyncRead + Unpin>(io: &mut BufReader<S>) -> Result<String> {
    let mut result = Vec::new();
    loop {
        let buffer = io.fill_buf().await?;
        ensure!(!buffer.is_empty(), "peer closed connection");
        let len = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |p| p + 1);
        ensure!(result.len() + len <= 65536, "peer line exceeds limit");
        let done = buffer[len - 1] == b'\n';
        result.extend_from_slice(&buffer[..len]);
        io.consume(len);
        if done {
            break;
        }
    }
    Ok(String::from_utf8(result)?)
}
async fn imap<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<S>,
    tag: &str,
    command: &str,
) -> Result<Vec<String>> {
    io.get_mut()
        .write_all(format!("{tag} {command}\r\n").as_bytes())
        .await?;
    io.get_mut().flush().await?;
    let mut lines = Vec::new();
    for _ in 0..1024 {
        let l = line(io).await?;
        if l.starts_with(&format!("{tag} ")) {
            ensure!(l.starts_with(&format!("{tag} OK")), "IMAP command failed");
            return Ok(lines);
        }
        lines.push(l);
    }
    bail!("IMAP response exceeds limit")
}
async fn smtp_reply<S: AsyncRead + Unpin>(io: &mut BufReader<S>, code: u16) -> Result<()> {
    for _ in 0..1024 {
        let l = line(io).await?;
        ensure!(
            l.len() >= 4 && l[..3] == code.to_string(),
            "SMTP command failed"
        );
        if l.as_bytes()[3] != b'-' {
            return Ok(());
        }
    }
    bail!("SMTP response exceeds limit")
}
async fn smtp<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<S>,
    command: &str,
    code: u16,
) -> Result<()> {
    io.get_mut()
        .write_all(format!("{command}\r\n").as_bytes())
        .await?;
    io.get_mut().flush().await?;
    smtp_reply(io, code).await
}
// Go deliberately accepts the public-host certificate on fixed loopback peers.
// Certificate name/chain is bypassed only here; handshake signatures stay verified.
#[derive(Debug)]
struct LoopbackVerifier;
impl ServerCertVerifier for LoopbackVerifier {
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
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
async fn tls(tcp: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(LoopbackVerifier))
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?)
}
pub fn executable(name: &str) -> Result<PathBuf> {
    // Go's exec.Command resolves against the parent's PATH before replacing the
    // child's environment. Preserve that operator-controlled process boundary.
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let path = dir.join(name);
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!("required executable {name} is unavailable")
}
pub async fn fixed(name: &str, args: &[&str]) -> Result<()> {
    let mut c = tokio::process::Command::new(executable(name)?);
    c.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .kill_on_drop(true);
    let output = c.output().await?;
    ensure!(
        output.status.success(),
        "{name} failed: {}",
        String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)])
    );
    Ok(())
}
pub async fn preflight() -> Result<()> {
    for unit in START {
        let m = std::fs::symlink_metadata(format!("/etc/systemd/system/{unit}.service"))?;
        ensure!(m.is_file(), "required unit unavailable");
    }
    let mut args = vec!["is-enabled"];
    args.extend(STOP);
    fixed("systemctl", &args).await
}
pub async fn stop() -> Result<()> {
    let mut args = vec!["stop"];
    args.extend(STOP);
    fixed("systemctl", &args).await
}
pub async fn start() -> Result<()> {
    let mut args = vec!["start"];
    args.extend(START);
    fixed("systemctl", &args).await
}
pub async fn readiness() -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let gateway = fixed(
            "curl",
            &[
                "--insecure",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "--max-filesize",
                "65536",
                "https://127.0.0.1/ready",
            ],
        )
        .await;
        let auth = fixed(
            "curl",
            &[
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "--max-filesize",
                "65536",
                "http://127.0.0.1:8443/health",
            ],
        )
        .await;
        if gateway.is_ok() && auth.is_ok() {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "fixed core readiness probes timed out"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
