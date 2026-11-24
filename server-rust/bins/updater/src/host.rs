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
    fixed("systemctl", &args).await?;
    check_worm_gateway_ready(
        Path::new("/etc/systemd/system/setjoin-gateway.service"),
        Path::new("/etc/setjoin/config.env"),
        Path::new("/etc/setjoin/gateway.env"),
    )
}

fn parse_env_assignments(src: &str) -> Vec<(String, String)> {
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    let mut out = Vec::new();
    while i < n {
        while i < n && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        if i >= n {
            break;
        }
        if matches!(bytes[i], b'#' | b';') {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let k_start = i;
        while i < n && !matches!(bytes[i], b'=' | b'\n') {
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            if i < n && bytes[i] == b'\n' {
                i += 1;
            }
            continue;
        }
        let key = src[k_start..i].trim_matches([' ', '\t', '\r']).to_owned();
        i += 1;
        while i < n && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        let mut quote: Option<u8> = if i < n && matches!(bytes[i], b'"' | b'\'') {
            let q = bytes[i];
            i += 1;
            Some(q)
        } else {
            None
        };
        let mut buf: Vec<u8> = Vec::new();
        let mut last_non_ws = 0;
        while i < n {
            let ch = bytes[i];
            match quote {
                None => {
                    if ch == b'\n' {
                        i += 1;
                        break;
                    }
                    if ch == b'\\' {
                        if i + 1 < n && bytes[i + 1] == b'\n' {
                            i += 2;
                            continue;
                        }
                        if i + 2 < n && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                            i += 3;
                            continue;
                        }
                        if i + 1 < n {
                            buf.push(bytes[i + 1]);
                            i += 2;
                            last_non_ws = buf.len();
                            continue;
                        }
                    }
                    buf.push(ch);
                    if !matches!(ch, b' ' | b'\t' | b'\r') {
                        last_non_ws = buf.len();
                    }
                    i += 1;
                }
                Some(b'"') => {
                    if ch == b'"' {
                        quote = None;
                        last_non_ws = buf.len();
                        i += 1;
                        continue;
                    }
                    if ch == b'\\' && i + 1 < n {
                        let nxt = bytes[i + 1];
                        if matches!(nxt, b'\\' | b'"' | b'$' | b'`') {
                            buf.push(nxt);
                            last_non_ws = buf.len();
                            i += 2;
                            continue;
                        }
                        if nxt == b'\n' {
                            i += 2;
                            continue;
                        }
                        if nxt == b'\r' && i + 2 < n && bytes[i + 2] == b'\n' {
                            i += 3;
                            continue;
                        }
                    }
                    buf.push(ch);
                    last_non_ws = buf.len();
                    i += 1;
                }
                Some(_) => {
                    if ch == b'\'' {
                        quote = None;
                        last_non_ws = buf.len();
                        i += 1;
                        continue;
                    }
                    buf.push(ch);
                    last_non_ws = buf.len();
                    i += 1;
                }
            }
        }
        let val = String::from_utf8_lossy(&buf[..last_non_ws]).into_owned();
        if !key.is_empty() {
            out.push((key, val));
        }
    }
    out
}

fn env_lookup(pairs: &[(String, String)], target: &str) -> Option<String> {
    pairs
        .iter()
        .rev()
        .find(|(k, _)| k == target)
        .map(|(_, v)| v.clone())
}

fn strip_inline_yaml_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut in_sq = false;
    let mut in_dq = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if !in_dq => in_sq = !in_sq,
            b'"' if !in_sq => in_dq = !in_dq,
            b'\\' if in_dq => {
                i += 2;
                continue;
            }
            b'#' if !in_sq && !in_dq && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')) => {
                return &s[..i];
            }
            _ => {}
        }
        i += 1;
    }
    s
}

fn clean_yaml_scalar(s: &str) -> String {
    let t = strip_inline_yaml_comment(s).trim();
    if let Some(inner) = t.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        inner.to_owned()
    } else if let Some(inner) = t.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        inner.to_owned()
    } else {
        t.to_owned()
    }
}

fn yaml_has_active_worm_mode(yaml: &str) -> bool {
    let mut in_worm = false;
    let mut worm_ind = 0usize;
    let mut child_ind: Option<usize> = None;
    for raw_line in yaml.lines() {
        let stripped = strip_inline_yaml_comment(raw_line);
        let trimmed = stripped.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }
        let ind = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if in_worm {
            if ind <= worm_ind {
                in_worm = false;
                child_ind = None;
            } else {
                if child_ind.is_none() {
                    child_ind = Some(ind);
                }
                if child_ind == Some(ind) {
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if clean_yaml_scalar(k) == "mode" {
                            let val = clean_yaml_scalar(v);
                            return !(val.is_empty() || matches!(val.as_str(), "null" | "Null" | "NULL" | "~"));
                        }
                    }
                }
                continue;
            }
        }
        if ind == 0 {
            if let Some((k, rest)) = trimmed.split_once(':') {
                if clean_yaml_scalar(k) == "worm" {
                    let rest_trim = rest.trim();
                    if rest_trim.is_empty() {
                        in_worm = true;
                        worm_ind = ind;
                    } else if let Some(flow) = rest_trim.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                        for entry in flow.split(',') {
                            if let Some((fk, fv)) = entry.split_once(':') {
                                if clean_yaml_scalar(fk) == "mode" {
                                    let val = clean_yaml_scalar(fv);
                                    return !(val.is_empty() || matches!(val.as_str(), "null" | "Null" | "NULL" | "~"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn gateway_has_worm_settings(unit_path: &Path, gateway_env_path: &Path) -> bool {
    let Ok(unit) = std::fs::read_to_string(unit_path) else {
        return false;
    };
    let has_storage_env = unit.lines().any(|line| {
        let t = line.trim();
        !t.starts_with('#')
            && !t.starts_with(';')
            && t.strip_prefix("EnvironmentFile=")
                .is_some_and(|rhs| rhs.trim().ends_with("storage.env"))
    });
    if !has_storage_env {
        return false;
    }
    let Ok(gw_env) = std::fs::read_to_string(gateway_env_path) else {
        return false;
    };
    let gw_pairs = parse_env_assignments(&gw_env);
    env_lookup(&gw_pairs, "WORM_MODE").is_some_and(|v| !v.is_empty())
}

pub(crate) fn check_worm_gateway_ready(
    unit_path: &Path,
    config_env_path: &Path,
    gateway_env_path: &Path,
) -> Result<()> {
    if !config_env_path.exists() {
        return Ok(());
    }
    let config_src = std::fs::read_to_string(config_env_path)
        .with_context(|| format!("reading {}", config_env_path.display()))?;
    let pairs = parse_env_assignments(&config_src);
    let ready = gateway_has_worm_settings(unit_path, gateway_env_path);
    let worm_active = match env_lookup(&pairs, "WORM_MODE") {
        Some(v) => !v.is_empty(),
        None => match env_lookup(&pairs, "SETJOIN_CONFIG").filter(|p| !p.is_empty()) {
            Some(yaml_path) => match std::fs::read_to_string(&yaml_path) {
                Ok(yaml) => yaml_has_active_worm_mode(&yaml),
                Err(err) => {
                    if ready {
                        false
                    } else {
                        bail!("cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying WORM gateway readiness: {err}");
                    }
                }
            },
            None => false,
        },
    };
    if worm_active && !ready {
        bail!(
            "WORM is enabled in host configuration, but setjoin-gateway unit/gateway.env lacks storage.env and WORM_MODE; run upgrade.sh refresh-gateway-env before activating"
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::check_worm_gateway_ready;

    #[test]
    fn worm_gateway_ready_checks_unit_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("setjoin-gateway.service");
        let cfg = dir.path().join("config.env");
        let gw = dir.path().join("gateway.env");
        let yaml = dir.path().join("setjoin.yaml");

        // WORM disabled -> Ok
        std::fs::write(&cfg, "HOSTNAME=mail.test\n").unwrap();
        std::fs::write(&unit, "[Service]\nEnvironmentFile=/etc/setjoin/gateway.env\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, &cfg, &gw).is_ok());

        // WORM enabled in config.env, missing storage.env and WORM_MODE -> Err
        std::fs::write(&cfg, "WORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, &cfg, &gw).is_err());

        // Unit has storage.env, gateway.env lacks WORM_MODE -> Err
        std::fs::write(
            &unit,
            "[Service]\nEnvironmentFile=-/etc/setjoin/storage.env\nEnvironmentFile=/etc/setjoin/gateway.env\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, &cfg, &gw).is_err());

        // Both storage.env and WORM_MODE present -> Ok
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, &cfg, &gw).is_ok());

        // WORM in SETJOIN_CONFIG YAML with missing gateway settings -> Err
        std::fs::write(&yaml, "worm:\n  mode: compliance\n").unwrap();
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\n", yaml.display())).unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, &cfg, &gw).is_err());

        // Explicit empty WORM_MODE= overrides YAML worm.mode -> Ok
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\nWORM_MODE=\n", yaml.display())).unwrap();
        assert!(check_worm_gateway_ready(&unit, &cfg, &gw).is_ok());
    }
}
