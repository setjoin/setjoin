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
    let explicit_cfg = std::env::var_os("SETJOIN_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(|d| std::path::PathBuf::from(d).join("config.env"));
    check_worm_gateway_ready(
        Path::new("/etc/systemd/system/setjoin-gateway.service"),
        explicit_cfg.as_deref(),
        Path::new("/etc/setjoin/config.env"),
    )
}

fn parse_env_assignments(src: &str) -> Vec<(String, String)> {
    #[derive(Clone, Copy)]
    enum State {
        PreValue,
        Value,
        DoubleQuote,
        SingleQuote,
    }
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
        let mut state = State::PreValue;
        let mut buf: Vec<u8> = Vec::new();
        let mut last_non_ws = 0;
        while i < n {
            let ch = bytes[i];
            match state {
                State::PreValue => {
                    if ch == b'\n' {
                        i += 1;
                        break;
                    }
                    if matches!(ch, b' ' | b'\t' | b'\r') {
                        i += 1;
                        continue;
                    }
                    if ch == b'"' {
                        state = State::DoubleQuote;
                        i += 1;
                        continue;
                    }
                    if ch == b'\'' {
                        state = State::SingleQuote;
                        i += 1;
                        continue;
                    }
                    if ch == b'\\' {
                        if i + 1 < n && bytes[i + 1] == b'\n' {
                            i += 2;
                            state = State::Value;
                            continue;
                        }
                        if i + 2 < n && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                            i += 3;
                            state = State::Value;
                            continue;
                        }
                        if i + 1 < n {
                            buf.push(bytes[i + 1]);
                            i += 2;
                            last_non_ws = buf.len();
                            state = State::Value;
                            continue;
                        }
                        i += 1;
                        state = State::Value;
                        continue;
                    }
                    buf.push(ch);
                    last_non_ws = buf.len();
                    i += 1;
                    state = State::Value;
                }
                State::Value => {
                    if ch == b'\n' {
                        i += 1;
                        break;
                    }
                    if ch == b'\\' {
                        if i + 1 < n && bytes[i + 1] == b'\n' {
                            i += 2;
                            state = State::Value;
                            continue;
                        }
                        if i + 2 < n && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                            i += 3;
                            state = State::Value;
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
                State::DoubleQuote => {
                    if ch == b'"' {
                        state = State::PreValue;
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
                State::SingleQuote => {
                    if ch == b'\'' {
                        state = State::PreValue;
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

fn yaml_scalar_is_null(val: &str) -> bool {
    val.is_empty() || matches!(val, "null" | "Null" | "NULL" | "~")
}

fn split_flow_entries(body: &str) -> Result<Vec<&str>, &'static str> {
    let mut parts = Vec::new();
    let bytes = body.as_bytes();
    let mut depth_brace = 0usize;
    let mut depth_bracket = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_sq {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_sq = false;
            }
            i += 1;
            continue;
        }
        if in_dq {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_sq = true,
            b'"' => in_dq = true,
            b'{' => depth_brace += 1,
            b'}' => {
                depth_brace = depth_brace.checked_sub(1).ok_or("unbalanced flow brace")?;
            }
            b'[' => depth_bracket += 1,
            b']' => {
                depth_bracket = depth_bracket
                    .checked_sub(1)
                    .ok_or("unbalanced flow bracket")?;
            }
            b',' if depth_brace == 0 && depth_bracket == 0 => {
                parts.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if in_sq || in_dq || depth_brace != 0 || depth_bracket != 0 {
        return Err("unterminated flow construct");
    }
    parts.push(&body[start..]);
    Ok(parts)
}

fn strip_yaml_key_props(k: &str) -> Result<String, &'static str> {
    let mut t = k.trim();
    if let Some(rest) = t.strip_prefix("!!str") {
        if let Some(first) = rest.chars().next() {
            if first == ' ' || first == '\t' {
                t = rest.trim_start_matches([' ', '\t']);
            }
        }
    }
    if t.starts_with('!') || t.starts_with('&') || t.starts_with('*') {
        return Err("unsupported YAML key property or alias");
    }
    Ok(clean_yaml_scalar(t))
}

fn normalize_retention_days(raw: &str) -> String {
    if let Ok(v) = raw.parse::<f64>() {
        if v.is_finite() && v.fract() == 0.0 && v >= (i64::MIN as f64) && v <= (i64::MAX as f64) {
            return (v as i64).to_string();
        }
    }
    raw.to_owned()
}

#[derive(Default, Debug, PartialEq, Eq)]
struct YamlWorm {
    mode: Option<String>,
    retention_days: Option<String>,
}

fn flow_worm_settings(flow: &str) -> Result<YamlWorm, &'static str> {
    let inner = flow
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or("malformed flow mapping")?;
    let entries = split_flow_entries(inner)?;
    let mut out = YamlWorm::default();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((fk, fv)) = trimmed.split_once(':') else {
            continue;
        };
        if fk.trim() == "<<" {
            return Err("YAML merge key in flow mapping");
        }
        let key_clean = strip_yaml_key_props(fk)?;
        let fv_trim = fv.trim();
        if matches!(key_clean.as_str(), "mode" | "retention_days")
            && (fv_trim.starts_with('*') || fv_trim.starts_with('&') || fv_trim.starts_with('!'))
        {
            return Err("YAML alias/tag in worm setting");
        }
        if key_clean == "mode" {
            let val = clean_yaml_scalar(fv_trim);
            out.mode = (!yaml_scalar_is_null(&val)).then_some(val);
        } else if key_clean == "retention_days" {
            let val = clean_yaml_scalar(fv_trim);
            out.retention_days = (!yaml_scalar_is_null(&val)).then(|| normalize_retention_days(&val));
        }
    }
    Ok(out)
}

fn yaml_worm_settings(yaml: &str) -> Result<YamlWorm, &'static str> {
    let mut joined_flow = String::new();
    let mut saw_first = false;
    let mut top_flow = false;
    for raw_line in yaml.lines() {
        let stripped = strip_inline_yaml_comment(raw_line).trim();
        if stripped.is_empty() || stripped == "---" || stripped == "..." {
            continue;
        }
        if !saw_first {
            saw_first = true;
            top_flow = stripped.starts_with('{');
        }
        if top_flow {
            if !joined_flow.is_empty() {
                joined_flow.push(' ');
            }
            joined_flow.push_str(stripped);
        }
    }
    if top_flow {
        let inner = joined_flow
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or("unterminated top-level flow mapping")?;
        for entry in split_flow_entries(inner)? {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((k, v)) = trimmed.split_once(':') else {
                continue;
            };
            if k.trim() == "<<" {
                return Err("root YAML merge key");
            }
            if strip_yaml_key_props(k)? == "worm" {
                let v_trim = v.trim();
                if yaml_scalar_is_null(v_trim) {
                    return Ok(YamlWorm::default());
                }
                return flow_worm_settings(v_trim);
            }
        }
        return Ok(YamlWorm::default());
    }

    let mut out = YamlWorm::default();
    let mut root_ind: Option<usize> = None;
    let mut in_worm = false;
    let mut worm_ind = 0usize;
    let mut child_ind: Option<usize> = None;
    let mut worm_flow_buf: Option<String> = None;
    for raw_line in yaml.lines() {
        let stripped = strip_inline_yaml_comment(raw_line);
        let trimmed = stripped.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }
        let ind = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if let Some(buf) = worm_flow_buf.as_mut() {
            buf.push(' ');
            buf.push_str(trimmed);
            if buf.trim_end().ends_with('}') && flow_worm_settings(buf).is_ok() {
                return flow_worm_settings(buf);
            }
            continue;
        }
        if in_worm {
            if ind <= worm_ind {
                in_worm = false;
                child_ind = None;
            } else {
                if child_ind.is_none() {
                    child_ind = Some(ind);
                    if trimmed.starts_with('{') {
                        if let Ok(parsed) = flow_worm_settings(trimmed) {
                            return Ok(parsed);
                        }
                        worm_flow_buf = Some(trimmed.to_owned());
                        continue;
                    }
                }
                if child_ind == Some(ind) {
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim() == "<<" {
                            return Err("worm YAML merge key");
                        }
                        let key_clean = strip_yaml_key_props(k)?;
                        let v_trim = v.trim();
                        if matches!(key_clean.as_str(), "mode" | "retention_days")
                            && (v_trim.starts_with('*')
                                || v_trim.starts_with('&')
                                || v_trim.starts_with('!'))
                        {
                            return Err("YAML alias/tag in worm setting");
                        }
                        if key_clean == "mode" {
                            let val = clean_yaml_scalar(v_trim);
                            out.mode = (!yaml_scalar_is_null(&val)).then_some(val);
                        } else if key_clean == "retention_days" {
                            let val = clean_yaml_scalar(v_trim);
                            out.retention_days =
                                (!yaml_scalar_is_null(&val)).then(|| normalize_retention_days(&val));
                        }
                    }
                }
                continue;
            }
        }
        let root = *root_ind.get_or_insert(ind);
        if ind < root {
            return Err("inconsistent root YAML indentation");
        }
        if ind == root {
            if let Some((k, rest)) = trimmed.split_once(':') {
                if k.trim() == "<<" {
                    return Err("root YAML merge key");
                }
                if strip_yaml_key_props(k)? == "worm" {
                    let rest_trim = rest.trim();
                    if rest_trim.is_empty() {
                        in_worm = true;
                        worm_ind = ind;
                    } else if yaml_scalar_is_null(rest_trim) {
                        return Ok(YamlWorm::default());
                    } else if rest_trim.starts_with('{') {
                        if let Ok(parsed) = flow_worm_settings(rest_trim) {
                            return Ok(parsed);
                        }
                        worm_flow_buf = Some(rest_trim.to_owned());
                    } else {
                        return Err("unsupported worm YAML value");
                    }
                }
            }
        }
    }
    if let Some(buf) = worm_flow_buf {
        return flow_worm_settings(&buf);
    }
    Ok(out)
}

fn parse_unit_env_files(unit: &str) -> Vec<(std::path::PathBuf, bool)> {
    let mut out = Vec::new();
    for line in unit.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        let Some(raw_rhs) = t.strip_prefix("EnvironmentFile=") else {
            continue;
        };
        let rhs = raw_rhs.trim();
        if rhs.is_empty() {
            out.clear();
            continue;
        }
        let (optional, rest) = if let Some(after) = rhs.strip_prefix('-') {
            (true, after.trim())
        } else {
            (false, rhs)
        };
        let unquoted = rest
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(rest);
        if !unquoted.is_empty() {
            out.push((std::path::PathBuf::from(unquoted), optional));
        }
    }
    out
}

fn load_effective_gateway_env(
    env_files: &[(std::path::PathBuf, bool)],
) -> Option<(Vec<(String, String)>, bool, bool)> {
    let has_storage_file = env_files.iter().any(|(p, _)| {
        p.file_name().and_then(|n| n.to_str()) == Some("storage.env")
            && std::fs::metadata(p).is_ok_and(|m| m.is_file())
    });
    let has_gateway_file = env_files.iter().any(|(p, _)| {
        p.file_name().and_then(|n| n.to_str()) == Some("gateway.env")
            && std::fs::metadata(p).is_ok_and(|m| m.is_file())
    });
    let mut effective_gw_pairs = Vec::new();
    for (path, optional) in env_files {
        match std::fs::read_to_string(path) {
            Ok(content) => effective_gw_pairs.extend(parse_env_assignments(&content)),
            Err(_) if !optional => return None,
            Err(_) => {}
        }
    }
    Some((effective_gw_pairs, has_storage_file, has_gateway_file))
}

fn gateway_has_worm_settings(
    env_files: &[(std::path::PathBuf, bool)],
    expected_mode: &str,
    expected_legal_hold: Option<&str>,
    expected_retention_days: Option<&str>,
) -> bool {
    let Some((effective_gw_pairs, has_storage_file, has_gateway_file)) =
        load_effective_gateway_env(env_files)
    else {
        return false;
    };
    if !has_storage_file || !has_gateway_file {
        return false;
    }
    if env_lookup(&effective_gw_pairs, "WORM_MODE").as_deref() != Some(expected_mode) {
        return false;
    }
    if env_lookup(&effective_gw_pairs, "WORM_LEGAL_HOLD_ENABLED").as_deref() != expected_legal_hold
    {
        return false;
    }
    let gw_retention = env_lookup(&effective_gw_pairs, "WORM_RETENTION_DAYS");
    let gw_retention_nonempty = gw_retention.as_deref().filter(|v| !v.is_empty());
    if gw_retention_nonempty != expected_retention_days {
        return false;
    }
    true
}

pub(crate) fn check_worm_gateway_ready(
    unit_path: &Path,
    explicit_config_env: Option<&Path>,
    default_config_env: &Path,
) -> Result<()> {
    let unit_src = std::fs::read_to_string(unit_path).ok();
    let env_files = unit_src
        .as_deref()
        .map(parse_unit_env_files)
        .unwrap_or_default();
    let unit_cfg = env_files
        .iter()
        .rfind(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some("gateway.env"))
        .and_then(|(p, _)| p.parent().map(|d| d.join("config.env")));
    let resolved_cfg = if let Some(explicit) = explicit_config_env {
        if !explicit.exists() {
            return Ok(());
        }
        explicit
    } else if unit_cfg.as_ref().is_some_and(|p| p.exists()) {
        unit_cfg.as_deref().unwrap()
    } else if default_config_env.exists() {
        default_config_env
    } else {
        return Ok(());
    };
    let config_src = std::fs::read_to_string(resolved_cfg)
        .with_context(|| format!("reading {}", resolved_cfg.display()))?;
    let pairs = parse_env_assignments(&config_src);
    let expected_legal_hold = env_lookup(&pairs, "WORM_LEGAL_HOLD_ENABLED");
    let config_worm_mode = env_lookup(&pairs, "WORM_MODE");
    let config_retention = env_lookup(&pairs, "WORM_RETENTION_DAYS");
    let need_yaml = config_worm_mode.is_none() || config_retention.is_none();
    let yaml_settings = if need_yaml && config_worm_mode.as_deref() != Some("") {
        match env_lookup(&pairs, "SETJOIN_CONFIG").filter(|p| !p.is_empty()) {
            Some(yaml_path) => match std::fs::read_to_string(&yaml_path) {
                Ok(yaml) => Some(yaml_worm_settings(&yaml).map_err(|reason| {
                    anyhow::anyhow!(
                        "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying WORM gateway readiness ({reason}); set WORM_MODE explicitly or run upgrade.sh refresh-gateway-env"
                    )
                })?),
                Err(err) => {
                    bail!(
                        "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying WORM gateway readiness: {err}"
                    );
                }
            },
            None => None,
        }
    } else {
        None
    };
    let expected_mode = match config_worm_mode {
        Some(v) => (!v.is_empty()).then_some(v),
        None => yaml_settings.as_ref().and_then(|y| y.mode.clone()),
    };
    let expected_retention_days = match config_retention {
        Some(v) => (!v.is_empty()).then_some(v),
        None => yaml_settings
            .as_ref()
            .and_then(|y| y.retention_days.clone()),
    };
    if let Some(mode) = expected_mode {
        if !gateway_has_worm_settings(
            &env_files,
            &mode,
            expected_legal_hold.as_deref(),
            expected_retention_days.as_deref(),
        ) {
            bail!(
                "WORM is enabled in host configuration, but setjoin-gateway unit/gateway.env lacks matching storage.env and WORM_MODE; run upgrade.sh refresh-gateway-env before activating"
            );
        }
    } else if let Some((effective_gw_pairs, _, has_gateway_file)) =
        load_effective_gateway_env(&env_files)
    {
        if env_lookup(&effective_gw_pairs, "DB_DSN").is_some_and(|v| !v.is_empty())
            && (!has_gateway_file || env_lookup(&effective_gw_pairs, "WORM_MODE").is_none())
        {
            bail!(
                "DB-backed setjoin-gateway unit/gateway.env lacks explicit WORM_MODE=; run upgrade.sh refresh-gateway-env before activating"
            );
        }
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
    use super::{check_worm_gateway_ready, parse_env_assignments};

    #[test]
    fn worm_gateway_ready_checks_unit_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("setjoin-gateway.service");
        let cfg = dir.path().join("config.env");
        let stale_default = dir.path().join("default/config.env");
        std::fs::create_dir_all(stale_default.parent().unwrap()).unwrap();
        std::fs::write(&stale_default, "HOSTNAME=stale.test\n").unwrap();
        let gw = dir.path().join("gateway.env");
        let storage = dir.path().join("storage.env");
        let yaml = dir.path().join("setjoin.yaml");

        // WORM disabled -> Ok
        std::fs::write(&cfg, "HOSTNAME=mail.test\n").unwrap();
        std::fs::write(
            &unit,
            format!("[Service]\nEnvironmentFile={}\n", gw.display()),
        )
        .unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());

        // Unit-derived custom config.env takes precedence over an existing default config.env
        std::fs::write(&cfg, "WORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());

        // Unit lacking EnvironmentFile=gateway.env fails even when gw exists on disk
        let no_gw_unit = dir.path().join("no-gw.service");
        std::fs::write(
            &no_gw_unit,
            format!("[Service]\nEnvironmentFile=-{}\n", storage.display()),
        )
        .unwrap();
        std::fs::write(&storage, "S3_BUCKET=mailblobs\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&no_gw_unit, Some(&cfg), &stale_default).is_err());

        // Unit references storage.env, gateway.env has WORM_MODE, but storage.env file is absent on disk -> Err
        std::fs::remove_file(&storage).unwrap();
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                storage.display(),
                gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());

        // Creating storage.env on disk satisfies readiness -> Ok
        std::fs::write(&storage, "S3_BUCKET=mailblobs\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());

        // Mismatched WORM_MODE or WORM_LEGAL_HOLD_ENABLED -> Err
        std::fs::write(&cfg, "WORM_MODE=governance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_LEGAL_HOLD_ENABLED=false\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &gw,
            "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_LEGAL_HOLD_ENABLED=false\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());

        // Adjacent quoted env spans match systemd env-file rules, while leading continuation enters VALUE
        std::fs::write(
            &cfg,
            "WORM_MODE=\"com\"'pli'\"ance\"\nWORM_LEGAL_HOLD_ENABLED=false\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        let cont_pairs = parse_env_assignments("WORM_MODE=\\\n\"compliance\"\n");
        assert_eq!(cont_pairs, vec![("WORM_MODE".into(), "\"compliance\"".into())]);

        // Tagged worm key + retention_days normalization and indented flow mapping beneath worm:
        std::fs::write(&yaml, "!!str worm: {mode: compliance, retention_days: 3650.}\n").unwrap();
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\n", yaml.display())).unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        std::fs::write(
            &gw,
            "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=3650\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());

        std::fs::write(
            &yaml,
            "worm:\n  { mode: compliance, retention_days: 3.65e3 }\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=2557\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());

        // Top-level flow YAML -> Err when mismatched, Ok when matched
        std::fs::write(&yaml, "{ s3: { bucket: a }, worm: { mode: compliance } }\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());

        // Merge key in YAML fails closed even when gateway sets WORM_MODE -> Err
        std::fs::write(&yaml, "<<: *base\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());

        // Explicit empty WORM_MODE= overrides YAML -> Ok
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\nWORM_MODE=\n", yaml.display())).unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());

        // Indented YAML root mapping -> detected
        std::fs::write(&yaml, "  worm:\n    mode: compliance\n").unwrap();
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\n", yaml.display())).unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());

        // Empty EnvironmentFile= clears earlier directives in systemd
        let cleared_unit = dir.path().join("cleared.service");
        std::fs::write(
            &cleared_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\nEnvironmentFile=\n",
                storage.display(),
                gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&cleared_unit, None, &stale_default).is_err());

        // DB-backed non-WORM host requires explicit WORM_MODE= in gateway.env
        let fed = dir.path().join("federation.env");
        std::fs::write(&fed, "DB_DSN=postgres://app@localhost/mail\n").unwrap();
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                fed.display(),
                gw.display()
            ),
        )
        .unwrap();
        std::fs::write(&cfg, "HOSTNAME=mail.test\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());
    }
}
