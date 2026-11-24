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

fn decode_yaml_hex(chars: &mut std::str::Chars<'_>, count: usize) -> Result<char, &'static str> {
    let mut val = 0u32;
    for _ in 0..count {
        let ch = chars.next().ok_or("truncated YAML escape")?;
        let d = ch.to_digit(16).ok_or("invalid hex in YAML escape")?;
        val = (val << 4) | d;
    }
    char::from_u32(val).ok_or("invalid Unicode scalar in YAML escape")
}

fn decode_yaml_double_quoted(inner: &str) -> Result<String, &'static str> {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let esc = chars.next().ok_or("trailing backslash in YAML string")?;
        match esc {
            '0' => out.push('\0'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            't' | '\t' => out.push('\t'),
            'n' => out.push('\n'),
            'v' => out.push('\x0b'),
            'f' => out.push('\x0c'),
            'r' => out.push('\r'),
            'e' => out.push('\x1b'),
            ' ' => out.push(' '),
            '"' => out.push('"'),
            '/' => out.push('/'),
            '\\' => out.push('\\'),
            'N' => out.push('\u{0085}'),
            '_' => out.push('\u{00A0}'),
            'L' => out.push('\u{2028}'),
            'P' => out.push('\u{2029}'),
            'x' => out.push(decode_yaml_hex(&mut chars, 2)?),
            'u' => out.push(decode_yaml_hex(&mut chars, 4)?),
            'U' => out.push(decode_yaml_hex(&mut chars, 8)?),
            _ => return Err("unsupported YAML escape sequence"),
        }
    }
    Ok(out)
}

fn clean_yaml_scalar(s: &str) -> Result<String, &'static str> {
    let t = strip_inline_yaml_comment(s).trim();
    if let Some(inner) = t.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        decode_yaml_double_quoted(inner)
    } else if let Some(inner) = t.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        Ok(inner.replace("''", "'"))
    } else {
        Ok(t.to_owned())
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
    clean_yaml_scalar(t)
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

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct YamlS3 {
    endpoint: Option<String>,
    access_key: Option<String>,
    secret_key: Option<String>,
    bucket: Option<String>,
    secure: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedS3 {
    endpoint: String,
    access_key: String,
    secret_key: String,
    bucket: String,
    secure: bool,
}

fn koanf_bool(raw: &str) -> bool {
    matches!(raw, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

fn strict_go_bool(raw: &str, key: &str) -> Result<bool, String> {
    if koanf_bool(raw) {
        Ok(true)
    } else if matches!(raw, "0" | "f" | "F" | "false" | "FALSE" | "False") {
        Ok(false)
    } else {
        Err(format!("invalid boolean for {key}: {raw:?}"))
    }
}

fn yaml_value_is_unquoted_null(raw_trim: &str, decoded: &str) -> bool {
    !(raw_trim.starts_with('"') || raw_trim.starts_with('\'')) && yaml_scalar_is_null(decoded)
}

fn flow_section_entries(
    flow: &str,
    watched_keys: &[&str],
) -> Result<Vec<(String, Option<String>)>, &'static str> {
    let inner = flow
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or("malformed flow mapping")?;
    let entries = split_flow_entries(inner)?;
    let mut out = Vec::new();
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
        if watched_keys.contains(&key_clean.as_str()) {
            if fv_trim.starts_with('*') || fv_trim.starts_with('&') || fv_trim.starts_with('!') {
                return Err("YAML alias/tag in section setting");
            }
            let val = clean_yaml_scalar(fv_trim)?;
            let mapped = (!yaml_value_is_unquoted_null(fv_trim, &val)).then_some(val);
            out.push((key_clean, mapped));
        }
    }
    Ok(out)
}

fn yaml_section_entries(
    yaml: &str,
    section: &str,
    watched_keys: &[&str],
) -> Result<Vec<(String, Option<String>)>, &'static str> {
    let yaml = yaml.strip_prefix('\u{feff}').unwrap_or(yaml);
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
            if strip_yaml_key_props(k)? == section {
                let v_trim = v.trim();
                if yaml_scalar_is_null(v_trim) {
                    return Ok(Vec::new());
                }
                return flow_section_entries(v_trim, watched_keys);
            }
        }
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut root_ind: Option<usize> = None;
    let mut in_section = false;
    let mut section_ind = 0usize;
    let mut child_ind: Option<usize> = None;
    let mut flow_buf: Option<String> = None;
    for raw_line in yaml.lines() {
        let stripped = strip_inline_yaml_comment(raw_line);
        let trimmed = stripped.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }
        let ind = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if let Some(buf) = flow_buf.as_mut() {
            buf.push(' ');
            buf.push_str(trimmed);
            if buf.trim_end().ends_with('}') && flow_section_entries(buf, watched_keys).is_ok() {
                return flow_section_entries(buf, watched_keys);
            }
            continue;
        }
        if in_section {
            if ind <= section_ind {
                in_section = false;
                child_ind = None;
            } else {
                if child_ind.is_none() {
                    child_ind = Some(ind);
                    if trimmed.starts_with('{') {
                        if let Ok(parsed) = flow_section_entries(trimmed, watched_keys) {
                            return Ok(parsed);
                        }
                        flow_buf = Some(trimmed.to_owned());
                        continue;
                    }
                }
                if child_ind == Some(ind) {
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim() == "<<" {
                            return Err("section YAML merge key");
                        }
                        let key_clean = strip_yaml_key_props(k)?;
                        let v_trim = v.trim();
                        if watched_keys.contains(&key_clean.as_str()) {
                            if v_trim.starts_with('*')
                                || v_trim.starts_with('&')
                                || v_trim.starts_with('!')
                            {
                                return Err("YAML alias/tag in section setting");
                            }
                            let val = clean_yaml_scalar(v_trim)?;
                            let mapped =
                                (!yaml_value_is_unquoted_null(v_trim, &val)).then_some(val);
                            out.push((key_clean, mapped));
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
                if strip_yaml_key_props(k)? == section {
                    let rest_trim = rest.trim();
                    if rest_trim.is_empty() {
                        in_section = true;
                        section_ind = ind;
                    } else if yaml_scalar_is_null(rest_trim) {
                        return Ok(Vec::new());
                    } else if rest_trim.starts_with('{') {
                        if let Ok(parsed) = flow_section_entries(rest_trim, watched_keys) {
                            return Ok(parsed);
                        }
                        flow_buf = Some(rest_trim.to_owned());
                    } else {
                        return Err("unsupported section YAML value");
                    }
                }
            }
        }
    }
    if let Some(buf) = flow_buf {
        return flow_section_entries(&buf, watched_keys);
    }
    Ok(out)
}

fn yaml_worm_settings(yaml: &str) -> Result<YamlWorm, &'static str> {
    let entries = yaml_section_entries(yaml, "worm", &["mode", "retention_days"])?;
    let mut out = YamlWorm::default();
    for (k, v) in entries {
        if k == "mode" {
            out.mode = v.filter(|s| !s.is_empty());
        } else if k == "retention_days" {
            out.retention_days = v
                .filter(|s| !s.is_empty())
                .map(|s| normalize_retention_days(&s));
        }
    }
    Ok(out)
}

fn yaml_s3_settings(yaml: &str) -> Result<YamlS3, &'static str> {
    let entries = yaml_section_entries(
        yaml,
        "s3",
        &["endpoint", "access_key", "secret_key", "bucket", "secure"],
    )?;
    let mut out = YamlS3::default();
    for (k, v) in entries {
        match k.as_str() {
            "endpoint" => out.endpoint = v,
            "access_key" => out.access_key = v,
            "secret_key" => out.secret_key = v,
            "bucket" => out.bucket = v,
            "secure" => out.secure = v,
            _ => {}
        }
    }
    Ok(out)
}

fn resolve_s3_settings(
    pairs: &[(String, String)],
    yaml_s3: Option<&YamlS3>,
) -> Result<ResolvedS3, String> {
    let mut endpoint = yaml_s3
        .and_then(|s| s.endpoint.as_deref())
        .unwrap_or("127.0.0.1:9000")
        .to_owned();
    if let Some(v) = env_lookup(pairs, "S3_ENDPOINT") {
        endpoint = v;
    }
    if endpoint == "127.0.0.1:9000" {
        if let Some(v) = env_lookup(pairs, "MINIO_ENDPOINT").filter(|v| !v.is_empty()) {
            endpoint = v;
        }
    }

    let mut access_key = yaml_s3
        .and_then(|s| s.access_key.as_deref())
        .unwrap_or("")
        .to_owned();
    if let Some(v) = env_lookup(pairs, "S3_ACCESS_KEY") {
        access_key = v;
    }
    if access_key.is_empty() {
        if let Some(v) = env_lookup(pairs, "MINIO_ACCESS_KEY").filter(|v| !v.is_empty()) {
            access_key = v;
        }
    }

    let mut secret_key = yaml_s3
        .and_then(|s| s.secret_key.as_deref())
        .unwrap_or("")
        .to_owned();
    if let Some(v) = env_lookup(pairs, "S3_SECRET_KEY") {
        secret_key = v;
    }
    if secret_key.is_empty() {
        if let Some(v) = env_lookup(pairs, "MINIO_SECRET_KEY").filter(|v| !v.is_empty()) {
            secret_key = v;
        }
    }

    let mut bucket = yaml_s3
        .and_then(|s| s.bucket.as_deref())
        .unwrap_or("mailblobs")
        .to_owned();
    if let Some(v) = env_lookup(pairs, "S3_BUCKET") {
        bucket = v;
    }
    if bucket == "mailblobs" {
        if let Some(v) = env_lookup(pairs, "MINIO_BUCKET").filter(|v| !v.is_empty()) {
            bucket = v;
        }
    }

    let secure = if let Some(v) = env_lookup(pairs, "MINIO_SECURE").filter(|v| !v.is_empty()) {
        strict_go_bool(&v, "MINIO_SECURE")?
    } else if let Some(v) = env_lookup(pairs, "S3_SECURE") {
        koanf_bool(&v)
    } else if let Some(v) = yaml_s3.and_then(|s| s.secure.as_deref()) {
        koanf_bool(v)
    } else {
        false
    };

    Ok(ResolvedS3 {
        endpoint,
        access_key,
        secret_key,
        bucket,
        secure,
    })
}

const STORAGE_ENV_KEYS: [&str; 8] = [
    "S3_ENDPOINT",
    "MINIO_ENDPOINT",
    "S3_BUCKET",
    "MINIO_BUCKET",
    "S3_ACCESS_KEY",
    "MINIO_ACCESS_KEY",
    "S3_SECRET_KEY",
    "MINIO_SECRET_KEY",
];

#[derive(Default, Debug)]
struct UnitEnvSpec {
    env_files: Vec<(std::path::PathBuf, bool)>,
    unset_env: Vec<String>,
}

fn split_systemd_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
            continue;
        }
        let mut word = String::new();
        while let Some(&ch) = chars.peek() {
            if ch.is_ascii_whitespace() {
                break;
            }
            if ch == '"' || ch == '\'' {
                let q = ch;
                chars.next();
                while let Some(inner) = chars.next() {
                    if inner == q {
                        break;
                    }
                    if inner == '\\' && q == '"' {
                        if let Some(esc) = chars.next() {
                            word.push(esc);
                        }
                    } else {
                        word.push(inner);
                    }
                }
            } else if ch == '\\' {
                chars.next();
                if let Some(esc) = chars.next() {
                    word.push(esc);
                }
            } else {
                word.push(ch);
                chars.next();
            }
        }
        if !word.is_empty() {
            out.push(word);
        }
    }
    out
}

fn systemd_logical_lines(unit: &str) -> Vec<String> {
    let unit = unit.strip_prefix('\u{feff}').unwrap_or(unit);
    let mut logical = Vec::new();
    let mut current = String::new();
    let mut continuing = false;
    for raw_line in unit.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim_start().starts_with('#') || line.trim_start().starts_with(';') {
            continue;
        }
        let trailing_bs = line.bytes().rev().take_while(|&b| b == b'\\').count();
        if trailing_bs % 2 == 1 {
            current.push_str(&line[..line.len() - 1]);
            current.push(' ');
            continuing = true;
        } else {
            current.push_str(line);
            logical.push(std::mem::take(&mut current));
            continuing = false;
        }
    }
    if continuing {
        logical.push(current);
    }
    logical
}

fn parse_unit_env_spec_into(unit: &str, spec: &mut UnitEnvSpec) {
    let mut in_service = false;
    for line in systemd_logical_lines(unit) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('[') && t.ends_with(']') {
            in_service = t == "[Service]";
            continue;
        }
        if !in_service {
            continue;
        }
        let Some((lhs, raw_rhs)) = t.split_once('=') else {
            continue;
        };
        let key = lhs.trim();
        let rhs = raw_rhs.trim();
        if key == "UnsetEnvironment" {
            if rhs.is_empty() {
                spec.unset_env.clear();
            } else {
                spec.unset_env.extend(split_systemd_words(rhs));
            }
            continue;
        }
        if key != "EnvironmentFile" {
            continue;
        }
        if rhs.is_empty() {
            spec.env_files.clear();
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
            spec.env_files
                .push((std::path::PathBuf::from(unquoted), optional));
        }
    }
}

fn dropin_rel_dirs(unit_name: &str) -> Vec<String> {
    let mut rels = Vec::new();
    let Some((stem, unit_type)) = unit_name.rsplit_once('.') else {
        rels.push(format!("{unit_name}.d"));
        return rels;
    };
    rels.push(format!("{unit_type}.d"));
    for (idx, _) in stem.match_indices('-') {
        if idx > 0 {
            rels.push(format!("{}-.{unit_type}.d", &stem[..idx]));
        }
    }
    if let Some((prefix, _)) = stem.split_once('@') {
        if !prefix.is_empty() {
            let tmpl = format!("{prefix}@.{unit_type}.d");
            if !rels.contains(&tmpl) {
                rels.push(tmpl);
            }
        }
    }
    let exact = format!("{unit_name}.d");
    if !rels.contains(&exact) {
        rels.push(exact);
    }
    rels
}

fn default_dropin_dirs(unit_path: &Path) -> Vec<std::path::PathBuf> {
    let Some(unit_name) = unit_path.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let Some(parent) = unit_path.parent() else {
        return Vec::new();
    };
    let rels = dropin_rel_dirs(unit_name);
    const SYSTEM_UNIT_DIRS: [&str; 5] = [
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/usr/local/lib/systemd/system",
        "/run/systemd/system",
        "/etc/systemd/system",
    ];
    let tiers: Vec<&Path> = if SYSTEM_UNIT_DIRS.iter().any(|dir| parent == Path::new(dir)) {
        SYSTEM_UNIT_DIRS.iter().map(Path::new).collect()
    } else {
        vec![parent]
    };
    let mut dirs = Vec::with_capacity(tiers.len() * rels.len());
    for tier in tiers {
        for rel in &rels {
            dirs.push(tier.join(rel));
        }
    }
    dirs
}

fn load_unit_env_spec_with_dirs(
    unit_path: &Path,
    dropin_dirs: &[std::path::PathBuf],
) -> Result<UnitEnvSpec> {
    let mut spec = UnitEnvSpec::default();
    match std::fs::read_to_string(unit_path) {
        Ok(src) => parse_unit_env_spec_into(&src, &mut spec),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", unit_path.display()));
        }
    }
    let mut dropins: std::collections::BTreeMap<String, std::path::PathBuf> =
        std::collections::BTreeMap::new();
    for dir in dropin_dirs {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry =
                        entry.with_context(|| format!("reading drop-in entry in {}", dir.display()))?;
                    let name = entry.file_name();
                    let Some(name_str) = name.to_str() else {
                        continue;
                    };
                    if name_str.starts_with('.') || !name_str.ends_with(".conf") {
                        continue;
                    }
                    let path = entry.path();
                    std::fs::symlink_metadata(&path)
                        .with_context(|| format!("stat drop-in {}", path.display()))?;
                    match std::fs::metadata(&path) {
                        Ok(meta) if !meta.is_dir() => {
                            dropins.insert(name_str.to_owned(), path);
                        }
                        Ok(_) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => {
                            return Err(err)
                                .with_context(|| format!("inspecting drop-in {}", path.display()));
                        }
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("reading drop-in dir {}", dir.display()));
            }
        }
    }
    for (_, path) in dropins {
        let src = std::fs::read_to_string(&path)
            .with_context(|| format!("reading drop-in {}", path.display()))?;
        parse_unit_env_spec_into(&src, &mut spec);
    }
    Ok(spec)
}

#[cfg(test)]
fn load_unit_env_files_with_dirs(
    unit_path: &Path,
    dropin_dirs: &[std::path::PathBuf],
) -> Result<Vec<(std::path::PathBuf, bool)>> {
    Ok(load_unit_env_spec_with_dirs(unit_path, dropin_dirs)?.env_files)
}

fn load_unit_env_spec(unit_path: &Path) -> Result<UnitEnvSpec> {
    let dropin_dirs = default_dropin_dirs(unit_path);
    load_unit_env_spec_with_dirs(unit_path, &dropin_dirs)
}

struct EffectiveGatewayEnv {
    pairs: Vec<(String, String)>,
    has_storage_file: bool,
    has_gateway_file: bool,
    gateway_file_worm_mode: Option<String>,
}

fn load_effective_gateway_env(spec: &UnitEnvSpec) -> Result<EffectiveGatewayEnv> {
    let has_storage_file = spec.env_files.iter().any(|(p, _)| {
        p.file_name().and_then(|n| n.to_str()) == Some("storage.env")
            && std::fs::metadata(p).is_ok_and(|m| m.is_file())
    });
    let has_gateway_file = spec.env_files.iter().any(|(p, _)| {
        p.file_name().and_then(|n| n.to_str()) == Some("gateway.env")
            && std::fs::metadata(p).is_ok_and(|m| m.is_file())
    });
    let mut pairs = Vec::new();
    let mut gateway_file_pairs = Vec::new();
    for (path, optional) in &spec.env_files {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let parsed = parse_env_assignments(&content);
                if path.file_name().and_then(|n| n.to_str()) == Some("gateway.env") {
                    gateway_file_pairs.extend(parsed.clone());
                }
                pairs.extend(parsed);
            }
            Err(err) if !optional => {
                return Err(err)
                    .with_context(|| format!("reading required EnvironmentFile {}", path.display()));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("reading optional EnvironmentFile {}", path.display()));
            }
        }
    }
    for entry in &spec.unset_env {
        if let Some((k, v)) = entry.split_once('=') {
            if env_lookup(&pairs, k).as_deref() == Some(v) {
                pairs.retain(|(name, _)| name != k);
            }
        } else {
            pairs.retain(|(name, _)| name != entry);
        }
    }
    let gateway_file_worm_mode = env_lookup(&gateway_file_pairs, "WORM_MODE");
    Ok(EffectiveGatewayEnv {
        pairs,
        has_storage_file,
        has_gateway_file,
        gateway_file_worm_mode,
    })
}

fn gateway_has_worm_settings(
    gw: &EffectiveGatewayEnv,
    expected_mode: &str,
    expected_legal_hold: Option<&str>,
    expected_retention_days: Option<&str>,
    expected_s3: &ResolvedS3,
    gateway_s3: &ResolvedS3,
) -> bool {
    if !gw.has_storage_file || !gw.has_gateway_file {
        return false;
    }
    let has_storage_setting = STORAGE_ENV_KEYS
        .iter()
        .any(|k| env_lookup(&gw.pairs, k).is_some_and(|v| !v.is_empty()));
    if !has_storage_setting {
        return false;
    }
    if expected_s3 != gateway_s3 {
        return false;
    }
    if env_lookup(&gw.pairs, "WORM_MODE").as_deref() != Some(expected_mode) {
        return false;
    }
    if env_lookup(&gw.pairs, "WORM_LEGAL_HOLD_ENABLED").as_deref() != expected_legal_hold {
        return false;
    }
    let gw_retention = env_lookup(&gw.pairs, "WORM_RETENTION_DAYS");
    let gw_retention_nonempty = gw_retention.as_deref().filter(|v| !v.is_empty());
    if gw_retention_nonempty != expected_retention_days {
        return false;
    }
    true
}

fn check_db_gateway_startup_prereqs(gw: &EffectiveGatewayEnv) -> Result<()> {
    let is_db_backed = env_lookup(&gw.pairs, "DB_DSN").is_some_and(|v| !v.is_empty());
    if !is_db_backed {
        return Ok(());
    }
    let has_gateway_worm = gw.has_gateway_file && gw.gateway_file_worm_mode.is_some();
    let effective_worm = env_lookup(&gw.pairs, "WORM_MODE");
    if !has_gateway_worm || effective_worm.is_none() {
        bail!(
            "DB-backed setjoin-gateway unit/gateway.env must set explicit WORM_MODE (empty when disabled); run upgrade.sh refresh-gateway-env before activating"
        );
    }
    if effective_worm.as_deref().is_some_and(|v| !v.is_empty()) {
        let has_storage_setting = STORAGE_ENV_KEYS
            .iter()
            .any(|k| env_lookup(&gw.pairs, k).is_some_and(|v| !v.is_empty()));
        if !gw.has_storage_file || !has_storage_setting {
            bail!(
                "DB-backed setjoin-gateway enables WORM_MODE, but lacks storage.env and S3_*/MINIO_* settings; run upgrade.sh refresh-gateway-env before activating"
            );
        }
    }
    Ok(())
}

pub(crate) fn check_worm_gateway_ready(
    unit_path: &Path,
    explicit_config_env: Option<&Path>,
    default_config_env: &Path,
) -> Result<()> {
    let unit_spec = load_unit_env_spec(unit_path)?;
    let gw = load_effective_gateway_env(&unit_spec)?;
    check_db_gateway_startup_prereqs(&gw)?;
    let unit_cfg = unit_spec
        .env_files
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
    let host_yaml_path = env_lookup(&pairs, "SETJOIN_CONFIG").filter(|p| !p.is_empty());
    let mut cached_yaml: Option<(String, String)> = None;
    let need_yaml = config_worm_mode.is_none() || config_retention.is_none();
    let yaml_settings = if need_yaml && config_worm_mode.as_deref() != Some("") {
        match host_yaml_path.as_ref() {
            Some(yaml_path) => match std::fs::read_to_string(yaml_path) {
                Ok(yaml) => {
                    let parsed = yaml_worm_settings(&yaml).map_err(|reason| {
                        anyhow::anyhow!(
                            "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying WORM gateway readiness ({reason}); set WORM_MODE explicitly or run upgrade.sh refresh-gateway-env"
                        )
                    })?;
                    cached_yaml = Some((yaml_path.clone(), yaml));
                    Some(parsed)
                }
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
        let host_yaml_s3 = match host_yaml_path.as_ref() {
            Some(yaml_path) => {
                let yaml = match cached_yaml.as_ref() {
                    Some((cached_path, src)) if cached_path == yaml_path => src.clone(),
                    _ => std::fs::read_to_string(yaml_path).map_err(|err| {
                        anyhow::anyhow!(
                            "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying S3 storage readiness: {err}"
                        )
                    })?,
                };
                Some(yaml_s3_settings(&yaml).map_err(|reason| {
                    anyhow::anyhow!(
                        "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying S3 storage readiness ({reason}); run upgrade.sh refresh-gateway-env"
                    )
                })?)
            }
            None => None,
        };
        let host_s3 = resolve_s3_settings(&pairs, host_yaml_s3.as_ref()).map_err(|reason| {
            anyhow::anyhow!(
                "invalid host S3 storage settings while verifying WORM gateway readiness ({reason})"
            )
        })?;
        let gw_yaml_path = env_lookup(&gw.pairs, "SETJOIN_CONFIG").filter(|p| !p.is_empty());
        let gw_yaml_s3 = match gw_yaml_path.as_ref() {
            Some(yaml_path) if host_yaml_path.as_ref() == Some(yaml_path) => host_yaml_s3.clone(),
            Some(yaml_path) => {
                let yaml = std::fs::read_to_string(yaml_path).map_err(|err| {
                    anyhow::anyhow!(
                        "cannot inspect gateway SETJOIN_CONFIG ({yaml_path}) while verifying S3 storage readiness: {err}"
                    )
                })?;
                Some(yaml_s3_settings(&yaml).map_err(|reason| {
                    anyhow::anyhow!(
                        "cannot inspect gateway SETJOIN_CONFIG ({yaml_path}) while verifying S3 storage readiness ({reason}); run upgrade.sh refresh-gateway-env"
                    )
                })?)
            }
            None => None,
        };
        let gw_s3 = resolve_s3_settings(&gw.pairs, gw_yaml_s3.as_ref()).map_err(|reason| {
            anyhow::anyhow!(
                "invalid gateway S3 storage settings while verifying WORM gateway readiness ({reason})"
            )
        })?;
        if !gateway_has_worm_settings(
            &gw,
            &mode,
            expected_legal_hold.as_deref(),
            expected_retention_days.as_deref(),
            &host_s3,
            &gw_s3,
        ) {
            bail!(
                "WORM is enabled in host configuration, but setjoin-gateway unit/gateway.env lacks matching storage.env and WORM_MODE; run upgrade.sh refresh-gateway-env before activating"
            );
        }
    } else {
        let is_db_backed = env_lookup(&gw.pairs, "DB_DSN").is_some_and(|v| !v.is_empty());
        let gateway_has_empty_worm =
            gw.has_gateway_file && gw.gateway_file_worm_mode.as_deref() == Some("");
        let effective_worm_empty = env_lookup(&gw.pairs, "WORM_MODE").as_deref() == Some("");
        if is_db_backed && (!gateway_has_empty_worm || !effective_worm_empty) {
            bail!(
                "DB-backed setjoin-gateway unit/gateway.env must set explicit empty WORM_MODE=; run upgrade.sh refresh-gateway-env before activating"
            );
        }
    }
    let livekit_expected = [
        env_lookup(&pairs, "LIVEKIT_API_KEY").filter(|v| !v.is_empty()),
        env_lookup(&pairs, "LIVEKIT_API_SECRET").filter(|v| !v.is_empty()),
        env_lookup(&pairs, "LIVEKIT_URL").filter(|v| !v.is_empty()),
    ];
    if let [Some(lk_key), Some(lk_secret), Some(lk_url)] = livekit_expected {
        if env_lookup(&gw.pairs, "LIVEKIT_API_KEY").as_deref() != Some(lk_key.as_str())
            || env_lookup(&gw.pairs, "LIVEKIT_API_SECRET").as_deref() != Some(lk_secret.as_str())
            || env_lookup(&gw.pairs, "LIVEKIT_URL").as_deref() != Some(lk_url.as_str())
        {
            bail!(
                "LiveKit is configured in host configuration, but setjoin-gateway unit/federation.env lacks matching LIVEKIT_* settings; run upgrade.sh refresh-gateway-env before activating"
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
    use std::path::Path;
    use super::{
        check_worm_gateway_ready, default_dropin_dirs, load_unit_env_files_with_dirs,
        parse_env_assignments, yaml_worm_settings,
    };

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

        // Top-level flow YAML -> Err when mismatched or S3 bucket differs, Ok when both match
        std::fs::write(&yaml, "{ s3: { bucket: a }, worm: { mode: compliance } }\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        std::fs::write(&storage, "S3_BUCKET=a\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());
        std::fs::write(&storage, "S3_BUCKET=mailblobs\n").unwrap();

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

        // Empty EnvironmentFile= (including whitespace around =) clears earlier directives in systemd
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
        assert!(check_worm_gateway_ready(&cleared_unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &cleared_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile = {}\nEnvironmentFile =\n",
                storage.display(),
                gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&cleared_unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &cleared_unit,
            format!(
                "[Service]\nEnvironmentFile = -{}\nEnvironmentFile = {}\n",
                storage.display(),
                gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&cleared_unit, Some(&cfg), &stale_default).is_ok());

        // DB-backed non-WORM host requires explicit empty WORM_MODE= in gateway.env and empty effective value
        let fed = dir.path().join("federation.env");
        let override_env = dir.path().join("override.env");
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
        // Stale non-empty WORM_MODE in gateway.env is rejected when host disables WORM
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        // Empty WORM_MODE= in another env file does not satisfy gateway.env requirement
        std::fs::write(&fed, "DB_DSN=postgres://app@localhost/mail\nWORM_MODE=\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());
        // Explicit WORM_MODE= in gateway.env succeeds when effective value stays empty
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_ok());
        // Later EnvironmentFile overriding WORM_MODE to non-empty is rejected
        std::fs::write(&override_env, "WORM_MODE=compliance\n").unwrap();
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\nEnvironmentFile={}\n",
                fed.display(),
                gw.display(),
                override_env.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, None, &stale_default).is_err());

        // Systemd drop-in appending WORM_MODE=compliance after gateway.env clears it fails preflight
        let dropin_dir = dir.path().join("setjoin-gateway.service.d");
        std::fs::create_dir_all(&dropin_dir).unwrap();
        let dropin_unit = dir.path().join("setjoin-gateway.service");
        std::fs::write(
            &dropin_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                fed.display(),
                gw.display()
            ),
        )
        .unwrap();
        std::fs::write(
            dropin_dir.join("10-override.conf"),
            format!("[Service]\nEnvironmentFile={}\n", override_env.display()),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&dropin_unit, None, &stale_default).is_err());
        std::fs::remove_file(dropin_dir.join("10-override.conf")).unwrap();
        assert!(check_worm_gateway_ready(&dropin_unit, None, &stale_default).is_ok());

        // Escaped double-quoted YAML key/value enables WORM preflight; empty storage.env fails even when WORM_MODE matches
        std::fs::write(
            &yaml,
            "\"w\\u006frm\":\n  \"m\\x6fde\": \"compli\\u0061nce\"\n",
        )
        .unwrap();
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\n", yaml.display())).unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                storage.display(),
                gw.display()
            ),
        )
        .unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        std::fs::write(&storage, "# empty storage env\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&storage, "S3_BUCKET=mailblobs\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());

        // Drop-in EnvironmentFile= reset clears base unit directives
        std::fs::create_dir_all(&dropin_dir).unwrap();
        std::fs::write(
            &dropin_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                storage.display(),
                gw.display()
            ),
        )
        .unwrap();
        std::fs::write(dropin_dir.join("20-reset.conf"), "[Service]\nEnvironmentFile=\n").unwrap();
        assert!(check_worm_gateway_ready(&dropin_unit, Some(&cfg), &stale_default).is_err());

        // UTF-8 BOM at start of YAML does not hide top-level worm key
        let bom_worm = yaml_worm_settings("\u{feff}worm:\n  mode: compliance\n").unwrap();
        assert_eq!(bom_worm.mode.as_deref(), Some("compliance"));

        // LiveKit configured in config.env must match gateway federation.env
        let lk_dir = dir.path().join("livekit");
        std::fs::create_dir_all(&lk_dir).unwrap();
        let lk_cfg = lk_dir.join("config.env");
        let lk_fed = lk_dir.join("federation.env");
        let lk_gw = lk_dir.join("gateway.env");
        let lk_unit = lk_dir.join("gw.service");
        std::fs::write(
            &lk_cfg,
            "LIVEKIT_API_KEY=setjoin\nLIVEKIT_API_SECRET=sec\nLIVEKIT_URL=ws://127.0.0.1:7880\n",
        )
        .unwrap();
        std::fs::write(&lk_gw, "GATEWAY_ENABLED=true\nWORM_MODE=\n").unwrap();
        std::fs::write(&lk_fed, "DB_DSN=postgres://app@localhost/mail\n").unwrap();
        std::fs::write(
            &lk_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                lk_fed.display(),
                lk_gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&lk_unit, Some(&lk_cfg), &stale_default).is_err());
        std::fs::write(
            &lk_fed,
            "DB_DSN=postgres://app@localhost/mail\nLIVEKIT_API_KEY=setjoin\nLIVEKIT_API_SECRET=sec\nLIVEKIT_URL=ws://127.0.0.1:7880\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&lk_unit, Some(&lk_cfg), &stale_default).is_ok());

        // Multi-tier drop-in precedence: /run tier applies under /etc base unit, /etc overrides same name
        let tier_root = dir.path().join("tiers");
        let tier_lib = tier_root.join("usr-lib/setjoin-gateway.service.d");
        let tier_run = tier_root.join("run/setjoin-gateway.service.d");
        let tier_etc = tier_root.join("etc/setjoin-gateway.service.d");
        std::fs::create_dir_all(&tier_lib).unwrap();
        std::fs::create_dir_all(&tier_run).unwrap();
        std::fs::create_dir_all(&tier_etc).unwrap();
        let tier_unit = tier_root.join("etc/setjoin-gateway.service");
        let f1 = dir.path().join("tier1.env");
        let f2 = dir.path().join("tier2.env");
        let f3 = dir.path().join("tier3.env");
        std::fs::write(&tier_unit, format!("[Service]\nEnvironmentFile={}\n", f1.display())).unwrap();
        std::fs::write(&tier_lib.join("10-a.conf"), format!("[Service]\nEnvironmentFile={}\n", f2.display())).unwrap();
        std::fs::write(&tier_run.join("10-a.conf"), format!("[Service]\nEnvironmentFile={}\n", f3.display())).unwrap();
        std::fs::write(&tier_etc.join("20-b.conf"), format!("[Service]\nEnvironmentFile={}\n", f2.display())).unwrap();
        let tier_dirs = default_dropin_dirs(Path::new("/etc/systemd/system/setjoin-gateway.service"));
        assert!(tier_dirs.contains(&Path::new("/run/systemd/system/setjoin-gateway.service.d").to_path_buf()));
        assert!(tier_dirs.contains(&Path::new("/usr/lib/systemd/system/setjoin-gateway.service.d").to_path_buf()));
        let merged = load_unit_env_files_with_dirs(&tier_unit, &[tier_lib, tier_run.clone(), tier_etc.clone()]).unwrap();
        assert_eq!(merged, vec![(f1, false), (f3, false), (f2, false)]);

        #[cfg(unix)]
        {
            let loop_dir = dir.path().join("loop.service.d");
            std::fs::create_dir_all(&loop_dir).unwrap();
            let loop_unit = dir.path().join("loop.service");
            std::fs::write(&loop_unit, "[Service]\n").unwrap();
            std::os::unix::fs::symlink(loop_dir.join("b.conf"), loop_dir.join("a.conf")).unwrap();
            std::os::unix::fs::symlink(loop_dir.join("a.conf"), loop_dir.join("b.conf")).unwrap();
            assert!(load_unit_env_files_with_dirs(&loop_unit, &[loop_dir]).is_err());
        }

        // Missing required EnvironmentFile= fails preflight even when host has no config.env
        let missing_req_unit = dir.path().join("missing-req.service");
        let missing_gw = dir.path().join("does-not-exist-gateway.env");
        let missing_default = dir.path().join("no-such-dir/config.env");
        std::fs::write(
            &missing_req_unit,
            format!("[Service]\nEnvironmentFile={}\n", missing_gw.display()),
        )
        .unwrap();
        let err_default =
            check_worm_gateway_ready(&missing_req_unit, None, &missing_default).unwrap_err();
        assert!(err_default.to_string().contains("reading required EnvironmentFile"));
        let err_explicit = check_worm_gateway_ready(
            &missing_req_unit,
            Some(&missing_default),
            &missing_default,
        )
        .unwrap_err();
        assert!(err_explicit.to_string().contains("reading required EnvironmentFile"));

        // Drop-in UnsetEnvironment= removes LiveKit after EnvironmentFile=, and empty UnsetEnvironment= resets it
        let unset_dir = dir.path().join("unset.service.d");
        std::fs::create_dir_all(&unset_dir).unwrap();
        let unset_unit = dir.path().join("unset.service");
        std::fs::write(
            &unset_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                lk_fed.display(),
                lk_gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unset_unit, Some(&lk_cfg), &stale_default).is_ok());
        std::fs::write(
            unset_dir.join("10-unset.conf"),
            "[Service]\nUnsetEnvironment=LIVEKIT_API_SECRET\n",
        )
        .unwrap();
        let unset_lk_err =
            check_worm_gateway_ready(&unset_unit, Some(&lk_cfg), &stale_default).unwrap_err();
        assert!(unset_lk_err.to_string().contains("LIVEKIT_*"));
        std::fs::write(unset_dir.join("20-reset.conf"), "[Service]\nUnsetEnvironment=\n").unwrap();
        assert!(check_worm_gateway_ready(&unset_unit, Some(&lk_cfg), &stale_default).is_ok());

        // Stale S3 settings in storage.env fail preflight even when WORM_MODE matches
        std::fs::write(
            &cfg,
            "WORM_MODE=compliance\nS3_ENDPOINT=https://s3.new.test\nS3_BUCKET=new-blobs\nS3_SECRET_KEY=new-secret\n",
        )
        .unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        std::fs::write(
            &storage,
            "S3_ENDPOINT=https://s3.old.test\nS3_BUCKET=new-blobs\nS3_SECRET_KEY=new-secret\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &storage,
            "S3_ENDPOINT=https://s3.new.test\nS3_BUCKET=new-blobs\nS3_SECRET_KEY=new-secret\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(&cfg, "WORM_MODE=compliance\n").unwrap();
        std::fs::write(&storage, "S3_BUCKET=mailblobs\n").unwrap();

        // Missing config.env still enforces DB-backed gateway startup prereqs (WORM_MODE + storage.env)
        let nocfg_dir = dir.path().join("no-cfg-db");
        std::fs::create_dir_all(&nocfg_dir).unwrap();
        let nocfg_fed = nocfg_dir.join("federation.env");
        let nocfg_gw = nocfg_dir.join("gateway.env");
        let nocfg_storage = nocfg_dir.join("storage.env");
        let nocfg_unit = nocfg_dir.join("nocfg.service");
        std::fs::write(&nocfg_fed, "DB_DSN=postgres://app@localhost/mail\n").unwrap();
        std::fs::write(&nocfg_gw, "GATEWAY_ENABLED=true\n").unwrap();
        std::fs::write(
            &nocfg_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                nocfg_fed.display(),
                nocfg_storage.display(),
                nocfg_gw.display()
            ),
        )
        .unwrap();
        let err_nocfg = check_worm_gateway_ready(&nocfg_unit, None, &missing_default).unwrap_err();
        assert!(err_nocfg.to_string().contains("WORM_MODE"));
        let err_nocfg_explicit =
            check_worm_gateway_ready(&nocfg_unit, Some(&missing_default), &missing_default)
                .unwrap_err();
        assert!(err_nocfg_explicit.to_string().contains("WORM_MODE"));
        std::fs::write(&nocfg_gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&nocfg_unit, None, &missing_default).is_err());
        std::fs::write(&nocfg_storage, "S3_BUCKET=mailblobs\n").unwrap();
        assert!(check_worm_gateway_ready(&nocfg_unit, None, &missing_default).is_ok());
        std::fs::write(&nocfg_gw, "GATEWAY_ENABLED=true\nWORM_MODE=\n").unwrap();
        assert!(check_worm_gateway_ready(&nocfg_unit, None, &missing_default).is_ok());

        // Drop-in section filtering, even/odd trailing backslashes, and prefix/type drop-ins
        let db_unset_dir = dir.path().join("db-unset");
        let db_unset_type = db_unset_dir.join("service.d");
        let db_unset_prefix = db_unset_dir.join("setjoin-.service.d");
        let db_unset_dropin = db_unset_dir.join("setjoin-gateway.service.d");
        std::fs::create_dir_all(&db_unset_type).unwrap();
        std::fs::create_dir_all(&db_unset_prefix).unwrap();
        std::fs::create_dir_all(&db_unset_dropin).unwrap();
        let db_unset_cfg = db_unset_dir.join("config.env");
        let db_unset_fed = db_unset_dir.join("federation.env");
        let db_unset_gw = db_unset_dir.join("gateway.env");
        let db_unset_unit = db_unset_dir.join("setjoin-gateway.service");
        std::fs::write(&db_unset_cfg, "HOSTNAME=mail.test\n").unwrap();
        std::fs::write(&db_unset_fed, "DB_DSN=postgres://app@localhost/mail\n").unwrap();
        std::fs::write(&db_unset_gw, "GATEWAY_ENABLED=true\nWORM_MODE=\n").unwrap();
        std::fs::write(
            &db_unset_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                db_unset_fed.display(),
                db_unset_gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&db_unset_unit, None, &stale_default).is_ok());
        std::fs::write(
            db_unset_dropin.join("10-install.conf"),
            "[Install]\nUnsetEnvironment=WORM_MODE\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&db_unset_unit, None, &stale_default).is_ok());
        std::fs::write(
            db_unset_type.join("12-type.conf"),
            "[Service]\nUnsetEnvironment=WORM_MODE\n",
        )
        .unwrap();
        let err_type = check_worm_gateway_ready(&db_unset_unit, None, &stale_default).unwrap_err();
        assert!(err_type.to_string().contains("WORM_MODE"));
        std::fs::remove_file(db_unset_type.join("12-type.conf")).unwrap();
        std::fs::write(
            db_unset_prefix.join("15-prefix.conf"),
            "[Service]\nUnsetEnvironment=WORM_MODE\n",
        )
        .unwrap();
        let err_prefix =
            check_worm_gateway_ready(&db_unset_unit, None, &stale_default).unwrap_err();
        assert!(err_prefix.to_string().contains("WORM_MODE"));
        std::fs::remove_file(db_unset_prefix.join("15-prefix.conf")).unwrap();
        std::fs::write(
            db_unset_dropin.join("20-unset-worm.conf"),
            "[Service]\nDescription=trailing literal \\\\\nUnsetEnvironment=FOO \\\n# comment inside continuation\n  WORM_MODE\n",
        )
        .unwrap();
        let unset_worm_err =
            check_worm_gateway_ready(&db_unset_unit, None, &stale_default).unwrap_err();
        assert!(unset_worm_err.to_string().contains("WORM_MODE"));
        let sys_dirs = default_dropin_dirs(Path::new("/etc/systemd/system/setjoin-gateway.service"));
        assert!(sys_dirs.contains(&Path::new("/lib/systemd/system/service.d").to_path_buf()));
        assert!(sys_dirs.contains(&Path::new("/etc/systemd/system/setjoin-.service.d").to_path_buf()));
    }
}
