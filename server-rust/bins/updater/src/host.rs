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

fn yaml_scalar_is_null(val: &str) -> bool {
    val.is_empty() || matches!(val, "null" | "Null" | "NULL" | "~")
}

fn strip_yaml_underscores(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('_') || s.ends_with('_') || s.contains("__") {
        return None;
    }
    let hex_prefixed = s.starts_with("0x")
        || s.starts_with("0X")
        || s.starts_with("+0x")
        || s.starts_with("+0X")
        || s.starts_with("-0x")
        || s.starts_with("-0X");
    let bytes = s.as_bytes();
    for (idx, &ch) in bytes.iter().enumerate() {
        if ch == b'_' {
            let prev = bytes[idx - 1];
            let next = bytes[idx + 1];
            if !prev.is_ascii_alphanumeric() && prev != b'_' {
                return None;
            }
            if !next.is_ascii_hexdigit() {
                return None;
            }
            if !hex_prefixed && (matches!(prev, b'e' | b'E') || matches!(next, b'e' | b'E')) {
                return None;
            }
        }
    }
    Some(s.replace('_', ""))
}

fn parse_go_hex_float64(s: &str) -> Option<f64> {
    let (neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    let rest = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X"))?;
    let p_idx = rest.find(['p', 'P'])?;
    let mant_raw = &rest[..p_idx];
    let exp_raw = &rest[p_idx + 1..];
    let (exp_neg, exp_digits) = if let Some(r) = exp_raw.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = exp_raw.strip_prefix('+') {
        (false, r)
    } else {
        (false, exp_raw)
    };
    if exp_digits.is_empty()
        || exp_digits.starts_with('_')
        || exp_digits.ends_with('_')
        || exp_digits.contains("__")
        || !exp_digits
            .bytes()
            .all(|b| b == b'_' || b.is_ascii_digit())
    {
        return None;
    }
    let exp_mag: i32 = exp_digits.replace('_', "").parse().ok()?;
    let exp_p = if exp_neg { -exp_mag } else { exp_mag };
    let valid_hex_part = |part: &str, allow_leading: bool| -> bool {
        let s = if allow_leading {
            part.strip_prefix('_').unwrap_or(part)
        } else {
            part
        };
        !s.is_empty()
            && !s.starts_with('_')
            && !s.ends_with('_')
            && !s.contains("__")
            && s.bytes().all(|b| b == b'_' || b.is_ascii_hexdigit())
    };
    let (int_hex, frac_hex) = match mant_raw.split_once('.') {
        Some((i, f)) => {
            if !i.is_empty() && !valid_hex_part(i, true) {
                return None;
            }
            if !f.is_empty() && !valid_hex_part(f, false) {
                return None;
            }
            (i, f)
        }
        None => {
            if !valid_hex_part(mant_raw, true) {
                return None;
            }
            (mant_raw, "")
        }
    };
    let int_clean = int_hex.replace('_', "");
    let frac_clean = frac_hex.replace('_', "");
    if int_clean.is_empty() && frac_clean.is_empty() {
        return None;
    }
    let mut val = 0.0_f64;
    for b in int_clean.bytes() {
        val = val * 16.0 + (b as char).to_digit(16)? as f64;
    }
    let mut frac_scale = 1.0_f64 / 16.0;
    for b in frac_clean.bytes() {
        val += ((b as char).to_digit(16)? as f64) * frac_scale;
        frac_scale /= 16.0;
    }
    let scaled = val * 2.0_f64.powi(exp_p);
    let result = if neg { -scaled } else { scaled };
    result.is_finite().then_some(result)
}

fn parse_go_float64(raw: &str) -> Option<f64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    if unsigned.starts_with("0x") || unsigned.starts_with("0X") {
        return parse_go_hex_float64(s);
    }
    let cleaned = strip_yaml_underscores(s)?;
    if unsigned.starts_with("0o")
        || unsigned.starts_with("0O")
        || unsigned.starts_with("0b")
        || unsigned.starts_with("0B")
    {
        return None;
    }
    let v: f64 = cleaned.parse().ok()?;
    v.is_finite().then_some(v)
}

fn valid_dec_underscores(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut saw_digit = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            if i == 0 || i + 1 == bytes.len() || bytes[i - 1] == b'_' || bytes[i + 1] == b'_' {
                return false;
            }
        } else if b.is_ascii_digit() {
            saw_digit = true;
        } else {
            return false;
        }
    }
    saw_digit
}

fn parse_yaml_float(raw: &str) -> Option<f64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains('_') {
        let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
        let mantissa = match unsigned.find(['e', 'E']) {
            Some(idx) => {
                let exp_raw = &unsigned[idx + 1..];
                let exp = exp_raw.strip_prefix(['+', '-']).unwrap_or(exp_raw);
                if !valid_dec_underscores(exp) {
                    return None;
                }
                &unsigned[..idx]
            }
            None => unsigned,
        };
        let int_ok = |part: &str| {
            part == "0"
                || (part.as_bytes().first().is_some_and(|b| matches!(b, b'1'..=b'9'))
                    && valid_dec_underscores(part))
        };
        match mantissa.split_once('.') {
            Some((int_part, frac_part)) => {
                if int_part.is_empty() && frac_part.is_empty() {
                    return None;
                }
                if !int_part.is_empty() && !int_ok(int_part) {
                    return None;
                }
                if !frac_part.is_empty() && !valid_dec_underscores(frac_part) {
                    return None;
                }
            }
            None => {
                if !int_ok(mantissa) {
                    return None;
                }
            }
        }
        let v: f64 = s.replace('_', "").parse().ok()?;
        return v.is_finite().then_some(v);
    }
    let v: f64 = s.parse().ok()?;
    v.is_finite().then_some(v)
}

fn normalize_retention_days(raw: &str) -> String {
    if let Some(v) = YamlParser::parse_yaml_int(raw) {
        return v.to_string();
    }
    if let Some(v) = parse_yaml_float(raw) {
        if v.fract() == 0.0 && v >= (i64::MIN as f64) && v < 9_223_372_036_854_775_808.0 {
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
    secure: Option<(String, bool)>,
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

fn yaml_koanf_bool(raw: &str, quoted: bool) -> bool {
    koanf_bool(raw)
        || (!quoted
            && (YamlParser::parse_yaml_int(raw) == Some(1)
                || parse_yaml_float(raw).is_some_and(|v| v == 1.0)))
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

#[derive(Clone, Debug)]
enum YamlNode {
    Null,
    Scalar(String, bool),
    Seq(Vec<YamlNode>),
    Map(Vec<(String, YamlNode)>),
}

fn map_insert(entries: &mut Vec<(String, YamlNode)>, key: String, val: YamlNode) {
    if let Some((_, existing)) = entries.iter_mut().find(|(k, _)| k == &key) {
        *existing = val;
    } else {
        entries.push((key, val));
    }
}

fn map_lookup<'a>(entries: &'a [(String, YamlNode)], key: &str) -> Option<&'a YamlNode> {
    entries.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
}

struct YamlParser<'a> {
    s: &'a str,
    b: &'a [u8],
    n: usize,
    i: usize,
    anchors: std::collections::HashMap<String, YamlNode>,
}

impl<'a> YamlParser<'a> {
    fn new(s: &'a str) -> Self {
        let b = s.as_bytes();
        Self {
            s,
            b,
            n: b.len(),
            i: 0,
            anchors: std::collections::HashMap::new(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_hws(&mut self) {
        while let Some(b' ' | b'\t') = self.peek() {
            self.i += 1;
        }
    }

    fn at_doc_marker_at(&self, pos: usize) -> bool {
        let rest = &self.b[pos..];
        let is_marker = rest.starts_with(b"---") || rest.starts_with(b"...");
        is_marker
            && rest
                .get(3)
                .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n' | b'#'))
    }

    fn skip_comment_eol(&mut self) -> Result<(), &'static str> {
        self.skip_hws();
        if self.peek() == Some(b'#') {
            while self.i < self.n && self.b[self.i] != b'\n' {
                self.i += 1;
            }
        }
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.i += 1;
                Ok(())
            }
            Some(_) => Err("unexpected trailing YAML content"),
        }
    }

    fn skip_blank_and_comments(&mut self) {
        while self.i < self.n {
            let line_start = self.i;
            self.skip_hws();
            if self.i >= self.n {
                break;
            }
            match self.b[self.i] {
                b'\n' => self.i += 1,
                b'#' => {
                    while self.i < self.n && self.b[self.i] != b'\n' {
                        self.i += 1;
                    }
                    if self.i < self.n {
                        self.i += 1;
                    }
                }
                _ if self.i == line_start && self.at_doc_marker_at(self.i) => {
                    while self.i < self.n && self.b[self.i] != b'\n' {
                        self.i += 1;
                    }
                    if self.i < self.n {
                        self.i += 1;
                    }
                }
                _ => {
                    self.i = line_start;
                    break;
                }
            }
        }
    }

    fn skip_flow_ws(&mut self) {
        while self.i < self.n {
            match self.b[self.i] {
                b' ' | b'\t' | b'\n' => self.i += 1,
                b'#' if self.i == 0 || matches!(self.b[self.i - 1], b' ' | b'\t' | b'\n') => {
                    while self.i < self.n && self.b[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn current_line_indent(&self) -> usize {
        let mut ind = 0usize;
        while self.i + ind < self.n && self.b[self.i + ind] == b' ' {
            ind += 1;
        }
        ind
    }

    fn is_prop_char(b: u8) -> bool {
        !matches!(
            b,
            b' ' | b'\t' | b'\n' | b',' | b'[' | b']' | b'{' | b'}'
        )
    }

    fn read_indicator_name(&mut self, prefix: u8) -> Result<String, &'static str> {
        if self.peek() != Some(prefix) {
            return Err("expected YAML indicator");
        }
        self.i += 1;
        let start = self.i;
        while self.i < self.n && Self::is_prop_char(self.b[self.i]) {
            self.i += 1;
        }
        if self.i == start {
            return Err("empty YAML anchor/alias/tag");
        }
        Ok(self.s[start..self.i].to_owned())
    }

    fn read_tag(&mut self) -> Result<String, &'static str> {
        if self.peek() != Some(b'!') {
            return Err("expected YAML tag");
        }
        self.i += 1;
        if self.peek() == Some(b'<') {
            self.i += 1;
            let uri_start = self.i;
            while self.i < self.n && !matches!(self.b[self.i], b'>' | b' ' | b'\t' | b'\n') {
                self.i += 1;
            }
            if self.peek() != Some(b'>') {
                return Err("unterminated verbatim YAML tag");
            }
            let uri = &self.s[uri_start..self.i];
            self.i += 1;
            if let Some(short) = uri.strip_prefix("tag:yaml.org,2002:") {
                if !short.is_empty() {
                    return Ok(format!("!{short}"));
                }
            }
            return Ok(format!("<{uri}>"));
        }
        let start = self.i;
        while self.i < self.n && Self::is_prop_char(self.b[self.i]) {
            self.i += 1;
        }
        if self.i == start {
            return Err("empty YAML anchor/alias/tag");
        }
        Ok(self.s[start..self.i].to_owned())
    }

    fn parse_node_props(&mut self) -> Result<(Option<String>, Option<String>), &'static str> {
        let mut tag: Option<String> = None;
        let mut anchor: Option<String> = None;
        loop {
            self.skip_hws();
            match self.peek() {
                Some(b'!') if tag.is_none() => {
                    tag = Some(self.read_tag()?);
                }
                Some(b'&') if anchor.is_none() => {
                    anchor = Some(self.read_indicator_name(b'&')?);
                }
                _ => break,
            }
        }
        self.skip_hws();
        Ok((tag, anchor))
    }

    fn parse_yaml_int(raw: &str) -> Option<i64> {
        let cleaned = strip_yaml_underscores(raw)?;
        let (neg, unsigned) = if let Some(rest) = cleaned.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = cleaned.strip_prefix('+') {
            (false, rest)
        } else {
            (false, cleaned.as_str())
        };
        if let Some(hex) = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")) {
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let v = i64::from_str_radix(hex, 16).ok()?;
            return neg.then(|| v.checked_neg()).unwrap_or(Some(v));
        }
        if let Some(oct) = unsigned.strip_prefix("0o").or_else(|| unsigned.strip_prefix("0O")) {
            if oct.is_empty() || !oct.bytes().all(|b| matches!(b, b'0'..=b'7')) {
                return None;
            }
            let v = i64::from_str_radix(oct, 8).ok()?;
            return neg.then(|| v.checked_neg()).unwrap_or(Some(v));
        }
        if let Some(bin) = unsigned.strip_prefix("0b").or_else(|| unsigned.strip_prefix("0B")) {
            if bin.is_empty() || !bin.bytes().all(|b| matches!(b, b'0' | b'1')) {
                return None;
            }
            let v = i64::from_str_radix(bin, 2).ok()?;
            return neg.then(|| v.checked_neg()).unwrap_or(Some(v));
        }
        if unsigned.starts_with('0') && unsigned.len() > 1 {
            let digits = &unsigned[1..];
            if !digits.bytes().all(|b| matches!(b, b'0'..=b'7')) {
                return None;
            }
            let v = i64::from_str_radix(digits, 8).ok()?;
            return neg.then(|| v.checked_neg()).unwrap_or(Some(v));
        }
        cleaned.parse::<i64>().ok()
    }

    fn parse_legacy_yaml_octal(raw: &str) -> Option<i64> {
        let cleaned = strip_yaml_underscores(raw)?;
        let (neg, unsigned) = if let Some(rest) = cleaned.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = cleaned.strip_prefix('+') {
            (false, rest)
        } else {
            (false, cleaned.as_str())
        };
        if unsigned.starts_with('0') && unsigned.len() > 1 {
            let digits = &unsigned[1..];
            if !digits.bytes().all(|b| matches!(b, b'0'..=b'7')) {
                return None;
            }
            let v = i64::from_str_radix(digits, 8).ok()?;
            return neg.then(|| v.checked_neg()).unwrap_or(Some(v));
        }
        None
    }

    fn apply_tag(tag: Option<&str>, node: YamlNode) -> Result<YamlNode, &'static str> {
        let Some(tag_val) = tag else {
            return Ok(node);
        };
        match tag_val {
            "!str" => match node {
                YamlNode::Null => Ok(YamlNode::Scalar(String::new(), true)),
                YamlNode::Scalar(s, _) => Ok(YamlNode::Scalar(s, true)),
                _ => Err("YAML !!str tag requires scalar"),
            },
            "!null" => match node {
                YamlNode::Null => Ok(YamlNode::Null),
                YamlNode::Scalar(ref s, _) if yaml_scalar_is_null(s) => Ok(YamlNode::Null),
                _ => Err("invalid YAML !!null value"),
            },
            "!bool" => match node {
                YamlNode::Scalar(ref s, _) => match s.as_str() {
                    "true" | "True" | "TRUE" => Ok(YamlNode::Scalar("true".into(), false)),
                    "false" | "False" | "FALSE" => Ok(YamlNode::Scalar("false".into(), false)),
                    _ => Err("invalid YAML !!bool value"),
                },
                _ => Err("invalid YAML !!bool value"),
            },
            "!int" => match node {
                YamlNode::Scalar(ref s, _) => {
                    if matches!(
                        s.as_str(),
                        "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
                    ) {
                        return Err("cannot coerce bool to YAML !!int");
                    }
                    let parsed = Self::parse_yaml_int(s).ok_or("invalid YAML !!int value")?;
                    Ok(YamlNode::Scalar(parsed.to_string(), false))
                }
                _ => Err("invalid YAML !!int value"),
            },
            "!float" => match node {
                YamlNode::Scalar(ref s, _) => {
                    if matches!(
                        s.as_str(),
                        "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
                    ) {
                        return Err("cannot coerce bool to YAML !!float");
                    }
                    if let Some(iv) = Self::parse_legacy_yaml_octal(s) {
                        return Ok(YamlNode::Scalar((iv as f64).to_string(), false));
                    }
                    let v = parse_yaml_float(s).ok_or("invalid YAML !!float value")?;
                    Ok(YamlNode::Scalar(v.to_string(), false))
                }
                _ => Err("invalid YAML !!float value"),
            },
            "!map" => match node {
                YamlNode::Null => Ok(YamlNode::Map(Vec::new())),
                YamlNode::Map(_) => Ok(node),
                _ => Err("YAML !!map requires a mapping"),
            },
            "!seq" => match node {
                YamlNode::Null => Ok(YamlNode::Seq(Vec::new())),
                YamlNode::Seq(_) => Ok(node),
                _ => Err("YAML !!seq requires a sequence"),
            },
            _ => Err("unsupported YAML tag"),
        }
    }

    fn parse_dquote(&mut self, multiline: bool) -> Result<String, &'static str> {
        self.i += 1; // '"'
        let start = self.i;
        while self.i < self.n {
            let ch = self.b[self.i];
            if ch == b'\\' {
                self.i += 1;
                if self.i < self.n {
                    let step = self.s[self.i..].chars().next().map_or(1, char::len_utf8);
                    self.i += step;
                }
                continue;
            }
            if ch == b'\n' && !multiline {
                return Err("unterminated double-quoted YAML scalar");
            }
            if ch == b'"' {
                let inner = &self.s[start..self.i];
                self.i += 1;
                return decode_yaml_double_quoted(inner);
            }
            self.i += 1;
        }
        Err("unterminated double-quoted YAML scalar")
    }

    fn parse_squote(&mut self, multiline: bool) -> Result<String, &'static str> {
        self.i += 1; // '\''
        let start = self.i;
        while self.i < self.n {
            let ch = self.b[self.i];
            if ch == b'\'' {
                if self.i + 1 < self.n && self.b[self.i + 1] == b'\'' {
                    self.i += 2;
                    continue;
                }
                let inner = &self.s[start..self.i];
                self.i += 1;
                return Ok(inner.replace("''", "'"));
            }
            if ch == b'\n' && !multiline {
                return Err("unterminated single-quoted YAML scalar");
            }
            self.i += 1;
        }
        Err("unterminated single-quoted YAML scalar")
    }

    fn parse_plain_token(&mut self, in_flow: bool) -> Result<(String, bool), &'static str> {
        let start = self.i;
        let mut end = start;
        while self.i < self.n {
            let ch = self.b[self.i];
            if ch == b'\n' {
                break;
            }
            if in_flow && matches!(ch, b',' | b'}' | b']') {
                break;
            }
            if ch == b':'
                && self
                    .b
                    .get(self.i + 1)
                    .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n') || (in_flow && matches!(c, b',' | b'}' | b']')))
            {
                break;
            }
            if ch == b'#' && (self.i == start || matches!(self.b[self.i - 1], b' ' | b'\t')) {
                break;
            }
            let step = self.s[self.i..].chars().next().map_or(1, char::len_utf8);
            self.i += step;
            end = self.i;
        }
        let raw = self.s[start..end].trim();
        let is_null = yaml_scalar_is_null(raw);
        if !in_flow {
            self.skip_comment_eol()?;
        }
        Ok((raw.to_owned(), is_null))
    }

    fn parse_key(&mut self, in_flow: bool) -> Result<(String, bool), &'static str> {
        let (tag, anchor) = self.parse_node_props()?;
        if anchor.is_some() {
            return Err("YAML anchor on mapping key unsupported");
        }
        let (raw_key, quoted) = match self.peek() {
            Some(b'"') => (self.parse_dquote(in_flow)?, true),
            Some(b'\'') => (self.parse_squote(in_flow)?, true),
            _ => {
                let start = self.i;
                let mut found = None;
                while self.i < self.n {
                    let ch = self.b[self.i];
                    if ch == b'\n' || (in_flow && matches!(ch, b',' | b'}' | b']')) {
                        break;
                    }
                    if ch == b':'
                        && self.b.get(self.i + 1).is_none_or(|c| {
                            matches!(c, b' ' | b'\t' | b'\n')
                                || (in_flow && matches!(c, b',' | b'}' | b']'))
                        })
                    {
                        found = Some(self.s[start..self.i].trim().to_owned());
                        break;
                    }
                    let step = self.s[self.i..].chars().next().map_or(1, char::len_utf8);
                    self.i += step;
                }
                let k = found.ok_or("expected ':' after YAML mapping key")?;
                (k, false)
            }
        };
        if let Some(ref t) = tag {
            if t != "!str" {
                return Err("unsupported YAML key tag");
            }
        }
        self.skip_hws();
        if self.peek() != Some(b':') {
            return Err("expected ':' after YAML mapping key");
        }
        let allow_merge = !quoted && tag.is_none();
        Ok((raw_key, allow_merge))
    }

    fn starts_block_mapping_entry(&self) -> bool {
        let mut p = self.i;
        while p < self.n && matches!(self.b[p], b' ' | b'\t') {
            p += 1;
        }
        if p >= self.n {
            return false;
        }
        match self.b[p] {
            b'-' if self
                .b
                .get(p + 1)
                .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n')) =>
            {
                false
            }
            b'{' | b'[' | b'*' | b'#' => false,
            b'"' => {
                p += 1;
                while p < self.n && self.b[p] != b'\n' {
                    if self.b[p] == b'\\' {
                        p += 2;
                        continue;
                    }
                    if self.b[p] == b'"' {
                        p += 1;
                        while p < self.n && matches!(self.b[p], b' ' | b'\t') {
                            p += 1;
                        }
                        return self.b.get(p) == Some(&b':')
                            && self
                                .b
                                .get(p + 1)
                                .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n'));
                    }
                    p += 1;
                }
                false
            }
            b'\'' => {
                p += 1;
                while p < self.n && self.b[p] != b'\n' {
                    if self.b[p] == b'\'' {
                        if self.b.get(p + 1) == Some(&b'\'') {
                            p += 2;
                            continue;
                        }
                        p += 1;
                        while p < self.n && matches!(self.b[p], b' ' | b'\t') {
                            p += 1;
                        }
                        return self.b.get(p) == Some(&b':')
                            && self
                                .b
                                .get(p + 1)
                                .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n'));
                    }
                    p += 1;
                }
                false
            }
            _ => {
                while p < self.n && self.b[p] != b'\n' {
                    if self.b[p] == b':'
                        && self
                            .b
                            .get(p + 1)
                            .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n'))
                    {
                        return true;
                    }
                    if self.b[p] == b'#' && matches!(self.b.get(p.wrapping_sub(1)), Some(b' ' | b'\t')) {
                        return false;
                    }
                    p += 1;
                }
                false
            }
        }
    }

    fn apply_merge_or_set(
        merged: &mut Vec<(String, YamlNode)>,
        explicit: &mut Vec<(String, YamlNode)>,
        key: String,
        val: YamlNode,
        allow_merge: bool,
    ) -> Result<(), &'static str> {
        if allow_merge && key == "<<" {
            match val {
                YamlNode::Map(entries) => {
                    for (mk, mv) in entries {
                        if !merged.iter().any(|(k, _)| k == &mk) {
                            merged.push((mk, mv));
                        }
                    }
                }
                YamlNode::Seq(items) => {
                    for item in items {
                        let YamlNode::Map(entries) = item else {
                            return Err("YAML merge sequence item must be mapping");
                        };
                        for (mk, mv) in entries {
                            if !merged.iter().any(|(k, _)| k == &mk) {
                                merged.push((mk, mv));
                            }
                        }
                    }
                }
                _ => return Err("YAML merge key requires mapping or mapping sequence"),
            }
        } else {
            map_insert(explicit, key, val);
        }
        Ok(())
    }

    fn finalize_map(
        mut merged: Vec<(String, YamlNode)>,
        explicit: Vec<(String, YamlNode)>,
    ) -> YamlNode {
        for (k, v) in explicit {
            map_insert(&mut merged, k, v);
        }
        YamlNode::Map(merged)
    }

    fn parse_flow_value(&mut self) -> Result<YamlNode, &'static str> {
        self.skip_flow_ws();
        let (tag, anchor) = self.parse_node_props()?;
        self.skip_flow_ws();
        if self.peek() == Some(b'*') {
            if tag.is_some() || anchor.is_some() {
                return Err("YAML alias cannot carry anchor or tag");
            }
            let alias = self.read_indicator_name(b'*')?;
            return self
                .anchors
                .get(&alias)
                .cloned()
                .ok_or("undefined YAML alias");
        }
        let val = match self.peek() {
            Some(b'{') => self.parse_flow_mapping()?,
            Some(b'[') => self.parse_flow_seq()?,
            Some(b'"') => YamlNode::Scalar(self.parse_dquote(true)?, true),
            Some(b'\'') => YamlNode::Scalar(self.parse_squote(true)?, true),
            _ => {
                let (plain, is_null) = self.parse_plain_token(true)?;
                if is_null && tag.as_deref() != Some("!str") {
                    YamlNode::Null
                } else {
                    YamlNode::Scalar(plain, false)
                }
            }
        };
        let tagged = Self::apply_tag(tag.as_deref(), val)?;
        if let Some(name) = anchor {
            self.anchors.insert(name, tagged.clone());
        }
        Ok(tagged)
    }

    fn parse_flow_mapping(&mut self) -> Result<YamlNode, &'static str> {
        self.i += 1; // '{'
        let mut merged = Vec::new();
        let mut explicit = Vec::new();
        loop {
            self.skip_flow_ws();
            if self.i >= self.n {
                return Err("unterminated flow mapping");
            }
            if self.peek() == Some(b'}') {
                self.i += 1;
                break;
            }
            let (key, allow_merge) = self.parse_key(true)?;
            self.i += 1; // ':'
            self.skip_flow_ws();
            let val = if matches!(self.peek(), Some(b',' | b'}')) {
                YamlNode::Null
            } else {
                self.parse_flow_value()?
            };
            Self::apply_merge_or_set(&mut merged, &mut explicit, key, val, allow_merge)?;
            self.skip_flow_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected ',' or '}' in flow mapping"),
            }
        }
        Ok(Self::finalize_map(merged, explicit))
    }

    fn parse_flow_seq(&mut self) -> Result<YamlNode, &'static str> {
        self.i += 1; // '['
        let mut items = Vec::new();
        loop {
            self.skip_flow_ws();
            if self.i >= self.n {
                return Err("unterminated flow sequence");
            }
            if self.peek() == Some(b']') {
                self.i += 1;
                break;
            }
            items.push(self.parse_flow_value()?);
            self.skip_flow_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected ',' or ']' in flow sequence"),
            }
        }
        Ok(YamlNode::Seq(items))
    }

    fn parse_block_scalar(&mut self, parent_indent: isize) -> Result<String, &'static str> {
        let style = self.b[self.i];
        self.i += 1;
        let mut chomp: Option<u8> = None;
        let mut explicit_ind: Option<isize> = None;
        while let Some(c) = self.peek() {
            match c {
                b'+' | b'-' => {
                    if chomp.is_some() {
                        return Err("duplicate YAML block scalar chomp");
                    }
                    chomp = Some(c);
                    self.i += 1;
                }
                b'1'..=b'9' => {
                    if explicit_ind.is_some() {
                        return Err("duplicate YAML block scalar indent");
                    }
                    explicit_ind = Some((c - b'0') as isize);
                    self.i += 1;
                }
                _ => break,
            }
        }
        self.skip_comment_eol()?;
        let mut raw_lines: Vec<(String, bool)> = Vec::new();
        let mut ind: Option<isize> = explicit_ind.map(|e| parent_indent + e);
        while self.i < self.n {
            let line_start = self.i;
            let nl = self.s[self.i..].find('\n').map(|o| self.i + o);
            let line_end = nl.unwrap_or(self.n);
            let line = &self.s[line_start..line_end];
            if line.bytes().all(|b| b == b' ') {
                let extra = match ind {
                    Some(d) if (line.len() as isize) > d => line[(d as usize)..].to_owned(),
                    _ => String::new(),
                };
                let is_empty = extra.is_empty();
                raw_lines.push((extra, is_empty));
                self.i = nl.map_or(self.n, |p| p + 1);
                continue;
            }
            let cur = line.bytes().take_while(|&b| b == b' ').count() as isize;
            if cur <= parent_indent {
                break;
            }
            let block_ind = match ind {
                Some(d) => {
                    if cur < d {
                        return Err("inconsistent block scalar indentation");
                    }
                    d
                }
                None => {
                    ind = Some(cur);
                    cur
                }
            };
            raw_lines.push((line[(block_ind as usize)..].to_owned(), false));
            self.i = nl.map_or(self.n, |p| p + 1);
        }
        let mut trailing_blanks = 0usize;
        while raw_lines.last().is_some_and(|(_, is_blank)| *is_blank) {
            raw_lines.pop();
            trailing_blanks += 1;
        }
        if raw_lines.is_empty() {
            return Ok(if chomp == Some(b'+') {
                "\n".repeat(trailing_blanks)
            } else {
                String::new()
            });
        }
        let body = if style == b'|' {
            raw_lines
                .into_iter()
                .map(|(t, _)| t)
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            let mut out = String::new();
            let mut blanks = 0usize;
            let mut prev_text: Option<String> = None;
            for (text, is_blank) in raw_lines {
                if is_blank {
                    blanks += 1;
                    continue;
                }
                if let Some(ref prev) = prev_text {
                    let more_indented = prev.starts_with([' ', '\t']) || text.starts_with([' ', '\t']);
                    if blanks > 0 {
                        let count = if more_indented { blanks + 1 } else { blanks };
                        for _ in 0..count {
                            out.push('\n');
                        }
                    } else if more_indented {
                        out.push('\n');
                    } else {
                        out.push(' ');
                    }
                } else if blanks > 0 {
                    for _ in 0..blanks {
                        out.push('\n');
                    }
                }
                out.push_str(&text);
                prev_text = Some(text);
                blanks = 0;
            }
            out
        };
        match chomp {
            Some(b'-') => Ok(body),
            Some(b'+') => Ok(format!("{body}{}", "\n".repeat(1 + trailing_blanks))),
            _ => Ok(format!("{body}\n")),
        }
    }

    fn parse_block_value(&mut self, parent_indent: isize) -> Result<YamlNode, &'static str> {
        let (tag, anchor) = self.parse_node_props()?;
        if self.peek() == Some(b'*') {
            if tag.is_some() || anchor.is_some() {
                return Err("YAML alias cannot carry anchor or tag");
            }
            let alias = self.read_indicator_name(b'*')?;
            self.skip_comment_eol()?;
            return self
                .anchors
                .get(&alias)
                .cloned()
                .ok_or("undefined YAML alias");
        }
        let val = match self.peek() {
            None | Some(b'\n' | b'#') => {
                self.skip_comment_eol()?;
                self.parse_block_value_node(parent_indent)?
            }
            Some(b'|' | b'>') => YamlNode::Scalar(self.parse_block_scalar(parent_indent)?, true),
            Some(b'{') => {
                let node = self.parse_flow_mapping()?;
                self.skip_comment_eol()?;
                node
            }
            Some(b'[') => {
                let node = self.parse_flow_seq()?;
                self.skip_comment_eol()?;
                node
            }
            Some(b'"') => {
                let node = YamlNode::Scalar(self.parse_dquote(false)?, true);
                self.skip_comment_eol()?;
                node
            }
            Some(b'\'') => {
                let node = YamlNode::Scalar(self.parse_squote(false)?, true);
                self.skip_comment_eol()?;
                node
            }
            _ => {
                let (plain, is_null) = self.parse_plain_token(false)?;
                if is_null && tag.as_deref() != Some("!str") {
                    YamlNode::Null
                } else {
                    YamlNode::Scalar(plain, false)
                }
            }
        };
        let tagged = Self::apply_tag(tag.as_deref(), val)?;
        if let Some(name) = anchor {
            self.anchors.insert(name, tagged.clone());
        }
        Ok(tagged)
    }

    fn parse_block_value_node(&mut self, parent_indent: isize) -> Result<YamlNode, &'static str> {
        self.skip_blank_and_comments();
        if self.i >= self.n {
            return Ok(YamlNode::Null);
        }
        let ind = self.current_line_indent() as isize;
        let line_rest = &self.b[self.i + (ind as usize)..];
        let is_seq_dash = line_rest.starts_with(b"- ")
            || line_rest == b"-"
            || line_rest.starts_with(b"-\n")
            || line_rest.starts_with(b"-#");
        if is_seq_dash && ind >= parent_indent {
            return self.parse_block_seq(ind as usize);
        }
        if ind <= parent_indent {
            return Ok(YamlNode::Null);
        }
        match self.b.get(self.i + (ind as usize)).copied() {
            Some(b'{') => {
                self.i += ind as usize;
                let node = self.parse_flow_mapping()?;
                self.skip_comment_eol()?;
                Ok(node)
            }
            Some(b'[') => {
                self.i += ind as usize;
                let node = self.parse_flow_seq()?;
                self.skip_comment_eol()?;
                Ok(node)
            }
            _ if self.starts_block_mapping_entry() => self.parse_block_mapping(ind as usize),
            _ => {
                self.i += ind as usize;
                let (tag, anchor) = self.parse_node_props()?;
                if self.peek() == Some(b'*') {
                    if tag.is_some() || anchor.is_some() {
                        return Err("YAML alias cannot carry anchor or tag");
                    }
                    let alias = self.read_indicator_name(b'*')?;
                    self.skip_comment_eol()?;
                    return self
                        .anchors
                        .get(&alias)
                        .cloned()
                        .ok_or("undefined YAML alias");
                }
                let node = match self.peek() {
                    Some(b'"') => {
                        let s = self.parse_dquote(false)?;
                        self.skip_comment_eol()?;
                        YamlNode::Scalar(s, true)
                    }
                    Some(b'\'') => {
                        let s = self.parse_squote(false)?;
                        self.skip_comment_eol()?;
                        YamlNode::Scalar(s, true)
                    }
                    Some(b'|' | b'>') => {
                        YamlNode::Scalar(self.parse_block_scalar(parent_indent)?, true)
                    }
                    _ => {
                        let (plain, is_null) = self.parse_plain_token(false)?;
                        if is_null && tag.as_deref() != Some("!str") {
                            YamlNode::Null
                        } else {
                            YamlNode::Scalar(plain, false)
                        }
                    }
                };
                let tagged = Self::apply_tag(tag.as_deref(), node)?;
                if let Some(name) = anchor {
                    self.anchors.insert(name, tagged.clone());
                }
                Ok(tagged)
            }
        }
    }

    fn parse_block_mapping(&mut self, indent: usize) -> Result<YamlNode, &'static str> {
        let mut merged = Vec::new();
        let mut explicit = Vec::new();
        loop {
            self.skip_blank_and_comments();
            if self.i >= self.n {
                break;
            }
            let ind = self.current_line_indent();
            if ind < indent {
                break;
            }
            if ind > indent {
                return Err("inconsistent YAML indentation");
            }
            self.i += indent;
            if self.peek() == Some(b'-')
                && self
                    .b
                    .get(self.i + 1)
                    .is_none_or(|c| matches!(c, b' ' | b'\t' | b'\n'))
            {
                return Err("unexpected sequence entry in YAML mapping");
            }
            let (key, allow_merge) = self.parse_key(false)?;
            self.i += 1; // ':'
            let val = self.parse_block_value(indent as isize)?;
            Self::apply_merge_or_set(&mut merged, &mut explicit, key, val, allow_merge)?;
        }
        Ok(Self::finalize_map(merged, explicit))
    }

    fn parse_block_seq(&mut self, seq_indent: usize) -> Result<YamlNode, &'static str> {
        let mut items = Vec::new();
        loop {
            self.skip_blank_and_comments();
            if self.i >= self.n {
                break;
            }
            let ind = self.current_line_indent();
            if ind != seq_indent {
                break;
            }
            let rest = &self.b[self.i + ind..];
            if !(rest.starts_with(b"- ") || rest == b"-" || rest.starts_with(b"-\n")) {
                break;
            }
            self.i += ind + 1;
            self.skip_hws();
            if matches!(self.peek(), None | Some(b'\n' | b'#')) {
                self.skip_comment_eol()?;
                self.skip_blank_and_comments();
                if self.i < self.n && self.current_line_indent() > seq_indent {
                    items.push(self.parse_block_value_node(seq_indent as isize)?);
                } else {
                    items.push(YamlNode::Null);
                }
            } else if self.starts_block_mapping_entry() {
                let ls = self.s[..self.i].rfind('\n').map_or(0, |p| p + 1);
                let item_indent = self.i - ls;
                let (k, allow_merge) = self.parse_key(false)?;
                self.i += 1; // ':'
                let v = self.parse_block_value(item_indent as isize)?;
                let mut merged = Vec::new();
                let mut explicit = Vec::new();
                Self::apply_merge_or_set(&mut merged, &mut explicit, k, v, allow_merge)?;
                if let YamlNode::Map(rest_entries) = self.parse_block_mapping(item_indent)? {
                    for (rk, rv) in rest_entries {
                        map_insert(&mut explicit, rk, rv);
                    }
                }
                items.push(Self::finalize_map(merged, explicit));
            } else {
                items.push(self.parse_block_value(seq_indent as isize)?);
            }
        }
        Ok(YamlNode::Seq(items))
    }

    fn parse_root_map(&mut self) -> Result<Vec<(String, YamlNode)>, &'static str> {
        self.skip_blank_and_comments();
        if self.i >= self.n {
            return Ok(Vec::new());
        }
        let ind = self.current_line_indent();
        let node = match self.b.get(self.i + ind).copied() {
            Some(b'{') => {
                self.i += ind;
                let m = self.parse_flow_mapping()?;
                self.skip_blank_and_comments();
                if self.i < self.n {
                    return Err("unexpected trailing YAML content");
                }
                m
            }
            _ => self.parse_block_mapping(ind)?,
        };
        self.skip_blank_and_comments();
        if self.i < self.n {
            return Err("unexpected trailing YAML content");
        }
        match node {
            YamlNode::Map(entries) => Ok(entries),
            _ => Err("expected top-level YAML mapping"),
        }
    }
}

fn parse_yaml_root_map(yaml: &str) -> Result<Vec<(String, YamlNode)>, &'static str> {
    let trimmed = yaml.strip_prefix('\u{feff}').unwrap_or(yaml);
    let normalized = trimmed.replace("\r\n", "\n");
    let mut parser = YamlParser::new(&normalized);
    parser.parse_root_map()
}

fn yaml_section_scalar_meta(
    section_entries: &[(String, YamlNode)],
    key: &str,
) -> Result<Option<(String, bool)>, &'static str> {
    match map_lookup(section_entries, key) {
        None | Some(YamlNode::Null) => Ok(None),
        Some(YamlNode::Scalar(s, quoted)) => Ok(Some((s.clone(), *quoted))),
        Some(_) => Err("non-scalar YAML section setting"),
    }
}

fn yaml_section_scalar(
    section_entries: &[(String, YamlNode)],
    key: &str,
) -> Result<Option<String>, &'static str> {
    Ok(yaml_section_scalar_meta(section_entries, key)?.map(|(s, _)| s))
}

fn systemd_env_merge(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in pairs {
        if let Some((_, slot)) = merged.iter_mut().find(|(name, _)| name == k) {
            *slot = v.clone();
        } else {
            merged.push((k.clone(), v.clone()));
        }
    }
    merged
}

fn env_lookup_precedence(pairs: &[(String, String)], keys: &[&str]) -> Option<String> {
    let merged = systemd_env_merge(pairs);
    merged
        .into_iter()
        .rev()
        .find(|(k, _)| keys.iter().any(|target| k.eq_ignore_ascii_case(target)))
        .map(|(_, v)| v)
}

fn parse_koanf_env_retention_days(raw: &str) -> Result<i64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty WORM_RETENTION_DAYS".into());
    }
    if let Ok(days) = s.parse::<i64>() {
        if days < 1 {
            return Err(format!(
                "invalid WORM_RETENTION_DAYS (must be >= 1): {raw:?}"
            ));
        }
        return Ok(days);
    }
    if let Some(v) = parse_go_float64(s) {
        if v >= (i64::MIN as f64) && v < 9_223_372_036_854_775_808.0 {
            let days = v as i64;
            if days < 1 {
                return Err(format!(
                    "invalid WORM_RETENTION_DAYS (must be >= 1): {raw:?}"
                ));
            }
            return Ok(days);
        }
    }
    Err(format!("invalid WORM_RETENTION_DAYS: {raw:?}"))
}

fn yaml_db_dsn(yaml: &str) -> Result<Option<String>, &'static str> {
    let root = parse_yaml_root_map(yaml)?;
    let Some(section) = map_lookup(&root, "db") else {
        return Ok(None);
    };
    let entries = match section {
        YamlNode::Null => return Ok(None),
        YamlNode::Map(entries) => entries,
        _ => return Err("unsupported db YAML value"),
    };
    yaml_section_scalar(entries, "dsn")
}

fn yaml_worm_settings(yaml: &str) -> Result<YamlWorm, &'static str> {
    let root = parse_yaml_root_map(yaml)?;
    let Some(section) = map_lookup(&root, "worm") else {
        return Ok(YamlWorm::default());
    };
    let entries = match section {
        YamlNode::Null => return Ok(YamlWorm::default()),
        YamlNode::Map(entries) => entries,
        _ => return Err("unsupported worm YAML value"),
    };
    let mode = yaml_section_scalar(entries, "mode")?.filter(|s| !s.is_empty());
    let retention_days = match map_lookup(entries, "retention_days") {
        None => None,
        Some(YamlNode::Null) => Some(String::new()),
        Some(YamlNode::Scalar(s, quoted)) => Some(if *quoted {
            s.clone()
        } else {
            normalize_retention_days(s)
        }),
        Some(_) => return Err("non-scalar YAML section setting"),
    };
    Ok(YamlWorm {
        mode,
        retention_days,
    })
}

fn yaml_s3_settings(yaml: &str) -> Result<YamlS3, &'static str> {
    let root = parse_yaml_root_map(yaml)?;
    let Some(section) = map_lookup(&root, "s3") else {
        return Ok(YamlS3::default());
    };
    let entries = match section {
        YamlNode::Null => return Ok(YamlS3::default()),
        YamlNode::Map(entries) => entries,
        _ => return Err("unsupported s3 YAML value"),
    };
    Ok(YamlS3 {
        endpoint: yaml_section_scalar(entries, "endpoint")?,
        access_key: yaml_section_scalar(entries, "access_key")?,
        secret_key: yaml_section_scalar(entries, "secret_key")?,
        bucket: yaml_section_scalar(entries, "bucket")?,
        secure: yaml_section_scalar_meta(entries, "secure")?,
    })
}

fn resolve_s3_settings(
    pairs: &[(String, String)],
    yaml_s3: Option<&YamlS3>,
) -> Result<ResolvedS3, String> {
    let mut endpoint = yaml_s3
        .and_then(|s| s.endpoint.as_deref())
        .unwrap_or("127.0.0.1:9000")
        .to_owned();
    if let Some(v) = env_lookup_precedence(pairs, &["S3__ENDPOINT", "S3_ENDPOINT"]) {
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
    if let Some(v) = env_lookup_precedence(pairs, &["S3_ACCESS_KEY"]) {
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
    if let Some(v) = env_lookup_precedence(pairs, &["S3_SECRET_KEY"]) {
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
    if let Some(v) = env_lookup_precedence(pairs, &["S3__BUCKET", "S3_BUCKET"]) {
        bucket = v;
    }
    if bucket == "mailblobs" {
        if let Some(v) = env_lookup(pairs, "MINIO_BUCKET").filter(|v| !v.is_empty()) {
            bucket = v;
        }
    }

    let secure = if let Some(v) = env_lookup(pairs, "MINIO_SECURE").filter(|v| !v.is_empty()) {
        strict_go_bool(&v, "MINIO_SECURE")?
    } else if let Some(v) = env_lookup_precedence(pairs, &["S3__SECURE", "S3_SECURE"]) {
        koanf_bool(&v)
    } else if let Some((ref v, quoted)) = yaml_s3.and_then(|s| s.secure.as_ref()) {
        yaml_koanf_bool(v, *quoted)
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

fn has_storage_env_setting(pairs: &[(String, String)]) -> bool {
    [
        "S3_ENDPOINT",
        "S3__ENDPOINT",
        "S3_BUCKET",
        "S3__BUCKET",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
    ]
    .iter()
    .any(|k| env_lookup_precedence(pairs, &[k]).is_some_and(|v| !v.is_empty()))
        || [
            "MINIO_ENDPOINT",
            "MINIO_BUCKET",
            "MINIO_ACCESS_KEY",
            "MINIO_SECRET_KEY",
        ]
        .iter()
        .any(|k| env_lookup(pairs, k).is_some_and(|v| !v.is_empty()))
}

#[derive(Default, Debug)]
struct UnitEnvSpec {
    inline_env: Vec<(String, String)>,
    env_files: Vec<(std::path::PathBuf, bool)>,
    unset_env: Vec<String>,
}

fn decode_systemd_hex(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    count: usize,
) -> Result<u32, &'static str> {
    let mut val = 0u32;
    for _ in 0..count {
        let Some(d) = chars.next().and_then(|c| c.to_digit(16)) else {
            return Err("invalid or truncated hex escape in systemd directive");
        };
        val = (val << 4) | d;
    }
    Ok(val)
}

fn decode_systemd_c_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    let Some(esc) = chars.next() else {
        return Err("trailing backslash escape in systemd directive");
    };
    match esc {
        'a' => out.push(0x07),
        'b' => out.push(0x08),
        'f' => out.push(0x0c),
        'n' => out.push(b'\n'),
        'r' => out.push(b'\r'),
        't' => out.push(b'\t'),
        'v' => out.push(0x0b),
        '\\' => out.push(b'\\'),
        '"' => out.push(b'"'),
        '\'' => out.push(b'\''),
        's' => out.push(b' '),
        'x' => {
            let val = decode_systemd_hex(chars, 2)?;
            if val == 0 {
                return Err("NUL escape is forbidden in systemd directive");
            }
            out.push(val as u8);
        }
        'u' => {
            let val = decode_systemd_hex(chars, 4)?;
            let ch = (val != 0)
                .then(|| char::from_u32(val))
                .flatten()
                .ok_or("invalid Unicode escape in systemd directive")?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        'U' => {
            let val = decode_systemd_hex(chars, 8)?;
            let ch = (val != 0)
                .then(|| char::from_u32(val))
                .flatten()
                .ok_or("invalid Unicode escape in systemd directive")?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        '0'..='7' => {
            let mut val = (esc as u32) - ('0' as u32);
            for _ in 0..2 {
                let Some(d @ '0'..='7') = chars.next() else {
                    return Err("invalid or truncated octal escape in systemd directive");
                };
                val = (val * 8) + ((d as u32) - ('0' as u32));
            }
            if val == 0 || val > 255 {
                return Err("invalid octal byte in systemd directive");
            }
            out.push(val as u8);
        }
        _ => return Err("unknown C escape sequence in systemd directive"),
    }
    Ok(())
}

fn split_systemd_words(s: &str) -> Result<Vec<String>, &'static str> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
            continue;
        }
        let mut word: Vec<u8> = Vec::new();
        while let Some(&ch) = chars.peek() {
            if ch.is_ascii_whitespace() {
                break;
            }
            if ch == '"' || ch == '\'' {
                let q = ch;
                chars.next();
                let mut closed = false;
                while let Some(inner) = chars.next() {
                    if inner == q {
                        closed = true;
                        break;
                    }
                    if inner == '\\' {
                        decode_systemd_c_escape(&mut chars, &mut word)?;
                    } else {
                        let mut buf = [0u8; 4];
                        word.extend_from_slice(inner.encode_utf8(&mut buf).as_bytes());
                    }
                }
                if !closed {
                    return Err("unterminated quote in systemd directive");
                }
            } else if ch == '\\' {
                chars.next();
                decode_systemd_c_escape(&mut chars, &mut word)?;
            } else {
                let mut buf = [0u8; 4];
                word.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                chars.next();
            }
        }
        let word = String::from_utf8(word).map_err(|_| "invalid UTF-8 in systemd directive")?;
        if !word.is_empty() {
            out.push(word);
        }
    }
    Ok(out)
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

fn expand_systemd_specifiers(raw: &str, unit_name: &str, directive_key: &str) -> Result<String> {
    if !raw.contains('%') {
        return Ok(raw.to_owned());
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let Some(spec) = chars.next() else {
            bail!(
                "unsupported trailing systemd specifier in {directive_key}= directive; resolve explicitly or run upgrade.sh refresh-gateway-env"
            );
        };
        match spec {
            '%' => out.push('%'),
            'n' => {
                ensure!(
                    !unit_name.is_empty(),
                    "cannot expand %n systemd specifier without unit name in {directive_key}= directive"
                );
                out.push_str(unit_name);
            }
            'N' => {
                let stem = unit_name
                    .rsplit_once('.')
                    .map(|(s, _)| s)
                    .unwrap_or(unit_name);
                ensure!(
                    !stem.is_empty(),
                    "cannot expand %N systemd specifier without unit name in {directive_key}= directive"
                );
                out.push_str(stem);
            }
            'E' => out.push_str("/etc"),
            't' => out.push_str("/run"),
            'S' => out.push_str("/var/lib"),
            'C' => out.push_str("/var/cache"),
            'L' => out.push_str("/var/log"),
            _ => bail!(
                "unsupported systemd specifier %{spec} in {directive_key}= directive; resolve explicitly or run upgrade.sh refresh-gateway-env"
            ),
        }
    }
    Ok(out)
}

fn parse_unit_env_spec_into(unit: &str, unit_name: &str, spec: &mut UnitEnvSpec) -> Result<()> {
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
        if key == "Environment" {
            if rhs.is_empty() {
                spec.inline_env.clear();
            } else {
                for word in split_systemd_words(rhs).map_err(anyhow::Error::msg)? {
                    let expanded = expand_systemd_specifiers(&word, unit_name, "Environment")?;
                    if let Some((k, v)) = expanded.split_once('=') {
                        if !k.is_empty() {
                            spec.inline_env.push((k.to_owned(), v.to_owned()));
                        }
                    }
                }
            }
            continue;
        }
        if key == "UnsetEnvironment" {
            if rhs.is_empty() {
                spec.unset_env.clear();
            } else {
                for word in split_systemd_words(rhs).map_err(anyhow::Error::msg)? {
                    spec.unset_env
                        .push(expand_systemd_specifiers(&word, unit_name, "UnsetEnvironment")?);
                }
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
        if rest.is_empty() {
            continue;
        }
        let expanded = expand_systemd_specifiers(rest, unit_name, "EnvironmentFile")?;
        if !std::path::Path::new(&expanded).is_absolute() {
            continue;
        }
        spec.env_files
            .push((std::path::PathBuf::from(expanded), optional));
    }
    Ok(())
}

fn dropin_unit_categories(unit_name: &str) -> (Option<String>, Vec<String>) {
    let Some((stem, unit_type)) = unit_name.rsplit_once('.') else {
        return (None, vec![format!("{unit_name}.d")]);
    };
    let type_dir = format!("{unit_type}.d");
    let mut unit_rels = Vec::new();
    for (idx, _) in stem.match_indices('-') {
        if idx > 0 {
            unit_rels.push(format!("{}-.{unit_type}.d", &stem[..idx]));
        }
    }
    if let Some((prefix, _)) = stem.split_once('@') {
        if !prefix.is_empty() {
            let tmpl = format!("{prefix}@.{unit_type}.d");
            if !unit_rels.contains(&tmpl) {
                unit_rels.push(tmpl);
            }
        }
    }
    let exact = format!("{unit_name}.d");
    if !unit_rels.contains(&exact) {
        unit_rels.push(exact);
    }
    (Some(type_dir), unit_rels)
}

fn default_dropin_dirs(unit_path: &Path) -> Vec<std::path::PathBuf> {
    let Some(unit_name) = unit_path.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let Some(parent) = unit_path.parent() else {
        return Vec::new();
    };
    let (type_rel, unit_rels) = dropin_unit_categories(unit_name);
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
    let mut dirs = Vec::with_capacity(tiers.len() * (unit_rels.len() + usize::from(type_rel.is_some())));
    if let Some(ref t) = type_rel {
        for tier in &tiers {
            dirs.push(tier.join(t));
        }
    }
    for tier in &tiers {
        for rel in &unit_rels {
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
    let unit_name = unit_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match std::fs::read_to_string(unit_path) {
        Ok(src) => parse_unit_env_spec_into(&src, unit_name, &mut spec)
            .with_context(|| format!("parsing {}", unit_path.display()))?,
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
        parse_unit_env_spec_into(&src, unit_name, &mut spec)
            .with_context(|| format!("parsing drop-in {}", path.display()))?;
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
    gateway_env_path: Option<std::path::PathBuf>,
    gateway_file_worm_mode: Option<String>,
}

fn glob_match_chars(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        '*' => {
            let mut k = 1;
            while k < p.len() && p[k] == '*' {
                k += 1;
            }
            for i in 0..=t.len() {
                if glob_match_chars(&p[k..], &t[i..]) {
                    return true;
                }
            }
            false
        }
        '?' => !t.is_empty() && glob_match_chars(&p[1..], &t[1..]),
        '[' => {
            if t.is_empty() {
                return false;
            }
            let ch = t[0];
            let mut idx = 1;
            let negated = idx < p.len() && (p[idx] == '!' || p[idx] == '^');
            if negated {
                idx += 1;
            }
            let mut matched = false;
            let mut first = true;
            while idx < p.len() {
                if p[idx] == ']' && !first {
                    return (matched ^ negated) && glob_match_chars(&p[idx + 1..], &t[1..]);
                }
                first = false;
                let start_c = p[idx];
                if idx + 2 < p.len() && p[idx + 1] == '-' && p[idx + 2] != ']' {
                    let end_c = p[idx + 2];
                    if ch >= start_c && ch <= end_c {
                        matched = true;
                    }
                    idx += 3;
                } else {
                    if ch == start_c {
                        matched = true;
                    }
                    idx += 1;
                }
            }
            // Unclosed '[' is treated as literal '[' per fnmatch/glob fallback.
            ch == '[' && glob_match_chars(&p[1..], &t[1..])
        }
        c => !t.is_empty() && t[0] == c && glob_match_chars(&p[1..], &t[1..]),
    }
}

fn glob_match(pat: &str, text: &str) -> bool {
    if text.starts_with('.') && !pat.starts_with('.') {
        return false;
    }
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_chars(&p, &t)
}

fn retain_existing_glob_candidates(
    candidates: Vec<std::path::PathBuf>,
) -> Result<Vec<std::path::PathBuf>> {
    let mut existing = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if let Some(parent) = candidate.parent().filter(|p| !p.as_os_str().is_empty()) {
            match std::fs::metadata(parent) {
                Ok(m) if !m.is_dir() => continue,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("inspecting EnvironmentFile glob dir {}", parent.display())
                    });
                }
            }
        }
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => existing.push(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "inspecting EnvironmentFile glob path {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    Ok(existing)
}

fn expand_env_file_glob(pattern: &Path) -> Result<Vec<std::path::PathBuf>> {
    let raw = pattern.to_string_lossy();
    if !(raw.contains('*') || raw.contains('?') || raw.contains('[')) {
        return Ok(vec![pattern.to_path_buf()]);
    }
    let mut candidates = vec![std::path::PathBuf::new()];
    let mut saw_glob = false;
    for comp in pattern.components() {
        match comp {
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::CurDir
            | std::path::Component::ParentDir => {
                for c in &mut candidates {
                    c.push(comp.as_os_str());
                }
                if saw_glob {
                    candidates = retain_existing_glob_candidates(candidates)?;
                }
            }
            std::path::Component::Normal(seg_os) => {
                let Some(seg) = seg_os.to_str() else {
                    for c in &mut candidates {
                        c.push(seg_os);
                    }
                    if saw_glob {
                        candidates = retain_existing_glob_candidates(candidates)?;
                    }
                    continue;
                };
                if !(seg.contains('*') || seg.contains('?') || seg.contains('[')) {
                    for c in &mut candidates {
                        c.push(seg_os);
                    }
                    if saw_glob {
                        candidates = retain_existing_glob_candidates(candidates)?;
                    }
                    continue;
                }
                saw_glob = true;
                let mut next = Vec::new();
                for base in &candidates {
                    let read_target = if base.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        base.as_path()
                    };
                    match std::fs::metadata(read_target) {
                        Ok(m) if !m.is_dir() => continue,
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => {
                            return Err(e).with_context(|| {
                                format!("inspecting EnvironmentFile glob dir {}", read_target.display())
                            });
                        }
                    }
                    let entries = std::fs::read_dir(read_target).with_context(|| {
                        format!("reading EnvironmentFile glob dir {}", read_target.display())
                    })?;
                    let mut names = Vec::new();
                    for entry in entries {
                        let entry = entry.with_context(|| {
                            format!("reading EnvironmentFile glob entry in {}", read_target.display())
                        })?;
                        if let Some(name) = entry.file_name().to_str() {
                            if glob_match(seg, name) {
                                names.push(name.to_owned());
                            }
                        }
                    }
                    names.sort();
                    for name in names {
                        next.push(base.join(name));
                    }
                }
                candidates = next;
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn load_effective_gateway_env(spec: &UnitEnvSpec) -> Result<EffectiveGatewayEnv> {
    let mut expanded_files: Vec<(std::path::PathBuf, bool)> = Vec::new();
    for (pattern, optional) in &spec.env_files {
        let raw = pattern.to_string_lossy();
        let has_glob = raw.contains('*') || raw.contains('?') || raw.contains('[');
        if !has_glob {
            expanded_files.push((pattern.clone(), *optional));
        } else {
            let matches = expand_env_file_glob(pattern)?;
            if matches.is_empty() && !*optional {
                bail!(
                    "reading required EnvironmentFile {}: no matching files",
                    pattern.display()
                );
            }
            for m in matches {
                expanded_files.push((m, *optional));
            }
        }
    }
    let has_storage_file = expanded_files.iter().any(|(p, _)| {
        p.file_name().and_then(|n| n.to_str()) == Some("storage.env")
            && std::fs::metadata(p).is_ok_and(|m| m.is_file())
    });
    let gateway_env_path = expanded_files
        .iter()
        .rfind(|(p, _)| {
            p.file_name().and_then(|n| n.to_str()) == Some("gateway.env")
                && std::fs::metadata(p).is_ok_and(|m| m.is_file())
        })
        .map(|(p, _)| p.clone());
    let has_gateway_file = gateway_env_path.is_some();
    let mut pairs = systemd_env_merge(&spec.inline_env);
    let mut gateway_file_pairs = Vec::new();
    for (path, optional) in &expanded_files {
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
    let mut pairs = systemd_env_merge(&pairs);
    for entry in &spec.unset_env {
        if let Some((k, v)) = entry.split_once('=') {
            if env_lookup(&pairs, k).as_deref() == Some(v) {
                pairs.retain(|(name, _)| name != k);
            }
        } else {
            pairs.retain(|(name, _)| name != entry);
        }
    }
    let gateway_file_worm_mode = env_lookup_precedence(&gateway_file_pairs, &["WORM__MODE", "WORM_MODE"]);
    Ok(EffectiveGatewayEnv {
        pairs,
        has_storage_file,
        has_gateway_file,
        gateway_env_path,
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
    if !has_storage_env_setting(&gw.pairs) {
        return false;
    }
    if expected_s3 != gateway_s3 {
        return false;
    }
    if env_lookup_precedence(&gw.pairs, &["WORM__MODE", "WORM_MODE"]).as_deref()
        != Some(expected_mode)
    {
        return false;
    }
    if env_lookup(&gw.pairs, "WORM_LEGAL_HOLD_ENABLED").as_deref() != expected_legal_hold {
        return false;
    }
    let gw_retention = env_lookup_precedence(&gw.pairs, &["WORM_RETENTION_DAYS"]);
    if gw_retention.as_deref() != expected_retention_days {
        return false;
    }
    true
}

fn gw_is_db_backed(gw: &EffectiveGatewayEnv) -> Result<bool> {
    if let Some(v) = env_lookup_precedence(&gw.pairs, &["DB__DSN", "DB_DSN"]) {
        return Ok(!v.is_empty());
    }
    let Some(yaml_path) = env_lookup(&gw.pairs, "SETJOIN_CONFIG").filter(|p| !p.is_empty()) else {
        return Ok(false);
    };
    let yaml = std::fs::read_to_string(&yaml_path).with_context(|| {
        format!("cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying DB-backed gateway readiness")
    })?;
    let dsn = yaml_db_dsn(&yaml).map_err(|reason| {
        anyhow::anyhow!(
            "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying DB-backed gateway readiness ({reason})"
        )
    })?;
    Ok(dsn.is_some_and(|v| !v.is_empty()))
}

fn check_db_gateway_startup_prereqs(gw: &EffectiveGatewayEnv) -> Result<()> {
    if !gw_is_db_backed(gw)? {
        return Ok(());
    }
    let has_gateway_worm = gw.has_gateway_file && gw.gateway_file_worm_mode.is_some();
    let effective_worm = env_lookup_precedence(&gw.pairs, &["WORM__MODE", "WORM_MODE"]);
    if !has_gateway_worm || effective_worm.is_none() {
        bail!(
            "DB-backed setjoin-gateway unit/gateway.env must set explicit WORM_MODE (empty when disabled); run upgrade.sh refresh-gateway-env before activating"
        );
    }
    if effective_worm.as_deref().is_some_and(|v| !v.is_empty()) {
        if !gw.has_storage_file || !has_storage_env_setting(&gw.pairs) {
            bail!(
                "DB-backed setjoin-gateway enables WORM_MODE, but lacks storage.env and S3_*/MINIO_* settings; run upgrade.sh refresh-gateway-env before activating"
            );
        }
        if let Some(raw_ret) = env_lookup_precedence(&gw.pairs, &["WORM_RETENTION_DAYS"]) {
            let days = parse_koanf_env_retention_days(&raw_ret)
                .map_err(|reason| anyhow::anyhow!("{reason}; run upgrade.sh refresh-gateway-env"))?;
            if days.to_string() != raw_ret.trim() {
                bail!(
                    "DB-backed setjoin-gateway unit/gateway.env WORM_RETENTION_DAYS must be canonical integer days (got {raw_ret:?}); run upgrade.sh refresh-gateway-env"
                );
            }
        } else if let Some(yaml_path) =
            env_lookup(&gw.pairs, "SETJOIN_CONFIG").filter(|p| !p.is_empty())
        {
            let yaml = std::fs::read_to_string(&yaml_path).with_context(|| {
                format!("cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying WORM retention")
            })?;
            let parsed = yaml_worm_settings(&yaml).map_err(|reason| {
                anyhow::anyhow!(
                    "cannot inspect SETJOIN_CONFIG ({yaml_path}) while verifying WORM retention ({reason})"
                )
            })?;
            if let Some(raw_ret) = parsed.retention_days {
                parse_koanf_env_retention_days(&raw_ret).map_err(|reason| {
                    anyhow::anyhow!("{reason}; run upgrade.sh refresh-gateway-env")
                })?;
            }
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
    let unit_cfg = gw
        .gateway_env_path
        .as_deref()
        .and_then(|p| p.parent().map(|d| d.join("config.env")));
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
    let config_worm_mode = env_lookup_precedence(&pairs, &["WORM__MODE", "WORM_MODE"]);
    let config_retention = env_lookup_precedence(&pairs, &["WORM_RETENTION_DAYS"]);
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
        Some(v) => Some(v),
        None => yaml_settings
            .as_ref()
            .and_then(|y| y.retention_days.clone()),
    };
    if let Some(mode) = expected_mode {
        let canonical_retention_days = expected_retention_days
            .as_deref()
            .map(|raw| {
                parse_koanf_env_retention_days(raw)
                    .map(|days| days.to_string())
                    .map_err(|reason| {
                        anyhow::anyhow!("{reason}; run upgrade.sh refresh-gateway-env")
                    })
            })
            .transpose()?;
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
            canonical_retention_days.as_deref(),
            &host_s3,
            &gw_s3,
        ) {
            bail!(
                "WORM is enabled in host configuration, but setjoin-gateway unit/gateway.env lacks matching storage.env and WORM_MODE; run upgrade.sh refresh-gateway-env before activating"
            );
        }
    } else {
        let is_db_backed = gw_is_db_backed(&gw)?;
        let gateway_has_empty_worm =
            gw.has_gateway_file && gw.gateway_file_worm_mode.as_deref() == Some("");
        let effective_worm_empty =
            env_lookup_precedence(&gw.pairs, &["WORM__MODE", "WORM_MODE"]).as_deref() == Some("");
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
        load_unit_env_spec_with_dirs, parse_env_assignments, parse_koanf_env_retention_days,
        split_systemd_words, yaml_worm_settings,
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
        let etc_type_pos = sys_dirs
            .iter()
            .position(|p| p == Path::new("/etc/systemd/system/service.d"))
            .unwrap();
        let lib_unit_pos = sys_dirs
            .iter()
            .position(|p| p == Path::new("/usr/lib/systemd/system/setjoin-gateway.service.d"))
            .unwrap();
        let etc_prefix_pos = sys_dirs
            .iter()
            .position(|p| p == Path::new("/etc/systemd/system/setjoin-.service.d"))
            .unwrap();
        let etc_unit_pos = sys_dirs
            .iter()
            .position(|p| p == Path::new("/etc/systemd/system/setjoin-gateway.service.d"))
            .unwrap();
        assert!(etc_type_pos < lib_unit_pos);
        assert!(lib_unit_pos < etc_prefix_pos);
        assert!(etc_prefix_pos < etc_unit_pos);
        assert!(sys_dirs.contains(&Path::new("/lib/systemd/system/service.d").to_path_buf()));

        // Cross-tier precedence:
        // 1) unit-specific /usr/lib/<unit>.d overrides same-named /etc/service.d
        // 2) /etc/setjoin-.service.d overrides same-named /usr/lib/setjoin-gateway.service.d
        let xtier = dir.path().join("xtier");
        let x_etc_type = xtier.join("etc-service.d");
        let x_lib_unit = xtier.join("lib-unit.d");
        let x_etc_prefix = xtier.join("etc-prefix.d");
        std::fs::create_dir_all(&x_etc_type).unwrap();
        std::fs::create_dir_all(&x_lib_unit).unwrap();
        std::fs::create_dir_all(&x_etc_prefix).unwrap();
        let x_unit = xtier.join("setjoin-gateway.service");
        std::fs::write(&x_unit, "[Service]\n").unwrap();
        std::fs::write(x_etc_type.join("40-worm.conf"), format!("[Service]\nEnvironmentFile={}\n", gw.display())).unwrap();
        std::fs::write(x_lib_unit.join("40-worm.conf"), format!("[Service]\nEnvironmentFile={}\n", storage.display())).unwrap();
        let x_merged = load_unit_env_files_with_dirs(&x_unit, &[x_etc_type, x_lib_unit.clone()]).unwrap();
        assert_eq!(x_merged, vec![(storage.clone(), false)]);
        std::fs::write(x_etc_prefix.join("40-worm.conf"), format!("[Service]\nEnvironmentFile={}\n", fed.display())).unwrap();
        let x_merged_tier = load_unit_env_files_with_dirs(&x_unit, &[x_lib_unit, x_etc_prefix]).unwrap();
        assert_eq!(x_merged_tier, vec![(fed.clone(), false)]);

        // Inline [Service] Environment= with C-style escapes supplies DB_DSN (caught even without config.env) and Environment= resets it
        let inline_dir = dir.path().join("inline-env");
        let inline_dropin = inline_dir.join("inline.service.d");
        std::fs::create_dir_all(&inline_dropin).unwrap();
        let inline_gw = inline_dir.join("gateway.env");
        let inline_unit = inline_dir.join("inline.service");
        std::fs::write(&inline_gw, "GATEWAY_ENABLED=true\n").unwrap();
        std::fs::write(
            &inline_unit,
            format!(
                "[Service]\nEnvironment=\"DB_DSN=post\\x67res://app@localhost/mail\"\nEnvironmentFile={}\n",
                inline_gw.display()
            ),
        )
        .unwrap();
        let inline_err = check_worm_gateway_ready(&inline_unit, None, &missing_default).unwrap_err();
        assert!(inline_err.to_string().contains("WORM_MODE"));
        std::fs::write(inline_dropin.join("10-reset.conf"), "[Service]\nEnvironment=\n").unwrap();
        assert!(check_worm_gateway_ready(&inline_unit, None, &missing_default).is_ok());

        // C-style escapes in UnsetEnvironment= (both double- and single-quoted) remove WORM_MODE
        let esc_dir = dir.path().join("esc-unset");
        let esc_dropin = esc_dir.join("esc.service.d");
        std::fs::create_dir_all(&esc_dropin).unwrap();
        let esc_cfg = esc_dir.join("config.env");
        let esc_gw = esc_dir.join("gateway.env");
        let esc_storage = esc_dir.join("storage.env");
        let esc_unit = esc_dir.join("esc.service");
        std::fs::write(&esc_cfg, "WORM_MODE=compliance\n").unwrap();
        std::fs::write(&esc_gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        std::fs::write(&esc_storage, "S3_BUCKET=mailblobs\n").unwrap();
        std::fs::write(
            &esc_unit,
            format!(
                "[Service]\nEnvironmentFile=-{}\nEnvironmentFile={}\n",
                esc_storage.display(),
                esc_gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&esc_unit, Some(&esc_cfg), &missing_default).is_ok());
        std::fs::write(
            esc_dropin.join("10-unset.conf"),
            "[Service]\nUnsetEnvironment=\"WORM_MODE=compli\\x61nce\"\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&esc_unit, Some(&esc_cfg), &missing_default).is_err());
        std::fs::write(
            esc_dropin.join("10-unset.conf"),
            "[Service]\nUnsetEnvironment='WORM_MODE=compli\\x61nce'\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&esc_unit, Some(&esc_cfg), &missing_default).is_err());

        // Wildcard EnvironmentFile= globbing expands sorted matches and fails closed on unmatched required globs
        let glob_dir = dir.path().join("glob-env");
        std::fs::create_dir_all(&glob_dir).unwrap();
        let glob_cfg = glob_dir.join("config.env");
        let glob_gw = glob_dir.join("gateway.env");
        let glob_extra_10 = glob_dir.join("10-extra.env");
        let glob_extra_20 = glob_dir.join("20-extra.env");
        let glob_unit = glob_dir.join("glob.service");
        std::fs::write(&glob_cfg, "HOSTNAME=mail.test\n").unwrap();
        std::fs::write(
            &glob_gw,
            "GATEWAY_ENABLED=true\nDB_DSN=postgres://app@localhost/mail\nWORM_MODE=\n",
        )
        .unwrap();
        std::fs::write(&glob_extra_10, "WORM_MODE=governance\n").unwrap();
        std::fs::write(&glob_extra_20, "WORM_MODE=\n").unwrap();
        std::fs::write(
            &glob_unit,
            format!(
                "[Service]\nEnvironmentFile={}\nEnvironmentFile=-{}\n",
                glob_dir.join("gate*.env").display(),
                glob_dir.join("*-extra.env").display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, None, &stale_default).is_ok());
        std::fs::write(&glob_extra_20, "WORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, None, &stale_default).is_err());
        // Required multi-segment glob profiles/*/storage.env skips subdirs missing storage.env and regular files
        std::fs::write(&glob_cfg, "WORM_MODE=compliance\n").unwrap();
        let profiles_dir = glob_dir.join("profiles");
        std::fs::create_dir_all(profiles_dir.join("empty")).unwrap();
        std::fs::create_dir_all(profiles_dir.join("active")).unwrap();
        std::fs::write(profiles_dir.join("note.txt"), "not a dir\n").unwrap();
        std::fs::write(
            profiles_dir.join("active").join("storage.env"),
            "S3_BUCKET=mailblobs\n",
        )
        .unwrap();
        std::fs::write(
            &glob_unit,
            format!(
                "[Service]\nEnvironmentFile={}\nEnvironmentFile={}\nEnvironmentFile=-{}\n",
                glob_dir.join("gate*.env").display(),
                profiles_dir.join("*").join("storage.env").display(),
                glob_dir.join("*-extra.env").display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, None, &stale_default).is_ok());
        // Trailing missing optional gateway.env must not shadow the preceding existing gateway.env when inferring config.env
        std::fs::write(
            &glob_unit,
            format!(
                "[Service]\nEnvironmentFile={}\nEnvironmentFile={}\nEnvironmentFile=-{}\nEnvironmentFile=-{}\n",
                glob_dir.join("gate*.env").display(),
                profiles_dir.join("*").join("storage.env").display(),
                glob_dir.join("*-extra.env").display(),
                glob_dir.join("missing").join("gateway.env").display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, None, &stale_default).is_ok());
        std::fs::write(&glob_cfg, "WORM_MODE=governance\n").unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, None, &stale_default).is_err());
        std::fs::write(&glob_cfg, "WORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, None, &stale_default).is_ok());
        std::fs::write(
            &glob_unit,
            format!(
                "[Service]\nEnvironmentFile={}\n",
                glob_dir.join("no-match-*.env").display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&glob_unit, Some(&glob_cfg), &stale_default).is_err());

        // Multi-byte UTF-8 \xC3\xA9 and octal \303\251 C-escapes decode as 'é', and unknown/truncated escapes fail closed
        let utf8_esc_dir = dir.path().join("utf8-esc");
        std::fs::create_dir_all(&utf8_esc_dir).unwrap();
        let utf8_gw = utf8_esc_dir.join("gateway.env");
        let utf8_unit = utf8_esc_dir.join("utf8.service");
        std::fs::write(&utf8_gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        std::fs::write(
            &utf8_unit,
            format!(
                "[Service]\nEnvironment=\"WORM_MODE=caf\\xC3\\xA9\"\nEnvironmentFile={}\nUnsetEnvironment=\"WORM_MODE=compli\\x61nce\"\nEnvironment=\"WORM_MODE=caf\\303\\251\"\n",
                utf8_gw.display()
            ),
        )
        .unwrap();
        assert_eq!(
            split_systemd_words("\"WORM_MODE=caf\\xC3\\xA9\"").unwrap(),
            vec!["WORM_MODE=caf\u{00e9}"]
        );
        assert_eq!(
            split_systemd_words("'WORM_MODE=caf\\303\\251'").unwrap(),
            vec!["WORM_MODE=caf\u{00e9}"]
        );
        assert!(split_systemd_words("\"WORM_MODE=\\z\"").is_err());
        assert!(split_systemd_words("\"WORM_MODE=\\x6\"").is_err());
        assert!(load_unit_env_spec_with_dirs(&utf8_unit, &[]).is_ok());
        std::fs::write(&utf8_unit, "[Service]\nEnvironment=\"WORM_MODE=\\z\"\n").unwrap();
        assert!(check_worm_gateway_ready(&utf8_unit, None, &missing_default).is_err());

        // YAML block scalars (|-), merge keys (<<: *base), !!str null bucket, !!bool, verbatim tags, and underscore numbers match render-storage
        std::fs::write(
            &yaml,
            "x_s3_base: &s3_base\n  endpoint: https://s3.base.test\n  secret_key: |-\n    block-secret\ns3:\n  <<: *s3_base\n  bucket: !!str null\n  secure: 1.0\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        std::fs::write(&cfg, format!("SETJOIN_CONFIG={}\n", yaml.display())).unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        std::fs::write(&storage, "S3_BUCKET=null\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &storage,
            "S3_ENDPOINT=https://s3.base.test\nS3_SECURE=true\nS3_BUCKET=null\nS3_ACCESS_KEY=\nS3_SECRET_KEY=block-secret\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: !!bool true\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        std::fs::write(&storage, "S3_BUCKET=mailblobs\nS3_SECURE=true\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: !<tag:yaml.org,2002:bool> true\nworm:\n  mode: compliance\n  retention_days: 1_000\n",
        )
        .unwrap();
        std::fs::write(
            &gw,
            "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=1000\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: !!float 1_0e-1\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: 1_0e-1\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: 0x_1\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: 0_1\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: !<tag:example.com,2000:custom> true\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        // Quoted "1.0" stays false (koanf bool semantics), matching render-storage
        std::fs::write(
            &yaml,
            "s3:\n  bucket: mailblobs\n  secure: \"1.0\"\nworm:\n  mode: compliance\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&storage, "S3_BUCKET=mailblobs\nS3_SECURE=false\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());

        // Exact systemd strv_env_merge + Go os.Environ() last-slot-wins semantics between WORM_MODE / WORM__MODE and S3_BUCKET / S3__BUCKET
        std::fs::write(
            &cfg,
            "WORM__MODE=\nWORM_MODE=compliance\nWORM__LEGAL_HOLD_ENABLED=false\nS3__BUCKET=ignored\nS3_BUCKET=mailblobs\n",
        )
        .unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=governance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        // In-place systemd strv_env_merge updates existing keys at their first-seen slot; the later slot wins across aliases
        std::fs::write(
            &cfg,
            "WORM_MODE=governance\nWORM__MODE=compliance\nWORM_MODE=\nS3__BUCKET=mailblobs\nS3_BUCKET=ignored\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &cfg,
            "WORM_MODE=governance\nWORM__MODE=compliance\nWORM_MODE=\nS3_BUCKET=ignored\nS3__BUCKET=mailblobs\nS3_BUCKET=still_ignored\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());

        // WORM_RETENTION_DAYS float/underscored values normalize to canonical integer days; non-canonical gateway.env or invalid values fail closed
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_RETENTION_DAYS=3650.0\n").unwrap();
        std::fs::write(
            &gw,
            "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=3650.0\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &gw,
            "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=3650\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_RETENTION_DAYS=0\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_RETENTION_DAYS=bad\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        // Explicit empty WORM_RETENTION_DAYS= and quoted/unexponented "0x10" fail closed while 0x1p+4 normalizes to 16
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_RETENTION_DAYS=\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_RETENTION_DAYS=0x10\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&cfg, "WORM_MODE=compliance\nWORM_RETENTION_DAYS=0x1p+4\n").unwrap();
        std::fs::write(
            &gw,
            "GATEWAY_ENABLED=true\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=16\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());
        // DB__DSN, YAML db.dsn, and missing-host-config malformed retention in gateway.env fail closed
        let db_missing_cfg = dir.path().join("absent-host.env");
        let db_unit = dir.path().join("db-variant.service");
        let db_gw = dir.path().join("db-sub").join("gateway.env");
        let db_storage = dir.path().join("db-sub").join("storage.env");
        let db_yaml = dir.path().join("db-variant.yaml");
        std::fs::create_dir_all(db_gw.parent().unwrap()).unwrap();
        std::fs::write(&db_storage, "S3_BUCKET=mailblobs\n").unwrap();
        std::fs::write(&db_gw, "GATEWAY_ENABLED=true\nDB__DSN=postgres://app@localhost/mail\n").unwrap();
        std::fs::write(
            &db_unit,
            format!(
                "[Service]\nEnvironmentFile={}\nEnvironmentFile={}\n",
                db_storage.display(),
                db_gw.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&db_unit, Some(&db_missing_cfg), &stale_default).is_err());
        std::fs::write(
            &db_gw,
            "GATEWAY_ENABLED=true\nDB__DSN=postgres://app@localhost/mail\nWORM_MODE=compliance\nWORM_RETENTION_DAYS=bad\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&db_unit, Some(&db_missing_cfg), &stale_default).is_err());
        std::fs::write(
            &db_yaml,
            "db:\n  dsn: postgres://app@localhost/mail\ns3:\n  bucket: mailblobs\n",
        )
        .unwrap();
        std::fs::write(
            &db_gw,
            format!("GATEWAY_ENABLED=true\nSETJOIN_CONFIG={}\n", db_yaml.display()),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&db_unit, Some(&db_missing_cfg), &stale_default).is_err());
        std::fs::write(
            &db_gw,
            format!(
                "GATEWAY_ENABLED=true\nSETJOIN_CONFIG={}\nWORM_MODE=\n",
                db_yaml.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&db_unit, Some(&db_missing_cfg), &stale_default).is_ok());

        // Case-insensitive koanf env keys (worm_mode / s3_bucket) match Go os.Environ() transform
        std::fs::write(&cfg, "worm_mode=compliance\ns3_bucket=custom-ci\n").unwrap();
        std::fs::write(&gw, "GATEWAY_ENABLED=true\nWORM_MODE=compliance\n").unwrap();
        std::fs::write(&storage, "S3_BUCKET=mailblobs\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&storage, "S3_BUCKET=custom-ci\n").unwrap();
        assert!(check_worm_gateway_ready(&unit, Some(&cfg), &stale_default).is_ok());

        // Systemd % specifiers (%%, %N) expand cleanly in EnvironmentFile/UnsetEnvironment, quoted EnvironmentFile is discarded, and unsupported specifiers (%H) fail closed
        let spec_dir = dir.path().join("spec-env");
        let spec_lit_dir = spec_dir.join("%lit");
        let spec_name_dir = spec_dir.join("spec");
        std::fs::create_dir_all(&spec_lit_dir).unwrap();
        std::fs::create_dir_all(&spec_name_dir).unwrap();
        let spec_unit = spec_dir.join("spec.service");
        std::fs::write(spec_lit_dir.join("storage.env"), "S3_BUCKET=mailblobs\n").unwrap();
        std::fs::write(
            spec_name_dir.join("gateway.env"),
            "GATEWAY_ENABLED=true\nDB_DSN=postgres://app@localhost/mail\nWORM_MODE=compliance\nLIVEKIT_API_KEY=lk\nLIVEKIT_API_SECRET=abc%def\nLIVEKIT_URL=http://127.0.0.1:7880\n",
        )
        .unwrap();
        std::fs::write(
            &spec_unit,
            format!(
                "[Service]\nEnvironmentFile={}/%%lit/storage.env\nEnvironmentFile={}/%N/gateway.env\n",
                spec_dir.display(),
                spec_dir.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&spec_unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(&cfg, "WORM_MODE=compliance\nS3_BUCKET=mailblobs\nLIVEKIT_API_KEY=lk\nLIVEKIT_API_SECRET=abc%def\nLIVEKIT_URL=http://127.0.0.1:7880\n").unwrap();
        assert!(check_worm_gateway_ready(&spec_unit, Some(&cfg), &stale_default).is_ok());
        std::fs::write(
            &spec_unit,
            format!(
                "[Service]\nEnvironmentFile={}/%%lit/storage.env\nEnvironmentFile={}/%N/gateway.env\nUnsetEnvironment=LIVEKIT_API_SECRET=abc%%def\n",
                spec_dir.display(),
                spec_dir.display()
            ),
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&spec_unit, Some(&cfg), &stale_default).is_err());
        std::fs::write(
            &spec_unit,
            "[Service]\nEnvironmentFile=\"/etc/setjoin/gateway.env\"\n",
        )
        .unwrap();
        assert!(load_unit_env_files_with_dirs(&spec_unit, &[]).unwrap().is_empty());
        std::fs::write(
            &spec_unit,
            "[Service]\nEnvironmentFile=-/etc/setjoin/%H/override.env\n",
        )
        .unwrap();
        assert!(check_worm_gateway_ready(&spec_unit, Some(&cfg), &stale_default).is_err());

        // C-unescaping runs before systemd % expansion, and specifier errors never echo directive values
        let c_name_dir = spec_dir.join("c-unescape");
        std::fs::create_dir_all(&c_name_dir).unwrap();
        std::fs::write(
            c_name_dir.join("gateway.env"),
            "GATEWAY_ENABLED=true\nDB_DSN=postgres://app@localhost/mail\nWORM_MODE=compliance\n",
        )
        .unwrap();
        let c_unit = spec_dir.join("c-unescape.service");
        std::fs::write(
            &c_unit,
            format!(
                "[Service]\nEnvironmentFile={}/%%lit/storage.env\nEnvironmentFile={}/%N/gateway.env\nEnvironment=SETJOIN_CONFIG=\\x25E/setjoin.yml\n",
                spec_dir.display(),
                spec_dir.display()
            ),
        )
        .unwrap();
        let c_spec = super::load_unit_env_spec(&c_unit).unwrap();
        let c_gw = super::load_effective_gateway_env(&c_spec).unwrap();
        assert_eq!(
            super::env_lookup(&c_gw.pairs, "SETJOIN_CONFIG").as_deref(),
            Some("/etc/setjoin.yml")
        );
        std::fs::write(
            &c_unit,
            "[Service]\nEnvironment=DB_DSN=postgres://u:supersecret@h/db FOO=%Z\n",
        )
        .unwrap();
        let redaction_err = format!(
            "{:#}",
            check_worm_gateway_ready(&c_unit, Some(&cfg), &stale_default).unwrap_err()
        );
        assert!(redaction_err.contains("Environment="));
        assert!(!redaction_err.contains("supersecret"));
        assert!(!redaction_err.contains("DB_DSN"));

        // Explicit YAML worm.retention_days: "" / null and overflowing 9223372036854775808 fail closed even when host config.env is absent
        let empty_ret_yaml = yaml_worm_settings("worm:\n  mode: compliance\n  retention_days: \"\"\n").unwrap();
        assert_eq!(empty_ret_yaml.retention_days.as_deref(), Some(""));
        let null_ret_yaml = yaml_worm_settings("worm:\n  mode: compliance\n  retention_days: null\n").unwrap();
        assert_eq!(null_ret_yaml.retention_days.as_deref(), Some(""));
        let overflow_ret_yaml = yaml_worm_settings("worm:\n  mode: compliance\n  retention_days: 9223372036854775808\n").unwrap();
        assert_eq!(overflow_ret_yaml.retention_days.as_deref(), Some("9223372036854775808"));
        for bad_ret in ["\"\"", "null", "9223372036854775808"] {
            std::fs::write(
                &db_yaml,
                format!(
                    "db:\n  dsn: postgres://app@localhost/mail\ns3:\n  bucket: mailblobs\nworm:\n  mode: compliance\n  retention_days: {bad_ret}\n"
                ),
            )
            .unwrap();
            std::fs::write(
                &db_gw,
                format!(
                    "GATEWAY_ENABLED=true\nSETJOIN_CONFIG={}\nWORM_MODE=compliance\n",
                    db_yaml.display()
                ),
            )
            .unwrap();
            assert!(check_worm_gateway_ready(&db_unit, Some(&db_missing_cfg), &stale_default).is_err());
        }

        // !!float / verbatim float tag on legacy octal and exact >2^53 i64 retention match Go, while tagged 0x/0o/0b radix floats fail closed
        let oct_float = yaml_worm_settings("worm:\n  retention_days: !!float \"0_10\"\n").unwrap();
        assert_eq!(oct_float.retention_days.as_deref(), Some("8"));
        let verbatim_oct_float = yaml_worm_settings(
            "worm:\n  retention_days: !<tag:yaml.org,2002:float> \"0_10\"\n",
        )
        .unwrap();
        assert_eq!(verbatim_oct_float.retention_days.as_deref(), Some("8"));
        for tagged_radix in [
            "worm:\n  retention_days: !!float \"0x10\"\n",
            "worm:\n  retention_days: !!float \"0o20\"\n",
            "worm:\n  retention_days: !!float \"0b10000\"\n",
            "worm:\n  retention_days: !!float \"0+10\"\n",
            "worm:\n  retention_days: !!float \"0_8\"\n",
            "worm:\n  retention_days: !!float \"0_8.5\"\n",
        ] {
            assert!(yaml_worm_settings(tagged_radix).is_err());
        }
        assert_eq!(
            parse_koanf_env_retention_days("9007199254740993").unwrap(),
            9_007_199_254_740_993
        );
    }
}
