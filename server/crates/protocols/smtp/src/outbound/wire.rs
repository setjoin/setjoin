//! Frozen textproto sequencing with bounded command and DATA phases.
use super::dane;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream},
    net::TcpStream,
};
use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig};
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type BoxStream = Box<dyn Stream>;
#[derive(Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub command: Duration,
    pub data: Duration,
}
impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            command: Duration::from_secs(300),
            data: Duration::from_secs(600),
        }
    }
}
pub(super) struct Reply {
    pub tls: bool,
    pub code: i32,
    pub text: String,
}
pub(super) struct Failure {
    pub tls: bool,
    pub code: i32,
    pub text: String,
    pub error: String,
}
impl From<String> for Failure {
    fn from(error: String) -> Self {
        Self {
            tls: false,
            code: 0,
            text: String::new(),
            error,
        }
    }
}
fn code(text: &str) -> i32 {
    let b = text.as_bytes();
    if b.len() >= 3 && b[..3].iter().all(u8::is_ascii_digit) {
        text[..3].parse().unwrap_or(0)
    } else {
        0
    }
}
fn refused(kind: &str, text: String, tls: bool) -> Failure {
    Failure {
        tls,
        code: code(&text),
        error: format!("{kind}: {text}"),
        text,
    }
}
pub(super) struct Session {
    io: BufStream<BoxStream>,
    pub used: Instant,
    pub tls: bool,
    /// True only when a TLSA record matched this session's chain at handshake.
    pub dane: bool,
    peer: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    deadline: tokio::time::Instant,
    data_timeout: Duration,
    addresses: String,
}
impl Session {
    pub fn new(socket: TcpStream, timeouts: Timeouts) -> Self {
        let addresses = format!(
            "{}->{}",
            socket
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_default(),
            socket
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default()
        );
        Self {
            io: BufStream::new(Box::new(socket)),
            used: Instant::now(),
            tls: false,
            dane: false,
            peer: Vec::new(),
            deadline: tokio::time::Instant::now() + timeouts.command,
            data_timeout: timeouts.data,
            addresses,
        }
    }
    pub fn rearm(&mut self, timeouts: Timeouts) {
        self.deadline = tokio::time::Instant::now() + timeouts.command;
        self.data_timeout = timeouts.data;
    }
    fn expired(&self, kind: &str) -> String {
        format!("{kind} tcp {}: i/o timeout", self.addresses)
    }
    pub async fn line(&mut self) -> Result<String, String> {
        let mut line = String::new();
        let read = tokio::time::timeout_at(self.deadline, self.io.read_line(&mut line))
            .await
            .map_err(|_| self.expired("read"))?
            .map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("EOF".into());
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }
    async fn write_command(&mut self, line: &str) -> Result<(), String> {
        let data = format!("{line}\r\n");
        tokio::time::timeout_at(self.deadline, async {
            self.io.write_all(data.as_bytes()).await?;
            self.io.flush().await
        })
        .await
        .map_err(|_| self.expired("write"))?
        .map_err(|e: std::io::Error| e.to_string())
    }
    pub async fn command(&mut self, line: &str) -> Result<String, String> {
        self.write_command(line).await?;
        self.line().await
    }
    pub async fn ehlo(&mut self, hostname: &str) -> Result<bool, String> {
        self.write_command(&format!("EHLO {hostname}"))
            .await
            .map_err(|e| format!("ehlo: {e}"))?;
        let mut tls = false;
        loop {
            let line = self
                .line()
                .await
                .map_err(|e| format!("ehlo response: {e}"))?;
            if line.to_uppercase().starts_with("250-STARTTLS") {
                tls = true
            };
            if line.starts_with("250 ") {
                return Ok(tls);
            }
        }
    }
    /// Whether the current TLSA records still match the chain this session proved.
    pub fn dane_still_matches(
        &self,
        host: &str,
        trust: &dane::Trust,
        policy: Option<&dane::Policy>,
    ) -> bool {
        let (Some(end_entity), Ok(name)) = (
            self.peer.first(),
            ServerName::try_from(host.trim_end_matches('.').to_owned()),
        ) else {
            return false;
        };
        crate::mutants::on("dane-pool-trusts-label")
            || matches!(
                trust.verify(
                    policy,
                    end_entity,
                    &self.peer[1..],
                    &name,
                    tokio_rustls::rustls::pki_types::UnixTime::now(),
                ),
                Ok(true)
            )
    }
    pub async fn upgrade(
        mut self,
        host: &str,
        hostname: &str,
        trust: Arc<dane::Trust>,
        policy: Option<Arc<dane::Policy>>,
    ) -> Result<Self, Failure> {
        self.write_command("STARTTLS")
            .await
            .map_err(|e| format!("starttls: {e}"))?;
        let line = self
            .line()
            .await
            .map_err(|e| format!("starttls response: {e}"))?;
        if !line.starts_with("220") {
            return Err(format!("starttls rejected: {line}").into());
        }
        let name = ServerName::try_from(host.trim_end_matches('.').to_owned())
            .map_err(|e| e.to_string())?;
        let deadline = self.deadline;
        let addresses = self.addresses.clone();
        let outcome = Arc::new(std::sync::Mutex::new(dane::Outcome::default()));
        let config = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(dane::Verifier {
                trust,
                policy,
                outcome: outcome.clone(),
            }))
            .with_no_client_auth(),
        );
        let handshake = tokio::time::timeout_at(
            deadline,
            tokio_rustls::TlsConnector::from(config).connect(name, self.io.into_inner()),
        )
        .await
        .map_err(|_| format!("tls handshake: read tcp {addresses}: i/o timeout"))?;
        let upgraded = match handshake {
            Ok(upgraded) => upgraded,
            Err(error) => {
                if outcome.lock().expect("dane outcome").mismatch {
                    return Err(format!("DANE: certificate does not match the authenticated TLSA records for {host} — delivery rejected per RFC 7672 §2.2").into());
                }
                return Err(format!("tls handshake: {error}").into());
            }
        };
        {
            let outcome = outcome.lock().expect("dane outcome");
            self.dane = outcome.matched || crate::mutants::on("dane-pool-trusts-label");
            self.peer = outcome.chain.clone();
        }
        self.io = BufStream::new(Box::new(upgraded));
        self.tls = true;
        self.ehlo(hostname).await.map_err(|e| {
            format!(
                "ehlo after tls: {}",
                e.strip_prefix("ehlo response: ")
                    .or_else(|| e.strip_prefix("ehlo: "))
                    .unwrap_or(&e)
            )
        })?;
        Ok(self)
    }
    pub async fn send(&mut self, from: &str, to: &str, raw: &[u8]) -> Result<Reply, Failure> {
        for address in [from, to] {
            if let Some(byte) = address.bytes().find(|c| *c < 0x20 || *c == 0x7f) {
                return Err(format!(
                    "smtp: envelope address contains invalid character 0x{byte:02X}"
                )
                .into());
            }
        }
        // Go's envelope gate intentionally discards transport errors and exposes the
        // (possibly empty) response, unlike the greeting and EHLO paths.
        let line = self
            .command(&format!("MAIL FROM:<{from}>"))
            .await
            .unwrap_or_default();
        if !line.starts_with("250") {
            return Err(refused("mail from rejected", line, self.tls));
        }
        let line = self
            .command(&format!("RCPT TO:<{to}>"))
            .await
            .unwrap_or_default();
        if !line.starts_with("250") {
            return Err(refused("rcpt to rejected", line, self.tls));
        }
        self.deadline = tokio::time::Instant::now() + self.data_timeout;
        self.write_command("DATA")
            .await
            .map_err(|e| format!("data: {e}"))?;
        let line = self.line().await.unwrap_or_default();
        if !line.starts_with("354") {
            return Err(refused("data rejected", line, self.tls));
        }
        let body = crate::mail_auth::outbound_data_frame(raw);
        tokio::time::timeout_at(self.deadline, self.io.write_all(&body))
            .await
            .map_err(|_| format!("write message body: {}", self.expired("write")))?
            .map_err(|e| format!("write message body: {e}"))?;
        tokio::time::timeout_at(self.deadline, self.io.flush())
            .await
            .map_err(|_| format!("flush message body: {}", self.expired("write")))?
            .map_err(|e| format!("flush message body: {e}"))?;
        let line = self.line().await.unwrap_or_default();
        if !line.starts_with("250") {
            return Err(refused("delivery rejected", line, self.tls));
        }
        Ok(Reply {
            tls: self.tls,
            code: code(&line),
            text: line,
        })
    }
}
