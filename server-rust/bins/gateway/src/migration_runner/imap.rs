//! Go's `IMAPConnector` (`mailserver/internal/migration/imap_client.go`): dial under
//! the SSRF private-address policy, `LOGIN`, `LIST "" "*"`, read-only `SELECT`
//! (`EXAMINE`) and bounded `UID FETCH (RFC822 FLAGS)` pages of 100 UIDs. The
//! protocol client is deliberately small: only the verbs and response shapes the
//! connector uses.
use super::{Batch, Change, Checkpoint, Dialer, ItemKind, SourceItem};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `imapCommandDeadline`: one post-handshake command round trip.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(120);
/// `maxMigrationMessageBytes`.
pub const MAX_MESSAGE: usize = 64 << 20;
/// `sourceBatchSize`.
pub const BATCH: u32 = 100;

#[derive(Clone, Debug, Default)]
pub struct ImapConfig {
    pub host: String,
    pub port: i64,
    pub tls_mode: String,
    pub private_hosts: Vec<String>,
    pub private_cidrs: Vec<String>,
    pub username: String,
    pub password: String,
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Io for T {}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Atom(String),
    Quoted(String),
    Literal(Vec<u8>),
    Nil,
    List(Vec<Token>),
}

impl Token {
    fn text(&self) -> Option<String> {
        match self {
            Token::Atom(s) | Token::Quoted(s) => Some(s.clone()),
            Token::Literal(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    }
}

enum Seg {
    Text(Vec<u8>),
    Literal(Vec<u8>),
}

enum Response {
    Tagged { tag: String, ok: bool, text: String },
    Untagged(Vec<Seg>),
    Continuation,
}

struct Parser<'a> {
    segs: &'a [Seg],
    seg: usize,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        match self.segs.get(self.seg)? {
            Seg::Text(t) => t.get(self.pos).copied(),
            Seg::Literal(_) => None,
        }
    }
    fn bump(&mut self) {
        self.pos += 1;
    }
    fn at_literal(&self) -> bool {
        matches!(self.segs.get(self.seg), Some(Seg::Literal(_)))
    }
    fn skip_space(&mut self) {
        while self.peek() == Some(b' ') {
            self.bump();
        }
    }
    /// Move past a text segment that is exhausted (the next one is a literal).
    fn advance_seg(&mut self) {
        if let Some(Seg::Text(t)) = self.segs.get(self.seg) {
            if self.pos >= t.len() {
                self.seg += 1;
                self.pos = 0;
            }
        }
    }
    fn value(&mut self) -> Option<Token> {
        self.skip_space();
        self.advance_seg();
        if self.at_literal() {
            let Seg::Literal(b) = &self.segs[self.seg] else {
                return None;
            };
            let token = Token::Literal(b.clone());
            self.seg += 1;
            self.pos = 0;
            return Some(token);
        }
        match self.peek()? {
            b'(' => {
                self.bump();
                let mut items = vec![];
                loop {
                    self.skip_space();
                    self.advance_seg();
                    if self.peek() == Some(b')') {
                        self.bump();
                        return Some(Token::List(items));
                    }
                    if self.peek().is_none() && !self.at_literal() {
                        return Some(Token::List(items));
                    }
                    items.push(self.value()?);
                }
            }
            b'"' => {
                self.bump();
                let mut out = Vec::new();
                loop {
                    match self.peek()? {
                        b'\\' => {
                            self.bump();
                            out.push(self.peek()?);
                            self.bump();
                        }
                        b'"' => {
                            self.bump();
                            break;
                        }
                        c => {
                            out.push(c);
                            self.bump();
                        }
                    }
                }
                Some(Token::Quoted(String::from_utf8_lossy(&out).into_owned()))
            }
            _ => {
                let mut out = Vec::new();
                // `BODY[HEADER]` style atoms contain brackets and may hold spaces
                // inside the brackets only in `BODY[HEADER.FIELDS (..)]`; the
                // connector never requests those.
                while let Some(c) = self.peek() {
                    if matches!(c, b' ' | b'(' | b')') {
                        break;
                    }
                    out.push(c);
                    self.bump();
                }
                let s = String::from_utf8_lossy(&out).into_owned();
                if s.eq_ignore_ascii_case("NIL") {
                    Some(Token::Nil)
                } else {
                    Some(Token::Atom(s))
                }
            }
        }
    }
}

/// Placeholder while the plain stream is handed to the TLS handshake.
struct Closed;
impl AsyncRead for Closed {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Closed {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Go's wording for the dial errors a test can provoke.
pub fn dial_error(error: &std::io::Error) -> String {
    io_error(std::io::Error::new(error.kind(), error.to_string()))
}

fn io_error(error: std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match error.kind() {
        ConnectionRefused => "connect: connection refused".into(),
        UnexpectedEof => "EOF".into(),
        TimedOut => "i/o timeout".into(),
        ConnectionReset => "read: connection reset by peer".into(),
        BrokenPipe => "write: broken pipe".into(),
        _ => error.to_string(),
    }
}

/// One IMAP connection: tag counter and a read buffer.
pub struct Conn {
    io: Box<dyn Io>,
    buf: Vec<u8>,
    tag: u32,
}

impl Conn {
    fn new(io: Box<dyn Io>) -> Self {
        Conn {
            io,
            buf: Vec::new(),
            tag: 0,
        }
    }

    async fn fill(&mut self) -> Result<(), String> {
        let mut chunk = [0u8; 16384];
        let n = self.io.read(&mut chunk).await.map_err(io_error)?;
        if n == 0 {
            return Err("EOF".into());
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    async fn line(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if let Some(at) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = self.buf[..at].to_vec();
                self.buf.drain(..at + 2);
                return Ok(line);
            }
            self.fill().await?;
        }
    }

    async fn bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            self.fill().await?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    async fn response(&mut self) -> Result<Response, String> {
        let first = self.line().await?;
        if first.first() == Some(&b'+') {
            return Ok(Response::Continuation);
        }
        if first.first() != Some(&b'*') {
            // Tagged: `<tag> OK|NO|BAD [CODE] text`.
            let text = String::from_utf8_lossy(&first).into_owned();
            let mut parts = text.splitn(3, ' ');
            let tag = parts.next().unwrap_or("").to_owned();
            let status = parts.next().unwrap_or("").to_ascii_uppercase();
            let rest = parts.next().unwrap_or("");
            // go-imap's `StatusResp.Info` excludes the response code.
            let info = if let Some(stripped) = rest.strip_prefix('[') {
                stripped
                    .split_once(']')
                    .map(|(_, t)| t.trim_start())
                    .unwrap_or("")
            } else {
                rest
            };
            return Ok(Response::Tagged {
                tag,
                ok: status == "OK",
                text: info.to_owned(),
            });
        }
        let mut segs = vec![];
        let mut line = first[1..].to_vec();
        loop {
            // A trailing `{N}` (or `{N+}`) announces a literal of N bytes.
            let literal = (line.last() == Some(&b'}'))
                .then(|| line.iter().rposition(|&c| c == b'{'))
                .flatten()
                .and_then(|open| {
                    let digits = &line[open + 1..line.len() - 1];
                    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
                    std::str::from_utf8(digits)
                        .ok()?
                        .parse::<usize>()
                        .ok()
                        .map(|n| (open, n))
                });
            match literal {
                Some((open, n)) => {
                    line.truncate(open);
                    segs.push(Seg::Text(line));
                    let data = self.bytes(n).await?;
                    segs.push(Seg::Literal(data));
                    line = self.line().await?;
                }
                None => {
                    segs.push(Seg::Text(line));
                    return Ok(Response::Untagged(segs));
                }
            }
        }
    }

    /// Send one command and collect its untagged responses.
    async fn command(&mut self, text: &str) -> Result<Vec<Vec<Seg>>, String> {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.io
            .write_all(format!("{tag} {text}\r\n").as_bytes())
            .await
            .map_err(io_error)?;
        self.io.flush().await.map_err(io_error)?;
        let mut out = vec![];
        loop {
            match self.response().await? {
                Response::Untagged(segs) => out.push(segs),
                Response::Continuation => {}
                Response::Tagged {
                    tag: t, ok, text, ..
                } if t == tag => {
                    return if ok { Ok(out) } else { Err(text) };
                }
                Response::Tagged { .. } => {}
            }
        }
    }
}

/// A quoted string, or a synchronising literal when the text needs one.
fn argument(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Modified UTF-7 (RFC 3501 section 5.1.3), both directions.
pub fn utf7_decode(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let mut b64 = String::new();
        let mut closed = false;
        for d in chars.by_ref() {
            if d == '-' {
                closed = true;
                break;
            }
            b64.push(d);
        }
        if !closed {
            out.push('&');
            out.push_str(&b64);
            continue;
        }
        if b64.is_empty() {
            out.push('&');
            continue;
        }
        let std: String = b64.replace(',', "/");
        let pad = (4 - std.len() % 4) % 4;
        let padded = format!("{std}{}", "=".repeat(pad));
        use base64::{engine::general_purpose::STANDARD, Engine};
        match STANDARD.decode(padded.as_bytes()) {
            Ok(bytes) => {
                let units: Vec<u16> = bytes
                    .chunks(2)
                    .filter(|p| p.len() == 2)
                    .map(|p| u16::from_be_bytes([p[0], p[1]]))
                    .collect();
                out.push_str(&String::from_utf16_lossy(&units));
            }
            Err(_) => {
                out.push('&');
                out.push_str(&b64);
                out.push('-');
            }
        }
    }
    out
}

pub fn utf7_encode(s: &str) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    let mut out = String::new();
    let mut pending: Vec<u16> = vec![];
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&STANDARD_NO_PAD.encode(bytes).replace('/', ","));
        out.push('-');
        pending.clear();
    };
    for c in s.chars() {
        if ('\u{20}'..='\u{7e}').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut units = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut units));
        }
    }
    flush(&mut pending, &mut out);
    out
}

pub struct Folder {
    pub name: String,
    pub path: Vec<String>,
    pub tags: Vec<String>,
}

/// `folderPath`.
pub fn folder_path(name: &str, delimiter: &str) -> Vec<String> {
    let delim = if delimiter.is_empty() { "/" } else { delimiter };
    name.split(delim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `folderTags`: special-use attributes, well-known names, the i18n table, then the leaf.
pub fn folder_tags(name: &str, delimiter: &str, attrs: &[String]) -> Vec<String> {
    for a in attrs {
        let tag = match a.to_lowercase().as_str() {
            "\\sent" => "Sent",
            "\\drafts" => "Drafts",
            "\\trash" => "Trash",
            "\\junk" | "\\spam" => "Spam",
            "\\archive" => "Archive",
            _ => continue,
        };
        return vec![tag.into()];
    }
    let lower = go_lower(name);
    let ends = |s: &[&str]| s.iter().any(|x| lower.ends_with(x));
    let tag = if lower == "inbox" {
        Some("Inbox")
    } else if lower == "sent" || ends(&[".sent", "/sent"]) {
        Some("Sent")
    } else if lower == "drafts" || ends(&[".drafts", "/drafts"]) {
        Some("Drafts")
    } else if lower == "trash" || lower == "deleted items" || ends(&[".trash", "/trash"]) {
        Some("Trash")
    } else if lower == "junk"
        || lower == "spam"
        || lower == "junk e-mail"
        || ends(&[".junk", "/spam"])
    {
        Some("Spam")
    } else if lower == "archive" || ends(&[".archive", "/archive"]) {
        Some("Archive")
    } else {
        None
    };
    if let Some(tag) = tag {
        return vec![tag.into()];
    }
    if let Some((_, tag)) = super::folder_i18n::NAMES.iter().find(|(n, _)| *n == name) {
        return vec![(*tag).into()];
    }
    let delim = if delimiter.is_empty() { "/" } else { delimiter };
    let parts: Vec<&str> = name.split(delim).collect();
    let mut leaf = parts[parts.len() - 1];
    if leaf.is_empty() && parts.len() > 1 {
        leaf = parts[parts.len() - 2];
    }
    if leaf.is_empty() {
        vec![]
    } else {
        vec![leaf.into()]
    }
}

/// `strings.ToLower` (Unicode simple case folding of each rune).
fn go_lower(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut l = c.to_lowercase();
            match (l.next(), l.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        })
        .collect()
}

fn token_i64(token: &Token) -> Option<i64> {
    token.text()?.parse().ok()
}

pub struct ImapConnector {
    pub config: ImapConfig,
    dialer: Dialer,
    /// Durable resume state: folder -> last imported UID and its UIDVALIDITY.
    resume: BTreeMap<String, i64>,
    validities: BTreeMap<String, u32>,
    session: Option<Session>,
}

struct Session {
    conn: Conn,
    folders: Vec<Folder>,
    folder: usize,
    status: Option<FolderStatus>,
    next_uid: u32,
}

#[derive(Clone, Copy)]
struct FolderStatus {
    uid_validity: u32,
    high_water: u32,
}

impl ImapConnector {
    pub fn new(config: ImapConfig, dialer: Dialer) -> Self {
        ImapConnector {
            config,
            dialer,
            resume: BTreeMap::new(),
            validities: BTreeMap::new(),
            session: None,
        }
    }

    /// `RestoreSourceState`: legacy UIDs first, then the durable checkpoints.
    pub fn restore(
        &mut self,
        legacy: &BTreeMap<String, i64>,
        durable: &[(String, String, serde_json::Value)],
    ) -> Result<(), String> {
        self.resume = legacy.clone();
        self.validities.clear();
        for (scope, kind, value) in durable {
            if kind != "imap_uid" {
                return Err(format!(
                    "restore source checkpoint {}: kind {} is not {}",
                    go_quote(scope),
                    go_quote(kind),
                    go_quote("imap_uid")
                ));
            }
            let uid = value.get("uid").or_else(|| value.get("lastUID"));
            let validity = value.get("uidValidity").and_then(|v| v.as_u64());
            let (Some(uid), Some(validity)) = (uid.and_then(|v| v.as_u64()), validity) else {
                return Err(format!(
                    "restore IMAP checkpoint {}: decode IMAP checkpoint: missing uid",
                    go_quote(scope)
                ));
            };
            self.resume.insert(scope.clone(), uid as i64);
            self.validities.insert(scope.clone(), validity as u32);
        }
        Ok(())
    }

    /// `ResolveSourceIdentity`: (mailbox key, selector digest).
    pub fn identity(&self) -> Result<(String, String), String> {
        use sha2::{Digest, Sha256};
        let selector = format!(
            "{}\0{}",
            go_trim(&go_lower(&self.config.host)),
            go_trim(&self.config.username)
        );
        if selector.trim_matches('\0').is_empty() {
            return Err("IMAP source mailbox selector is required".into());
        }
        let digest = hex(&Sha256::digest(format!("imap\0{selector}").as_bytes()));
        Ok((format!("imap:{digest}"), digest))
    }

    async fn dial(&self) -> Result<Conn, String> {
        let port = u16::try_from(self.config.port)
            .map_err(|_| format!("dial tcp: address {}: invalid port", self.config.port))?;
        let stream = self
            .dialer
            .dial(
                &self.config.host,
                port,
                &self.config.private_hosts,
                &self.config.private_cidrs,
            )
            .await
            .map_err(|e| format!("IMAP destination is not allowed: {e}"))?;
        let tls = |stream: Box<dyn Io>| async {
            let connector = tls_connector();
            let name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(self.config.host.clone())
                    .map_err(|e| format!("IMAP TLS handshake: {e}"))?;
            connector
                .connect(name, stream)
                .await
                .map_err(|e| format!("IMAP TLS handshake: {e}"))
        };
        match self.config.tls_mode.as_str() {
            "tls" => {
                let secured = tls(stream).await?;
                let mut conn = Conn::new(Box::new(secured));
                greeting(&mut conn).await?;
                Ok(conn)
            }
            "starttls" => {
                let mut conn = Conn::new(stream);
                greeting(&mut conn).await?;
                timed(conn.command("STARTTLS"))
                    .await
                    .map_err(|e| format!("STARTTLS failed: {e}"))?;
                let plain = std::mem::replace(&mut conn.io, Box::new(Closed));
                let secured = tls(plain).await?;
                Ok(Conn::new(Box::new(secured)))
            }
            "none" => {
                let mut conn = Conn::new(stream);
                greeting(&mut conn).await?;
                Ok(conn)
            }
            other => Err(format!("unsupported IMAP TLS mode {}", go_quote(other))),
        }
    }

    async fn login(&self, conn: &mut Conn) -> Result<(), String> {
        timed(conn.command(&format!(
            "LOGIN {} {}",
            argument(&self.config.username),
            argument(&self.config.password)
        )))
        .await
        .map_err(|e| format!("imap login: {e}"))?;
        Ok(())
    }

    /// `TestConnection`: dial, log in, list the root.
    pub async fn test_connection(&self) -> Result<(), String> {
        let mut conn = self.dial().await?;
        self.login(&mut conn).await?;
        timed(conn.command("LIST \"\" \"*\""))
            .await
            .map_err(|e| format!("imap list: {e}"))?;
        let _ = timed(conn.command("LOGOUT")).await;
        Ok(())
    }

    /// Admin `test-connection` without credentials: reachability and TLS only.
    pub async fn reachability(&self) -> Result<(), String> {
        let mut conn = self.dial().await?;
        let _ = timed(conn.command("LOGOUT")).await;
        Ok(())
    }

    async fn list_folders(conn: &mut Conn) -> Result<Vec<Folder>, String> {
        let responses = timed(conn.command("LIST \"\" \"*\""))
            .await
            .map_err(|e| format!("imap list: {e}"))?;
        let mut folders = vec![];
        for segs in responses {
            let mut p = Parser {
                segs: &segs,
                seg: 0,
                pos: 0,
            };
            let Some(Token::Atom(kind)) = p.value() else {
                continue;
            };
            if !kind.eq_ignore_ascii_case("LIST") {
                continue;
            }
            let (Some(Token::List(attrs)), Some(delim), Some(name)) =
                (p.value(), p.value(), p.value())
            else {
                continue;
            };
            let attrs: Vec<String> = attrs.iter().filter_map(Token::text).collect();
            let delimiter = delim.text().unwrap_or_default();
            let Some(name) = name.text() else { continue };
            let name = utf7_decode(&name);
            if attrs.iter().any(|a| a.eq_ignore_ascii_case("\\Noselect")) {
                continue;
            }
            folders.push(Folder {
                path: folder_path(&name, &delimiter),
                tags: folder_tags(&name, &delimiter, &attrs),
                name,
            });
        }
        Ok(folders)
    }

    /// The next closed page, or `None` when every folder is done. Each call reads
    /// at most one UID range of 100.
    pub async fn next_batch(&mut self) -> Result<Option<Batch>, String> {
        if self.session.is_none() {
            let mut conn = self.dial().await?;
            self.login(&mut conn).await?;
            let folders = Self::list_folders(&mut conn).await?;
            self.session = Some(Session {
                conn,
                folders,
                folder: 0,
                status: None,
                next_uid: 0,
            });
        }
        loop {
            let session = self.session.as_mut().expect("session");
            if session.folder >= session.folders.len() {
                let _ = timed(session.conn.command("LOGOUT")).await;
                self.session = None;
                return Ok(None);
            }
            let name = session.folders[session.folder].name.clone();
            if session.status.is_none() {
                let responses = timed(
                    session
                        .conn
                        .command(&format!("EXAMINE {}", argument(&utf7_encode(&name)))),
                )
                .await
                .map_err(|e| format!("imap select {}: {e}", go_quote(&name)))?;
                let (mut validity, mut next) = (0u32, 0u32);
                for segs in &responses {
                    let mut p = Parser {
                        segs,
                        seg: 0,
                        pos: 0,
                    };
                    // `* OK [UIDVALIDITY n] ...` (the code is part of the text).
                    if let Some(Seg::Text(t)) = segs.first() {
                        let text = String::from_utf8_lossy(t).into_owned();
                        for (key, slot) in [("UIDVALIDITY", &mut validity), ("UIDNEXT", &mut next)]
                        {
                            if let Some(at) = text.find(&format!("[{key} ")) {
                                let rest = &text[at + key.len() + 2..];
                                if let Some(end) = rest.find(']') {
                                    *slot = rest[..end].trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                    let _ = p.value();
                }
                let start = {
                    let last = self.resume.get(&name).copied().filter(|n| *n > 0);
                    match last {
                        Some(last)
                            if u64::try_from(last).is_ok_and(|n| n <= u32::MAX as u64)
                                && self.validities.get(&name).copied().unwrap_or(0) == validity =>
                        {
                            last as u32 + 1
                        }
                        _ => 1,
                    }
                };
                let session = self.session.as_mut().expect("session");
                if next <= start {
                    session.folder += 1;
                    continue;
                }
                session.status = Some(FolderStatus {
                    uid_validity: validity,
                    high_water: next - 1,
                });
                session.next_uid = start;
            }
            let session = self.session.as_mut().expect("session");
            let status = session.status.expect("status");
            let range_start = session.next_uid;
            let range_end = range_start
                .checked_add(BATCH - 1)
                .filter(|e| *e <= status.high_water)
                .unwrap_or(status.high_water);
            let responses = timed(session.conn.command(&format!(
                "UID FETCH {range_start}:{range_end} (RFC822 FLAGS)"
            )))
            .await?;
            let folder = &session.folders[session.folder];
            let mut items: Vec<SourceItem> = vec![];
            let mut oversize = None;
            for segs in &responses {
                let mut p = Parser {
                    segs,
                    seg: 0,
                    pos: 0,
                };
                let _seq = p.value();
                let Some(Token::Atom(kind)) = p.value() else {
                    continue;
                };
                if !kind.eq_ignore_ascii_case("FETCH") {
                    continue;
                }
                let Some(Token::List(fields)) = p.value() else {
                    continue;
                };
                let (mut uid, mut raw, mut flags) = (0u32, None, vec![]);
                let mut it = fields.iter();
                while let Some(key) = it.next() {
                    let Some(key) = key.text() else { continue };
                    let value = it.next();
                    let upper = key.to_ascii_uppercase();
                    if upper == "UID" {
                        uid = value.and_then(token_i64).unwrap_or(0) as u32;
                    } else if upper == "FLAGS" {
                        if let Some(Token::List(l)) = value {
                            flags = l.iter().filter_map(Token::text).collect();
                        }
                    } else if upper == "RFC822" || upper.starts_with("BODY[") {
                        raw = match value {
                            Some(Token::Literal(b)) => Some(b.clone()),
                            Some(Token::Quoted(s)) => Some(s.clone().into_bytes()),
                            _ => None,
                        };
                    }
                }
                let _ = &flags;
                if uid < range_start || uid > range_end {
                    continue;
                }
                let Some(raw) = raw else { continue };
                if raw.len() > MAX_MESSAGE {
                    oversize.get_or_insert_with(|| {
                        format!(
                            "RFC822 message exceeds the {} MiB migration cap",
                            MAX_MESSAGE >> 20
                        )
                    });
                    continue;
                }
                items.push(SourceItem {
                    kind: ItemKind::Mail,
                    change: Change::Upsert,
                    object_id: format!("imap:{}:{}:{}", folder.name, status.uid_validity, uid),
                    version: hex(&<sha2::Sha256 as sha2::Digest>::digest(&raw)),
                    folder_id: folder.name.clone(),
                    raw,
                    ics: String::new(),
                    vcf: String::new(),
                    folder_path: folder.path.clone(),
                    tags: folder.tags.clone(),
                    uid,
                    uid_validity: status.uid_validity,
                });
            }
            if let Some(error) = oversize {
                return Err(error);
            }
            items.sort_by_key(|i| i.uid);
            let batch = Batch {
                items,
                checkpoint: Checkpoint::Imap {
                    folder: folder.name.clone(),
                    uid: range_end,
                    uid_validity: status.uid_validity,
                },
            };
            if range_end == status.high_water {
                session.status = None;
                session.folder += 1;
            } else {
                session.next_uid = range_end + 1;
            }
            return Ok(Some(batch));
        }
    }
}

async fn greeting(conn: &mut Conn) -> Result<(), String> {
    match tokio::time::timeout(COMMAND_DEADLINE, conn.response()).await {
        Ok(Ok(Response::Untagged(_))) => Ok(()),
        Ok(Ok(_)) => Err("unexpected greeting".into()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("i/o timeout".into()),
    }
}

async fn timed<T>(f: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    match tokio::time::timeout(COMMAND_DEADLINE, f).await {
        Ok(r) => r,
        Err(_) => Err("i/o timeout".into()),
    }
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn go_trim(s: &str) -> String {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{85}')
        .to_owned()
}

/// Go's `%q` for the strings these messages quote.
pub(crate) fn go_quote(s: &str) -> String {
    setjoin_mailboxes::private_policy::quote(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf7_round_trips() {
        for s in ["INBOX", "Sent Items", "收件箱", "a&b", "Entwürfe/Ä"] {
            assert_eq!(utf7_decode(&utf7_encode(s)), s);
        }
        assert_eq!(utf7_encode("a&b"), "a&-b");
        assert_eq!(utf7_decode("&AOQ-"), "ä");
    }

    #[test]
    fn tags_follow_go() {
        let tags = |n: &str, d: &str, a: &[&str]| {
            folder_tags(n, d, &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(tags("INBOX", "/", &[]), ["Inbox"]);
        assert_eq!(tags("Whatever", "/", &["\\Sent"]), ["Sent"]);
        assert_eq!(tags("Foo.Trash", ".", &[]), ["Trash"]);
        assert_eq!(tags("收件箱", "/", &[]), ["Inbox"]);
        assert_eq!(tags("Work/Projects", "/", &[]), ["Projects"]);
        assert_eq!(folder_path("Work/Projects", "/"), ["Work", "Projects"]);
    }

    #[test]
    fn parser_reads_fetch_with_literal() {
        let segs = vec![
            Seg::Text(b"3 FETCH (UID 12 FLAGS (\\Seen \\Flagged) RFC822 ".to_vec()),
            Seg::Literal(b"Subject: x\r\n\r\nhi".to_vec()),
            Seg::Text(b")".to_vec()),
        ];
        let mut p = Parser {
            segs: &segs,
            seg: 0,
            pos: 0,
        };
        assert_eq!(p.value(), Some(Token::Atom("3".into())));
        assert_eq!(p.value(), Some(Token::Atom("FETCH".into())));
        let Some(Token::List(items)) = p.value() else {
            panic!("list")
        };
        assert_eq!(items.len(), 6);
        assert_eq!(items[5], Token::Literal(b"Subject: x\r\n\r\nhi".to_vec()));
    }
}
