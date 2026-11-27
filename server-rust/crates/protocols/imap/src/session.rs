//! One connection's command loop (`handleConn`) and the session-level commands.
use crate::{
    auth,
    conn::{Conn, Io, LineError, READ_TIMEOUT},
    messages::operation_id,
    registry::SessionRelease,
    tracker::UserSlot,
    Server, TlsMode,
};
use setjoin_authz::principals::{
    MailboxPrincipal, MutateCapability, ReadCapability, TxFactory, UserPrincipal,
};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId},
};
use setjoin_pg::Type;
use sha2::{Digest as _, Sha256};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, time::timeout};

const HANDSHAKE: Duration = Duration::from_secs(30);

pub(crate) struct Session {
    pub(crate) server: Arc<Server>,
    pub(crate) conn: Conn,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) secure: bool,
    pub(crate) authed: bool,
    pub(crate) user_id: i64,
    pub(crate) user_email: String,
    pub(crate) client_ip: String,
    pub(crate) user_principal: Option<UserPrincipal>,
    pub(crate) principal: Option<MailboxPrincipal>,
    pub(crate) release: Option<UserSlot>,
    pub(crate) session_release: Option<SessionRelease>,
    pub(crate) close_tx: Arc<watch::Sender<bool>>,
    pub(crate) close_rx: watch::Receiver<bool>,
    pub(crate) selected: String,
    pub(crate) mailbox_id: i64,
    pub(crate) tag_id: i64,
    pub(crate) read_only: bool,
    pub(crate) use_membership_uid: bool,
    pub(crate) out: Vec<u8>,
}

pub(crate) async fn handle(server: Arc<Server>, socket: tokio::net::TcpStream) {
    let peer = socket.peer_addr().ok();
    let io = if server.mode == TlsMode::Implicit {
        let Some(tls) = server.tls.clone() else {
            return;
        };
        match timeout(
            HANDSHAKE,
            tokio_rustls::TlsAcceptor::from(tls).accept(socket),
        )
        .await
        {
            Ok(Ok(stream)) => Io::Tls(Box::new(stream)),
            _ => return,
        }
    } else {
        Io::Plain(socket)
    };
    let (close_tx, close_rx) = watch::channel(false);
    let mut session = Session {
        secure: server.mode == TlsMode::Implicit,
        server,
        conn: Conn::new(io),
        peer,
        authed: false,
        user_id: 0,
        user_email: String::new(),
        client_ip: String::new(),
        user_principal: None,
        principal: None,
        release: None,
        session_release: None,
        close_tx: Arc::new(close_tx),
        close_rx,
        selected: String::new(),
        mailbox_id: 0,
        tag_id: 0,
        read_only: false,
        use_membership_uid: false,
        out: Vec::new(),
    };
    session.run().await;
}

/// Go's `strings.Trim(s, "\"")` / `splitIMAPArgs` operate on the joined,
/// whitespace-normalised argument string.
pub(crate) fn split_args(args: &str) -> Vec<&str> {
    let b = args.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += 1;
            }
            if i < b.len() {
                i += 1;
            }
        } else {
            while i < b.len() && b[i] != b' ' && b[i] != b'\t' {
                i += 1;
            }
        }
        out.push(&args[start..i]);
    }
    out
}

pub(crate) fn canonical_mailbox(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        "Inbox".into()
    } else {
        name.into()
    }
}

impl Session {
    pub(crate) fn reply(&mut self, tag: &str, msg: &str) {
        self.out
            .extend_from_slice(format!("{tag} {msg}\r\n").as_bytes());
    }

    pub(crate) async fn flush(&mut self) -> bool {
        if *self.close_rx.borrow() {
            self.out.clear();
            return false;
        }
        let out = std::mem::take(&mut self.out);
        out.is_empty() || self.conn.write_all(&out).await.is_ok()
    }

    pub(crate) fn capabilities(&self) -> String {
        let mut caps = String::from("IMAP4rev2 LOGIN-REFERRALS ID ENABLE");
        if !self.secure && self.server.tls.is_some() {
            caps.push_str(" STARTTLS");
        }
        if !self.secure && self.server.mode != TlsMode::None {
            caps.push_str(" LOGINDISABLED");
        }
        caps
    }

    pub(crate) fn reject_plaintext_auth(&mut self, tag: &str) -> bool {
        if self.server.mode != TlsMode::None && !self.secure {
            self.reply(tag, "NO [PRIVACYREQUIRED] Must issue STARTTLS first");
            return true;
        }
        false
    }

    /// Every identity transition runs this before the new identity is installed.
    pub(crate) fn reset_selected(&mut self) {
        self.selected.clear();
        self.mailbox_id = 0;
        self.tag_id = 0;
        self.read_only = false;
        self.use_membership_uid = false;
    }

    async fn next_line(&mut self) -> Option<Vec<u8>> {
        let mut closed = self.close_rx.clone();
        tokio::select! {
            _ = async { let _ = closed.wait_for(|v| *v).await; } => None,
            line = timeout(READ_TIMEOUT, self.conn.read_line()) => match line {
                Ok(Ok(line)) => Some(line),
                Ok(Err(LineError::TooLong)) => {
                    self.reply("*", "BAD line too long");
                    self.flush().await;
                    None
                }
                _ => None,
            },
        }
    }

    /// Continuation line of AUTHENTICATE (`readLineLimited`, no reply on failure).
    pub(crate) async fn continuation(&mut self) -> Option<String> {
        if !self.flush().await {
            return None;
        }
        let mut closed = self.close_rx.clone();
        let line = tokio::select! {
            _ = async { let _ = closed.wait_for(|v| *v).await; } => return None,
            line = timeout(READ_TIMEOUT, self.conn.read_line()) => line,
        };
        let Ok(Ok(line)) = line else { return None };
        Some(String::from_utf8_lossy(&line).trim().to_string())
    }

    async fn run(&mut self) {
        let greeting = format!("OK [CAPABILITY {}] mailserver ready", self.capabilities());
        self.reply("*", &greeting);
        if !self.flush().await {
            return;
        }
        loop {
            let Some(raw) = self.next_line().await else {
                return;
            };
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                self.reply(parts[0], "BAD Command not understood");
                if !self.flush().await {
                    return;
                }
                continue;
            }
            let tag = parts[0];
            let cmd = parts[1].to_uppercase();
            let args = parts[2..].join(" ");
            let mut quit = false;
            match cmd.as_str() {
                "CAPABILITY" => {
                    let caps = format!("CAPABILITY {}", self.capabilities());
                    self.reply("*", &caps);
                    self.reply(tag, "OK CAPABILITY completed");
                }
                "NOOP" => self.reply(tag, "OK NOOP completed"),
                "LOGOUT" => {
                    self.reply("*", "BYE Logging out");
                    self.reply(tag, "OK LOGOUT completed");
                    quit = true;
                }
                "LOGIN" => auth::login(self, tag, &args).await,
                "AUTHENTICATE" => auth::authenticate(self, tag, &args).await,
                "SELECT" | "EXAMINE" => self.select(tag, &cmd, &args).await,
                "LSUB" => self.reply(tag, "OK LSUB completed"),
                "NAMESPACE" => {
                    self.reply("*", "NAMESPACE ((\"\" \"/\")) NIL NIL");
                    self.reply(tag, "OK NAMESPACE completed");
                }
                "SUBSCRIBE" | "UNSUBSCRIBE" => self.reply(tag, &format!("OK {cmd} completed")),
                "ID" => self.reply(tag, "OK ID completed"),
                "ENABLE" => self.reply(tag, "OK ENABLE completed"),
                "UNSELECT" => {
                    self.reply("*", "OK [CLOSED] Previous mailbox closed");
                    self.selected.clear();
                    self.mailbox_id = 0;
                    self.reply(tag, "OK UNSELECT completed");
                }
                "STARTTLS" => {
                    if !self.starttls(tag).await {
                        return;
                    }
                }
                "FETCH" => self.fetch(tag, &args, false).await,
                "SEARCH" => self.search(tag, false, &args).await,
                "STORE" => self.store(tag, false, &args).await,
                "UID" => self.uid_command(tag, &args).await,
                "LIST" => self.list(tag).await,
                "STATUS" => self.status(tag, &args).await,
                "EXPUNGE" => self.expunge(tag).await,
                "CLOSE" => self.close(tag).await,
                "CREATE" => self.create(tag, &args).await,
                "DELETE" => self.delete(tag, &args).await,
                "RENAME" => self.rename(tag, &args).await,
                "MOVE" => self.transfer(tag, &args, false, true).await,
                "COPY" => self.transfer(tag, &args, false, false).await,
                "APPEND" => {
                    if !self.append(tag, &args).await {
                        return;
                    }
                }
                "IDLE" => {
                    if !self.idle(tag).await {
                        return;
                    }
                }
                _ => self.reply(tag, "BAD Command not implemented"),
            }
            if !self.flush().await || quit {
                return;
            }
        }
    }

    /// Returns false when the connection must end (failed upgrade).
    async fn starttls(&mut self, tag: &str) -> bool {
        if self.secure {
            self.reply(tag, "BAD TLS is already active");
            return true;
        }
        if self.authed {
            self.reply(tag, "BAD STARTTLS is not permitted after authentication");
            return true;
        }
        let Some(tls) = self.server.tls.clone() else {
            self.reply(tag, "NO STARTTLS not available");
            return true;
        };
        self.reply(tag, "OK Begin TLS negotiation now");
        if !self.flush().await {
            return false;
        }
        // Go loads the pair after the OK; a failure leaves the plaintext socket
        // open with nothing sent. Here the connection ends instead (the client is
        // mid-handshake and cannot continue either way).
        let tls = match &self.server.tls_files {
            Some((cert, key)) => match crate::tls::server_config(cert, key) {
                Ok(fresh) => fresh,
                Err(_) => return false,
            },
            None => tls,
        };
        self.conn.discard_buffered();
        let Io::Plain(socket) = std::mem::replace(&mut self.conn.io, Io::Upgrading) else {
            return false;
        };
        match timeout(
            HANDSHAKE,
            tokio_rustls::TlsAcceptor::from(tls).accept(socket),
        )
        .await
        {
            Ok(Ok(stream)) => {
                self.conn.io = Io::Tls(Box::new(stream));
                self.secure = true;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn tx_factory(&self) -> Option<&TxFactory> {
        self.server.tx_factory.as_ref()
    }

    pub(crate) fn user_principal(&self) -> Option<&UserPrincipal> {
        self.user_principal.as_ref()
    }

    pub(crate) fn read_cap(&self) -> Option<ReadCapability> {
        self.principal.as_ref()?.require_read().ok()
    }

    pub(crate) fn mutate_cap(&self) -> Option<MutateCapability> {
        self.principal.as_ref()?.require_mutate().ok()
    }

    pub(crate) fn mailbox_envelope(
        &self,
        cap: &MutateCapability,
        payload: &[u8],
    ) -> CommandEnvelope<()> {
        let generation = self
            .principal
            .as_ref()
            .map_or(Generation(1), MailboxPrincipal::generation);
        self.mailbox_envelope_for_generation(cap, generation, payload)
    }

    fn mailbox_envelope_for_generation(
        &self,
        cap: &MutateCapability,
        generation: Generation,
        payload: &[u8],
    ) -> CommandEnvelope<()> {
        CommandEnvelope {
            operation: operation_id(cap.actor().get()),
            authority: AuthorityKey {
                actor: cap.actor(),
                scope: ResourceScope::Mailbox(cap.mailbox()),
                generation,
            },
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(payload).into()),
            command: (),
        }
    }

    /// Resolve a `MutateCapability` + matching `CommandEnvelope` for `mailbox_id`.
    /// Reuses the currently bound session principal when it already targets `mailbox_id`,
    /// otherwise mints a temporary `MailboxPrincipal` via `TxFactory::mint_capability_mailbox`
    /// so cross-mailbox `APPEND` (before `SELECT`, or targeting another owned mailbox)
    /// enforces ownership and RLS against the destination mailbox.
    pub(crate) async fn mutate_cap_for(
        &self,
        mailbox_id: i64,
        payload: &[u8],
    ) -> Option<(MutateCapability, CommandEnvelope<()>)> {
        if let Some(p) = self.principal.as_ref() {
            if p.mailbox().get() == mailbox_id {
                let cap = p.require_mutate().ok()?;
                let env = self.mailbox_envelope_for_generation(&cap, p.generation(), payload);
                return Some((cap, env));
            }
        }
        let tx_factory = self.tx_factory()?;
        let actor = ActorId::new(self.user_id).ok()?;
        let mb = MailboxId::new(mailbox_id).ok()?;
        let principal = tx_factory
            .mint_capability_mailbox(actor, mb, &self.user_email, &self.client_ip)
            .await
            .ok()?;
        let cap = principal.require_mutate().ok()?;
        let env = self.mailbox_envelope_for_generation(&cap, principal.generation(), payload);
        Some((cap, env))
    }

    async fn select(&mut self, tag: &str, cmd: &str, args: &str) {
        if !self.authed {
            self.reply(tag, "NO Authentication required");
            return;
        }
        if !self.selected.is_empty() {
            self.reply("*", "OK [CLOSED] Previous mailbox closed");
        }
        // RFC 9051 6.3.2: a failed SELECT leaves nothing selected.
        self.reset_selected();
        let folder = canonical_mailbox(args.trim_matches('"'));
        self.selected = folder.clone();
        self.read_only = cmd == "EXAMINE";
        let (Some(tx_factory), Some(user_principal)) =
            (self.tx_factory().cloned(), self.user_principal().cloned())
        else {
            self.selected.clear();
            self.reply(tag, "NO No such mailbox");
            return;
        };
        // Run SELECT/EXAMINE tag lookup under UserPrincipal (app.current_user_id only)
        // so secondary owned mailboxes remain visible under V287 FORCE RLS on `tags`.
        let rows = tx_factory
            .run_user_read_pipelined(
                &user_principal,
                "SELECT t.id, t.mailbox_id, COALESCE(t.total_count, 0)::bigint, \
                 COALESCE(t.unread_count, 0)::bigint, \
                 COALESCE(t.imap_uid_validity, 0)::bigint, COALESCE(t.imap_uid_next, 1)::bigint, \
                 COALESCE((SELECT enabled FROM feature_toggles \
                           WHERE key='feature.imap_membership_uid'),FALSE) \
                 AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE) \
                 FROM tags t JOIN mailboxes m ON m.id = t.mailbox_id \
                 WHERE m.user_id = $1 AND (t.name = $2 OR t.imap_name = $2) \
                   AND t.imap_expose = TRUE LIMIT 1",
                &[(&self.user_id, Type::INT8), (&folder, Type::TEXT)],
            )
            .await;
        let Some(row) = rows.ok().and_then(|rows| rows.into_iter().next()) else {
            self.selected.clear();
            self.reply(tag, "NO No such mailbox");
            return;
        };
        let (Ok(tag_id), Ok(mailbox_id), Ok(total), Ok(mut uid_validity), Ok(mut next_uid)) = (
            row.try_get::<_, i64>(0),
            row.try_get::<_, i64>(1),
            row.try_get::<_, i64>(2),
            row.try_get::<_, i64>(4),
            row.try_get::<_, i64>(5),
        ) else {
            self.selected.clear();
            self.reply(tag, "NO No such mailbox");
            return;
        };
        let membership: bool = row.try_get(6).unwrap_or(false);
        // Bind/refresh the session's MailboxPrincipal to the selected mailbox so
        // subsequent mailbox-scoped commands (FETCH/SEARCH/STORE/APPEND/EXPUNGE)
        // enforce RLS against the selected (possibly secondary) owned mailbox.
        let needs_rebind = self
            .principal
            .as_ref()
            .is_none_or(|p| p.mailbox().get() != mailbox_id);
        if needs_rebind {
            let (Ok(actor), Ok(mb)) = (ActorId::new(self.user_id), MailboxId::new(mailbox_id))
            else {
                self.selected.clear();
                self.reply(tag, "NO No such mailbox");
                return;
            };
            let Ok(selected_principal) = tx_factory
                .mint_capability_mailbox(actor, mb, &self.user_email, &self.client_ip)
                .await
            else {
                self.selected.clear();
                self.reply(tag, "NO No such mailbox");
                return;
            };
            if selected_principal.require_read().is_err() {
                self.selected.clear();
                self.reply(tag, "NO No such mailbox");
                return;
            }
            self.principal = Some(selected_principal);
        }
        self.mailbox_id = mailbox_id;
        self.tag_id = tag_id;
        self.use_membership_uid = membership;
        if uid_validity == 0 {
            // Non-security jitter, as in Go: microsecond clock plus 0..1e6.
            let micros = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_micros() as i64)
                .unwrap_or(0);
            let jitter = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() % 1_000_000)
                .unwrap_or(0);
            uid_validity = micros + i64::from(jitter);
        }
        if next_uid < 1 {
            if let Some(max) = self.max_uid_fallback().await {
                if max > 0 {
                    next_uid = max;
                }
            }
        }
        self.reply("*", "FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen)");
        // Go emits a trailing space here (reply(fmt, "")).
        self.out
            .extend_from_slice(format!("* {total} EXISTS \r\n").as_bytes());
        self.out.extend_from_slice(
            format!("* OK [UIDVALIDITY {uid_validity}] UIDs valid \r\n").as_bytes(),
        );
        self.out.extend_from_slice(
            format!("* OK [UIDNEXT {next_uid}] Predicted next UID \r\n").as_bytes(),
        );
        self.reply(
            "*",
            "OK [PERMANENTFLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen)] Flags permitted",
        );
        if self.read_only {
            self.reply(tag, "OK [READ-ONLY] EXAMINE completed");
        } else {
            self.reply(tag, "OK [READ-WRITE] SELECT completed");
        }
    }

    /// MAX(uid)+1 under the mailbox scope, only when the tag has no stored next UID.
    async fn max_uid_fallback(&self) -> Option<i64> {
        let tx_factory = self.tx_factory()?;
        let read_cap = self.read_cap()?;
        let sql = if self.use_membership_uid {
            "SELECT COALESCE(MAX(mt.imap_uid), 0) + 1 FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND mt.is_primary = TRUE"
        } else {
            "SELECT COALESCE(MAX(m.imap_uid), 0) + 1 FROM messages m \
             JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
             WHERE mt.tag_id = $1 AND mt.is_primary = TRUE"
        };
        let rows = tx_factory
            .run_mailbox_read_pipelined(&read_cap, sql, &[(&self.tag_id, Type::INT8)])
            .await
            .ok()?;
        rows.first()?.try_get::<_, i64>(0).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_args_matches_go_splitimapargs() {
        assert_eq!(split_args("user pass"), vec!["user", "pass"]);
        assert_eq!(
            split_args("\"a@b\" \"my secret password\""),
            vec!["\"a@b\"", "\"my secret password\""]
        );
        assert_eq!(split_args("  "), Vec::<&str>::new());
        assert_eq!(split_args("\"open"), vec!["\"open"]);
        assert_eq!(split_args("\"\"\"x\"\"\""), vec!["\"\"", "\"x\"", "\"\""]);
        assert_eq!(split_args("\u{e9}\"x y\""), vec!["\u{e9}\"x", "y\""]);
    }

    #[test]
    fn only_inbox_folds_case() {
        for name in ["INBOX", "Inbox", "iNbOx"] {
            assert_eq!(canonical_mailbox(name), "Inbox");
        }
        for name in ["Sent", "sent", "INBOX-Archive", ""] {
            assert_eq!(canonical_mailbox(name), name);
        }
    }
}
