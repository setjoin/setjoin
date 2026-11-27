//! One connection's command loop (`handleConn`) and the session-level commands.
use crate::{
    auth,
    conn::{Conn, Io, LineError, READ_TIMEOUT},
    messages::{operation_id, FetchRow, Range},
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
use setjoin_pg::{MailboxTx, ReadOnly, StatementFailure, Type};
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
    pub(crate) condstore_enabled: bool,
    pub(crate) qresync_enabled: bool,
    pub(crate) selected_highest_modseq: Option<i64>,
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
        condstore_enabled: false,
        qresync_enabled: false,
        selected_highest_modseq: None,
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

struct QResyncSelectSnapshot {
    total: i64,
    uid_validity: i64,
    next_uid: i64,
    mailbox_max_uid: i64,
    use_membership_uid: bool,
    highest_modseq: i64,
    delta: Option<QResyncDelta>,
}

struct QResyncDelta {
    rows: Vec<FetchRow>,
    vanished: Vec<i64>,
    resync_required: bool,
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
        if self.authed {
            caps.push_str(" CONDSTORE QRESYNC");
        }
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
    /// Note: RFC 7162 `condstore_enabled` / `qresync_enabled` persist across
    /// mailbox selections within the same authenticated session.
    pub(crate) fn reset_selected(&mut self) {
        self.selected.clear();
        self.mailbox_id = 0;
        self.tag_id = 0;
        self.read_only = false;
        self.use_membership_uid = false;
        self.selected_highest_modseq = None;
    }

    /// Persist CONDSTORE activation for the remainder of the session (RFC 7162 §3.1).
    /// On first activation while a mailbox is already selected, emits the untagged
    /// `* OK [HIGHESTMODSEQ <n>] Highest` response code.
    pub(crate) async fn activate_condstore(&mut self) {
        let was_enabled = self.condstore_enabled;
        self.condstore_enabled = true;
        if !was_enabled && self.selected_mailbox() {
            if let Some(hms) = self.read_highest_modseq().await {
                self.selected_highest_modseq = Some(hms);
                self.reply("*", &format!("OK [HIGHESTMODSEQ {hms}] Highest"));
            }
        }
    }

    async fn read_highest_modseq(&self) -> Option<i64> {
        let tx_factory = self.tx_factory()?;
        let read_cap = self.read_cap()?;
        let mailbox = read_cap.mailbox().get();
        let rows = tx_factory
            .run_mailbox_read_pipelined(
                &read_cap,
                "SELECT imap_mailbox_highestmodseq($1)::bigint",
                &[(&mailbox, Type::INT8)],
            )
            .await
            .ok()?;
        rows.first()?
            .try_get::<_, Option<i64>>(0)
            .ok()?
            .map(|v| v.max(1))
    }

    fn enable(&mut self, tag: &str, args: &str) {
        let mut enabled = Vec::<&'static str>::new();
        let mut saw_condstore = false;
        let mut saw_qresync = false;
        for token in args.split_whitespace() {
            match token.to_uppercase().as_str() {
                "QRESYNC" => {
                    saw_qresync = true;
                    saw_condstore = true;
                }
                "CONDSTORE" => {
                    saw_condstore = true;
                }
                _ => {}
            }
        }
        if saw_qresync {
            self.qresync_enabled = true;
            self.condstore_enabled = true;
            enabled.push("QRESYNC");
            enabled.push("CONDSTORE");
        } else if saw_condstore {
            self.condstore_enabled = true;
            enabled.push("CONDSTORE");
        }
        if !enabled.is_empty() {
            self.reply("*", &format!("ENABLED {}", enabled.join(" ")));
        }
        self.reply(tag, "OK ENABLE completed");
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
                "ENABLE" => self.enable(tag, &args),
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
        let req = match parse_select_args(args) {
            Ok(req) => req,
            Err(msg) => {
                self.reply(tag, msg);
                return;
            }
        };
        if req.qresync.is_some() && !self.qresync_enabled {
            self.reply(tag, "BAD QRESYNC requires ENABLE QRESYNC");
            return;
        }
        let folder = req.folder;
        self.read_only = cmd == "EXAMINE";
        if let Some(qr) = req.qresync {
            self.select_with_qresync(tag, folder, qr).await;
            return;
        }
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
                 AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE), \
                 (COALESCE(m.jmap_email_state, 0) + 1)::bigint \
                 FROM tags t JOIN mailboxes m ON m.id = t.mailbox_id \
                 WHERE m.user_id = $1 AND (t.name = $2 OR t.imap_name = $2) \
                   AND t.imap_expose = TRUE LIMIT 1",
                &[(&self.user_id, Type::INT8), (&folder, Type::TEXT)],
            )
            .await;
        let Some(row) = rows.ok().and_then(|rows| rows.into_iter().next()) else {
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
        let highest_modseq: i64 = row.try_get::<_, i64>(7).unwrap_or(1).max(1);
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
        self.selected = folder;
        self.mailbox_id = mailbox_id;
        self.tag_id = tag_id;
        self.use_membership_uid = membership;
        self.selected_highest_modseq = Some(highest_modseq);
        if req.condstore {
            self.condstore_enabled = true;
        }
        if uid_validity == 0 {
            uid_validity = fallback_uid_validity();
        }
        if next_uid < 1 {
            if let Some(max) = self.max_uid_fallback().await {
                if max > 0 {
                    next_uid = max;
                }
            }
        }
        self.emit_select_headers(total, uid_validity, next_uid, highest_modseq);
        if self.read_only {
            self.reply(tag, "OK [READ-ONLY] EXAMINE completed");
        } else {
            self.reply(tag, "OK [READ-WRITE] SELECT completed");
        }
    }

    /// Execute `SELECT`/`EXAMINE (... QRESYNC ...)` inside ONE `REPEATABLE READ READ ONLY`
    /// transaction so mailbox metadata (`UIDVALIDITY`, `UIDNEXT`, `HIGHESTMODSEQ`),
    /// live messages, and `imap_vanished_uids_since` share a single MVCC snapshot.
    async fn select_with_qresync(&mut self, tag: &str, folder: String, qr: QResyncParams) {
        let (Some(tx_factory), Some(user_principal)) =
            (self.tx_factory().cloned(), self.user_principal().cloned())
        else {
            self.selected.clear();
            self.reply(tag, "NO No such mailbox");
            return;
        };
        let id_rows = tx_factory
            .run_user_read_pipelined(
                &user_principal,
                "SELECT t.id, t.mailbox_id \
                 FROM tags t JOIN mailboxes m ON m.id = t.mailbox_id \
                 WHERE m.user_id = $1 AND (t.name = $2 OR t.imap_name = $2) \
                   AND t.imap_expose = TRUE LIMIT 1",
                &[(&self.user_id, Type::INT8), (&folder, Type::TEXT)],
            )
            .await;
        let Some(id_row) = id_rows.ok().and_then(|rows| rows.into_iter().next()) else {
            self.reply(tag, "NO No such mailbox");
            return;
        };
        let (Ok(tag_id), Ok(mailbox_id)) =
            (id_row.try_get::<_, i64>(0), id_row.try_get::<_, i64>(1))
        else {
            self.reply(tag, "NO Server error");
            return;
        };
        let (Ok(actor), Ok(mb)) = (ActorId::new(self.user_id), MailboxId::new(mailbox_id)) else {
            self.reply(tag, "NO Server error");
            return;
        };
        let selected_principal = if self
            .principal
            .as_ref()
            .is_some_and(|p| p.mailbox().get() == mailbox_id)
        {
            self.principal.clone().unwrap()
        } else {
            let Ok(minted) = tx_factory
                .mint_capability_mailbox(actor, mb, &self.user_email, &self.client_ip)
                .await
            else {
                self.selected.clear();
                self.reply(tag, "NO No such mailbox");
                return;
            };
            minted
        };
        let Ok(read_cap) = selected_principal.require_read() else {
            self.selected.clear();
            self.reply(tag, "NO No such mailbox");
            return;
        };
        let user_id = self.user_id;
        let last_modseq = qr.last_modseq;
        let req_validity = qr.uid_validity;
        let known_ref = qr.known_uids.clone();

        let Ok(mut tx) = tx_factory.begin_mailbox_read_repeatable(&read_cap).await else {
            self.reply(tag, "NO Server error");
            return;
        };
        let snap_res: Result<QResyncSelectSnapshot, StatementFailure> = async {
            let meta_rows = tx
                .query(
                    "SELECT COALESCE(t.total_count, 0)::bigint, \
                     COALESCE(t.imap_uid_validity, 0)::bigint, \
                     COALESCE(t.imap_uid_next, 1)::bigint, \
                     COALESCE((SELECT enabled FROM feature_toggles \
                               WHERE key='feature.imap_membership_uid'),FALSE) \
                     AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE), \
                     (COALESCE(m.jmap_email_state, 0) + 1)::bigint, \
                     GREATEST( \
                       COALESCE((SELECT MAX(t2.imap_uid_next) FROM tags t2 WHERE t2.mailbox_id = m.id), 1) - 1, \
                       COALESCE((SELECT MAX(m2.imap_uid) FROM messages m2 WHERE m2.mailbox_id = m.id), 0), \
                       COALESCE((SELECT MAX(j.imap_uid) FROM jmap_changes_journal j WHERE j.mailbox_id = m.id AND j.datatype = 'email'), 0) \
                     )::bigint \
                     FROM tags t JOIN mailboxes m ON m.id = t.mailbox_id \
                     WHERE t.id = $1 AND m.id = $2 AND m.user_id = $3 \
                       AND t.imap_expose = TRUE LIMIT 1",
                    &[
                        (&tag_id, Type::INT8),
                        (&mailbox_id, Type::INT8),
                        (&user_id, Type::INT8),
                    ],
                )
                .await?;
            let Some(meta) = meta_rows.first() else {
                return Err(crate::messages::failure("mailbox disappeared"));
            };
            let (Ok(total), Ok(mut uid_validity), Ok(mut next_uid)) = (
                meta.try_get::<_, i64>(0),
                meta.try_get::<_, i64>(1),
                meta.try_get::<_, i64>(2),
            ) else {
                return Err(crate::messages::failure("metadata scan failed"));
            };
            let use_membership_uid: bool = meta.try_get(3).unwrap_or(false);
            let highest_modseq: i64 = meta.try_get::<_, i64>(4).unwrap_or(1).max(1);
            let mailbox_max_uid: i64 = meta.try_get::<_, i64>(5).unwrap_or(0).max(0);
            let uid_col = if use_membership_uid {
                "mt.imap_uid"
            } else {
                "m.imap_uid"
            };
            if next_uid < 1 {
                let fb_sql = format!(
                    "SELECT COALESCE(MAX({uid_col}), 0) + 1 FROM messages m \
                     JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at \
                     WHERE mt.tag_id = $1 AND m.mailbox_id = $2 AND mt.is_primary = TRUE"
                );
                let fb = tx
                    .query(&fb_sql, &[(&tag_id, Type::INT8), (&mailbox_id, Type::INT8)])
                    .await?;
                if let Some(max) = fb.first().and_then(|r| r.try_get::<_, i64>(0).ok()) {
                    if max > 0 {
                        next_uid = max;
                    }
                }
            }
            if uid_validity == 0 {
                uid_validity = fallback_uid_validity();
            }

            let delta = if req_validity == uid_validity {
                let rows =
                    crate::messages::read_fetch_rows_in_tx(&mut tx, tag_id, mailbox_id, uid_col)
                        .await?;
                let max_active_uid = rows.iter().map(|r| r.msg.uid).max().unwrap_or(0);
                let legacy_bound = if use_membership_uid {
                    0
                } else {
                    mailbox_max_uid
                };
                let star_uid = max_active_uid
                    .max(next_uid.saturating_sub(1))
                    .max(legacy_bound);
                let (vanished, resync_required) = query_vanished_uids_in_tx(
                    &mut tx,
                    mailbox_id,
                    tag_id,
                    last_modseq,
                    use_membership_uid,
                    known_ref.as_deref(),
                    star_uid,
                )
                .await?;
                Some(QResyncDelta {
                    rows,
                    vanished,
                    resync_required,
                })
            } else {
                None
            };

            Ok(QResyncSelectSnapshot {
                total,
                uid_validity,
                next_uid,
                mailbox_max_uid,
                use_membership_uid,
                highest_modseq,
                delta,
            })
        }
        .await;
        let _ = tx.finish().await;

        let Ok(snap) = snap_res else {
            self.reply(tag, "NO Server error");
            return;
        };

        self.principal = Some(selected_principal);
        self.selected = folder;
        self.mailbox_id = mailbox_id;
        self.tag_id = tag_id;
        self.use_membership_uid = snap.use_membership_uid;
        self.selected_highest_modseq = Some(snap.highest_modseq);
        self.condstore_enabled = true;

        self.emit_select_headers(
            snap.total,
            snap.uid_validity,
            snap.next_uid,
            snap.highest_modseq,
        );

        if let Some(delta) = snap.delta {
            let max_active_uid = delta.rows.iter().map(|r| r.msg.uid).max().unwrap_or(0);
            let legacy_bound = if snap.use_membership_uid {
                0
            } else {
                snap.mailbox_max_uid
            };
            let star_uid = max_active_uid
                .max(snap.next_uid.saturating_sub(1))
                .max(legacy_bound);
            let aligned_floor = qr.seq_match.as_ref().map_or(0, |(seqs, uids)| {
                crate::messages::compute_qresync_aligned_uid_floor(seqs, uids, &delta.rows)
            });
            let vanished_str = if delta.resync_required {
                let mut fallback_ranges = if let Some(known) = qr.known_uids.as_deref() {
                    crate::messages::subtract_live_from_ranges(known, &delta.rows, star_uid)
                } else if star_uid >= 1 {
                    crate::messages::subtract_live_from_ranges(
                        &[Range {
                            lo: 1,
                            hi: star_uid,
                        }],
                        &delta.rows,
                        star_uid,
                    )
                } else {
                    Vec::new()
                };
                if aligned_floor > 0 {
                    fallback_ranges = fallback_ranges
                        .into_iter()
                        .filter_map(|(lo, hi)| {
                            (hi > aligned_floor)
                                .then_some((lo.max(aligned_floor.saturating_add(1)), hi))
                        })
                        .collect();
                }
                crate::messages::format_uid_ranges(&fallback_ranges)
            } else {
                let bounded: Vec<i64> = delta
                    .vanished
                    .iter()
                    .copied()
                    .filter(|&uid| uid > aligned_floor)
                    .collect();
                crate::messages::format_uid_set(&bounded)
            };
            if !vanished_str.is_empty() {
                self.reply("*", &format!("VANISHED (EARLIER) {vanished_str}"));
            }
            for row in &delta.rows {
                if let Some(known) = qr.known_uids.as_deref() {
                    if !crate::messages::uid_in_ranges(row.msg.uid, known, star_uid) {
                        continue;
                    }
                }
                if delta.resync_required || row.msg.modseq > qr.last_modseq {
                    let flags = crate::messages::flag_names_joined(&row.msg);
                    self.reply(
                        "*",
                        &format!(
                            "{} FETCH (UID {} FLAGS ({}) MODSEQ ({}))",
                            row.msg.seq, row.msg.uid, flags, row.msg.modseq
                        ),
                    );
                }
            }
        }

        if self.read_only {
            self.reply(tag, "OK [READ-ONLY] EXAMINE completed");
        } else {
            self.reply(tag, "OK [READ-WRITE] SELECT completed");
        }
    }

    fn emit_select_headers(
        &mut self,
        total: i64,
        uid_validity: i64,
        next_uid: i64,
        highest_modseq: i64,
    ) {
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
        if self.condstore_enabled {
            self.reply("*", &format!("OK [HIGHESTMODSEQ {highest_modseq}] Highest"));
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

fn fallback_uid_validity() -> i64 {
    // Non-security jitter, as in Go: microsecond clock plus 0..1e6.
    let micros = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    let jitter = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() % 1_000_000)
        .unwrap_or(0);
    micros + i64::from(jitter)
}

/// Fail-closed query to `imap_vanished_uids_since` inside an existing snapshot
/// transaction (`MailboxTx<ReadOnly>`). Any DB error or malformed JSON returns `Err`.
pub(crate) async fn query_vanished_uids_in_tx(
    tx: &mut MailboxTx<ReadOnly>,
    mailbox_id: i64,
    tag_id: i64,
    since_modseq: i64,
    use_membership_uid: bool,
    known_ranges: Option<&[Range]>,
    star_uid: i64,
) -> Result<(Vec<i64>, bool), StatementFailure> {
    let rows = tx
        .query(
            "SELECT imap_vanished_uids_since($1, $2, $3, $4, NULL::bigint[])::text",
            &[
                (&mailbox_id, Type::INT8),
                (&tag_id, Type::INT8),
                (&since_modseq, Type::INT8),
                (&use_membership_uid, Type::BOOL),
            ],
        )
        .await?;
    let text = rows
        .first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(|| crate::messages::failure("imap_vanished_uids_since returned no payload"))?;
    let payload: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| crate::messages::failure("invalid imap_vanished_uids_since JSON"))?;
    let resync_required = payload
        .get("resyncRequired")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| crate::messages::failure("missing resyncRequired in vanished payload"))?;
    let mut vanished: Vec<i64> = payload
        .get("vanished")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| crate::messages::failure("missing vanished array in vanished payload"))?
        .iter()
        .filter_map(serde_json::Value::as_i64)
        .filter(|uid| *uid > 0)
        .collect();
    if let Some(ranges) = known_ranges {
        let max_uid = vanished.iter().copied().max().unwrap_or(0).max(star_uid);
        vanished.retain(|uid| crate::messages::uid_in_ranges(*uid, ranges, max_uid));
    }
    Ok((vanished, resync_required))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QResyncParams {
    pub(crate) uid_validity: i64,
    pub(crate) last_modseq: i64,
    pub(crate) known_uids: Option<Vec<Range>>,
    pub(crate) seq_match: Option<(Vec<Range>, Vec<Range>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectRequest {
    pub(crate) folder: String,
    pub(crate) condstore: bool,
    pub(crate) qresync: Option<QResyncParams>,
}

/// Find the starting index of a trailing `(CONDSTORE ...)` or `(QRESYNC ...)`
/// parameter block after the mailbox name, preserving legacy folder names verbatim.
fn find_select_params(args: &str) -> Option<usize> {
    let trimmed = args.trim_end();
    if !trimmed.ends_with(')') {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && bytes[i] == b'(' && i > 0 && bytes[i - 1].is_ascii_whitespace() {
            let inner = trimmed[i + 1..trimmed.len() - 1].trim_start();
            let head = inner
                .split(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
                .next()
                .unwrap_or("");
            if head.eq_ignore_ascii_case("CONDSTORE") || head.eq_ignore_ascii_case("QRESYNC") {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub(crate) fn parse_select_args(args: &str) -> Result<SelectRequest, &'static str> {
    let Some(param_start) = find_select_params(args) else {
        return Ok(SelectRequest {
            folder: canonical_mailbox(args.trim_matches('"')),
            condstore: false,
            qresync: None,
        });
    };
    let folder_raw = args[..param_start].trim();
    let folder = canonical_mailbox(folder_raw.trim_matches('"'));
    let trimmed = args.trim_end();
    let inner = trimmed[param_start + 1..trimmed.len() - 1].trim();
    let mut condstore = false;
    let mut qresync = None;
    let mut rest = inner;
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '(')
            .unwrap_or(rest.len());
        let kw = &rest[..end];
        rest = rest[end..].trim_start();
        if kw.eq_ignore_ascii_case("CONDSTORE") {
            condstore = true;
        } else if kw.eq_ignore_ascii_case("QRESYNC") {
            if qresync.is_some() || !rest.starts_with('(') {
                return Err("BAD Invalid QRESYNC parameters");
            }
            // Match balanced parens for the QRESYNC argument list.
            let mut depth = 0usize;
            let mut close_idx = None;
            for (idx, ch) in rest.char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            close_idx = Some(idx);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close_idx) = close_idx else {
                return Err("BAD Invalid QRESYNC parameters");
            };
            let q_inner = rest[1..close_idx].trim();
            rest = &rest[close_idx + 1..];
            // Optional 4th seq-match-data: (<known-sequence-set> <known-uid-set>),
            // strictly ascending, no '*', and equal cardinality (RFC 7162 §3.2.5.2).
            let (q_head, seq_match_raw) = match q_inner.find('(') {
                Some(pos) => (q_inner[..pos].trim(), Some(q_inner[pos..].trim())),
                None => (q_inner, None),
            };
            let seq_match = if let Some(sm) = seq_match_raw {
                if !sm.starts_with('(') || !sm.ends_with(')') {
                    return Err("BAD Invalid QRESYNC seq-match-data");
                }
                let sm_inner = sm[1..sm.len() - 1].trim();
                if sm_inner.contains('(') || sm_inner.contains(')') {
                    return Err("BAD Invalid QRESYNC seq-match-data");
                }
                let sm_parts: Vec<&str> = sm_inner.split_whitespace().collect();
                if sm_parts.len() != 2 {
                    return Err("BAD Invalid QRESYNC seq-match-data");
                }
                let (Some((seq_ranges, seq_count)), Some((uid_ranges, uid_count))) = (
                    crate::messages::parse_strict_ascending_set_no_star(sm_parts[0]),
                    crate::messages::parse_strict_ascending_set_no_star(sm_parts[1]),
                ) else {
                    return Err("BAD Invalid QRESYNC seq-match-data");
                };
                if seq_count != uid_count {
                    return Err("BAD Invalid QRESYNC seq-match-data");
                }
                Some((seq_ranges, uid_ranges))
            } else {
                None
            };
            let tokens: Vec<&str> = q_head.split_whitespace().collect();
            if tokens.len() < 2 || tokens.len() > 3 {
                return Err("BAD Invalid QRESYNC parameters");
            }
            let Ok(uid_validity) = tokens[0].parse::<i64>() else {
                return Err("BAD Invalid QRESYNC UIDVALIDITY");
            };
            let Ok(last_modseq) = tokens[1].parse::<i64>() else {
                return Err("BAD Invalid QRESYNC MODSEQ");
            };
            // RFC 7162 §3.2.5.2: both uidvalidity and mod-sequence-value MUST be >= 1.
            if uid_validity <= 0 || last_modseq <= 0 {
                return Err("BAD Invalid QRESYNC parameters");
            }
            let known_uids = if let Some(uid_spec) = tokens.get(2) {
                let Some(parsed) = crate::messages::parse_uid_set_strict_no_star(uid_spec) else {
                    return Err("BAD Invalid QRESYNC known UID set");
                };
                Some(parsed)
            } else {
                None
            };
            condstore = true;
            qresync = Some(QResyncParams {
                uid_validity,
                last_modseq,
                known_uids,
                seq_match,
            });
        } else {
            return Err("BAD Unknown SELECT parameter");
        }
    }
    Ok(SelectRequest {
        folder,
        condstore,
        qresync,
    })
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

    #[test]
    fn parse_select_args_supports_condstore_and_qresync() {
        assert_eq!(
            parse_select_args("INBOX").unwrap(),
            SelectRequest {
                folder: "Inbox".into(),
                condstore: false,
                qresync: None,
            }
        );
        assert_eq!(
            parse_select_args("\"My Folder\" (CONDSTORE)").unwrap(),
            SelectRequest {
                folder: "My Folder".into(),
                condstore: true,
                qresync: None,
            }
        );
        let q = parse_select_args("INBOX (QRESYNC (1111 42 1:10,15 (1:3 2,5,9)))").unwrap();
        assert_eq!(q.folder, "Inbox");
        assert!(q.condstore);
        let qr = q.qresync.unwrap();
        assert_eq!(qr.uid_validity, 1111);
        assert_eq!(qr.last_modseq, 42);
        assert_eq!(
            qr.known_uids.unwrap(),
            vec![Range { lo: 1, hi: 10 }, Range { lo: 15, hi: 15 }]
        );
        assert_eq!(
            qr.seq_match.unwrap(),
            (
                vec![Range { lo: 1, hi: 3 }],
                vec![
                    Range { lo: 2, hi: 2 },
                    Range { lo: 5, hi: 5 },
                    Range { lo: 9, hi: 9 }
                ]
            )
        );

        // RFC 7162 BAD rejections
        assert!(parse_select_args("INBOX (QRESYNC (1111 0))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (0 5))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 1:*))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 1:5 (1:* 2:6)))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 1:5 (1:3)))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 1:5 (1:3 2:6) trailing))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 (3:1 1:3)))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 (2,1 1,2)))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 (1:2 10:12)))").is_err());
        assert!(parse_select_args("INBOX (QRESYNC (1111 5 (1,2,2 10,20,30)))").is_err());
    }
}
