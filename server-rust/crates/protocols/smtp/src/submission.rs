//! SMTP submission (MSA, port 587): a port of frozen Go's `SubmissionServer`
//! (#501). AUTH PLAIN/LOGIN only after STARTTLS, the shared threat gate (#420),
//! envelope-from ownership, `smtp_submission_send` and the post-commit event.
//! There is no proxy and no switch back to Go.
//!
//! Every statement runs on the worker credential, as in Go (`workerPool`):
//! submission self-authenticates at AUTH and the reducer self-authorizes the
//! sender before any write.
use crate::{framing, reducer_reply};
use futures_util::future::BoxFuture;
use serde_json::Value;
use setjoin_mime as mime;
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use setjoin_threat::{
    registry::{Closer, ProtocolSessionRegistry},
    tracker::{ConnTracker, UserSlot},
    ConnectionMeta, ThreatAction, ThreatGate,
};
use sha2::{Digest, Sha256};
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};

/// `mailserver/auth` CloudEvents at each AUTH outcome (same seam as IMAP).
pub trait AuthWebhooks: Send + Sync {
    fn login<'a>(&'a self, email: &'a str, provider: &'a str, ip: &'a str) -> BoxFuture<'a, ()>;
    fn login_failed<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> BoxFuture<'a, ()>;
}
/// Post-commit `mail.sent` event; only reducer-derived subjects reach it.
pub trait SubmissionEvents: Send + Sync {
    fn sent<'a>(
        &'a self,
        user: i64,
        mailbox: i64,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, ()>;
}
/// Process-wide feature flags (`feature_toggles` with registry defaults).
pub trait Flags: Send + Sync {
    fn enabled(&self, key: &str) -> bool;
}
impl<F: Fn(&str) -> bool + Send + Sync> Flags for F {
    fn enabled(&self, key: &str) -> bool {
        self(key)
    }
}

const MAX_RECIPIENTS: usize = 1000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const CONTINUATION_CAP: usize = 8192;

pub struct Submission {
    db: WorkerDatabase,
    gate: Option<Arc<dyn ThreatGate>>,
    webhooks: Option<Arc<dyn AuthWebhooks>>,
    events: Option<Arc<dyn SubmissionEvents>>,
    flags: Arc<dyn Flags>,
    blobs: Option<Arc<dyn crate::RawBlobs>>,
    starttls: Option<(PathBuf, PathBuf)>,
    max_connections: usize,
    users: ConnTracker,
    registry: Option<Arc<ProtocolSessionRegistry>>,
    dummy_hash: &'static str,
    dummy_verifications: std::sync::atomic::AtomicUsize,
}

/// bcrypt cost 10; the gateway passes the profile's own algorithm (SECFIX3).
const DUMMY_BCRYPT: &str = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

impl Submission {
    /// `Unwired` threat policy mirrors Go's nil interceptor (fixtures only); the
    /// gateway refuses to activate a listener without the shared gate.
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            gate: None,
            webhooks: None,
            events: None,
            flags: Arc::new(|_: &str| true),
            blobs: None,
            starttls: None,
            max_connections: 0,
            users: ConnTracker::default(),
            registry: None,
            dummy_hash: DUMMY_BCRYPT,
            dummy_verifications: Default::default(),
        }
    }
    /// The fixed hash an unknown/disabled account is verified against, in the
    /// crypto profile's algorithm (`setjoin_identity::login::dummy_hash`).
    pub fn with_dummy_hash(mut self, hash: &'static str) -> Self {
        self.dummy_hash = hash;
        self
    }
    /// How many password hashes were spent on accounts that do not exist.
    pub fn dummy_verifications(&self) -> usize {
        self.dummy_verifications.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn with_threat_gate(mut self, gate: Arc<dyn ThreatGate>) -> Self {
        self.gate = Some(gate);
        self
    }
    pub fn threat_enforced(&self) -> bool {
        self.gate.is_some()
    }
    pub fn with_auth_webhooks(mut self, sink: Arc<dyn AuthWebhooks>) -> Self {
        self.webhooks = Some(sink);
        self
    }
    pub fn webhooks_wired(&self) -> bool {
        self.webhooks.is_some()
    }
    pub fn with_events(mut self, events: Arc<dyn SubmissionEvents>) -> Self {
        self.events = Some(events);
        self
    }
    pub fn with_flags(mut self, flags: Arc<dyn Flags>) -> Self {
        self.flags = flags;
        self
    }
    pub fn with_blob_store(mut self, blobs: Arc<dyn crate::RawBlobs>) -> Self {
        self.blobs = Some(blobs);
        self
    }
    /// Go `SetTLS`: STARTTLS with the files re-read at every upgrade.
    pub fn with_starttls_files(mut self, cert: PathBuf, key: PathBuf) -> Result<Self, String> {
        crate::tls::server_config(&cert, &key)?;
        self.starttls = Some((cert, key));
        Ok(self)
    }
    /// `SetMaxConns`: 0 is unlimited; accepts wait for a slot like `LimitListener`.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }
    /// `SetPerUserMaxConns`: 0 or negative is unlimited.
    pub fn with_per_user_max(self, max: i64) -> Self {
        self.users.set_max(max);
        self
    }
    pub fn with_session_registry(mut self, registry: Arc<ProtocolSessionRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut stop: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let slots = (self.max_connections > 0)
            .then(|| Arc::new(tokio::sync::Semaphore::new(self.max_connections)));
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            let permit = match &slots {
                Some(slots) => {
                    let acquired = tokio::select! {
                        _ = stop.changed() => break,
                        p = slots.clone().acquire_owned() => p,
                    };
                    acquired.ok()
                }
                None => None,
            };
            let conn = tokio::select! {
                _ = stop.changed() => break,
                Some(_) = sessions.join_next() => continue,
                conn = listener.accept() => conn,
            };
            let (socket, _) = match conn {
                Ok(c) => c,
                Err(_) => continue,
            };
            let server = self.clone();
            sessions.spawn(async move {
                let _permit = permit;
                let _ = server.session(socket).await;
            });
        }
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        Ok(())
    }

    fn starttls_config(&self) -> Result<Arc<tokio_rustls::rustls::ServerConfig>, String> {
        let (cert, key) = self.starttls.as_ref().ok_or("no certificate")?;
        crate::tls::server_config(cert, key)
    }

    fn feature(&self, key: &str) -> bool {
        self.flags.enabled(key)
    }

    async fn session(self: Arc<Self>, socket: TcpStream) -> io::Result<()> {
        let peer = socket.peer_addr()?;
        let (close_tx, mut close_rx) = watch::channel(false);
        let mut state = State {
            ip: peer.ip().to_canonical().to_string(),
            io: BufReader::new(Box::new(socket)),
            tls: false,
            authed: false,
            user: 0,
            from: Vec::new(),
            to: Vec::new(),
            db: None,
            slot: None,
            registry_release: None,
            closer: Arc::new(close_tx),
        };
        // A registry revocation drops the whole session future, closing the socket
        // like Go's `conn.Close()` from `ProtocolSessionRegistry`.
        tokio::select! {
            r = self.commands(&mut state) => r,
            _ = close_rx.changed() => Ok(()),
        }
    }

    async fn commands(&self, c: &mut State) -> io::Result<()> {
        c.reply(220, "mailserver ESMTP submission ready").await?;
        loop {
            let line =
                match tokio::time::timeout(COMMAND_TIMEOUT, framing::command(&mut c.io)).await {
                    Err(_) => {
                        c.reply(421, "4.4.2 Connection timed out").await?;
                        return Ok(());
                    }
                    Ok(line) => match line {
                        Err(_) => return Ok(()),
                        Ok(framing::Line::Eof) => return Ok(()),
                        Ok(framing::Line::TooLong) => {
                            c.reply(500, "5.5.2 Line too long").await?;
                            continue;
                        }
                        Ok(framing::Line::Bytes(line)) => line,
                    },
                };
            let split = line.iter().position(|&b| b == b' ');
            let cmd = String::from_utf8_lossy(&line[..split.unwrap_or(line.len())]).to_uppercase();
            let arg: &[u8] = split.map(|i| &line[i + 1..]).unwrap_or(&[]);
            match cmd.as_str() {
                "EHLO" => {
                    let mut text = String::from(
                        "250-mailserver\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n",
                    );
                    if self.starttls.is_some() && !c.tls {
                        text.push_str("250-STARTTLS\r\n");
                    }
                    if c.tls {
                        text.push_str("250-AUTH LOGIN PLAIN\r\n");
                    }
                    text.push_str("250 SIZE 157286400\r\n");
                    c.write(text.as_bytes()).await?;
                }
                "STARTTLS" => {
                    if c.tls {
                        c.reply(503, "TLS already active").await?;
                        return Ok(());
                    }
                    if self.starttls.is_none() {
                        c.reply(503, "STARTTLS not available").await?;
                        return Ok(());
                    }
                    c.reply(220, "Ready to start TLS").await?;
                    let Ok(config) = self.starttls_config() else {
                        c.reply(454, "TLS not available due to server error").await?;
                        return Ok(());
                    };
                    // Go replaces its textproto reader, discarding pipelined bytes.
                    let stream = std::mem::replace(
                        &mut c.io,
                        BufReader::new(Box::new(tokio::io::join(tokio::io::empty(), tokio::io::sink()))),
                    )
                    .into_inner();
                    let accepted = tokio::time::timeout(
                        Duration::from_secs(300),
                        tokio_rustls::TlsAcceptor::from(config).accept(stream),
                    )
                    .await;
                    let Ok(Ok(tls)) = accepted else {
                        return Ok(());
                    };
                    c.io = BufReader::new(Box::new(tls));
                    c.tls = true;
                    c.reset();
                }
                "AUTH" => {
                    if !c.tls {
                        c.reply(530, "Must issue STARTTLS first").await?;
                        return Ok(());
                    }
                    self.auth(c, arg).await?;
                }
                "MAIL" => self.mail(c, arg).await?,
                "RCPT" => self.rcpt(c, arg).await?,
                "DATA" => {
                    if !self.data(c).await? {
                        return Ok(());
                    }
                }
                "RSET" => {
                    c.reset();
                    c.reply(250, "OK").await?;
                }
                "QUIT" => {
                    c.reply(221, "Bye").await?;
                    return Ok(());
                }
                "NOOP" => c.reply(250, "OK").await?,
                _ => c.reply(500, "Command not recognized").await?,
            }
        }
    }

    // ---- AUTH ----------------------------------------------------------

    async fn auth(&self, c: &mut State, arg: &[u8]) -> io::Result<()> {
        let arg = String::from_utf8_lossy(arg).into_owned();
        let mut fields = arg.split_whitespace();
        let Some(mech) = fields.next() else {
            return c.reply(501, "Syntax error").await;
        };
        match mech.to_uppercase().as_str() {
            "PLAIN" => {
                let b64 = arg.strip_prefix("PLAIN ").unwrap_or(&arg).to_string();
                self.auth_plain(c, b64).await
            }
            "LOGIN" => self.auth_login(c).await,
            _ => c.reply(504, "Mechanism not supported").await,
        }
    }

    async fn auth_plain(&self, c: &mut State, mut b64: String) -> io::Result<()> {
        if b64.is_empty() {
            c.reply(334, " ").await?;
            b64 = c.continuation().await?.unwrap_or_default();
        }
        let Some(data) = decode_std(&b64) else {
            return c.reply(501, "Invalid base64").await;
        };
        // RFC 4616: authzid\0authcid\0passwd
        let text = String::from_utf8_lossy(&data).into_owned();
        let parts: Vec<&str> = text.split('\0').collect();
        if parts.len() != 3 {
            return c.reply(501, "Invalid PLAIN format").await;
        }
        if !parts[0].is_empty() && parts[0] != parts[1] {
            return c.reply(501, "Authorization identity not supported").await;
        }
        let (email, password) = (parts[1].to_string(), parts[2].to_string());
        self.check_password(c, &email, &password).await
    }

    async fn auth_login(&self, c: &mut State) -> io::Result<()> {
        c.reply(334, "VXNlcm5hbWU6").await?;
        let user = c.continuation().await?.unwrap_or_default();
        let username = decode_std(&user).unwrap_or_default();
        c.reply(334, "UGFzc3dvcmQ6").await?;
        let pass = c.continuation().await?.unwrap_or_default();
        let password = decode_std(&pass).unwrap_or_default();
        self.check_password(
            c,
            &String::from_utf8_lossy(&username),
            &String::from_utf8_lossy(&password),
        )
        .await
    }

    /// `pwhash.LogAuthEvent`: unknown providers are never logged; a toggle
    /// checker applies only where Go passed one.
    async fn log_event(
        &self,
        c: &mut State,
        user: Option<i64>,
        event: &str,
        provider: &str,
        email: &str,
        ip: &str,
        checked: bool,
    ) {
        let key = match provider {
            "app_password" => "feature.auth_log_app_password",
            "basic" => "feature.auth_log_basic",
            "bcrypt" => "feature.auth_log_bcrypt",
            "conditional_access" => "feature.auth_log_conditional_access",
            "jwt" => "feature.auth_log_jwt",
            "kerberos" => "feature.auth_log_kerberos",
            "ldap" => "feature.auth_log_ldap",
            "rate_limit" => "feature.auth_log_rate_limit",
            "threat" => "feature.auth_log_threat",
            "webauthn" => "feature.auth_log_webauthn",
            _ => return,
        };
        if checked && !self.feature(key) {
            return;
        }
        let email = (!email.is_empty()).then_some(email);
        let ip = (!ip.is_empty()).then_some(ip);
        let _ = c
            .query(
                &self.db,
                "INSERT INTO auth_event_log (user_id, event, provider, email, ip_address, details) \
                 VALUES ($1, $2, $3, $4, $5::text::inet, NULL)",
                &[
                    (&user, Type::INT8),
                    (&event, Type::TEXT),
                    (&provider, Type::TEXT),
                    (&email, Type::TEXT),
                    (&ip, Type::TEXT),
                ],
            )
            .await;
    }

    async fn webhook(&self, success: bool, email: &str, provider: &str, ip: &str) {
        if let Some(sink) = &self.webhooks {
            if success {
                sink.login(email, provider, ip).await;
            } else {
                sink.login_failed(email, provider, ip).await;
            }
        }
    }

    async fn check_password(&self, c: &mut State, email: &str, password: &str) -> io::Result<()> {
        let authenticated_at = std::time::SystemTime::now();
        let ip = c.ip.clone();
        let mut meta = ConnectionMeta {
            source_ip: ip.clone(),
            username: email.to_string(),
            protocol: "smtp".into(),
            ..ConnectionMeta::default()
        };
        const TOO_MANY: &str = "Too many authentication attempts \u{2014} try again later";
        if let Some(gate) = self.gate.clone() {
            let (action, delay) = gate.intercept(&meta).await;
            match action {
                ThreatAction::Reject => {
                    self.log_event(c, None, "login_failed", "threat", email, &ip, true)
                        .await;
                    return c
                        .reply(421, "Authentication temporarily unavailable")
                        .await;
                }
                ThreatAction::Tarpitted => {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    self.log_event(c, None, "login_failed", "threat", email, &ip, true)
                        .await;
                    return c
                        .reply(421, "Authentication temporarily unavailable")
                        .await;
                }
                ThreatAction::RateLimited => {
                    self.log_event(c, None, "login_failed", "rate_limit", email, &ip, true)
                        .await;
                    return c.reply(421, TOO_MANY).await;
                }
                ThreatAction::Allow => {}
            }
        }
        // Defence-in-depth counters that Go keeps beside the interceptor.
        let ip_key = format!("ip:{ip}");
        if let Ok(rows) = c
            .query(
                &self.db,
                "SELECT rate_limit_check($1, 10, 5, 30)",
                &[(&ip_key, Type::TEXT)],
            )
            .await
        {
            if rows.first().is_some_and(|r| !r.get::<_, bool>(0)) {
                return c.reply(421, TOO_MANY).await;
            }
        }
        if let Ok(rows) = c
            .query(
                &self.db,
                "SELECT rate_limit_check('acct:' || lower($1), 5, 15, 60)",
                &[(&email, Type::TEXT)],
            )
            .await
        {
            if rows.first().is_some_and(|r| !r.get::<_, bool>(0)) {
                return c.reply(421, TOO_MANY).await;
            }
        }
        if let Some(user) = self.check_app_password(c, email, password).await {
            c.authed = true;
            c.user = user;
            if let Some(gate) = self.gate.clone() {
                meta.app_password = true;
                gate.record_result(&meta, true, user).await;
                meta.user_id = user;
                let (action, reason) = gate.evaluate_post_auth(&mut meta).await;
                if action == ThreatAction::Reject {
                    self.log_event(
                        c,
                        Some(user),
                        "login_failed",
                        "conditional_access",
                        email,
                        &ip,
                        true,
                    )
                    .await;
                    c.authed = false;
                    c.user = 0;
                    return c
                        .reply(535, &format!("5.7.0 Access blocked by policy: {reason}"))
                        .await;
                }
            }
            self.webhook(true, email, "app_password", &ip).await;
            return self.admit(c, user, authenticated_at).await;
        }
        let Some(user) = self.check_user_password(c, email, password).await else {
            self.log_event(c, None, "login_failed", "bcrypt", email, &ip, true)
                .await;
            self.webhook(false, email, "bcrypt", &ip).await;
            if let Some(gate) = &self.gate {
                gate.record_result(&meta, false, 0).await;
            }
            return c.reply(535, "Authentication failed").await;
        };
        self.log_event(c, Some(user), "login", "bcrypt", email, &ip, true)
            .await;
        self.webhook(true, email, "bcrypt", &ip).await;
        c.authed = true;
        c.user = user;
        if let Some(gate) = self.gate.clone() {
            gate.record_result(&meta, true, user).await;
            meta.user_id = user;
            let (action, reason) = gate.evaluate_post_auth(&mut meta).await;
            if action == ThreatAction::Reject {
                self.log_event(
                    c,
                    Some(user),
                    "login_failed",
                    "conditional_access",
                    email,
                    &ip,
                    true,
                )
                .await;
                c.authed = false;
                c.user = 0;
                return c
                    .reply(535, &format!("5.7.0 Access blocked by policy: {reason}"))
                    .await;
            }
        }
        self.admit(c, user, authenticated_at).await
    }

    /// Per-user slot, then the revocation registry, then 235.
    async fn admit(
        &self,
        c: &mut State,
        user: i64,
        authenticated_at: std::time::SystemTime,
    ) -> io::Result<()> {
        match self.users.try_acquire(user) {
            Ok(slot) => {
                // Mirrored Go defect: a second successful AUTH overwrites `c.release`
                // without calling it, so the first slot is never given back.
                if let Some(first) = c.slot.replace(slot) {
                    std::mem::forget(first);
                }
            }
            Err(()) => {
                c.authed = false;
                c.user = 0;
                return c.reply(550, "Too many connections from this account").await;
            }
        }
        c.registry_release = None;
        if let Some(registry) = &self.registry {
            c.registry_release = Some(registry.register(user, authenticated_at, c.closer.clone()));
        }
        c.reply(235, "Authentication successful").await
    }

    /// `pwhash.CheckAppPassword`.
    async fn check_app_password(&self, c: &mut State, email: &str, token: &str) -> Option<i64> {
        let digest = Sha256::digest(token.as_bytes());
        let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let found = c
            .query(
                &self.db,
                "SELECT u.id FROM users u JOIN app_passwords ap ON ap.user_id = u.id \
                 WHERE lower(u.email) = lower($1) AND u.enabled = TRUE AND ap.token_hash = $2 \
                 AND ap.revoked_at IS NULL AND (ap.expires_at IS NULL OR ap.expires_at > now())",
                &[(&email, Type::TEXT), (&hash, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()));
        let Some(user) = found else {
            self.log_event(c, None, "login_failed", "app_password", email, "", false)
                .await;
            return None;
        };
        let _ = c
            .query(
                &self.db,
                "UPDATE app_passwords SET last_used_at = now() \
                 WHERE user_id = $1 AND token_hash = $2 AND revoked_at IS NULL",
                &[(&user, Type::INT8), (&hash, Type::TEXT)],
            )
            .await;
        let _ = c
            .query(
                &self.db,
                "UPDATE users SET last_login_at = now() WHERE id = $1",
                &[(&user, Type::INT8)],
            )
            .await;
        self.log_event(c, Some(user), "login", "app_password", email, "", false)
            .await;
        let rows = c
            .query(
                &self.db,
                "SELECT id FROM users WHERE id = $1 AND enabled = TRUE",
                &[(&user, Type::INT8)],
            )
            .await
            .ok()?;
        rows.first()?;
        Some(user)
    }

    /// `auth.CheckPassword`: bcrypt/SM3 verification, best-effort below-floor
    /// self-heal, then the fail-closed guest check.
    async fn check_user_password(&self, c: &mut State, email: &str, password: &str) -> Option<i64> {
        let rows = c
            .query(
                &self.db,
                "SELECT u.id, u.password_hash FROM users u JOIN domains d ON d.id = u.domain_id \
                 WHERE u.email = $1 AND u.enabled = TRUE",
                &[(&email, Type::TEXT)],
            )
            .await
            .ok();
        // Security fix (SECFIX3 pattern, #501): frozen Go returned before any hash
        // for an unknown/disabled/hash-less account, so timing revealed which
        // accounts exist. Every such path now costs one verify of the profile's
        // algorithm.
        let known = rows.as_ref().and_then(|rows| rows.first()).and_then(|row| {
            let hash = row.try_get::<_, String>(1).ok().filter(|h| !h.is_empty())?;
            Some((row.get::<_, i64>(0), hash))
        });
        let Some((id, hash)) = known else {
            if !crate::mutants::on("smtp-no-dummy-hash") {
                self.dummy_verifications
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let dummy = self.dummy_hash;
                let pw = password.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    setjoin_authz::password::verify(dummy, &pw)
                })
                .await;
            }
            return None;
        };
        let verified = hash.clone();
        let pw = password.to_string();
        let (valid, upgrade) = tokio::task::spawn_blocking(move || {
            let valid = setjoin_authz::password::verify(&hash, &pw);
            let upgrade = valid
                .then(|| setjoin_authz::password::standard_upgrade(&hash, &pw))
                .flatten();
            (valid, upgrade)
        })
        .await
        .ok()?;
        if !valid {
            return None;
        }
        if let Some(new) = upgrade {
            let _ = c
                .query(
                    &self.db,
                    "UPDATE users SET password_hash = $1 WHERE email = $2 AND password_hash = $3",
                    &[(&new, Type::TEXT), (&email, Type::TEXT), (&verified, Type::TEXT)],
                )
                .await;
        }
        let guest = c
            .query(
                &self.db,
                "SELECT is_guest_account($1)",
                &[(&id, Type::INT8)],
            )
            .await
            .ok()?;
        if guest.first()?.try_get::<_, bool>(0).ok()? {
            return None;
        }
        Some(id)
    }

    // ---- envelope ------------------------------------------------------

    async fn mail(&self, c: &mut State, arg: &[u8]) -> io::Result<()> {
        if !c.authed {
            return c.reply(530, "Authentication required").await;
        }
        if !has_prefix(arg, b"FROM:") {
            return c.reply(501, "Syntax error").await;
        }
        c.from = mime::extract_addr(&arg[5..]);
        let from = String::from_utf8(c.from.clone()).ok();
        let user = c.user;
        let allowed = match &from {
            None => None,
            Some(from) => c
                .query(
                    &self.db,
                    "SELECT EXISTS(\
                     SELECT 1 FROM mailboxes mb \
                     LEFT JOIN aliases a ON a.mailbox_id = mb.id AND lower(a.email) = lower($1) \
                     WHERE mb.user_id = $2 AND mailbox_lifecycle_access_allowed(mb.id) \
                     AND (lower(mb.email) = lower($1) OR a.id IS NOT NULL))",
                    &[(from, Type::TEXT), (&user, Type::INT8)],
                )
                .await
                .ok()
                .and_then(|rows| rows.first().map(|r| r.get::<_, bool>(0))),
        };
        if allowed != Some(true) {
            c.from.clear();
            return c
                .reply(553, "Envelope-from address not authorized for this user")
                .await;
        }
        c.reply(250, "OK").await
    }

    async fn rcpt(&self, c: &mut State, arg: &[u8]) -> io::Result<()> {
        if !c.authed {
            return c.reply(530, "Authentication required").await;
        }
        if !has_prefix(arg, b"TO:") {
            return c.reply(501, "Syntax error").await;
        }
        if c.from.is_empty() {
            return c.reply(503, "Need MAIL before RCPT").await;
        }
        if c.to.len() >= MAX_RECIPIENTS {
            return c.reply(452, "Too many recipients").await;
        }
        c.to.push(mime::extract_addr(&arg[3..]));
        c.reply(250, "OK").await
    }

    /// Returns false when the connection must close.
    async fn data(&self, c: &mut State) -> io::Result<bool> {
        if !c.authed {
            c.reply(530, "Authentication required").await?;
            return Ok(true);
        }
        if c.from.is_empty() || c.to.is_empty() {
            c.reply(503, "Need MAIL and RCPT before DATA").await?;
            return Ok(true);
        }
        c.reply(354, "Start mail input; end with <CRLF>.<CRLF>")
            .await?;
        // No spill and no admission semaphore: Go reads the frame with io.ReadAll.
        let unlimited = Arc::new(tokio::sync::Semaphore::new(
            tokio::sync::Semaphore::MAX_PERMITS,
        ));
        let body = match tokio::time::timeout(
            COMMAND_TIMEOUT,
            framing::data(&mut c.io, unlimited),
        )
        .await
        {
            Ok(Err(framing::DataError::BareLf)) => {
                c.reply(500, "5.5.2 Bare LF not allowed").await?;
                return Ok(false);
            }
            Ok(Err(_)) | Err(_) => {
                c.reply(451, "Error reading message").await?;
                return Ok(true);
            }
            Ok(Ok(body)) => body,
        };
        if body.bytes.len() > framing::MAX_MESSAGE {
            c.reply(552, "Message size exceeds fixed maximum message size")
                .await?;
            return Ok(true);
        }
        if let Some(error) = framing::long_line(&body.bytes) {
            c.write(error.as_bytes()).await?;
            return Ok(true);
        }
        let result = self.submit(c, body.bytes).await?;
        c.reset();
        if result {
            c.reply(250, "OK").await?;
        }
        Ok(true)
    }

    /// True only when the send reducer committed; every failure replies itself.
    async fn submit(&self, c: &mut State, data: Vec<u8>) -> io::Result<bool> {
        let mut msg = data;
        let subject = mime::go_lossy(&mime::extract_header(&msg, "Subject"));
        let mut message_id = mime::go_lossy(&mime::extract_header(&msg, "Message-Id"));
        if message_id.is_empty() {
            use ring::rand::SecureRandom;
            let mut id = [0u8; 8];
            let _ = ring::rand::SystemRandom::new().fill(&mut id);
            let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
            message_id = format!("<{hex}@{}>", local_hostname());
        }
        if mime::extract_header(&msg, "Date").is_empty() {
            let date = chrono::Local::now().format("%a, %d %b %Y %H:%M:%S %z");
            let mut prefixed = format!("Date: {date}\r\n").into_bytes();
            prefixed.extend_from_slice(&msg);
            msg = prefixed;
        }
        let user = c.user;
        {
            let (_, from_addr) = mime::parse_from(&mime::extract_header(&msg, "From"));
            let auth_email = c
                .query(
                    &self.db,
                    "SELECT email FROM users WHERE id = $1",
                    &[(&user, Type::INT8)],
                )
                .await
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()));
            if let Some(auth_email) = auth_email.filter(|e| !e.is_empty()) {
                let from_text = mime::go_lossy(&from_addr);
                if !from_text.eq_ignore_ascii_case(&auth_email)
                    && mime::extract_header(&msg, "Sender").is_empty()
                {
                    let mut prefixed = format!("Sender: <{auth_email}>\r\n").into_bytes();
                    prefixed.extend_from_slice(&msg);
                    msg = prefixed;
                }
            }
        }
        let in_reply_to = mime::go_lossy(&mime::extract_header(&msg, "In-Reply-To"));
        let references = mime::go_lossy(&mime::extract_header(&msg, "References"));
        let to_addrs = mime::parse_address_list(&mime::extract_header(&msg, "To"));
        let cc_addrs = mime::parse_address_list(&mime::extract_header(&msg, "Cc"));
        let bcc_addrs = mime::parse_address_list(&mime::extract_header(&msg, "Bcc"));
        let has_attachments = msg.windows(31).any(|w| w == b"Content-Disposition: attachment");
        let raw_ref = format!("blobs/{}", hex(&Sha256::digest(&msg)));

        let mailbox = match c
            .query(
                &self.db,
                "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
                &[(&user, Type::INT8)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()))
        {
            Some(id) => id,
            None => {
                c.reply(451, "4.3.0 Mailbox temporarily unavailable").await?;
                return Ok(false);
            }
        };
        let (_, mut from_addr) = mime::parse_from(&mime::extract_header(&msg, "From"));
        if from_addr.is_empty() {
            let rows = c
                .query(
                    &self.db,
                    "SELECT email, display_name FROM users WHERE id = $1",
                    &[(&user, Type::INT8)],
                )
                .await
                .ok();
            let resolved = rows.as_ref().and_then(|rows| rows.first()).and_then(|r| {
                let email = r.try_get::<_, String>(0).ok()?;
                r.try_get::<_, String>(1).ok()?;
                Some(email)
            });
            match resolved {
                Some(email) => from_addr = email.into_bytes(),
                None => {
                    c.reply(554, "5.3.0 Failed to resolve sender address")
                        .await?;
                    return Ok(false);
                }
            }
        }
        let from_addr = mime::go_lossy(&from_addr);
        if let Some(blobs) = &self.blobs {
            if blobs.put(&raw_ref, &msg).await.is_err() {
                c.reply(451, "4.3.0 Temporary storage failure").await?;
                return Ok(false);
            }
        }
        let Ok(conn) = self.db.connect_session().await else {
            c.reply(554, "5.3.0 Internal error").await?;
            return Ok(false);
        };
        if conn.batch("BEGIN").await.is_err() {
            c.reply(554, "5.3.0 Internal error").await?;
            return Ok(false);
        }
        for (key, guc) in [
            ("feature.rules_engine", "app.skip_rules"),
            ("feature.dlp", "app.skip_dlp"),
            ("feature.journaling", "app.skip_journaling"),
            ("feature.retention", "app.skip_retention"),
        ] {
            if !self.feature(key) {
                let _ = conn
                    .query(
                        "SELECT set_config($1,'true',true)",
                        &[(&guc, Type::TEXT)],
                    )
                    .await;
            }
        }
        let fts = if self.feature("feature.full_text_search") {
            "false"
        } else {
            "true"
        };
        let _ = conn
            .query(
                "SELECT set_config('app.skip_fts',$1,true)",
                &[(&fts, Type::TEXT)],
            )
            .await;
        if !self.feature("feature.mailbox_audit_log") {
            let _ = conn
                .query(
                    "SELECT set_config('app.skip_audit','true',true)",
                    &[],
                )
                .await;
        }
        let rcpts: Vec<String> = c.to.iter().map(|r| mime::go_lossy(r)).collect();
        let envelope = Value::from(rcpts.clone()).to_string();
        let body_text = mime::go_lossy(&mime::extract_body_text(&msg));
        let body_html = mime::go_lossy(&mime::extract_body_html(&msg));
        let size = msg.len() as i64;
        let none: Option<&str> = None;
        let rows = conn
            .query_detailed(
                "SELECT message_id,subject_user_id,subject_mailbox_id,publication_enrolled \
                 FROM smtp_submission_send($1,$2,$3,$4,$5,$6::text::jsonb,$7::text::jsonb,$8::text::jsonb,$9,$10,$11,$12,$13,$14,$15,$16::text::timestamptz,$17::text::jsonb)",
                &[
                    (&user, Type::INT8),
                    (&mailbox, Type::INT8),
                    (&raw_ref, Type::TEXT),
                    (&message_id, Type::TEXT),
                    (&from_addr, Type::TEXT),
                    (&to_addrs, Type::TEXT),
                    (&cc_addrs, Type::TEXT),
                    (&bcc_addrs, Type::TEXT),
                    (&subject, Type::TEXT),
                    (&in_reply_to, Type::TEXT),
                    (&references, Type::TEXT),
                    (&body_text, Type::TEXT),
                    (&body_html, Type::TEXT),
                    (&size, Type::INT8),
                    (&has_attachments, Type::BOOL),
                    (&none, Type::TEXT),
                    (&envelope, Type::TEXT),
                ],
            )
            .await;
        let rows = match rows {
            Ok(rows) => rows,
            Err(error) => {
                let _ = conn.batch("ROLLBACK").await;
                let reply = reducer_reply::submission(&error);
                c.write(reply.as_bytes()).await?;
                return Ok(false);
            }
        };
        // Never acknowledge a lost commit; a dropped connection rolls back.
        if conn.batch("COMMIT").await.is_err() {
            c.reply(554, "5.3.0 Internal error").await?;
            return Ok(false);
        }
        let row = &rows[0];
        let sent: Option<i64> = row.get(0);
        let user_subject: Option<i64> = row.get(1);
        let mailbox_subject: Option<i64> = row.get(2);
        let enrolled: bool = row.get(3);
        if sent.is_some() && !enrolled {
            if let (Some(events), Some(user), Some(mailbox)) =
                (&self.events, user_subject, mailbox_subject)
            {
                for rcpt in &rcpts {
                    events.sent(user, mailbox, &from_addr, rcpt).await;
                }
            }
        }
        Ok(true)
    }
}

trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
type BoxStream = Box<dyn Stream>;

struct State {
    ip: String,
    io: BufReader<BoxStream>,
    tls: bool,
    authed: bool,
    user: i64,
    from: Vec<u8>,
    to: Vec<Vec<u8>>,
    db: Option<WorkerConnection>,
    slot: Option<UserSlot>,
    registry_release: Option<setjoin_threat::registry::SessionRelease>,
    closer: Closer,
}

impl State {
    fn reset(&mut self) {
        self.from.clear();
        self.to.clear();
    }
    async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let stream = self.io.get_mut();
        stream.write_all(bytes).await?;
        stream.flush().await
    }
    async fn reply(&mut self, code: u16, text: &str) -> io::Result<()> {
        self.write(format!("{code} {text}\r\n").as_bytes()).await
    }
    /// One AUTH continuation line (Go ignores the read error and uses ""). Lines
    /// beyond the cap are drained and refused as invalid base64 (Go kept them
    /// all in memory; recorded in `oracle/divergences.json`).
    async fn continuation(&mut self) -> io::Result<Option<String>> {
        let line = tokio::time::timeout(COMMAND_TIMEOUT, framing::command(&mut self.io)).await;
        Ok(match line {
            Ok(Ok(framing::Line::Bytes(b))) if b.len() <= CONTINUATION_CAP => {
                Some(String::from_utf8_lossy(&b).into_owned())
            }
            Ok(Ok(framing::Line::Bytes(_) | framing::Line::TooLong)) => Some("!".into()),
            _ => None,
        })
    }
    /// One session-bound worker connection; a failed statement discards it.
    async fn query(
        &mut self,
        db: &WorkerDatabase,
        sql: &str,
        params: &[setjoin_pg::Param<'_>],
    ) -> Result<Vec<setjoin_pg::Row>, String> {
        if self.db.is_none() {
            self.db = Some(db.connect_session().await.map_err(|e| e.to_string())?);
        }
        let result = self.db.as_ref().unwrap().query(sql, params).await;
        if result.is_err() {
            self.db = None;
        }
        result
    }
}

fn has_prefix(arg: &[u8], prefix: &[u8]) -> bool {
    arg.len() >= prefix.len() && arg[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Go `base64.StdEncoding.DecodeString`: padded, trailing bits tolerated.
fn decode_std(text: &str) -> Option<Vec<u8>> {
    use base64::{
        alphabet,
        engine::{general_purpose::GeneralPurposeConfig, GeneralPurpose},
        Engine,
    };
    const STD: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    STD.decode(text.as_bytes()).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn local_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into())
}
