//! Inbound SMTP session. Whole-listener activation belongs to #351.
mod admission;
mod delivery;
mod framing;
pub mod inbound;
pub mod mail_auth;
mod mutants;
pub mod outbound;
mod reducer_reply;
pub mod submission;
mod tls;
pub use delivery::{DeliveryEvents, DeliveryFeatures, RawBlobs};
use futures_util::{stream::FuturesUnordered, StreamExt};
use std::{io, sync::Arc, time::Duration};
pub use submission::Submission;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};

struct Effective {
    auth: Option<mail_auth::MailAuth>,
    greylisting: bool,
    features: DeliveryFeatures,
}
pub struct Server {
    auth: Option<mail_auth::MailAuth>,
    greylisting: bool,
    max_connections: usize,
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    enforce: bool,
    db: Option<setjoin_pg::workers::WorkerDatabase>,
    large: Arc<tokio::sync::Semaphore>,
    features: DeliveryFeatures,
    events: Option<Arc<dyn DeliveryEvents>>,
    blobs: Option<Arc<dyn RawBlobs>>,
    tls_files: Option<(std::path::PathBuf, std::path::PathBuf)>,
    flags: Option<Arc<dyn submission::Flags>>,
    spam_store: Option<Arc<setjoin_spam::Store>>,
    inbound: Arc<inbound::Pipeline>,
}
impl Default for Server {
    fn default() -> Self {
        Self {
            auth: None,
            db: None,
            greylisting: false,
            max_connections: 100,
            tls: None,
            enforce: false,
            large: Arc::new(tokio::sync::Semaphore::new(4)),
            features: DeliveryFeatures::default(),
            events: None,
            blobs: None,
            tls_files: None,
            flags: None,
            spam_store: None,
            inbound: inbound::Pipeline::new(Default::default()),
        }
    }
}
impl Server {
    pub fn with_inbound_config(mut self, config: inbound::Config) -> Self {
        self.inbound = inbound::Pipeline::new(config);
        self
    }
    pub fn with_spam_store(mut self, store: Arc<setjoin_spam::Store>) -> Self {
        self.spam_store = Some(store);
        self
    }
    pub fn spam_stats(&self) -> setjoin_spam::BatchStats {
        self.spam_store
            .as_ref()
            .map_or(Default::default(), |s| s.stats())
    }
    pub fn with_mail_auth(mut self, auth: mail_auth::MailAuth) -> Self {
        self.auth = Some(auth);
        self
    }
    pub fn with_greylisting(mut self, enabled: bool) -> Self {
        self.greylisting = enabled;
        self
    }
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }
    pub fn with_tls(mut self, tls: Arc<tokio_rustls::rustls::ServerConfig>) -> Self {
        self.tls = Some(tls);
        self
    }
    /// Production TLS (#501): the Go cipher/curve policy with the files re-read at
    /// every handshake, so a renewed certificate is served without a restart.
    pub fn with_tls_files(
        mut self,
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
    ) -> Result<Self, String> {
        tls::server_config(&cert, &key)?;
        self.tls_files = Some((cert, key));
        Ok(self)
    }
    /// Per-session feature flags (`feature_toggles`): greylisting, mail
    /// authentication and the delivery GUCs follow the live registry like Go's
    /// `toggles.IsEnabled` instead of a startup snapshot.
    pub fn with_flags(mut self, flags: Arc<dyn submission::Flags>) -> Self {
        self.flags = Some(flags);
        self
    }
    fn tls_config(&self) -> io::Result<Option<Arc<tokio_rustls::rustls::ServerConfig>>> {
        if let Some(tls) = &self.tls {
            return Ok(Some(tls.clone()));
        }
        match &self.tls_files {
            Some((cert, key)) => tls::server_config(cert, key)
                .map(Some)
                .map_err(io::Error::other),
            None => Ok(None),
        }
    }
    fn has_tls(&self) -> bool {
        self.tls.is_some() || self.tls_files.is_some()
    }
    fn effective(&self) -> Effective {
        let Some(flags) = &self.flags else {
            return Effective {
                auth: self.auth.clone(),
                greylisting: self.greylisting,
                features: self.features.clone(),
            };
        };
        let on = |key: &str| flags.enabled(key);
        Effective {
            auth: self.auth.clone().map(|auth| {
                auth.with_features(mail_auth::Features {
                    spf: on("feature.spf"),
                    dkim: on("feature.dkim"),
                    dmarc: on("feature.dmarc"),
                    arc: on("feature.arc"),
                })
            }),
            greylisting: on("feature.greylisting"),
            features: DeliveryFeatures {
                rules: on("feature.rules_engine"),
                vacation: on("feature.vacation"),
                journaling: on("feature.journaling"),
                retention: on("feature.retention"),
                full_text_search: on("feature.full_text_search"),
                audit: on("feature.mailbox_audit_log"),
                external_first_time: on("feature.external_sender_first_time"),
            },
        }
    }
    pub fn with_tls_enforce(mut self, enforce: bool) -> Self {
        self.enforce = enforce;
        self
    }
    pub fn with_delivery_features(mut self, features: DeliveryFeatures) -> Self {
        self.features = features;
        self
    }
    pub fn with_delivery_events(mut self, events: Arc<dyn DeliveryEvents>) -> Self {
        self.events = Some(events);
        self
    }
    pub fn with_blob_store(mut self, blobs: Arc<dyn RawBlobs>) -> Self {
        self.blobs = Some(blobs);
        self
    }

    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_database(mut self, db: setjoin_pg::workers::WorkerDatabase) -> Self {
        self.spam_store = Some(Arc::new(setjoin_spam::Store::new(db.clone())));
        self.db = Some(db);
        self
    }
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut stop: watch::Receiver<bool>,
    ) -> io::Result<()> {
        self.inbound.initialize(self.flags.as_deref()).await;
        let mut sessions = tokio::task::JoinSet::new();
        let slots = Arc::new(tokio::sync::Semaphore::new(self.max_connections));
        // Refusals run beside the accept loop with their own bounds (security fix
        // 2026-11-05, #488: Go awaited an implicit-TLS handshake for a refused client
        // inline, so one stalled client froze every later accept).
        let refusals = Arc::new(tokio::sync::Semaphore::new(REFUSALS));
        let mut owned = std::collections::HashMap::new();
        loop {
            tokio::select! {
             _=stop.changed()=>break,
             conn=listener.accept()=>{
                let (socket,peer)=conn?;
                let ip=peer.ip().to_canonical().to_string();
                if !admission::allow(&self,&ip).await {
                    refuse(&mut sessions,&refusals,socket,self.tls_config().ok().flatten(),b"421 Too many connections from your IP\r\n").await;
                    continue;
                }
                let Ok(slot)=slots.clone().try_acquire_owned() else {
                    refuse(&mut sessions,&refusals,socket,self.tls_config().ok().flatten(),b"421 Too many connections, try again later\r\n").await;
                    continue;
                };
                let id=admission::session_id(&ip);
                admission::open(&self,&id,&ip).await;
                let server=self.clone();let sid=id.clone();
                let task=sessions.spawn(async move {
                    let _slot=slot;
                    let result=session(server.clone(),socket,&sid).await;
                    if !matches!(result,Ok(true)){admission::close(&server,&sid).await;}
                    result.map(|_|())
                });
                owned.insert(task.id(),id);
             },
             Some(done)=sessions.join_next_with_id()=>{let id=match done{Ok((id,_))=>id,Err(error)=>error.id()};owned.remove(&id);}
            }
        }
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        for id in owned.values() {
            admission::close(&self, id).await;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Greeting,
    Ehlo,
    Mail,
    Rcpt,
    Data,
}
trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
type BoxStream = Box<dyn Stream>;
async fn session(server: Arc<Server>, socket: TcpStream, session_id: &str) -> io::Result<bool> {
    let ip = socket.peer_addr()?.ip().to_canonical().to_string();
    let eff = server.effective();
    let spam_batch = server
        .spam_store
        .as_ref()
        .map(|store| Arc::new(tokio::sync::Mutex::new(store.batch())));
    let stream: BoxStream = if let Some(tls) = server.tls_config()? {
        let tls = tokio::time::timeout(
            Duration::from_secs(300),
            tokio_rustls::TlsAcceptor::from(tls.clone()).accept(socket),
        )
        .await
        .map_err(io::Error::other)??;
        Box::new(tls)
    } else {
        Box::new(socket)
    };
    let mut io = BufReader::new(stream);
    let mut upgraded = false;
    io.get_mut().write_all(b"220 mailserver ESMTP\r\n").await?;
    let mut phase = Phase::Greeting;
    let mut from = Vec::new();
    let mut spf = "none";
    let mut helo = String::new();

    let mut recipients = Vec::new();
    let mut database = None;
    loop {
        let line =
            match tokio::time::timeout(Duration::from_secs(300), framing::command(&mut io)).await {
                Err(_) => {
                    io.get_mut()
                        .write_all(b"421 4.4.2 Connection timed out\r\n")
                        .await?;
                    return Ok(false);
                }
                Ok(line) => match line? {
                    framing::Line::Eof => return Ok(false),
                    framing::Line::TooLong => {
                        io.get_mut()
                            .write_all(b"500 5.5.2 Line too long\r\n")
                            .await?;
                        continue;
                    }
                    framing::Line::Bytes(line) => line,
                },
            };
        let raw_arg = line
            .iter()
            .position(|&c| c == b' ')
            .map(|i| &line[i + 1..])
            .unwrap_or(&[]);
        let line = String::from_utf8_lossy(&line);
        let (token, arg) = line.split_once(' ').unwrap_or((&line, ""));
        // smtp-proto accepts a broader whitespace boundary than frozen Go's
        // strings.Cut(line," "). Only adopt its command when that boundary agrees.
        let wire = format!("{line}\r\n");
        let parsed = smtp_proto::Request::parse(&mut wire.as_bytes().iter());
        let upper = token.to_uppercase();
        let command = parsed
            .as_ref()
            .ok()
            .filter(|r| token.eq_ignore_ascii_case(r.name()))
            .map(|r| r.name())
            .unwrap_or(&upper);
        let reply = match command {
            "EHLO" => {
                phase = Phase::Ehlo;
                helo = arg.to_string();
                if server.has_tls() {
                    "250-mailserver\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250-STARTTLS\r\n250 SIZE 157286400\r\n"
                } else {
                    "250-mailserver\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250 SIZE 157286400\r\n"
                }
            }
            "HELO" => {
                phase = Phase::Ehlo;
                helo = arg.to_string();
                "250 mailserver\r\n"
            }
            "MAIL" => {
                if server.enforce && !upgraded {
                    "530 5.7.0 Must issue STARTTLS first\r\n"
                } else if phase != Phase::Ehlo {
                    "503 Send EHLO/HELO first\r\n"
                } else if !arg.to_uppercase().starts_with("FROM:") {
                    "501 Syntax error\r\n"
                } else {
                    from = setjoin_mime::extract_addr(&raw_arg[5..]);
                    recipients.clear();
                    spf = if let Some(auth) = &eff.auth {
                        auth.mail_from(&from, &helo, &ip).await
                    } else {
                        "none"
                    };
                    phase = Phase::Mail;
                    "250 OK\r\n"
                }
            }
            "RCPT" => {
                if !arg.to_uppercase().starts_with("TO:") {
                    "501 Syntax error\r\n"
                } else if phase != Phase::Mail && phase != Phase::Rcpt {
                    "503 Bad sequence of commands\r\n"
                } else if from.is_empty() {
                    "503 Need MAIL before RCPT\r\n"
                } else {
                    phase = Phase::Rcpt;
                    let recipient =
                        String::from_utf8(setjoin_mime::extract_addr(&raw_arg[3..])).ok();
                    if recipients.len() >= 1000 {
                        "452 Too many recipients\r\n"
                    } else if let Some(recipient) = recipient {
                        let known = recipient_exists(&server, &mut database, &recipient).await;
                        if known == Lookup::Failed && !mutants::on("smtp-lookup-failure-permanent")
                        {
                            // A lookup outage must be retried, never bounced (#488).
                            "451 4.3.0 Temporary lookup failure, please try again later\r\n"
                        } else if known != Lookup::Found {
                            "550 No such user here\r\n"
                        } else if greylisted(eff.greylisting, &mut database, &ip, &from, &recipient)
                            .await
                        {
                            "450 Greylisted — please retry in a few minutes\r\n"
                        } else {
                            recipients.push(recipient);
                            "250 OK\r\n"
                        }
                    } else {
                        "550 No such user here\r\n"
                    }
                }
            }
            "DATA" => {
                if phase != Phase::Rcpt {
                    "503 Need MAIL and RCPT before DATA\r\n"
                } else if recipients.is_empty() && !mutants::on("smtp-data-without-recipients") {
                    // Every RCPT was refused: nothing can be delivered, so never
                    // open DATA (frozen Go then answered 250 for a dropped message).
                    "554 5.5.1 No valid recipients\r\n"
                } else {
                    phase = Phase::Data;
                    io.get_mut()
                        .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                        .await?;
                    match tokio::time::timeout(
                        Duration::from_secs(300),
                        framing::data(&mut io, server.large.clone()),
                    )
                    .await
                    {
                        Ok(Err(framing::DataError::BareLf)) => {
                            io.get_mut()
                                .write_all(b"500 5.5.2 Bare LF not allowed\r\n")
                                .await?;
                            return Ok(false);
                        }
                        Ok(Err(framing::DataError::Saturated)) => {
                            "451 4.3.1 Mail system full, try again later\r\n"
                        }
                        Err(_) | Ok(Err(framing::DataError::Io)) => "451 Error reading message\r\n",
                        Ok(Ok(body)) => {
                            if body.bytes.len() > framing::MAX_MESSAGE {
                                "552 Message size exceeds fixed maximum message size\r\n"
                            } else if let Some(error) = framing::long_line(&body.bytes) {
                                io.get_mut().write_all(error.as_bytes()).await?;
                                continue;
                            } else {
                                let service = delivery::Delivery {
                                    auth: eff.auth.clone(),
                                    flags: server.flags.clone(),
                                    inbound: server.inbound.clone(),
                                    spam_batch: spam_batch.clone(),
                                    recipients: recipients.clone(),
                                    spf,
                                    db: server.db.clone(),
                                    features: eff.features.clone(),
                                    events: server.events.clone(),
                                    blobs: server.blobs.clone(),
                                };
                                // Go waits for every recipient, limits fanout to eight,
                                // and retains the first completed failure. Never cancel
                                // siblings after an independently committed delivery.
                                let result = {
                                    let mut recipients = recipients.iter();
                                    let mut deliveries = FuturesUnordered::new();
                                    for recipient in recipients.by_ref().take(8) {
                                        deliveries.push(service.receive(
                                            &from,
                                            recipient,
                                            &helo,
                                            &ip,
                                            &body.bytes,
                                        ));
                                    }
                                    let mut first = Ok(());
                                    let mut phish_dropped = false;
                                    while let Some(delivered) = deliveries.next().await {
                                        let delivered = match delivered {
                                            Ok(delivery::Accepted::PhishDrop) => {
                                                phish_dropped = true;
                                                // #544 (owner-approved security fix 2026-11-05): an
                                                // anti-phish rejection is a refusal, never a 250 that
                                                // silently drops the mail (the mutant restores Go's).
                                                if crate::mutants::on("smtp-phish-silent-drop") {
                                                    Ok(())
                                                } else {
                                                    Err(delivery::Failure::AntiPhishRejected)
                                                }
                                            }
                                            Ok(delivery::Accepted::Normal) => Ok(()),
                                            Err(error) => Err(error),
                                        };
                                        if first.is_ok()
                                            || matches!(
                                                &delivered,
                                                Err(delivery::Failure::DmarcRejected)
                                            )
                                        {
                                            first = delivered;
                                        } else if matches!(
                                            &delivered,
                                            Err(delivery::Failure::GroupRejected)
                                        ) && !matches!(
                                            &first,
                                            Err(delivery::Failure::DmarcRejected)
                                        ) {
                                            first = delivered;
                                        }
                                        if let Some(recipient) = recipients.next() {
                                            deliveries.push(service.receive(
                                                &from,
                                                recipient,
                                                &helo,
                                                &ip,
                                                &body.bytes,
                                            ));
                                        }
                                    }
                                    if phish_dropped
                                        && matches!(first, Err(delivery::Failure::DmarcRejected))
                                    {
                                        Err(delivery::Failure::DmarcAntiPhishRejected)
                                    } else {
                                        first
                                    }
                                };
                                let reply = result
                                    .as_ref()
                                    .map(|_| "250 OK\r\n")
                                    .unwrap_or_else(|error| delivery::failure(error));
                                from.clear();
                                recipients.clear();
                                phase = Phase::Ehlo;
                                reply
                            }
                        }
                    }
                }
            }
            "RSET" => {
                from.clear();
                recipients.clear();
                if phase != Phase::Greeting {
                    phase = Phase::Ehlo
                };
                "250 OK\r\n"
            }
            "NOOP" => "250 OK\r\n",
            "STARTTLS" => {
                if upgraded {
                    "503 TLS already active\r\n"
                } else if server.has_tls() {
                    io.get_mut()
                        .write_all(b"220 Ready to start TLS\r\n")
                        .await?;
                    let tls = server
                        .tls_config()?
                        .ok_or_else(|| io::Error::other("TLS configuration vanished"))?;
                    // Go replaces its textproto reader, discarding pipelined bytes.
                    let stream = io.into_inner();
                    let tls = tokio::time::timeout(
                        Duration::from_secs(300),
                        tokio_rustls::TlsAcceptor::from(tls.clone()).accept(stream),
                    )
                    .await
                    .map_err(io::Error::other)??;
                    io = BufReader::new(Box::new(tls) as BoxStream);
                    upgraded = true;
                    from.clear();
                    recipients.clear();
                    if phase != Phase::Greeting {
                        phase = Phase::Ehlo
                    }
                    continue;
                } else {
                    "503 STARTTLS not available\r\n"
                }
            }
            "QUIT" => "221 Bye\r\n",
            _ => "500 Command not recognized\r\n",
        };
        io.get_mut().write_all(reply.as_bytes()).await?;
        if command == "QUIT" || command == "STARTTLS" {
            admission::close(&server, session_id).await;
            io.get_mut().shutdown().await?;
            return Ok(true);
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lookup {
    Found,
    Missing,
    /// The database could not answer: neither a yes nor a no.
    Failed,
}
async fn recipient_exists(
    server: &Server,
    connection: &mut Option<setjoin_pg::workers::WorkerConnection>,
    addr: &str,
) -> Lookup {
    if connection.is_none() {
        let Some(db) = &server.db else {
            return Lookup::Missing;
        };
        let Ok(db) = db.connect().await else {
            return Lookup::Failed;
        };
        *connection = Some(db);
    }
    let db = connection.as_ref().unwrap();
    let Ok(rows)=db.query("SELECT EXISTS( \
        SELECT 1 FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id \
        WHERE a.email=lower($1) AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting' \
        UNION SELECT 1 FROM mailboxes m WHERE m.email=lower($1) \
        AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting' \
        UNION SELECT 1 FROM domains d JOIN mailboxes m ON m.id=d.catch_all_mailbox_id \
        WHERE lower($1) LIKE '%@' || d.name AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting')",
        &[(&addr,setjoin_pg::Type::TEXT)]).await else {*connection=None;return Lookup::Failed};
    if rows.first().is_some_and(|row| row.get::<_, bool>(0)) {
        Lookup::Found
    } else {
        Lookup::Missing
    }
}

const REFUSALS: usize = 64;
const REFUSAL_DEADLINE: Duration = Duration::from_secs(5);
/// Send a refusal without ever delaying the accept loop: bounded concurrency, a
/// short deadline for the whole exchange (including an implicit-TLS handshake),
/// and the socket is simply closed when the bound is exhausted.
async fn refuse(
    sessions: &mut tokio::task::JoinSet<io::Result<()>>,
    refusals: &Arc<tokio::sync::Semaphore>,
    socket: TcpStream,
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    reply: &'static [u8],
) {
    if mutants::on("smtp-inline-refusal") {
        // Frozen Go: the refusal (and its TLS handshake) ran in the accept loop.
        let _ = reject(socket, tls, reply).await;
        return;
    }
    let Ok(permit) = refusals.clone().try_acquire_owned() else {
        return;
    };
    sessions.spawn(async move {
        let _permit = permit;
        let _ = tokio::time::timeout(REFUSAL_DEADLINE, reject(socket, tls, reply)).await;
        Ok(())
    });
}
async fn reject(
    mut socket: TcpStream,
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    reply: &[u8],
) -> io::Result<()> {
    if let Some(tls) = tls {
        let mut socket = tokio_rustls::TlsAcceptor::from(tls).accept(socket).await?;
        socket.write_all(reply).await?;
        socket.shutdown().await
    } else {
        socket.write_all(reply).await?;
        socket.shutdown().await
    }
}

async fn greylisted(
    enabled: bool,
    connection: &mut Option<setjoin_pg::workers::WorkerConnection>,
    ip: &str,
    from: &[u8],
    to: &str,
) -> bool {
    if !enabled {
        return false;
    }
    let Ok(from) = std::str::from_utf8(from) else {
        return false;
    };
    let Some(db) = connection.as_ref() else {
        return false;
    };
    let result = db
        .query(
            "SELECT NOT greylist_check($1::inet,$2,$3)",
            &[
                (&ip, setjoin_pg::Type::TEXT),
                (&from, setjoin_pg::Type::TEXT),
                (&to, setjoin_pg::Type::TEXT),
            ],
        )
        .await;
    match result {
        Ok(rows) => rows.first().is_some_and(|row| row.get::<_, bool>(0)),
        Err(_) => {
            *connection = None;
            false
        }
    }
}
