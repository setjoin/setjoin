//! Queue transport on the worker credential. See DOX.md for Go's failure cuts.
use futures_util::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use serde_json::json;
use setjoin_pg::{workers::WorkerDatabase, Type};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::Mutex};

pub const NAME: &str = "outbound-mail";
pub const INTERVAL: Duration = Duration::from_secs(10);
pub trait RawSource: Send + Sync {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>>;
}
/// Forwarded link preparation runs after raw loading and before DKIM. A failed
/// transform retains the original bytes, matching frozen Go's fail-safe rule.
pub trait ForwardTransform: Send + Sync {
    fn apply(&self, raw: &[u8]) -> Result<Vec<u8>, String>;
}
/// Resolver and socket boundaries; protocol decisions stay in this crate.
pub trait Network: Send + Sync {
    fn mx<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<Vec<String>, String>>;
    fn connect<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<TcpStream, String>>;
}
pub mod dane;
mod mtasts;
pub use mtasts::PolicyFetch;
mod network;
mod tlsrpt;
pub mod transport;
pub use network::SystemNetwork;
mod wire;
pub use wire::Timeouts;
use wire::{Failure, Reply, Session};
// A failed statement is never retried. Subsequent independent statements may
// reconnect, as pgxpool does after discarding a failed session in frozen Go.
struct Statements {
    db: WorkerDatabase,
    connection: Mutex<Option<setjoin_pg::workers::WorkerConnection>>,
}
impl Statements {
    fn new(db: WorkerDatabase, connection: setjoin_pg::workers::WorkerConnection) -> Self {
        Self {
            db,
            connection: Mutex::new(Some(connection)),
        }
    }
    async fn query(
        &self,
        sql: &str,
        params: &[setjoin_pg::Param<'_>],
    ) -> Result<Vec<setjoin_pg::Row>, String> {
        let mut cached = self.connection.lock().await;
        if cached.is_none() {
            *cached = Some(self.db.connect_session().await.map_err(|e| e.to_string())?)
        }
        let result = cached.as_ref().unwrap().query(sql, params).await;
        if result.is_err() {
            *cached = None
        };
        result
    }
    async fn execute(&self, sql: &str, params: &[setjoin_pg::Param<'_>]) -> Result<(), String> {
        self.query(sql, params).await.map(|_| ())
    }
}
struct Item {
    forward_unwrap: bool,
    id: i64,
    message: String,
    from: String,
    recipients: Vec<String>,
    attempt: i32,
    mailbox: Option<i64>,
    pk: Option<i64>,
    received: Option<String>,
}
impl Item {
    fn read(row: setjoin_pg::Row) -> Option<Self> {
        Some(Self {
            forward_unwrap: row.try_get(8).ok()?,
            id: row.try_get(0).ok()?,
            message: row.try_get(1).ok()?,
            from: row.try_get(2).ok()?,
            recipients: row.try_get(3).ok()?,
            attempt: row.try_get(4).ok()?,
            mailbox: row.try_get(5).ok()?,
            pk: row.try_get(6).ok()?,
            received: row.try_get(7).ok()?,
        })
    }
}
struct Recipient {
    address: String,
    host: String,
    code: i32,
    text: String,
    outcome: &'static str,
    tls: bool,
}
fn recipient(address: &str, host: &str, result: Result<Reply, Failure>) -> Recipient {
    let (code, text, outcome, tls) = match result {
        Ok(reply) => (reply.code, reply.text, "accepted", reply.tls),
        Err(failure) => {
            let outcome = match failure.code {
                200..=299 => "accepted",
                400..=499 => "deferred",
                500..=599 => "rejected",
                _ => "error",
            };
            (
                failure.code,
                if failure.text.is_empty() {
                    failure.error
                } else {
                    failure.text
                },
                outcome,
                failure.tls,
            )
        }
    };
    Recipient {
        address: address.into(),
        host: host.into(),
        code,
        text,
        outcome,
        tls,
    }
}
pub struct OutboundWorker {
    transport: Option<Arc<transport::TransportSecurity>>,
    transform: Option<Arc<dyn ForwardTransform>>,
    db: WorkerDatabase,
    blobs: Arc<dyn RawSource>,
    network: Arc<dyn Network>,
    hostname: String,
    pool: Mutex<HashMap<String, Vec<Session>>>,
    trust: Arc<dane::Trust>,
    timeouts: Timeouts,
    policy: Mutex<(Instant, TlsPolicy)>,
    permits: Arc<tokio::sync::Semaphore>,
}
impl OutboundWorker {
    pub fn new(
        db: WorkerDatabase,
        blobs: Arc<dyn RawSource>,
        network: Arc<dyn Network>,
        hostname: String,
    ) -> Self {
        let trust = Arc::new(dane::Trust::system());
        Self {
            transport: None,
            transform: None,
            trust,
            timeouts: Timeouts::default(),
            policy: Mutex::new((Instant::now(), TlsPolicy::default())),
            permits: Arc::new(tokio::sync::Semaphore::new(20)),
            db,
            blobs,
            network,
            hostname,
            pool: Mutex::new(HashMap::new()),
        }
    }
    /// Startup requires an authoritative feature snapshot; cache preload itself
    /// is best-effort, as Go's InitMTASTSCache is.
    pub async fn initialize_transport(&self) -> Result<(), String> {
        if let Some(security) = &self.transport {
            security.refresh().await?;
            security.initialize_cache().await;
        }
        Ok(())
    }
    pub async fn refresh_transport_features(&self) {
        if let Some(security) = &self.transport {
            let _ = security.refresh().await;
        }
    }
    pub fn with_transport_security(mut self, security: Arc<transport::TransportSecurity>) -> Self {
        self.transport = Some(security);
        self
    }
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
    pub fn with_forward_transform(mut self, transform: Arc<dyn ForwardTransform>) -> Self {
        self.transform = Some(transform);
        self
    }
    /// Replace the PKIX trust anchors (the default is the system store).
    pub fn with_tls_roots(
        mut self,
        anchors: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        self.trust = Arc::new(dane::Trust::new(anchors));
        self
    }
    pub async fn close(&self) {
        self.pool.lock().await.clear()
    }
    async fn put(&self, host: &str, mut session: Session) {
        session.used = Instant::now();
        let mut pool = self.pool.lock().await;
        let sessions = pool.entry(host.to_owned()).or_default();
        if sessions.len() < 5 {
            sessions.push(session)
        }
    }
    async fn deliver(
        &self,
        host: &str,
        from: &str,
        to: &str,
        raw: &[u8],
        require_tls: bool,
        skip_tls: bool,
    ) -> Result<Reply, Failure> {
        let policy = if let Some(security) = &self.transport {
            security.dane_policy(host).await?
        } else {
            None
        };
        let dane_required = policy.is_some();
        let require_tls = require_tls || dane_required;
        let pooled = self
            .pool
            .lock()
            .await
            .get_mut(host)
            .and_then(Vec::pop)
            .filter(|s| s.used.elapsed().as_secs() < 60);
        if let Some(mut session) = pooled {
            session.rearm(self.timeouts);
            // A pooled session serves a DANE destination only if a TLSA record matched
            // its chain when it was established AND the current records still match
            // it (security fix 2026-11-05, #500: Go labelled every TLS session
            // DANE-validated, even one that never matched a record).
            let dane_ok = !dane_required
                || (session.tls
                    && session.dane
                    && session.dane_still_matches(host, &self.trust, policy.as_deref()));
            if (session.tls || !require_tls)
                && dane_ok
                && session
                    .command("RSET")
                    .await
                    .is_ok_and(|s| s.starts_with('2'))
            {
                if let Ok(reply) = session.send(from, to, raw).await {
                    self.put(host, session).await;
                    return Ok(reply);
                }
            }
            self.pool.lock().await.remove(host);
        }
        let socket = tokio::time::timeout(self.timeouts.connect, self.network.connect(host))
            .await
            .map_err(|_| {
                format!(
                    "connect: dial tcp {}:25: i/o timeout",
                    host.trim_end_matches('.')
                )
            })?
            .map_err(|e| format!("connect: {e}"))?;
        let mut session = Session::new(socket, self.timeouts);
        let line = session.line().await.map_err(|e| format!("greeting: {e}"))?;
        if !line.starts_with("220") {
            return Err(format!("unexpected greeting: {line}").into());
        }
        let has_tls = session.ehlo(&self.hostname).await?;
        if has_tls && (!skip_tls || dane_required) {
            session = session
                .upgrade(host, &self.hostname, self.trust.clone(), policy)
                .await?;
        } else if require_tls {
            return Err(format!(
                "TLS required but not offered by {host} (MTA-STS enforce or DANE policy)"
            )
            .into());
        }
        let reply = session.send(from, to, raw).await.map_err(|mut e| {
            e.tls = session.tls;
            e
        })?;
        self.put(host, session).await;
        Ok(reply)
    }
    async fn pending(&self) -> Result<Vec<Item>, String> {
        self.refresh_transport_features().await;
        let connection = self.db.connect_session().await.map_err(|e| e.to_string())?;
        self.refresh_policy(&connection).await;
        let depth = connection
            .query(
                "SELECT COUNT(*) FROM outbound_queue WHERE status IN ('pending','deferred')",
                &[],
            )
            .await;
        if let Ok(rows) = depth {
            let depth = rows[0].get::<_, i64>(0);
            if depth > 1000 {
                eprintln!("outbound queue backlog depth={depth}");
                // Frozen Go's polymorphic json_build_object(...,$1) cannot infer
                // $1's type (42P18), so its ignored pg_notify never publishes.
                // Do not repair the notification while transferring authority.
            }
        }
        drop(connection);
        let connection = self.db.connect_session().await.map_err(|e| e.to_string())?;
        let mut stream=connection.rows("SELECT q.id,q.message_id,q.from_addr,q.rcpt_addrs,q.attempt_count,q.mailbox_id,q.message_pk,m.received_at::text,q.forward_unwrap_links FROM outbound_queue q LEFT JOIN messages m ON m.id=q.message_pk WHERE q.status IN ('pending','deferred') AND q.next_attempt_at<=now() ORDER BY q.queued_at ASC LIMIT 10",&[]).await?;
        let mut items = vec![];
        // Go keeps already-scanned rows and ignores Rows.Err on a stream fault.
        while let Ok(Some(row)) = stream.next().await {
            if let Some(item) = Item::read(row) {
                items.push(item)
            }
        }
        drop(stream);
        drop(connection);
        Ok(items)
    }
    pub async fn tick(&self) -> Result<(), String> {
        let items = self.pending().await?;
        let mut deliveries = FuturesUnordered::new();
        for item in items {
            deliveries.push(async move {
                let _permit = self.permits.acquire().await.map_err(|e| e.to_string())?;
                let connection = self.db.connect_session().await.map_err(|e| e.to_string())?;
                self.deliver_item(&Statements::new(self.db.clone(), connection), &item)
                    .await;
                Ok::<_, String>(())
            })
        }
        let mut error = None;
        while let Some(result) = deliveries.next().await {
            if let Err(e) = result {
                error = Some(e)
            }
        }
        error.map_or(Ok(()), Err)
    }
    /// Go's ticker has no eager first pass. Saturation blocks dispatch before
    /// another batch is selected, preserving its twenty-delivery bound.
    pub async fn run_until(self, stop: impl std::future::Future<Output = ()>) {
        let worker = Arc::new(self);
        let mut tasks = tokio::task::JoinSet::new();
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        'running: loop {
            tokio::select! {
                _=&mut stop=>break,
                _=ticker.tick()=>{
                    let pending=tokio::select!{_=&mut stop=>break 'running,items=worker.pending()=>items};
                    let items=match pending{Ok(items)=>items,Err(e)=>{eprintln!("outbound-mail: {e}");continue}};
                    for item in items {
                        let permit=tokio::select!{_=&mut stop=>break 'running,permit=worker.permits.clone().acquire_owned()=>permit};
                        let Ok(permit)=permit else{break 'running};let worker=worker.clone();
                        tasks.spawn(async move {let _permit=permit;match worker.db.connect_session().await {Ok(conn)=>worker.deliver_item(&Statements::new(worker.db.clone(),conn),&item).await,Err(e)=>eprintln!("outbound-mail: {e}")}});
                    }
                },
                result=tasks.join_next(),if !tasks.is_empty()=>{if let Some(Err(e))=result{eprintln!("outbound-mail: {e}")}}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        worker.close().await;
    }
    async fn refresh_policy(&self, connection: &setjoin_pg::workers::WorkerConnection) {
        let mut cached = self.policy.lock().await;
        if Instant::now() < cached.0 {
            return;
        }
        if let Ok(rows)=connection.query("SELECT key,value->>0 FROM system_config WHERE key IN ('outbound_tls_enforce_domains','outbound_tls_skip_domains','outbound_tls_global_mode')",&[]).await{
            let mut policy=TlsPolicy::default();for row in rows{let (Ok(key),Ok(value))=(row.try_get::<_,String>(0),row.try_get::<_,String>(1))else{continue};match key.as_str(){"outbound_tls_enforce_domains"=>policy.enforce=serde_json::from_str(&value).unwrap_or_default(),"outbound_tls_skip_domains"=>policy.skip=serde_json::from_str(&value).unwrap_or_default(),"outbound_tls_global_mode"=>policy.global=value=="enforce",_=>{}}};cached.1=policy;
        }
        cached.0 = Instant::now() + Duration::from_secs(300);
    }
    async fn raw(&self, connection: &Statements, item: &Item) -> Result<Vec<u8>, String> {
        let rows=connection.query("UPDATE outbound_queue SET status='sending' WHERE id=$1 RETURNING COALESCE(raw_ref,'')",&[(&item.id,Type::INT8)]).await.map_err(|e|format!("failed to read raw_ref: {e}"))?;
        let raw: String = rows
            .first()
            .ok_or("failed to read raw_ref: no rows in result set")?
            .get(0);
        if raw.is_empty() {
            return Err("failed to read raw_ref: empty raw_ref".into());
        }
        if raw.contains(['\r', '\n']) {
            return Ok(raw.into_bytes());
        }
        self.blobs
            .get(&raw)
            .await
            .map_err(|e| format!("failed to read blob content: {e}"))
    }
    async fn deliver_item(&self, connection: &Statements, item: &Item) {
        let raw = match self.raw(connection, item).await {
            Ok(raw) => raw,
            Err(error) => {
                self.failed(connection, item, &error).await;
                return;
            }
        };
        let raw = if item.forward_unwrap {
            self.transform
                .as_ref()
                .and_then(|transform| transform.apply(&raw).ok())
                .unwrap_or(raw)
        } else {
            raw
        };
        let raw =
            crate::mail_auth::sign_outbound(&self.db, &item.from, &raw, item.forward_unwrap).await;
        let (results, last_error) = self.recipients(item, &raw).await;
        for r in &results {
            if let (Some(mailbox), Some(pk), Some(received)) = (
                item.mailbox,
                item.pk.filter(|p| *p != 0),
                item.received.as_ref(),
            ) {
                let host = if r.host.is_empty() {
                    None
                } else {
                    Some(&r.host)
                };
                let smtp_code = if r.code == 0 { None } else { Some(r.code) };
                let text = if r.text.is_empty() {
                    None
                } else {
                    Some(&r.text)
                };
                let attempt = i64::from(item.attempt) + 1;
                let _=connection.execute("INSERT INTO delivery_attempts(message_pk,received_at,mailbox_id,recipient_email,mx_host,attempt_number,smtp_code,smtp_text,outcome,tls) VALUES($1,$2::timestamptz,$3,$4,$5,$6::integer,$7,$8,$9,$10)",&[(&pk,Type::INT8),(received,Type::TEXT),(&mailbox,Type::INT8),(&r.address,Type::TEXT),(&host,Type::TEXT),(&attempt,Type::INT8),(&smtp_code,Type::INT4),(&text,Type::TEXT),(&r.outcome,Type::TEXT),(&r.tls,Type::BOOL)]).await;
            }
        }
        let accepted = results
            .iter()
            .filter(|r| r.outcome == "accepted")
            .collect::<Vec<_>>();
        if accepted.is_empty() {
            self.failed(
                connection,
                item,
                &format!("all recipients failed: {last_error}"),
            )
            .await;
            return;
        }
        let _=connection.execute("UPDATE outbound_queue SET status='delivered',delivered_at=now(),attempt_count=attempt_count+1 WHERE id=$1",&[(&item.id,Type::INT8)]).await;
        if let Some(first) = accepted.iter().find(|r| !r.address.is_empty()) {
            let details = json!({"delivered":accepted.len(),"total":results.len()}).to_string();
            let _=connection.execute("INSERT INTO message_trace(message_id,event,from_addr,rcpt_addr,remote_host,details) VALUES($1,'delivered',$2,$3,$4,$5::jsonb)",&[(&item.message,Type::TEXT),(&item.from,Type::TEXT),(&first.address,Type::TEXT),(&first.host,Type::TEXT),(&details,Type::TEXT)]).await;
        }
    }
    async fn recipients(&self, item: &Item, raw: &[u8]) -> (Vec<Recipient>, String) {
        let mut results = vec![];
        let mut last_error = String::new();
        for address in &item.recipients {
            let domain = address.rsplit_once('@').map_or("", |(_, d)| d);
            if domain.is_empty() {
                last_error = format!("invalid recipient address: {address}");
                results.push(recipient(address, "", Err(last_error.clone().into())));
                continue;
            }
            let hosts = self.network.mx(domain).await.unwrap_or_default();
            if hosts.is_empty() {
                last_error = format!("MX lookup failed for {domain}");
                results.push(recipient(address, "", Err(last_error.clone().into())));
                continue;
            }
            let mut final_result = Err(Failure::from(String::new()));
            let mut final_host = String::new();
            let (require_tls, skip_tls) = self.policy.lock().await.1.resolve(domain);
            let mta_policy = if let Some(security) = &self.transport {
                security.mta_policy(domain).await
            } else {
                None
            };
            let report_uri = if let Some(security) = &self.transport {
                security.report_uri(domain).await
            } else {
                String::new()
            };
            let mta_enforce = mta_policy.as_ref().is_some_and(|p| p.mode == "enforce");
            let require_tls = require_tls || mta_enforce;
            for host in hosts {
                final_host = host;
                if mta_enforce && !mta_policy.as_ref().unwrap().matches(&final_host) {
                    last_error =
                        format!("MTA-STS enforce: MX {final_host} not in policy for {domain}");
                    final_result = Err(last_error.clone().into());
                    continue;
                }
                final_result = self
                    .deliver(&final_host, &item.from, address, raw, require_tls, skip_tls)
                    .await;
                if let Some(security) = &self.transport {
                    security
                        .record_session(
                            domain,
                            &final_host,
                            &report_uri,
                            final_result.as_ref().err().map(|e| e.error.as_str()),
                        )
                        .await;
                }
                match &final_result {
                    Ok(_) => break,
                    Err(e) => last_error = format!("delivery to {address} failed: {}", e.error),
                }
            }
            results.push(recipient(address, &final_host, final_result));
        }
        (results, last_error)
    }
    async fn failed(&self, connection: &Statements, item: &Item, error: &str) {
        let attempts = i64::from(item.attempt) + 1;
        let status = if attempts >= 20 {
            "bounced"
        } else {
            "deferred"
        };
        let backoff = match attempts {
            10.. => 1440,
            5..=9 => 240,
            2..=4 => 15,
            _ => 1,
        };
        let _=connection.execute("UPDATE outbound_queue SET status=$1,attempt_count=$2::integer,last_error=$3,next_attempt_at=now()+make_interval(mins=>$4) WHERE id=$5",&[(&status,Type::TEXT),(&attempts,Type::INT8),(&error,Type::TEXT),(&backoff,Type::INT4),(&item.id,Type::INT8)]).await;
        if status == "bounced" {
            if let Some(to) = item.recipients.first().filter(|r| !r.is_empty()) {
                let details = json!({"error":error}).to_string();
                let _=connection.execute("INSERT INTO message_trace(message_id,event,from_addr,rcpt_addr,details) VALUES($1,'bounced',$2,$3,$4::jsonb)",&[(&item.message,Type::TEXT),(&item.from,Type::TEXT),(to,Type::TEXT),(&details,Type::TEXT)]).await;
            }
        }
    }
}

#[derive(Default)]
struct TlsPolicy {
    enforce: Vec<String>,
    skip: Vec<String>,
    global: bool,
}
impl TlsPolicy {
    fn resolve(&self, domain: &str) -> (bool, bool) {
        if self.enforce.iter().any(|v| v.eq_ignore_ascii_case(domain)) {
            (true, false)
        } else if self.skip.iter().any(|v| v.eq_ignore_ascii_case(domain)) {
            (false, true)
        } else {
            (self.global, false)
        }
    }
}
