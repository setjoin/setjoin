//! Live PostgreSQL + TCP-proxy proofs for Issue #540 (Wave 1.2):
//! - Capability handles (`MailboxTx`, `UserTx`, `AdminReadTx`, `AdminSensitiveRead`,
//!   `AdminWriteTx`, `WorkerTx` / `WorkerPool`) under `setjoin_app` (`NOBYPASSRLS`)
//!   and `setjoin_worker` (`BYPASSRLS`).
//! - 1-RTT `tokio::join!(biased; ...)` pipelining + 2-RTT interactive writes +
//!   multi-chunk (>64 KB) result streaming without `mpsc::channel(1)` deadlock.
//! - Pre-encoding (`ToSql` / `\0` / session lock refusal before `BEGIN` -> 0 wire bytes).
//! - Tightened Step 1 (`BEGIN`) failure truth table + mid-pipeline `BZ001`
//!   (not masked by `25P02`) + clean pool-of-1 recycle + quarantine on drop/timeout.
//! - `RecyclingMethod::Fast` stale-socket 1-retry on reads and 2-RTT `BEGIN`.
//! - Non-Tokio `std::thread::spawn` dirty-lease drop (zero panic) + PgBouncer-safe
//!   held-lock `CancelRequest` prompt release.
//! - `OptIn` bounded LRU prepared cache, `PlanCacheHint::ForceCustomPlan`, and
//!   zero `TYPEINFO_QUERY` on default `PreparedStatementMode::Unnamed`.

use setjoin_contracts::{
    authority::AuthorityKey,
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_db::lifecycle::accepted_contract;
use setjoin_pg::{
    mint, operation_hex, AppPool, AuditEvent, CommandOutcome, MailboxAuthContext,
    PgBouncerAttestation, PlanCacheHint, PreparedStatementMode, ReceiptCommand, Rejection,
    ScopedExecutor, ScopedTx, Timeouts, Type, WorkerPool,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_postgres::{
    types::{private::BytesMut, IsNull, ToSql},
    Client, NoTls,
};

// ---------------------------------------------------------------------------
// Test environment helpers (matching db_scope.rs DSN / REQUIRE_DB gate)
// ---------------------------------------------------------------------------

fn owner_dsn() -> Option<String> {
    ["TEST_DB_DSN", "DB_DSN"]
        .into_iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

fn require_db() -> bool {
    std::env::var("REQUIRE_DB").as_deref() == Ok("1")
}

fn explicit_app_dsn() -> Option<String> {
    std::env::var("DB_APP_DSN").ok().filter(|v| !v.is_empty())
}

fn explicit_worker_dsn() -> Option<String> {
    std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|v| !v.is_empty())
}

fn app_dsn(owner: &str) -> String {
    explicit_app_dsn().unwrap_or_else(|| swap_dsn_user(owner, "setjoin_app"))
}

fn worker_dsn(owner: &str) -> String {
    // Match WorkerDatabase::from_dsns & tests/sql-contracts: never strip a
    // SCRAM-SHA-256 password to forge setjoin_worker when DB_WORKER_DSN is unset.
    explicit_worker_dsn().unwrap_or_else(|| owner.to_owned())
}

fn swap_dsn_user(dsn: &str, role: &str) -> String {
    if let Some((scheme, rest)) = dsn.split_once("://") {
        if let Some((_, host)) = rest.split_once('@') {
            return format!("{scheme}://{role}@{host}");
        }
    }
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|p| !p.starts_with("user="))
        .map(str::to_owned)
        .collect();
    parts.push(format!("user={role}"));
    parts.join(" ")
}

fn replace_host_port(dsn: &str, addr: SocketAddr) -> String {
    if let Some((scheme, rest)) = dsn.split_once("://") {
        let (auth, after_auth) = match rest.split_once('@') {
            Some((a, b)) => (format!("{a}@"), b),
            None => (String::new(), rest),
        };
        let suffix = after_auth
            .find(['/', '?'])
            .map(|idx| &after_auth[idx..])
            .unwrap_or("");
        return format!("{scheme}://{auth}{addr}{suffix}");
    }
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|p| !p.starts_with("host=") && !p.starts_with("port="))
        .map(str::to_owned)
        .collect();
    parts.push(format!("host={}", addr.ip()));
    parts.push(format!("port={}", addr.port()));
    parts.join(" ")
}

fn parse_target_addr(dsn: &str) -> SocketAddr {
    let cfg: tokio_postgres::Config = dsn.parse().expect("valid DSN");
    let host = match cfg.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.as_str(),
        _ => "127.0.0.1",
    };
    let port = cfg.get_ports().first().copied().unwrap_or(5432);
    format!("{host}:{port}").parse().expect("TCP SocketAddr")
}

async fn connect_raw(dsn: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

fn skip_or_fail(test: &str, reason: &str) {
    if require_db() {
        panic!("REQUIRE_DB=1 but {test} cannot run: {reason}");
    }
    use std::io::Write;
    let line = format!("SETJOIN-PG-DB-SKIP (reason={reason}) test={test}\n");
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

struct Fixture {
    owner: Client,
    app_dsn: String,
    worker_dsn: String,
    user_a: i64,
    user_b: i64,
    mailbox_a: i64,
    mailbox_b: i64,
    message_a: i64,
    message_b: i64,
    created_ops: Vec<OperationId>,
}

static COUNTER: AtomicUsize = AtomicUsize::new(1);

fn next_op() -> OperationId {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&0x540_0000_0000_0001u64.to_be_bytes());
    bytes[8..].copy_from_slice(&n.to_be_bytes());
    OperationId(bytes)
}

fn make_envelope(authority: AuthorityKey) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: next_op(),
        authority,
        binding: accepted_contract(),
        payload_digest: Digest([0x5a; 32]),
        command: (),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

async fn make_tenant(owner: &Client, label: &str) -> (i64, i64, i64) {
    let mailbox: i64 = owner
        .query_one("SELECT mk_account($1)", &[&label])
        .await
        .expect("mk_account")
        .get(0);
    let user: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id = $1", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    let tag: i64 = owner
        .query_one("SELECT get_tag_id('Inbox', $1)", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    let hdr = format!("{label}-m1");
    let row = owner
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, \
             to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read) \
             VALUES ($1, $2, 1, $3, 'subject', 'sender@ext.test', '[]'::jsonb, '[]'::jsonb, 10, \
             'thr-' || $3, 'raw-' || $3, now(), FALSE) RETURNING id, received_at::text",
            &[&mailbox, &tag, &hdr],
        )
        .await
        .expect("insert message");
    let message: i64 = row.get(0);
    let received: String = row.get(1);
    owner
        .execute(
            "SELECT tag_message($1, $2::text::timestamptz, 'Inbox', $3, 'deliver', TRUE)",
            &[&message, &received, &mailbox],
        )
        .await
        .expect("tag_message");
    (user, mailbox, message)
}

async fn setup_fixture(test: &str) -> Option<Fixture> {
    let Some(owner_dsn) = owner_dsn() else {
        skip_or_fail(test, "no-dsn");
        return None;
    };
    let owner = match connect_raw(&owner_dsn).await {
        Ok(c) => c,
        Err(e) => {
            skip_or_fail(test, &format!("connect:{e}"));
            return None;
        }
    };
    let app_dsn = app_dsn(&owner_dsn);
    let worker_dsn = worker_dsn(&owner_dsn);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let prefix = format!("cap540-{}-{seq}", std::process::id());
    let (user_a, mailbox_a, message_a) = make_tenant(&owner, &format!("{prefix}-a")).await;
    let (user_b, mailbox_b, message_b) = make_tenant(&owner, &format!("{prefix}-b")).await;

    Some(Fixture {
        owner,
        app_dsn,
        worker_dsn,
        user_a,
        user_b,
        mailbox_a,
        mailbox_b,
        message_a,
        message_b,
        created_ops: Vec::new(),
    })
}

impl Fixture {
    async fn cleanup(self) {
        let mbs = vec![self.mailbox_a, self.mailbox_b];
        let users = vec![self.user_a, self.user_b];
        let o = &self.owner;
        let _ = o
            .batch_execute("BEGIN; SET LOCAL session_replication_role = replica")
            .await;
        for op in &self.created_ops {
            let _ = o
                .execute(
                    "DELETE FROM rust_operation_receipts WHERE operation_id = $1::text::uuid",
                    &[&operation_hex(*op)],
                )
                .await;
        }
        let _ = o
            .execute(
                "DELETE FROM mailbox_audit_log WHERE mailbox_id = ANY($1)",
                &[&mbs],
            )
            .await;
        let _ = o
            .execute(
                "DELETE FROM admin_audit_log WHERE user_id = ANY($1)",
                &[&users],
            )
            .await;
        let _ = o.batch_execute("COMMIT").await;
        let _ = o
            .execute("DELETE FROM messages WHERE mailbox_id = ANY($1)", &[&mbs])
            .await;
        let _ = o.batch_execute("BEGIN").await;
        let _ = o
            .execute("DELETE FROM mailboxes WHERE id = ANY($1)", &[&mbs])
            .await;
        let _ = o
            .execute("DELETE FROM users WHERE id = ANY($1)", &[&users])
            .await;
        let _ = o.batch_execute("COMMIT").await;
    }
}

// ---------------------------------------------------------------------------
// TCP Proxy helpers (RTT counting, socket kill, and Step-1 BEGIN fault injection)
// ---------------------------------------------------------------------------

struct CountingProxy {
    addr: SocketAddr,
    rtts: Arc<AtomicUsize>,
    c2s_bytes: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    drop_next_c2s: Arc<AtomicBool>,
    dropped_on_c2s: Arc<AtomicUsize>,
    _task: tokio::task::JoinHandle<()>,
}

impl CountingProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rtts = Arc::new(AtomicUsize::new(0));
        let c2s_bytes = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let drop_next_c2s = Arc::new(AtomicBool::new(false));
        let dropped_on_c2s = Arc::new(AtomicUsize::new(0));

        let rtts_c = Arc::clone(&rtts);
        let bytes_c = Arc::clone(&c2s_bytes);
        let conns_c = Arc::clone(&connections);
        let arm_c = Arc::clone(&drop_next_c2s);
        let drops_c = Arc::clone(&dropped_on_c2s);

        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                conns_c.fetch_add(1, Ordering::SeqCst);
                let Ok(server) = TcpStream::connect(upstream).await else {
                    continue;
                };
                let _ = client.set_nodelay(true);
                let _ = server.set_nodelay(true);
                let rtts = Arc::clone(&rtts_c);
                let bytes = Arc::clone(&bytes_c);
                let arm = Arc::clone(&arm_c);
                let drops = Arc::clone(&drops_c);
                // Track direction: false = last packet was server->client (so next c2s starts a new RTT)
                let awaiting_server = Arc::new(AtomicBool::new(false));

                tokio::spawn(async move {
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = server.into_split();
                    let await_c2s = Arc::clone(&awaiting_server);
                    let await_s2c = Arc::clone(&awaiting_server);

                    let c2s = async {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            let n = cr.read(&mut buf).await?;
                            if n == 0 {
                                break;
                            }
                            if arm.swap(false, Ordering::SeqCst) {
                                // Half-open fault: client thought the socket was alive
                                // at pool.get(), wrote its first c2s bytes, and the
                                // proxy immediately drops the connection without
                                // forwarding those bytes to PostgreSQL.
                                drops.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            bytes.fetch_add(n, Ordering::SeqCst);
                            if !await_c2s.swap(true, Ordering::SeqCst) {
                                rtts.fetch_add(1, Ordering::SeqCst);
                            }
                            sw.write_all(&buf[..n]).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    };
                    let s2c = async {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            let n = sr.read(&mut buf).await?;
                            if n == 0 {
                                break;
                            }
                            await_s2c.store(false, Ordering::SeqCst);
                            cw.write_all(&buf[..n]).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    };
                    tokio::select! {
                        _ = c2s => {}
                        _ = s2c => {}
                    }
                });
            }
        });

        Self {
            addr,
            rtts,
            c2s_bytes,
            connections,
            drop_next_c2s,
            dropped_on_c2s,
            _task: task,
        }
    }

    fn reset(&self) {
        self.rtts.store(0, Ordering::SeqCst);
        self.c2s_bytes.store(0, Ordering::SeqCst);
    }

    fn rtts(&self) -> usize {
        self.rtts.load(Ordering::SeqCst)
    }

    fn c2s_bytes(&self) -> usize {
        self.c2s_bytes.load(Ordering::SeqCst)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Arm a one-shot half-open fault: keep the pooled socket open until the
    /// client writes its next `c2s` byte, then drop immediately without
    /// forwarding to PostgreSQL.
    fn arm_drop_on_next_c2s(&self) {
        self.drop_next_c2s.store(true, Ordering::SeqCst);
    }

    fn dropped_on_c2s(&self) -> usize {
        self.dropped_on_c2s.load(Ordering::SeqCst)
    }
}

fn pg_error_response(sqlstate: &str, msg: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"ERROR\0");
    body.push(b'C');
    body.extend_from_slice(sqlstate.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(msg.as_bytes());
    body.push(0);
    body.push(0);
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(b'E');
    frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

fn pg_ready_for_query(status: u8) -> [u8; 6] {
    [b'Z', 0, 0, 0, 5, status]
}

fn pg_extended_ok_no_rows() -> Vec<u8> {
    let mut out = Vec::new();
    // ParseComplete ('1'), BindComplete ('2'), NoData ('n'), CommandComplete ("SELECT 0"), ReadyForQuery ('I')
    out.extend_from_slice(&[b'1', 0, 0, 0, 4]);
    out.extend_from_slice(&[b'2', 0, 0, 0, 4]);
    out.extend_from_slice(&[b'n', 0, 0, 0, 4]);
    let tag = b"SELECT 0\0";
    out.push(b'C');
    out.extend_from_slice(&((tag.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(&pg_ready_for_query(b'I'));
    out
}

fn burst_has_trailing_commit(buf: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut last_was_commit = false;
    while pos < buf.len() {
        if pos + 5 > buf.len() {
            return false;
        }
        let tag = buf[pos];
        let len = i32::from_be_bytes([buf[pos + 1], buf[pos + 2], buf[pos + 3], buf[pos + 4]]);
        if len < 4 {
            return false;
        }
        let frame_end = pos + 1 + (len as usize);
        if frame_end > buf.len() {
            return false;
        }
        last_was_commit = tag == b'Q' && &buf[pos + 5..frame_end] == b"COMMIT\0";
        pos = frame_end;
    }
    pos == buf.len() && last_was_commit
}

const FAULT_OFF: u8 = 0;
const FAULT_ALL_DB_ERR: u8 = 1;
const FAULT_AUTOCOMMIT_HAZARD: u8 = 2;
const FAULT_TRANSPORT_DROP: u8 = 3;

struct BeginFaultProxy {
    addr: SocketAddr,
    mode: Arc<AtomicU8>,
    connections: Arc<AtomicUsize>,
    _task: tokio::task::JoinHandle<()>,
}

impl BeginFaultProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mode = Arc::new(AtomicU8::new(FAULT_OFF));
        let connections = Arc::new(AtomicUsize::new(0));
        let mode_c = Arc::clone(&mode);
        let conns_c = Arc::clone(&connections);

        let task = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                conns_c.fetch_add(1, Ordering::SeqCst);
                let Ok(mut server) = TcpStream::connect(upstream).await else {
                    continue;
                };
                let _ = client.set_nodelay(true);
                let _ = server.set_nodelay(true);
                let mode = Arc::clone(&mode_c);

                tokio::spawn(async move {
                    let (mut cr, mut cw) = client.split();
                    let (mut sr, mut sw) = server.split();
                    let mut cbuf = vec![0u8; 65536];
                    let mut sbuf = vec![0u8; 65536];
                    loop {
                        tokio::select! {
                            n = cr.read(&mut cbuf) => {
                                let Ok(n) = n else { break };
                                if n == 0 { break; }
                                let active_mode = mode.load(Ordering::SeqCst);
                                if active_mode != FAULT_OFF && cbuf[..n].windows(16).any(|w| w == b"BEGIN READ WRITE") {
                                    // Consume the fault once.
                                    mode.store(FAULT_OFF, Ordering::SeqCst);
                                    if active_mode == FAULT_TRANSPORT_DROP {
                                        break;
                                    }
                                    // Buffer until the full pipelined burst through
                                    // the trailing Q("COMMIT\0") frame has arrived.
                                    let mut burst = cbuf[..n].to_vec();
                                    while !burst_has_trailing_commit(&burst) {
                                        match tokio::time::timeout(
                                            Duration::from_secs(2),
                                            cr.read(&mut cbuf),
                                        )
                                        .await
                                        {
                                            Ok(Ok(more)) if more > 0 => {
                                                burst.extend_from_slice(&cbuf[..more]);
                                            }
                                            _ => break,
                                        }
                                    }
                                    // Count the pipelined frames in this burst (1 Query BEGIN + K Sync-terminated extended steps + 1 Query COMMIT).
                                    // We parse exact PG v3 frontend messages starting at offset 0.
                                    let mut responses = Vec::new();
                                    let mut pos = 0usize;
                                    let mut step_idx = 0usize; // 0=BEGIN, 1=preamble, 2=business, ...
                                    while pos + 5 <= burst.len() {
                                        let tag = burst[pos];
                                        let len = i32::from_be_bytes([
                                            burst[pos + 1],
                                            burst[pos + 2],
                                            burst[pos + 3],
                                            burst[pos + 4],
                                        ]) as usize;
                                        if len < 4 || pos + 1 + len > burst.len() {
                                            break;
                                        }
                                        pos += 1 + len;
                                        if tag == b'Q' || tag == b'S' {
                                            if step_idx == 0 {
                                                // Step 1 (BEGIN) fails with server ErrorResponse.
                                                responses.extend_from_slice(&pg_error_response("53300", "synthetic BEGIN failure"));
                                                responses.extend_from_slice(&pg_ready_for_query(b'I'));
                                            } else if active_mode == FAULT_ALL_DB_ERR {
                                                responses.extend_from_slice(&pg_error_response("53300", "synthetic step failure"));
                                                responses.extend_from_slice(&pg_ready_for_query(b'I'));
                                            } else if active_mode == FAULT_AUTOCOMMIT_HAZARD {
                                                if tag == b'S' {
                                                    // Step 2/3 unexpectedly returns Ok!
                                                    responses.extend_from_slice(&pg_extended_ok_no_rows());
                                                } else {
                                                    // COMMIT on idle connection returns CommandComplete + ReadyForQuery
                                                    let tag_bytes = b"COMMIT\0";
                                                    responses.push(b'C');
                                                    responses.extend_from_slice(&((tag_bytes.len() + 4) as i32).to_be_bytes());
                                                    responses.extend_from_slice(tag_bytes);
                                                    responses.extend_from_slice(&pg_ready_for_query(b'I'));
                                                }
                                            }
                                            step_idx += 1;
                                        }
                                    }
                                    let _ = cw.write_all(&responses).await;
                                    continue;
                                }
                                if sw.write_all(&cbuf[..n]).await.is_err() { break; }
                            }
                            n = sr.read(&mut sbuf) => {
                                let Ok(n) = n else { break };
                                if n == 0 { break; }
                                if cw.write_all(&sbuf[..n]).await.is_err() { break; }
                            }
                        }
                    }
                });
            }
        });

        Self {
            addr,
            mode,
            connections,
            _task: task,
        }
    }
}

#[derive(Debug)]
struct SyntheticFailingToSql;

impl ToSql for SyntheticFailingToSql {
    fn to_sql(
        &self,
        _ty: &Type,
        _out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        Err("synthetic ToSql failure".into())
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    tokio_postgres::types::to_sql_checked!();
}

// ---------------------------------------------------------------------------
// 1. MailboxTx<ReadOnly> (25006 + divergent actor != owner)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mailbox_read_only_enforces_25006_and_supports_divergent_actor_owner() {
    let Some(fx) = setup_fixture("mailbox_read_only_enforces_25006").await else {
        return;
    };
    let pool = AppPool::from_dsn(&fx.app_dsn, 1).unwrap();
    // Delegated mailbox: actor = user_b, mailbox = mailbox_a (owned by user_a!).
    let delegated = mint::mailbox(
        ActorId::new(fx.user_b).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    let rows = pool
        .run_mailbox_read_pipelined(
            &delegated,
            "SELECT current_setting('app.current_mailbox_id')::bigint, \
                    current_setting('app.current_user_id')::bigint, \
                    (SELECT count(*)::bigint FROM messages WHERE id = $1), \
                    (SELECT count(*)::bigint FROM messages WHERE id = $2)",
            &[(&fx.message_a, Type::INT8), (&fx.message_b, Type::INT8)],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, i64>(0), fx.mailbox_a);
    assert_eq!(rows[0].get::<_, i64>(1), fx.user_b);
    assert_ne!(rows[0].get::<_, i64>(0), rows[0].get::<_, i64>(1));
    assert_eq!(
        rows[0].get::<_, i64>(2),
        1,
        "own delegated mailbox row visible"
    );
    assert_eq!(
        rows[0].get::<_, i64>(3),
        0,
        "foreign mailbox row hidden by RLS"
    );

    // Interactive MailboxTx<ReadOnly>: PG enforces 25006 on state-mutating SELECT.
    let mut tx = pool.begin_mailbox_read(&delegated).await.unwrap();
    let err = tx
        .query("SELECT nextval('users_id_seq')", &[])
        .await
        .unwrap_err();
    assert_eq!(err.sqlstate.as_deref(), Some("25006"), "{err:?}");
    drop(tx);

    // 1-RTT pipelined read also enforces 25006.
    let err = pool
        .run_mailbox_read_pipelined(&delegated, "SELECT nextval('users_id_seq')", &[])
        .await
        .unwrap_err();
    assert_eq!(err.sqlstate.as_deref(), Some("25006"), "{err:?}");

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 2. UserTx (empty mailbox GUC + verified actor + zero GUC leakage)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_tx_installs_empty_mailbox_guc_and_verified_actor() {
    let Some(fx) = setup_fixture("user_tx_empty_mailbox_guc").await else {
        return;
    };
    let pool = AppPool::from_dsn(&fx.app_dsn, 1).unwrap();
    let user = mint::user(ActorId::new(fx.user_a).unwrap(), Generation(1));

    let rows = pool
        .run_user_read_pipelined(
            &user,
            "SELECT NULLIF(current_setting('app.current_mailbox_id', true), ''), \
                    current_setting('app.current_user_id', true)::bigint",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, Option<String>>(0), None);
    assert_eq!(rows[0].get::<_, i64>(1), fx.user_a);

    let env = make_envelope(user.authority());
    let out = pool
        .run_user_write_pipelined(
            &env,
            &user,
            deadline(),
            "SELECT NULLIF(current_setting('app.current_mailbox_id', true), ''), \
                    current_setting('app.current_user_id', true)::bigint, \
                    current_setting('app.rust_operation_id', true)",
            &[],
            None,
            |rows| {
                Ok((
                    rows[0].get::<_, Option<String>>(0),
                    rows[0].get::<_, i64>(1),
                    rows[0].get::<_, String>(2),
                ))
            },
        )
        .await;
    match out {
        CommandOutcome::Committed((mb, actor, op)) => {
            assert_eq!(mb, None);
            assert_eq!(actor, fx.user_a);
            assert_eq!(op, operation_hex(env.operation));
        }
        other => panic!("expected Committed, got {other:?}"),
    }

    // Interactive UserTx<ReadOnly> also enforces 25006.
    let mut rtx = pool.begin_user_read(&user).await.unwrap();
    let err = rtx
        .query("SELECT nextval('users_id_seq')", &[])
        .await
        .unwrap_err();
    assert_eq!(err.sqlstate.as_deref(), Some("25006"), "{err:?}");
    drop(rtx);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 3. AdminWriteTx + AdminSensitiveRead under audit_policy.level = 'lean'
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_write_and_sensitive_read_commit_core_audit_under_lean_policy_and_enforce_25006() {
    let Some(fx) = setup_fixture("admin_core_audit_lean").await else {
        return;
    };
    let prev_level: String = fx
        .owner
        .query_one("SELECT level FROM audit_policy WHERE id = 1", &[])
        .await
        .unwrap()
        .get(0);
    fx.owner
        .execute("UPDATE audit_policy SET level = 'lean' WHERE id = 1", &[])
        .await
        .unwrap();

    let pool = AppPool::from_dsn(&fx.app_dsn, 2)
        .unwrap()
        .with_audit_keys("enc-key-540".into(), "hmac-key-540".into());
    let admin = mint::admin(ActorId::new(fx.user_a).unwrap(), Generation(1));

    // A) Interactive AdminWriteTx<Unaudited> -> record_audit -> AdminWriteTx<Audited>::commit
    let env1 = make_envelope(admin.authority());
    let tx = pool
        .begin_admin_write(&env1, &admin, deadline())
        .await
        .unwrap();
    let audit1 = AuditEvent::new("test.admin_interactive", "user")
        .unwrap()
        .with_target_id(fx.user_b)
        .with_notes("interactive-540");
    let tx = tx.record_audit(&audit1).await.unwrap();
    assert!(matches!(tx.commit().await, CommandOutcome::Committed(())));

    // B) 1-RTT pipelined AdminWrite
    let env2 = make_envelope(admin.authority());
    let audit2 = AuditEvent::new("test.admin_pipelined", "user")
        .unwrap()
        .with_target_id(fx.user_b)
        .with_notes("pipelined-540");
    let out = pool
        .run_admin_write_pipelined(
            &env2,
            &admin,
            deadline(),
            &audit2,
            "SELECT 1::int4",
            &[],
            None,
            |rows| Ok(rows[0].get::<_, i32>(0)),
        )
        .await;
    assert!(matches!(out, CommandOutcome::Committed(1)), "{out:?}");

    // C) AdminSensitiveRead single-call API: Tx 1 commits core audit, Tx 2 runs BEGIN READ ONLY.
    let audit3 = AuditEvent::new("test.ediscovery_read", "mailbox")
        .unwrap()
        .with_target_id(fx.mailbox_a)
        .with_notes("sensitive-540");
    let rows = pool
        .run_admin_sensitive_read(
            &admin,
            &audit3,
            "SELECT current_setting('transaction_read_only'), current_setting('app.current_user_id')::bigint",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        rows[0].get::<_, String>(0),
        "on",
        "Tx 2 must be BEGIN READ ONLY"
    );
    assert_eq!(rows[0].get::<_, i64>(1), fx.user_a);

    // D) AdminSensitiveRead blocks volatile state-mutating SELECT with PostgreSQL 25006!
    let audit4 = AuditEvent::new("test.ediscovery_volatile_block", "mailbox")
        .unwrap()
        .with_notes("volatile-25006");
    let err = pool
        .run_admin_sensitive_read(&admin, &audit4, "SELECT nextval('users_id_seq')", &[])
        .await
        .unwrap_err();
    assert_eq!(err.sqlstate.as_deref(), Some("25006"), "{err:?}");

    // E) AdminReadTx<Standard> also enforces real BEGIN READ ONLY (25006).
    let mut std_tx = pool.begin_admin_read(&admin).await.unwrap();
    let err = std_tx
        .query("SELECT nextval('users_id_seq')", &[])
        .await
        .unwrap_err();
    assert_eq!(err.sqlstate.as_deref(), Some("25006"), "{err:?}");
    drop(std_tx);

    // F) AdminSensitiveRead: when Tx 1 audit fails (e.g. invalid inet -> 22P02),
    //    Tx 2 MUST NEVER execute (single-call AND closure forms).
    let bad_audit = AuditEvent::new("test.ediscovery_tx1_fail", "mailbox")
        .unwrap()
        .with_ip("not-a-valid-ip");
    let err_single = pool
        .run_admin_sensitive_read(&admin, &bad_audit, "SELECT nextval('users_id_seq')", &[])
        .await
        .unwrap_err();
    assert_eq!(
        err_single.sqlstate.as_deref(),
        Some("22P02"),
        "expected Tx 1 audit failure (22P02), not Tx 2 25006: {err_single:?}"
    );

    let tx2_executed = Arc::new(AtomicBool::new(false));
    let tx2_flag = Arc::clone(&tx2_executed);
    let err_closure = pool
        .run_admin_sensitive_read_with(&admin, &bad_audit, async move |tx| {
            tx2_flag.store(true, Ordering::SeqCst);
            tx.query("SELECT 1::int4", &[]).await
        })
        .await
        .unwrap_err();
    assert_eq!(
        err_closure.sqlstate.as_deref(),
        Some("22P02"),
        "{err_closure:?}"
    );
    assert!(
        !tx2_executed.load(Ordering::SeqCst),
        "Tx 2 closure must NEVER run when Tx 1 audit fails"
    );

    // Verify ALL 4 successful core audit rows were committed under level='lean'
    // with actor == verified admin, and 0 rows were written for the failed audit.
    let count: i64 = fx
        .owner
        .query_one(
            "SELECT count(*)::bigint FROM admin_audit_log \
             WHERE user_id = $1 AND action IN ( \
               'test.admin_interactive', 'test.admin_pipelined', \
               'test.ediscovery_read', 'test.ediscovery_volatile_block' \
             )",
            &[&fx.user_a],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 4,
        "all core admin audits must commit even when audit_policy.level = 'lean'"
    );

    fx.owner
        .execute(
            "UPDATE audit_policy SET level = $1 WHERE id = 1",
            &[&prev_level],
        )
        .await
        .unwrap();
    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 4. WorkerPool & WorkerTx (BYPASSRLS + empty tenant GUCs)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn worker_pool_and_worker_tx_use_bypassrls_and_clear_tenant_gucs() {
    let Some(fx) = setup_fixture("worker_pool_bypassrls").await else {
        return;
    };
    let wpool = WorkerPool::from_dsn(&fx.worker_dsn, 2)
        .unwrap()
        .with_audit_keys("w-enc".into(), "w-hmac".into());

    let mut wtx = wpool.begin_repeatable_read_only().await.unwrap();
    let rows = wtx
        .query(
            "SELECT current_setting('transaction_isolation'), \
                    current_setting('transaction_read_only'), \
                    NULLIF(current_setting('app.current_mailbox_id', true), ''), \
                    NULLIF(current_setting('app.current_user_id', true), ''), \
                    (SELECT count(*)::bigint FROM messages WHERE id IN ($1, $2))",
            &[(&fx.message_a, Type::INT8), (&fx.message_b, Type::INT8)],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "repeatable read");
    assert_eq!(rows[0].get::<_, String>(1), "on");
    assert_eq!(rows[0].get::<_, Option<String>>(2), None);
    assert_eq!(rows[0].get::<_, Option<String>>(3), None);
    assert_eq!(
        rows[0].get::<_, i64>(4),
        2,
        "setjoin_worker BYPASSRLS sees cross-tenant rows"
    );
    wtx.commit().await.unwrap();

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 5. TCP Proxy 1-RTT & 2-RTT Proof + Multi-Chunk (>64 KB) No Deadlock
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_proxy_proves_1rtt_pipelined_and_2rtt_interactive_and_large_multichunk_no_deadlock() {
    let Some(mut fx) = setup_fixture("tcp_proxy_1rtt_multichunk").await else {
        return;
    };
    let upstream = parse_target_addr(&fx.app_dsn);
    let proxy = CountingProxy::start(upstream).await;
    let proxied_dsn = replace_host_port(&fx.app_dsn, proxy.addr);

    let pool = AppPool::from_dsn(&proxied_dsn, 1).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );

    // Warm up the single pooled connection.
    let _ = pool
        .run_mailbox_read_pipelined(&mb, "SELECT 1::int4", &[])
        .await
        .unwrap();

    // A) Warm 1-RTT pipelined read (RecyclingMethod::Fast = 0 checkout RTT + 1 pipeline RTT = 1 RTT).
    proxy.reset();
    let rows = pool
        .run_mailbox_read_pipelined(&mb, "SELECT 42::int4", &[])
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 42);
    assert_eq!(
        proxy.rtts(),
        1,
        "expected exactly 1 RTT for warm pipelined read (RecyclingMethod::Fast), got {}",
        proxy.rtts()
    );

    // B) Warm 1-RTT pipelined write WITH receipt = 1 RTT!
    let env = make_envelope(mb.authority());
    fx.created_ops.push(env.operation);
    let cmd = ReceiptCommand {
        family: "F18",
        command: "test.pipelined_1rtt",
    };
    proxy.reset();
    let out = pool
        .run_mailbox_write_pipelined(
            &env,
            &mb,
            deadline(),
            "UPDATE messages SET is_read = TRUE WHERE id = $1 AND mailbox_id = $2 RETURNING id",
            &[(&fx.message_a, Type::INT8), (&fx.mailbox_a, Type::INT8)],
            Some(cmd),
            |rows| Ok(rows[0].get::<_, i64>(0)),
        )
        .await;
    assert!(
        matches!(out, CommandOutcome::Committed(id) if id == fx.message_a),
        "{out:?}"
    );
    assert_eq!(
        proxy.rtts(),
        1,
        "expected exactly 1 RTT for warm pipelined receipted write, got {}",
        proxy.rtts()
    );

    // C) Interactive write (BEGIN+preamble 1 RTT + query 1 RTT + COMMIT 1 RTT <= 3 RTTs, vs 6-8 previously).
    let env2 = make_envelope(mb.authority());
    proxy.reset();
    let out2 = pool
        .run_mailbox_write(&env2, &mb, deadline(), async |tx| {
            let rows = tx.query("SELECT 99::int4", &[]).await?;
            Ok::<_, setjoin_pg::StatementFailure>(rows[0].get::<_, i32>(0))
        })
        .await;
    assert!(matches!(out2, CommandOutcome::Committed(99)), "{out2:?}");
    assert!(
        proxy.rtts() <= 3,
        "expected <= 3 RTTs for warm interactive write, got {}",
        proxy.rtts()
    );

    // D) Multi-chunk (>64 KB, ~256 KB) result set inside 1-RTT pipeline MUST NOT deadlock mpsc::channel(1)!
    let env3 = make_envelope(mb.authority());
    let big = tokio::time::timeout(
        Duration::from_secs(5),
        pool.run_mailbox_write_pipelined(
            &env3,
            &mb,
            deadline(),
            "SELECT g::int4, repeat('X', 1024) FROM generate_series(1, 256) AS g",
            &[],
            None,
            |rows| {
                let total_bytes: usize = rows.iter().map(|r| r.get::<_, String>(1).len()).sum();
                Ok((rows.len(), total_bytes))
            },
        ),
    )
    .await
    .expect("multi-chunk (>256 KB) 1-RTT pipeline must not deadlock");
    assert!(
        matches!(big, CommandOutcome::Committed((256, 262_144))),
        "{big:?}"
    );

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 6. Client-Side ToSql / NUL Failure Never Sends COMMIT or Writes Rows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_side_tosql_and_nul_failures_in_pipeline_never_send_commit_or_write_rows() {
    let Some(fx) = setup_fixture("client_side_preencode_zero_wire").await else {
        return;
    };
    let upstream = parse_target_addr(&fx.app_dsn);
    let proxy = CountingProxy::start(upstream).await;
    let proxied_dsn = replace_host_port(&fx.app_dsn, proxy.addr);

    let pool = AppPool::from_dsn(&proxied_dsn, 1).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    // Warm connection so any wire activity would show up cleanly.
    let _ = pool
        .run_mailbox_read_pipelined(&mb, "SELECT 1::int4", &[])
        .await
        .unwrap();

    let cmd = ReceiptCommand {
        family: "F18",
        command: "test.preencode_fail",
    };

    // Case 1: Mismatched ToSql type in step 3
    let env1 = make_envelope(mb.authority());
    let bad_num: i32 = 7;
    proxy.reset();
    let out1 = pool
        .run_mailbox_write_pipelined(
            &env1,
            &mb,
            deadline(),
            "SELECT $1::text",
            &[(&bad_num, Type::TEXT)],
            Some(cmd),
            |_| Ok(()),
        )
        .await;
    assert!(
        matches!(out1, CommandOutcome::RolledBack(Rejection::Statement(_))),
        "{out1:?}"
    );
    assert_eq!(
        proxy.c2s_bytes(),
        0,
        "mismatched ToSql must send 0 bytes on wire"
    );

    // Case 2: Custom failing ToSql in step 3
    let env2 = make_envelope(mb.authority());
    let failing = SyntheticFailingToSql;
    proxy.reset();
    let out2 = pool
        .run_mailbox_write_pipelined(
            &env2,
            &mb,
            deadline(),
            "SELECT $1::text",
            &[(&failing, Type::TEXT)],
            Some(cmd),
            |_| Ok(()),
        )
        .await;
    assert!(
        matches!(out2, CommandOutcome::RolledBack(Rejection::Statement(_))),
        "{out2:?}"
    );
    assert_eq!(
        proxy.c2s_bytes(),
        0,
        "custom ToSql error must send 0 bytes on wire"
    );

    // Case 3: Interior NUL byte in SQL
    let env3 = make_envelope(mb.authority());
    proxy.reset();
    let out3 = pool
        .run_mailbox_write_pipelined(&env3, &mb, deadline(), "SELECT 1\0", &[], Some(cmd), |_| {
            Ok(())
        })
        .await;
    assert!(
        matches!(out3, CommandOutcome::RolledBack(Rejection::Statement(_))),
        "{out3:?}"
    );
    assert_eq!(
        proxy.c2s_bytes(),
        0,
        "NUL byte in SQL must send 0 bytes on wire"
    );

    // Verify 0 receipts committed for all 3 operations.
    for op in [env1.operation, env2.operation, env3.operation] {
        let exists: bool = fx
            .owner
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id = $1::text::uuid)",
                &[&operation_hex(op)],
            )
            .await
            .unwrap()
            .get(0);
        assert!(
            !exists,
            "no receipt may be committed after client-side failure"
        );
    }

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 7. Step 1 (BEGIN) Failure Tightened Truth Table & Quarantine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn step1_begin_error_quarantines_and_classifies_tightened_truth_table() {
    let Some(fx) = setup_fixture("step1_begin_truth_table").await else {
        return;
    };
    let upstream = parse_target_addr(&fx.app_dsn);
    let proxy = BeginFaultProxy::start(upstream).await;
    let proxied_dsn = replace_host_port(&fx.app_dsn, proxy.addr);

    let pool = AppPool::from_dsn(&proxied_dsn, 1).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );

    // Warm connection #1 and record its PostgreSQL backend PID.
    let pid1: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);

    // Case A: Step 1 BEGIN returns server ErrorResponse AND every mutating step returns server ErrorResponse
    // -> RolledBack(Rejection::Unavailable) + connection quarantined!
    proxy.mode.store(FAULT_ALL_DB_ERR, Ordering::SeqCst);
    let env_a = make_envelope(mb.authority());
    let out_a = pool
        .run_mailbox_write_pipelined(&env_a, &mb, deadline(), "SELECT 1::int4", &[], None, |_| {
            Ok(())
        })
        .await;
    assert!(
        matches!(out_a, CommandOutcome::RolledBack(Rejection::Unavailable)),
        "expected RolledBack(Unavailable), got {out_a:?}"
    );
    // Next call must open a fresh backend PID (proving quarantine!)
    let pid2: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_ne!(pid2, pid1, "Step 1 BEGIN error must quarantine");

    // Case B: Step 1 BEGIN returns server ErrorResponse, while step 3 unexpectedly returns Ok (autocommit hazard!)
    // -> CommandOutcome::Unknown { operation } + connection quarantined!
    proxy.mode.store(FAULT_AUTOCOMMIT_HAZARD, Ordering::SeqCst);
    let env_b = make_envelope(mb.authority());
    let out_b = pool
        .run_mailbox_write_pipelined(&env_b, &mb, deadline(), "SELECT 1::int4", &[], None, |_| {
            Ok(())
        })
        .await;
    assert!(
        matches!(out_b, CommandOutcome::Unknown { operation } if operation == env_b.operation),
        "autocommit hazard on BEGIN error must yield Unknown, got {out_b:?}"
    );
    let pid3: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_ne!(pid3, pid2, "autocommit hazard must quarantine");

    // Case C: Step 1 BEGIN fails with transport drop (no ErrorResponse)
    // -> CommandOutcome::Unknown { operation } + connection quarantined!
    proxy.mode.store(FAULT_TRANSPORT_DROP, Ordering::SeqCst);
    let env_c = make_envelope(mb.authority());
    let out_c = pool
        .run_mailbox_write_pipelined(&env_c, &mb, deadline(), "SELECT 1::int4", &[], None, |_| {
            Ok(())
        })
        .await;
    assert!(
        matches!(out_c, CommandOutcome::Unknown { operation } if operation == env_c.operation),
        "BEGIN transport drop must yield Unknown, got {out_c:?}"
    );
    let pid4: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_ne!(pid4, pid3, "BEGIN transport drop must quarantine");
    assert!(proxy.connections.load(Ordering::SeqCst) >= 4);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 8. Mid-Pipeline BZ001 Rollback (not 25P02) + Pool-of-1 Clean Recycle + Timeout Quarantine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mid_pipeline_bz001_returns_bz001_not_25p02_and_recycles_cleanly_on_pool_of_1() {
    let Some(fx) = setup_fixture("mid_pipeline_bz001_recycle").await else {
        return;
    };
    let pool = AppPool::from_dsn(&fx.app_dsn, 1).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    let pid_before: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);

    // Business step calls calendar_free_busy_multi with nonexistent mailbox -> raises real BZ001!
    // Step 4 (receipt insert) receives 25P02; step 5 (COMMIT) rolls back cleanly.
    let env = make_envelope(mb.authority());
    let cmd = ReceiptCommand {
        family: "F17",
        command: "test.bz001_mid_pipeline",
    };
    let out = pool
        .run_mailbox_write_pipelined(
            &env,
            &mb,
            deadline(),
            "SELECT calendar_free_busy_multi(-9999999::bigint, ARRAY[]::bigint[], now(), now())::text",
            &[],
            Some(cmd),
            |_| Ok(()),
        )
        .await;
    match out {
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            assert_eq!(
                f.sqlstate.as_deref(),
                Some("BZ001"),
                "must preserve BZ001 and NEVER mask with 25P02: {f:?}"
            );
        }
        other => panic!("expected RolledBack(Statement(BZ001)), got {other:?}"),
    }

    // Receipt must NOT have committed.
    let receipt_exists: bool = fx
        .owner
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id = $1::text::uuid)",
            &[&operation_hex(env.operation)],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!receipt_exists);

    // Pool of size 1: SAME backend PID recycled cleanly AND all app.* GUCs empty!
    let probe = pool
        .run_mailbox_read_pipelined(
            &mb,
            "SELECT pg_backend_pid(), NULLIF(current_setting('app.rust_operation_id', true), '')",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        probe[0].get::<_, i32>(0),
        pid_before,
        "clean BZ001 rollback with COMMIT->ROLLBACK ack should recycle connection"
    );
    assert_eq!(probe[0].get::<_, Option<String>>(1), None);

    // Dropped / client-timed-out 1-RTT write MUST quarantine (different PID) with
    // zero leaked GUCs or open transaction on the next checkout.
    let env_drop = make_envelope(mb.authority());
    let fut = pool.run_mailbox_write_pipelined(
        &env_drop,
        &mb,
        Instant::now() + Duration::from_secs(10),
        "SELECT pg_sleep(5)::text",
        &[],
        None,
        |_| Ok(()),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(120), fut)
            .await
            .is_err(),
        "client timeout should drop in-flight 1-RTT write future"
    );
    let after_drop = pool
        .run_mailbox_read_pipelined(
            &mb,
            "SELECT pg_backend_pid(), NULLIF(current_setting('app.rust_operation_id', true), '')",
            &[],
        )
        .await
        .unwrap();
    assert_ne!(
        after_drop[0].get::<_, i32>(0),
        pid_before,
        "dropped/timed-out tx must quarantine and open a fresh backend"
    );
    assert_eq!(after_drop[0].get::<_, Option<String>>(1), None);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 9. Stale-Socket 1-Retry on 2-RTT Writes & Pure Reads (No Spurious Unknown)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stale_socket_retry_on_2rtt_write_and_read_only_avoids_spurious_unknown() {
    let Some(fx) = setup_fixture("stale_socket_fast_retry").await else {
        return;
    };
    let upstream = parse_target_addr(&fx.app_dsn);
    let proxy = CountingProxy::start(upstream).await;
    let proxied_dsn = replace_host_port(&fx.app_dsn, proxy.addr);

    let pool = AppPool::from_dsn(&proxied_dsn, 1).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );

    // 1) Pure read-only stale-socket 1-retry (half-open drop on first c2s write):
    let _ = pool
        .run_mailbox_read_pipelined(&mb, "SELECT 1::int4", &[])
        .await
        .unwrap();
    let conns_before = proxy.connections();
    let drops_before = proxy.dropped_on_c2s();
    proxy.arm_drop_on_next_c2s();
    let rows = pool
        .run_mailbox_read_pipelined(&mb, "SELECT 7::int4", &[])
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 7);
    assert_eq!(
        proxy.dropped_on_c2s(),
        drops_before + 1,
        "attempt 0 must write to half-open pooled socket and hit proxy c2s drop"
    );
    assert_eq!(
        proxy.connections(),
        conns_before + 1,
        "attempt 1 must open a fresh connection and succeed"
    );

    // 2) 2-RTT interactive AppPool::run_mailbox_write stale-socket retry (NO spurious Unknown!):
    let conns_before = proxy.connections();
    let drops_before = proxy.dropped_on_c2s();
    proxy.arm_drop_on_next_c2s();
    let env = make_envelope(mb.authority());
    let out = pool
        .run_mailbox_write(&env, &mb, deadline(), async |tx| {
            let r = tx.query("SELECT 11::int4", &[]).await?;
            Ok::<_, setjoin_pg::StatementFailure>(r[0].get::<_, i32>(0))
        })
        .await;
    assert!(
        matches!(out, CommandOutcome::Committed(11)),
        "2-RTT write must retry stale socket on BEGIN, never spurious Unknown: {out:?}"
    );
    assert_eq!(
        proxy.dropped_on_c2s(),
        drops_before + 1,
        "2-RTT write attempt 0 must hit half-open drop on BEGIN"
    );
    assert_eq!(proxy.connections(), conns_before + 1);

    // 3) Legacy ScopedExecutor::run 2-RTT stale-socket retry (NO spurious Unknown!):
    let legacy = ScopedExecutor::from_dsn(&proxied_dsn, 1).unwrap();
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    let _ = legacy.read("SELECT 1::int4", &[]).await.unwrap();
    let conns_before = proxy.connections();
    let drops_before = proxy.dropped_on_c2s();
    proxy.arm_drop_on_next_c2s();
    let env2 = make_envelope(auth.authority());
    let out2 = legacy
        .run(&env2, &auth, deadline(), async |tx: &mut ScopedTx| {
            let r = tx.query("SELECT 13::int4", &[]).await?;
            Ok::<_, setjoin_pg::StatementFailure>(r[0].get::<_, i32>(0))
        })
        .await;
    assert!(
        matches!(out2, CommandOutcome::Committed(13)),
        "legacy ScopedExecutor::run must retry stale socket on BEGIN: {out2:?}"
    );
    assert_eq!(
        proxy.dropped_on_c2s(),
        drops_before + 1,
        "legacy ScopedExecutor::run attempt 0 must hit half-open drop on BEGIN"
    );
    assert_eq!(proxy.connections(), conns_before + 1);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 10. Non-Tokio std::thread::spawn Dirty-Lease Drop Never Panics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dropping_dirty_lease_on_non_tokio_std_thread_never_panics() {
    let Some(fx) = setup_fixture("non_tokio_thread_drop").await else {
        return;
    };
    // Build pool on a plain OS thread so even captured runtime_handle is None!
    let app_dsn = fx.app_dsn.clone();
    let pool = std::thread::spawn(move || AppPool::from_dsn(&app_dsn, 1).unwrap())
        .join()
        .unwrap();

    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    // Open an active read-only tx (dirty lease!)
    let tx = pool.debug_open_read_tx(&mb).await.unwrap();
    // Drop it on a non-Tokio std::thread::spawn: must NOT panic!
    std::thread::spawn(move || {
        drop(tx);
    })
    .join()
    .expect("dropping dirty lease outside Tokio runtime must never panic");

    // Pool slot was synchronously freed -> pool of size 1 immediately serves next query.
    let rows = pool
        .run_mailbox_read_pipelined(&mb, "SELECT 123::int4", &[])
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 123);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 11. Held-Lock CancelRequest Promptly Releases pg_advisory_xact_lock
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_lock_cancel_request_releases_advisory_xact_lock_promptly_before_statement_timeout() {
    let Some(fx) = setup_fixture("held_lock_cancel_request").await else {
        return;
    };
    let long_timeouts = Timeouts {
        pool_wait: Duration::from_secs(2),
        create: Duration::from_secs(2),
        statement: Duration::from_secs(30),
    };
    let pool = AppPool::from_dsn_with(&fx.app_dsn, 1, long_timeouts).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    let lock_key: i64 = 540_000_000_000 + fx.mailbox_a;
    let env = make_envelope(mb.authority());

    // Start a 1-RTT write that takes pg_advisory_xact_lock(lock_key) and sleeps 25s,
    // then drop the future after 250ms (well before the 30s statement_timeout!).
    let lock_params: [setjoin_pg::Param<'_>; 1] = [(&lock_key, Type::INT8)];
    let fut = pool.run_mailbox_write_pipelined(
        &env,
        &mb,
        Instant::now() + Duration::from_secs(30),
        "SELECT pg_advisory_xact_lock($1), pg_sleep(25)::text",
        &lock_params,
        None,
        |_| Ok(()),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), fut)
            .await
            .is_err(),
        "sleeping query should have been cancelled client-side"
    );

    // Poll from owner until pg_try_advisory_lock(lock_key) succeeds — CancelRequest
    // must release the held lock promptly (far below the 30s statement_timeout).
    let start = Instant::now();
    let mut acquired = false;
    while start.elapsed() < Duration::from_secs(5) {
        let got: bool = fx
            .owner
            .query_one("SELECT pg_try_advisory_lock($1)", &[&lock_key])
            .await
            .unwrap()
            .get(0);
        if got {
            let _ = fx
                .owner
                .query_one("SELECT pg_advisory_unlock($1)", &[&lock_key])
                .await;
            acquired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        acquired,
        "held pg_advisory_xact_lock was not released promptly by CancelRequest (elapsed {:?})",
        start.elapsed()
    );

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 12. OptIn Bounded LRU Cap, ForceCustomPlan, and Unnamed Zero TYPEINFO_QUERY
// ---------------------------------------------------------------------------

#[tokio::test]
async fn opt_in_prepared_lru_cap_force_custom_plan_and_unnamed_zero_typeinfo() {
    let Some(fx) = setup_fixture("prepared_lru_and_unnamed").await else {
        return;
    };
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );

    // A) Default PreparedStatementMode::Unnamed creates ZERO named prepared statements
    //    (zero TYPEINFO_QUERY `s0`!).
    let unnamed_pool = AppPool::from_dsn(&fx.app_dsn, 1).unwrap();
    let _ = unnamed_pool
        .run_mailbox_read_pipelined(&mb, "SELECT 1::int4, 'hello'::text", &[])
        .await
        .unwrap();
    let env = make_envelope(mb.authority());
    let _ = unnamed_pool
        .run_mailbox_write_pipelined(
            &env,
            &mb,
            deadline(),
            "SELECT $1::int8, $2::text",
            &[(&fx.mailbox_a, Type::INT8), (&"world", Type::TEXT)],
            None,
            |_| Ok(()),
        )
        .await;
    let prep_count: i64 = unnamed_pool
        .run_mailbox_read_pipelined(
            &mb,
            "SELECT count(*)::bigint FROM pg_prepared_statements",
            &[],
        )
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(
        prep_count, 0,
        "default Unnamed mode must leave 0 named prepared statements (zero TYPEINFO_QUERY s0)"
    );

    // B) OptIn bounded LRU (cap = 3) + PlanCacheHint::ForceCustomPlan:
    let att = PgBouncerAttestation::new(200, false, 3).unwrap();
    assert_eq!(att.effective_cap(), 3);
    let opt_in_pool = AppPool::from_dsn_configured(
        &fx.app_dsn,
        1,
        Timeouts::resolved(),
        PreparedStatementMode::OptIn(att),
        PlanCacheHint::ForceCustomPlan,
    )
    .unwrap();

    // Verify ForceCustomPlan took effect via Step 1 SET LOCAL plan_cache_mode = force_custom_plan.
    let mode_rows = opt_in_pool
        .run_mailbox_read_pipelined(&mb, "SELECT current_setting('plan_cache_mode')", &[])
        .await
        .unwrap();
    assert_eq!(mode_rows[0].get::<_, String>(0), "force_custom_plan");

    // Execute 6 distinct static SQL statements on the same pool-of-1 connection and
    // verify the per-connection LRU NEVER exceeds cap = 3!
    let queries: [&'static str; 6] = [
        "SELECT 1::int4",
        "SELECT 2::int4",
        "SELECT 3::int4",
        "SELECT 4::int4",
        "SELECT 5::int4",
        "SELECT 6::int4",
    ];
    let mut last_len = 0;
    for (idx, sql) in queries.into_iter().enumerate() {
        let rows = opt_in_pool
            .run_mailbox_read_pipelined(&mb, sql, &[])
            .await
            .unwrap();
        assert_eq!(rows[0].get::<_, i32>(0), (idx + 1) as i32);
        let (len, cap) = opt_in_pool.debug_prepared_cache_stats().await.unwrap();
        assert_eq!(cap, 3);
        assert!(
            len > 0 && len <= 3,
            "LRU cache must populate and stay within cap 3: len={len}"
        );
        last_len = len;
    }
    assert_eq!(last_len, 3, "LRU cache should fill up to cap 3");

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// 13. Interactive Capability Tx Local Refusal Rolls Back Cleanly (No Unknown)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interactive_capability_tx_local_refusal_rolls_back_cleanly_without_unknown() {
    let Some(fx) = setup_fixture("interactive_local_refusal_rollback").await else {
        return;
    };
    let pool = AppPool::from_dsn(&fx.app_dsn, 1).unwrap();
    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    let user = mint::user(ActorId::new(fx.user_a).unwrap(), Generation(1));
    let admin = mint::admin(ActorId::new(fx.user_a).unwrap(), Generation(1));

    let pid_before: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);

    // 1) MailboxTx<ReadWrite> local `admit` refusal -> RolledBack(Statement), NOT Unknown,
    //    and healthy connection recycles with same PID.
    let env_mb = make_envelope(mb.authority());
    let out_mb = pool
        .run_mailbox_write(&env_mb, &mb, deadline(), async |tx| {
            let _ = tx.execute("SET ROLE setjoin_worker", &[]).await?;
            Ok::<_, setjoin_pg::StatementFailure>(())
        })
        .await;
    match out_mb {
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            assert!(f.sqlstate.is_none(), "expected local refusal, got {f:?}");
        }
        other => panic!("expected RolledBack(Statement) on local admit refusal, got {other:?}"),
    }
    let pid_after_mb: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(
        pid_after_mb, pid_before,
        "local refusal must roll back and recycle healthy connection"
    );

    // 2) UserTx<ReadWrite> local `pre_encode_params` refusal -> RolledBack(Statement), NOT Unknown.
    let env_user = make_envelope(user.authority());
    let out_user = pool
        .run_user_write(&env_user, &user, deadline(), async |tx| {
            let mismatched: i32 = 42;
            let _ = tx
                .query("SELECT $1::text", &[(&mismatched, Type::TEXT)])
                .await?;
            Ok::<_, setjoin_pg::StatementFailure>(())
        })
        .await;
    match out_user {
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            assert!(f.sqlstate.is_none(), "expected local refusal, got {f:?}");
        }
        other => {
            panic!("expected RolledBack(Statement) on local pre-encode refusal, got {other:?}")
        }
    }
    let pid_after_user: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(pid_after_user, pid_before);

    // 3) AdminWriteTx<Audited> local `admit` refusal after record_audit -> commit()
    //    runs ROLLBACK (rolling back the audit row too!) and returns RolledBack(Statement),
    //    NEVER Unknown, while keeping the healthy connection pooled.
    let env_admin = make_envelope(admin.authority());
    let tx = pool
        .begin_admin_write(&env_admin, &admin, deadline())
        .await
        .unwrap();
    let audit = AuditEvent::new("test.admin_local_refusal_rolled_back", "user")
        .unwrap()
        .with_target_id(fx.user_b);
    let mut tx = tx.record_audit(&audit).await.unwrap();
    let refusal = tx
        .execute("SELECT set_config('app.current_user_id', '999', true)", &[])
        .await
        .unwrap_err();
    assert!(refusal.sqlstate.is_none(), "{refusal:?}");
    let out_admin = tx.commit().await;
    match out_admin {
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            assert!(f.sqlstate.is_none(), "expected local refusal, got {f:?}");
        }
        other => {
            panic!("expected RolledBack(Statement) on AdminWriteTx local refusal, got {other:?}")
        }
    }
    let pid_after_admin: i32 = pool
        .run_mailbox_read_pipelined(&mb, "SELECT pg_backend_pid()", &[])
        .await
        .unwrap()[0]
        .get(0);
    assert_eq!(pid_after_admin, pid_before);

    let rolled_back_audit_count: i64 = fx
        .owner
        .query_one(
            "SELECT count(*)::bigint FROM admin_audit_log \
             WHERE user_id = $1 AND action = 'test.admin_local_refusal_rolled_back'",
            &[&fx.user_a],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        rolled_back_audit_count, 0,
        "audit row in AdminWriteTx must roll back after local statement refusal"
    );

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// Wave 1.8 Phase 546a live DB proofs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn phase546a_audited_reducer_contract_enforces_db_core_audit_proof() {
    use setjoin_pg::{
        AdminReducerOutcome, ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope,
    };
    let Some(fx) = setup_fixture("546a_audited_reducer").await else {
        return;
    };
    let worker_pool = WorkerPool::from_dsn(&fx.worker_dsn, 4).expect("WorkerPool");
    let admin_pool = worker_pool.admin_pool();
    let admin = mint::admin(ActorId::new(fx.user_a).unwrap(), Generation(1));

    // Create a disposable custom role to delete via rust_admin_role_delete.
    let role_id: i64 = fx
        .owner
        .query_one(
            "INSERT INTO admin_role_groups (name, permissions) \
             VALUES ($1, ARRAY['users.read']) RETURNING id",
            &[&format!("p546a-role-{}", fx.user_a)],
        )
        .await
        .unwrap()
        .get(0);

    static ROLE_DELETE_CONTRACT: SqlContract = SqlContract {
        id: "test546a.admin_role_delete",
        domain: "test",
        sql: "SELECT rust_admin_role_delete($1, $2, $3, $4)::text",
        params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
        columns: &[ColumnSpec::unnamed(Type::TEXT)],
        scope: SqlScope::AdminWrite,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::ReducerWritesCoreAudit,
    };

    static STANDARD_CONTRACT: SqlContract = SqlContract {
        id: "test546a.standard_not_audited",
        domain: "test",
        sql: "SELECT $1::bigint",
        params: &[Type::INT8],
        columns: &[ColumnSpec::unnamed(Type::INT8)],
        scope: SqlScope::AdminWrite,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };

    // 1. Standard posture contract is refused locally before execution.
    let env_std = make_envelope(admin.authority());
    let tx_std = admin_pool
        .begin_admin_write(&env_std, &admin, deadline())
        .await
        .unwrap();
    let std_err = match tx_std
        .execute_audited_reducer_contract(&STANDARD_CONTRACT, &[])
        .await
    {
        Ok(_) => panic!("Standard posture must be refused by execute_audited_reducer_contract"),
        Err(e) => e,
    };
    assert!(std_err.message.contains("ReducerWritesCoreAudit"));

    // 2. Branch-only early return (404 role not found) leaves app.core_audit_written
    //    unset -> returns rollback-only AdminReducerOutcome::NoOp (cannot commit!).
    let missing_id: i64 = -999_999;
    let scope_global: i64 = 0;
    let ip = "127.0.0.1";
    let env_noop = make_envelope(admin.authority());
    let tx_noop = admin_pool
        .begin_admin_write(&env_noop, &admin, deadline())
        .await
        .unwrap();
    let outcome_noop = tx_noop
        .execute_audited_reducer_contract(&ROLE_DELETE_CONTRACT, &[&scope_global, &missing_id, &ip])
        .await
        .expect("404 early return yields Ok(NoOp)");
    match outcome_noop {
        AdminReducerOutcome::NoOp { tx, rows } => {
            let body: String = rows[0].get(0);
            assert!(body.contains("404"), "expected 404 payload, got {body}");
            tx.rollback().await.expect("rollback NoOp cleanly");
        }
        AdminReducerOutcome::Audited { .. } => {
            panic!("branch-only 404 return without audit_write MUST NOT transition to Audited")
        }
    }

    // 3. Successful deletion invokes audit_write(p_actor, ..., 'core') ->
    //    PostgreSQL sets app.core_audit_written='1' -> transitions to Audited
    //    with zero double-auditing and R2-bound p_actor!
    let before_audits: i64 = fx
        .owner
        .query_one(
            "SELECT count(*)::bigint FROM admin_audit_log \
             WHERE user_id = $1 AND action = 'role_delete' AND target_id = $2",
            &[&fx.user_a, &role_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before_audits, 0);

    let env_del = make_envelope(admin.authority());
    let tx_del = admin_pool
        .begin_admin_write(&env_del, &admin, deadline())
        .await
        .unwrap();
    let outcome_del = tx_del
        .execute_audited_reducer_contract(&ROLE_DELETE_CONTRACT, &[&scope_global, &role_id, &ip])
        .await
        .expect("audited delete succeeds");
    match outcome_del {
        AdminReducerOutcome::Audited { tx, rows } => {
            let body: String = rows[0].get(0);
            assert!(body.contains("204"), "expected 204 payload, got {body}");
            assert!(matches!(tx.commit().await, CommandOutcome::Committed(())));
        }
        AdminReducerOutcome::NoOp { tx, .. } => {
            let _ = tx.rollback().await;
            panic!("expected Audited outcome when core audit_write ran");
        }
    }

    let after_audits: i64 = fx
        .owner
        .query_one(
            "SELECT count(*)::bigint FROM admin_audit_log \
             WHERE user_id = $1 AND action = 'role_delete' AND target_id = $2",
            &[&fx.user_a, &role_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after_audits, 1,
        "exactly one core audit row must exist (zero double-auditing)"
    );

    fx.cleanup().await;
}

#[tokio::test]
async fn phase546a_effect_writes_lock_order_semaphore_lookup_iterated_and_pre_auth() {
    use setjoin_pg::{
        ColumnSpec, OperationLookup, RlsCheck, SqlAuditPosture, SqlContract, SqlScope,
    };
    let Some(mut fx) = setup_fixture("546a_effect_preauth").await else {
        return;
    };
    let app_pool = AppPool::from_dsn(&fx.app_dsn, 4)
        .expect("AppPool")
        .with_effect_concurrency(2);
    let worker_pool = WorkerPool::from_dsn(&fx.worker_dsn, 4).expect("WorkerPool");
    let admin_pool = worker_pool.admin_pool();

    let mb = mint::mailbox(
        ActorId::new(fx.user_a).unwrap(),
        MailboxId::new(fx.mailbox_a).unwrap(),
        Generation(1),
    );
    let user = mint::user(ActorId::new(fx.user_a).unwrap(), Generation(1));
    let admin = mint::admin(ActorId::new(fx.user_a).unwrap(), Generation(1));

    let has_explicit_app = explicit_app_dsn().is_some();
    let has_explicit_worker = explicit_worker_dsn().is_some();

    // 1. Mailbox effect write: idle_in_transaction_session_timeout = 8s,
    //    #481 prelock_mailbox_hierarchy, durable receipt, lookup_mailbox_command.
    let cmd_mb = ReceiptCommand {
        family: "test546a",
        command: "mailbox_effect",
    };
    let env_mb = make_envelope(mb.authority());
    fx.created_ops.push(env_mb.operation);
    let out = app_pool
        .run_mailbox_effect_write(cmd_mb, &env_mb, &mb, deadline(), async |tx| {
            tx.prelock_mailbox_hierarchy().await?;
            let rows = tx
                .query(
                    "SELECT current_setting('idle_in_transaction_session_timeout'), \
                            (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                       FROM pg_roles r WHERE r.rolname = current_user",
                    &[],
                )
                .await?;
            Ok((
                rows[0].get::<_, String>(0),
                rows[0].get::<_, bool>(1),
                rows[0].get::<_, String>(2),
            ))
        })
        .await;
    match out {
        CommandOutcome::Committed((idle_timeout, non_bypass, role)) => {
            assert_eq!(idle_timeout, "8s");
            if has_explicit_app {
                assert!(
                    non_bypass,
                    "DB_APP_DSN role must be NOSUPERUSER NOBYPASSRLS"
                );
                assert_eq!(role, "setjoin_app");
            }
        }
        other => panic!("expected Committed mailbox effect write, got {other:?}"),
    }
    assert_eq!(
        app_pool
            .lookup_mailbox_command(&mb, env_mb.operation, cmd_mb)
            .await
            .unwrap(),
        OperationLookup::Committed
    );
    assert_eq!(
        app_pool
            .lookup_mailbox_command(&mb, OperationId([0xEE; 16]), cmd_mb)
            .await
            .unwrap(),
        OperationLookup::Absent
    );

    // 2. User effect write + lookup_user_command.
    let cmd_u = ReceiptCommand {
        family: "test546a",
        command: "user_effect",
    };
    let env_u = make_envelope(user.authority());
    fx.created_ops.push(env_u.operation);
    let out_u = app_pool
        .run_user_effect_write(cmd_u, &env_u, &user, deadline(), async |tx| {
            let rows = tx
                .query(
                    "SELECT current_setting('idle_in_transaction_session_timeout'), \
                            (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                       FROM pg_roles r WHERE r.rolname = current_user",
                    &[],
                )
                .await?;
            Ok((
                rows[0].get::<_, String>(0),
                rows[0].get::<_, bool>(1),
                rows[0].get::<_, String>(2),
            ))
        })
        .await;
    match out_u {
        CommandOutcome::Committed((idle_timeout, non_bypass, role)) => {
            assert_eq!(idle_timeout, "8s");
            if has_explicit_app {
                assert!(
                    non_bypass,
                    "DB_APP_DSN role must be NOSUPERUSER NOBYPASSRLS"
                );
                assert_eq!(role, "setjoin_app");
            }
        }
        other => panic!("expected Committed user effect write, got {other:?}"),
    }
    assert_eq!(
        app_pool
            .lookup_user_command(&user, env_u.operation, cmd_u)
            .await
            .unwrap(),
        OperationLookup::Committed
    );

    // 3. query_iterated_contract on ReadOnly handles preserves partial rows on mid-stream error.
    static ITER_MB: SqlContract = SqlContract {
        id: "test546a.iter_mb",
        domain: "test",
        sql: "SELECT CASE WHEN g = 3 THEN 1 / (g - 3) ELSE g END AS v FROM generate_series(1, 5) g",
        params: &[],
        columns: &[ColumnSpec::named("v", Type::INT4)],
        scope: SqlScope::MailboxReadOnly,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };
    let mut ro = app_pool.begin_mailbox_read(&mb).await.unwrap();
    let partial = ro.query_iterated_contract(&ITER_MB, &[]).await.unwrap();
    assert_eq!(
        partial
            .iter()
            .map(|r| r.get::<_, i32>(0))
            .collect::<Vec<_>>(),
        vec![1, 2],
        "query_iterated_contract must retain rows delivered before mid-stream error"
    );
    ro.finish().await.unwrap();

    // 4. Encapsulated AdminWorkerPool: cross-tenant AdminSensitiveRead + PreAuthReadTx.
    let audit_ev = AuditEvent::new("test546a.cross_tenant_read", "message").unwrap();
    let all_rows = admin_pool
        .run_admin_sensitive_read(
            &admin,
            &audit_ev,
            "SELECT count(*)::bigint, \
                    (SELECT (r.rolbypassrls OR r.rolsuper) FROM pg_roles r WHERE r.rolname = current_user), \
                    current_user::text \
               FROM messages WHERE id = ANY($1)",
            &[(&vec![fx.message_a, fx.message_b], Type::INT8_ARRAY)],
        )
        .await
        .expect("AdminWorkerPool sensitive read");
    assert_eq!(
        all_rows[0].get::<_, i64>(0),
        2,
        "AdminWorkerPool BYPASSRLS sees cross-tenant messages after Tx 1 core audit"
    );
    assert!(
        all_rows[0].get::<_, bool>(1),
        "AdminWorkerPool role must have rolbypassrls or rolsuper"
    );
    if has_explicit_worker {
        assert_eq!(all_rows[0].get::<_, String>(2), "setjoin_worker");
    }

    static PRE_AUTH_USER: SqlContract = SqlContract {
        id: "test546a.pre_auth_user",
        domain: "test",
        sql: "SELECT u.id, (r.rolbypassrls OR r.rolsuper), current_user::text \
                FROM users u JOIN pg_roles r ON r.rolname = current_user WHERE u.id = $1",
        params: &[Type::INT8],
        columns: &[
            ColumnSpec::named("id", Type::INT8),
            ColumnSpec::unnamed(Type::BOOL),
            ColumnSpec::unnamed(Type::TEXT),
        ],
        scope: SqlScope::AuthPreScope,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };
    let mut pre_tx = admin_pool.begin_pre_auth_read().await.unwrap();
    let pre_rows = pre_tx
        .query_contract(&PRE_AUTH_USER, &[&fx.user_b])
        .await
        .unwrap();
    assert_eq!(pre_rows.len(), 1);
    assert_eq!(pre_rows[0].get::<_, i64>(0), fx.user_b);
    assert!(
        pre_rows[0].get::<_, bool>(1),
        "PreAuthReadTx role must have rolbypassrls or rolsuper"
    );
    if has_explicit_worker {
        assert_eq!(pre_rows[0].get::<_, String>(2), "setjoin_worker");
    }
    // PreAuthReadTx refuses non-AuthPreScope contracts locally.
    assert!(pre_tx.query_contract(&ITER_MB, &[]).await.is_err());
    pre_tx.finish().await.unwrap();

    fx.cleanup().await;
}
