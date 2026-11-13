//! Connections for a conformance run. Every parameterised statement goes
//! through `query_typed` (an unnamed statement) or `simple_query`, so the
//! harness works behind the PgBouncer transaction pool that `DB_DSN` names.
use std::time::Duration;

use futures_util::stream::{poll_fn, StreamExt};
use tokio::sync::mpsc;
use tokio_postgres::{AsyncMessage, Client, NoTls};

use crate::db_gate::{self, DbGate, SKIP_MARKER};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The database a case runs against: the owner DSN (fixtures, observation),
/// the direct DSN used only to LISTEN, and the optional `setjoin_app` DSN the
/// command under test runs on (so FORCE RLS binds it as in production).
pub struct Db {
    pub dsn: String,
    pub direct: String,
    pub app: Option<String>,
}

/// DB-backed oracles run on a shared, CPU-starved host: the authz precondition reads
/// (default 1 s, a timeout forwards the request to Go) would turn scheduling stalls into
/// bogus parity failures (#421). Widen the bound once, before any authz read; an explicit
/// `SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS` always wins.
fn widen_authz_precheck() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS").is_none() {
            std::env::set_var("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS", "15000");
        }
        // The same stall would expire the executors' 1 s pool wait and 2 s statement bounds.
        if std::env::var_os("SETJOIN_PG_DEADLINE_MS").is_none() {
            std::env::set_var("SETJOIN_PG_DEADLINE_MS", "30000");
        }
    });
}

impl Db {
    /// Resolve the gate for `case`. `None` means the case is skipped (a
    /// greppable `CONFORMANCE-SKIP` line is written straight to stderr, past
    /// libtest's output capture). With `REQUIRE_DB` set and no database, panics.
    pub fn for_case(case: &str) -> Option<Db> {
        match db_gate::resolve(|k| std::env::var(k).ok()) {
            DbGate::Run { dsn, direct, app } => {
                widen_authz_precheck();
                Some(Db { dsn, direct, app })
            }
            DbGate::Skip => {
                use std::io::Write;
                // One write of the whole line, so parallel cases never interleave.
                let line = format!(
                    "{SKIP_MARKER} (reason=no-db case={case}) — set TEST_DB_DSN or DB_DSN; REQUIRE_DB=1 makes this a failure\n"
                );
                let _ = std::io::stderr().lock().write_all(line.as_bytes());
                None
            }
            DbGate::Missing => panic!(
                "REQUIRE_DB is set but neither TEST_DB_DSN nor DB_DSN is — fail-closed: case {case} must not pass as a silent skip"
            ),
        }
    }

    /// An owner client; its connection task runs on the current runtime.
    pub async fn connect(&self) -> Result<Client, BoxError> {
        open(&self.dsn).await
    }

    /// The client the command under test runs on: `setjoin_app` when
    /// `DB_APP_DSN` is set, else the owner.
    pub async fn connect_command(&self) -> Result<Client, BoxError> {
        open(self.app.as_deref().unwrap_or(&self.dsn)).await
    }

    /// LISTEN on `channel` over the direct connection.
    pub async fn listen(&self, channel: &str) -> Result<Listener, BoxError> {
        let (client, mut conn) = tokio_postgres::connect(&self.direct, NoTls).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut messages = poll_fn(move |cx| conn.poll_message(cx));
            while let Some(Ok(msg)) = messages.next().await {
                if let AsyncMessage::Notification(n) = msg {
                    if tx
                        .send((n.channel().to_string(), n.payload().to_string()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        client
            .batch_execute(&format!("LISTEN {}", quote_ident(channel)))
            .await?;
        Ok(Listener {
            _client: client,
            channel: channel.to_string(),
            rx,
        })
    }
}

/// A LISTEN session on one channel.
pub struct Listener {
    _client: Client,
    channel: String,
    rx: mpsc::UnboundedReceiver<(String, String)>,
}

const SENTINEL: &str = "conformance-oracle-sentinel";

impl Listener {
    /// Every payload delivered on the channel since the last drain. A sentinel
    /// is sent from `writer` in its own transaction; NOTIFY delivery follows
    /// commit order, so everything committed before the sentinel has arrived
    /// once the sentinel has.
    pub async fn drain(&mut self, writer: &Client) -> Result<Vec<String>, BoxError> {
        writer
            .query_typed(
                "SELECT pg_notify($1, $2)",
                &[
                    (&self.channel, tokio_postgres::types::Type::TEXT),
                    (&SENTINEL, tokio_postgres::types::Type::TEXT),
                ],
            )
            .await?;
        let mut seen = Vec::new();
        loop {
            let next = tokio::time::timeout(Duration::from_secs(10), self.rx.recv())
                .await
                .map_err(|_| "timed out waiting for the NOTIFY sentinel")?
                .ok_or("listener connection closed")?;
            if next.0 != self.channel {
                continue;
            }
            if next.1 == SENTINEL {
                return Ok(seen);
            }
            seen.push(next.1);
        }
    }
}

async fn open(dsn: &str) -> Result<Client, BoxError> {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
