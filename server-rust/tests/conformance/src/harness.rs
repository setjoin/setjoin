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
/// the direct DSN used only to LISTEN, the `setjoin_app` DSN (`DB_APP_DSN`)
/// the tenant runtime runs on (so `FORCE RLS` binds it as in production), and
/// the `setjoin_worker` DSN (`DB_WORKER_DSN`) for cross-tenant workers.
pub struct Db {
    pub dsn: String,
    pub direct: String,
    pub app: Option<String>,
    pub worker: Option<String>,
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
            DbGate::Run {
                dsn,
                direct,
                app,
                worker,
            } => {
                widen_authz_precheck();
                Some(Db {
                    dsn,
                    direct,
                    app,
                    worker,
                })
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

    /// The constrained `setjoin_app` DSN (`DB_APP_DSN`), required under
    /// Wave 1.9 (`#547`) fail-closed `FORCE RLS` startup enforcement.
    pub fn app_dsn(&self) -> &str {
        self.app
            .as_deref()
            .expect("DB_APP_DSN is required for Release N+1 (#547) fail-closed runtime boot")
    }

    /// The cross-tenant `BYPASSRLS` worker DSN (`DB_WORKER_DSN`), falling back
    /// to the owner DSN only when `DB_WORKER_DSN` is unset (never to `DB_APP_DSN`).
    pub fn worker_dsn(&self) -> &str {
        self.worker.as_deref().unwrap_or(&self.dsn)
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
        let since_id: i64 = client
            .query_opt(
                "SELECT COALESCE(MAX(id), 0)::bigint FROM public.notify_intents WHERE channel = $1",
                &[&channel],
            )
            .await
            .ok()
            .flatten()
            .map(|r| r.get(0))
            .unwrap_or(0);
        Ok(Listener {
            _client: client,
            channel: channel.to_string(),
            since_id,
            rx,
        })
    }
}

/// A LISTEN session on one channel.
pub struct Listener {
    _client: Client,
    channel: String,
    since_id: i64,
    rx: mpsc::UnboundedReceiver<(String, String)>,
}

const SENTINEL: &str = "conformance-oracle-sentinel";

impl Listener {
    /// Flush any pending `notify_intents` rows emitted for this channel AFTER
    /// `Db::listen()` into `pg_notify` (preserving `ORDER BY id` without
    /// collapsing identical payloads emitted across separate transactions),
    /// then collect every payload delivered before the sentinel.
    ///
    /// With Wave 2.1 (#548) retiring `feature.notify_decouple` so `app_notify`
    /// unconditionally writes `notify_intents`, this keeps all ~95 in-process
    /// conformance `Db::listen` + `Listener::drain` suites working without
    /// spawning a background drainer or adding any production test GUC.
    pub async fn drain(&mut self, writer: &Client) -> Result<Vec<String>, BoxError> {
        let rows = writer
            .query_typed(
                "WITH batch AS ( \
                   DELETE FROM notify_intents \
                    WHERE id IN ( \
                        SELECT id FROM notify_intents \
                         WHERE channel = $1 AND id > $2 \
                         ORDER BY id \
                         FOR UPDATE SKIP LOCKED \
                    ) \
                    RETURNING id, payload \
                 ) \
                 SELECT payload FROM batch ORDER BY id",
                &[
                    (&self.channel, tokio_postgres::types::Type::TEXT),
                    (&self.since_id, tokio_postgres::types::Type::INT8),
                ],
            )
            .await?;
        // Emit each row in its own autocommit statement so PostgreSQL does not
        // collapse identical (channel, payload) notifications produced by
        // separate transactions (e.g. `*_repeat` conformance cases).
        for row in rows {
            let payload: String = row.get(0);
            writer
                .query_typed(
                    "SELECT pg_notify($1, $2)",
                    &[
                        (&self.channel, tokio_postgres::types::Type::TEXT),
                        (&payload, tokio_postgres::types::Type::TEXT),
                    ],
                )
                .await?;
        }
        self.drain_raw(writer).await
    }

    /// Collect every payload already delivered on the channel since the last
    /// drain WITHOUT touching `notify_intents`. Used by tests (such as
    /// `notify_drain_startup.rs`) that assert an external `NotifyIntentDrain`
    /// worker performed the drain.
    pub async fn drain_raw(&mut self, writer: &Client) -> Result<Vec<String>, BoxError> {
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
