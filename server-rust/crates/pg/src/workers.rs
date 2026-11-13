//! Database connections reserved for background workers.
//!
//! The caller supplies the worker credential, not the request pool. In
//! particular, session advisory locks require session-affine connections.

use crate::{auth::AuditKeys, executor::AUDIT_SCOPE};
use futures_util::future::poll_fn;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_postgres::{types::Type, AsyncMessage, Client, Config, NoTls, Notification};

type Error = Box<dyn std::error::Error + Send + Sync>;

const CRON_LOCK: &str = "cron:scheduler-single-flight";
const CRON_TASK_LOCK_PREFIX: &str = "cron-task:";

#[derive(Clone)]
pub struct WorkerDatabase {
    config: Config,
    audit_keys: Option<Arc<AuditKeys>>,
}

// Unlike a detached JoinHandle, this guard owns an in-flight snapshot's
// lifetime. A client timeout must cancel server SQL as well as its driver.
struct RevocationSnapshotDriver {
    task: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
    cancel: Option<tokio_postgres::CancelToken>,
}
impl Drop for RevocationSnapshotDriver {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        cancel.cancel_query(NoTls),
                    ).await;
                });
            }
        }
        self.task.abort();
    }
}

impl WorkerDatabase {
    pub fn new(dsn: &str) -> Result<Self, tokio_postgres::Error> {
        Ok(Self {
            config: dsn.parse()?,
            audit_keys: None,
        })
    }

    /// Use the worker DSN when configured; otherwise retain Go's fallback.
    pub fn from_dsns(
        request_dsn: &str,
        worker_dsn: Option<&str>,
    ) -> Result<Self, tokio_postgres::Error> {
        Self::new(worker_dsn.filter(|s| !s.is_empty()).unwrap_or(request_dsn))
    }

    /// Open an unnamed-statement adapter using this worker credential only.
    pub async fn connect(&self) -> Result<WorkerConnection, Error> {
        Ok(WorkerConnection {
            inner: crate::operator::OperatorConnection::from_config(self.config.clone())
                .await
                .map_err(std::io::Error::other)?,
        })
    }

    /// A worker connection with the deployment audit keys set for the whole
    /// session, as Go's `pgxutil.OpenPool` `AfterConnect` does (an empty key is
    /// skipped). Plain `connect` stays for callers that scope keys per transaction.
    pub async fn connect_session(&self) -> Result<WorkerConnection, Error> {
        let connection = self.connect().await?;
        if let Some(keys) = &self.audit_keys {
            for (name, value) in [
                ("app.encryption_key", &keys.encryption),
                ("app.audit_hmac_key", &keys.audit_hmac),
            ] {
                if !value.is_empty() {
                    connection
                        .query(
                            "SELECT set_config($1, $2, false)",
                            &[(&name, Type::TEXT), (value, Type::TEXT)],
                        )
                        .await?;
                }
            }
        }
        Ok(connection)
    }

    /// Trusted deployment settings for audited worker mutations. No request or
    /// tenant-supplied GUC name/value is accepted. Shares the executor allowlist.
    pub fn with_audit_keys(mut self, encryption_key: String, audit_hmac_key: String) -> Self {
        self.audit_keys = Some(Arc::new(AuditKeys {
            encryption: encryption_key,
            audit_hmac: audit_hmac_key,
        }));
        self
    }

    /// Acquire Go's session-level scheduler lock on a dedicated connection.
    pub async fn try_cron_singleton(&self) -> Result<Option<SingletonLease>, Error> {
        self.try_session_lock(CRON_LOCK.to_string()).await
    }

    /// Acquire the Rust per-task lock (`cron-task:<name>`, #365). It is a
    /// different key from Go's scheduler lock, so a task can run here while Go
    /// keeps its own lock for the tasks it still runs.
    pub async fn try_cron_task_lock(&self, task: &str) -> Result<Option<SingletonLease>, Error> {
        self.try_session_lock(format!("{CRON_TASK_LOCK_PREFIX}{task}"))
            .await
    }

    async fn try_session_lock(&self, key: String) -> Result<Option<SingletonLease>, Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let driver = tokio::spawn(connection);
        let rows = client
            .query_typed(
                "SELECT pg_try_advisory_lock(hashtextextended($1, 0))",
                &[(&key, Type::TEXT)],
            )
            .await?;
        if !rows[0].get::<_, bool>(0) {
            drop(client);
            driver.await??;
            return Ok(None);
        }
        Ok(Some(SingletonLease {
            inner: Arc::new(SingletonConnection {
                key,
                client,
                driver: tokio::sync::Mutex::new(driver),
            }),
        }))
    }

    /// Cross-tenant security reconciliation, on the worker credential only.
    /// The request pool must not be used for this global snapshot.
    pub async fn active_session_revocations(&self) -> Result<Vec<SessionRevocation>, Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let mut driver = RevocationSnapshotDriver {
            task: tokio::spawn(connection),
            cancel: Some(client.cancel_token()),
        };
        let rows = client
            .query_typed(
                "SELECT user_id, scope, COALESCE(jti,''), COALESCE(family_id,''), \
             (extract(epoch FROM not_before)*1000000)::bigint, \
             (extract(epoch FROM expires_at)*1000000)::bigint \
             FROM session_revocations WHERE expires_at > now()",
                &[],
            )
            .await?;
        let rows = rows
            .into_iter()
            .map(|row| SessionRevocation {
                user_id: row.get(0),
                scope: row.get(1),
                jti: row.get(2),
                family: row.get(3),
                not_before_nanos: i128::from(row.get::<_, i64>(4)) * 1_000,
                expires_at_nanos: Some(i128::from(row.get::<_, i64>(5)) * 1_000),
            })
            .collect();
        driver.cancel = None; // The query completed; only graceful close remains.
        drop(client);
        (&mut driver.task).await??;
        Ok(rows)
    }
}

/// Background-only SQL adapter; never constructed from an HTTP auth context.
pub struct WorkerConnection {
    inner: crate::operator::OperatorConnection,
}
/// A dedicated worker's single active, bounded row stream. Drain or drop it
/// before another query; dropping the owning connection aborts its driver.
pub struct WorkerRows {
    pub(crate) inner: std::pin::Pin<Box<tokio_postgres::RowStream>>,
}
impl WorkerRows {
    pub async fn next(&mut self) -> Result<Option<crate::Row>, String> {
        use futures_util::StreamExt;
        self.inner
            .next()
            .await
            .transpose()
            .map_err(crate::operator::error)
    }
}
impl WorkerConnection {
    pub async fn rows(
        &self,
        statement: &str,
        params: &[crate::Param<'_>],
    ) -> Result<WorkerRows, String> {
        self.inner.rows(statement, params).await
    }
    pub async fn query(
        &self,
        statement: &str,
        params: &[crate::Param<'_>],
    ) -> Result<Vec<crate::Row>, String> {
        self.inner.query(statement, params).await
    }

    /// Same worker authority and unnamed query as `query`, retaining typed
    /// diagnostics for allowlisted protocol projections. Never expose raw text.
    pub async fn query_detailed(
        &self,
        statement: &str,
        params: &[crate::Param<'_>],
    ) -> Result<Vec<crate::Row>, crate::StatementFailure> {
        self.inner.query_detailed(statement, params).await
    }

    /// Affected-row count of one statement (rows returned for a `SELECT`).
    pub async fn execute(
        &self,
        statement: &str,
        params: &[crate::Param<'_>],
    ) -> Result<u64, String> {
        self.inner.execute(statement, params).await
    }

    /// Fixed transaction control (`BEGIN`/`COMMIT`/`ROLLBACK`) on this session.
    pub async fn batch(&self, statements: &'static str) -> Result<(), String> {
        self.inner.batch(statements).await
    }
}

#[derive(Clone, Debug)]
pub struct SessionRevocation {
    pub user_id: i64,
    pub scope: String,
    pub jti: String,
    pub family: String,
    pub not_before_nanos: i128,
    pub expires_at_nanos: Option<i128>,
}

/// Holds the lock until explicit release or loss of the database connection.
#[derive(Clone)]
pub struct SingletonLease {
    inner: Arc<SingletonConnection>,
}

struct SingletonConnection {
    key: String,
    client: Client,
    driver: tokio::sync::Mutex<tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>>,
}

impl SingletonLease {
    /// Confirm the backend retaining the lock is still reachable.
    pub async fn ensure_connected(&self) -> Result<(), Error> {
        self.inner.client.query_typed("SELECT 1", &[]).await?;
        Ok(())
    }

    /// Resolves if the backend holding the session lock disconnects.
    pub async fn connection_lost(&self) {
        let _ = (&mut *self.inner.driver.lock().await).await;
    }

    pub async fn release(self) -> Result<(), Error> {
        let inner = Arc::try_unwrap(self.inner).map_err(|_| {
            std::io::Error::other("cannot release a singleton while its workers are running")
        })?;
        inner
            .client
            .query_typed(
                "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
                &[(&inner.key, Type::TEXT)],
            )
            .await?;
        drop(inner.client);
        inner.driver.into_inner().await??;
        Ok(())
    }
}

/// A LISTEN subscription on an explicitly supplied direct PostgreSQL DSN.
pub struct DirectListener {
    client: Option<Client>,
    notifications: mpsc::UnboundedReceiver<Notification>,
    driver: Option<tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>>,
}

impl DirectListener {
    pub async fn connect(direct_dsn: &str, channel: &str) -> Result<Self, Error> {
        if channel.is_empty()
            || !channel
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_:.-".contains(&c))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid notification channel",
            )
            .into());
        }
        let (client, mut connection) = tokio_postgres::connect(direct_dsn, NoTls).await?;
        let (send, notifications) = mpsc::unbounded_channel();
        let driver = tokio::spawn(async move {
            while let Some(message) = poll_fn(|cx| connection.poll_message(cx)).await {
                match message? {
                    AsyncMessage::Notification(notification) => {
                        let _ = send.send(notification);
                    }
                    _ => {}
                }
            }
            Ok(())
        });
        client
            .batch_execute(&format!("LISTEN \"{channel}\""))
            .await?;
        Ok(Self {
            client: Some(client),
            notifications,
            driver: Some(driver),
        })
    }

    /// Add a trusted dispatcher channel on this same direct connection.
    pub async fn listen(&self, channel: &str) -> Result<(), Error> {
        self.channel_command("LISTEN", channel).await
    }

    pub async fn unlisten(&self, channel: &str) -> Result<(), Error> {
        self.channel_command("UNLISTEN", channel).await
    }

    async fn channel_command(&self, command: &str, channel: &str) -> Result<(), Error> {
        if channel.is_empty()
            || !channel
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_:.-".contains(&c))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid notification channel",
            )
            .into());
        }
        self.client
            .as_ref()
            .expect("live listener")
            .batch_execute(&format!("{command} \"{channel}\""))
            .await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<Notification> {
        self.notifications.recv().await
    }

    pub async fn close(mut self) -> Result<(), Error> {
        drop(self.client.take());
        self.driver.take().expect("live listener").await??;
        Ok(())
    }
}

impl Drop for DirectListener {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// A terminal recovery chunk selected by the cross-tenant cleanup worker.
#[derive(Clone, Debug)]
pub struct RecoveryChunk {
    pub session_id: String,
    pub item_id: String,
    pub offset: i64,
    pub key: String,
}

impl WorkerDatabase {
    /// Run one fixed reducer statement the way Go's cron executor does: on the
    /// worker credential, with the deployment audit keys when configured.
    /// `sql` is `'static` so no request or tenant text can reach it.
    pub async fn run_cron_statement(&self, sql: &'static str) -> Result<(), Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let driver = tokio::spawn(connection);
        if let Some(keys) = &self.audit_keys {
            client.batch_execute("BEGIN").await?;
            client
                .query_typed(
                    AUDIT_SCOPE,
                    &[
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                    ],
                )
                .await?;
        }
        client.simple_query(sql).await?;
        if self.audit_keys.is_some() {
            client.batch_execute("COMMIT").await?;
        }
        drop(client);
        driver.await??;
        Ok(())
    }

    /// One canonical guest expiry sweep, with trusted transaction-local audit keys.
    pub async fn guest_expire_due(&self) -> Result<(), Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let driver = tokio::spawn(connection);
        if let Some(keys) = &self.audit_keys {
            client.batch_execute("BEGIN").await?;
            client
                .query_typed(
                    AUDIT_SCOPE,
                    &[
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                    ],
                )
                .await?;
        }
        client
            .query_typed("SELECT guest_expire_due(500)", &[])
            .await?;
        if self.audit_keys.is_some() {
            client.batch_execute("COMMIT").await?;
        }
        drop(client);
        driver.await??;
        Ok(())
    }
    /// Expire uploads, then obtain the same bounded batch as Go's cleanup worker.
    pub async fn recovery_cleanup_batch(&self) -> Result<Vec<RecoveryChunk>, Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let driver = tokio::spawn(connection);
        if let Some(keys) = &self.audit_keys {
            client.batch_execute("BEGIN").await?;
            client
                .query_typed(
                    AUDIT_SCOPE,
                    &[
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                    ],
                )
                .await?;
        }
        client
            .query_typed("SELECT mail_recovery_uploads_expire()", &[])
            .await?;
        if self.audit_keys.is_some() {
            client.batch_execute("COMMIT").await?;
        }
        // Expiration commits before batch selection, preserving Go's separate
        // transactions even if the following read or object deletion fails.
        let rows = client.query_typed(
            "SELECT chunk.session_id::text, chunk.item_id, chunk.start_offset, chunk.object_key \
             FROM mail_recovery_upload_chunks chunk \
             JOIN mail_recovery_upload_sessions session ON session.id=chunk.session_id \
             WHERE session.status IN ('quarantined','deduplicated','rejected','aborted','expired') \
             ORDER BY chunk.created_at LIMIT 256", &[]).await?;
        let items = rows
            .into_iter()
            .map(|row| RecoveryChunk {
                session_id: row.get(0),
                item_id: row.get(1),
                offset: row.get(2),
                key: row.get(3),
            })
            .collect();
        drop(client);
        driver.await??;
        Ok(items)
    }

    /// Acknowledge only the exact object successfully removed from storage.
    pub async fn acknowledge_recovery_chunk(&self, item: &RecoveryChunk) -> Result<(), Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let driver = tokio::spawn(connection);
        client
            .query_typed(
                "SELECT mail_recovery_chunk_cleanup_complete($1::text::uuid,$2,$3,$4)",
                &[
                    (&item.session_id, Type::TEXT),
                    (&item.item_id, Type::TEXT),
                    (&item.offset, Type::INT8),
                    (&item.key, Type::TEXT),
                ],
            )
            .await?;
        drop(client);
        driver.await??;
        Ok(())
    }
}
