//! Standalone operator connections. Authority is the explicitly selected local
//! database credential, never an HTTP-supplied identity. No SET ROLE or session
//! GUCs. Parameters and statements use the unnamed protocol, including DB_DSN.
use crate::{Param, Row};
use tokio_postgres::{Client, NoTls};

pub struct OperatorConnection {
    client: Client,
    driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}

pub fn error(err: tokio_postgres::Error) -> String {
    if let Some(db) = err.as_db_error() {
        return format!(
            "{}: {} (SQLSTATE {})",
            db.severity(),
            db.message(),
            db.code().code()
        );
    }
    err.to_string()
}

impl OperatorConnection {
    /// Unnamed, backpressured rows on this dedicated connection.
    pub(crate) async fn rows(
        &self,
        statement: &str,
        params: &[Param<'_>],
    ) -> Result<crate::workers::WorkerRows, String> {
        let rows = self
            .client
            .query_typed_raw(statement, params.iter().map(|(v, t)| (*v, t.clone())))
            .await
            .map_err(error)?;
        Ok(crate::workers::WorkerRows {
            inner: Box::pin(rows),
        })
    }
    pub async fn connect(dsn: &str) -> Result<Self, String> {
        Self::connect_password(dsn, "").await
    }

    /// Restore credentials arrive separately from the credential-free child DSN.
    pub async fn connect_password(dsn: &str, password: &str) -> Result<Self, String> {
        let mut config: tokio_postgres::Config = dsn.parse().map_err(error)?;
        if !password.is_empty() {
            config.password(password);
        } else if config.get_password().is_none_or(|p| p.is_empty()) {
            let environment = if config.get_password().is_none() {
                std::env::var("PGPASSWORD").ok().filter(|p| !p.is_empty())
            } else {
                None
            };
            if let Some(password) = environment.or_else(|| passfile_password(&config)) {
                config.password(password);
            }
        }
        Self::from_config(config).await
    }

    pub(crate) async fn from_config(config: tokio_postgres::Config) -> Result<Self, String> {
        let (client, connection) = config.connect(NoTls).await.map_err(error)?;
        Ok(Self {
            client,
            driver: tokio::spawn(connection),
        })
    }

    pub async fn query(&self, statement: &str, params: &[Param<'_>]) -> Result<Vec<Row>, String> {
        self.client
            .query_typed(statement, params)
            .await
            .map_err(error)
    }

    pub(crate) async fn query_detailed(
        &self,
        statement: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, crate::StatementFailure> {
        self.client
            .query_typed(statement, params)
            .await
            .map_err(|e| crate::StatementFailure::from_db(&e))
    }

    /// Run one statement and return the command tag's affected-row count
    /// (a `SELECT` counts its rows, like pgx's `RowsAffected`).
    pub async fn execute(&self, statement: &str, params: &[Param<'_>]) -> Result<u64, String> {
        use futures_util::StreamExt;
        let stream = self
            .client
            .query_typed_raw(statement, params.iter().map(|(v, t)| (*v, t.clone())))
            .await
            .map_err(error)?;
        tokio::pin!(stream);
        while let Some(row) = stream.next().await {
            row.map_err(error)?;
        }
        Ok(stream.rows_affected().unwrap_or(0))
    }

    /// Simple-protocol statements without parameters (`BEGIN`/`COMMIT`/`ROLLBACK`).
    pub async fn batch(&self, statements: &'static str) -> Result<(), String> {
        self.client.batch_execute(statements).await.map_err(error)
    }

    /// Resolve one operator-selected user's devices with a transaction-local
    /// encryption key, matching frozen mailctl. Nothing is sent until COMMIT.
    pub async fn resolve_push_devices(
        &mut self,
        email: &str,
        key: &str,
    ) -> Result<(i64, Vec<PushDevice>, usize), String> {
        use tokio_postgres::types::Type;
        let tx = self
            .client
            .transaction()
            .await
            .map_err(|e| format!("begin push test transaction: {}", error(e)))?;
        tx.query_typed(
            "SELECT set_config('app.encryption_key',$1,true)",
            &[(&key, Type::TEXT)],
        )
        .await
        .map_err(|e| format!("set encryption key: {}", error(e)))?;
        let users = tx
            .query_typed(
                "SELECT id FROM users WHERE email=lower($1)",
                &[(&email, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("resolve user {email:?}: {}", error(e)))?;
        let user = users
            .first()
            .ok_or_else(|| format!("resolve user {email:?}: no rows in result set"))?
            .get::<_, i64>(0);
        let rows=tx.query_typed("SELECT id,push_provider,push_decrypt_token(push_token_enc) FROM push_devices WHERE user_id=$1 AND revoked_at IS NULL",&[(&user,Type::INT8)]).await.map_err(|e|format!("resolve push devices: {}",error(e)))?;
        let mut devices = Vec::new();
        let mut unreadable = 0;
        for row in rows {
            let id = row.try_get::<_, i64>(0);
            let provider = row.try_get::<_, String>(1);
            let token = row.try_get::<_, Option<String>>(2);
            match (id, provider, token) {
                (Ok(id), Ok(provider), Ok(Some(token))) if !token.is_empty() => {
                    devices.push(PushDevice {
                        id,
                        provider,
                        token,
                    })
                }
                (_, _, Ok(Some(token))) if token.is_empty() => {}
                _ => unreadable += 1,
            }
        }
        tx.commit()
            .await
            .map_err(|e| format!("commit push test transaction: {}", error(e)))?;
        Ok((user, devices, unreadable))
    }

    /// Owner-only repeatable-read snapshot, kept alive while external pg_dump
    /// imports its exported snapshot identifier.
    pub async fn backup_snapshot(&mut self) -> Result<OperatorSnapshot<'_>, String> {
        let tx = self
            .client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(error)?;
        Ok(OperatorSnapshot { tx })
    }

    /// Match frozen Go's operator-only schema reset, including its no-users lock.
    /// DDL stays on an owner connection; no request pool or role impersonation.
    pub async fn reset_empty_for_restore(&mut self) -> Result<(), String> {
        let tx = self
            .client
            .transaction()
            .await
            .map_err(|e| format!("begin restore schema reset: {}", error(e)))?;
        tx.batch_execute("LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE")
            .await
            .map_err(|e| format!("lock users before restore schema reset: {}", error(e)))?;
        // Keep the operator adapter's unnamed protocol ahead of schema DDL.
        let users: i64 = tx
            .query_typed("SELECT count(*) FROM public.users", &[])
            .await
            .map_err(|e| format!("re-check users before restore schema reset: {}", error(e)))?[0]
            .get(0);
        if users != 0 {
            return Err(format!(
                "restore target became populated after blob restore: found {users} user(s)"
            ));
        }
        tx.batch_execute("DROP SCHEMA public CASCADE")
            .await
            .map_err(|e| format!("drop preloaded public schema: {}", error(e)))?;
        tx.batch_execute("CREATE SCHEMA public")
            .await
            .map_err(|e| format!("recreate public schema: {}", error(e)))?;
        tx.commit()
            .await
            .map_err(|e| format!("commit restore schema reset: {}", error(e)))
    }

    /// Embedded DDL applies each canonical migration in its own transaction.
    /// Each migration retains Go's one transaction and fails closed on COMMIT.
    pub async fn apply_migration(&mut self, name: &str, sql: &str) -> Result<(), String> {
        let tx = self
            .client
            .transaction()
            .await
            .map_err(|e| format!("begin tx for {name}: {}", error(e)))?;
        tx.batch_execute(sql).await.map_err(|e| {
            format!(
                "{name} failed (rolled back, schema unchanged): {}",
                error(e)
            )
        })?;
        tx.commit()
            .await
            .map_err(|e| format!("commit {name}: {}", error(e)))
    }
}

// Only standalone operator connections use libpq/pgx credential defaults.
// Worker-selected configurations enter from_config directly and cannot inherit
// an unrelated operator password from this process's environment.
fn passfile_password(config: &tokio_postgres::Config) -> Option<String> {
    use std::io::BufRead;
    use tokio_postgres::config::Host;
    let user = config.get_user()?;
    let database = config.get_dbname().unwrap_or(user);
    let host = match config.get_hosts().first() {
        Some(Host::Tcp(host)) => host.as_str(),
        _ => "localhost",
    };
    let port = config
        .get_ports()
        .first()
        .copied()
        .unwrap_or(5432)
        .to_string();
    let path = std::env::var_os("PGPASSFILE")
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".pgpass"))
        })?;
    let file = std::fs::File::open(path).ok()?;
    for line in std::io::BufReader::new(file).lines() {
        let line = line.ok()?;
        if line.len() >= 65536 {
            return None;
        }
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        // Match frozen pgpassfile's escaping and first-match semantics.
        let escaped = line.replace("\\\\", "\r").replace("\\:", "\n");
        let fields = escaped
            .split(':')
            .map(|s| s.replace('\r', "\\").replace('\n', ":"))
            .collect::<Vec<_>>();
        if fields.len() == 5
            && fields[..4]
                .iter()
                .zip([host, &port, database, user])
                .all(|(pattern, value)| pattern == "*" || pattern == value)
        {
            return Some(fields[4].clone());
        }
    }
    None
}

pub struct OperatorSnapshot<'a> {
    tx: tokio_postgres::Transaction<'a>,
}
impl OperatorSnapshot<'_> {
    pub async fn query(&self, statement: &str, params: &[Param<'_>]) -> Result<Vec<Row>, String> {
        self.tx.query_typed(statement, params).await.map_err(error)
    }
    pub async fn commit(self) -> Result<(), String> {
        self.tx.commit().await.map_err(error)
    }
}

pub struct PushDevice {
    pub id: i64,
    pub provider: String,
    pub token: String,
}

impl Drop for OperatorConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
