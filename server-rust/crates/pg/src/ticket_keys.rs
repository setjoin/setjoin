//! Persistence for the TLS ticket-key handover. This does not start a worker.
use std::{future::Future, time::Duration};
use tokio_postgres::{types::Type, Config, NoTls};

type Error = Box<dyn std::error::Error + Send + Sync>;

// Dropping a worker future must also stop its connection task.
struct Driver(tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An explicit worker-credential connection to the system ticket-key row.
pub struct TicketKeyStore {
    config: Config,
}

impl TicketKeyStore {
    pub fn new(dsn: &str) -> Result<Self, tokio_postgres::Error> {
        Ok(Self {
            config: dsn.parse()?,
        })
    }

    pub async fn load(&self) -> Result<Option<String>, Error> {
        self.read("SELECT value::text FROM system_config WHERE key='tls_session_ticket_keys'")
            .await
    }

    /// The deployment identifier that binds sealed `system_config` secrets
    /// (`identity.deployment_id`, a JSON string).
    pub async fn deployment_id(&self) -> Result<Option<String>, Error> {
        self.read("SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'")
            .await
    }

    /// Remove the persisted generations (a legacy plaintext row nobody may trust).
    pub async fn delete(&self) -> Result<(), Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let mut driver = Driver(tokio::spawn(connection));
        let result = client
            .execute("DELETE FROM system_config WHERE key='tls_session_ticket_keys'", &[])
            .await;
        drop(client);
        let driver_result = (&mut driver.0).await?;
        result?;
        driver_result?;
        Ok(())
    }

    async fn read(&self, sql: &str) -> Result<Option<String>, Error> {
        let (client, connection) = self.config.connect(NoTls).await?;
        let mut driver = Driver(tokio::spawn(connection));
        let result = client.query_typed(sql, &[]).await;
        drop(client);
        let driver_result = (&mut driver.0).await?;
        let row = result?;
        driver_result?;
        Ok(row.first().and_then(|r| r.get::<_, Option<String>>(0)))
    }

    /// Cancel and drain the in-flight SQL statement before returning on shutdown.
    pub async fn save_until<S: Future<Output = ()>>(
        &self,
        json: &str,
        shutdown: S,
    ) -> Result<bool, Error> {
        tokio::pin!(shutdown);
        let (client, connection) = tokio::select! { _ = &mut shutdown => return Ok(true), result = self.config.connect(NoTls) => result? };
        let driver = tokio::spawn(connection);
        let cancel = client.cancel_token();
        let mut cancelled = false;
        let mut close_connection = false;
        let result = {
            let params: &[(&(dyn tokio_postgres::types::ToSql + Sync), Type)] =
                &[(&json, Type::TEXT)];
            let query = client.query_typed("INSERT INTO system_config (key,value,encrypted,description,updated_at) VALUES ('tls_session_ticket_keys',$1::text::jsonb,TRUE,'TLS session ticket keys (auto-rotated, sealed in the system_config secret envelope)',now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, encrypted=TRUE, updated_at=now()", params);
            tokio::pin!(query);
            tokio::select! {
                result = &mut query => Some(result),
                _ = &mut shutdown => {
                    cancelled = true;
                    match tokio::time::timeout(Duration::from_secs(5), cancel.cancel_query(NoTls)).await {
                        Ok(Ok(())) => match tokio::time::timeout(Duration::from_secs(5), &mut query).await {
                            Ok(result) => Some(result),
                            Err(_) => { close_connection = true; None }
                        },
                        _ => { close_connection = true; None }
                    }
                }
            }
        };
        drop(client);
        if close_connection {
            driver.abort();
            let _ = driver.await;
            return Ok(true);
        }
        driver.await??;
        if !cancelled {
            result.expect("completed query has a result")?;
        }
        Ok(cancelled)
    }
}
