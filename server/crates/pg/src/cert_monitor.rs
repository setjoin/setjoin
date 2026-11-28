//! Global health-history writes for the certificate monitor.

use std::future::Future;
use std::time::Duration;
use tokio_postgres::{types::Type, Config, NoTls};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct CertMonitorDatabase {
    config: Config,
}

impl CertMonitorDatabase {
    /// Use the worker credential, with the request DSN only as its fallback.
    pub fn new(dsn: &str) -> Result<Self, tokio_postgres::Error> {
        Ok(Self {
            config: dsn.parse()?,
        })
    }

    /// Writes one row, or cancels and joins the query on shutdown. Returns
    /// true when shutdown won. A failed cancellation closes and joins the
    /// connection instead of leaving its driver running in the background.
    pub async fn record_until<S: Future<Output = ()>>(
        &self,
        status: &str,
        days_left: i32,
        details: &str,
        shutdown: S,
    ) -> Result<bool, Error> {
        tokio::pin!(shutdown);
        let (client, connection) = tokio::select! {
            () = &mut shutdown => return Ok(true),
            connected = self.config.connect(NoTls) => connected?,
        };
        let driver = tokio::spawn(connection);
        let cancel = client.cancel_token();
        let mut cancelled = false;
        let mut close_connection = false;
        let result = {
            let parameters: &[(&(dyn tokio_postgres::types::ToSql + Sync), Type)] = &[
                (&status, Type::TEXT),
                (&days_left, Type::INT4),
                (&details, Type::TEXT),
            ];
            let query = client.query_typed(
                "INSERT INTO health_history (check_name, status, value, threshold, details, checked_at) VALUES ('tls_cert', $1, $2::integer, 30, $3, now())",
                parameters,
            );
            tokio::pin!(query);
            tokio::select! {
                result = &mut query => Some(result),
                () = &mut shutdown => {
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
