use crate::{files::*, journal::Event};
use anyhow::{ensure, Result};
use serde_json::Value;
use tokio_postgres::{types::ToSql, Client};

pub struct Connection {
    pub client: Client,
    locked: std::sync::atomic::AtomicBool,
    driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl Connection {
    pub async fn connect(dsn: &str) -> Result<Self> {
        let parsed = crate::dbtls::parse(dsn)?;
        let mut config: tokio_postgres::Config = parsed.dsn.parse()?;
        config.ssl_mode(crate::dbtls::ssl_mode(parsed.mode));
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(crate::dbtls::client_config(&parsed)?);
        let (client, connection) = config.connect(tls).await?;
        Ok(Self {
            client,
            locked: std::sync::atomic::AtomicBool::new(false),
            driver: tokio::spawn(connection),
        })
    }
    pub async fn json(&self, sql: &str, args: &[&(dyn ToSql + Sync)]) -> Result<Value> {
        Ok(self.client.query_one(sql, args).await?.get(0))
    }
    pub async fn latest(&self) -> Result<Option<Intent>> {
        let v = self.json("SELECT upgrade_intent_read(NULL)", &[]).await?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(Intent::parse(&v)?))
    }
    pub async fn lock(&self) -> Result<()> {
        use std::sync::atomic::Ordering;
        if self.locked.load(Ordering::Relaxed) {
            return Ok(());
        }
        let locked: bool = self
            .client
            .query_one("SELECT pg_try_advisory_lock(21322,21840)", &[])
            .await?
            .get(0);
        ensure!(
            locked,
            "another updater holds the installation advisory lock"
        );
        self.locked.store(true, Ordering::Relaxed);
        Ok(())
    }
    pub async fn claim(&self, e: &Event) -> Result<Intent> {
        let v = self
            .json(
                "SELECT upgrade_intent_claim($1,$2,$3,$4)",
                &[&e.intent_id, &e.generation, &e.executor_id, &e.lease_id],
            )
            .await?;
        let i = Intent::parse(&v)?;
        ensure!(
            i.id == e.intent_id
                && i.release_id == e.release_id
                && i.manifest_digest == e.manifest_digest
                && i.recovery_set_id == e.recovery_set_id
                && i.recovery_set_digest == e.recovery_set_digest
                && v["leaseId"] == e.lease_id.to_string(),
            "claim authority differs"
        );
        Ok(i)
    }
    pub async fn mutate(&self, e: &Event) -> Result<()> {
        let sql = if e.terminal() {
            "SELECT upgrade_intent_complete($1,$2,$3,$4,$5,$6,$7)"
        } else {
            "SELECT upgrade_intent_progress($1,$2,$3,$4,$5,$6,$7)"
        };
        let expected = e.generation - 1;
        let result = self
            .json(
                sql,
                &[
                    &e.intent_id,
                    &expected,
                    &e.executor_id,
                    &e.lease_id,
                    &e.state,
                    &e.hash,
                    &e.evidence,
                ],
            )
            .await?;
        ensure!(
            result["stateGeneration"].as_str() == Some(e.generation.to_string().as_str()),
            "reducer generation differs"
        );
        Ok(())
    }
    pub async fn recover(&self, e: &Event) -> Result<()> {
        let expected = e.generation - 1;
        let result = self
            .json(
                "SELECT upgrade_intent_recover($1,$2,$3,$4,$5,$6)",
                &[
                    &e.intent_id,
                    &expected,
                    &e.executor_id,
                    &e.lease_id,
                    &e.hash,
                    &e.evidence,
                ],
            )
            .await?;
        ensure!(
            result["intentId"].as_str() == Some(e.intent_id.to_string().as_str())
                && result["state"] == "rolled_back"
                && result["stateGeneration"].as_str() == Some(e.generation.to_string().as_str()),
            "recovery reducer response identity differs"
        );
        Ok(())
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
#[derive(Clone)]
pub struct Intent {
    pub id: i64,
    pub release_id: String,
    pub manifest_digest: String,
    pub recovery_set_id: String,
    pub recovery_set_digest: String,
    pub state: String,
    pub generation: i64,
}
impl Intent {
    fn parse(v: &Value) -> Result<Self> {
        let string = |key: &str| v[key].as_str().unwrap_or_default().to_owned();
        let id = string("intentId").parse::<i64>()?;
        let generation = string("stateGeneration").parse::<i64>()?;
        ensure!(
            id > 0
                && generation > 0
                && v["intentId"].as_str() == Some(id.to_string().as_str())
                && v["stateGeneration"].as_str() == Some(generation.to_string().as_str()),
            "invalid decimal authority"
        );
        let result = Self {
            id,
            generation,
            release_id: string("releaseId"),
            manifest_digest: string("manifestDigest"),
            recovery_set_id: string("recoverySetId"),
            recovery_set_digest: string("recoverySetDigest"),
            state: string("state"),
        };
        ensure!(
            identifier(&result.release_id) && digest(&result.manifest_digest),
            "invalid release authority"
        );
        ensure!(
            result.recovery_set_id.is_empty() && result.recovery_set_digest.is_empty()
                || uuid::Uuid::parse_str(&result.recovery_set_id).is_ok()
                    && digest(&result.recovery_set_digest),
            "invalid recovery authority"
        );
        Ok(result)
    }
    pub fn prepared(&self, executor: &str) -> Event {
        Event {
            sequence: 0,
            intent_id: self.id,
            release_id: self.release_id.clone(),
            manifest_digest: self.manifest_digest.clone(),
            recovery_set_id: self.recovery_set_id.clone(),
            recovery_set_digest: self.recovery_set_digest.clone(),
            lease_id: uuid::Uuid::new_v4(),
            executor_id: executor.into(),
            generation: self.generation,
            state: self.state.clone(),
            step: "claim_prepared".into(),
            evidence: serde_json::json!({"prepared":true}),
            previous_hash: String::new(),
            hash: String::new(),
        }
    }
}
