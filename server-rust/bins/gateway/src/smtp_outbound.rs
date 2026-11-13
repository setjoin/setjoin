//! The outbound queue's object-store and process wiring.
use crate::recovery_worker::S3Store;
use futures_util::future::BoxFuture;

pub struct BlobSource(pub S3Store);
impl setjoin_smtp::outbound::RawSource for BlobSource {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(self.0.smtp_raw(key))
    }
}

/// Only an explicit named, single-writer handover may launch the task.
pub async fn from_environment() -> Result<Option<setjoin_smtp::outbound::OutboundWorker>, String> {
    let listed = |name: &str| {
        std::env::var(name)
            .unwrap_or_default()
            .split(',')
            .any(|value| value.trim() == setjoin_smtp::outbound::NAME)
    };
    if !listed("RUST_WORKERS_ON") {
        return Ok(None);
    }
    if !listed("GO_WORKERS_OFF") {
        return Err(
            "outbound-mail requires GO_WORKERS_OFF=outbound-mail before Rust starts it".into(),
        );
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for outbound-mail")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = setjoin_pg::workers::WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|_| "invalid DB_WORKER_DSN for outbound-mail")?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let network = std::sync::Arc::new(setjoin_smtp::outbound::SystemNetwork::new()?);
    let hostname = network.local_hostname().await;
    let dns = std::sync::Arc::new(setjoin_smtp::mail_auth::SystemDns::new()?);
    let security = std::sync::Arc::new(
        setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
            setjoin_smtp::outbound::transport::SystemTlsa::new(),
        ))
        .with_policy_fetch(
            db.clone(),
            dns.clone(),
            std::sync::Arc::new(HttpPolicyFetch::new()),
        )
        .with_reporting(db.clone(), dns)
        .with_live_features(db.clone()),
    );
    let worker = setjoin_smtp::outbound::OutboundWorker::new(
        db,
        std::sync::Arc::new(BlobSource(S3Store::from_env()?)),
        network,
        hostname,
    )
    .with_transport_security(security);
    let keys = crate::link_protect::TokenKeys::from_env();
    let worker = worker.with_forward_transform(std::sync::Arc::new(ForwardPreparation(keys)));
    worker
        .initialize_transport()
        .await
        .map_err(|error| format!("outbound-mail transport configuration: {error}"))?;
    Ok(Some(worker))
}

mod prepare;
pub use prepare::ForwardPreparation;

mod policy;
pub use policy::HttpPolicyFetch;
