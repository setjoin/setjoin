//! Independent direct connections; LISTEN precedes each authoritative reload.
use crate::{Error, Gate};
use setjoin_pg::workers::DirectListener;
use std::{sync::Arc, time::Duration};
pub struct Watchers(Vec<tokio::task::JoinHandle<()>>);
impl Drop for Watchers {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
fn named(dsn: &str, name: &str) -> String {
    if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        format!(
            "{dsn}{}application_name={name}",
            if dsn.contains('?') { "&" } else { "?" }
        )
    } else {
        format!("{dsn} application_name={name}")
    }
}
impl Watchers {
    pub async fn start(gate: Arc<Gate>, direct: &str, name: &str) -> Result<Self, Error> {
        if !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err("invalid listener name".into());
        }
        let flags = named(direct, &format!("{name}-flags"));
        let policy = named(direct, &format!("{name}-policy"));
        // feature_toggles is boot-critical in Go; CA setup is separately supervised.
        let initial = DirectListener::connect(&flags, "config_changed").await?;
        gate.reload_flags().await?;
        Ok(Self(vec![
            tokio::spawn(run(gate.clone(), flags, false, Some(initial))),
            tokio::spawn(run(gate, policy, true, None)),
        ]))
    }
}
async fn reconcile(gate: &Gate, policy: bool) -> Result<(), Error> {
    if policy {
        gate.engine
            .invalidate_auth()
            .await
            .map_err(|e| e.message.into())
    } else {
        gate.reload_flags().await
    }
}
async fn run(gate: Arc<Gate>, dsn: String, policy: bool, mut initial: Option<DirectListener>) {
    let channel = if policy {
        "conditional_access"
    } else {
        "config_changed"
    };
    let mut retry = Duration::from_secs(1);
    loop {
        let subscribed = if let Some(listener) = initial.take() {
            Ok(listener)
        } else {
            match tokio::time::timeout(
                Duration::from_secs(5),
                DirectListener::connect(&dsn, channel),
            )
            .await
            {
                Ok(Ok(listener)) => {
                    if reconcile(&gate, policy).await.is_ok() {
                        Ok(listener)
                    } else {
                        Err(())
                    }
                }
                _ => Err(()),
            }
        };
        if let Ok(mut listener) = subscribed {
            retry = Duration::from_secs(1);
            while listener.recv().await.is_some() {
                if !policy {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                // Payloads are hints only; forged flag values never replace DB authority.
                if let Err(error) = reconcile(&gate, policy).await {
                    eprintln!("auth config reload: {error}");
                }
            }
        }
        tokio::time::sleep(retry).await;
        retry = (retry * 2).min(Duration::from_secs(30));
    }
}
