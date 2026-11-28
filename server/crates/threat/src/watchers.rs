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

    /// Multiplex `config_changed` and `conditional_access` onto a shared
    /// [`setjoin_pg::ListenHub`] instead of opening two standalone direct
    /// PostgreSQL connections (#543).
    pub async fn start_with_hub(
        gate: Arc<Gate>,
        hub: &setjoin_pg::ListenHub,
    ) -> Result<Self, Error> {
        let mut flags_sub = hub
            .subscribe("config_changed")
            .await
            .map_err(|e| format!("threat flags listen hub subscribe: {e}"))?;
        let mut policy_sub = hub
            .subscribe("conditional_access")
            .await
            .map_err(|e| format!("threat policy listen hub subscribe: {e}"))?;
        gate.reload_flags().await?;
        let flags_gate = gate.clone();
        let flags_task = tokio::spawn(async move {
            while let Some(event) = flags_sub.recv().await {
                if matches!(event, setjoin_pg::ListenEvent::Notification(_)) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if let Err(error) = reconcile(&flags_gate, false).await {
                    eprintln!("auth config reload: {error}");
                }
            }
        });
        let policy_task = tokio::spawn(async move {
            while let Some(_event) = policy_sub.recv().await {
                if let Err(error) = reconcile(&gate, true).await {
                    eprintln!("auth config reload: {error}");
                }
            }
        });
        Ok(Self(vec![flags_task, policy_task]))
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
