//! SAML SP cache invalidation over direct LISTEN credentials.
use super::*;
use std::time::Duration;
pub struct Listener(tokio::task::JoinHandle<()>);
impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn relevant(key: &str) -> bool {
    if matches!(key, "auth_methods" | "saml_sp") {
        return true;
    }
    false
}
impl Registry {
    async fn reconcile(&self, epoch: u64) -> Result<(), String> {
        self.entries
            .reload_snapshot(epoch, self.load_entries())
            .await
    }

    pub async fn listen(self: &Arc<Self>, direct_dsn: &str) -> Listener {
        // Subscribe before the authoritative read, closing the load→LISTEN gap.
        let initial = match self.entries.connect(direct_dsn).await {
            Ok((listener, epoch)) => match self.reconcile(epoch).await {
                Ok(()) => Some((listener, epoch)),
                Err(error) => {
                    eprintln!("saml_sp initial reconcile: {error}");
                    None
                }
            },
            Err(error) => {
                eprintln!("saml_sp LISTEN: {error}");
                None
            }
        };
        let registry = self.clone();
        let dsn = direct_dsn.to_owned();
        Listener(tokio::spawn(async move {
            let mut current = initial;
            loop {
                let (mut listener, epoch) = match current.take() {
                    Some(l) => l,
                    None => match registry.entries.connect(&dsn).await {
                        Ok((listener, epoch)) => {
                            if let Err(e) = registry.reconcile(epoch).await {
                                eprintln!("saml_sp reconnect reconcile: {e}");
                                drop(listener);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                            (listener, epoch)
                        }
                        Err(e) => {
                            eprintln!("saml_sp LISTEN: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    },
                };
                while let Some(n) = listener.recv().await {
                    if config_change(n.payload())
                        .map(|key| relevant(&key))
                        .unwrap_or(false)
                    {
                        if let Err(e) = registry.reconcile(epoch).await {
                            eprintln!("saml_sp reconcile: {e}");
                            break;
                        }
                    }
                }
                drop(listener);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }

    /// Multiplex SAML SP `config_changed` invalidation onto a shared
    /// [`setjoin_pg::ListenHub`] (#543).
    pub async fn listen_with_hub(self: &Arc<Self>, hub: &setjoin_pg::ListenHub) -> Listener {
        let initial = match self.entries.subscribe_hub(hub).await {
            Ok((sub, epoch)) => match self.reconcile(epoch).await {
                Ok(()) => Some((sub, epoch)),
                Err(error) => {
                    eprintln!("saml_sp initial reconcile: {error}");
                    self.entries.disconnect_epoch(epoch);
                    None
                }
            },
            Err(error) => {
                eprintln!("saml_sp LISTEN hub: {error}");
                None
            }
        };
        let registry = self.clone();
        let hub = hub.clone();
        Listener(tokio::spawn(async move {
            let mut current = initial;
            loop {
                let (mut sub, epoch) = match current.take() {
                    Some(pair) => pair,
                    None => match registry.entries.subscribe_hub(&hub).await {
                        Ok((sub, epoch)) => {
                            if let Err(e) = registry.reconcile(epoch).await {
                                eprintln!("saml_sp reconnect reconcile: {e}");
                                registry.entries.disconnect_epoch(epoch);
                                drop(sub);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                            (sub, epoch)
                        }
                        Err(e) => {
                            eprintln!("saml_sp LISTEN hub: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    },
                };
                while let Some(event) = sub.recv().await {
                    match event {
                        setjoin_pg::ListenEvent::Notification(n) => {
                            if config_change(&n.payload)
                                .map(|key| relevant(&key))
                                .unwrap_or(false)
                            {
                                if let Err(e) = registry.reconcile(epoch).await {
                                    eprintln!("saml_sp reconcile: {e}");
                                    registry.entries.disconnect_epoch(epoch);
                                    break;
                                }
                            }
                        }
                        setjoin_pg::ListenEvent::ResyncRequired { .. } => {
                            if let Err(e) = registry.reconcile(epoch).await {
                                eprintln!("saml_sp resync reconcile: {e}");
                                registry.entries.disconnect_epoch(epoch);
                                break;
                            }
                        }
                    }
                }
                registry.entries.disconnect_epoch(epoch);
                drop(sub);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }
}
