//! OIDC RP cache invalidation over direct LISTEN credentials.
use super::*;
pub struct Listener(tokio::task::JoinHandle<()>);
impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn relevant(key: &str) -> bool {
    if matches!(key, "auth_methods" | "oidc_rp") {
        return true;
    }
    key.strip_prefix("oidc_provider_")
        .and_then(|s| s.strip_suffix("_config"))
        .is_some_and(|s| {
            !s.is_empty() && s.len() <= 200 && !s.chars().any(|c| c < ' ' || c == '\u{7f}')
        })
}
impl Registry {
    async fn reconcile(&self, epoch: u64) -> Result<(), String> {
        self.providers
            .reload_snapshot(epoch, self.load_providers())
            .await
    }

    pub async fn listen(self: &Arc<Self>, direct_dsn: &str) -> Listener {
        // Subscribe before the authoritative read, closing the load→LISTEN gap.
        let initial = match self.providers.connect(direct_dsn).await {
            Ok((listener, epoch)) => match self.reconcile(epoch).await {
                Ok(()) => Some((listener, epoch)),
                Err(error) => {
                    eprintln!("oidc_rp initial reconcile: {error}");
                    None
                }
            },
            Err(error) => {
                eprintln!("oidc_rp LISTEN: {error}");
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
                    None => match registry.providers.connect(&dsn).await {
                        Ok((listener, epoch)) => {
                            if let Err(e) = registry.reconcile(epoch).await {
                                eprintln!("oidc_rp reconnect reconcile: {e}");
                                drop(listener);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                            (listener, epoch)
                        }
                        Err(e) => {
                            eprintln!("oidc_rp LISTEN: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    },
                };
                while let Some(n) = listener.recv().await {
                    if serde_json::from_str::<serde_json::Value>(n.payload())
                        .ok()
                        .and_then(|v| v["key"].as_str().map(relevant))
                        .unwrap_or(false)
                    {
                        if let Err(e) = registry.reconcile(epoch).await {
                            eprintln!("oidc_rp reconcile: {e}");
                            break;
                        }
                    }
                }
                drop(listener);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }

    /// Multiplex OIDC RP `config_changed` invalidation onto a shared
    /// [`setjoin_pg::ListenHub`] (#543).
    pub async fn listen_with_hub(self: &Arc<Self>, hub: &setjoin_pg::ListenHub) -> Listener {
        let initial = match self.providers.subscribe_hub(hub).await {
            Ok((sub, epoch)) => match self.reconcile(epoch).await {
                Ok(()) => Some((sub, epoch)),
                Err(error) => {
                    eprintln!("oidc_rp initial reconcile: {error}");
                    self.providers.disconnect_epoch(epoch);
                    None
                }
            },
            Err(error) => {
                eprintln!("oidc_rp LISTEN hub: {error}");
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
                    None => match registry.providers.subscribe_hub(&hub).await {
                        Ok((sub, epoch)) => {
                            if let Err(e) = registry.reconcile(epoch).await {
                                eprintln!("oidc_rp reconnect reconcile: {e}");
                                registry.providers.disconnect_epoch(epoch);
                                drop(sub);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                            (sub, epoch)
                        }
                        Err(e) => {
                            eprintln!("oidc_rp LISTEN hub: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    },
                };
                while let Some(event) = sub.recv().await {
                    match event {
                        setjoin_pg::ListenEvent::Notification(n) => {
                            if serde_json::from_str::<serde_json::Value>(&n.payload)
                                .ok()
                                .and_then(|v| v["key"].as_str().map(relevant))
                                .unwrap_or(false)
                            {
                                if let Err(e) = registry.reconcile(epoch).await {
                                    eprintln!("oidc_rp reconcile: {e}");
                                    registry.providers.disconnect_epoch(epoch);
                                    break;
                                }
                            }
                        }
                        setjoin_pg::ListenEvent::ResyncRequired { .. } => {
                            if let Err(e) = registry.reconcile(epoch).await {
                                eprintln!("oidc_rp resync reconcile: {e}");
                                registry.providers.disconnect_epoch(epoch);
                                break;
                            }
                        }
                    }
                }
                registry.providers.disconnect_epoch(epoch);
                drop(sub);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }
}
