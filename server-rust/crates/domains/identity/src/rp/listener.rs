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
    pub async fn listen(self: &Arc<Self>, direct_dsn: &str) -> Listener {
        // Subscribe before the authoritative read, closing the load→LISTEN gap.
        let initial = match self.providers.connect(direct_dsn).await {
            Ok((listener, epoch)) => match self.reload_snapshot(Some(epoch)).await {
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
                            if let Err(e) = registry.reload_snapshot(Some(epoch)).await {
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
                        if let Err(e) = registry.reload_snapshot(Some(epoch)).await {
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
}
