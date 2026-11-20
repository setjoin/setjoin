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
    pub async fn listen(self: &Arc<Self>, direct_dsn: &str) -> Listener {
        // Subscribe before the authoritative read, closing the load→LISTEN gap.
        let initial = match self.entries.connect(direct_dsn).await {
            Ok((listener, epoch)) => match self.reload_snapshot(Some(epoch)).await {
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
                            if let Err(e) = registry.reload_snapshot(Some(epoch)).await {
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
                        if let Err(e) = registry.reload_snapshot(Some(epoch)).await {
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
}
