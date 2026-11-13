//! Explicitly transferred SAML SP cache task, with direct LISTEN credentials only.
use super::*;
use setjoin_pg::workers::DirectListener;
use std::time::Duration;
pub struct Listener(tokio::task::JoinHandle<()>);
impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// Startup guard: the Rust task never competes with the Go task by accident.
pub fn admit_worker(rust_on: &str, go_off: &str) -> Result<bool, String> {
    let contains = |raw: &str| raw.split(',').any(|v| v.trim() == "saml_sp");
    if !contains(rust_on) {
        return Ok(false);
    }
    if !contains(go_off) {
        return Err("saml_sp requires GO_WORKERS_OFF=saml_sp".into());
    }
    Ok(true)
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
        let mut initial = DirectListener::connect(direct_dsn, "config_changed")
            .await
            .ok();
        if initial.is_some() {
            if let Err(e) = self.reload().await {
                eprintln!("saml_sp initial reconcile: {e}");
                initial = None;
            }
        }
        let registry = self.clone();
        let dsn = direct_dsn.to_owned();
        Listener(tokio::spawn(async move {
            let mut current = initial;
            loop {
                let mut listener = match current.take() {
                    Some(l) => l,
                    None => match DirectListener::connect(&dsn, "config_changed").await {
                        Ok(l) => {
                            if let Err(e) = registry.reload().await {
                                eprintln!("saml_sp reconnect reconcile: {e}");
                                drop(l);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                            l
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
                        if let Err(e) = registry.reload().await {
                            eprintln!("saml_sp reconcile: {e}");
                        }
                    }
                }
                drop(listener);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }))
    }
}
