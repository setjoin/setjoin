//! `system.health_alert` (#457): Go's `health.Handler` keeps `prevStatus` per check and
//! dispatches `NewCloudEvent("mailserver/gateway", "system.health_alert",
//! {"check": name, "status": "failed"})` on each ok-to-error transition (not on every poll
//! of a persistent error), through the generic organization-scoped `Dispatch`. One tracker
//! serves both Rust health evaluations (public `/health` and `/admin/health`), as Go's
//! single handler serves both.
use crate::webhook::{CloudEvent, Dispatcher};
use std::{collections::HashMap, sync::Arc, sync::Mutex};

pub struct HealthAlerts {
    previous: Mutex<HashMap<String, String>>,
    dispatcher: Dispatcher,
}

pub type Observer = setjoin_static::health::Alerts;

impl HealthAlerts {
    pub fn new(dispatcher: Dispatcher) -> Arc<Self> {
        Arc::new(Self {
            previous: Mutex::new(HashMap::new()),
            dispatcher,
        })
    }

    /// The observer both health evaluations call with their `(check, status)` rows.
    pub fn observer(self: &Arc<Self>) -> Observer {
        let tracker = self.clone();
        Arc::new(move |rows| {
            let tracker = tracker.clone();
            Box::pin(async move { tracker.observe(rows).await })
        })
    }

    async fn observe(&self, rows: Vec<(String, String)>) {
        for (check, status) in rows {
            let alert = {
                let mut previous = self.previous.lock().expect("health alert state");
                let before = previous.insert(check.clone(), status.clone());
                status == "error" && before.as_deref() != Some("error")
            };
            if alert {
                self.dispatcher
                    .dispatch(&CloudEvent::new(
                        "mailserver/gateway",
                        "system.health_alert",
                        serde_json::json!({"check": check, "status": "failed"}),
                    ))
                    .await;
            }
        }
    }
}
