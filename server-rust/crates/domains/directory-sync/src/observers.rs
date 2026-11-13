//! The AD and identity toggle observers (`gatewayToggleObserver`,
//! `runADToggleObserver`, `runIdentityToggleObserver`).
//!
//! Go's toggle lifecycle reloads its snapshot, then tells each observer which
//! `config_changed` notification caused it. Every notification is only a hint:
//! the observers coalesce hints into one-slot signals and the consumer re-reads
//! authoritative state. Rust derives worker state from the database per
//! request and tick, so the AD observer's whole effect is waking the AD loop
//! (Go's `ReloadConfig` replaces the worker, which starts an immediate cycle).
use setjoin_pg::workers::DirectListener;
use std::future::Future;
use std::time::Duration;

pub const CONFIG_CHANGED: &str = "config_changed";
pub const FEATURE_AD_SYNC: &str = "feature.ad_sync";
pub const FEATURE_IDENTITY_MODEL_V2: &str = "feature.identity_model_v2";

/// `toggle.Notification` as the observers read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Notification {
    pub key: String,
    pub reload: bool,
}

/// Go `decodeNotification`: malformed or keyless payloads are reload hints.
pub fn decode(payload: &str) -> Notification {
    match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(serde_json::Value::Object(map)) => {
            // Go decodes `{"key","enabled","reload"}` case-insensitively; a
            // field of the wrong type fails the whole decode.
            let mut note = Notification::default();
            for (name, value) in &map {
                match (name.to_ascii_lowercase().as_str(), value) {
                    ("key", serde_json::Value::String(text)) => note.key = text.clone(),
                    ("reload", serde_json::Value::Bool(flag)) => note.reload = *flag,
                    ("key" | "reload", serde_json::Value::Null) => {}
                    ("key" | "reload" | "enabled", other)
                        if !other.is_null()
                            && !(name.eq_ignore_ascii_case("enabled") && other.is_boolean())
                            && !(name.eq_ignore_ascii_case("key") && other.is_string())
                            && !(name.eq_ignore_ascii_case("reload") && other.is_boolean()) =>
                    {
                        return Notification {
                            key: String::new(),
                            reload: true,
                        }
                    }
                    _ => {}
                }
            }
            if note.key.is_empty() && !note.reload {
                note.reload = true;
            }
            note
        }
        _ => Notification {
            key: String::new(),
            reload: true,
        },
    }
}

/// The AD signal: a reload hint or `feature.ad_sync`.
pub fn touches_ad(n: &Notification) -> bool {
    n.reload || n.key == FEATURE_AD_SYNC
}

/// The identity signal: a reload hint, `feature.identity_model_v2` or
/// `identity.source.<id>` with a positive integer id.
pub fn touches_identity(n: &Notification) -> bool {
    n.reload || n.key == FEATURE_IDENTITY_MODEL_V2 || valid_identity_source_key(&n.key)
}

pub fn valid_identity_source_key(key: &str) -> bool {
    key.strip_prefix("identity.source.").is_some_and(|id| {
        let digits = id.strip_prefix('+').unwrap_or(id);
        !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && id.parse::<i64>().is_ok_and(|n| n > 0)
    })
}

/// Listen on `config_changed` over the direct connection and call `signal`
/// for every notification `wanted` accepts, and once per (re)connection (Go's
/// reconnect reconciler delivers a reload hint). Returns when `stop` resolves.
pub async fn run_observer(
    direct_dsn: String,
    wanted: fn(&Notification) -> bool,
    signal: impl Fn(),
    stop: impl Future<Output = ()>,
) {
    tokio::pin!(stop);
    loop {
        let listener = tokio::select! {
            _ = &mut stop => return,
            result = DirectListener::connect(&direct_dsn, CONFIG_CHANGED) => result,
        };
        match listener {
            Ok(mut listener) => {
                signal();
                loop {
                    let event = tokio::select! {
                        _ = &mut stop => {
                            let _ = listener.close().await;
                            return;
                        }
                        event = listener.recv() => event,
                    };
                    let Some(event) = event else {
                        let _ = listener.close().await;
                        break;
                    };
                    if wanted(&decode(event.payload())) {
                        signal();
                    }
                }
            }
            Err(error) => eprintln!("setjoin-gateway: toggle observer listener: {error}"),
        }
        tokio::select! {
            _ = &mut stop => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_keyless_payloads_are_reload_hints() {
        assert!(decode("not json").reload);
        assert!(decode("{}").reload);
        assert!(decode("{\"key\":\"\",\"enabled\":true}").reload);
        assert!(decode("{\"key\":5}").reload);
        let named = decode("{\"key\":\"feature.ad_sync\",\"enabled\":false}");
        assert_eq!(named.key, FEATURE_AD_SYNC);
        assert!(!named.reload);
    }

    #[test]
    fn ad_and_identity_signals_match_go() {
        let n = |k: &str| Notification {
            key: k.into(),
            reload: false,
        };
        assert!(touches_ad(&n("feature.ad_sync")));
        assert!(!touches_ad(&n("feature.identity_model_v2")));
        assert!(touches_ad(&decode("garbage")));
        assert!(touches_identity(&n("feature.identity_model_v2")));
        assert!(touches_identity(&n("identity.source.12")));
        assert!(!touches_identity(&n("identity.source.0")));
        assert!(!touches_identity(&n("identity.source.x")));
        assert!(!touches_identity(&n("identity.source.")));
        assert!(!touches_identity(&n("feature.ad_sync")));
    }
}
