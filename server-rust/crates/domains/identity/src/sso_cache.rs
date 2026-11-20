//! When a registry is watched, only its current live connection can publish trust.
use setjoin_pg::workers::DirectListener;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

#[derive(PartialEq, Eq)]
enum Connection {
    Unmanaged,
    Disconnected,
    Live,
}

struct State<T> {
    entries: BTreeMap<String, Arc<T>>,
    epoch: u64,
    connection: Connection,
}

pub(super) struct Cache<T>(RwLock<State<T>>);

pub(super) struct Reload {
    epoch: u64,
    pub(super) allow_partial: bool,
}

const DISCONNECTED: &str = "SSO configuration listener disconnected";

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self(RwLock::new(State {
            entries: BTreeMap::new(),
            epoch: 0,
            connection: Connection::Unmanaged,
        }))
    }
}

impl<T> Cache<T> {
    pub(super) fn get(&self, name: &str) -> Option<Arc<T>> {
        self.0.read().unwrap().entries.get(name).cloned()
    }

    fn begin_connection(&self) -> u64 {
        let mut state = self.0.write().unwrap();
        state.epoch += 1;
        state.connection = Connection::Disconnected;
        state.entries.clear();
        state.epoch
    }

    fn connected(&self, epoch: u64) -> bool {
        let mut state = self.0.write().unwrap();
        if state.epoch != epoch {
            return false;
        }
        state.connection = Connection::Live;
        true
    }

    fn disconnected(&self, epoch: u64) {
        let mut state = self.0.write().unwrap();
        if state.epoch == epoch {
            state.epoch += 1;
            state.connection = Connection::Disconnected;
            state.entries.clear();
        }
    }

    pub(super) fn start_reload(&self, expected_epoch: Option<u64>) -> Result<Reload, String> {
        let state = self.0.read().unwrap();
        if state.connection == Connection::Disconnected
            || expected_epoch.is_some_and(|epoch| epoch != state.epoch)
        {
            return Err(DISCONNECTED.into());
        }
        Ok(Reload {
            epoch: state.epoch,
            allow_partial: state.connection == Connection::Unmanaged,
        })
    }

    pub(super) fn publish(
        &self,
        reload: Reload,
        entries: BTreeMap<String, Arc<T>>,
    ) -> Result<(), String> {
        let mut state = self.0.write().unwrap();
        if state.epoch != reload.epoch || state.connection == Connection::Disconnected {
            return Err(DISCONNECTED.into());
        }
        state.entries = entries;
        Ok(())
    }
}

impl<T: Send + Sync + 'static> Cache<T> {
    pub(super) async fn connect(
        self: &Arc<Self>,
        dsn: &str,
    ) -> Result<(DirectListener, u64), Box<dyn std::error::Error + Send + Sync>> {
        let epoch = self.begin_connection();
        let cache = self.clone();
        let listener = DirectListener::connect_with_disconnect(dsn, "config_changed", move || {
            cache.disconnected(epoch);
        })
        .await;
        match listener {
            Ok(listener) if self.connected(epoch) => Ok((listener, epoch)),
            Ok(_) => Err(DISCONNECTED.into()),
            Err(error) => {
                self.disconnected(epoch);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_from_disconnected_epoch_cannot_publish() {
        let cache = Cache::default();
        let epoch = cache.begin_connection();
        assert!(cache.connected(epoch));
        let seed = cache.start_reload(Some(epoch)).unwrap();
        cache
            .publish(seed, BTreeMap::from([("idp".into(), Arc::new("seed"))]))
            .unwrap();
        let stale = cache.start_reload(Some(epoch)).unwrap();
        let stale_after_reconnect = cache.start_reload(Some(epoch)).unwrap();

        cache.disconnected(epoch);
        assert!(cache.get("idp").is_none());
        assert!(cache.start_reload(Some(epoch)).is_err());
        assert!(cache
            .publish(stale, BTreeMap::from([("idp".into(), Arc::new("stale"))]))
            .is_err());
        assert!(cache.get("idp").is_none());

        let next = cache.begin_connection();
        assert!(cache.connected(next));
        let fresh = cache.start_reload(Some(next)).unwrap();
        cache
            .publish(fresh, BTreeMap::from([("idp".into(), Arc::new("fresh"))]))
            .unwrap();
        assert!(cache
            .publish(
                stale_after_reconnect,
                BTreeMap::from([("idp".into(), Arc::new("stale"))]),
            )
            .is_err());
        cache.disconnected(epoch);
        assert_eq!(cache.get("idp").as_deref(), Some(&"fresh"));
    }
}
