//! When a registry is watched, only its current live subscription can publish trust.
use setjoin_pg::workers::DirectListener;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, RwLock},
};

#[derive(PartialEq, Eq)]
enum Connection {
    Unmanaged,
    Disconnected,
    Live,
}

type Entries<T> = BTreeMap<String, Arc<T>>;
type Snapshot<T> = Result<(Entries<T>, Vec<String>), String>;

struct State<T> {
    entries: Entries<T>,
    epoch: u64,
    connection: Connection,
}

const DISCONNECTED: &str = "SSO configuration listener disconnected";

impl<T> State<T> {
    fn current_epoch(&self) -> Result<u64, String> {
        if self.connection == Connection::Disconnected {
            return Err(DISCONNECTED.into());
        }
        Ok(self.epoch)
    }

    fn require_epoch(&self, epoch: u64) -> Result<(), String> {
        if self.current_epoch()? != epoch {
            return Err(DISCONNECTED.into());
        }
        Ok(())
    }

    fn disconnect(&mut self, epoch: u64) {
        if self.epoch == epoch {
            // Also fence a racing successful LISTEN acknowledgement.
            self.epoch += 1;
            self.connection = Connection::Disconnected;
            self.entries.clear();
        }
    }
}

pub(super) struct Cache<T> {
    state: Arc<RwLock<State<T>>>,
    reload: tokio::sync::Mutex<()>,
}

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            state: Arc::new(RwLock::new(State {
                entries: BTreeMap::new(),
                epoch: 0,
                connection: Connection::Unmanaged,
            })),
            reload: tokio::sync::Mutex::new(()),
        }
    }
}

impl<T> Cache<T> {
    pub(super) fn get(&self, name: &str) -> Option<Arc<T>> {
        self.state.read().unwrap().entries.get(name).cloned()
    }

    fn begin_connection(&self) -> u64 {
        let mut state = self.state.write().unwrap();
        state.epoch += 1;
        state.connection = Connection::Disconnected;
        state.entries.clear();
        state.epoch
    }

    fn connected(&self, epoch: u64) -> bool {
        let mut state = self.state.write().unwrap();
        if state.epoch != epoch {
            return false;
        }
        state.connection = Connection::Live;
        true
    }

    // Capture at invocation, even if the caller delays polling the future.
    pub(super) fn reload<'a>(
        &'a self,
        load: impl Future<Output = Snapshot<T>> + 'a,
    ) -> impl Future<Output = Result<(), String>> + 'a {
        let epoch = self.state.read().unwrap().current_epoch();
        async move { self.reload_snapshot(epoch?, load).await }
    }

    pub(super) async fn reload_snapshot(
        &self,
        epoch: u64,
        load: impl Future<Output = Snapshot<T>>,
    ) -> Result<(), String> {
        let _guard = self.reload.lock().await;
        self.state.read().unwrap().require_epoch(epoch)?;
        let snapshot = load.await;
        let mut state = self.state.write().unwrap();
        state.require_epoch(epoch)?;
        match snapshot {
            Ok((entries, errors)) if errors.is_empty() => {
                state.entries = entries;
                Ok(())
            }
            Ok((entries, errors)) => {
                if state.connection == Connection::Unmanaged {
                    state.entries = entries;
                } else {
                    state.entries.clear();
                }
                Err(errors.join("; "))
            }
            Err(error) => {
                state.entries.clear();
                Err(error)
            }
        }
    }
}

impl<T: Send + Sync + 'static> Cache<T> {
    pub(super) async fn connect(
        &self,
        dsn: &str,
    ) -> Result<(DirectListener, u64), Box<dyn std::error::Error + Send + Sync>> {
        let epoch = self.begin_connection();
        let listener = DirectListener::connect_guarded(
            dsn,
            "config_changed",
            self.state.clone(),
            move |state| state.disconnect(epoch),
        )
        .await?;
        if self.connected(epoch) {
            Ok((listener, epoch))
        } else {
            Err(DISCONNECTED.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::ready,
        pin::{pin, Pin},
        task::{Context, Poll, Waker},
    };

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn snapshot(value: u8) -> Snapshot<u8> {
        Ok((BTreeMap::from([("idp".into(), Arc::new(value))]), vec![]))
    }

    fn subscribe(cache: &Cache<u8>) -> u64 {
        let epoch = cache.begin_connection();
        assert!(cache.connected(epoch));
        epoch
    }

    #[test]
    fn queued_reload_cannot_adopt_resubscribed_epoch() {
        let cache = Cache::default();
        let old = subscribe(&cache);
        let guard = cache.reload.try_lock().unwrap();
        let mut queued = pin!(cache.reload(ready(snapshot(1))));
        assert!(poll_once(queued.as_mut()).is_pending());

        cache.state.write().unwrap().disconnect(old);
        subscribe(&cache);
        drop(guard);
        assert_eq!(poll_once(queued), Poll::Ready(Err(DISCONNECTED.into())));
        assert!(cache.get("idp").is_none());
    }

    #[test]
    fn in_flight_reload_cannot_publish_after_loss() {
        for resubscribe in [false, true] {
            let cache = Cache::default();
            let old = subscribe(&cache);
            let seed = cache.reload(ready(snapshot(1)));
            assert_eq!(poll_once(pin!(seed)), Poll::Ready(Ok(())));
            assert_eq!(cache.get("idp").as_deref(), Some(&1));

            let (finish, wait) = tokio::sync::oneshot::channel();
            let mut loading = pin!(cache.reload(async {
                wait.await.unwrap();
                snapshot(2)
            }));
            assert!(poll_once(loading.as_mut()).is_pending());
            cache.state.write().unwrap().disconnect(old);
            assert!(cache.get("idp").is_none());
            assert!(!cache.connected(old));

            if resubscribe {
                subscribe(&cache);
            }
            finish.send(()).unwrap();
            assert_eq!(poll_once(loading), Poll::Ready(Err(DISCONNECTED.into())));
            assert!(cache.get("idp").is_none());
        }
    }

    #[test]
    fn only_requests_after_listen_confirmation_can_restore_trust() {
        let cache = Cache::default();
        let old = subscribe(&cache);
        let before_loss = cache.reload(ready(snapshot(1)));
        cache.state.write().unwrap().disconnect(old);
        let offline = cache.reload(ready(snapshot(2)));
        let next = cache.begin_connection();
        let subscribing = cache.reload(ready(snapshot(3)));
        assert!(cache.connected(next));

        let fresh = cache.reload_snapshot(next, ready(snapshot(4)));
        assert_eq!(poll_once(pin!(fresh)), Poll::Ready(Ok(())));
        for stale in [before_loss, offline, subscribing] {
            assert_eq!(
                poll_once(pin!(stale)),
                Poll::Ready(Err(DISCONNECTED.into()))
            );
        }
        cache.state.write().unwrap().disconnect(old);
        assert_eq!(cache.get("idp").as_deref(), Some(&4));
    }
}
