//! The process-local connection registry shared by WS, SSE and presence.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};
type Close = Arc<dyn Fn() + Send + Sync>;
#[derive(Clone, Default)]
pub struct ConnectionRegistry(Arc<Mutex<State>>);
#[derive(Default)]
struct State {
    next: u64,
    closed: bool,
    entries: HashMap<u64, Entry>,
}
struct Entry {
    user: i64,
    mailbox: Option<i64>,
    chat: bool,
    close: Close,
}
/// Drop removes this connection exactly once.
pub struct Connection {
    registry: Weak<Mutex<State>>,
    id: u64,
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(state) = self.registry.upgrade() {
            state
                .lock()
                .expect("connection registry")
                .entries
                .remove(&self.id);
        }
    }
}
impl ConnectionRegistry {
    /// Identity and mailbox come from a verified session; `chat` records an admitted subscription.
    pub fn register(
        &self,
        user: i64,
        mailbox: Option<i64>,
        chat: bool,
        close: Close,
    ) -> Connection {
        assert!(user > 0 && mailbox.is_none_or(|id| id > 0));
        let mut state = self.0.lock().expect("connection registry");
        if state.closed {
            drop(state);
            close();
            return Connection {
                registry: Weak::new(),
                id: 0,
            };
        }
        state.next += 1;
        let id = state.next;
        state.entries.insert(
            id,
            Entry {
                user,
                mailbox,
                chat,
                close,
            },
        );
        Connection {
            registry: Arc::downgrade(&self.0),
            id,
        }
    }
    pub fn is_online(&self, user: i64) -> bool {
        self.0
            .lock()
            .expect("connection registry")
            .entries
            .values()
            .any(|e| e.user == user && e.chat)
    }
    pub fn evict_user(&self, user: i64) {
        self.evict(|e| e.user == user);
    }
    pub fn evict_mailbox(&self, mailbox: i64) {
        self.evict(|e| e.mailbox == Some(mailbox));
    }
    pub fn shutdown(&self) {
        self.0.lock().expect("connection registry").closed = true;
        self.evict(|_| true);
    }
    fn evict(&self, matches: impl Fn(&Entry) -> bool) {
        let closes: Vec<_> = {
            let mut state = self.0.lock().expect("connection registry");
            let ids: Vec<_> = state
                .entries
                .iter()
                .filter(|(_, e)| matches(e))
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| state.entries.remove(&id))
                .map(|e| e.close)
                .collect()
        };
        for close in closes {
            close();
        }
    }
}
