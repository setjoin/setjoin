//! Port of `threat.ProtocolSessionRegistry` for password-authenticated
//! protocol connections (IMAP, later SMTP submission). Only the scope=all
//! revocation applies to them: they carry no token JTI or refresh family.
//! The feed (the `session_revoke` NOTIFY and the periodic reconcile) belongs to
//! the session-denylist refresh in #420; until it calls [`apply`] and
//! [`reconcile`] a Rust listener never sees a revocation.
//!
//! [`apply`]: ProtocolSessionRegistry::apply
//! [`reconcile`]: ProtocolSessionRegistry::reconcile
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct RevocationRow {
    pub user_id: i64,
    pub not_before: SystemTime,
    /// `None` is Go's zero time: rolling-compatibility default of 31 days.
    pub expires_at: Option<SystemTime>,
    /// Only `all` revokes a password session; narrower scopes are ignored.
    pub scope_all: bool,
}

/// Closing handle for one connection; the session loop watches it.
pub type Closer = Arc<watch::Sender<bool>>;

struct Entry {
    authenticated_at: SystemTime,
    conn: Closer,
}
struct Watermark {
    not_before: SystemTime,
    expires_at: SystemTime,
}
#[derive(Default)]
struct Inner {
    next: u64,
    sessions: HashMap<i64, HashMap<u64, Entry>>,
    all_before: HashMap<i64, Watermark>,
}

#[derive(Default)]
pub struct ProtocolSessionRegistry {
    inner: Mutex<Inner>,
}

/// Idempotent release: runs on drop.
pub struct SessionRelease {
    registry: Option<Arc<ProtocolSessionRegistry>>,
    user: i64,
    id: u64,
}
impl Drop for SessionRelease {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.take() {
            let mut inner = registry.lock();
            if let Some(map) = inner.sessions.get_mut(&self.user) {
                map.remove(&self.id);
                if map.is_empty() {
                    inner.sessions.remove(&self.user);
                }
            }
        }
    }
}

impl ProtocolSessionRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn prune(inner: &mut Inner, now: SystemTime) {
        inner.all_before.retain(|_, w| w.expires_at > now);
    }

    /// Records one authenticated connection. An already-revoked authentication
    /// closes the connection at once and returns a no-op release.
    pub fn register(
        self: &Arc<Self>,
        user: i64,
        authenticated_at: SystemTime,
        conn: Closer,
    ) -> SessionRelease {
        let none = SessionRelease {
            registry: None,
            user,
            id: 0,
        };
        if user <= 0 {
            return none;
        }
        let mut inner = self.lock();
        Self::prune(&mut inner, SystemTime::now());
        if let Some(w) = inner.all_before.get(&user) {
            if authenticated_at <= w.not_before {
                drop(inner);
                let _ = conn.send(true);
                return none;
            }
        }
        inner.next += 1;
        let id = inner.next;
        inner.sessions.entry(user).or_default().insert(
            id,
            Entry {
                authenticated_at,
                conn,
            },
        );
        SessionRelease {
            registry: Some(self.clone()),
            user,
            id,
        }
    }

    pub fn apply(&self, row: &RevocationRow) {
        if row.user_id <= 0 || !row.scope_all {
            return;
        }
        let now = SystemTime::now();
        let expires_at = match row.expires_at {
            Some(at) if at <= now => return,
            Some(at) => at,
            None => now + Duration::from_secs(31 * 24 * 3600),
        };
        let mut close = Vec::new();
        {
            let mut inner = self.lock();
            Self::prune(&mut inner, now);
            if inner
                .all_before
                .get(&row.user_id)
                .is_none_or(|w| row.not_before > w.not_before)
            {
                inner.all_before.insert(
                    row.user_id,
                    Watermark {
                        not_before: row.not_before,
                        expires_at,
                    },
                );
            }
            if let Some(map) = inner.sessions.get_mut(&row.user_id) {
                map.retain(|_, e| {
                    if e.authenticated_at <= row.not_before {
                        close.push(e.conn.clone());
                        false
                    } else {
                        true
                    }
                });
                if map.is_empty() {
                    inner.sessions.remove(&row.user_id);
                }
            }
        }
        for conn in close {
            let _ = conn.send(true);
        }
    }

    pub fn reconcile(&self, rows: &[RevocationRow]) {
        {
            let mut inner = self.lock();
            Self::prune(&mut inner, SystemTime::now());
        }
        for row in rows {
            self.apply(row);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closer() -> (Closer, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Arc::new(tx), rx)
    }
    fn row(user: i64, not_before: SystemTime) -> RevocationRow {
        RevocationRow {
            user_id: user,
            not_before,
            expires_at: None,
            scope_all: true,
        }
    }

    #[test]
    fn apply_closes_only_sessions_authenticated_at_or_before_the_watermark() {
        let registry = Arc::new(ProtocolSessionRegistry::default());
        let now = SystemTime::now();
        let (old, old_rx) = closer();
        let (new, new_rx) = closer();
        let (other, other_rx) = closer();
        let _a = registry.register(7, now - Duration::from_secs(10), old);
        let _b = registry.register(7, now + Duration::from_secs(10), new);
        let _c = registry.register(8, now - Duration::from_secs(10), other);
        registry.apply(&row(7, now));
        assert!(*old_rx.borrow());
        assert!(!*new_rx.borrow(), "later authentication survives");
        assert!(!*other_rx.borrow(), "other users are untouched");
    }

    #[test]
    fn watermark_closes_a_late_registration_and_expires() {
        let registry = Arc::new(ProtocolSessionRegistry::default());
        let now = SystemTime::now();
        registry.apply(&row(7, now + Duration::from_secs(3600)));
        let (conn, rx) = closer();
        let _release = registry.register(7, now, conn);
        assert!(*rx.borrow(), "revoked at registration closes at once");
        // A row already past its expiry is ignored entirely.
        let registry = Arc::new(ProtocolSessionRegistry::default());
        registry.apply(&RevocationRow {
            expires_at: Some(now - Duration::from_secs(1)),
            ..row(7, now + Duration::from_secs(3600))
        });
        let (conn, rx) = closer();
        let _release = registry.register(7, now, conn);
        assert!(!*rx.borrow());
    }

    #[test]
    fn narrower_scopes_and_invalid_users_never_revoke_password_sessions() {
        let registry = Arc::new(ProtocolSessionRegistry::default());
        let now = SystemTime::now();
        let (conn, rx) = closer();
        let _release = registry.register(7, now - Duration::from_secs(1), conn);
        registry.apply(&RevocationRow {
            scope_all: false,
            ..row(7, now)
        });
        registry.apply(&row(0, now));
        assert!(!*rx.borrow());
    }

    #[test]
    fn release_forgets_the_session_and_reconcile_reapplies_rows() {
        let registry = Arc::new(ProtocolSessionRegistry::default());
        let now = SystemTime::now();
        let (conn, rx) = closer();
        let release = registry.register(7, now - Duration::from_secs(1), conn);
        drop(release);
        registry.apply(&row(7, now));
        assert!(!*rx.borrow(), "a released session is not closed");
        let (conn, rx) = closer();
        let _live = registry.register(9, now - Duration::from_secs(1), conn);
        registry.reconcile(&[row(9, now)]);
        assert!(*rx.borrow());
    }
}
