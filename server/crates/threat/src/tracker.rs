//! Per-user connection slots (`tlsutil.ConnTracker`): 0 or negative means unlimited.
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex,
    },
};

#[derive(Default)]
pub struct ConnTracker {
    max: AtomicI32,
    users: Mutex<HashMap<i64, Arc<AtomicI32>>>,
}

/// Holds one slot until dropped; dropping is the release callback.
pub struct UserSlot(Option<Arc<AtomicI32>>);

impl Drop for UserSlot {
    fn drop(&mut self) {
        if let Some(count) = self.0.take() {
            count.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl ConnTracker {
    /// Saturating clamp into i32, as Go does: a huge value must not wrap negative.
    pub fn set_max(&self, n: i64) {
        self.max
            .store(n.clamp(-1, i32::MAX as i64) as i32, Ordering::SeqCst);
    }

    pub fn try_acquire(&self, user: i64) -> Result<UserSlot, ()> {
        let limit = self.max.load(Ordering::SeqCst);
        if limit <= 0 {
            return Ok(UserSlot(None));
        }
        let count = self
            .users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(user)
            .or_default()
            .clone();
        if count.fetch_add(1, Ordering::SeqCst) + 1 > limit {
            count.fetch_sub(1, Ordering::SeqCst);
            return Err(());
        }
        Ok(UserSlot(Some(count)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_release_and_independent_users() {
        let tracker = ConnTracker::default();
        tracker.set_max(1);
        let first = tracker.try_acquire(1).unwrap();
        assert!(tracker.try_acquire(1).is_err());
        assert!(tracker.try_acquire(2).is_ok(), "per-user accounting");
        drop(first);
        assert!(tracker.try_acquire(1).is_ok(), "release restores the slot");
    }

    #[test]
    fn zero_negative_and_overflow_limits() {
        let tracker = ConnTracker::default();
        assert!(tracker.try_acquire(1).is_ok() && tracker.try_acquire(1).is_ok());
        tracker.set_max(-5);
        let _held: Vec<_> = (0..4).map(|_| tracker.try_acquire(1).unwrap()).collect();
        tracker.set_max(i64::MAX);
        assert_eq!(tracker.max.load(Ordering::SeqCst), i32::MAX);
    }
}
