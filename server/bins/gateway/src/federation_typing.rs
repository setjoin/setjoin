//! The admitted Chat typing producer: debounce before DB work, then a detached
//! five-second, user-scoped read and best-effort ephemeral send. No durable queue.
use setjoin_federation::service::{Service, TypingChannel};
use setjoin_pg::{ScopedExecutor, Type};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_STAMPS: usize = 4096;
const DEBOUNCE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Default)]
struct DebounceMap {
    stamps: HashMap<i64, Instant>,
}

impl DebounceMap {
    fn debounced_at(&mut self, channel: i64, now: Instant) -> bool {
        if self
            .stamps
            .get(&channel)
            .is_some_and(|last| now.saturating_duration_since(*last) < DEBOUNCE_WINDOW)
        {
            return true;
        }
        if !self.stamps.contains_key(&channel) && self.stamps.len() >= MAX_STAMPS {
            self.stamps
                .retain(|_, last| now.saturating_duration_since(*last) < DEBOUNCE_WINDOW);
            while self.stamps.len() >= MAX_STAMPS {
                let Some(&oldest) = self
                    .stamps
                    .iter()
                    .min_by_key(|(&ch, &ts)| (ts, ch))
                    .map(|(ch, _)| ch)
                else {
                    break;
                };
                self.stamps.remove(&oldest);
            }
        }
        self.stamps.insert(channel, now);
        false
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.stamps.len()
    }
}

pub struct Typing {
    service: Arc<Service>,
    stamps: Mutex<DebounceMap>,
}
impl Typing {
    pub fn new(service: Arc<Service>) -> Self {
        Self {
            service,
            stamps: Mutex::new(DebounceMap::default()),
        }
    }
    /// Matches Go's per-channel stamp, including refused local signals, while
    /// strictly enforcing the 4096-entry memory cap (#265).
    pub fn debounced(&self, channel: i64) -> bool {
        self.stamps
            .lock()
            .unwrap()
            .debounced_at(channel, Instant::now())
    }
    pub fn send(
        self: Arc<Self>,
        exec: ScopedExecutor,
        actor: setjoin_authz::AuthContext,
        channel: i64,
    ) {
        tokio::spawn(async move {
            let _=tokio::time::timeout(Duration::from_secs(5),async {
                let user=actor.user_id();
                let actor_id = setjoin_contracts::ids::ActorId::new(user).ok()?;
                let rows=crate::policy_composition::user_read(
                    &exec,
                    actor_id,
                    "SELECT c.federated_peer_domain,c.federated_room_id,c.federated_remote_id FROM chat_channels c WHERE c.id=$1 AND (c.visibility='public' OR EXISTS(SELECT 1 FROM chat_channel_members m WHERE m.channel_id=c.id AND m.user_id=$2))",
                    &[(&channel,Type::INT8),(&user,Type::INT8)]).await.ok()?;
                let row=rows.first()?;
                let peer:Option<String>=row.try_get(0).ok()?;let room:Option<String>=row.try_get(1).ok()?;let remote:Option<String>=row.try_get(2).ok()?;
                if peer.is_none()&&room.is_none() {return None}
                let ch=TypingChannel{channel_id:channel,local_user_email:actor.email().into(),peer_domain:peer.unwrap_or_default(),room_id:room.unwrap_or_default(),remote_id:remote.unwrap_or_default()};
                self.service.send_typing(&tokio_util::sync::CancellationToken::new(),&ch).await;
                Some(())
            }).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_map_never_exceeds_cap_with_5000_fresh_entries() {
        let mut map = DebounceMap::default();
        let now = Instant::now();
        for ch in 1..=5000_i64 {
            assert!(!map.debounced_at(ch, now), "first signal for channel {ch}");
            assert!(
                map.len() <= MAX_STAMPS,
                "map exceeded cap after inserting channel {ch}: len={}",
                map.len()
            );
        }
        assert_eq!(map.len(), MAX_STAMPS);
    }

    #[test]
    fn debounce_map_evicts_oldest_when_full_and_prunes_stale_entries_first() {
        let mut map = DebounceMap::default();
        let base = Instant::now();
        assert!(!map.debounced_at(1, base));
        assert!(map.debounced_at(1, base + Duration::from_millis(200)));

        let newer = base + Duration::from_millis(500);
        for ch in 2..=(MAX_STAMPS as i64) {
            assert!(!map.debounced_at(ch, newer));
        }
        assert_eq!(map.len(), MAX_STAMPS);

        // Still fresh (<1s old): inserting a new channel must evict the oldest
        // entry (channel 1 at `base`), keeping len == MAX_STAMPS.
        let at_600ms = base + Duration::from_millis(600);
        assert!(!map.debounced_at(MAX_STAMPS as i64 + 1, at_600ms));
        assert_eq!(map.len(), MAX_STAMPS);
        // Channel 1 was evicted, so it is no longer debounced.
        assert!(!map.debounced_at(1, at_600ms));
        assert_eq!(map.len(), MAX_STAMPS);

        // Once all entries are stale (>=1s old), retain prunes them cleanly.
        let after_window = at_600ms + Duration::from_secs(2);
        assert!(!map.debounced_at(99_999, after_window));
        assert_eq!(map.len(), 1);
    }
}
