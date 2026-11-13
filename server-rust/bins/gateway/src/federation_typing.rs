//! The admitted Chat typing producer: debounce before DB work, then a detached
//! five-second, user-scoped read and best-effort ephemeral send. No durable queue.
use setjoin_federation::service::{Service, TypingChannel};
use setjoin_pg::{ScopedExecutor, Type};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub struct Typing {
    service: Arc<Service>,
    stamps: Mutex<HashMap<i64, Instant>>,
}
impl Typing {
    pub fn new(service: Arc<Service>) -> Self {
        Self {
            service,
            stamps: Mutex::new(HashMap::new()),
        }
    }
    /// Matches Go's per-channel stamp, including refused local signals.
    pub fn debounced(&self, channel: i64) -> bool {
        let now = Instant::now();
        let mut stamps = self.stamps.lock().unwrap();
        if stamps
            .get(&channel)
            .is_some_and(|last| now.duration_since(*last) < Duration::from_secs(1))
        {
            return true;
        }
        if stamps.len() >= 4096 {
            stamps.retain(|_, last| now.duration_since(*last) < Duration::from_secs(1));
        }
        stamps.insert(channel, now);
        false
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
                let rows=exec.read_user_scoped(setjoin_contracts::ids::ActorId::new(user).expect("verified actor"),
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
