//! Process-local, demand-driven LISTEN dispatcher shared by push transports.
//! Channel names are derived by the authenticated transport, never by clients.
use setjoin_pg::workers::DirectListener;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot, Mutex};

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct PushHub {
    direct: String,
    listen_hub: Option<setjoin_pg::ListenHub>,
    actor: Mutex<Option<Actor>>,
}

struct Actor {
    commands: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Actor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Command {
    Subscribe {
        channels: Vec<String>,
        reply: oneshot::Sender<Result<Subscription, Error>>,
    },
    Release(u64),
}

#[derive(Clone, Debug)]
pub struct Event {
    pub channel: String,
    pub payload: String,
}

pub struct Subscription {
    pub events: Events,
    commands: mpsc::UnboundedSender<Command>,
    id: u64,
}

/// Independent bounded rails, as Go's state/revoke/raw channels. A slow raw
/// consumer cannot spend the mailbox state or revocation buffer.
pub struct Events {
    rails: Vec<mpsc::Receiver<Event>>,
    next: usize,
}
impl Events {
    pub async fn recv(&mut self) -> Option<Event> {
        futures_util::future::poll_fn(|cx| {
            let mut open = false;
            for offset in 0..self.rails.len() {
                let index = (self.next + offset) % self.rails.len();
                match self.rails[index].poll_recv(cx) {
                    std::task::Poll::Ready(Some(event)) => {
                        self.next = (index + 1) % self.rails.len();
                        return std::task::Poll::Ready(Some(event));
                    }
                    std::task::Poll::Pending => open = true,
                    _ => {}
                }
            }
            if open {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(None)
            }
        })
        .await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Release(self.id));
    }
}

impl PushHub {
    pub fn new(direct_dsn: String) -> Arc<Self> {
        Arc::new(Self {
            direct: direct_dsn,
            listen_hub: None,
            actor: Mutex::new(None),
        })
    }

    pub fn with_listen_hub(hub: setjoin_pg::ListenHub) -> Arc<Self> {
        Arc::new(Self {
            direct: String::new(),
            listen_hub: Some(hub),
            actor: Mutex::new(None),
        })
    }

    pub async fn subscribe(&self, channels: Vec<String>) -> Result<Subscription, Error> {
        if let Some(hub) = &self.listen_hub {
            let mut subs = Vec::with_capacity(channels.len());
            for ch in &channels {
                subs.push(
                    hub.subscribe(ch.clone())
                        .await
                        .map_err(|e| format!("push listen hub subscribe: {e}"))?,
                );
            }
            let mut groups = HashMap::new();
            let mut rails = Vec::new();
            let mut senders = Vec::with_capacity(channels.len());
            for channel in &channels {
                let state = ["tag:", "calendar:", "contact:", "task:"]
                    .iter()
                    .any(|prefix| channel.starts_with(prefix));
                let (group, capacity) = if state {
                    ("state", 64)
                } else if channel == "session_revoke" {
                    ("session_revoke", 4)
                } else if channel == "drive-alarm" {
                    ("drive-alarm", 8)
                } else {
                    (channel.as_str(), 16)
                };
                let send = groups.entry(group.to_owned()).or_insert_with(|| {
                    let (send, receive) = mpsc::channel(capacity);
                    rails.push(receive);
                    send
                });
                senders.push(send.clone());
            }
            for (sub, send) in subs.into_iter().zip(senders) {
                tokio::spawn(forward_hub_subscription(sub, send));
            }
            let (commands, _rx) = mpsc::unbounded_channel();
            return Ok(Subscription {
                events: Events { rails, next: 0 },
                commands,
                id: 0,
            });
        }
        if self.direct.trim().is_empty() {
            return Err("DB_DIRECT_DSN is required for push subscriptions".into());
        }
        let mut actor = self.actor.lock().await;
        if actor.as_ref().is_none_or(|a| a.commands.is_closed()) {
            let listener = DirectListener::connect(&self.direct, "session_revoke").await?;
            let (commands, receive) = mpsc::unbounded_channel();
            let task = tokio::spawn(dispatch(listener, receive, commands.clone()));
            *actor = Some(Actor { commands, task });
        }
        let (reply, result) = oneshot::channel();
        actor
            .as_ref()
            .expect("started actor")
            .commands
            .send(Command::Subscribe { channels, reply })?;
        drop(actor);
        result.await?
    }
}

struct Consumer {
    channels: HashSet<String>,
    events: HashMap<String, mpsc::Sender<Event>>,
}

async fn dispatch(
    mut listener: DirectListener,
    mut commands: mpsc::UnboundedReceiver<Command>,
    sender: mpsc::UnboundedSender<Command>,
) {
    let mut consumers: HashMap<u64, Consumer> = HashMap::new();
    let mut listening = HashSet::from(["session_revoke".to_owned()]);
    let mut next = 0;
    loop {
        tokio::select! {
            notification = listener.recv() => {
                let Some(notification) = notification else { break };
                for consumer in consumers.values() {
                    if consumer.channels.contains(notification.channel()) {
                        // Go's dispatcher drops a new payload when the client buffer is full.
                        let _ = consumer.events[notification.channel()].try_send(Event { channel: notification.channel().to_owned(), payload: notification.payload().to_owned() });
                    }
                }
            }
            command = commands.recv() => match command {
                Some(Command::Subscribe { channels, reply }) => {
                    let mut failure = None;
                    for channel in &channels {
                        if !listening.contains(channel) {
                            match listener.listen(channel).await {
                                Ok(()) => { listening.insert(channel.clone()); }
                                Err(error) => { failure = Some(error); break }
                            }
                        }
                    }
                    if let Some(error) = failure { let _ = reply.send(Err(error)); continue }
                    next += 1;
                    let mut groups=HashMap::new();let mut rails=Vec::new();let mut events=HashMap::new();
                    for channel in &channels {
                        let state=["tag:","calendar:","contact:","task:"].iter().any(|prefix|channel.starts_with(prefix));
                        let (group,capacity)=if state {("state",64)}else if channel=="session_revoke"{("session_revoke",4)}else if channel=="drive-alarm"{("drive-alarm",8)}else{(channel.as_str(),16)};
                        let send=groups.entry(group.to_owned()).or_insert_with(||{let (send,receive)=mpsc::channel(capacity);rails.push(receive);send});
                        events.insert(channel.clone(),send.clone());
                    }
                    consumers.insert(next, Consumer { channels: channels.into_iter().collect(), events });
                    let subscription = Subscription { events: Events {rails,next:0}, commands: sender.clone(), id: next };
                    let _ = reply.send(Ok(subscription));
                }
                Some(Command::Release(id)) => {
                    consumers.remove(&id);
                    let unused: Vec<_> = listening.iter().filter(|channel| channel.as_str() != "session_revoke" && !consumers.values().any(|c| c.channels.contains(*channel))).cloned().collect();
                    for channel in unused {
                        if listener.unlisten(&channel).await.is_err() { return }
                        listening.remove(&channel);
                    }
                }
                None => break,
            }
        }
    }
}

trait EventSource {
    fn next_event(
        &mut self,
    ) -> impl std::future::Future<Output = Option<setjoin_pg::ListenEvent>> + Send;
}

impl EventSource for setjoin_pg::ListenSubscription {
    fn next_event(
        &mut self,
    ) -> impl std::future::Future<Output = Option<setjoin_pg::ListenEvent>> + Send {
        self.recv()
    }
}

/// Forward events from a [`setjoin_pg::ListenSubscription`] into a push rail.
///
/// Races `send.closed()` against `sub.recv()` so a disconnected WebSocket/SSE
/// client drops its `ListenSubscription` immediately (triggering `UNLISTEN` on
/// idle user channels), and breaks on [`setjoin_pg::ListenEvent::ResyncRequired`]
/// so the push stream closes cleanly for client resync.
async fn forward_hub_subscription(sub: setjoin_pg::ListenSubscription, send: mpsc::Sender<Event>) {
    forward_events(sub, send).await;
}

async fn forward_events(mut sub: impl EventSource, send: mpsc::Sender<Event>) {
    loop {
        tokio::select! {
            biased;
            _ = send.closed() => break,
            ev = sub.next_event() => match ev {
                Some(setjoin_pg::ListenEvent::Notification(notif)) => {
                    let _ = send.try_send(Event {
                        channel: notif.channel,
                        payload: notif.payload,
                    });
                }
                Some(setjoin_pg::ListenEvent::ResyncRequired { .. }) | None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use setjoin_pg::{ListenEvent, ListenNotification};
    use std::time::Duration;

    impl EventSource for mpsc::Receiver<ListenEvent> {
        fn next_event(&mut self) -> impl std::future::Future<Output = Option<ListenEvent>> + Send {
            self.recv()
        }
    }

    #[tokio::test]
    async fn client_disconnect_exits_forwarder_and_drops_subscription_promptly() {
        let (src_tx, src_rx) = mpsc::channel::<ListenEvent>(4);
        let (rail_tx, rail_rx) = mpsc::channel::<Event>(4);

        let task = tokio::spawn(forward_events(src_rx, rail_tx));
        tokio::task::yield_now().await;
        assert!(
            !src_tx.is_closed(),
            "subscription must remain open while client is connected"
        );

        drop(rail_rx);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("forwarder task must exit promptly on client disconnect")
            .expect("forwarder task join");
        assert!(
            src_tx.is_closed(),
            "ListenSubscription must be dropped immediately on client disconnect"
        );
    }

    #[tokio::test]
    async fn resync_required_closes_push_stream_cleanly() {
        let (src_tx, src_rx) = mpsc::channel::<ListenEvent>(4);
        let (rail_tx, mut rail_rx) = mpsc::channel::<Event>(4);

        let task = tokio::spawn(forward_events(src_rx, rail_tx));
        src_tx
            .send(ListenEvent::Notification(ListenNotification {
                channel: "tag:1".into(),
                payload: "{\"state\":\"1\"}".into(),
            }))
            .await
            .unwrap();
        let ev = rail_rx.recv().await.expect("forwarded notification");
        assert_eq!(ev.channel, "tag:1");
        assert_eq!(ev.payload, "{\"state\":\"1\"}");

        src_tx
            .send(ListenEvent::ResyncRequired { epoch: 2 })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("forwarder task must exit on ResyncRequired")
            .expect("forwarder task join");
        assert!(
            rail_rx.recv().await.is_none(),
            "push stream must close cleanly on ResyncRequired"
        );
    }
}
