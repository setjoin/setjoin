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
            actor: Mutex::new(None),
        })
    }

    pub async fn subscribe(&self, channels: Vec<String>) -> Result<Subscription, Error> {
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
