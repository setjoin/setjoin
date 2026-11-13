//! Process-local chain configuration; Basic password proof stays with #420.
//! This cache has no shared effects and runs alongside Go's copy until deletion.
use setjoin_pg::{workers::DirectListener, ScopedExecutor};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[derive(Default)]
pub struct Chain {
    basic: AtomicBool,
}
impl Chain {
    pub fn basic_allowed(&self) -> bool {
        self.basic.load(Ordering::Acquire)
    }
    /// Read the same two authoritative configuration statements as Go. JWT stays
    /// installed independently of this snapshot, including query and scan failures.
    pub async fn reload(&self, db: &ScopedExecutor) -> Result<(), String> {
        let loaded=async {
   db.read("SELECT slug,priority,config_json::text FROM auth_methods WHERE enabled=TRUE ORDER BY priority ASC",&[]).await.map_err(|e|format!("auth methods: {}",e.message))?;
   let rows=db.read("SELECT enabled FROM feature_toggles WHERE key='feature.disable_basic_auth'",&[]).await.map_err(|e|format!("basic toggle: {}",e.message))?;
   Ok::<_,String>(rows.first().is_some_and(|r|!r.get::<_,bool>(0)))
  }.await;
        // Publish a complete generation; a successful refresh has no deny window.
        self.basic
            .store(loaded.as_ref().copied().unwrap_or(false), Ordering::Release);
        loaded?;
        Ok(())
    }
    /// Every connection subscribes before refreshing, repairing notifications lost
    /// during connection loss. A socket loss retains the last snapshot as Go does;
    /// a failed authoritative refresh removes password admission until recovery.
    pub async fn listen(
        self: Arc<Self>,
        db: ScopedExecutor,
        direct: String,
        mut stop: tokio::sync::oneshot::Receiver<()>,
    ) {
        let mut subscribed = false;
        loop {
            let connected = tokio::select! {_=&mut stop=>return,r=tokio::time::timeout(std::time::Duration::from_secs(5),DirectListener::connect(&direct,"config_changed"))=>r};
            if let Ok(Ok(mut listener)) = connected {
                subscribed = true;
                if let Err(error) = self.reload(&db).await {
                    eprintln!("auth-chain reload: {error}");
                }
                loop {
                    tokio::select! {
                     _=&mut stop=>{drop(listener);return;},
                     message=listener.recv()=>{if message.is_none(){break;}if let Err(error)=self.reload(&db).await{eprintln!("auth-chain reload: {error}");}}
                    }
                }
            } else if !subscribed {
                self.basic.store(false, Ordering::Release);
            }
            tokio::select! {_=&mut stop=>return,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
        }
    }
}
