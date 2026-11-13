//! Process-local TZID catalog keyed by (calendar, TZID): a TZID stored in one calendar never
//! serves another (owner-approved security fix 2026-11-05, #512; frozen Go keyed by TZID alone).
use super::stored_timezone;
use setjoin_pg::{workers::DirectListener, ScopedExecutor};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

#[derive(Default)]
pub(super) struct Timezones {
    values: RwLock<HashMap<(i64, String), String>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    listening: AtomicBool,
}
/// The cache key. The mutant `caldav-tz-global-key` restores frozen Go's TZID-only key.
fn key(calendar: i64, tzid: &str) -> (i64, String) {
    let calendar = if setjoin_contracts::mutants::on("caldav-tz-global-key") { 0 } else { calendar };
    (calendar, tzid.to_owned())
}
impl Timezones {
    pub async fn warm(exec: &ScopedExecutor) -> Arc<Self> {
        let cache = Arc::new(Self::default());
        cache.reload(exec).await;
        cache
    }
    async fn reload(&self, exec: &ScopedExecutor) {
        let Ok(rows) = setjoin_calendar::dav::timezone_catalog(exec).await else {
            return;
        };
        let mut values = self.values.write().expect("timezone cache");
        // Go stores/overwrites rows and never clears keys absent on reload.
        for (calendar, tzid, standard) in rows {
            if !standard.is_empty() {
                values.insert(key(calendar, &tzid), stored_timezone(&tzid, &standard));
            }
        }
    }
    pub async fn lookup(
        &self,
        exec: &ScopedExecutor,
        calendar: i64,
        user: i64,
        tzid: &str,
    ) -> Option<String> {
        if !tzid.is_empty() && tzid != "UTC" {
            if let Some(value) = self
                .values
                .read()
                .expect("timezone cache")
                .get(&key(calendar, tzid))
                .cloned()
            {
                return Some(value);
            }
        }
        if let Some(standard) = setjoin_calendar::dav::owned_timezone(exec, calendar, user, tzid)
            .await
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
        {
            let value = stored_timezone(tzid, &standard);
            self.values
                .write()
                .expect("timezone cache")
                .insert(key(calendar, tzid), value.clone());
            return Some(value);
        }
        if !tzid.is_empty() && tzid != "UTC" {
            super::ical::timezone(tzid)
        } else {
            None
        }
    }
    pub fn listening(&self) -> bool {
        self.listening.load(Ordering::SeqCst)
    }
    pub fn start(self: &Arc<Self>, exec: ScopedExecutor, direct: String) {
        let mut task = self.task.lock().expect("timezone task");
        if task.is_some() {
            return;
        }
        let cache = Arc::downgrade(self);
        *task = Some(tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                if cache.strong_count() == 0 {
                    return;
                }
                let connection = tokio::time::timeout(
                    Duration::from_secs(2),
                    DirectListener::connect(&direct, "timezone_changed"),
                )
                .await;
                if let Ok(Ok(mut listener)) = connection {
                    backoff = Duration::from_secs(1);
                    if let Some(cache) = cache.upgrade() {
                        cache.listening.store(true, Ordering::SeqCst);
                    } else {
                        return;
                    }
                    while listener.recv().await.is_some() {
                        if let Some(cache) = cache.upgrade() {
                            cache.reload(&exec).await;
                        } else {
                            return;
                        }
                    }
                    if let Some(cache) = cache.upgrade() {
                        cache.listening.store(false, Ordering::SeqCst);
                    }
                    let _ = listener.close().await;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }));
    }
    pub fn stop(&self) {
        if let Some(task) = self.task.lock().expect("timezone task").take() {
            task.abort();
        }
        self.listening.store(false, Ordering::SeqCst);
    }
}
impl Drop for Timezones {
    fn drop(&mut self) {
        if let Ok(task) = self.task.get_mut() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
    }
}
