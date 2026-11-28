//! Shared keyed FTRL models and the inbound connection's bounded scoring batch.
#![forbid(unsafe_code)]
pub mod model;
use model::{Model, SIZE};
use setjoin_pg::{workers::WorkerDatabase, Type};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, LazyLock,
    },
};

const RESIDENT_BYTES: i64 = 8 + SIZE as i64 * 24;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatchStats {
    pub loads: i64,
    pub hits: i64,
    pub resident_models: i64,
    pub resident_bytes: i64,
}
#[derive(Default)]
pub struct Stats {
    loads: AtomicI64,
    resident_models: AtomicI64,
    resident_bytes: AtomicI64,
}
impl Stats {
    pub fn snapshot(&self) -> BatchStats {
        BatchStats {
            loads: self.loads.load(Ordering::Relaxed),
            // Frozen PGModelStore never receives the BatchScorer's local hit count.
            hits: 0,
            resident_models: self.resident_models.load(Ordering::Relaxed),
            resident_bytes: self.resident_bytes.load(Ordering::Relaxed),
        }
    }
}
/// The composition root shares these counters between inbound listeners and the
/// admin spam dashboard. Tests can inject a fresh Stats through Store::with_stats.
pub fn process_stats() -> Arc<Stats> {
    static STATS: LazyLock<Arc<Stats>> = LazyLock::new(|| Arc::new(Stats::default()));
    STATS.clone()
}
pub struct Store {
    db: WorkerDatabase,
    stats: Arc<Stats>,
}
impl Store {
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            stats: Arc::new(Stats::default()),
        }
    }
    pub fn with_stats(mut self, stats: Arc<Stats>) -> Self {
        self.stats = stats;
        self
    }
    pub fn stats(&self) -> BatchStats {
        self.stats.snapshot()
    }
    pub fn batch(self: &Arc<Self>) -> Batch {
        Batch {
            store: self.clone(),
            models: HashMap::new(),
            calls: 0,
        }
    }
    async fn load(&self, user: i64) -> Result<Model, String> {
        let connection = self.db.connect().await.map_err(|e| e.to_string())?;
        let rows = connection
            .query(
                "SELECT model_bytes,disabled FROM user_spam_model WHERE user_id=$1",
                &[(&user, Type::INT8)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(Model::new(user));
        };
        if row.get::<_, bool>(1) {
            return Err("spam scoring disabled".into());
        }
        let bytes: Vec<u8> = row.get(0);
        if bytes.is_empty() {
            return Ok(Model::new(user));
        }
        Model::load(user, &bytes).map_err(str::to_owned)
    }
}
/// One SMTP connection holds at most 50 scored deliveries' models. Its drop
/// releases all models on QUIT, disconnect, timeout or listener cancellation.
pub struct Batch {
    store: Arc<Store>,
    models: HashMap<i64, Model>,
    calls: usize,
}
impl Batch {
    pub async fn score(&mut self, user: i64, raw: &[u8], batch: bool) -> Result<f64, String> {
        if !batch {
            return Ok(self.store.load(user).await?.score(raw));
        }
        if self.calls >= 50 {
            self.reset();
        }
        if !self.models.contains_key(&user) {
            let model = self.store.load(user).await?;
            self.models.insert(user, model);
            self.store.stats.loads.fetch_add(1, Ordering::Relaxed);
            self.store
                .stats
                .resident_models
                .fetch_add(1, Ordering::Relaxed);
            self.store
                .stats
                .resident_bytes
                .fetch_add(RESIDENT_BYTES, Ordering::Relaxed);
        }
        self.calls += 1;
        Ok(self.models[&user].score(raw))
    }
    fn reset(&mut self) {
        if !self.models.is_empty() {
            // Parity: Go decrements the model gauge once for the whole batch,
            // even when several models were released. Bytes still release fully.
            self.store
                .stats
                .resident_models
                .fetch_sub(1, Ordering::Relaxed);
            self.store
                .stats
                .resident_bytes
                .fetch_sub(self.models.len() as i64 * RESIDENT_BYTES, Ordering::Relaxed);
        }
        self.models.clear();
        self.calls = 0;
    }
}
impl Drop for Batch {
    fn drop(&mut self) {
        self.reset();
    }
}
