//! Booking expiry (Go's `booking.Sweeper`): every ten minutes, mark pending
//! requests whose verification window has passed as expired. One fixed reducer
//! statement on the worker credential; Go waits a full interval before its
//! first sweep and logs-and-continues on error, as this does.
use setjoin_pg::workers::WorkerDatabase;
use std::{future::Future, time::Duration};

pub const INTERVAL: Duration = Duration::from_secs(600);

pub struct BookingExpiry {
    db: WorkerDatabase,
}

impl BookingExpiry {
    pub fn new(db: WorkerDatabase) -> Self {
        Self { db }
    }

    /// One sweep: Go's `SELECT booking_expire_due()`.
    pub async fn tick(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.db
            .run_cron_statement(setjoin_calendar::EXPIRE_DUE)
            .await
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, result = self.tick() => {
                if result.is_err() {
                    eprintln!("booking sweeper: booking_expire_due failed");
                }
            }}
        }
    }
}
