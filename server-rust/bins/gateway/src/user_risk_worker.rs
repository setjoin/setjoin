//! User-risk scoring (Go's `cron.RunUserRiskCron`, worker `user-risk`): every 15 minutes, score the
//! users with `auth_attempts` activity in the last 24 hours by calling `compute_user_risk` per
//! user on the worker credential. The tick is a no-op while `feature.user_risk` is off (default
//! off; Go resolves the toggle from the database row, no environment override). Id-cursored
//! batches of 200, at most 5 per tick and 45 seconds per tick, exactly as Go bounds it; Go waits
//! one full interval before the first tick and logs-and-continues on error, as this does.
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
use setjoin_pg::Type;
use std::{future::Future, time::Duration};

pub const NAME: &str = "user-risk";
pub const INTERVAL: Duration = Duration::from_secs(15 * 60);
pub const BATCH_SIZE: i64 = 200;
pub const MAX_BATCHES: usize = 5;
pub const TICK_DEADLINE: Duration = Duration::from_secs(45);

pub struct UserRisk {
    db: WorkerDatabase,
}

impl UserRisk {
    pub fn new(db: WorkerDatabase) -> Self {
        Self { db }
    }

    /// `toggles.IsEnabled(toggle.FeatureUserRisk)`: the database row, else off.
    async fn enabled(&self, connection: &WorkerConnection) -> bool {
        match connection
            .query(
                "SELECT enabled FROM feature_toggles WHERE key = 'feature.user_risk'",
                &[],
            )
            .await
        {
            Ok(rows) => rows
                .first()
                .and_then(|r| r.try_get::<_, bool>(0).ok())
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// One tick: Go's `computeUserRiskTick`.
    pub async fn tick(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connection = self.db.connect_session().await?;
        if !self.enabled(&connection).await {
            return Ok(());
        }
        // The whole tick is bounded; hitting the bound abandons the rest like Go's context.
        let _ = tokio::time::timeout(TICK_DEADLINE, Self::score(&connection)).await;
        Ok(())
    }

    async fn score(connection: &WorkerConnection) {
        let mut cursor = 0i64;
        for _ in 0..MAX_BATCHES {
            let rows = match connection
                .query(
                    "SELECT DISTINCT u.id \
                       FROM users u JOIN auth_attempts a ON a.target_username = u.email \
                      WHERE a.occurred_at > now() - interval '24 hours' AND u.id > $1 \
                      ORDER BY u.id \
                      LIMIT $2",
                    &[(&cursor, Type::INT8), (&BATCH_SIZE, Type::INT8)],
                )
                .await
            {
                Ok(rows) => rows,
                Err(_) => {
                    eprintln!("user-risk cron: active-user query failed");
                    return;
                }
            };
            let ids: Vec<i64> = rows
                .iter()
                .filter_map(|r| r.try_get::<_, i64>(0).ok())
                .collect();
            if ids.is_empty() {
                return;
            }
            for id in &ids {
                if connection
                    .execute("SELECT compute_user_risk($1)", &[(id, Type::INT8)])
                    .await
                    .is_err()
                {
                    eprintln!("user-risk cron: compute failed for user {id}");
                }
            }
            cursor = *ids.last().expect("non-empty");
            if (ids.len() as i64) < BATCH_SIZE {
                return;
            }
        }
        eprintln!(
            "user-risk cron: batch budget reached; remaining active users deferred to the next tick"
        );
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, result = self.tick() => {
                if result.is_err() {
                    eprintln!("user-risk cron: tick failed");
                }
            }}
        }
    }
}
