//! Group `monitor`: `GET /admin/monitor/live` and `GET /admin/reports/summary`, both
//! behind `requireMailPerm` and read-only. Go answers a failed summary with a minimal
//! problem; the live counters never fail.
use super::{Action, Env};
use crate::{Body, Response};
use hyper::Request;

pub(super) async fn run(what: Action, r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    match what {
        Action::MonitorLive => {
            let sections =
                crate::admin_identity_input::query(r.uri(), "sections").unwrap_or_default();
            let goroutines = tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks() as u64;
            let body = setjoin_platform::monitor::live(e.worker, &sections, goroutines).await;
            e.reply(body, 200)
        }
        _ => {
            let raw = crate::admin_identity_input::query(r.uri(), "days").unwrap_or_default();
            let days = setjoin_platform::monitor::days(&raw);
            let period = if raw.is_empty() { "7" } else { raw.as_str() };
            match setjoin_platform::monitor::summary(e.exec, period, days).await {
                Ok(body) => e.reply(body, 200),
                Err(_) => e.bare(500, "database error"),
            }
        }
    }
}
