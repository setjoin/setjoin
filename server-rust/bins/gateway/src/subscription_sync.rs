//! Calendar subscription sync (Go's `calendarsync.Worker`): every fifteen minutes
//! (plus up to three of jitter) claim due `calendar_subscriptions` rows, fetch each
//! feed, and apply it through the `calendar_subscription_refresh` reducer.
//!
//! The feed URL is user-supplied, so the fetch is SSRF-safe the way Go's is: every
//! redirect hop is re-validated before it is dialled, and the connector itself
//! refuses non-public addresses (the guard that also defeats DNS rebinding). Go
//! reports every fetch failure as the one generic `couldn't reach that URL`; so does
//! this. The first fetch of a new subscription runs detached through [`SyncKick`].
use crate::calendar::SubscriptionKick;
use crate::ics;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
use setjoin_pg::Type;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

pub const TICK: Duration = Duration::from_secs(15 * 60);
pub const JITTER_MAX: Duration = Duration::from_secs(3 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FETCH_BYTES: usize = 5 << 20;
const MAX_REDIRECTS: usize = 5;
const BATCH: i64 = 20;
const COULD_NOT_REACH: &str = "couldn't reach that URL";

/// Resolves like the system resolver but returns only public addresses, so a
/// public name rebound to an internal address cannot be dialled.
struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| !crate::ssrf::blocked(a.ip()))
                .collect();
            if found.is_empty() {
                return Err("URL is not allowed (must be http/https to a public host)".into());
            }
            Ok(Box::new(found.into_iter()) as Addrs)
        })
    }
}

#[derive(Clone)]
struct Due {
    id: i64,
    calendar: i64,
    url: String,
    etag: String,
    last_modified: String,
}

enum Fetched {
    NotModified,
    Feed {
        events: Vec<ics::Event>,
        parse_errors: usize,
        etag: Option<Vec<u8>>,
        last_modified: Option<Vec<u8>>,
    },
}

enum FetchError {
    CouldNotReach,
    NoEvents(usize),
}

impl FetchError {
    fn text(&self) -> String {
        match self {
            Self::CouldNotReach => COULD_NOT_REACH.into(),
            Self::NoEvents(n) => format!("no events could be parsed ({n} errors)"),
        }
    }
}

pub struct SubscriptionSync {
    db: WorkerDatabase,
    client: reqwest::Client,
    guard_literal_ips: bool,
}

impl SubscriptionSync {
    /// The production worker: dial-time guard on, no proxy (Go's transport has none).
    pub fn new(db: WorkerDatabase) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(PublicOnly))
            .connect_timeout(Duration::from_secs(10))
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("subscription fetch client");
        Self {
            db,
            client,
            guard_literal_ips: true,
        }
    }

    /// Test seam matching the Go tests' unguarded-dial client (loopback fixtures):
    /// redirects are still handed back to the worker's own loop.
    pub fn unguarded_for_tests(db: WorkerDatabase) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("subscription fetch client");
        Self {
            db,
            client,
            guard_literal_ips: false,
        }
    }

    /// One tick: claim every due subscription and refresh each in turn.
    pub async fn tick(&self) {
        let due = match self.claim_due().await {
            Ok(due) => due,
            Err(e) => {
                eprintln!("calendarsync: claim failed: {e}");
                return;
            }
        };
        for sub in due {
            self.refresh_one(sub).await;
        }
    }

    async fn claim_due(&self) -> Result<Vec<Due>, String> {
        let c = self.db.connect().await.map_err(|e| e.to_string())?;
        let rows = c
            .query(
                "WITH due AS (
                    SELECT id FROM calendar_subscriptions
                     WHERE last_fetch_at IS NULL
                        OR last_fetch_at < now() - make_interval(mins => refresh_interval_minutes)
                     ORDER BY last_fetch_at NULLS FIRST
                     FOR UPDATE SKIP LOCKED
                     LIMIT $1
                 )
                 UPDATE calendar_subscriptions s
                    SET last_fetch_at = now()
                   FROM due
                  WHERE s.id = due.id
                 RETURNING s.id, s.calendar_id, s.url, COALESCE(s.etag, ''), COALESCE(s.last_modified, '')",
                &[(&BATCH, Type::INT8)],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| Due {
                id: r.get(0),
                calendar: r.get(1),
                url: r.get(2),
                etag: r.get(3),
                last_modified: r.get(4),
            })
            .collect())
    }

    /// Go's `RefreshSubscriptionNow`: fetch and apply one subscription immediately.
    pub async fn refresh_now(&self, subscription: i64, calendar: i64, url: String) {
        self.refresh_one(Due {
            id: subscription,
            calendar,
            url,
            etag: String::new(),
            last_modified: String::new(),
        })
        .await;
    }

    async fn refresh_one(&self, sub: Due) {
        let fetched = match tokio::time::timeout(
            FETCH_TIMEOUT,
            self.fetch(&sub.url, &sub.etag, &sub.last_modified),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(FetchError::CouldNotReach),
        };
        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(e) => return self.record_status(sub.id, "error", &e.text()).await,
        };
        let (events, parse_errors, etag, last_modified) = match fetched {
            Fetched::NotModified => return self.record_status(sub.id, "ok", "").await,
            Fetched::Feed {
                events,
                parse_errors,
                etag,
                last_modified,
            } => (events, parse_errors, etag, last_modified),
        };
        let json = ics::events_to_json(&events);
        let (status, message) = if parse_errors > 0 {
            (
                "partial",
                format!(
                    "{} of {} events synced",
                    events.len(),
                    events.len() + parse_errors
                ),
            )
        } else {
            ("ok", String::new())
        };
        if let Err(e) = self
            .apply(sub.id, sub.calendar, &json, status, &message, &etag, &last_modified)
            .await
        {
            eprintln!(
                "calendarsync: refresh reducer failed subscription_id={} error={e}",
                sub.id
            );
            self.record_status(sub.id, "error", "sync failed \u{2014} will retry next cycle")
                .await;
        }
    }

    /// The reducer and the status/etag bookkeeping in one transaction.
    #[allow(clippy::too_many_arguments)]
    async fn apply(
        &self,
        id: i64,
        calendar: i64,
        json: &str,
        status: &str,
        message: &str,
        etag: &Option<Vec<u8>>,
        last_modified: &Option<Vec<u8>>,
    ) -> Result<(), String> {
        // A validator that is not UTF-8 cannot be stored as text: the database
        // rejects it inside the transaction in Go, so nothing is applied.
        let text = |v: &Option<Vec<u8>>| -> Result<String, String> {
            match v {
                None => Ok(String::new()),
                Some(bytes) => String::from_utf8(bytes.clone())
                    .map_err(|_| "invalid byte sequence for encoding \"UTF8\"".to_owned()),
            }
        };
        let (etag, last_modified) = (text(etag)?, text(last_modified)?);
        let c = self.db.connect_session().await.map_err(|e| e.to_string())?;
        c.query("BEGIN", &[]).await?;
        let result = self
            .apply_in_tx(&c, id, calendar, json, status, message, &etag, &last_modified)
            .await;
        match result {
            Ok(()) => c.query("COMMIT", &[]).await.map(|_| ()),
            Err(e) => {
                let _ = c.query("ROLLBACK", &[]).await;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_in_tx(
        &self,
        c: &WorkerConnection,
        id: i64,
        calendar: i64,
        json: &str,
        status: &str,
        message: &str,
        etag: &str,
        last_modified: &str,
    ) -> Result<(), String> {
        c.query(
            "SELECT calendar_subscription_refresh($1, $2, $3::jsonb)",
            &[(&id, Type::INT8), (&calendar, Type::INT8), (&json, Type::TEXT)],
        )
        .await?;
        c.query(
            "UPDATE calendar_subscriptions
                SET last_status = $2, last_error = NULLIF($3, ''),
                    etag = NULLIF($4, ''), last_modified = NULLIF($5, '')
              WHERE id = $1",
            &[
                (&id, Type::INT8),
                (&status, Type::TEXT),
                (&message, Type::TEXT),
                (&etag, Type::TEXT),
                (&last_modified, Type::TEXT),
            ],
        )
        .await?;
        Ok(())
    }

    async fn record_status(&self, id: i64, status: &str, message: &str) {
        let result = async {
            let c = self.db.connect().await.map_err(|e| e.to_string())?;
            c.query(
                "UPDATE calendar_subscriptions
                    SET last_status = $2, last_error = NULLIF($3, '')
                  WHERE id = $1",
                &[(&id, Type::INT8), (&status, Type::TEXT), (&message, Type::TEXT)],
            )
            .await
        }
        .await;
        if let Err(e) = result {
            eprintln!("calendarsync: status bookkeeping failed subscription_id={id}: {e}");
        }
    }

    fn refused(&self, url: &reqwest::Url) -> bool {
        self.guard_literal_ips
            && match url.host() {
                Some(url::Host::Ipv4(ip)) => crate::ssrf::blocked(IpAddr::V4(ip)),
                Some(url::Host::Ipv6(ip)) => crate::ssrf::blocked(IpAddr::V6(ip)),
                _ => false,
            }
    }

    /// Go's `fetch`: conditional GET on hop 0, up to five re-validated redirects.
    async fn fetch(&self, raw: &str, etag: &str, last_modified: &str) -> Result<Fetched, FetchError> {
        let mut current = normalize_webcal(raw);
        for hop in 0..=MAX_REDIRECTS {
            let url = reqwest::Url::parse(&current).map_err(|_| FetchError::CouldNotReach)?;
            if self.refused(&url) {
                return Err(FetchError::CouldNotReach);
            }
            let mut request = self
                .client
                .get(url)
                .header("Accept", "text/calendar, */*")
                .header("User-Agent", "setjoin-calendarsync/1");
            if hop == 0 {
                if !etag.is_empty() {
                    request = request.header("If-None-Match", etag);
                }
                if !last_modified.is_empty() {
                    request = request.header("If-Modified-Since", last_modified);
                }
            }
            let mut response = request.send().await.map_err(|_| FetchError::CouldNotReach)?;
            let status = response.status().as_u16();
            match status {
                304 => return Ok(Fetched::NotModified),
                300..=399 => {
                    let location = response
                        .headers()
                        .get("location")
                        .map(|v| v.as_bytes().to_vec())
                        .unwrap_or_default();
                    if location.is_empty() {
                        return Err(FetchError::CouldNotReach);
                    }
                    let location = String::from_utf8(location).map_err(|_| FetchError::CouldNotReach)?;
                    let base = reqwest::Url::parse(&current).map_err(|_| FetchError::CouldNotReach)?;
                    let next = base.join(&location).map_err(|_| FetchError::CouldNotReach)?;
                    let next = normalize_webcal(next.as_str());
                    // The redirect target is the feed operator's choice: reject it
                    // before it is ever dialled.
                    if !crate::ssrf::valid_url(&next) {
                        return Err(FetchError::CouldNotReach);
                    }
                    current = next;
                }
                200 => {
                    let mut body = Vec::new();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|_| FetchError::CouldNotReach)?
                    {
                        body.extend_from_slice(&chunk);
                        if body.len() > MAX_FETCH_BYTES {
                            return Err(FetchError::CouldNotReach);
                        }
                    }
                    let (events, parse_errors) = ics::split_and_parse(&body);
                    if events.is_empty() && parse_errors > 0 {
                        return Err(FetchError::NoEvents(parse_errors));
                    }
                    let validator = |name: &str| {
                        response
                            .headers()
                            .get(name)
                            .map(|v| v.as_bytes().to_vec())
                            .filter(|v| valid_validator(v))
                            .filter(|v| !v.is_empty())
                    };
                    return Ok(Fetched::Feed {
                        events,
                        parse_errors,
                        etag: validator("etag"),
                        last_modified: validator("last-modified"),
                    });
                }
                _ => return Err(FetchError::CouldNotReach),
            }
        }
        Err(FetchError::CouldNotReach)
    }

    /// Go's ticker loop: wait a full interval (plus jitter) before every tick.
    pub async fn run_until(self: Arc<Self>, stop: impl Future<Output = ()> + Send) {
        tokio::pin!(stop);
        loop {
            let jitter = rand_jitter();
            tokio::select! {biased; _ = &mut stop => return, _ = tokio::time::sleep(TICK + jitter) => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }
}

fn rand_jitter() -> Duration {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    Duration::from_nanos(u64::from_le_bytes(b) % JITTER_MAX.as_nanos() as u64)
}

/// `httpguts.ValidHeaderFieldValue`: control bytes other than space and tab fail.
pub fn valid_validator(value: &[u8]) -> bool {
    value
        .iter()
        .all(|b| !(*b < b' ' || *b == 0x7f) || *b == b' ' || *b == b'\t')
}

pub fn normalize_webcal(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix("webcal://") {
        format!("https://{rest}")
    } else if let Some(rest) = raw.strip_prefix("webcals://") {
        format!("https://{rest}")
    } else {
        raw.to_owned()
    }
}

/// Installed in the gateway when this worker runs in Rust: the subscribe route's
/// detached first fetch.
pub struct SyncKick {
    sync: Arc<SubscriptionSync>,
}

impl SyncKick {
    pub fn new(sync: Arc<SubscriptionSync>) -> Self {
        Self { sync }
    }
}

impl SubscriptionKick for SyncKick {
    fn kick(&self, subscription: i64, calendar: i64, url: String) {
        let sync = self.sync.clone();
        tokio::spawn(async move { sync.refresh_now(subscription, calendar, url).await });
    }
}
