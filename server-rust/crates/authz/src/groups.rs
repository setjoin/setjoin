//! Shared org/AD group resolver (#542).
//!
//! Resolves a verified user's memberships across all three strictly disjoint
//! Setjoin group namespaces inside a user-scoped `BEGIN READ ONLY` transaction
//! (`app.current_user_id = user_id`), satisfying `FORCE RLS` under
//! `setjoin_app` (`NOBYPASSRLS`):
//!
//! 1. `user_group_members` (`V045` `FORCE RLS`) -> [`CaGroupId`]
//! 2. `directory_groups` (`V186` `FORCE RLS`) + `directory_group_members`
//!    (`V186` `FORCE RLS`) + `identity_sources` -> [`DirectoryGroupId`],
//!    matching `directory_group_effective_member`'s exact predicate
//! 3. `distribution_groups` + `distribution_group_members` (mailbox-keyed via
//!    the user's mailboxes) -> [`DistributionGroupId`] plus
//!    `admin_scope_groups` filtered by
//!    `NOT dg.is_dynamic AND (dg.scim_external_id IS NOT NULL OR dg.usable_as_admin_scope)`.
//!
//! Concurrency and fail-closed guarantees:
//! - Bounded LRU cache (default 4096 verified users, 60s TTL).
//! - Synchronization uses a short-lived `std::sync::Mutex` that is **never**
//!   held across any DB `.await` I/O.
//! - Every DB failure returns `Err(GroupResolveError::Unavailable)` — never an
//!   empty membership set.
//! - `group_membership_changed` `LISTEN` notifications invalidate either one
//!   user (`{"user_id": N}`) or the entire cache (`{"all": true}` or
//!   unparseable payload), using subscribe-before-refresh on reconnect.

use setjoin_contracts::ids::{ActorId, Generation};
use setjoin_pg::{workers::DirectListener, AppPool, ScopedExecutor, StatementFailure, Type};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

/// Default upper bound on cached verified-user entries.
pub const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// Default TTL for cached group memberships.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Notification channel emitted by `V285__group_membership_notify.sql`.
pub const NOTIFY_CHANNEL: &str = "group_membership_changed";

/// Conditional Access group identifier (`user_group_members.group_id`).
/// Strictly disjoint from [`DirectoryGroupId`] and [`DistributionGroupId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CaGroupId(i64);

impl CaGroupId {
    pub const fn new(id: i64) -> Option<Self> {
        if id > 0 {
            Some(Self(id))
        } else {
            None
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Normalized AD/directory group identifier (`directory_groups.id`).
/// Strictly disjoint from [`CaGroupId`] and [`DistributionGroupId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectoryGroupId(i64);

impl DirectoryGroupId {
    pub const fn new(id: i64) -> Option<Self> {
        if id > 0 {
            Some(Self(id))
        } else {
            None
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Distribution/SCIM group identifier (`distribution_groups.id`).
/// Strictly disjoint from [`CaGroupId`] and [`DirectoryGroupId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DistributionGroupId(i64);

impl DistributionGroupId {
    pub const fn new(id: i64) -> Option<Self> {
        if id > 0 {
            Some(Self(id))
        } else {
            None
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Resolved group memberships across all three strictly disjoint namespaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupMembership {
    /// Conditional Access groups (`user_group_members`).
    pub ca_groups: Vec<CaGroupId>,
    /// Effective active directory groups (`directory_groups` + `directory_group_members`).
    pub directory_groups: Vec<DirectoryGroupId>,
    /// All distribution groups containing any mailbox owned by the user.
    pub distribution_groups: Vec<DistributionGroupId>,
    /// Non-dynamic distribution groups usable as admin scope sets
    /// (`NOT is_dynamic AND (scim_external_id IS NOT NULL OR usable_as_admin_scope)`).
    pub admin_scope_groups: Vec<DistributionGroupId>,
}

impl GroupMembership {
    /// Raw CA group IDs for Conditional Access policy evaluation.
    pub fn ca_group_ids(&self) -> Vec<i64> {
        self.ca_groups.iter().map(|id| id.get()).collect()
    }

    pub fn has_ca_group(&self, id: CaGroupId) -> bool {
        self.ca_groups.contains(&id)
    }

    pub fn has_directory_group(&self, id: DirectoryGroupId) -> bool {
        self.directory_groups.contains(&id)
    }

    pub fn has_distribution_group(&self, id: DistributionGroupId) -> bool {
        self.distribution_groups.contains(&id)
    }

    pub fn has_admin_scope_group(&self, id: DistributionGroupId) -> bool {
        self.admin_scope_groups.contains(&id)
    }
}

/// Fail-closed error returned when group memberships cannot be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupResolveError {
    InvalidUserId,
    Unavailable(String),
}

impl fmt::Display for GroupResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUserId => f.write_str("invalid user id for group resolution"),
            Self::Unavailable(msg) => write!(f, "group resolver unavailable: {msg}"),
        }
    }
}

impl std::error::Error for GroupResolveError {}

impl From<StatementFailure> for GroupResolveError {
    fn from(value: StatementFailure) -> Self {
        Self::Unavailable(value.message)
    }
}

const CA_GROUPS_SQL: &str =
    "SELECT group_id FROM user_group_members WHERE user_id = $1 ORDER BY group_id";

const DIRECTORY_GROUPS_SQL: &str = "\
SELECT DISTINCT g.id \
  FROM directory_groups g \
  JOIN users u ON u.id = $1 AND u.enabled \
  JOIN directory_group_members m ON m.group_id = g.id AND m.user_id = u.id \
  LEFT JOIN identity_sources s ON s.id = g.source_id \
 WHERE g.state = 'active' \
   AND g.domain_id = u.domain_id \
   AND (g.kind <> 'source' OR s.state = 'active') \
   AND (g.kind <> 'dynamic' OR directory_group_dynamic_matches_fields(\
         g.dynamic_filter, u.domain_id, u.department_id, u.enabled)) \
 ORDER BY g.id";

const DISTRIBUTION_GROUPS_SQL: &str = "\
SELECT DISTINCT dg.id, \
       (NOT dg.is_dynamic AND (dg.scim_external_id IS NOT NULL OR dg.usable_as_admin_scope)) AS is_admin_scope \
  FROM distribution_group_members dgm \
  JOIN mailboxes mb ON mb.id = dgm.mailbox_id AND mb.user_id = $1 \
  JOIN distribution_groups dg ON dg.id = dgm.group_id \
 ORDER BY dg.id";

#[derive(Clone)]
enum Backend {
    App(AppPool),
    Executor(ScopedExecutor),
}

struct CacheEntry {
    value: Arc<GroupMembership>,
    expires_at: Instant,
    order: u64,
}

struct LruCache {
    capacity: usize,
    ttl: Duration,
    seq: u64,
    epoch: u64,
    entries: HashMap<i64, CacheEntry>,
    lru: BTreeMap<u64, i64>,
}

impl LruCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            seq: 0,
            epoch: 0,
            entries: HashMap::new(),
            lru: BTreeMap::new(),
        }
    }

    fn get(&mut self, user_id: i64, now: Instant) -> Option<Arc<GroupMembership>> {
        let expired = self
            .entries
            .get(&user_id)
            .is_some_and(|e| now >= e.expires_at);
        if expired {
            if let Some(old) = self.entries.remove(&user_id) {
                self.lru.remove(&old.order);
            }
            return None;
        }
        let entry = self.entries.get_mut(&user_id)?;
        let old_order = entry.order;
        self.seq = self.seq.wrapping_add(1);
        entry.order = self.seq;
        let value = Arc::clone(&entry.value);
        self.lru.remove(&old_order);
        self.lru.insert(self.seq, user_id);
        Some(value)
    }

    fn insert(&mut self, user_id: i64, value: Arc<GroupMembership>, now: Instant) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        if let Some(old) = self.entries.remove(&user_id) {
            self.lru.remove(&old.order);
        }
        // Evict any expired head entries first, then evict strict LRU until under capacity.
        while self.entries.len() >= self.capacity {
            let Some((_, oldest_user)) = self.lru.pop_first() else {
                break;
            };
            self.entries.remove(&oldest_user);
        }
        self.seq = self.seq.wrapping_add(1);
        let order = self.seq;
        self.entries.insert(
            user_id,
            CacheEntry {
                value,
                expires_at: now + self.ttl,
                order,
            },
        );
        self.lru.insert(order, user_id);
    }

    fn invalidate_user(&mut self, user_id: i64) {
        self.epoch = self.epoch.wrapping_add(1);
        if let Some(old) = self.entries.remove(&user_id) {
            self.lru.remove(&old.order);
        }
    }

    fn invalidate_all(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.entries.clear();
        self.lru.clear();
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Shared bounded-LRU resolver for CA, directory, and distribution/admin-scope
/// group memberships.
pub struct GroupResolver {
    backend: Backend,
    cache: Mutex<LruCache>,
}

impl GroupResolver {
    /// Construct a resolver backed by `#540`'s [`AppPool`] (`UserTx<ReadOnly>`).
    pub fn new(pool: AppPool) -> Self {
        Self {
            backend: Backend::App(pool),
            cache: Mutex::new(LruCache::new(DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL)),
        }
    }

    /// Construct a resolver backed by a legacy [`ScopedExecutor`] (`read_user_scoped`).
    pub fn from_executor(exec: ScopedExecutor) -> Self {
        Self {
            backend: Backend::Executor(exec),
            cache: Mutex::new(LruCache::new(DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL)),
        }
    }

    /// Override cache capacity and TTL (primarily for tests).
    pub fn with_limits(self, capacity: usize, ttl: Duration) -> Self {
        Self {
            backend: self.backend,
            cache: Mutex::new(LruCache::new(capacity, ttl)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Current number of cached verified-user entries.
    pub fn cached_len(&self) -> usize {
        self.lock().len()
    }

    /// Invalidate one user's cached group memberships.
    pub fn invalidate_user(&self, user_id: i64) {
        self.lock().invalidate_user(user_id);
    }

    /// Invalidate all cached group memberships (used on group-wide invalidation
    /// and on `LISTEN` reconnect).
    pub fn invalidate_all(&self) {
        self.lock().invalidate_all();
    }

    /// Process one `group_membership_changed` `LISTEN` notification payload.
    ///
    /// - `{"all": true}` (or any malformed/unknown payload) -> [`Self::invalidate_all`]
    /// - `{"user_id": N}` (`N > 0`) -> [`Self::invalidate_user`]
    pub fn on_notification(&self, payload: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            self.invalidate_all();
            return;
        };
        if value.get("all").and_then(serde_json::Value::as_bool) == Some(true) {
            self.invalidate_all();
            return;
        }
        if let Some(uid) = value
            .get("user_id")
            .and_then(serde_json::Value::as_i64)
            .filter(|&id| id > 0)
        {
            self.invalidate_user(uid);
            return;
        }
        self.invalidate_all();
    }

    /// Resolve all three group namespaces for `user_id`, using the bounded LRU
    /// cache and falling back to a live user-scoped `BEGIN READ ONLY` DB read
    /// (`app.current_user_id = user_id`).
    ///
    /// Never holds the cache mutex across DB `.await` I/O, and fails closed
    /// (`Err(GroupResolveError::Unavailable)`) on any database error.
    pub async fn resolve(&self, user_id: i64) -> Result<Arc<GroupMembership>, GroupResolveError> {
        let actor = ActorId::new(user_id).map_err(|_| GroupResolveError::InvalidUserId)?;
        let epoch_before = {
            let mut cache = self.lock();
            if let Some(hit) = cache.get(user_id, Instant::now()) {
                return Ok(hit);
            }
            cache.epoch
        };

        let membership = Arc::new(self.load_live(actor).await?);

        {
            let mut cache = self.lock();
            if cache.epoch == epoch_before {
                cache.insert(user_id, Arc::clone(&membership), Instant::now());
            }
        }
        Ok(membership)
    }

    /// Resolve strictly live from the database (bypassing cache reads, still
    /// running under `UserTx<ReadOnly>` / `read_user_scoped`).
    pub async fn resolve_live(&self, user_id: i64) -> Result<GroupMembership, GroupResolveError> {
        let actor = ActorId::new(user_id).map_err(|_| GroupResolveError::InvalidUserId)?;
        self.load_live(actor).await
    }

    async fn load_live(&self, actor: ActorId) -> Result<GroupMembership, GroupResolveError> {
        let uid = actor.get();
        match &self.backend {
            Backend::App(pool) => {
                let verified = setjoin_pg::mint::user(actor, Generation(1));
                let mut tx = pool.begin_user_read(&verified).await?;
                let ca_rows = tx.query(CA_GROUPS_SQL, &[(&uid, Type::INT8)]).await?;
                let dir_rows = tx
                    .query(DIRECTORY_GROUPS_SQL, &[(&uid, Type::INT8)])
                    .await?;
                let dist_rows = tx
                    .query(DISTRIBUTION_GROUPS_SQL, &[(&uid, Type::INT8)])
                    .await?;
                tx.finish().await?;
                parse_membership(&ca_rows, &dir_rows, &dist_rows)
            }
            Backend::Executor(exec) => {
                let ca_rows = exec
                    .read_user_scoped(actor, CA_GROUPS_SQL, &[(&uid, Type::INT8)])
                    .await?;
                let dir_rows = exec
                    .read_user_scoped(actor, DIRECTORY_GROUPS_SQL, &[(&uid, Type::INT8)])
                    .await?;
                let dist_rows = exec
                    .read_user_scoped(actor, DISTRIBUTION_GROUPS_SQL, &[(&uid, Type::INT8)])
                    .await?;
                parse_membership(&ca_rows, &dir_rows, &dist_rows)
            }
        }
    }

    /// Subscribe to `group_membership_changed` over `DB_DIRECT_DSN` using
    /// subscribe-before-refresh: every connection/reconnect subscribes first
    /// and then calls [`Self::invalidate_all`] so changes lost during
    /// disconnect are never served from stale cache.
    pub async fn listen(
        self: Arc<Self>,
        direct_dsn: String,
        stop: tokio::sync::oneshot::Receiver<()>,
    ) {
        self.listen_until(direct_dsn, async {
            let _ = stop.await;
        })
        .await;
    }

    /// Same as [`Self::listen`], driven by a `watch::Receiver<bool>` shutdown
    /// channel (matches gateway `RuntimeAccess::run`).
    pub async fn listen_watch(
        self: Arc<Self>,
        direct_dsn: String,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        self.listen_until(direct_dsn, async move {
            while !*stop.borrow() {
                if stop.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
    }

    async fn listen_until<F: std::future::Future<Output = ()>>(
        self: Arc<Self>,
        direct_dsn: String,
        stop: F,
    ) {
        tokio::pin!(stop);
        if direct_dsn.is_empty() {
            stop.await;
            return;
        }
        loop {
            let connected = tokio::select! {
                _ = &mut stop => return,
                r = tokio::time::timeout(
                    Duration::from_secs(5),
                    DirectListener::connect(&direct_dsn, NOTIFY_CHANNEL),
                ) => r,
            };
            if let Ok(Ok(mut listener)) = connected {
                // Subscribe-before-refresh: invalidate any entries cached before
                // the subscription became active.
                self.invalidate_all();
                loop {
                    tokio::select! {
                        _ = &mut stop => {
                            drop(listener);
                            return;
                        }
                        msg = listener.recv() => {
                            let Some(msg) = msg else {
                                break;
                            };
                            self.on_notification(msg.payload());
                        }
                    }
                }
            }
            tokio::select! {
                _ = &mut stop => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }
}

fn parse_membership(
    ca_rows: &[setjoin_pg::Row],
    dir_rows: &[setjoin_pg::Row],
    dist_rows: &[setjoin_pg::Row],
) -> Result<GroupMembership, GroupResolveError> {
    let mut ca_groups = Vec::with_capacity(ca_rows.len());
    for row in ca_rows {
        let id: i64 = row
            .try_get(0)
            .map_err(|e| GroupResolveError::Unavailable(e.to_string()))?;
        if let Some(gid) = CaGroupId::new(id) {
            ca_groups.push(gid);
        }
    }

    let mut directory_groups = Vec::with_capacity(dir_rows.len());
    for row in dir_rows {
        let id: i64 = row
            .try_get(0)
            .map_err(|e| GroupResolveError::Unavailable(e.to_string()))?;
        if let Some(gid) = DirectoryGroupId::new(id) {
            directory_groups.push(gid);
        }
    }

    let mut distribution_groups = Vec::with_capacity(dist_rows.len());
    let mut admin_scope_groups = Vec::new();
    for row in dist_rows {
        let id: i64 = row
            .try_get(0)
            .map_err(|e| GroupResolveError::Unavailable(e.to_string()))?;
        let is_admin_scope: bool = row
            .try_get(1)
            .map_err(|e| GroupResolveError::Unavailable(e.to_string()))?;
        if let Some(gid) = DistributionGroupId::new(id) {
            distribution_groups.push(gid);
            if is_admin_scope {
                admin_scope_groups.push(gid);
            }
        }
    }

    Ok(GroupMembership {
        ca_groups,
        directory_groups,
        distribution_groups,
        admin_scope_groups,
    })
}

/// Direct user-scoped CA group lookup helper for `policy::store::resolve_scope`.
pub(crate) async fn resolve_ca_groups_with_executor(
    exec: &ScopedExecutor,
    user_id: i64,
) -> Result<Vec<i64>, StatementFailure> {
    let actor = ActorId::new(user_id).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid user id for CA group resolution".into(),
    })?;
    let rows = exec
        .read_user_scoped(actor, CA_GROUPS_SQL, &[(&user_id, Type::INT8)])
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_group_ids_reject_non_positive() {
        assert_eq!(CaGroupId::new(0), None);
        assert_eq!(CaGroupId::new(-5), None);
        assert_eq!(CaGroupId::new(7).map(CaGroupId::get), Some(7));
        assert_eq!(DirectoryGroupId::new(0), None);
        assert_eq!(DirectoryGroupId::new(8).map(DirectoryGroupId::get), Some(8));
        assert_eq!(DistributionGroupId::new(0), None);
        assert_eq!(
            DistributionGroupId::new(9).map(DistributionGroupId::get),
            Some(9)
        );
    }

    #[test]
    fn lru_evicts_least_recently_used_and_honors_ttl() {
        let mut cache = LruCache::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        let m = |id: i64| {
            Arc::new(GroupMembership {
                ca_groups: vec![CaGroupId::new(id).unwrap()],
                ..Default::default()
            })
        };
        cache.insert(1, m(10), t0);
        cache.insert(2, m(20), t0 + Duration::from_secs(1));
        // Touch user 1 so user 2 becomes LRU.
        assert_eq!(
            cache
                .get(1, t0 + Duration::from_secs(2))
                .unwrap()
                .ca_group_ids(),
            vec![10]
        );
        // Inserting user 3 must evict user 2, keeping users 1 and 3.
        cache.insert(3, m(30), t0 + Duration::from_secs(3));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(2, t0 + Duration::from_secs(4)).is_none());
        assert!(cache.get(1, t0 + Duration::from_secs(4)).is_some());
        assert!(cache.get(3, t0 + Duration::from_secs(4)).is_some());
        // After TTL, entries expire.
        assert!(cache.get(1, t0 + Duration::from_secs(61)).is_none());
    }

    #[test]
    fn notification_payload_routing() {
        let exec = ScopedExecutor::from_dsn("postgres://mail@127.0.0.1:1/nonexistent", 1).unwrap();
        let resolver = GroupResolver::from_executor(exec);
        let now = Instant::now();
        {
            let mut c = resolver.lock();
            c.insert(101, Arc::new(GroupMembership::default()), now);
            c.insert(102, Arc::new(GroupMembership::default()), now);
        }
        assert_eq!(resolver.cached_len(), 2);
        resolver.on_notification(r#"{"source":"user_group_members","user_id":101}"#);
        assert_eq!(resolver.cached_len(), 1);
        assert!(resolver.lock().get(101, now).is_none());
        assert!(resolver.lock().get(102, now).is_some());

        resolver.on_notification(r#"{"source":"directory_group_invalidations","all":true}"#);
        assert_eq!(resolver.cached_len(), 0);

        {
            let mut c = resolver.lock();
            c.insert(103, Arc::new(GroupMembership::default()), now);
        }
        resolver.on_notification("not-json");
        assert_eq!(resolver.cached_len(), 0);
    }
}
